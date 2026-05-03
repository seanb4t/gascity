package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/99designs/keyring"
)

// useFixedSecretPrompt replaces secretPromptFn with a deterministic
// password function so the file backend does not prompt interactively.
// It restores the original on test cleanup.
func useFixedSecretPrompt(t *testing.T) {
	t.Helper()
	orig := secretPromptFn
	secretPromptFn = func(_ string) (string, error) { return "test-password", nil }
	t.Cleanup(func() { secretPromptFn = orig })
}

// writeTestSupervisorTOML drops a minimal supervisor.toml in a temp
// home and returns the path so subcommand tests can read it.
func writeTestSupervisorTOML(t *testing.T, body string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("GC_HOME", home)
	cfgPath := filepath.Join(home, "supervisor.toml")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return cfgPath
}

func TestSecretSet_FromStdin(t *testing.T) {
	useFixedSecretPrompt(t)
	dir := t.TempDir()
	writeTestSupervisorTOML(t, `
[secrets]
backend = "file"
[secrets.file]
dir = "`+dir+`"
prefixes = ["EXA_API_KEY"]
`)
	var stdout, stderr bytes.Buffer
	cmd := newSupervisorSecretSetCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"EXA_API_KEY", "--from-stdin"})
	cmd.SetIn(strings.NewReader("sk-from-stdin"))
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v\nstderr: %s", err, stderr.String())
	}

	var getOut bytes.Buffer
	getCmd := newSupervisorSecretGetCmd(&getOut, &stderr)
	getCmd.SetArgs([]string{"EXA_API_KEY"})
	if err := getCmd.Execute(); err != nil {
		t.Fatalf("get Execute: %v", err)
	}
	if getOut.String() != "sk-from-stdin" {
		t.Errorf("get output = %q, want sk-from-stdin", getOut.String())
	}
}

func TestSecretGet_NotFound(t *testing.T) {
	useFixedSecretPrompt(t)
	dir := t.TempDir()
	writeTestSupervisorTOML(t, `
[secrets]
backend = "file"
[secrets.file]
dir = "`+dir+`"
prefixes = ["EXA_API_KEY"]
`)
	var stdout, stderr bytes.Buffer
	cmd := newSupervisorSecretGetCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"EXA_API_KEY"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute = nil err, want error for not-found")
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty on not-found", stdout.String())
	}
}

func TestSecretDelete_Idempotent(t *testing.T) {
	useFixedSecretPrompt(t)
	dir := t.TempDir()
	writeTestSupervisorTOML(t, `
[secrets]
backend = "file"
[secrets.file]
dir = "`+dir+`"
prefixes = ["EXA_API_KEY"]
`)
	var stdout, stderr bytes.Buffer
	cmd := newSupervisorSecretDeleteCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"EXA_API_KEY", "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("delete non-existent: %v", err)
	}
}

func TestSecretReload_NoSupervisor(t *testing.T) {
	writeTestSupervisorTOML(t, `[secrets]`)
	var stdout, stderr bytes.Buffer
	cmd := newSupervisorSecretReloadCmd(&stdout, &stderr)
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("Execute = nil, want error when supervisor not running")
	}
	if !strings.Contains(stderr.String(), "not running") && !strings.Contains(err.Error(), "not running") {
		t.Errorf("expected 'not running' message, got stderr=%q err=%v", stderr.String(), err)
	}
}

func TestSecretImportEnv_HappyPath(t *testing.T) {
	dir := t.TempDir()
	writeTestSupervisorTOML(t, `
[secrets]
backend = "file"
[secrets.file]
dir = "`+dir+`"
prefixes = []
`)
	useFixedSecretPrompt(t)
	t.Setenv("GC_SUPERVISOR_ENV", "FOO_KEY,BAR_TOKEN")
	t.Setenv("FOO_KEY", "foo-val")
	t.Setenv("BAR_TOKEN", "bar-val")

	var stdout, stderr bytes.Buffer
	cmd := newSupervisorSecretImportEnvCmd(&stdout, &stderr)
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	promptFn := func(_ string) (string, error) { return "test-password", nil }
	ring, _ := keyring.Open(keyring.Config{
		ServiceName: "gc-supervisor", AllowedBackends: []keyring.BackendType{keyring.FileBackend},
		FileDir: dir, FilePasswordFunc: promptFn,
	})
	keys, _ := ring.Keys()
	sort.Strings(keys)
	want := []string{"BAR_TOKEN", "FOO_KEY"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Errorf("keyring contents = %v, want %v", keys, want)
	}

	if !strings.Contains(stdout.String(), "[secrets.file]") || !strings.Contains(stdout.String(), "FOO_KEY") {
		t.Errorf("suggested TOML missing from stdout:\n%s", stdout.String())
	}
}

func TestSecretList_DriftDetection(t *testing.T) {
	dir := t.TempDir()
	writeTestSupervisorTOML(t, `
[secrets]
backend = "file"
[secrets.file]
dir = "`+dir+`"
prefixes = ["EXA_API_KEY", "FIRECRAWL_KEY", "LINEAR_TOKEN"]
`)
	useFixedSecretPrompt(t)

	promptFn := func(_ string) (string, error) { return "test-password", nil }
	ring, err := keyring.Open(keyring.Config{
		ServiceName:      "gc-supervisor",
		AllowedBackends:  []keyring.BackendType{keyring.FileBackend},
		FileDir:          dir,
		FilePasswordFunc: promptFn,
	})
	if err != nil {
		t.Fatalf("open ring: %v", err)
	}
	if err := ring.Set(keyring.Item{Key: "EXA_API_KEY", Data: []byte("v")}); err != nil {
		t.Fatalf("set EXA_API_KEY: %v", err)
	}
	if err := ring.Set(keyring.Item{Key: "LINEAR_TOKEN", Data: []byte("v")}); err != nil {
		t.Fatalf("set LINEAR_TOKEN: %v", err)
	}
	if err := ring.Set(keyring.Item{Key: "ORPHAN_KEY", Data: []byte("v")}); err != nil {
		t.Fatalf("set ORPHAN_KEY: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := newSupervisorSecretListCmd(&stdout, &stderr)
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"EXA_API_KEY", "OK",
		"FIRECRAWL_KEY", "MISSING",
		"LINEAR_TOKEN", "OK",
		"ORPHAN_KEY", "ORPHAN",
		"(supervisor down)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing %q\nfull output:\n%s", want, out)
		}
	}
}
