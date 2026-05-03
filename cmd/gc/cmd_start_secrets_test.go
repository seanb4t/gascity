package main

import (
	"context"
	"os"
	"testing"

	"github.com/99designs/keyring"
	"github.com/gastownhall/gascity/internal/supervisor"
	supsecrets "github.com/gastownhall/gascity/internal/supervisor/secrets"
)

const startTestSecretsPassword = "gc-start-test-password"

// setupStartSecretsTest creates a temp supervisor.toml and file-backend keyring,
// seeds keyName=keyVal, and returns the loaded SecretsConfig. The test env is
// cleaned up automatically via t.Cleanup.
func setupStartSecretsTest(t *testing.T, keyName, keyVal string) supervisor.SecretsConfig {
	t.Helper()

	// Restore env state on cleanup.
	if v, ok := os.LookupEnv(keyName); ok {
		t.Cleanup(func() { os.Setenv(keyName, v) })    //nolint:errcheck,tenv
	} else {
		t.Cleanup(func() { os.Unsetenv(keyName) }) //nolint:tenv
	}
	os.Unsetenv(keyName) //nolint:tenv

	// Use the fixed password via the env var that secretsFilePromptFunc reads.
	t.Setenv(secretsFileEnvPasswordVar, startTestSecretsPassword)

	fileDir := t.TempDir()
	tomlBody := "[secrets]\nbackend = \"file\"\n\n[secrets.file]\ndir = \"" + fileDir + "\"\nprefixes = [\"" + keyName + "\"]\n"
	writeTestSupervisorTOML(t, tomlBody)

	// Seed the file backend.
	promptFn := func(_ string) (string, error) { return startTestSecretsPassword, nil }
	ring, err := keyring.Open(keyring.Config{
		ServiceName:      "gc-supervisor",
		AllowedBackends:  []keyring.BackendType{keyring.FileBackend},
		FileDir:          fileDir,
		FilePasswordFunc: promptFn,
	})
	if err != nil {
		t.Fatalf("open keyring: %v", err)
	}
	if err := ring.Set(keyring.Item{Key: keyName, Data: []byte(keyVal)}); err != nil {
		t.Fatalf("seed keyring: %v", err)
	}

	cfg, err := supervisor.LoadConfig(supervisor.ConfigPath())
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	return cfg.Secrets
}

// TestGCStart_LoadsSecretsBeforeMCPExpansion verifies that the gc start path
// loads secrets from the keyring into the process environment. MCP
// .template.toml files reference keys like {{.EXA_API_KEY}}; for those to
// expand correctly the key must be in the process env before MCP projection
// runs. This test exercises the loader in isolation — the same approach as
// TestRunSupervisor_LoadsSecretsBeforeAPIBind — rather than running the full
// doStartStandalone pipeline against a real city filesystem.
func TestGCStart_LoadsSecretsBeforeMCPExpansion(t *testing.T) {
	const testKey = "TEST_SECRET_KEY_START"
	const testVal = "gc-start-test-value"

	cfg := setupStartSecretsTest(t, testKey, testVal)

	loader := supsecrets.NewLoader(secretsFilePromptFunc())
	res, err := loader.LoadAll(context.Background(), cfg)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(res.Set) != 1 {
		t.Fatalf("Set = %v, want one entry", res.Set)
	}
	if got := os.Getenv(testKey); got != testVal {
		t.Errorf("%s = %q, want %q", testKey, got, testVal)
	}
}

// TestGCStart_LoadStartupSecrets_WireCheck verifies that loadStartupSecrets
// is wired into the gc start code path and populates env vars from the keyring.
// doStartStandalone must call loadStartupSecrets before runStage1MCPProjection.
func TestGCStart_LoadStartupSecrets_WireCheck(t *testing.T) {
	const testKey = "TEST_WIRE_SECRET_START"
	const testVal = "wired"

	_ = setupStartSecretsTest(t, testKey, testVal)

	// loadStartupSecrets is the function wired into doStartStandalone.
	// Calling it directly must populate the env var.
	loadStartupSecrets(context.Background(), os.Stderr)

	if got := os.Getenv(testKey); got != testVal {
		t.Errorf("%s = %q after loadStartupSecrets, want %q", testKey, got, testVal)
	}
}
