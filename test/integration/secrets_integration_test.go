//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	supervisor "github.com/gastownhall/gascity/internal/supervisor"
	"github.com/gastownhall/gascity/internal/supervisor/secrets"
)

// seedAgeStoreForIntegration creates a secrets.Store rooted at
// filepath.Join(gcHome, "secrets") and writes each key→value pair into it.
// GC_SECRETS_PASSPHRASE is set to "test-pass" for the duration of the test.
func seedAgeStoreForIntegration(t *testing.T, gcHome string, items map[string]string) {
	t.Helper()
	// GC_HOME must be set so secrets.Open can resolve the default passphrase
	// keyfile path (supervisor.DefaultHome panics in test binaries without it).
	t.Setenv("GC_HOME", gcHome)
	t.Setenv(secrets.EnvPassphraseVar, "test-pass")
	secretsDir := filepath.Join(gcHome, "secrets")
	if err := os.MkdirAll(secretsDir, 0o700); err != nil {
		t.Fatalf("mkdir secrets dir: %v", err)
	}
	keys := make([]string, 0, len(items))
	for k := range items {
		keys = append(keys, k)
	}
	cfg := supervisor.AgeBackendConfig{Dir: secretsDir, Keys: keys}
	store, err := secrets.Open(cfg)
	if err != nil {
		t.Fatalf("secrets.Open: %v", err)
	}
	for k, v := range items {
		if err := store.Set(k, []byte(v)); err != nil {
			t.Fatalf("Set %s: %v", k, err)
		}
	}
}

// TestSupervisor_LoadsAgeSecretsAtStartup builds the real gc binary, starts a
// supervisor with an age-encrypted store containing EXA_API_KEY, waits for it
// to be healthy, then queries GET /v1/supervisor/secrets/status to confirm the
// secret was loaded. This exercises the full path:
// SecretsConfig → secrets.Open → Loader.LoadAll → os.Setenv → API endpoint.
func TestSupervisor_LoadsAgeSecretsAtStartup(t *testing.T) {
	bin := buildGCBinary(t)

	// Use a short-path root (macOS AF_UNIX path limit ~104 chars).
	root := shortTempDir(t)
	gcHome := filepath.Join(root, "home")
	secretsDir := filepath.Join(gcHome, "secrets")
	runtimeDir := filepath.Join(root, "run")
	for _, dir := range []string{gcHome, secretsDir, runtimeDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	// Seed dolt identity so the supervisor can initialise beads.
	if err := seedDoltIdentityForRoot(gcHome); err != nil {
		t.Fatalf("seed dolt identity: %v", err)
	}

	// Write the secret into the age store.
	const secretValue = "integration-value"
	seedAgeStoreForIntegration(t, gcHome, map[string]string{
		"EXA_API_KEY": secretValue,
	})

	port := reserveFreePort(t)
	cfg := fmt.Sprintf(`[supervisor]
port = %d

[secrets.age]
dir = %q
keys = ["EXA_API_KEY"]
`, port, secretsDir)
	if err := os.WriteFile(filepath.Join(gcHome, "supervisor.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write supervisor.toml: %v", err)
	}

	baseURL := "http://127.0.0.1:" + fmt.Sprint(port)
	env := integrationEnvFor(gcHome, runtimeDir, true)
	// Supply the age passphrase via env so the supervisor doesn't prompt.
	env = append(env, secrets.EnvPassphraseVar+"=test-pass")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, bin, "supervisor", "run")
	cmd.Env = env

	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start supervisor: %v", err)
	}
	var supervisorLog strings.Builder
	go func() { _, _ = io.Copy(&supervisorLog, stderr) }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("supervisor stderr:\n%s", supervisorLog.String())
		}
	})

	waitHTTP(t, baseURL+"/health", 15*time.Second)

	statusURL := baseURL + "/v1/supervisor/secrets/status"
	resp, err := http.Get(statusURL)
	if err != nil {
		t.Fatalf("GET %s: %v", statusURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s: status %d\nbody: %s", statusURL, resp.StatusCode, body)
	}

	var status struct {
		Secrets []struct {
			Name   string `json:"name"`
			Length int    `json:"length"`
			SHA256 string `json:"sha256"`
		} `json:"secrets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode secrets status: %v", err)
	}

	var found bool
	expectedHash := func() string {
		sum := sha256.Sum256([]byte(secretValue))
		return hex.EncodeToString(sum[:])
	}()
	for _, s := range status.Secrets {
		if s.Name == "EXA_API_KEY" {
			found = true
			if s.Length != len(secretValue) {
				t.Errorf("EXA_API_KEY length = %d, want %d", s.Length, len(secretValue))
			}
			if s.SHA256 != expectedHash {
				t.Errorf("EXA_API_KEY sha256 = %q, want %q", s.SHA256, expectedHash)
			}
		}
	}
	if !found {
		t.Errorf("EXA_API_KEY not found in secrets status; got %d secrets: %+v", len(status.Secrets), status.Secrets)
	}
}

// TestSupervisor_AgeSIGHUPReload verifies cross-process SIGHUP secret reload.
// Reload logic is covered by unit tests (TestSecretsReload_RoundTrip, TestReload_*);
// this test adds signal-delivery coverage once a shared HTTP test client exists.
func TestSupervisor_AgeSIGHUPReload(t *testing.T) {
	t.Skip("TODO: requires a gc API test client helper to assert SHA-256 change after SIGHUP")
}
