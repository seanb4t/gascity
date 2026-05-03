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

	"github.com/99designs/keyring"
)

// TestSupervisor_LoadsSecretsAtStartup builds the real gc binary, starts a
// supervisor with a file-backend keyring containing EXA_API_KEY, waits for it
// to be healthy, then queries GET /v1/supervisor/secrets/status to confirm the
// secret was loaded. This exercises the full path:
// SecretsConfig → keyring.Open → Loader.LoadAll → os.Setenv → API endpoint.
func TestSupervisor_LoadsSecretsAtStartup(t *testing.T) {
	bin := buildGCBinary(t)

	// Use a short-path root (macOS AF_UNIX path limit ~104 chars).
	root := shortTempDir(t)
	gcHome := filepath.Join(root, "home")
	keyringDir := filepath.Join(gcHome, "secrets")
	runtimeDir := filepath.Join(root, "run")
	for _, dir := range []string{gcHome, keyringDir, runtimeDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	// Seed dolt identity so the supervisor can initialise beads.
	if err := seedDoltIdentityForRoot(gcHome); err != nil {
		t.Fatalf("seed dolt identity: %v", err)
	}

	// Write the secret into the file-backend keyring. We use the same
	// fixed password that the supervisor config will pass at load time.
	const secretValue = "integration-value"
	ring, err := keyring.Open(keyring.Config{
		ServiceName:      "gc-supervisor",
		AllowedBackends:  []keyring.BackendType{keyring.FileBackend},
		FileDir:          keyringDir,
		FilePasswordFunc: func(_ string) (string, error) { return "test-password", nil },
	})
	if err != nil {
		t.Fatalf("open keyring: %v", err)
	}
	if err := ring.Set(keyring.Item{Key: "EXA_API_KEY", Data: []byte(secretValue)}); err != nil {
		t.Fatalf("keyring.Set EXA_API_KEY: %v", err)
	}

	// Write supervisor.toml with a pinned port and the file-backend config.
	port := reserveFreePort(t)
	cfg := fmt.Sprintf(`[supervisor]
port = %d

[secrets]
backend = "file"

[secrets.file]
dir = %q
prefixes = ["EXA_API_KEY"]
`, port, keyringDir)
	if err := os.WriteFile(filepath.Join(gcHome, "supervisor.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("write supervisor.toml: %v", err)
	}

	baseURL := "http://127.0.0.1:" + fmt.Sprint(port)
	env := integrationEnvFor(gcHome, runtimeDir, true)
	// Supply the file-backend password via env so the supervisor doesn't
	// try to open an interactive terminal prompt.
	env = append(env, "GC_SECRETS_FILE_PASSWORD=test-password")

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

	// Wait for the supervisor HTTP server to be ready.
	waitHTTP(t, baseURL+"/health", 15*time.Second)

	// Query the secrets status endpoint and assert EXA_API_KEY is present
	// with the expected SHA-256 fingerprint.
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

	// Find EXA_API_KEY in the response.
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

// TestSupervisor_SIGHUPReload verifies that the supervisor reloads secrets
// when it receives SIGHUP. The assertion path requires sending a SIGHUP and
// querying the status endpoint, which needs a small API client helper that
// doesn't exist yet in the test suite. Scaffold is here; flesh out once the
// helper lands.
func TestSupervisor_SIGHUPReload(t *testing.T) {
	t.Skip("pending API client helper for tests — scaffold present, assertions need query-after-SIGHUP support")
}
