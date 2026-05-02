package secrets

import (
	"testing"

	"github.com/99designs/keyring"
	"github.com/gastownhall/gascity/internal/supervisor"
)

// fileBackendConfig builds a SecretsConfig pointed at a temp dir for
// hermetic file-backend tests.
func fileBackendConfig(t *testing.T, prefixes []string) supervisor.SecretsConfig {
	t.Helper()
	return supervisor.SecretsConfig{
		Backend: "file",
		File: supervisor.FileBackendConfig{
			Dir:      t.TempDir(),
			Prefixes: prefixes,
		},
	}
}

// fixedFilePrompt returns a deterministic password for the encrypted
// file backend so tests don't prompt interactively.
func fixedFilePrompt() keyring.PromptFunc {
	return func(_ string) (string, error) { return "test-password", nil }
}

func TestOpenKeyring_FileBackend(t *testing.T) {
	cfg := fileBackendConfig(t, nil)
	ring, err := openKeyring(cfg, fixedFilePrompt())
	if err != nil {
		t.Fatalf("openKeyring: %v", err)
	}
	if ring == nil {
		t.Fatal("openKeyring returned nil ring")
	}
}

func TestOpenKeyring_UnknownBackend(t *testing.T) {
	cfg := supervisor.SecretsConfig{Backend: "vault"}
	if _, err := openKeyring(cfg, fixedFilePrompt()); err == nil {
		t.Fatal("openKeyring with unknown backend = nil err, want error")
	}
}

func TestKeyringRoundTrip_FileBackend(t *testing.T) {
	cfg := fileBackendConfig(t, []string{"EXA_API_KEY"})
	ring, err := openKeyring(cfg, fixedFilePrompt())
	if err != nil {
		t.Fatalf("openKeyring: %v", err)
	}

	if err := ring.Set(keyring.Item{Key: "EXA_API_KEY", Data: []byte("sk-test-123")}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	keys, err := ring.Keys()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(keys) != 1 || keys[0] != "EXA_API_KEY" {
		t.Fatalf("Keys = %v, want [EXA_API_KEY]", keys)
	}

	item, err := ring.Get("EXA_API_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(item.Data) != "sk-test-123" {
		t.Fatalf("Get returned %q, want sk-test-123", string(item.Data))
	}
}
