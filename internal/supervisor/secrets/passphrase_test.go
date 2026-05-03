package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPassphrase_EnvWins(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "from-env")
	dir := t.TempDir()
	keyfile := filepath.Join(dir, ".secrets-passphrase")
	if err := os.WriteFile(keyfile, []byte("from-keyfile"), 0o600); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}
	got, src, err := resolvePassphrase(passphraseSources{KeyfilePath: keyfile})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "from-env" {
		t.Fatalf("want from-env, got %q", got)
	}
	if src != PassphraseSourceEnv {
		t.Fatalf("want PassphraseSourceEnv, got %v", src)
	}
}

func TestPassphrase_KeyfileWhenEnvUnset(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	dir := t.TempDir()
	keyfile := filepath.Join(dir, ".secrets-passphrase")
	if err := os.WriteFile(keyfile, []byte("from-keyfile\n"), 0o600); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}
	got, src, err := resolvePassphrase(passphraseSources{KeyfilePath: keyfile})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "from-keyfile" {
		t.Fatalf("want from-keyfile (trailing \\n stripped), got %q", got)
	}
	if src != PassphraseSourceKeyfile {
		t.Fatalf("want PassphraseSourceKeyfile, got %v", src)
	}
}

func TestPassphrase_KeyfileWorldReadableRejected(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	dir := t.TempDir()
	keyfile := filepath.Join(dir, ".secrets-passphrase")
	if err := os.WriteFile(keyfile, []byte("x"), 0o644); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}
	_, _, err := resolvePassphrase(passphraseSources{KeyfilePath: keyfile})
	if err == nil {
		t.Fatalf("0644 keyfile must be rejected")
	}
	if !strings.Contains(err.Error(), "insecure mode") {
		t.Fatalf("error must mention insecure mode: %v", err)
	}
}

func TestPassphrase_KeyfileGroupReadableRejected(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	dir := t.TempDir()
	keyfile := filepath.Join(dir, ".secrets-passphrase")
	if err := os.WriteFile(keyfile, []byte("x"), 0o640); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}
	_, _, err := resolvePassphrase(passphraseSources{KeyfilePath: keyfile})
	if err == nil || !strings.Contains(err.Error(), "insecure mode") {
		t.Fatalf("0640 keyfile must be rejected; got %v", err)
	}
}

func TestPassphrase_KeyfileSymlinkRejected(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("from-target"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, ".secrets-passphrase")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	_, _, err := resolvePassphrase(passphraseSources{KeyfilePath: link})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked keyfile must be rejected; got %v", err)
	}
}
