package secrets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// fakeCmdRunner records calls and returns canned output.
type fakeCmdRunner struct {
	stdout []byte
	code   int
	err    error
	calls  [][]string
	delay  time.Duration
}

func (f *fakeCmdRunner) Run(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, -1, ctx.Err()
		}
	}
	return f.stdout, f.code, f.err
}

func withFakeRunner(t *testing.T, r *fakeCmdRunner) {
	t.Helper()
	prev := keychainCmdRunner
	keychainCmdRunner = r
	t.Cleanup(func() { keychainCmdRunner = prev })
}

func withGOOS(t *testing.T, goos string) {
	t.Helper()
	prev := detectGOOS
	detectGOOS = func() string { return goos }
	t.Cleanup(func() { detectGOOS = prev })
}

func TestPassphrase_KeychainBootstrap(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	withGOOS(t, "darwin")
	withFakeRunner(t, &fakeCmdRunner{stdout: []byte("from-keychain\n"), code: 0})
	got, src, err := resolvePassphrase(passphraseSources{KeychainAccount: "user@personal"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "from-keychain" {
		t.Fatalf("want from-keychain, got %q", got)
	}
	if src != PassphraseSourceKeychain {
		t.Fatalf("want PassphraseSourceKeychain, got %v", src)
	}
}

func TestPassphrase_KeychainBootstrapEmptyStringRejected(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	withGOOS(t, "darwin")
	var logs []string
	logFn := func(format string, args ...interface{}) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}
	withFakeRunner(t, &fakeCmdRunner{stdout: []byte(""), code: 0})
	_, _, err := resolvePassphrase(passphraseSources{
		KeychainAccount: "user@personal",
		LogFn:           logFn,
	})
	if err == nil || !strings.Contains(err.Error(), "no passphrase") {
		t.Fatalf("empty-keychain must fall through to no-sources error; got %v", err)
	}
	matched := false
	for _, l := range logs {
		if strings.Contains(l, "ERROR:") && strings.Contains(l, "empty passphrase") {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("expected ERROR-level log about empty passphrase; got logs=%v", logs)
	}
}

func TestPassphrase_KeychainBootstrapExit44(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	withGOOS(t, "darwin")
	withFakeRunner(t, &fakeCmdRunner{code: 44})
	_, _, err := resolvePassphrase(passphraseSources{KeychainAccount: "user@personal"})
	if err == nil || !strings.Contains(err.Error(), "no passphrase") {
		t.Fatalf("exit 44 must fall through; got %v", err)
	}
}

func TestPassphrase_KeychainBootstrapTimeout(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	withGOOS(t, "darwin")
	// Force a timeout shorter than the production 5s for test speed.
	withFakeRunner(t, &fakeCmdRunner{delay: 50 * time.Millisecond})
	restore := overrideKeychainTimeoutForTest(10 * time.Millisecond)
	t.Cleanup(restore)
	_, _, err := resolvePassphrase(passphraseSources{KeychainAccount: "user@personal"})
	if err == nil || !strings.Contains(err.Error(), "no passphrase") {
		t.Fatalf("timeout must fall through; got %v", err)
	}
}

func TestPassphrase_KeychainBootstrapNonDarwinSkipped(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	withGOOS(t, "linux")
	r := &fakeCmdRunner{stdout: []byte("ignored"), code: 0}
	withFakeRunner(t, r)
	_, _, err := resolvePassphrase(passphraseSources{KeychainAccount: "user@personal"})
	if err == nil {
		t.Fatalf("non-darwin: must fall through to no-sources error")
	}
	if len(r.calls) != 0 {
		t.Fatalf("non-darwin must not invoke security; got calls=%v", r.calls)
	}
}

func TestPassphrase_NonTTYNoSourcesFails(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	dir := t.TempDir()
	_, _, err := resolvePassphrase(passphraseSources{
		KeyfilePath: filepath.Join(dir, ".secrets-passphrase"),
		NoTTY:       true,
	})
	if err == nil {
		t.Fatalf("no sources + non-TTY: want error, got nil")
	}
	for _, want := range []string{
		"GC_SECRETS_PASSPHRASE",
		"0600 keyfile",
		"gc-supervisor-passphrase",
		"interactively",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error must mention %q; got %v", want, err)
		}
	}
}
