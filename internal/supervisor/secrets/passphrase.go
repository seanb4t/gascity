package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/term"
)

// EnvPassphraseVar is the env var consulted first by the resolution
// chain. Replaces the CGo branch's GC_SECRETS_FILE_PASSWORD.
const EnvPassphraseVar = "GC_SECRETS_PASSPHRASE"

// PassphraseSource identifies which step in the resolution chain
// produced the passphrase. The CLI's `set` command surfaces it on
// first-secret commit so the user can sanity-check the chain.
type PassphraseSource int

const (
	PassphraseSourceUnset    PassphraseSource = iota
	PassphraseSourceEnv
	PassphraseSourceKeyfile
	PassphraseSourceKeychain
	PassphraseSourcePrompt
)

// String returns a human-readable description of the passphrase source.
func (p PassphraseSource) String() string {
	switch p {
	case PassphraseSourceEnv:
		return "GC_SECRETS_PASSPHRASE"
	case PassphraseSourceKeyfile:
		return "keyfile"
	case PassphraseSourceKeychain:
		return "macOS Keychain"
	case PassphraseSourcePrompt:
		return "interactive prompt"
	default:
		return "<unset>"
	}
}

// passphraseSources captures the resolution-chain inputs. Tests
// construct one directly; production code (Task 11) builds it from
// supervisor.AgeBackendConfig.
type passphraseSources struct {
	KeyfilePath     string
	KeychainAccount string // empty disables Keychain bootstrap
	NoTTY           bool   // tests force this true to avoid stdin reads
	LogFn           func(format string, args ...interface{})
}

// resolvePassphrase walks the env → keyfile → Keychain → TTY chain.
// Returns the passphrase, which step produced it, or a wrapped error
// describing why no source was usable.
func resolvePassphrase(sources passphraseSources) (string, PassphraseSource, error) {
	if v := os.Getenv(EnvPassphraseVar); v != "" {
		return v, PassphraseSourceEnv, nil
	}
	if sources.KeyfilePath != "" {
		v, err := readKeyfile(sources.KeyfilePath)
		if err != nil {
			if !errors.Is(err, errKeyfileMissing) {
				return "", PassphraseSourceUnset, err
			}
			// fall through: keyfile not present is not an error, it just
			// skips this resolution step.
		} else if v != "" {
			return v, PassphraseSourceKeyfile, nil
		}
	}
	if v, ok, err := keychainBootstrap(sources.KeychainAccount, sources.logger()); err != nil {
		return "", PassphraseSourceUnset, err
	} else if ok {
		return v, PassphraseSourceKeychain, nil
	}
	if v, ok := promptForPassphrase(sources); ok && v != "" {
		return v, PassphraseSourcePrompt, nil
	}
	return "", PassphraseSourceUnset, errPassphraseNoSources(sources.KeyfilePath)
}

var errKeyfileMissing = errors.New("keyfile not present")

func readKeyfile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", errKeyfileMissing
		}
		return "", fmt.Errorf("lstat keyfile %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("passphrase file %s is a symlink; refuse to follow", path)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("passphrase file %s is not a regular file (mode %v)", path, info.Mode())
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("passphrase file %s has insecure mode %#o; chmod 0600", path, perm)
	}
	if err := checkKeyfileOwner(path, info); err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read keyfile %s: %w", path, err)
	}
	return strings.TrimRight(string(data), "\n"), nil
}

func errPassphraseNoSources(keyfilePath string) error {
	return fmt.Errorf(
		"no passphrase: set %s, place a 0600 keyfile at %s, on macOS seed the "+
			"gc-supervisor-passphrase Keychain item, or run interactively",
		EnvPassphraseVar, keyfilePath,
	)
}

// cmdRunner abstracts os/exec for tests. Production sets the package
// variable to a real implementation; tests override.
type cmdRunner interface {
	Run(ctx context.Context, name string, args ...string) (stdout []byte, exitCode int, err error)
}

// detectGOOS is a package var so tests can pin it.
var detectGOOS = func() string { return runtime.GOOS }

// keychainCmdRunner is the production runner — wraps exec.CommandContext.
// Tests assign a fake to this var.
var keychainCmdRunner cmdRunner = realCmdRunner{}

type realCmdRunner struct{}

func (realCmdRunner) Run(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err == nil {
		return out, 0, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return out, exitErr.ExitCode(), nil
	}
	return out, -1, err
}

// keychainServiceName is the service-name for the passphrase-bootstrap
// Keychain item. Constant; users seed it once via `security add-generic-password`.
const keychainServiceName = "gc-supervisor-passphrase"

// keychainTimeoutVar is the deadline for the security subprocess.
// Declared as a var (not const) so overrideKeychainTimeoutForTest can
// swap it for fast tests.
var keychainTimeoutVar = 5 * time.Second

// overrideKeychainTimeoutForTest swaps the production timeout. Returns
// a restore func suitable for t.Cleanup.
func overrideKeychainTimeoutForTest(d time.Duration) func() {
	prev := keychainTimeoutVar
	keychainTimeoutVar = d
	return func() { keychainTimeoutVar = prev }
}

// keychainBootstrap runs `security find-generic-password -s gc-supervisor-passphrase -a $account -w`
// with a 5s timeout. Returns the passphrase + true if found, false +
// error if not (caller falls through). Empty stdout is treated as
// ERROR-and-fall-through to prevent a mis-set Keychain item from
// silently producing an empty-passphrase store.
func keychainBootstrap(account string, logger func(format string, args ...interface{})) (string, bool, error) {
	if detectGOOS() != "darwin" {
		return "", false, nil
	}
	if account == "" {
		return "", false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), keychainTimeoutVar)
	defer cancel()
	stdout, code, err := keychainCmdRunner.Run(ctx, "security",
		"find-generic-password", "-s", keychainServiceName, "-a", account, "-w")
	if ctx.Err() == context.DeadlineExceeded {
		logger("WARN: macOS Keychain lookup for gc-supervisor-passphrase timed out after %s; is the login keychain locked?", keychainTimeoutVar)
		return "", false, nil
	}
	if err != nil && code == -1 {
		// command failed to spawn (e.g. /usr/bin/security missing)
		logger("WARN: macOS Keychain bootstrap: %v", err)
		return "", false, nil
	}
	switch code {
	case 0:
		passphrase := strings.TrimRight(string(stdout), "\n")
		if passphrase == "" {
			logger(
				"ERROR: macOS Keychain bootstrap returned empty passphrase. "+
					"The gc-supervisor-passphrase item is mis-set. Re-seed with: "+
					"security add-generic-password -U -s gc-supervisor-passphrase -a %q -w",
				account,
			)
			return "", false, nil
		}
		return passphrase, true, nil
	case 44:
		// Item not found.
		return "", false, nil
	default:
		logger("WARN: macOS Keychain bootstrap exit %d: %s", code, strings.TrimSpace(string(stdout)))
		return "", false, nil
	}
}

// promptForPassphrase reads from the controlling TTY without echo.
// Returns (passphrase, true) on success; ("", false) on non-TTY or
// read error. Tests force NoTTY=true to bypass entirely.
func promptForPassphrase(sources passphraseSources) (string, bool) {
	if sources.NoTTY {
		return "", false
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", false
	}
	fmt.Fprint(os.Stderr, "Passphrase: ")
	bytes, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", false
	}
	return string(bytes), true
}

// logger returns the log function for passphraseSources, defaulting to stderr.
func (s passphraseSources) logger() func(format string, args ...interface{}) {
	if s.LogFn != nil {
		return s.LogFn
	}
	return func(format string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, "secrets: "+format+"\n", args...)
	}
}
