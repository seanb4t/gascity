package secrets

import (
	"errors"
	"fmt"
	"os"
	"strings"
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
	// Keychain bootstrap and TTY prompt land in Tasks 8 and 9.
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
