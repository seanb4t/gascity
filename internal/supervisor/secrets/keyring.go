// Package secrets provides config-driven secret loading for the gc
// supervisor. See engdocs/design/supervisor-secrets-v0.md.
package secrets

import (
	"fmt"
	"os"
	"runtime"

	"github.com/99designs/keyring"
	"github.com/gastownhall/gascity/internal/supervisor"
)

const (
	defaultServiceName   = "gc-supervisor"
	defaultAccountSuffix = "@personal"

	// EnvPasswordVar is the environment variable consulted by EnvPasswordPromptFunc.
	// When set, its value is used as the file-backend encryption password without
	// prompting the terminal. Intended for headless deployments and integration
	// tests; MUST NOT be used in interactive sessions where better security is
	// available. Other backends (keychain, secret-service, wincred) ignore it.
	EnvPasswordVar = "GC_SECRETS_FILE_PASSWORD"
)

// EnvPasswordPromptFunc returns a keyring.PromptFunc for the file backend.
// If EnvPasswordVar is set in the environment, that value is returned
// directly (no terminal interaction). Otherwise, keyring.TerminalPrompt
// is used, which reads from the controlling TTY.
func EnvPasswordPromptFunc() func(string) (string, error) {
	if pw := os.Getenv(EnvPasswordVar); pw != "" {
		return func(_ string) (string, error) { return pw, nil }
	}
	return keyring.TerminalPrompt
}

// OpenKeyring translates a SecretsConfig into a keyring.Config and
// opens the appropriate backend. The promptFn is used for backends
// that require a password (e.g., the encrypted file backend); pass
// keyring.TerminalPrompt for production use.
func OpenKeyring(cfg supervisor.SecretsConfig, promptFn keyring.PromptFunc) (keyring.Keyring, error) {
	kcfg := keyring.Config{
		ServiceName:                    serviceName(cfg.Keychain.ServiceName),
		KeychainName:                   "login",
		KeychainTrustApplication:       true,
		KeychainAccessibleWhenUnlocked: true,
		FilePasswordFunc:               promptFn,
	}
	backends, err := allowedBackends(cfg.Backend)
	if err != nil {
		return nil, err
	}
	kcfg.AllowedBackends = backends

	if cfg.Backend == "file" {
		if cfg.File.Dir == "" {
			return nil, fmt.Errorf("secrets.file.dir: required when backend = \"file\"")
		}
		kcfg.FileDir = cfg.File.Dir
	}

	ring, err := keyring.Open(kcfg)
	if err != nil {
		return nil, fmt.Errorf("opening keyring backend %q: %w", cfg.Backend, err)
	}
	return ring, nil
}

// allowedBackends maps our SecretsConfig.Backend string to the
// keyring.BackendType slice. "auto" returns the platform default.
func allowedBackends(name string) ([]keyring.BackendType, error) {
	switch name {
	case "", "auto":
		return platformDefaultBackends(), nil
	case "keychain":
		return []keyring.BackendType{keyring.KeychainBackend}, nil
	case "secret-service":
		return []keyring.BackendType{keyring.SecretServiceBackend}, nil
	case "file":
		return []keyring.BackendType{keyring.FileBackend}, nil
	case "pass":
		return []keyring.BackendType{keyring.PassBackend}, nil
	case "wincred":
		return []keyring.BackendType{keyring.WinCredBackend}, nil
	default:
		return nil, fmt.Errorf("unknown secrets backend %q", name)
	}
}

// platformDefaultBackends returns the preferred backends for "auto"
// mode. Order matters: keyring.Open returns the first available.
func platformDefaultBackends() []keyring.BackendType {
	switch runtime.GOOS {
	case "darwin":
		return []keyring.BackendType{keyring.KeychainBackend}
	case "linux":
		return []keyring.BackendType{keyring.SecretServiceBackend, keyring.PassBackend}
	case "windows":
		return []keyring.BackendType{keyring.WinCredBackend}
	default:
		return nil
	}
}

// serviceName returns the configured service name or the default.
func serviceName(configured string) string {
	if configured != "" {
		return configured
	}
	return defaultServiceName
}

// resolveAccount returns the account string to use for keyring
// operations. Defaults to "$USER@personal" if not configured.
func resolveAccount(configured string) string {
	if configured != "" {
		return configured
	}
	user := os.Getenv("USER")
	if user == "" {
		user = "unknown"
	}
	return user + defaultAccountSuffix
}
