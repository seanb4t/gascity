package secrets

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/99designs/keyring"
	"github.com/gastownhall/gascity/internal/supervisor"
)

// Result is returned by LoadAll. Each slice is sorted for stable output
// in logs and tests.
type Result struct {
	Set     []string // env vars successfully set
	Missing []string // configured prefixes that matched zero items
	Skipped []string // matched items whose value was empty
	Errors  []error  // per-prefix or per-item errors (non-fatal)
}

// Loader holds the state needed to perform full-sync reloads. A
// single Loader instance lives for the supervisor process lifetime.
type Loader struct {
	prompt  keyring.PromptFunc
	mu      sync.Mutex
	lastSet map[string]struct{}
}

// NewLoader returns a Loader that uses promptFn for backends needing
// a password (the encrypted file backend). Pass keyring.TerminalPrompt
// for production; pass a fixed-string prompt in tests.
func NewLoader(promptFn keyring.PromptFunc) *Loader {
	return &Loader{
		prompt:  promptFn,
		lastSet: make(map[string]struct{}),
	}
}

// LoadAll opens the configured backend, enumerates matching keys for
// each prefix, and sets corresponding env vars via os.Setenv. The
// returned error is non-nil only when the backend itself fails to
// open or enumerate; per-prefix and per-item failures appear in
// Result.Errors and never escalate to a fatal error.
func (l *Loader) LoadAll(ctx context.Context, cfg supervisor.SecretsConfig) (Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	res := Result{}

	ring, err := openKeyring(cfg, l.prompt)
	if err != nil {
		return res, err
	}

	keys, err := ring.Keys()
	if err != nil {
		return res, fmt.Errorf("listing keyring keys: %w", err)
	}

	prefixes := loaderPrefixes(cfg)
	nextSet := make(map[string]struct{})

	for _, prefix := range prefixes {
		matches := filterByPrefix(keys, prefix)
		if len(matches) == 0 {
			res.Missing = append(res.Missing, prefix)
			continue
		}
		for _, key := range matches {
			item, err := ring.Get(key)
			if err != nil {
				res.Errors = append(res.Errors, fmt.Errorf("get %s: %w", key, err))
				continue
			}
			if len(item.Data) == 0 {
				res.Skipped = append(res.Skipped, key)
				continue
			}
			os.Setenv(key, string(item.Data))
			res.Set = append(res.Set, key)
			nextSet[key] = struct{}{}
		}
	}

	sort.Strings(res.Set)
	sort.Strings(res.Missing)
	sort.Strings(res.Skipped)
	l.lastSet = nextSet
	return res, nil
}

// loaderPrefixes returns the prefix list relevant to the configured
// backend.
func loaderPrefixes(cfg supervisor.SecretsConfig) []string {
	if cfg.Backend == "file" {
		return cfg.File.Prefixes
	}
	return cfg.Keychain.Prefixes
}

// filterByPrefix returns all keys that have the given prefix, sorted.
func filterByPrefix(keys []string, prefix string) []string {
	out := make([]string, 0)
	for _, k := range keys {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
