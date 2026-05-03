package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/gastownhall/gascity/internal/supervisor"
)

// Result is returned by LoadAll. Each slice is sorted for stable output
// in logs and tests.
type Result struct {
	Set     []string // env vars successfully set
	Missing []string // configured keys with no <KEY>.age file in the store
	Skipped []string // keys whose value was empty
	Errors  []error  // per-key errors (non-fatal)
}

// Loader holds the state needed to perform full-sync reloads. A
// single Loader instance lives for the supervisor process lifetime.
type Loader struct {
	mu      sync.Mutex
	lastSet map[string]struct{}
}

// NewLoader returns a Loader. Passphrase resolution happens inside
// Open() at LoadAll/Reload time via the env→keyfile→Keychain→TTY chain.
func NewLoader() *Loader {
	return &Loader{
		lastSet: make(map[string]struct{}),
	}
}

// LoadAll opens the configured age store, reads each configured key,
// and sets corresponding env vars via os.Setenv. The returned error is
// non-nil only when the store itself fails to open; per-key failures
// (missing/empty/decrypt-error) appear in Result and never escalate.
func (l *Loader) LoadAll(ctx context.Context, cfg supervisor.SecretsConfig) (Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	res := Result{}

	store, err := Open(cfg.Age)
	if err != nil {
		return res, err
	}

	nextSet := make(map[string]struct{})
	for _, key := range cfg.Age.Keys {
		data, err := store.Get(key)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				res.Missing = append(res.Missing, key)
				continue
			}
			res.Errors = append(res.Errors, fmt.Errorf("get %s: %w", key, err))
			continue
		}
		if len(data) == 0 {
			res.Skipped = append(res.Skipped, key)
			continue
		}
		os.Setenv(key, string(data))
		res.Set = append(res.Set, key)
		nextSet[key] = struct{}{}
	}

	sort.Strings(res.Set)
	sort.Strings(res.Missing)
	sort.Strings(res.Skipped)
	l.lastSet = nextSet
	return res, nil
}

// ReloadResult extends Result with diff information showing what
// changed since the previous LoadAll/Reload call.
type ReloadResult struct {
	Result
	Added   []string // env vars set this reload that weren't set before
	Updated []string // env vars whose values changed
	Removed []string // env vars unset this reload (not in store anymore)
}

// Reload re-reads the age store and reconciles env state. Keys
// removed from the store since the last load are os.Unsetenv'd;
// new and changed keys are os.Setenv'd. Reload is idempotent.
func (l *Loader) Reload(ctx context.Context, cfg supervisor.SecretsConfig) (ReloadResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	rr := ReloadResult{}

	store, err := Open(cfg.Age)
	if err != nil {
		return rr, err
	}

	nextSet := make(map[string]struct{})
	for _, key := range cfg.Age.Keys {
		data, err := store.Get(key)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				if _, wasSet := l.lastSet[key]; !wasSet {
					// Newly missing — was never loaded.
					rr.Missing = append(rr.Missing, key)
				}
				// Else: was loaded last time; the trailing lastSet
				// diff loop will report it as Removed. Avoid the
				// double-classification (Missing + Removed) for the
				// same key.
				continue
			}
			rr.Errors = append(rr.Errors, fmt.Errorf("get %s: %w", key, err))
			continue
		}
		if len(data) == 0 {
			rr.Skipped = append(rr.Skipped, key)
			continue
		}
		newVal := string(data)
		oldVal, hadBefore := os.LookupEnv(key)
		os.Setenv(key, newVal)
		rr.Set = append(rr.Set, key)
		nextSet[key] = struct{}{}

		switch {
		case !hadBefore || !l.wasInLastSet(key):
			rr.Added = append(rr.Added, key)
		case oldVal != newVal:
			rr.Updated = append(rr.Updated, key)
		}
	}

	// Remove env vars that were set on previous load but no longer
	// appear in the store.
	for key := range l.lastSet {
		if _, stillPresent := nextSet[key]; stillPresent {
			continue
		}
		os.Unsetenv(key)
		rr.Removed = append(rr.Removed, key)
	}

	sort.Strings(rr.Set)
	sort.Strings(rr.Missing)
	sort.Strings(rr.Skipped)
	sort.Strings(rr.Added)
	sort.Strings(rr.Updated)
	sort.Strings(rr.Removed)
	l.lastSet = nextSet
	return rr, nil
}

func (l *Loader) wasInLastSet(key string) bool {
	_, ok := l.lastSet[key]
	return ok
}

// Names returns the names of env vars the loader set on its most
// recent LoadAll/Reload. Used by the supervisor's HTTP API to report
// drift status without ever exposing values.
func (l *Loader) Names() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.lastSet))
	for k := range l.lastSet {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
