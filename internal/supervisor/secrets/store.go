package secrets

import (
	"errors"
	"time"
)

// Store is the age-encrypted on-disk secret store. One instance per
// configured cfg.Age.Dir; concurrency-safe for distinct keys via
// per-file atomic rename. See engdocs/design/supervisor-secrets-v0.md.
type Store struct {
	dir        string
	passphrase string
}

// ErrNotFound is returned by Get and other read paths when a configured
// secret has no corresponding <KEY>.age file. Callers (Loader, CLI)
// distinguish it from other errors via errors.Is.
var ErrNotFound = errors.New("secret not found")

// stamp file constants — load-bearing on-disk format. Future format
// changes ship a new versioned name (e.g. -v1) with explicit migration.
const (
	stampFileName  = ".gc-secrets-stamp-v0.age"
	stampPlaintext = "gc-supervisor-secrets-stamp-v0\n"
	tmpSuffix      = ".age.tmp"
	ageSuffix      = ".age"
)

// tmpSweepAge is the mtime threshold for the stale-tmp sweep at Open().
// 5 minutes is dramatically longer than any normal write (milliseconds)
// while short enough that a crashed `gc supervisor secret set` doesn't
// leave junk in the dir indefinitely.
//
// Typed as time.Duration so call sites can subtract it directly:
//
//	cutoff := time.Now().Add(-tmpSweepAge)
//
// rather than the bug-prone `time.Duration(seconds) * time.Second` form.
var tmpSweepAge = 5 * time.Minute
