package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
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

// Set encrypts value with the store's passphrase and writes <key>.age
// atomically (write to <key>.age.tmp, fsync, rename). Concurrent Set
// of distinct keys is safe via per-file atomic rename. Concurrent Set
// of the SAME key is NOT safe — both writes share the <key>.age.tmp
// path and can corrupt each other before rename; callers must
// serialize Set on the same key. Readers never observe a partially-
// renamed file because Rename is atomic.
func (s *Store) Set(key string, value []byte) error {
	rec, err := age.NewScryptRecipient(s.passphrase)
	if err != nil {
		return fmt.Errorf("age recipient: %w", err)
	}
	tmpPath := filepath.Join(s.dir, key+tmpSuffix)
	finalPath := filepath.Join(s.dir, key+ageSuffix)
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open tmp: %w", err)
	}
	defer os.Remove(tmpPath) // no-op if rename succeeded
	w, err := age.Encrypt(f, rec)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("age encrypt: %w", err)
	}
	if _, err := w.Write(value); err != nil {
		_ = f.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := w.Close(); err != nil {
		_ = f.Close()
		return fmt.Errorf("age close: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	// Best-effort dir.Sync for crash safety; failures here aren't fatal.
	if dirF, err := os.Open(s.dir); err == nil {
		_ = dirF.Sync()
		_ = dirF.Close()
	}
	return nil
}

// Get decrypts <key>.age and returns its plaintext. Returns
// ErrNotFound if the file does not exist.
func (s *Store) Get(key string) ([]byte, error) {
	path := filepath.Join(s.dir, key+ageSuffix)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	id, err := age.NewScryptIdentity(s.passphrase)
	if err != nil {
		return nil, fmt.Errorf("age identity: %w", err)
	}
	r, err := age.Decrypt(f, id)
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", key, err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, fmt.Errorf("read %s: %w", key, err)
	}
	return buf.Bytes(), nil
}

// Remove deletes <key>.age. Idempotent — a missing file is not an
// error.
func (s *Store) Remove(key string) error {
	path := filepath.Join(s.dir, key+ageSuffix)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}
