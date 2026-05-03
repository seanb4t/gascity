package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// AgeConfigForTest is the test-only minimal config used by
// openWithPassphrase. Production Open (Task 11) takes the real
// supervisor.AgeBackendConfig.
type AgeConfigForTest struct {
	Dir string
}

// openWithPassphrase constructs a *Store, sweeps stale *.age.tmp
// files, then enforces the stamp invariants per the Open() matrix in
// engdocs/design/supervisor-secrets-v0.md:
//
//	hasSecrets=no, stamp=no   -> eager-write stamp, proceed
//	hasSecrets=yes, stamp=yes -> verifies (Task 6)
//	hasSecrets=yes, stamp=no  -> hard error (Task 6)
//
// Production Open() (Task 11) wraps this with passphrase resolution.
func openWithPassphrase(cfg AgeConfigForTest, passphrase string) (*Store, error) {
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", cfg.Dir, err)
	}
	s := &Store{dir: cfg.Dir, passphrase: passphrase}
	if err := s.sweepStaleTmps(); err != nil {
		return nil, err
	}
	if err := s.verifyOrInitStamp(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) sweepStaleTmps() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}
	cutoff := time.Now().Add(-tmpSweepAge)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), tmpSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue // best-effort
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(s.dir, e.Name()))
		}
	}
	return nil
}

// hasSecretsOnDisk reports whether any *.age file other than the
// stamp exists in s.dir.
func (s *Store) hasSecretsOnDisk() (bool, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return false, fmt.Errorf("read dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == stampFileName || strings.HasSuffix(name, tmpSuffix) {
			continue
		}
		if strings.HasSuffix(name, ageSuffix) {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) stampPath() string {
	return filepath.Join(s.dir, stampFileName)
}

func (s *Store) writeStamp() error {
	rec, err := age.NewScryptRecipient(s.passphrase)
	if err != nil {
		return fmt.Errorf("age recipient: %w", err)
	}
	tmp := s.stampPath() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open stamp tmp: %w", err)
	}
	w, err := age.Encrypt(f, rec)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("age encrypt stamp: %w", err)
	}
	if _, err := w.Write([]byte(stampPlaintext)); err != nil {
		_ = f.Close()
		return fmt.Errorf("write stamp: %w", err)
	}
	if err := w.Close(); err != nil {
		_ = f.Close()
		return fmt.Errorf("age close stamp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("fsync stamp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close stamp: %w", err)
	}
	return os.Rename(tmp, s.stampPath())
}

// verifyOrInitStamp implements the Open() invariants matrix from the
// spec. This commit handles only the empty-dir case; the wrong-passphrase
// and stamp-deleted cases are added in Task 6.
func (s *Store) verifyOrInitStamp() error {
	hasSecrets, err := s.hasSecretsOnDisk()
	if err != nil {
		return err
	}
	if _, err := os.Stat(s.stampPath()); err == nil {
		// Stamp present — verification deferred to Task 6.
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat stamp: %w", err)
	}
	// Stamp absent.
	if hasSecrets {
		// Deferred to Task 6: hard error here.
		return nil
	}
	// Empty dir → eager-write stamp.
	return s.writeStamp()
}

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

// Keys returns the names of secrets currently in the store. Filters
// out the stamp sentinel and any *.age.tmp files (in-flight or
// crashed writes). Used by the CLI's `list` command for ORPHAN drift
// detection; not used by the Loader, which gets keys from config.
func (s *Store) Keys() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read dir %s: %w", s.dir, err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == stampFileName {
			continue
		}
		if strings.HasSuffix(name, tmpSuffix) {
			continue
		}
		if !strings.HasSuffix(name, ageSuffix) {
			continue
		}
		out = append(out, strings.TrimSuffix(name, ageSuffix))
	}
	return out, nil
}
