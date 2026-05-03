// Package secrets provides config-driven secret loading for the gc
// supervisor. See engdocs/design/supervisor-secrets-v0.md.
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
	"github.com/gastownhall/gascity/internal/supervisor"
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

// Open returns an age-backed *Store ready for Get/Set/Remove/Keys.
// It resolves the passphrase via the env→keyfile→Keychain→TTY chain,
// sweeps stale *.age.tmp files, and enforces the stamp invariants
// matrix from engdocs/design/supervisor-secrets-v0.md.
//
// Defaults computed from cfg.Dir / cfg.PassphraseFile / cfg.PassphraseKeychainAccount
// when those fields are empty. Default Dir / PassphraseFile use
// supervisor.DefaultHome() — which panics in test binaries unless
// GC_HOME is set. Tests must either pass cfg.Dir explicitly OR set
// t.Setenv("GC_HOME", t.TempDir()) before calling Open.
func Open(cfg supervisor.AgeBackendConfig) (*Store, error) {
	dir := cfg.Dir
	if dir == "" {
		dir = filepath.Join(supervisor.DefaultHome(), "secrets")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	keyfile := cfg.PassphraseFile
	if keyfile == "" {
		keyfile = filepath.Join(supervisor.DefaultHome(), ".secrets-passphrase")
	}
	account := cfg.PassphraseKeychainAccount
	if account == "" {
		if u := os.Getenv("USER"); u != "" {
			account = u + "@personal"
		}
	}
	passphrase, _, err := resolvePassphrase(passphraseSources{
		KeyfilePath:     keyfile,
		KeychainAccount: account,
	})
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, passphrase: passphrase}
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
	defer os.Remove(tmp) // no-op if rename succeeded
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

// verifyOrInitStamp implements the Open() invariants matrix from the spec:
//
//	hasSecrets=no, stamp=no   -> eager-write stamp, proceed
//	stamp=yes (any)           -> verify stamp matches current passphrase
//	hasSecrets=yes, stamp=no  -> hard error (stamp deleted or passphrase rotated)
func (s *Store) verifyOrInitStamp() error {
	hasSecrets, err := s.hasSecretsOnDisk()
	if err != nil {
		return err
	}
	_, statErr := os.Stat(s.stampPath())
	stampPresent := statErr == nil
	if !stampPresent && !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("stat stamp: %w", statErr)
	}

	switch {
	case !hasSecrets && !stampPresent:
		// Brand-new install — eager-write the stamp under the resolved passphrase.
		return s.writeStamp()
	case stampPresent:
		// Stamp present (with or without secrets) — verify it matches the
		// current passphrase. This catches the wrong-passphrase case for
		// non-empty stores AND the empty-but-init'd case where someone
		// re-opens before the first Set.
		return s.verifyStamp()
	case hasSecrets && !stampPresent:
		return fmt.Errorf(
			"secrets: stamp file missing but %s contains existing .age files; "+
				"refusing to proceed. If you rotated the passphrase, run "+
				"'gc supervisor secret rotate-passphrase' (deferred to v2). "+
				"Until then, the safe recovery is: (a) restore the stamp from backup, "+
				"or (b) 'rm %s/*.age && gc supervisor secret set ...' to start fresh",
			s.dir, s.dir,
		)
	}
	return nil
}

// verifyStamp decrypts the stamp file and confirms its plaintext matches
// stampPlaintext. Returns a clear error if the passphrase is wrong.
func (s *Store) verifyStamp() error {
	f, err := os.Open(s.stampPath())
	if err != nil {
		return fmt.Errorf("open stamp: %w", err)
	}
	defer f.Close()
	id, err := age.NewScryptIdentity(s.passphrase)
	if err != nil {
		return fmt.Errorf("age identity: %w", err)
	}
	r, err := age.Decrypt(f, id)
	if err != nil {
		return fmt.Errorf(
			"secrets: passphrase does not match existing store at %s; "+
				"refusing to open. If you rotated the passphrase, re-encrypt "+
				"the store with 'gc supervisor secret rotate-passphrase' "+
				"(deferred to v2; until then, the manual recovery is: delete "+
				"%s/*.age and re-run 'gc supervisor secret set' for each key)",
			s.dir, s.dir,
		)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return fmt.Errorf("read stamp: %w", err)
	}
	if buf.String() != stampPlaintext {
		return fmt.Errorf(
			"secrets: stamp file at %s decoded to unexpected plaintext; "+
				"this should never happen — the on-disk format may be from a "+
				"newer gc version. Check the stamp filename version suffix.",
			s.stampPath(),
		)
	}
	return nil
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
