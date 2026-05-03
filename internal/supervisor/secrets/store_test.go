package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// newTestStore returns a *Store rooted at t.TempDir() with a fixed
// passphrase. Mirrors the production constructor's contract while
// skipping passphrase resolution.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	return &Store{dir: t.TempDir(), passphrase: "test-pass"}
}

func TestStore_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("EXA_API_KEY", []byte("sk-exa-12345")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get("EXA_API_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "sk-exa-12345" {
		t.Fatalf("Get: want %q, got %q", "sk-exa-12345", string(got))
	}
	// File mode must be 0600.
	info, err := os.Stat(filepath.Join(s.dir, "EXA_API_KEY"+ageSuffix))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("file mode: want %#o, got %#o", want, got)
	}
}

func TestStore_GetMissingReturnsErrNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Get("NOPE")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestStore_RemoveIdempotent(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("KEY", []byte("val")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Remove("KEY"); err != nil {
		t.Fatalf("Remove (existing): %v", err)
	}
	if err := s.Remove("KEY"); err != nil {
		t.Fatalf("Remove (missing) should be nil, got %v", err)
	}
}

func TestStore_KeysFiltersTmpAndStamp(t *testing.T) {
	s := newTestStore(t)
	if err := s.Set("ALPHA", []byte("a")); err != nil {
		t.Fatalf("Set ALPHA: %v", err)
	}
	if err := s.Set("BETA", []byte("b")); err != nil {
		t.Fatalf("Set BETA: %v", err)
	}
	// Plant junk that must NOT appear in Keys output.
	mustWrite(t, filepath.Join(s.dir, stampFileName), []byte("stamp"))
	mustWrite(t, filepath.Join(s.dir, "GAMMA"+tmpSuffix), []byte("incomplete"))
	mustWrite(t, filepath.Join(s.dir, "README.txt"), []byte("not a secret"))

	got, err := s.Keys()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	sort.Strings(got)
	want := []string{"ALPHA", "BETA"}
	if len(got) != len(want) {
		t.Fatalf("Keys length: want %v, got %v", want, got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("Keys[%d]: want %q, got %q", i, want[i], got[i])
		}
	}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestStore_OpenStampEagerlyWrittenOnEmptyDir(t *testing.T) {
	dir := t.TempDir()
	s, err := openForTest(t, dir, "test-pass")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = s
	stampPath := filepath.Join(dir, stampFileName)
	if _, err := os.Stat(stampPath); err != nil {
		t.Fatalf("stamp should exist after Open on empty dir: %v", err)
	}
}

func TestStore_StaleTmpSweptAtOpen(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "OLD"+tmpSuffix)
	fresh := filepath.Join(dir, "NEW"+tmpSuffix)
	mustWrite(t, stale, []byte("stale"))
	mustWrite(t, fresh, []byte("fresh"))
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	if _, err := openForTest(t, dir, "test-pass"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale .tmp should have been swept; stat err=%v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("fresh .tmp should still be present (in-flight write): %v", err)
	}
}

// openForTest is a thin wrapper around openWithPassphrase that takes a
// passphrase directly, bypassing the resolution chain. The production
// Open() signature does its own resolution; we'll add it in Task 11.
// Until then, openForTest is a private helper used by store_test.go.
func openForTest(t *testing.T, dir, passphrase string) (*Store, error) {
	t.Helper()
	return openWithPassphrase(AgeConfigForTest{Dir: dir}, passphrase)
}

