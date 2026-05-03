package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
