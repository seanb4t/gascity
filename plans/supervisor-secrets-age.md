# Supervisor Secrets (age) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the CGo-branch's `99designs/keyring` backend with pure-Go age-encrypted file storage so the gc binary keeps `CGO_ENABLED=0` while preserving the supervisor-managed secret loading feature surface.

**Architecture:** New `*secrets.Store` concrete type stores each secret as `<KEY>.age` under `cfg.Age.Dir` with passphrase-derived (scrypt) age recipients. Single passphrase resolved via env → 0600 keyfile → macOS Keychain bootstrap → TTY prompt. Stamp file `.gc-secrets-stamp-v0.age` enforces passphrase-store consistency at `Open()`. The Loader, CLI, and `/v1/supervisor/secrets/status` API endpoint stay shape-identical to the CGo branch but consume `*Store` directly (no `Backend` interface — single concrete type per AGENTS.md).

**Tech Stack:** Go (CGO_ENABLED=0), `filippo.io/age` (pure-Go, MIT), existing `github.com/BurntSushi/toml`, `github.com/spf13/cobra`, `golang.org/x/term`, `os/exec` (only for the macOS Keychain passphrase bootstrap).

**Spec:** `engdocs/design/supervisor-secrets-v0.md` (HEAD `b4daa9ed`).

**Branch:** `feat/supervisor-secrets-age` (already created off `feat/supervisor-secrets-keychain` HEAD; three doc-pivot commits already in place).

**Project conventions (AGENTS.md):** TDD; tests next to code as `*_test.go`; conventional commits; atomic per logical change; never commit `--no-verify`; `bd` for task tracking, never `TodoWrite`/`TaskCreate`.

---

## File map

This branch inherits the entire CGo-branch tree. Most files **stay**; only the secrets backend layer changes.

**New files:**
- `internal/supervisor/secrets/store.go` — `Store` struct, `Open()`, CRUD, `ErrNotFound`, stamp invariants, `.tmp` sweep
- `internal/supervisor/secrets/store_test.go` — round-trip + stamp matrix + sweep + concurrency tests
- `internal/supervisor/secrets/passphrase.go` — env → keyfile → Keychain → TTY resolution chain
- `internal/supervisor/secrets/passphrase_test.go` — chain tests with cmdRunner fake + Lstat/UID/mode tests

**Modified files:**
- `go.mod` / `go.sum` — add `filippo.io/age`; later remove `github.com/99designs/keyring` and `github.com/99designs/go-keychain`
- `internal/supervisor/config.go` — drop `KeychainBackendConfig` + `FileBackendConfig` + `Backend` field; add `AgeBackendConfig` with `Dir` / `PassphraseFile` / `PassphraseKeychainAccount` / `Keys`; rewrite `Validate`; switch to strict TOML decode in `LoadConfig`
- `internal/supervisor/config_test.go` — replace prefix/file-backend tests with age-shape tests + strict-decode test
- `internal/supervisor/secrets/secrets.go` — drop `keyring.PromptFunc` arg from `NewLoader`; replace `OpenKeyring` calls with `Open(cfg.Age)`; replace `keyring.Item` returns with `[]byte` + `ErrNotFound`
- `internal/supervisor/secrets/secrets_test.go` — replace `seedFileKeyring` helper with `seedAgeStore`; drop `99designs/keyring` import
- `cmd/gc/cmd_supervisor.go` — `runSupervisor` calls `secrets.NewLoader()` (no promptFn arg) and `LoadAll(ctx, supCfg.Secrets)`; the Missing-loop's `WARN: secrets prefix %q matched zero items in keyring` log gets reworded to `secrets key %q not present in age store`
- `cmd/gc/cmd_supervisor_secret.go` — replace `secrets.OpenKeyring` + `keyring.Item` with `*secrets.Store`; replace `keyring.ErrKeyNotFound` with `secrets.ErrNotFound`; rewrite `newSupervisorSecretImportEnvCmd` to print `[secrets.age] keys = [...]` instead of `[secrets.keychain] prefixes = [...]`; rewrite `buildSecretRows` to use exact-match `cfg.Secrets.Age.Keys` instead of prefix scan over `cfg.Secrets.Keychain.Prefixes` / `cfg.Secrets.File.Prefixes`; delete dead helpers `backendOrAuto`, `secretPromptFn`; add overwrite confirmation in `set`
- `cmd/gc/cmd_supervisor_secret_test.go` — replace `keyring.Config{FileBackend...}` test seeding with `*Store` + temp-dir + `t.Setenv("GC_SECRETS_PASSPHRASE", ...)`; add `TestSet_NewKey`, `TestSet_OverwritePromptsWithoutForce`, `TestSet_OverwriteWithForceSkipsPrompt`, `TestSet_FromStdinNoPrompt`
- `cmd/gc/cmd_supervisor_lifecycle_secrets_test.go` — same seeding swap; update the assertion on the WARN log line wording
- `cmd/gc/cmd_start_secrets_test.go` — same seeding swap
- `test/integration/secrets_integration_test.go` — same seeding swap; rename `TestSupervisor_*Keyring*` → `TestSupervisor_*Age*`
- `.goreleaser.yml` — revert `CGO_ENABLED=1` → `CGO_ENABLED=0`; remove `overrides:` block (CGo cross-toolchain envs)
- `.github/workflows/release.yml` — replace docker-run-goreleaser-cross step with the original `goreleaser/goreleaser-action` step
- `.github/workflows/rc-gate.yml` — same revert

**Deleted files:**
- `internal/supervisor/secrets/keyring.go`
- `internal/supervisor/secrets/keyring_test.go`

**Files to leave in place (DO NOT DELETE):**
- `internal/supervisor/secrets/testenv_import_test.go` — generated by `scripts/add-testenv-import.go`, enforced by `TestRequiresDedicatedTestenvImportFile` in `internal/testenv/lint_test.go`. Required for the testenv leak-vector env-var scrub to apply to this package's test binary. Earlier drafts of this plan misclassified it as a "5-line stub" — that's wrong; deleting it breaks repo-wide testenv lint.

---

## Task 1: Revert release-pipeline CGo switches

**Files:**
- Modify: `.goreleaser.yml`
- Modify: `.github/workflows/release.yml`
- Modify: `.github/workflows/rc-gate.yml`

This task is independent of any Go code change; it just restores the project's pre-CGo-branch release configuration. Must be done first because the spec's distribution-constraints invariant (`CGO_ENABLED=0 go build ./...` succeeds) is a quality gate at every later commit.

- [ ] **Step 1: Read the keychain-branch's pre-CGo `.goreleaser.yml` from git history**

```bash
git show feat/supervisor-secrets-keychain^^:.goreleaser.yml
# Use this as the reference for what to restore. (^^ = two commits before
# the CGo switch on that branch; adjust if the history shape differs.)
```

If `^^` doesn't land on a pre-CGo version, use:

```bash
git log --oneline --all -- .goreleaser.yml | head -20
git show <pre-cgo-sha>:.goreleaser.yml
```

- [ ] **Step 2: Restore `.goreleaser.yml`**

Replace the file contents with:

```yaml
version: 2

builds:
  - main: ./cmd/gc
    binary: gc
    env:
      - CGO_ENABLED=0
    ldflags:
      - -s -w -X main.version={{ .Tag }} -X main.commit={{ .Commit }} -X main.date={{ .Date }}
    goos:
      - linux
      - darwin
    goarch:
      - amd64
      - arm64

archives:
  - id: gc-archive
    formats: [tar.gz]
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"

checksum:
  name_template: "{{ .ProjectName }}_{{ .Version }}_checksums.txt"
  algorithm: sha256

release:
  prerelease: auto
  replace_existing_artifacts: true

# Homebrew tap distribution is generated by .github/workflows/release.yml after
# GoReleaser uploads all release archives. The tap formula installs the release
# assets directly; no source build or Go toolchain is required for users.

changelog:
  sort: asc
  filters:
    exclude:
      - "^docs:"
      - "^test:"
      - "^ci:"
      - "^chore:"
      - "Merge pull request"
      - "Merge branch"
  groups:
    - title: "Features"
      regexp: '^.*feat(\(\w+\))?:.*$'
      order: 0
    - title: "Bug Fixes"
      regexp: '^.*fix(\(\w+\))?:.*$'
      order: 1
    - title: "Others"
      order: 999
```

Key change: `CGO_ENABLED=0`, no `overrides:` block.

- [ ] **Step 3: Restore the `Run GoReleaser` step in `.github/workflows/release.yml`**

In `.github/workflows/release.yml`, replace the `Run GoReleaser` step's docker-run-goreleaser-cross block with:

```yaml
      - name: Run GoReleaser
        uses: goreleaser/goreleaser-action@9c156ee8a17a598857849441385a2041ef570552 # v6.3.0
        with:
          distribution: goreleaser
          version: "~> v2"
          args: release --clean ${{ github.repository != 'gastownhall/gascity' && '--skip=publish --skip=announce' || '' }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GORELEASER_CURRENT_TAG: ${{ github.ref_name }}
```

Resolve the action SHA by running `git log --all -- .github/workflows/release.yml | head` and showing pre-CGo content, OR run:

```bash
gh api /repos/goreleaser/goreleaser-action/git/refs/tags/v6.3.0 --jq .object.sha
```

Use the resolved SHA in the `@<sha> # v6.3.0` pin.

- [ ] **Step 4: Restore the equivalent step in `.github/workflows/rc-gate.yml`**

Same revert pattern. Open `.github/workflows/rc-gate.yml`, find the `goreleaser-cross` docker-run step, replace with the `goreleaser/goreleaser-action` invocation matching the pre-CGo shape (same SHA pin as Step 3).

- [ ] **Step 5: Verify locally**

```bash
CGO_ENABLED=0 go build ./...
echo $?  # expect 0
```

(If this fails because `internal/supervisor/secrets/keyring.go` references `99designs/keyring` which transitively requires CGo: that's expected — we'll fix it in Task 13. For now, the failure means the *release pipeline* stops asking for CGo; the source still has CGo references that get cleaned up later. Confirm the failure mode is "package linking" not "go build infrastructure" before moving on.)

Actually the right local check at this stage:

```bash
goreleaser check       # validates the .goreleaser.yml shape
echo $?  # expect 0
```

- [ ] **Step 6: Commit**

```bash
git add .goreleaser.yml .github/workflows/release.yml .github/workflows/rc-gate.yml
git commit -m "$(cat <<'EOF'
revert(release): drop goreleaser-cross switch and CGO_ENABLED=1

Restores the project's pre-CGo release pipeline. This branch ships a
pure-Go age-encrypted secrets backend (see
engdocs/design/supervisor-secrets-v0.md), so the keychain-branch's
CGo cross-compilation is unnecessary here.

Reverts:
- .goreleaser.yml: CGO_ENABLED=1 → 0; remove overrides: block
- .github/workflows/release.yml: docker-run goreleaser-cross →
  goreleaser/goreleaser-action
- .github/workflows/rc-gate.yml: same

The Go source still imports github.com/99designs/keyring at this
commit — that's removed in a later commit once the *secrets.Store
replacement is wired up.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Add `filippo.io/age` dependency + `Store` skeleton

**Files:**
- Modify: `go.mod`, `go.sum`
- Create: `internal/supervisor/secrets/store.go`

This task adds the new code *alongside* the existing keyring-based code. Build stays green. New code is unused until later tasks wire it in.

- [ ] **Step 1: Add the age dependency**

```bash
go get filippo.io/age@latest
go mod tidy
```

Expected: `go.mod` now contains `filippo.io/age v1.x.y` and `go.sum` is updated. Verify:

```bash
grep '^require ' go.mod | head -20
go list -m filippo.io/age
```

- [ ] **Step 2: Create `internal/supervisor/secrets/store.go` with type skeleton + sentinel**

```go
package secrets

import (
	"errors"
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
//   cutoff := time.Now().Add(-tmpSweepAge)
// rather than the bug-prone `time.Duration(seconds) * time.Second` form.
var tmpSweepAge = 5 * time.Minute
```

- [ ] **Step 3: Verify the package still compiles**

```bash
go build ./internal/supervisor/secrets/...
echo $?  # expect 0
```

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum internal/supervisor/secrets/store.go
git commit -m "$(cat <<'EOF'
feat(supervisor/secrets): add filippo.io/age and Store skeleton

Adds the age dependency and the empty Store type that subsequent
commits flesh out. ErrNotFound and on-disk format constants
(stampFileName, stampPlaintext, tmpSuffix, ageSuffix) are declared
once here so all later commits reference the same load-bearing
strings.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `Store.Set` / `Store.Get` / `Store.Remove` round-trip

**Files:**
- Modify: `internal/supervisor/secrets/store.go`
- Create: `internal/supervisor/secrets/store_test.go`

- [ ] **Step 1: Write the failing round-trip test**

Create `internal/supervisor/secrets/store_test.go`:

```go
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
```

- [ ] **Step 2: Run the test and verify it fails**

```bash
go test ./internal/supervisor/secrets/ -run 'TestStore_(RoundTrip|GetMissingReturnsErrNotFound|RemoveIdempotent)' -count=1
```

Expected: compile error (`Set`, `Get`, `Remove` undefined on `*Store`).

- [ ] **Step 3: Implement `Set`, `Get`, `Remove` in `store.go`**

Add to `internal/supervisor/secrets/store.go`:

```go
import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
)

// Set encrypts value with the store's passphrase and writes <key>.age
// atomically (write to <key>.age.tmp, fsync, rename). Concurrent Set
// of distinct keys is safe; concurrent Set of the same key has
// last-writer-wins semantics with no half-written file ever observable.
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
		if os.IsNotExist(err) {
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
```

- [ ] **Step 4: Run the tests and verify they pass**

```bash
go test ./internal/supervisor/secrets/ -run 'TestStore_(RoundTrip|GetMissingReturnsErrNotFound|RemoveIdempotent)' -count=1 -v
```

Expected: `PASS` for all three.

- [ ] **Step 5: Commit**

```bash
git add internal/supervisor/secrets/store.go internal/supervisor/secrets/store_test.go
git commit -m "$(cat <<'EOF'
feat(supervisor/secrets): Store.Set/Get/Remove with atomic rename

Per-secret <KEY>.age files under cfg.Age.Dir, encrypted with age's
scrypt recipient over the store's passphrase. Set writes to
<KEY>.age.tmp + fsync + rename for atomicity; concurrent Set of
distinct keys is race-safe. Get returns ErrNotFound for missing
files. Remove is idempotent.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `Store.Keys` with `.tmp` and stamp filtering

**Files:**
- Modify: `internal/supervisor/secrets/store.go`, `internal/supervisor/secrets/store_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/supervisor/secrets/store_test.go`:

```go
import "sort" // add to existing imports if not present

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
```

- [ ] **Step 2: Run test, verify failure**

```bash
go test ./internal/supervisor/secrets/ -run TestStore_KeysFiltersTmpAndStamp -count=1
```

Expected: compile error (`Keys` undefined).

- [ ] **Step 3: Implement `Keys`**

Add to `internal/supervisor/secrets/store.go`:

```go
import "strings" // add if not present

// Keys returns the names of secrets currently in the store. Filters
// out the stamp sentinel and any *.age.tmp files (in-flight or
// crashed writes). Used by the CLI's `list` command for ORPHAN drift
// detection; not used by the Loader, which gets keys from config.
func (s *Store) Keys() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
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
```

- [ ] **Step 4: Run test, verify pass**

```bash
go test ./internal/supervisor/secrets/ -run TestStore_KeysFiltersTmpAndStamp -count=1 -v
```

Expected: `PASS`.

- [ ] **Step 5: Commit**

```bash
git add internal/supervisor/secrets/store.go internal/supervisor/secrets/store_test.go
git commit -m "$(cat <<'EOF'
feat(supervisor/secrets): Store.Keys with .tmp and stamp filtering

Keys() reads cfg.Age.Dir and returns secret names (.age suffix
stripped), excluding the stamp sentinel (.gc-secrets-stamp-v0.age)
and any in-flight/crashed *.age.tmp files. Used exclusively by the
CLI's `list` command for ORPHAN drift detection.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `Open()` — passphrase parameter, stale `.tmp` sweep, eager-stamp on empty dir

**Files:**
- Modify: `internal/supervisor/secrets/store.go`, `internal/supervisor/secrets/store_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/supervisor/secrets/store_test.go`:

```go
import "time" // add if not present

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
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale .tmp should have been swept; stat err=%v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("fresh .tmp should still be present (in-flight write): %v", err)
	}
}

// openForTest is a thin wrapper around Open that takes a passphrase
// directly, bypassing the resolution chain. The production Open()
// signature does its own resolution; we'll add it in Task 9. Until
// then, openForTest is a private helper used by store_test.go.
func openForTest(t *testing.T, dir, passphrase string) (*Store, error) {
	t.Helper()
	cfg := AgeConfigForTest(dir)
	return openWithPassphrase(cfg, passphrase)
}

// AgeConfigForTest returns a minimal AgeBackendConfig pointed at dir.
// Lives in store_test.go so tests don't depend on the supervisor
// package; production constructors (added in Task 9) take the real
// supervisor.AgeBackendConfig.
type AgeConfigForTestT struct {
	Dir string
}

func AgeConfigForTest(dir string) AgeConfigForTestT {
	return AgeConfigForTestT{Dir: dir}
}
```

- [ ] **Step 2: Run, verify failure**

```bash
go test ./internal/supervisor/secrets/ -run 'TestStore_(OpenStampEagerlyWrittenOnEmptyDir|StaleTmpSweptAtOpen)' -count=1
```

Expected: compile error (`openWithPassphrase` undefined).

- [ ] **Step 3: Implement `openWithPassphrase` + sweep + eager stamp**

Add to `internal/supervisor/secrets/store.go`:

```go
import "time" // add to existing imports

// openWithPassphrase constructs a *Store, sweeps stale *.age.tmp
// files, then enforces the stamp invariants per the Open() matrix in
// engdocs/design/supervisor-secrets-v0.md:
//
//   hasSecrets=no, stamp=no    -> eager-write stamp, proceed
//   hasSecrets=yes, stamp=yes, verifies   -> proceed
//   hasSecrets=yes, stamp=yes, no-verify  -> hard error
//   hasSecrets=yes, stamp=no   -> hard error (refuse to write fresh stamp)
//
// Production Open() (Task 9) wraps this with passphrase resolution.
func openWithPassphrase(cfg AgeConfigForTestT, passphrase string) (*Store, error) {
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
```

(Note: this step intentionally does *not* implement the verify-or-init logic for non-empty stores yet — that's Task 6. The `verifyOrInitStamp` call resolves to a stub here that handles only the empty-dir case.)

Add the stub:

```go
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
	} else if !os.IsNotExist(err) {
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
```

- [ ] **Step 4: Run, verify pass**

```bash
go test ./internal/supervisor/secrets/ -run 'TestStore_(OpenStampEagerlyWrittenOnEmptyDir|StaleTmpSweptAtOpen)' -count=1 -v
```

Expected: `PASS`.

Also run the full package tests to make sure nothing regressed:

```bash
go test ./internal/supervisor/secrets/ -count=1
```

Expected: all pass (the Task-3/Task-4 tests still work because `Set`/`Get`/`Remove`/`Keys` don't depend on the new Open path).

- [ ] **Step 5: Commit**

```bash
git add internal/supervisor/secrets/store.go internal/supervisor/secrets/store_test.go
git commit -m "$(cat <<'EOF'
feat(supervisor/secrets): Open() empty-dir eager stamp + .tmp sweep

openWithPassphrase wraps Store construction with two invariants:
- Stale *.age.tmp files older than 5 minutes are swept (crashed-set
  cleanup; in-flight writes are preserved).
- On a brand-new empty dir, the stamp file is eagerly written under
  the resolved passphrase (closes the "user typos passphrase, only
  finds out later" hole). Spec, decision row 11.

The verify-on-non-empty-store and wrong-passphrase paths land in the
next commit. Production Open() (with passphrase resolution) lands
in a later task.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Stamp invariants — wrong passphrase + stamp-deleted hard errors

**Files:**
- Modify: `internal/supervisor/secrets/store.go`, `internal/supervisor/secrets/store_test.go`

- [ ] **Step 1: Write failing tests**

Append to `internal/supervisor/secrets/store_test.go`:

```go
import "strings" // add if not present

func TestStore_OpenWithWrongPassphraseFailsAtStamp(t *testing.T) {
	dir := t.TempDir()
	if _, err := openForTest(t, dir, "right-pass"); err != nil {
		t.Fatalf("Open (init): %v", err)
	}
	// Plant a "real" secret under the right passphrase so the dir is non-empty.
	s := &Store{dir: dir, passphrase: "right-pass"}
	if err := s.Set("KEY", []byte("v")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// Re-open with wrong passphrase.
	_, err := openForTest(t, dir, "wrong-pass")
	if err == nil {
		t.Fatalf("Open with wrong passphrase: want error, got nil")
	}
	if !strings.Contains(err.Error(), "passphrase does not match") {
		t.Fatalf("error must mention passphrase mismatch: %v", err)
	}
}

func TestStore_OpenStampDeletedNonEmptyStoreRejected(t *testing.T) {
	dir := t.TempDir()
	if _, err := openForTest(t, dir, "pass"); err != nil {
		t.Fatalf("Open (init): %v", err)
	}
	s := &Store{dir: dir, passphrase: "pass"}
	if err := s.Set("KEY", []byte("v")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// User accidentally deletes the stamp.
	if err := os.Remove(filepath.Join(dir, stampFileName)); err != nil {
		t.Fatalf("remove stamp: %v", err)
	}
	_, err := openForTest(t, dir, "pass")
	if err == nil {
		t.Fatalf("Open with deleted stamp on non-empty store: want error, got nil")
	}
	if !strings.Contains(err.Error(), "stamp file missing") {
		t.Fatalf("error must mention missing stamp: %v", err)
	}
	// The stamp must NOT have been silently re-created.
	if _, err := os.Stat(filepath.Join(dir, stampFileName)); !os.IsNotExist(err) {
		t.Fatalf("Open must not write a fresh stamp under unknown passphrase; stat err=%v", err)
	}
}
```

- [ ] **Step 2: Run, verify failure**

```bash
go test ./internal/supervisor/secrets/ -run 'TestStore_(OpenWithWrongPassphraseFailsAtStamp|OpenStampDeletedNonEmptyStoreRejected)' -count=1
```

Expected: both fail (no error returned where one is expected).

- [ ] **Step 3: Implement the full `verifyOrInitStamp`**

Replace the stub in `internal/supervisor/secrets/store.go` with:

```go
func (s *Store) verifyOrInitStamp() error {
	hasSecrets, err := s.hasSecretsOnDisk()
	if err != nil {
		return err
	}
	stampInfo, statErr := os.Stat(s.stampPath())
	stampPresent := statErr == nil
	if !stampPresent && !os.IsNotExist(statErr) {
		return fmt.Errorf("stat stamp: %w", statErr)
	}

	switch {
	case !hasSecrets && !stampPresent:
		// Brand-new install — eager-write the stamp under the resolved passphrase.
		return s.writeStamp()
	case hasSecrets && stampPresent:
		return s.verifyStamp()
	case !hasSecrets && stampPresent:
		// Re-opening an init'd store with no secrets yet — verify the
		// stamp matches the current passphrase.
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
	_ = stampInfo
	return nil
}

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
```

- [ ] **Step 4: Run, verify pass**

```bash
go test ./internal/supervisor/secrets/ -count=1 -v
```

Expected: all `TestStore_*` pass.

- [ ] **Step 4a: Add the format-string-is-constant + concurrent-set tests**

Append to `internal/supervisor/secrets/store_test.go`:

```go
import "sync" // add to existing imports

// Spec decision row 11 names the stamp plaintext as a load-bearing
// versioned constant. This test names the constant explicitly so any
// future commit that renames or rewrites it trips here.
func TestStore_StampFormatStringIsConstant(t *testing.T) {
	const want = "gc-supervisor-secrets-stamp-v0\n"
	if stampPlaintext != want {
		t.Fatalf("stampPlaintext changed: want %q, got %q. "+
			"This is a load-bearing on-disk constant — if you really need to "+
			"change it, ship a new versioned filename and migration path.",
			want, stampPlaintext)
	}
	if stampFileName != ".gc-secrets-stamp-v0.age" {
		t.Fatalf("stampFileName changed; same versioning rule applies")
	}
}

func TestStore_ConcurrentSetDifferentKeys(t *testing.T) {
	dir := t.TempDir()
	if _, err := openForTest(t, dir, "pass"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	s := &Store{dir: dir, passphrase: "pass"}
	var wg sync.WaitGroup
	keys := []string{"ALPHA", "BETA", "GAMMA", "DELTA"}
	for _, k := range keys {
		wg.Add(1)
		go func(k string) {
			defer wg.Done()
			if err := s.Set(k, []byte("v-"+k)); err != nil {
				t.Errorf("Set %s: %v", k, err)
			}
		}(k)
	}
	wg.Wait()
	for _, k := range keys {
		got, err := s.Get(k)
		if err != nil {
			t.Errorf("Get %s: %v", k, err)
			continue
		}
		if string(got) != "v-"+k {
			t.Errorf("Get %s: want v-%s, got %q", k, k, got)
		}
	}
}
```

- [ ] **Step 5: Commit**

```bash
git add internal/supervisor/secrets/store.go internal/supervisor/secrets/store_test.go
git commit -m "$(cat <<'EOF'
feat(supervisor/secrets): stamp Open() invariants — wrong-pass + missing-stamp errors

Completes the Open() invariants matrix from the spec:
- Wrong passphrase against existing stamp → hard error with the
  documented rotation message.
- Stamp deleted but secrets remain → hard error refusing to write
  a fresh stamp under a possibly-wrong passphrase. This was the
  silent-corruption mode the second adversarial review caught.
- Stamp present + verifies, with or without secrets → proceed.
- Empty dir → eager stamp (already in previous commit).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Passphrase resolver — env + 0600 keyfile (Lstat / UID / mode)

**Files:**
- Create: `internal/supervisor/secrets/passphrase.go`, `internal/supervisor/secrets/passphrase_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/supervisor/secrets/passphrase_test.go`:

```go
package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPassphrase_EnvWins(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "from-env")
	dir := t.TempDir()
	keyfile := filepath.Join(dir, ".secrets-passphrase")
	if err := os.WriteFile(keyfile, []byte("from-keyfile"), 0o600); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}
	got, src, err := resolvePassphrase(passphraseSources{KeyfilePath: keyfile})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "from-env" {
		t.Fatalf("want from-env, got %q", got)
	}
	if src != PassphraseSourceEnv {
		t.Fatalf("want PassphraseSourceEnv, got %v", src)
	}
}

func TestPassphrase_KeyfileWhenEnvUnset(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	dir := t.TempDir()
	keyfile := filepath.Join(dir, ".secrets-passphrase")
	if err := os.WriteFile(keyfile, []byte("from-keyfile\n"), 0o600); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}
	got, src, err := resolvePassphrase(passphraseSources{KeyfilePath: keyfile})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "from-keyfile" {
		t.Fatalf("want from-keyfile (trailing \\n stripped), got %q", got)
	}
	if src != PassphraseSourceKeyfile {
		t.Fatalf("want PassphraseSourceKeyfile, got %v", src)
	}
}

func TestPassphrase_KeyfileWorldReadableRejected(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	dir := t.TempDir()
	keyfile := filepath.Join(dir, ".secrets-passphrase")
	if err := os.WriteFile(keyfile, []byte("x"), 0o644); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}
	_, _, err := resolvePassphrase(passphraseSources{KeyfilePath: keyfile})
	if err == nil {
		t.Fatalf("0644 keyfile must be rejected")
	}
	if !strings.Contains(err.Error(), "insecure mode") {
		t.Fatalf("error must mention insecure mode: %v", err)
	}
}

func TestPassphrase_KeyfileGroupReadableRejected(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	dir := t.TempDir()
	keyfile := filepath.Join(dir, ".secrets-passphrase")
	if err := os.WriteFile(keyfile, []byte("x"), 0o640); err != nil {
		t.Fatalf("write keyfile: %v", err)
	}
	_, _, err := resolvePassphrase(passphraseSources{KeyfilePath: keyfile})
	if err == nil || !strings.Contains(err.Error(), "insecure mode") {
		t.Fatalf("0640 keyfile must be rejected; got %v", err)
	}
}

func TestPassphrase_KeyfileSymlinkRejected(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("from-target"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, ".secrets-passphrase")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	_, _, err := resolvePassphrase(passphraseSources{KeyfilePath: link})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked keyfile must be rejected; got %v", err)
	}
}
```

- [ ] **Step 2: Run, verify failure**

```bash
go test ./internal/supervisor/secrets/ -run 'TestPassphrase_(EnvWins|KeyfileWhenEnvUnset|KeyfileWorldReadableRejected|KeyfileGroupReadableRejected|KeyfileSymlinkRejected)' -count=1
```

Expected: compile error.

- [ ] **Step 3: Implement the env + keyfile portion of `resolvePassphrase`**

Create `internal/supervisor/secrets/passphrase.go`:

```go
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
	PassphraseSourceUnset PassphraseSource = iota
	PassphraseSourceEnv
	PassphraseSourceKeyfile
	PassphraseSourceKeychain
	PassphraseSourcePrompt
)

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
// construct one directly; production code (Task 9) builds it from
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
		if os.IsNotExist(err) {
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
```

Now create the platform-specific owner check. The Lstat owner check uses
`syscall.Stat_t` which has different field types across platforms; isolate
it in `passphrase_unix.go`:

Create `internal/supervisor/secrets/passphrase_unix.go`:

```go
//go:build unix

package secrets

import (
	"fmt"
	"os"
	"syscall"
)

func checkKeyfileOwner(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Non-unix or test stub — skip ownership check.
		return nil
	}
	if int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf(
			"passphrase file %s is owned by uid %d, but current process euid is %d; refuse",
			path, stat.Uid, os.Geteuid(),
		)
	}
	return nil
}
```

(The `//go:build unix` tag covers darwin + linux; Windows is a no-target per
the spec but the build won't fail since we're only used on unix paths in
practice.)

- [ ] **Step 4: Run, verify pass**

```bash
go test ./internal/supervisor/secrets/ -run 'TestPassphrase_' -count=1 -v
```

Expected: `PASS` on the five tests added. Other passphrase tests (Keychain, TTY) don't exist yet.

- [ ] **Step 5: Commit**

```bash
git add internal/supervisor/secrets/passphrase.go internal/supervisor/secrets/passphrase_unix.go internal/supervisor/secrets/passphrase_test.go
git commit -m "$(cat <<'EOF'
feat(supervisor/secrets): passphrase resolver — env + 0600 keyfile

resolvePassphrase walks the env → keyfile → Keychain → TTY chain.
This commit lands env + keyfile steps:
- GC_SECRETS_PASSPHRASE env var wins when non-empty.
- Keyfile at cfg.Age.PassphraseFile, verified via os.Lstat (rejects
  symlinks), regular-file check, mode strictly 0600 (rejects 0644
  and 0640), owning-UID matches process EUID. ACL-based override is
  documented in the spec as a known limitation (Mode() doesn't see
  POSIX ACLs).
- Trailing \n stripped to support `echo "pass" > keyfile` writes.

PassphraseSource enum surfaces which step won; the CLI uses it on
first-secret commit so users can sanity-check the chain at the
moment of greatest typo risk.

Keychain-bootstrap and TTY-prompt steps land in subsequent commits.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Passphrase resolver — macOS Keychain bootstrap (timeout, empty rejection)

**Files:**
- Modify: `internal/supervisor/secrets/passphrase.go`, `internal/supervisor/secrets/passphrase_test.go`

- [ ] **Step 1: Add a `cmdRunner` injection hook to `passphrase.go`**

Append to `internal/supervisor/secrets/passphrase.go`:

```go
import (
	"context"
	"os/exec"
	"runtime"
	"time"
)

// cmdRunner abstracts os/exec for tests. Production sets the package
// variable to a real implementation; tests override.
type cmdRunner interface {
	Run(ctx context.Context, name string, args ...string) (stdout []byte, exitCode int, err error)
}

// detectGOOS is a package var so tests can pin it.
var detectGOOS = func() string { return runtime.GOOS }

// keychainCmdRunner is the production runner — wraps exec.CommandContext.
// Tests assign a fake to this var.
var keychainCmdRunner cmdRunner = realCmdRunner{}

type realCmdRunner struct{}

func (realCmdRunner) Run(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err == nil {
		return out, 0, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return out, exitErr.ExitCode(), nil
	}
	return out, -1, err
}

// keychainServiceName is the service-name for the passphrase-bootstrap
// Keychain item. Constant; users seed it once via `security add-generic-password`.
const keychainServiceName = "gc-supervisor-passphrase"

const keychainTimeout = 5 * time.Second

// keychainBootstrap runs `security find-generic-password -s gc-supervisor-passphrase -a $account -w`
// with a 5s timeout. Returns the passphrase + true if found, false +
// error if not (caller falls through). Empty stdout is treated as
// ERROR-and-fall-through to prevent a mis-set Keychain item from
// silently producing an empty-passphrase store.
func keychainBootstrap(account string, logger func(format string, args ...interface{})) (string, bool, error) {
	if detectGOOS() != "darwin" {
		return "", false, nil
	}
	if account == "" {
		return "", false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), keychainTimeout)
	defer cancel()
	stdout, code, err := keychainCmdRunner.Run(ctx, "security",
		"find-generic-password", "-s", keychainServiceName, "-a", account, "-w")
	if ctx.Err() == context.DeadlineExceeded {
		logger("WARN: macOS Keychain lookup for gc-supervisor-passphrase timed out after %s; is the login keychain locked?", keychainTimeout)
		return "", false, nil
	}
	if err != nil && code == -1 {
		// command failed to spawn (e.g. /usr/bin/security missing)
		logger("WARN: macOS Keychain bootstrap: %v", err)
		return "", false, nil
	}
	switch code {
	case 0:
		passphrase := strings.TrimRight(string(stdout), "\n")
		if passphrase == "" {
			logger(
				"ERROR: macOS Keychain bootstrap returned empty passphrase. " +
					"The gc-supervisor-passphrase item is mis-set. Re-seed with: " +
					"security add-generic-password -U -s gc-supervisor-passphrase -a %q -w",
				account,
			)
			return "", false, nil
		}
		return passphrase, true, nil
	case 44:
		// Item not found.
		return "", false, nil
	default:
		logger("WARN: macOS Keychain bootstrap exit %d: %s", code, strings.TrimSpace(string(stdout)))
		return "", false, nil
	}
}
```

Now wire `keychainBootstrap` into `resolvePassphrase`. Modify the function:

```go
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
		} else if v != "" {
			return v, PassphraseSourceKeyfile, nil
		}
	}
	if v, ok, err := keychainBootstrap(sources.KeychainAccount, sources.logger()); err != nil {
		return "", PassphraseSourceUnset, err
	} else if ok {
		return v, PassphraseSourceKeychain, nil
	}
	// TTY prompt step lands in Task 9.
	return "", PassphraseSourceUnset, errPassphraseNoSources(sources.KeyfilePath)
}

func (s passphraseSources) logger() func(format string, args ...interface{}) {
	if s.LogFn != nil {
		return s.LogFn
	}
	return func(format string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, "secrets: "+format+"\n", args...)
	}
}
```

And add `LogFn` to `passphraseSources`:

```go
type passphraseSources struct {
	KeyfilePath     string
	KeychainAccount string
	NoTTY           bool
	LogFn           func(format string, args ...interface{})
}
```

- [ ] **Step 2: Write the failing tests**

Append to `internal/supervisor/secrets/passphrase_test.go`:

```go
import (
	"context"
	"time"
)

// fakeCmdRunner records calls and returns canned output.
type fakeCmdRunner struct {
	stdout []byte
	code   int
	err    error
	calls  [][]string
	delay  time.Duration
}

func (f *fakeCmdRunner) Run(ctx context.Context, name string, args ...string) ([]byte, int, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, -1, ctx.Err()
		}
	}
	return f.stdout, f.code, f.err
}

func withFakeRunner(t *testing.T, r *fakeCmdRunner) {
	t.Helper()
	prev := keychainCmdRunner
	keychainCmdRunner = r
	t.Cleanup(func() { keychainCmdRunner = prev })
}

func withGOOS(t *testing.T, goos string) {
	t.Helper()
	prev := detectGOOS
	detectGOOS = func() string { return goos }
	t.Cleanup(func() { detectGOOS = prev })
}

func TestPassphrase_KeychainBootstrap(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	withGOOS(t, "darwin")
	withFakeRunner(t, &fakeCmdRunner{stdout: []byte("from-keychain\n"), code: 0})
	got, src, err := resolvePassphrase(passphraseSources{KeychainAccount: "user@personal"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "from-keychain" {
		t.Fatalf("want from-keychain, got %q", got)
	}
	if src != PassphraseSourceKeychain {
		t.Fatalf("want PassphraseSourceKeychain, got %v", src)
	}
}

func TestPassphrase_KeychainBootstrapEmptyStringRejected(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	withGOOS(t, "darwin")
	var logs []string
	logFn := func(format string, args ...interface{}) {
		logs = append(logs, fmtSprintf(format, args...))
	}
	withFakeRunner(t, &fakeCmdRunner{stdout: []byte(""), code: 0})
	_, _, err := resolvePassphrase(passphraseSources{
		KeychainAccount: "user@personal",
		LogFn:           logFn,
	})
	if err == nil || !strings.Contains(err.Error(), "no passphrase") {
		t.Fatalf("empty-keychain must fall through to no-sources error; got %v", err)
	}
	matched := false
	for _, l := range logs {
		if strings.Contains(l, "ERROR:") && strings.Contains(l, "empty passphrase") {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("expected ERROR-level log about empty passphrase; got logs=%v", logs)
	}
}

func TestPassphrase_KeychainBootstrapExit44(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	withGOOS(t, "darwin")
	withFakeRunner(t, &fakeCmdRunner{code: 44})
	_, _, err := resolvePassphrase(passphraseSources{KeychainAccount: "user@personal"})
	if err == nil || !strings.Contains(err.Error(), "no passphrase") {
		t.Fatalf("exit 44 must fall through; got %v", err)
	}
}

func TestPassphrase_KeychainBootstrapTimeout(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	withGOOS(t, "darwin")
	// Force a timeout shorter than the production 5s for test speed.
	prev := keychainCmdRunner
	keychainCmdRunner = &fakeCmdRunner{delay: 50 * time.Millisecond}
	t.Cleanup(func() { keychainCmdRunner = prev })
	prevTimeout := overrideKeychainTimeoutForTest(10 * time.Millisecond)
	t.Cleanup(prevTimeout)
	_, _, err := resolvePassphrase(passphraseSources{KeychainAccount: "user@personal"})
	if err == nil || !strings.Contains(err.Error(), "no passphrase") {
		t.Fatalf("timeout must fall through; got %v", err)
	}
}

func TestPassphrase_KeychainBootstrapNonDarwinSkipped(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	withGOOS(t, "linux")
	r := &fakeCmdRunner{stdout: []byte("ignored"), code: 0}
	withFakeRunner(t, r)
	_, _, err := resolvePassphrase(passphraseSources{KeychainAccount: "user@personal"})
	if err == nil {
		t.Fatalf("non-darwin: must fall through to no-sources error")
	}
	if len(r.calls) != 0 {
		t.Fatalf("non-darwin must not invoke security; got calls=%v", r.calls)
	}
}

// fmtSprintf is fmt.Sprintf re-exported under a short name; dodges
// `import "fmt"` boilerplate at the top of test files that don't
// already need it (this file imports fmt only via the helper).
func fmtSprintf(format string, args ...interface{}) string { return fmt.Sprintf(format, args...) }
```

The test references `overrideKeychainTimeoutForTest` — add to `passphrase.go`:

```go
// overrideKeychainTimeoutForTest swaps the production timeout. Returns
// a restore func suitable for t.Cleanup.
func overrideKeychainTimeoutForTest(d time.Duration) func() {
	prev := keychainTimeoutVar
	keychainTimeoutVar = d
	return func() { keychainTimeoutVar = prev }
}

// Replace the const with a var so tests can swap it.
var keychainTimeoutVar = 5 * time.Second
```

Replace `keychainTimeout` references in `keychainBootstrap` with `keychainTimeoutVar`, and remove the `const keychainTimeout` declaration.

- [ ] **Step 3: Run, verify pass**

```bash
go test ./internal/supervisor/secrets/ -run TestPassphrase_Keychain -count=1 -v
```

Expected: all five `TestPassphrase_Keychain*` pass.

- [ ] **Step 4: Run the full secrets package tests**

```bash
go test ./internal/supervisor/secrets/ -count=1
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add internal/supervisor/secrets/passphrase.go internal/supervisor/secrets/passphrase_test.go
git commit -m "$(cat <<'EOF'
feat(supervisor/secrets): passphrase resolver — macOS Keychain bootstrap

Step 3 of the resolution chain. Single read-only `security
find-generic-password -s gc-supervisor-passphrase -a $account -w`
call wrapped in a 5s context timeout (so a locked-keychain GUI
prompt on launchd-managed supervisor cannot hang startup).

Outcomes:
- exit 0 with non-empty stdout → use as passphrase
- exit 0 with empty stdout → ERROR log + fall through (rejects mis-set
  Keychain item that would otherwise produce an empty-passphrase store
  silently — round-2 adversarial finding)
- exit 44 → not found, fall through silently
- timeout / other error → WARN log + fall through

Non-darwin: skipped without any subprocess call.

cmdRunner + detectGOOS test hooks let CI Linux runners exercise every
path without `security` installed.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Passphrase resolver — TTY prompt + non-TTY error

**Files:**
- Modify: `internal/supervisor/secrets/passphrase.go`, `internal/supervisor/secrets/passphrase_test.go`

This task closes the resolver chain by adding the final TTY-prompt step. The production `Open(supervisor.AgeBackendConfig)` constructor — which depends on the new `supervisor.AgeBackendConfig` type — is deferred to Task 11, where the schema is in place. **No deferred-back-later instructions in this task.** The `openWithPassphrase` shim from Task 5 stays in place until Task 11 deletes it.

Note: `golang.org/x/term` is already in `go.mod` as an indirect dep (used by other parts of the codebase). After adding the import in Step 1, `go mod tidy` will promote it to direct. Stage `go.mod` / `go.sum` in this task's commit if they change.

- [ ] **Step 1: Implement the TTY step + non-TTY error in `resolvePassphrase`**

Modify `internal/supervisor/secrets/passphrase.go`:

```go
import (
	"golang.org/x/term"
)

// promptForPassphrase reads from the controlling TTY without echo.
// Returns (passphrase, true) on success; (errMsg, false) on non-TTY.
// Tests force NoTTY=true to bypass.
func promptForPassphrase(sources passphraseSources) (string, bool) {
	if sources.NoTTY {
		return "", false
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", false
	}
	fmt.Fprint(os.Stderr, "Passphrase: ")
	bytes, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", false
	}
	return string(bytes), true
}
```

Append the TTY step to `resolvePassphrase`, replacing the trailing comment:

```go
	if v, ok := promptForPassphrase(sources); ok && v != "" {
		return v, PassphraseSourcePrompt, nil
	}
	return "", PassphraseSourceUnset, errPassphraseNoSources(sources.KeyfilePath)
```

- [ ] **Step 2: Add the failing TTY test**

Append to `internal/supervisor/secrets/passphrase_test.go`:

```go
func TestPassphrase_NonTTYNoSourcesFails(t *testing.T) {
	t.Setenv("GC_SECRETS_PASSPHRASE", "")
	dir := t.TempDir()
	_, _, err := resolvePassphrase(passphraseSources{
		KeyfilePath: filepath.Join(dir, ".secrets-passphrase"),
		NoTTY:       true,
	})
	if err == nil {
		t.Fatalf("no sources + non-TTY: want error, got nil")
	}
	for _, want := range []string{
		"GC_SECRETS_PASSPHRASE",
		"0600 keyfile",
		"gc-supervisor-passphrase",
		"interactively",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error must mention %q; got %v", want, err)
		}
	}
}
```

- [ ] **Step 3: Verify Step 2 fails, then passes**

```bash
go test ./internal/supervisor/secrets/ -run TestPassphrase_NonTTYNoSourcesFails -count=1 -v
```

Expected: `PASS`.

- [ ] **Step 4: Run `go mod tidy` if `golang.org/x/term` was promoted from indirect to direct**

```bash
go mod tidy
git diff go.mod go.sum
```

If diff is non-empty, stage `go.mod` and `go.sum` in the commit below.

- [ ] **Step 5: Commit**

```bash
git add internal/supervisor/secrets/passphrase.go internal/supervisor/secrets/passphrase_test.go go.mod go.sum
git commit -m "$(cat <<'EOF'
feat(supervisor/secrets): passphrase resolver — TTY prompt + non-TTY error

Closes the resolution chain: when env, keyfile, and Keychain all
miss, prompt on the TTY; in non-TTY contexts (CI, launchd-managed
supervisor) fail with the documented multi-line error message
naming every other source so the user can pick one.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: SecretsConfig schema swap + strict TOML decode

**Files:**
- Modify: `internal/supervisor/config.go`, `internal/supervisor/config_test.go`

This task replaces `KeychainBackendConfig` + `FileBackendConfig` + `Backend` with `AgeBackendConfig`, and switches `LoadConfig` to strict TOML decode so a stale `[secrets.keychain]` section produces a clear error instead of silent acceptance.

- [ ] **Step 1: Read the current schema to know what to delete**

```bash
sed -n '270,370p' internal/supervisor/config.go
```

- [ ] **Step 2: Write failing tests for the new schema**

Append to `internal/supervisor/config_test.go` (and remove tests for the
old `KeychainBackendConfig` / `FileBackendConfig` / `Backend` enum,
which are about to be deleted):

```go
func TestSecretsConfig_Validate_KeyShape(t *testing.T) {
	cfg := SecretsConfig{Age: AgeBackendConfig{Keys: []string{"lower-case-bad"}}}
	err := cfg.Validate(nil)
	if err == nil || !strings.Contains(err.Error(), "is not a valid env-var name") {
		t.Fatalf("want shape error, got %v", err)
	}
}

func TestSecretsConfig_Validate_ReservedKey(t *testing.T) {
	cfg := SecretsConfig{Age: AgeBackendConfig{Keys: []string{"PATH"}}}
	err := cfg.Validate(nil)
	if err == nil || !strings.Contains(err.Error(), "would shadow reserved env var") {
		t.Fatalf("want reserved error, got %v", err)
	}
}

func TestSecretsConfig_Validate_GoodCaseAccepted(t *testing.T) {
	cfg := SecretsConfig{Age: AgeBackendConfig{Keys: []string{"EXA_API_KEY", "FIRECRAWL_KEY"}}}
	if err := cfg.Validate(nil); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}

func TestLoadConfig_RejectsUnknownSecretsSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "supervisor.toml")
	body := `
[supervisor]
port = 1234

[secrets.keychain]
keys = ["EXA_API_KEY"]
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatalf("LoadConfig must reject [secrets.keychain]")
	}
	for _, want := range []string{"secrets.keychain", "supervisor-secrets-v0", "switching"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error must mention %q; got %v", want, err)
		}
	}
}
```

(Add `"strings"` and `"path/filepath"` to the imports if not already present.)

- [ ] **Step 3: Run, verify failure**

```bash
go test ./internal/supervisor/ -run 'TestSecretsConfig_Validate_(KeyShape|ReservedKey|GoodCaseAccepted)|TestLoadConfig_RejectsUnknownSecretsSection' -count=1
```

Expected: compile errors (`AgeBackendConfig` undefined, `KeychainBackendConfig` may still be referenced by old tests).

- [ ] **Step 4: Replace the schema in `internal/supervisor/config.go`**

Find the existing `SecretsConfig` / `KeychainBackendConfig` / `FileBackendConfig` block (currently lines ~273-322) and replace with:

```go
// SecretsConfig configures the supervisor's age-encrypted secret store.
// See engdocs/design/supervisor-secrets-v0.md.
type SecretsConfig struct {
	Age AgeBackendConfig `toml:"age,omitempty"`
}

// AgeBackendConfig configures the per-secret age-encrypted file store.
type AgeBackendConfig struct {
	// Dir is where <KEY>.age files (and the .gc-secrets-stamp-v0.age sentinel)
	// are stored. Default "$GC_HOME/secrets" (typically ~/.gc/secrets).
	Dir string `toml:"dir,omitempty"`

	// PassphraseFile is the path to the optional 0600 keyfile holding the
	// age passphrase. Default "$GC_HOME/.secrets-passphrase" — sibling of
	// Dir, NOT inside it, to avoid filename collisions with secret files.
	PassphraseFile string `toml:"passphrase_file,omitempty"`

	// PassphraseKeychainAccount is the account field for the macOS Keychain
	// passphrase-bootstrap lookup (darwin only). Default "$USER@personal".
	// Used only when env + keyfile resolution failed. The Keychain item is
	// identified by service_name="gc-supervisor-passphrase" + this account;
	// gc never writes to it (the user runs `security add-generic-password`
	// once manually to seed it).
	PassphraseKeychainAccount string `toml:"passphrase_keychain_account,omitempty"`

	// Keys are the env-var names to load. Each must exist as <KEY>.age
	// under Dir at supervisor startup; missing keys WARN-and-continue.
	Keys []string `toml:"keys"`
}

// envVarNameRE matches uppercase POSIX env-var names.
var envVarNameRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// Validate checks the configuration for shape errors. The reservedKey
// predicate is injected by the caller; nil falls back to a minimal
// default recognizing only PATH and GC_HOME.
func (c SecretsConfig) Validate(reservedKey func(string) bool) error {
	if reservedKey == nil {
		reservedKey = func(name string) bool {
			return name == "PATH" || name == "GC_HOME"
		}
	}
	for i, k := range c.Age.Keys {
		if !envVarNameRE.MatchString(k) {
			return fmt.Errorf("secrets.age.keys[%d]: %q is not a valid env-var name (must match [A-Z_][A-Z0-9_]*)", i, k)
		}
		if reservedKey(k) {
			return fmt.Errorf("secrets.age.keys[%d]: %q would shadow reserved env var", i, k)
		}
	}
	return nil
}
```

- [ ] **Step 5: Switch `LoadConfig` to strict TOML decode**

Find the `LoadConfig` function (around line 123). Replace:

```go
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
```

with:

```go
	md, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return cfg, err
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		// Surface the most-actionable case explicitly: stale CGo-branch
		// [secrets.keychain] / [secrets.file] sections.
		for _, k := range undecoded {
			key := k.String()
			if strings.HasPrefix(key, "secrets.") {
				return cfg, fmt.Errorf(
					"unknown key %q in %s. Did you mean to migrate from the "+
						"feat/supervisor-secrets-keychain branch? See "+
						"engdocs/design/supervisor-secrets-v0.md#switching-from-the-cgo-branch",
					key, path,
				)
			}
		}
		return cfg, fmt.Errorf("unknown keys in %s: %v", path, undecoded)
	}
	return cfg, nil
```

Add `"strings"` import if not already present.

- [ ] **Step 6: Run, verify pass**

```bash
go test ./internal/supervisor/ -run 'TestSecretsConfig_|TestLoadConfig_' -count=1 -v
```

Expected: all four tests pass.

- [ ] **Step 7: Verify the rest of the supervisor package still compiles**

```bash
go build ./internal/supervisor/...
```

Expected: success. (The `internal/supervisor/secrets/` package will still
build because Tasks 2-9 don't import the supervisor types yet.)

- [ ] **Step 8: Commit**

```bash
git add internal/supervisor/config.go internal/supervisor/config_test.go
git commit -m "$(cat <<'EOF'
refactor(supervisor): SecretsConfig schema — drop Keychain/File, add Age

Replaces the CGo branch's KeychainBackendConfig + FileBackendConfig +
Backend enum with a single AgeBackendConfig. New fields:
- Dir              (default $GC_HOME/secrets)
- PassphraseFile   (default $GC_HOME/.secrets-passphrase)
- PassphraseKeychainAccount  (default $USER@personal, darwin only)
- Keys             (exact-match env var names)

Removes the prefix-matching semantics; every entry in Keys is matched
exactly against <KEY>.age in Dir.

LoadConfig now uses toml.Decode (strict mode) so a stale
[secrets.keychain] or [secrets.file] section in supervisor.toml is
rejected with a clear error pointing at the migration guide. This
matches the spec's adversarial-fix #11.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Production `Open()` + Loader refactor + delete `keyring.go` (atomic swap)

**Files:**
- Modify: `internal/supervisor/secrets/store.go`, `internal/supervisor/secrets/store_test.go`
- Modify: `internal/supervisor/secrets/secrets.go`, `internal/supervisor/secrets/secrets_test.go`
- Modify: `cmd/gc/cmd_supervisor.go` (`runSupervisor` Loader construction + WARN log wording)
- Modify: `cmd/gc/cmd_supervisor_lifecycle_secrets_test.go`, `cmd/gc/cmd_start_secrets_test.go` (test seeders)
- Delete: `internal/supervisor/secrets/keyring.go`, `internal/supervisor/secrets/keyring_test.go`

**This is one atomic task** — it must commit as a single unit so no intermediate state has a half-broken build. The reason: removing `keyring.go` orphans `OpenKeyring` / `EnvPasswordPromptFunc` / `EnvPasswordVar`, but `cmd/gc/cmd_supervisor.go:697` and `cmd/gc/cmd_supervisor_secret.go` import those identifiers. They must all change in the same commit. The CLI's overwrite-confirmation work and full `cmd_supervisor_secret.go` rewrite are still in Task 12 — this task only touches the parts of `cmd_supervisor_secret.go` that are needed to remove the dependency.

Wait — `cmd_supervisor_secret.go` is too tangled to split. **Task 11 covers all `keyring`-removal in `cmd_supervisor_secret.go` too**, and Task 12 just adds the overwrite confirmation feature on top. So the file map for Task 11 also includes `cmd/gc/cmd_supervisor_secret.go`, `cmd/gc/cmd_supervisor_secret_test.go`.

- [ ] **Step 1: Add the production `Open()` constructor to `store.go`**

Add to `internal/supervisor/secrets/store.go`:

```go
import (
	"github.com/gastownhall/gascity/internal/supervisor"
)

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
```

- [ ] **Step 2: Delete the test-only `openWithPassphrase`, `AgeConfigForTest`, `AgeConfigForTestT`**

Search-and-remove from `internal/supervisor/secrets/store.go`:
- The `openWithPassphrase` function
- The `AgeConfigForTestT` type and `AgeConfigForTest` constructor

Search-and-remove from `internal/supervisor/secrets/store_test.go`:
- The duplicate `AgeConfigForTestT` declaration if any
- Replace the existing `openForTest` body with the new wrapper:

```go
import (
	"github.com/gastownhall/gascity/internal/supervisor"
)

// openForTest returns a Store rooted at dir, using passphrase as the
// bootstrap value via env. Sets GC_HOME so DefaultHome() does not
// panic in test binaries even though we override Dir.
func openForTest(t *testing.T, dir, passphrase string) (*Store, error) {
	t.Helper()
	t.Setenv("GC_HOME", t.TempDir())
	t.Setenv(EnvPassphraseVar, passphrase)
	return Open(supervisor.AgeBackendConfig{Dir: dir})
}
```

- [ ] **Step 3: Run the full secrets-package tests**

```bash
go test ./internal/supervisor/secrets/ -count=1 -v
```

Expected: all `TestStore_*` and `TestPassphrase_*` pass against the real
`Open` constructor. (`TestRequiresDedicatedTestenvImportFile` is in `internal/testenv/`, untouched here — runs separately.)

- [ ] **Step 4: Refactor the Loader to use `*Store` instead of `keyring.Keyring`**

Open `internal/supervisor/secrets/secrets.go`. Replace the file's
contents with:

```go
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

// Result is returned by LoadAll.
type Result struct {
	Set     []string // env vars successfully set, sorted
	Missing []string // configured keys not present in the store
	Skipped []string // present but empty value
	Errors  []error  // per-key errors during retrieval
}

// Loader holds state for full-sync reloads. One instance per supervisor
// process lifetime.
type Loader struct {
	mu      sync.Mutex
	lastSet map[string]struct{}
}

// NewLoader returns a Loader. The CGo branch's promptFn argument is
// gone — the age backend resolves passphrases internally via the
// resolution chain.
func NewLoader() *Loader {
	return &Loader{lastSet: make(map[string]struct{})}
}

// LoadAll opens the store, retrieves each configured key, and sets
// the corresponding env var. Per-key errors do not escalate to a
// fatal return; they appear in Result.Errors.
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

// ReloadResult extends Result with diff information.
type ReloadResult struct {
	Result
	Added   []string
	Updated []string
	Removed []string
}

// Reload re-opens the store and reconciles env state with full-sync
// semantics. Idempotent.
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
				rr.Missing = append(rr.Missing, key)
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

// Names returns the names of env vars set on the most recent
// LoadAll/Reload. Used by /v1/supervisor/secrets/status.
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
```

- [ ] **Step 5: Update `secrets_test.go` to use the new Loader API**

Open `internal/supervisor/secrets/secrets_test.go`. Search for every
reference to `OpenKeyring`, `keyring.Item`, `NewLoader(promptFn)`,
`fileBackendConfig`, `seedFileKeyring`, `fixedFilePrompt`. Replace
the seeding helper with:

```go
// seedAgeStore creates a temp-dir-rooted age store with the given
// keys + values, returns a SecretsConfig pointed at it. Sets GC_HOME
// so any default-path computation inside Open doesn't panic.
func seedAgeStore(t *testing.T, keys []string, items map[string]string) supervisor.SecretsConfig {
	t.Helper()
	t.Setenv("GC_HOME", t.TempDir())
	t.Setenv(EnvPassphraseVar, "test-pass")
	dir := t.TempDir()
	cfg := supervisor.SecretsConfig{
		Age: supervisor.AgeBackendConfig{
			Dir:  dir,
			Keys: keys,
		},
	}
	store, err := Open(cfg.Age)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for k, v := range items {
		if err := store.Set(k, []byte(v)); err != nil {
			t.Fatalf("Set %s: %v", k, err)
		}
	}
	return cfg
}
```

Update every existing test in `secrets_test.go` to call `seedAgeStore`
instead of `seedFileKeyring`, and update `NewLoader()` calls to drop
the `promptFn` argument.

**Do NOT delete `testenv_import_test.go`.** That file is generated by
`scripts/add-testenv-import.go` and required by the repo-wide lint test
`TestRequiresDedicatedTestenvImportFile` in `internal/testenv/lint_test.go`.
Removing it breaks the testenv leak-vector scrub for this package's
test binary and fails the lint test.

- [ ] **Step 6: Run the secrets package tests**

```bash
go test ./internal/supervisor/secrets/ -count=1 -v
```

Expected: all pass.

- [ ] **Step 7: Survey ALL `keyring`-import callers in `cmd/gc/`**

```bash
grep -rn "secrets\.NewLoader\|secrets\.OpenKeyring\|secrets\.EnvPasswordPromptFunc\|secrets\.EnvPasswordVar\|99designs/keyring" --include="*.go" cmd/gc/
```

Expected output (each must be addressed in this commit):
- `cmd/gc/cmd_supervisor.go:697` — `secretsLoader = secrets.NewLoader(secrets.EnvPasswordPromptFunc())`
- `cmd/gc/cmd_supervisor.go` (loop nearby) — WARN log says "secrets prefix %q matched zero items in keyring" → reword
- `cmd/gc/cmd_supervisor_secret.go` — `import "github.com/99designs/keyring"`, `secrets.OpenKeyring(...)`, `keyring.Item`, `keyring.ErrKeyNotFound`, `keyring.TerminalPrompt`, `secretPromptFn`
- `cmd/gc/cmd_supervisor_secret_test.go`, `cmd/gc/cmd_start_secrets_test.go`, `cmd/gc/cmd_supervisor_lifecycle_secrets_test.go` — `keyring.Config{FileBackend...}`, `OpenKeyring`, `seedFileKeyring` helpers, `keyring.Item`

- [ ] **Step 8: Update `cmd/gc/cmd_supervisor.go`**

In `runSupervisor`, replace:

```go
secretsLoader = secrets.NewLoader(secrets.EnvPasswordPromptFunc())
```

with:

```go
secretsLoader = secrets.NewLoader()
```

Reword the WARN-Missing log inside the same block from:

```go
fmt.Fprintf(stderr, "gc supervisor: WARN: secrets prefix %q matched zero items in keyring\n", p)
```

to:

```go
fmt.Fprintf(stderr, "gc supervisor: WARN: secrets key %q not present in age store\n", p)
```

And update the variable name `p` → `k` in the loop if it's still called `p` (cosmetic but the new wording reads better with `k`).

- [ ] **Step 9: Rewrite `cmd/gc/cmd_supervisor_secret.go` to drop the `keyring` import**

Open the file. Apply these substitutions in order:

1. **Remove imports:** delete `"github.com/99designs/keyring"` from the import block.
2. **Replace `openSecretRing` (~line 257) and the `secretPromptFn` package var** with:

```go
// openSecretStore opens the configured age store. Replaces the CGo
// branch's openSecretRing.
func openSecretStore(cfg supervisor.Config) (*secrets.Store, error) {
	return secrets.Open(cfg.Secrets.Age)
}
```

   Delete the `secretPromptFn` package var.

3. **Update every call site** of `openSecretRing` → `openSecretStore`. Returns `*secrets.Store` instead of `keyring.Keyring`.

4. **Replace `ring.Set(keyring.Item{Key: name, Data: []byte(value)})`** → `store.Set(name, []byte(value))`.

5. **Replace `ring.Get(name)` (which returned `keyring.Item`)** → `data, err := store.Get(name)` returning `[]byte`. Update the `set` and `list` call sites.

6. **Replace `keyring.ErrKeyNotFound`** → `secrets.ErrNotFound` in `isNotFoundErr`. The `os.IsNotExist` branch becomes redundant (Store.Remove already handles it); remove it.

7. **Rewrite `newSupervisorSecretImportEnvCmd`** (~lines 175-222). The current code reads `cfg.Secrets.Backend` and prints `[secrets.keychain]` or `[secrets.file]`. The age branch only has `[secrets.age]`. Rewrite the body:

```go
return &cobra.Command{
	Use:   "import-env",
	Short: "Migrate from GC_SUPERVISOR_ENV plaintext-in-plist to the age store",
	Long: `Reads each key listed in $GC_SUPERVISOR_ENV from the current shell
environment, writes it to the age store, and prints a suggested
[secrets.age] keys block to add to ~/.gc/supervisor.toml.`,
	Args: cobra.NoArgs,
	RunE: func(c *cobra.Command, args []string) error {
		cfg, err := loadSupervisorConfigForSecrets()
		if err != nil {
			return err
		}
		store, err := openSecretStore(cfg)
		if err != nil {
			return err
		}
		raw := os.Getenv("GC_SUPERVISOR_ENV")
		keys := supervisorServiceExplicitEnvKeys(raw)
		if len(keys) == 0 {
			fmt.Fprintln(stderr, "GC_SUPERVISOR_ENV is empty or unset; nothing to import")
			return nil
		}
		var imported []string
		for _, k := range keys {
			v := os.Getenv(k)
			if v == "" {
				fmt.Fprintf(stderr, "skipping %s: empty in current env\n", k)
				continue
			}
			if err := store.Set(k, []byte(v)); err != nil {
				fmt.Fprintf(stderr, "set %s: %v\n", k, err)
				continue
			}
			imported = append(imported, k)
		}
		sort.Strings(imported)
		fmt.Fprintf(stdout, "Imported %d secrets to age store at %s.\n\n", len(imported), cfg.Secrets.Age.Dir)
		fmt.Fprintln(stdout, "Add the following to ~/.gc/supervisor.toml:")
		fmt.Fprintf(stdout, "\n[secrets.age]\nkeys = [%s]\n", quotedList(imported))
		return nil
	},
}
```

8. **Delete `backendOrAuto` helper** — no longer referenced.

9. **Rewrite `buildSecretRows` (~lines 351-431)**. The current code does prefix-scan over `cfg.Secrets.Keychain.Prefixes` / `cfg.Secrets.File.Prefixes`. The new schema has exact-match `cfg.Secrets.Age.Keys`. Replace the loop:

```go
func buildSecretRows(cfg supervisor.Config) ([]secretRow, error) {
	store, err := openSecretStore(cfg)
	if err != nil {
		return nil, err
	}
	keys, err := store.Keys()
	if err != nil {
		return nil, err
	}
	inStore := make(map[string]bool, len(keys))
	for _, k := range keys {
		inStore[k] = true
	}

	liveByName, liveErr := fetchLiveSupervisorSecrets(cfg.Supervisor.PortOrDefault())

	configured := make(map[string]bool)
	var rows []secretRow
	for _, k := range cfg.Secrets.Age.Keys {
		configured[k] = true
		if !inStore[k] {
			rows = append(rows, secretRow{
				Name:       k,
				Configured: true,
				InKeyring:  false,
				LiveStatus: "no",
				Status:     "MISSING",
			})
			continue
		}
		liveStatus := "(supervisor down)"
		status := "OK"
		if liveErr == nil {
			if live, ok := liveByName[k]; ok {
				liveStatus = "yes"
				data, _ := store.Get(k)
				localSum := sha256.Sum256(data)
				localHash := hex.EncodeToString(localSum[:])
				if live.SHA256 != localHash {
					status = "MISMATCH"
				}
			} else {
				liveStatus = "no"
				status = "STALE"
			}
		}
		rows = append(rows, secretRow{
			Name:       k,
			Configured: true,
			InKeyring:  true,
			LiveStatus: liveStatus,
			Status:     status,
		})
	}
	// Orphans: in store but not in configured.
	for _, k := range keys {
		if !configured[k] {
			rows = append(rows, secretRow{
				Name:       k,
				Configured: false,
				InKeyring:  true,
				LiveStatus: "no",
				Status:     "ORPHAN",
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, nil
}
```

(Note: `secretRow.InKeyring` field name stays for now — it's a public-ish JSON field. Renaming it to `InStore` is cosmetic and out of scope; if you want the rename, do it in a follow-up commit. The list-output table heading `IN-STORE` from the spec is achieved in `printSecretRowsTable` — change the column header string only.)

Update `printSecretRowsTable` heading: change `"IN-KEYRING"` → `"IN-STORE"`.

- [ ] **Step 10: Update CLI test seeders**

In `cmd/gc/cmd_supervisor_secret_test.go`, `cmd/gc/cmd_start_secrets_test.go`, `cmd/gc/cmd_supervisor_lifecycle_secrets_test.go`:

- Drop `import "github.com/99designs/keyring"`.
- Replace any `keyring.Config{FileDir: dir, FilePasswordFunc: promptFn, ...}` test setup with the `seedTestStore` helper from Task 12 (defined there). For now in this commit, inline a minimal version:

```go
// seedTestStore — temporary helper used until Task 12 introduces the
// shared version. Sets up a temp age store rooted at t.TempDir() with
// the given items, returns a supervisor.Config pointed at it.
func seedTestStore(t *testing.T, items map[string]string) supervisor.Config {
	t.Helper()
	t.Setenv("GC_HOME", t.TempDir())
	t.Setenv(secrets.EnvPassphraseVar, "test-pass")
	dir := t.TempDir()
	keys := make([]string, 0, len(items))
	for k := range items {
		keys = append(keys, k)
	}
	cfg := supervisor.Config{
		Secrets: supervisor.SecretsConfig{
			Age: supervisor.AgeBackendConfig{
				Dir:  dir,
				Keys: keys,
			},
		},
	}
	store, err := secrets.Open(cfg.Secrets.Age)
	if err != nil {
		t.Fatalf("secrets.Open: %v", err)
	}
	for k, v := range items {
		if err := store.Set(k, []byte(v)); err != nil {
			t.Fatalf("Set %s: %v", k, err)
		}
	}
	return cfg
}
```

Update WARN-line assertion in `cmd_supervisor_lifecycle_secrets_test.go`: any test asserting `"matched zero items in keyring"` becomes `"not present in age store"`.

- [ ] **Step 11: Delete `keyring.go` and `keyring_test.go`**

```bash
git rm internal/supervisor/secrets/keyring.go internal/supervisor/secrets/keyring_test.go
```

(Do NOT delete `testenv_import_test.go`.)

- [ ] **Step 12: Verify the entire build is green**

```bash
go build ./...
go vet ./...
go test ./internal/supervisor/... ./cmd/gc/... -count=1 -short
```

Expected: all succeed. The `99designs/keyring` package is still in `go.mod` but no longer imported — `go mod tidy` in Task 14 cleans that up.

- [ ] **Step 13: Commit**

```bash
git add internal/supervisor/secrets/ cmd/gc/cmd_supervisor.go cmd/gc/cmd_supervisor_secret.go cmd/gc/cmd_supervisor_secret_test.go cmd/gc/cmd_supervisor_lifecycle_secrets_test.go cmd/gc/cmd_start_secrets_test.go
git commit -m "$(cat <<'EOF'
refactor(supervisor/secrets): swap to *secrets.Store; delete keyring.go

Atomic swap — every importer of github.com/99designs/keyring inside
the gc binary moves to *secrets.Store in one commit so no
intermediate state has a broken build:

- internal/supervisor/secrets/store.go: production Open() with
  passphrase resolution + stamp invariants + .tmp sweep.
- internal/supervisor/secrets/secrets.go: Loader/LoadAll/Reload/Names
  consume *Store directly. NewLoader() takes no args (CGo branch's
  promptFn argument gone). EnvPasswordVar renamed to EnvPassphraseVar.
- internal/supervisor/secrets/keyring.go: deleted.
- cmd/gc/cmd_supervisor.go: NewLoader() callsite updated; WARN-Missing
  log reworded ("not present in age store" vs "matched zero items in
  keyring").
- cmd/gc/cmd_supervisor_secret.go: openSecretRing → openSecretStore
  (returns *secrets.Store). keyring.Item / keyring.ErrKeyNotFound /
  keyring.TerminalPrompt usages all gone. import-env emits
  [secrets.age] keys = [...] block. buildSecretRows replaced with an
  exact-match loop over cfg.Secrets.Age.Keys instead of the prefix
  scan over cfg.Secrets.{Keychain,File}.Prefixes. Dead helpers
  backendOrAuto and secretPromptFn removed. Table heading IN-KEYRING
  → IN-STORE.
- Test seeders in cmd/gc/ updated to use *Store via t.TempDir() +
  t.Setenv(GC_SECRETS_PASSPHRASE, "test-pass") + GC_HOME guard.
- internal/supervisor/secrets/testenv_import_test.go preserved
  (gated by TestRequiresDedicatedTestenvImportFile in
  internal/testenv/lint_test.go).

Build is green; go.mod still lists 99designs/keyring as a require
but no source imports it. Cleaned up by `go mod tidy` in next commit.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: Add overwrite confirmation to `gc supervisor secret set`

**Files:**
- Modify: `cmd/gc/cmd_supervisor_secret.go`, `cmd/gc/cmd_supervisor_secret_test.go`

This task adds the `--force` flag and overwrite-confirmation prompt to `set`. The `*Store` plumbing is already in place from Task 11 — this is feature work on top of it.

- [ ] **Step 1: Update `newSupervisorSecretSetCmd` to add `--force` and the overwrite check**

In the `newSupervisorSecretSetCmd` factory, replace the existing definition with:

```go
func newSupervisorSecretSetCmd(stdout, stderr io.Writer) *cobra.Command {
	var fromStdin, force bool
	cmd := &cobra.Command{
		Use:   "set <NAME>",
		Short: "Store a secret in the configured backend",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			name := args[0]
			cfg, err := loadSupervisorConfigForSecrets()
			if err != nil {
				return err
			}
			store, err := openSecretStore(cfg)
			if err != nil {
				return err
			}
			// Overwrite confirmation. --from-stdin always proceeds because the
			// caller is non-interactive.
			if !force && !fromStdin {
				if _, err := store.Get(name); err == nil {
					if !confirm(c.InOrStdin(), stdout, fmt.Sprintf("Secret %q already exists. Overwrite? (y/N): ", name)) {
						return nil
					}
				}
			}
			value, err := readSecretValue(c.InOrStdin(), fromStdin)
			if err != nil {
				return err
			}
			return store.Set(name, []byte(value))
		},
	}
	cmd.Flags().BoolVar(&fromStdin, "from-stdin", false, "read value from stdin instead of prompting")
	cmd.Flags().BoolVar(&force, "force", false, "skip overwrite confirmation")
	return cmd
}
```

- [ ] **Step 2: Add the overwrite-confirmation tests**

Append to `cmd/gc/cmd_supervisor_secret_test.go`:

```go
func TestSet_NewKey(t *testing.T) {
	cfg := seedTestStore(t, nil)
	configureSupervisorPathForTest(t, cfg)
	stdin := strings.NewReader("first-value\n")
	cmd := newSupervisorSecretSetCmd(io.Discard, io.Discard)
	cmd.SetIn(stdin)
	cmd.SetArgs([]string{"NEW_KEY", "--from-stdin"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	store, err := secrets.Open(cfg.Secrets.Age)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := store.Get("NEW_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "first-value" {
		t.Fatalf("want first-value, got %q", got)
	}
}

func TestSet_OverwritePromptsWithoutForce(t *testing.T) {
	cfg := seedTestStore(t, map[string]string{"EXA_API_KEY": "old"})
	configureSupervisorPathForTest(t, cfg)
	stdin := strings.NewReader("n\n")
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	cmd := newSupervisorSecretSetCmd(stdout, stderr)
	cmd.SetIn(stdin)
	cmd.SetArgs([]string{"EXA_API_KEY"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	store, err := secrets.Open(cfg.Secrets.Age)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := store.Get("EXA_API_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "old" {
		t.Fatalf("value must be unchanged after declining overwrite; got %q", got)
	}
}

func TestSet_OverwriteWithForceSkipsPrompt(t *testing.T) {
	cfg := seedTestStore(t, map[string]string{"EXA_API_KEY": "old"})
	configureSupervisorPathForTest(t, cfg)
	stdin := strings.NewReader("new-value\n")
	cmd := newSupervisorSecretSetCmd(io.Discard, io.Discard)
	cmd.SetIn(stdin)
	cmd.SetArgs([]string{"EXA_API_KEY", "--force", "--from-stdin"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	store, err := secrets.Open(cfg.Secrets.Age)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := store.Get("EXA_API_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "new-value" {
		t.Fatalf("value must be replaced under --force; got %q", got)
	}
}

func TestSet_FromStdinNoPrompt(t *testing.T) {
	// --from-stdin is non-interactive by definition; even when the key
	// already exists, --from-stdin should NOT prompt for overwrite
	// confirmation (no terminal to prompt).
	cfg := seedTestStore(t, map[string]string{"EXA_API_KEY": "old"})
	configureSupervisorPathForTest(t, cfg)
	stdin := strings.NewReader("new-value\n")
	cmd := newSupervisorSecretSetCmd(io.Discard, io.Discard)
	cmd.SetIn(stdin)
	cmd.SetArgs([]string{"EXA_API_KEY", "--from-stdin"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	store, err := secrets.Open(cfg.Secrets.Age)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := store.Get("EXA_API_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "new-value" {
		t.Fatalf("--from-stdin must overwrite without prompting; got %q", got)
	}
}
```

`seedTestStore` and `configureSupervisorPathForTest` are reused from Task 11. Promote `seedTestStore` to a shared helper at the top of `cmd_supervisor_secret_test.go` (move from inline-in-Task-11 to file-level) so all tests reference the same definition; remove any inline duplicates.

- [ ] **Step 3: Run the new tests**

```bash
go test ./cmd/gc/ -run 'TestSet_(NewKey|OverwritePromptsWithoutForce|OverwriteWithForceSkipsPrompt|FromStdinNoPrompt)' -count=1 -v
```

Expected: all four pass.

- [ ] **Step 4: Verify the full build is still green**

```bash
go build ./...
go vet ./...
```

Expected: success.

- [ ] **Step 5: Commit**

```bash
git add cmd/gc/cmd_supervisor_secret.go cmd/gc/cmd_supervisor_secret_test.go
git commit -m "$(cat <<'EOF'
feat(cli): overwrite confirmation in 'gc supervisor secret set'

Adds --force flag and an interactive overwrite-confirmation prompt
when `set <KEY>` would clobber an existing key. --from-stdin always
proceeds without prompting (non-interactive caller). Mirrors the
existing 'delete --force' UX pattern.

Closes round-1 adversarial finding: the CGo branch silently
overwrote on `set`, with no recovery path if the user typed the
wrong value.

Tests cover all four cases:
- new key (no prompt)
- existing key without --force (prompts; "n" aborts)
- existing key with --force (silent overwrite)
- existing key with --from-stdin (silent overwrite, non-interactive)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: Update integration tests

**Files:**
- Modify: `test/integration/secrets_integration_test.go`

The keyring-removal already happened atomically in Task 11. This task only updates the integration tests to use `*Store` seeding and rename keyring-flavored test names.

- [ ] **Step 1: Survey what the integration test currently does**

```bash
grep -n "Keyring\|keyring\|OpenKeyring\|99designs" test/integration/secrets_integration_test.go
```

Expected: hits referencing `OpenKeyring` setup + test names with `Keyring` in them.

- [ ] **Step 2: Rewrite the test seeders to use `*Store`**

Use the same pattern as `cmd/gc/cmd_supervisor_secret_test.go::seedTestStore` (Task 11's helper) — create a temp directory, set env, call `secrets.Open(cfg.Secrets.Age)`, then `store.Set` each seed value. The integration scope difference: the test exec's the supervisor binary as a child process, so the seed dir must live somewhere the child also reads (set `GC_HOME=<test-tmp-dir>` and the child finds it via supervisor.toml that the test writes).

Rename test functions:
- `TestSupervisor_LoadsKeyringSecretsAtStartup` → `TestSupervisor_LoadsAgeSecretsAtStartup`
- `TestSupervisor_KeyringSIGHUPReload` → `TestSupervisor_AgeSIGHUPReload`
- (any other `*Keyring*` → `*Age*`)

- [ ] **Step 3: Decide on the macOS-Keychain integration test**

The spec lists `TestSupervisor_KeychainPassphraseBootstrap` (`//go:build integration && darwin`) as an integration test. Two options:

- **(A)** Add it as `t.Skip("manual smoke step — see plan Task 15")` so it sits as future scaffolding.
- **(B)** Omit it entirely; the manual smoke procedure in Task 15 covers it.

**Choose (B).** A `t.Skip` test that always skips clutters output without adding signal; the manual smoke recipe in Task 15 is sufficient documentation of how to verify the bootstrap path.

- [ ] **Step 4: Run the integration tests**

```bash
go test ./test/integration/ -tags=integration -run TestSupervisor_Age -count=1 -v
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add test/integration/secrets_integration_test.go
git commit -m "$(cat <<'EOF'
test(integration): supervisor age-store load + SIGHUP reload

Renames the CGo branch's TestSupervisor_*Keyring* tests to
TestSupervisor_*Age*, swaps the seed setup from a keyring.Config{
FileBackend...} to a *secrets.Store rooted at the test's GC_HOME,
asserts the same end-to-end behavior: child process inherits
secret env vars at startup; SIGHUP-reload picks up changes for
post-HUP child spawns.

The macOS-Keychain bootstrap integration test from the spec is
omitted in favor of the manual smoke recipe in Task 15 — a always-
skip test would add no signal.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 14: Drop `github.com/99designs/keyring` dependency

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Tidy modules**

```bash
go mod tidy
```

Expected: `github.com/99designs/keyring` and `github.com/99designs/go-keychain`
disappear from `go.mod` (no remaining importers).

- [ ] **Step 2: Confirm**

```bash
grep -E '99designs' go.mod go.sum
```

Expected: zero hits.

- [ ] **Step 3: Verify build is still green**

```bash
CGO_ENABLED=0 go build ./...
go vet ./...
```

Expected: both succeed cleanly. The `CGO_ENABLED=0` is the load-bearing
distribution invariant.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "$(cat <<'EOF'
chore(deps): drop github.com/99designs/keyring dependency

No remaining importers — *secrets.Store and the age library cover
the full surface.

Verifies the distribution invariant: CGO_ENABLED=0 go build ./...
succeeds without any platform-specific link dependencies.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 15: Pre-flight quality gates + push

**Files:** none (verification only)

- [ ] **Step 1: Run all listed quality gates from AGENTS.md**

```bash
make test                                  # fast unit baseline
go vet ./...                               # vet clean
make dashboard-check                       # internal/api/ untouched in this branch but verify
CGO_ENABLED=0 go build ./...               # distribution invariant
goreleaser check                           # .goreleaser.yml shape
```

Each must succeed. If any fail, fix and re-commit (small fix-up commit
is fine; no need to amend earlier commits).

- [ ] **Step 2: Manual smoke on macOS**

End-to-end migration recipe from the spec:

```bash
# Use a temporary GC_HOME so the smoke doesn't touch real data.
export GC_HOME=$(mktemp -d -t gc-smoke)
mkdir -p "$GC_HOME"

# Build & run from the branch.
go build -o /tmp/gc-smoke ./cmd/gc

# Set up the bootstrap passphrase in macOS Keychain (interactive).
security add-generic-password -U \
  -s gc-supervisor-passphrase \
  -a "$USER@personal" \
  -T "" \
  -w
# (security prompts twice for the password — type it both times)

# Configure supervisor.toml.
mkdir -p "$GC_HOME"
cat > "$GC_HOME/supervisor.toml" <<'EOF'
[supervisor]
port = 19876

[secrets.age]
keys = ["EXA_SMOKE_KEY"]
EOF

# Seed a secret.
/tmp/gc-smoke supervisor secret set EXA_SMOKE_KEY
# (prompts for value)

# List should show OK.
/tmp/gc-smoke supervisor secret list

# Cleanup: delete the temporary Keychain item.
security delete-generic-password -s gc-supervisor-passphrase -a "$USER@personal" || true
rm -rf "$GC_HOME"
unset GC_HOME
```

Expected: smooth flow, secret stored under `$GC_HOME/secrets/EXA_SMOKE_KEY.age`,
`list` shows `EXA_SMOKE_KEY: OK`.

- [ ] **Step 3: Push**

```bash
git push -u seanb4t feat/supervisor-secrets-age
git status                  # MUST show "up to date with origin"
```

- [ ] **Step 4: Open the side-by-side comparison summary for upstream**

Per the spec's rollout section, this branch is offered upstream alongside
`feat/supervisor-secrets-keychain`. Prepare a short note for the PR
description (in your PR body, not a commit):

```markdown
## Two parallel branches; pick one

- `feat/supervisor-secrets-keychain` (CGo, OS-keychain backend)
- `feat/supervisor-secrets-age` (this branch — pure Go, age files)

Same supervisor-managed-secrets feature surface; different
distribution model + storage layout. See the head of each spec for
the trade-off summary.
```

(No code commit; this is the PR description.)

---

## Self-review checklist (run before declaring done)

After completing all tasks, run this self-review against the spec:

1. **Spec coverage:** Skim every section of `engdocs/design/supervisor-secrets-v0.md`. Decision rows 1-12 must each map to an implemented task above:
   - Row 1 (exact-match keys) → Task 10 validation
   - Row 2 (WARN-loud-and-continue) → Task 11 LoadAll
   - Row 3 (no per-secret OS-keychain) → entire branch
   - Row 4 (account default) → Task 11 production `Open()` + Task 8 keychainBootstrap
   - Row 5 (CLI subcommand tree) → Tasks 11 + 12
   - Row 6 (no backend enum) → Task 10
   - Row 7 (startup + SIGHUP reload) → Task 11 (Loader stays unchanged in shape; SIGHUP wiring inherited from CGo branch)
   - Row 8 (full-sync semantics) → Task 11 Reload
   - Row 9 (one file per secret) → Task 3
   - Row 10 (passphrase chain) → Tasks 7-9
   - Row 11 (stamp invariants) → Tasks 5-6
   - Row 12 (keyfile outside secrets dir) → Task 11 production `Open()` + Task 7 keyfile resolution

2. **Placeholder scan:** No `TODO` / `TBD` / "implement appropriate error handling" anywhere in this plan. Every step has either complete code or an exact bash command.

3. **Type consistency:**
   - `*Store`, `secrets.Open(cfg.Age)`, `secrets.ErrNotFound`, `secrets.EnvPassphraseVar` used consistently across Tasks 9-12.
   - `supervisor.AgeBackendConfig` used everywhere the new schema applies (Tasks 9, 10, 11, 12).
   - `keychainBootstrap`, `cmdRunner`, `detectGOOS` consistent across Task 8 + tests.
   - Stamp constants (`stampFileName`, `stampPlaintext`, `tmpSuffix`, `ageSuffix`) defined once in Task 2 and referenced everywhere else.
   - `tmpSweepAge` typed as `time.Duration` directly; consumers use `time.Now().Add(-tmpSweepAge)`.

4. **Coverage of adversarial-review fixes:**
   - Bootstrap-command-correctness (round-2 critical #1) → Task 8 + Task 15 manual smoke + spec migration section.
   - Stamp invariants (round-2 critical #2) → Task 6.
   - No `Backend` interface (round-2 major #4) → entire plan uses `*Store` directly.
   - Lstat + symlink rejection (round-2 major) → Task 7.
   - 5s `security` timeout (round-2 major) → Task 8.
   - Stale `.tmp` sweep at Open() (round-2 major) → Task 5.
   - Drop vestigial `[secrets].backend` field (round-2 minor) → Task 10.
   - Rename `keychain_account` → `passphrase_keychain_account` (round-2 minor) → Task 10.
   - Versioned stamp string (round-2 minor) → Task 2 const + Task 6 `TestStore_StampFormatStringIsConstant`.
   - Strict TOML decode for unknown sections (round-2 minor) → Task 10.

5. **Coverage of plan-review fixes (round-3 review of this plan):**
   - `testenv_import_test.go` preserved (round-3 critical) → Task 11 explicit "do NOT delete" note.
   - Atomic Loader+CLI+keyring-delete swap (round-3 critical: broken intermediate cmd/gc commit) → Task 11 absorbs all of Task 11+12+13's keyring-removal work.
   - `import-env` rewrite to emit `[secrets.age]` (round-3 critical) → Task 11 Step 9.
   - `buildSecretRows` exact-match rewrite (round-3 critical) → Task 11 Step 9.
   - `cmd/gc/cmd_supervisor.go:697` Loader callsite (round-3 major) → Task 11 Step 8.
   - `tmpSweepAge` typed as `time.Duration` (round-3 major) → Task 2.
   - `t.Setenv("GC_HOME", t.TempDir())` in test seeders to avoid `DefaultHome()` panic (round-3 major) → Tasks 11 + 12.
   - Spec test names added: `TestStore_ConcurrentSetDifferentKeys`, `TestStore_StampFormatStringIsConstant`, `TestSet_NewKey`, `TestSet_FromStdinNoPrompt` (round-3 major) → Tasks 6 + 12.
   - `t.Skip` darwin integration test omitted (round-3 minor) → Task 13 chooses option (B).

6. **Distribution invariant:** Task 1 reverts the CGo release switch; Task 14 verifies `CGO_ENABLED=0 go build ./...` clean; Task 15 re-verifies. The invariant survives.

7. **Import-block instruction discipline:** every "add `import X`" instruction in this plan reads as "add `\"X\"` to the existing `import (...)` block at the top of the file." A subagent merging code blindly should NEVER produce a second `import` block — if you find yourself about to add one, the existing block is somewhere above; merge into it.

---

**Plan complete and saved to `plans/supervisor-secrets-age.md`.**

Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
