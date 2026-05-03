# Supervisor secrets v0 — age-encrypted secret loading

**Status:** Design (2026-05-02, pivoted 2026-05-03 to age-only)
**Author:** Sean Brandt
**Implementation target:** github.com/seanb4t/gascity → PR upstream
**Related:** `engdocs/design/machine-wide-supervisor-v0.md`, `engdocs/contributors/primitive-test.md`

> **Branch note.** This spec describes the **`feat/supervisor-secrets-age`**
> branch — pure-Go, no CGo. Secrets live in `~/.gc/secrets/<KEY>.age`,
> encrypted with `filippo.io/age` under a single passphrase. The passphrase
> itself can come from a macOS Keychain item (a single `security` lookup at
> startup) so daily-driver Mac users don't type it; CI uses
> `GC_SECRETS_PASSPHRASE`; Linux daily-drivers can use a `0600` keyfile. No
> per-secret subprocess to `security`, no Keychain backend. A parallel branch
> `feat/supervisor-secrets-keychain` exists with a different UX — secrets stored
> as individual macOS Keychain items via `github.com/99designs/keyring` (CGo).
> Both are offered upstream as **alternatives, not equivalents**: pick this
> branch for distribution simplicity (`CGO_ENABLED=0`, single static binary,
> works identically on every supported platform) or the CGo branch for native
> per-secret OS Keychain integration.

## Problem

Today the machine-wide supervisor receives third-party API keys (EXA, Firecrawl, Linear, etc.) through one of two mechanisms, both with structural problems:

1. **`GC_SUPERVISOR_ENV` allow-list** (`cmd/gc/cmd_supervisor_lifecycle.go:425`) snapshots env-var values plaintext into `~/Library/LaunchAgents/com.gascity.supervisor.plist` at install time. The plist is `0600` but still ends up in Time Machine backups, leaks via `plutil -p`, and re-keys require re-running install.
2. **Hardcoded provider-credential prefixes** (`cmd/gc/cmd_supervisor_lifecycle.go:403`) auto-snapshot `ANTHROPIC_*`, `GEMINI_*`, `GOOGLE_*`, `OPENAI_*` from the install-time shell. Same plaintext-on-disk concern, with no opt-out.

Users who try to work around this with a launchd `ProgramArguments` wrapper script that pulls from macOS Keychain hit a deeper issue: `gc start` calls `ensureSupervisorRunning` (`cmd/gc/cmd_supervisor_city.go:213`), which unconditionally calls `doSupervisorInstall` (`cmd/gc/cmd_supervisor_lifecycle.go:138`). The plist is regenerated from `supervisorLaunchdTemplate` on every routine city startup, clobbering any wrapper patch and bouncing the supervisor with the clean version. Plist-side patches are fundamentally fragile.

## Goal

Add config-driven, in-process secret loading to `gc supervisor run` that:

- Loads named secrets from a platform secret store at supervisor startup and on `SIGHUP`.
- Stores nothing plaintext on disk and leaves zero footprint in the launchd plist.
- Works regardless of how `supervisor run` is launched (launchd, systemd, direct invocation).
- Leaves room for systemd / Linux Secret Service / Windows Credential Manager backends in the future without breaking the v1 API.

## Non-goals (v1)

- 1Password / Vault / sops integration — future contribution; the parallel CGo branch covers OS-keychain integration if that's the shape you want.
- Per-secret OS-keychain entries — covered by the CGo branch; intentionally out of scope here.
- Linux Secret Service / D-Bus integration — deferred to a future PR; we don't ship what we can't test against.
- Per-city secret allowlists — `city.toml`'s `allow_env_override` already filters which env vars reach which agents; do not duplicate.
- Hot rotation of secrets *into running children* — SIGHUP updates supervisor env + future spawns; existing children keep their pre-spawn env (Unix process env is immutable post-spawn).
- Encrypted-at-rest `supervisor.toml` — config remains plaintext; secrets themselves never appear in it.
- Auto-discovery of unconfigured store items — the supervisor never loads anything not declared in `keys`. `gc supervisor secret list` surfaces orphans as a hint only.
- Deprecation of `GC_SUPERVISOR_ENV` — coexists in v1; future call.

## Distribution constraints

This branch keeps the existing pure-Go (`CGO_ENABLED=0`) release pipeline
unchanged. No goreleaser-cross switch, no Docker-based release builds, no new
toolchain pins.

- **All platforms**: `filippo.io/age` (pure-Go, MIT) for encrypted-file storage.
  No CGo, no D-Bus, no Apple Security framework linkage, no third-party keyring
  abstraction. One uniform code path on every supported platform.
- **macOS-only convenience**: `/usr/bin/security(1)` is invoked at most once per
  supervisor startup as a *read-only* lookup of the age passphrase
  (`security find-generic-password -s gc-supervisor-passphrase -a $account -w`).
  This is opt-in via the passphrase resolution chain — when env / keyfile are
  unset and the binary is on darwin, gc tries Keychain before prompting. No
  per-secret `security` calls; no `add-generic-password` from gc (the user runs
  it themselves once, manually, to seed the passphrase).
- **Windows**: not a release target. `.goreleaser.yml` builds `linux + darwin`
  only; existing `_windows.go` files are developer-build stubs and remain so.

**Why this trade-off.** The CGo branch (`feat/supervisor-secrets-keychain`)
puts the in-process OS-keychain abstraction first and accepts CGo
cross-compilation as the cost. This branch is a different product: distribution
simplicity first, encrypted-file storage instead of OS-keychain entries. The
upstream pitch is "pick the UX you want": one keychain entry per secret (CGo)
or one age-encrypted file per secret (this branch). Both keep secrets out of
plaintext config and out of `os.Environ()` snapshots.

**Cross-platform code shape.** No `//go:build` constraints on backend code.
The macOS-Keychain passphrase-bootstrap call is a `runtime.GOOS == "darwin"`
guard around an `exec.Command("security", ...)`; the call compiles on every
platform (only fails at exec time on non-darwin, which the guard prevents).
This matches the existing `runtime.GOOS` switch pattern in the CGo branch's
`keyring.go` and keeps every test runnable on Linux CI.

## Design decisions (settled)

| # | Decision | Rationale |
|---|---|---|
| 1 | Single `keys` list; every entry is an exact key name (no prefix matching) | Multi-key prefix matching from the CGo branch is dropped — exact-match is unambiguous and matches the per-file storage layout one-to-one. |
| 2 | Missing/empty matches: WARN-loud-and-continue | Supervisor is shared infrastructure; one missing third-party key must not bring it down. AGENTS.md "Don't Swallow Errors" satisfied by the WARN log entry. |
| 3 | Backend: `filippo.io/age` only — no per-secret OS-keychain integration | One uniform code path. Pure Go, MIT-licensed, well-respected. The CGo branch covers OS-keychain integration for users who want that shape; this branch optimizes for distribution simplicity (`CGO_ENABLED=0`, single binary). |
| 4 | Account (passphrase Keychain item): configurable, default `$USER@personal` | Used only for the macOS-Keychain passphrase-bootstrap step. Matches the CGo branch's account convention; leaves room for `sean@personal` vs `sean@work` later. |
| 5 | New CLI subcommand: `gc supervisor secret {set,get,list,delete,reload,import-env}` with drift detection in `list` | Cross-platform UX — users don't need to know about age files, file permissions, or `security`. Drift detection surfaces config-vs-store-vs-supervisor disagreement at a glance. |
| 6 | No `backend` enum — age is implicit | The `[secrets].backend` field exists for forward compatibility (so future `secret-service` / `1password` additions don't break existing configs), but the only allowed values in v1 are `""` (default) and `"age"`. Anything else is a validation error pointing users to the CGo branch if they wanted OS-keychain. |
| 7 | Loading model: startup load + SIGHUP reload (Approach 3) | ~50 lines beyond startup-only; meaningful UX win for rotation. Lazy spawn-time injection (better security) deferred to v2. |
| 8 | "Full sync" reload semantics | Keys removed from the store between reloads are `os.Unsetenv`'d. Tracked via `lastSet` map on the `Loader`. |
| 9 | age on-disk format: one file per secret under `cfg.Age.Dir` | `<dir>/<KEY>.age` per secret, atomic rename via `<KEY>.age.tmp`. Per-file blast radius — corrupting one file doesn't lose the others. No global lock needed for concurrent `set` of different keys. |
| 10 | Passphrase resolution chain: env → keyfile → macOS Keychain → TTY prompt | Each step is more explicit than the next. CI uses env (`GC_SECRETS_PASSPHRASE`), daily-driver macOS uses Keychain (one `security` call at startup, no per-secret subprocess), Linux daily-driver uses a `0600` keyfile, interactive prompt is the last resort. |
| 11 | Passphrase verification at `Open()` via sentinel file | First `Set` writes a `.gc-secrets-stamp.age` containing a known plaintext. Subsequent `Open` calls decrypt-and-verify the stamp before serving any `Get`/`Set`. Mismatch fails fast with a clear error rather than silently surfacing per-secret decryption errors. |
| 12 | Passphrase keyfile lives **outside** the secrets dir | Default `~/.gc/.secrets-passphrase` (sibling of `~/.gc/secrets/`), not inside it. Avoids any naming collision with `<KEY>.age` files and makes the secrets dir contain only `*.age` plus the stamp. |

## Architecture

### Module layout

`internal/supervisor/secrets/` (sibling of `internal/supervisor/config.go`, `publications.go`, `registry.go`).

```
internal/supervisor/secrets/
├── backend.go        # Backend interface + Open() constructor + ErrNotFound sentinel
├── secrets.go        # public API: Loader, LoadAll, Reload (consumes Backend)
├── secrets_test.go   # unit tests using ageBackend in t.TempDir()
├── age.go            # ageBackend: per-file age encryption under cfg.Age.Dir
├── age_test.go       # round-trip + corruption + concurrency tests
├── passphrase.go     # passphrase resolution: env → keyfile → macOS Keychain → TTY
└── passphrase_test.go
```

**Why a `Backend` interface with one current implementation:** the v1 spec ships
only the age backend, but the CLI and `Loader` consume an interface
(`Get`/`Set`/`Remove`/`Keys`) so that (a) tests can substitute an in-memory
fake without touching real filesystem state, (b) future backends — e.g., a
Linux Secret Service driver, or 1Password integration — slot in without
disturbing call sites. The "no premature abstraction" rule is satisfied by the
test-fake counting as a real second implementation.

This is the same pattern gascity follows elsewhere (e.g., `internal/api/genclient`
insulates HTTP types from the domain model).

### Wired into

- `cmd/gc/cmd_supervisor_lifecycle.go` — `runSupervisor` calls `secrets.LoadAll(cfg)` after config load, before API server bind. SIGHUP handler installed.
- `cmd/gc/cmd_supervisor_secret.go` — registers the `gc supervisor secret` subcommand tree. Consumes `secrets.Backend` interface only; no direct keyring-library types.
- `internal/supervisor/config.go` — extends `Config` with `Secrets SecretsConfig` field + validation.
- `internal/api/` — endpoint `GET /v1/supervisor/secrets/status` for drift detection.

## Config schema

### Go types

```go
type Config struct {
    Supervisor  Section           `toml:"supervisor"`
    Publication PublicationConfig `toml:"publication,omitempty"`
    Secrets     SecretsConfig     `toml:"secrets,omitempty"`
}

type SecretsConfig struct {
    Backend string           `toml:"backend,omitempty"` // "" or "age" (v1)
    Age     AgeBackendConfig `toml:"age,omitempty"`
}

type AgeBackendConfig struct {
    // Dir is where <KEY>.age files (and the .gc-secrets-stamp.age sentinel)
    // are stored. Default "$GC_HOME/secrets" (typically ~/.gc/secrets).
    Dir string `toml:"dir,omitempty"`

    // PassphraseFile is the path to the optional 0600 keyfile holding the
    // age passphrase. Default "$GC_HOME/.secrets-passphrase" — sibling of
    // Dir, NOT inside it, to avoid filename collisions with secret files.
    PassphraseFile string `toml:"passphrase_file,omitempty"`

    // KeychainAccount is the account field for the macOS Keychain
    // passphrase-bootstrap lookup. Default "$USER@personal". Used only on
    // darwin, only when env + keyfile resolution failed. The Keychain item
    // is identified by service_name="gc-supervisor-passphrase" + this
    // account; gc never writes to it (the user runs `security
    // add-generic-password` once manually to seed it).
    KeychainAccount string `toml:"keychain_account,omitempty"`

    // Keys are the env-var names to load. Each must exist as <KEY>.age
    // under Dir at supervisor startup; missing keys WARN-and-continue.
    Keys []string `toml:"keys"`
}
```

### On-disk shape (`~/.gc/supervisor.toml`)

```toml
[supervisor]
port = 9876

[secrets]
# backend = "age" is the default and only allowed value in v1.
# Omit or set explicitly. Anything else fails validation with a pointer
# to the parallel feat/supervisor-secrets-keychain branch for users who
# want OS-keychain integration.

[secrets.age]
keys = ["EXA_API_KEY", "FIRECRAWL_KEY", "LINEAR_TOKEN"]
# Each entry is an exact env-var name. Files at <dir>/<KEY>.age must be
# present at startup; missing files WARN-and-continue. Defaults:
#   dir              = "$GC_HOME/secrets"
#   passphrase_file  = "$GC_HOME/.secrets-passphrase"  (optional 0600 keyfile)
#   keychain_account = "$USER@personal"                (macOS bootstrap only)
```

### Filesystem layout under `cfg.Age.Dir`

```
~/.gc/secrets/
├── EXA_API_KEY.age          # ciphertext of EXA_API_KEY's value
├── FIRECRAWL_KEY.age
├── LINEAR_TOKEN.age
├── .gc-secrets-stamp.age    # sentinel for passphrase verification
└── <key>.age.tmp            # temporary, only during atomic rename
                             # filtered out by Keys()/LoadAll
```

The passphrase keyfile (`~/.gc/.secrets-passphrase`) is **not** in this
directory — it's a sibling, so `Keys()` enumeration cannot accidentally
treat it as a secret.

### Validation

Implemented as `func (c SecretsConfig) Validate(reservedKey func(string) bool) error` in `internal/supervisor/config.go`. The `reservedKey` predicate is injected by the caller (cmd/gc passes its `isReservedSupervisorEnvKey`) to avoid an `internal/supervisor` → `cmd/gc` import cycle. Same-package tests pass `nil`, which falls back to a minimal default recognizing only `PATH` and `GC_HOME`. Fail-fast at config-load time, not at backend query time.

| Rule | Error |
|---|---|
| `Backend` not `""` or `"age"` (v1) | `secrets.backend: %q is not supported in this build; only "age" is available. For OS-keychain integration use the feat/supervisor-secrets-keychain branch.` |
| Key doesn't match env-var-name shape | `secrets.age.keys[%d]: %q is not a valid env-var name`. **Reuse `supervisorServiceEnvNameRE` from `cmd_supervisor_lifecycle.go:381`** — promote it to a package-level export rather than duplicating the regex literal. |
| Key shadows reserved env var | `secrets.age.keys[%d]: %q would shadow reserved env var`. Check against the union of `supervisorServiceFixedEnvKeys` (GC_HOME, PATH, XDG_RUNTIME_DIR — supervisor sets these itself) and `supervisorServiceEnvKeys` (HOME, USER, SHELL, LANG, etc. — auto-persist whitelist). Implementation: extract a single `isReservedSupervisorEnvKey(name) bool` helper in `cmd/gc/cmd_supervisor_lifecycle.go` that consults both maps; call it from both the install path's existing checks and the new `SecretsConfig.Validate`. |

### Passphrase resolution

The age backend encrypts every file with a single passphrase, resolved at
`Open()` time and cached on the backend instance for its lifetime. The
resolution chain — most explicit user intent wins:

1. **`GC_SECRETS_PASSPHRASE` env var.** Non-empty value used directly. Intended
   for CI, headless systemd-managed gc, and container deployments.
2. **Keyfile at `cfg.Age.PassphraseFile`** (default `~/.gc/.secrets-passphrase`).
   Plain UTF-8, mode strictly `0600` (mode verified by `os.Stat` — any
   `mode & 0o077 != 0` is **rejected with a hard error** at `Open()`, not
   auto-fixed: a wrong-permissions keyfile is a configuration mistake the user
   should fix consciously, not have papered over). Use case: "save once, never
   type again" on Linux daily-drivers.
3. **macOS Keychain bootstrap (darwin only).** A single read-only call:
   `security find-generic-password -s gc-supervisor-passphrase -a $account -w`.
   Exit 0 → stdout (one trailing newline stripped) is the passphrase. Exit 44
   → not found, fall through to step 4. Other non-zero → log WARN, fall
   through to step 4. **gc never writes to this Keychain item.** The user
   seeds it once, manually, with `security add-generic-password -U -s gc-supervisor-passphrase -a $account` — note no `-w` argument so `security` reads the password from stdin/terminal, not argv (avoids process-table leak). Documented in the migration section.
4. **Interactive TTY prompt.** `golang.org/x/term.IsTerminal` checked first;
   non-TTY → fail with the documented error message verbatim
   (`"no passphrase: set GC_SECRETS_PASSPHRASE, place a 0600 keyfile at <path>, run on macOS with the gc-supervisor-passphrase Keychain item, or run interactively"`).
   TTY case → `term.ReadPassword(int(os.Stdin.Fd()))`.

### Passphrase verification at Open

Each `Open()` decrypts a sentinel file `<cfg.Age.Dir>/.gc-secrets-stamp.age`
before serving any `Get`/`Set`. The stamp's plaintext is a constant
`gc-supervisor-secrets-stamp-v0`. Three cases:

- **No stamp file present** (first-ever `Open`): the first successful `Set`
  creates one atomically, encrypted with the resolved passphrase.
- **Stamp present, decrypts successfully**: continue.
- **Stamp present, decrypts to wrong plaintext or fails**: `Open()` returns a
  hard error: `secrets: passphrase does not match existing store at <dir>; refusing to open. If you rotated the passphrase, re-encrypt the store with 'gc supervisor secret rotate-passphrase' (deferred to v2; until then, delete <dir> and re-run 'gc supervisor secret set' for each key).`

This catches the silent-decryption-failure mode the adversarial review flagged:
without the stamp, a user who changes their `GC_SECRETS_PASSPHRASE` would see
each `Get` fail individually as a "decryption error" with no clear
attribution. With it, `Open()` fails up front with an actionable message.

### Coexistence with `GC_SUPERVISOR_ENV`

- `GC_SUPERVISOR_ENV` mechanism unchanged in v1.
- If a key is set by both: age-loaded secret wins. Document precedence.
- `gc supervisor install` help text gains a one-line note pointing users to `[secrets.age]` for new secret needs. Hard deprecation deferred.

## Loading flow

### Startup ordering in `runSupervisor`

```
1. Acquire supervisor lock                       (existing)
2. Load ~/.gc/supervisor.toml                    (existing — extend to populate cfg.Secrets)
3. Validate cfg.Secrets                          (NEW — fail-fast on bad config)
4. secrets.LoadAll(ctx, cfg.Secrets)             (NEW)
5. Install SIGHUP handler                        (NEW — closure captures cfg path + Loader)
6. Bind API server                               (existing)
7. Begin reconciliation loop                     (existing)
```

Secret load happens **after** config load and validation, **before** the API server binds — surfaces passphrase or backend misconfiguration before any city tries to connect.

### Per-command opt-in for non-supervisor entry points

The supervisor process loads secrets in `runSupervisor`. Other gc entry points that perform MCP template expansion in their own process (not via the supervisor) must call `loadStartupSecrets` themselves — `MCPTemplateData` consults `os.Environ()` for keys listed in `cfg.AgentDefaults.AllowEnvOverride`, and that env needs to contain the keychain values.

**Current opt-in sites:**
- `gc start` (`cmd/gc/cmd_start.go`, `doStartStandalone`) — projects MCP for stage-1 validation.
- `gc mcp list` (`cmd/gc/cmd_mcp.go`) — inspection command that runs the same projection.
- `gc doctor` (`cmd/gc/cmd_doctor.go`) — `mcp-config` health check runs projection.

**Why per-command, not `cobra.PersistentPreRunE`:** loading secrets on every gc invocation forces a passphrase resolution (and an age decryption per key) for every `gc version`, `gc bd ready`, etc. On macOS users who use the Keychain bootstrap, that's also a `security` subprocess call per invocation. Per-command opt-in localizes the cost to commands that actually need projection. The maintenance burden is "remember to add the call when you write a new projection-touching command" — small enough that the alternative isn't worth it.

**`loadStartupSecrets` is non-fatal:** missing `supervisor.toml` returns silently; backend errors log to stderr but don't abort the caller. Safe to call from any entry point.

### `LoadAll` algorithm

```go
type Result struct {
    Set     []string  // env vars successfully set, sorted
    Missing []string  // configured keys not present in the backend
    Skipped []string  // present but empty value
    Errors  []error   // per-key errors during retrieval
}

func (l *Loader) LoadAll(ctx context.Context, cfg SecretsConfig) (Result, error)
```

Per-load:

1. `secrets.Open(cfg)` — returns the age `Backend`. `Open` resolves the
   passphrase via the chain in "Passphrase resolution" above and verifies
   against the stamp file. If any of that fails, return `(Result{}, err)`;
   caller logs ERROR and continues. Supervisor stays up with no secrets
   loaded.
2. For each configured key (exact match — no prefix expansion):
   - `backend.Get(key)`.
     - `ErrNotFound` → append to `Result.Missing`, continue.
     - Other error → append to `Result.Errors`, continue.
     - Success with empty bytes → append to `Result.Skipped`, do not
       `os.Setenv`.
     - Success with non-empty bytes → `os.Setenv(key, string(data))`, append to
       `Result.Set`.
3. Update `l.lastSet` (used by `Reload` for full-sync semantics).

`backend.Keys()` is **not** called by `LoadAll` — keys come from the config's
exact-match `keys` list. `Keys()` is exclusively used by the CLI's `list`
command for drift detection (orphan reporting), and reads `os.ReadDir(cfg.Age.Dir)`
filtered to files matching `*.age` and **not** ending in `.age.tmp` or named
`.gc-secrets-stamp.age`.

### Failure-mode matrix

| Failure | Behavior | Log level |
|---|---|---|
| `secrets.Open()` fails (bad config / missing passphrase / CLI exec failure) | Return error; supervisor logs ERROR and continues. Not fatal. | ERROR |
| Configured key not present in backend (`ErrNotFound`) | Append to `Missing`, continue. | WARN |
| `backend.Get(key)` fails (permission, decryption, transport) | Append to `Errors`, continue with other keys. | WARN |
| Key value is empty | Append to `Skipped`, do not call `os.Setenv`. | WARN |

**No backend failure brings down the supervisor.** Worst case: secrets
unavailable; agents that need them fail when invoked, with a clear chain of
evidence in `supervisor.log`.

### age backend write path (`Set`)

```
1. tmpPath := filepath.Join(cfg.Age.Dir, key + ".age.tmp")
2. f, _   := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
3. age.Encrypt(f, scryptRecipient, plaintext)
4. f.Sync(); f.Close()
5. os.Rename(tmpPath, filepath.Join(cfg.Age.Dir, key + ".age"))
6. dir.Sync()                                       // crash-safety
```

The `.age.tmp` suffix is filtered out of `Keys()` and `LoadAll`, so a crashed
`Set` mid-write leaves at most a stale `.tmp` file (cleaned up on the next
successful `Set` of the same key). Two concurrent `Set` calls on different
keys race-safe through atomic rename. Two concurrent `Set` calls on the same
key: last writer wins, but the file is always either pre-write or
post-rename — never half-written.

### age backend read path (`Get`)

```
1. f, err := os.Open(filepath.Join(cfg.Age.Dir, key + ".age"))
   - os.IsNotExist(err) → return ErrNotFound
   - other error → return wrapped error
2. plaintext, err := age.Decrypt(f, scryptIdentity)
   - decrypt error → return wrapped error (passphrase already verified at Open)
3. return plaintext, nil
```

### `Reload` algorithm (full-sync)

```go
type ReloadResult struct {
    Result
    Added   []string
    Updated []string
    Removed []string
}

func (l *Loader) Reload(ctx context.Context, cfg SecretsConfig) (ReloadResult, error)
```

1. Re-open the backend (config may have changed; `Open` is cheap — passphrase
   resolution + stamp verify, no per-secret work).
2. For each configured key, run the same per-key flow as `LoadAll`: `Get`,
   classify into `Set` / `Missing` / `Skipped` / `Errors`.
3. Compare against `l.lastSet`:
   - In new set, not in `lastSet` → append to `Added`.
   - In new set with value differing from current `os.Getenv(key)` → append to
     `Updated`.
   - In `lastSet`, not in new set → `os.Unsetenv(key)`, append to `Removed`.
4. Replace `l.lastSet` with new set.

Reload is idempotent — calling twice with no changes yields empty
Added/Updated/Removed.

### SIGHUP handler

Re-reads `supervisor.toml` AND re-runs the secret load. Edge cases:

- **`Backend` field changed**: validation rejects anything other than `""` / `"age"`. WARN + keep old config.
- **Validation fails on reload**: WARN + ignore. Old config remains active.
- **Concurrent SIGHUPs**: serialize via mutex on the Loader.
- **Passphrase rotated and stamp verification now fails**: `Open` returns the rotation error described above. Reload logs ERROR; supervisor keeps the previously-loaded env values until restarted (children spawned post-HUP get the stale env, which is the same as the Unix env-immutability wrinkle below).

### Unix env-immutability wrinkle (documented behavior)

SIGHUP updates the supervisor's own env. Children spawned **before** the HUP keep their pre-spawn env until they cycle. This is a Unix process-env property, not a design flaw. Mention explicitly in user-facing docs for `gc supervisor secret reload`.

## CLI surface

New file: `cmd/gc/cmd_supervisor_secret.go`.

| Command | Behavior |
|---|---|
| `gc supervisor secret set <NAME>` | Prompts for value (no echo). Writes `<dir>/<NAME>.age`. **If the key already exists**, prompts to confirm overwrite unless `--force` is supplied. |
| `gc supervisor secret set <NAME> --from-stdin` | Reads value from stdin (single line, no trailing newline). Same overwrite-confirmation rule applies. |
| `gc supervisor secret set <NAME> --force` | Skips overwrite confirmation. |
| `gc supervisor secret get <NAME>` | Prints value to stdout (no trailing newline). Exit 1 if not found. `--quiet` suppresses stderr "not found" message. |
| `gc supervisor secret list` | Tabular output (or `--json`). Shows drift across config / store / live supervisor. |
| `gc supervisor secret delete <NAME>` | Removes from store. `--force` skips confirmation. Idempotent (exit 0 if NAME didn't exist). |
| `gc supervisor secret import-env` | Reads keys named in `GC_SUPERVISOR_ENV` from current shell env, writes each to the age store, prints suggested `[secrets.age] keys` block. |
| `gc supervisor secret reload` | Discovers supervisor PID, sends SIGHUP. Works regardless of how supervisor was launched. |

### `list` drift detection

Reconciles three sources:

1. Configured `keys` list in `supervisor.toml`.
2. Items currently in the configured backend (via `Backend.Keys()`).
3. Env vars currently set in the *running supervisor* (queried via the new HTTP endpoint below).

```
NAME              CONFIGURED  IN-STORE  LIVE-IN-SUPERVISOR  STATUS
EXA_API_KEY       yes         yes       yes                 OK
FIRECRAWL_KEY     yes         no        no                  MISSING
LINEAR_TOKEN      yes         yes       no                  STALE (run: gc supervisor secret reload)
ORPHAN_KEY        no          yes       no                  ORPHAN (in store, not in configured keys)
```

Status semantics:

- **OK** — configured + in backend + live in supervisor.
- **MISSING** — configured but absent from backend (the WARN-loud-continue case).
- **STALE** — configured + in backend + not in supervisor → user added secret but didn't reload.
- **MISMATCH** — configured + in backend + in supervisor but values differ (length-and-hash compare; we never display values).
- **ORPHAN** — present as `<key>.age` under `Age.Dir` but not in the configured `keys` list. Harmless; usually means user added a key directly without updating config, or removed a key from config without deleting its file.

If supervisor is down, `list` falls back to "config + backend only" and marks live status as `(supervisor down)`.

### Live-supervisor query: `/v1/supervisor/secrets/status`

New Huma-registered endpoint. Returns per-secret `{name, length, sha256}`. **Never the value.** Inherits whatever auth `/v1/supervisor/*` already has (per `engdocs/architecture/api-control-plane.md`).

Per gascity's typed-wire invariant: response struct registered via `huma.Register` with typed Output; OpenAPI regeneration captures the new endpoint (`make dashboard-check`).

### Backend lookup in CLI

Each subcommand independently reads `supervisor.toml` and calls
`secrets.Open(cfg.Secrets)` with the same config the supervisor uses. The CLI
consumes the `Backend` interface only; it never imports an implementation type
or platform-specific code path. **No coupling between CLI and running
supervisor for backend access** — `gc supervisor secret set EXA_API_KEY` works
whether the supervisor is up or down.

Sentinel errors used by the CLI: `secrets.ErrNotFound` (replaces the CGo
branch's `keyring.ErrKeyNotFound`). The "delete is idempotent" path checks
`errors.Is(err, secrets.ErrNotFound)`.

## Testing strategy

### Unit tests (next to code, no build tag)

`internal/supervisor/secrets/secrets_test.go` (driven by `ageBackend` in
`t.TempDir()` with `t.Setenv("GC_SECRETS_PASSPHRASE", "test-pass")`):

| Test | Asserts |
|---|---|
| `TestLoadAll_EmptyStore` | `Result.Set` empty, all configured keys in `Missing`, no error |
| `TestLoadAll_ExactMatch` | env var set, `Set = ["EXA_API_KEY"]`, `Missing` empty |
| `TestLoadAll_MultipleKeys` | every configured key set independently |
| `TestLoadAll_EmptyValueSkipped` | env var NOT set, item in `Skipped` |
| `TestLoadAll_BackendOpenFails` | returns error, supervisor caller continues |
| `TestLoadAll_ReservedKeyRejected` | validation error before any backend call |
| `TestReload_AddedUpdatedRemoved` | `ReloadResult` populated correctly; `os.Unsetenv` called for removed |
| `TestReload_Idempotent` | second call's `Added/Updated/Removed` all empty |

`internal/supervisor/secrets/age_test.go`:

| Test | Asserts |
|---|---|
| `TestAge_RoundTrip` | Set + Get returns same bytes; file mode 0600; stamp file created on first Set |
| `TestAge_GetMissing` | returns `ErrNotFound` |
| `TestAge_RemoveIdempotent` | Remove on missing key returns nil |
| `TestAge_KeysFiltersTmpAndStamp` | `*.age` filter excludes `.age.tmp` files and `.gc-secrets-stamp.age` |
| `TestAge_TmpFileIgnoredOnGet` | a stale `.age.tmp` file does not satisfy `Get` for that key |
| `TestAge_OpenWithWrongPassphraseFailsAtStamp` | stamp verification fails fast with the documented "passphrase does not match" message; no per-secret decryption attempted |
| `TestAge_ConcurrentSetDifferentKeys` | parallel `Set` of different keys both succeed; both files present |
| `TestAge_AtomicRenameOnCrash` | simulated crash mid-write (delete process before rename) leaves no half-encrypted `.age` file; `.tmp` is ignored |

`internal/supervisor/secrets/passphrase_test.go`:

| Test | Asserts |
|---|---|
| `TestPassphrase_EnvWins` | env set + keyfile present → env value used |
| `TestPassphrase_KeyfileWhenEnvUnset` | env unset, 0600 keyfile present → keyfile content used (one trailing `\n` stripped if present) |
| `TestPassphrase_KeyfileWorldReadableRejected` | mode 0644 keyfile → hard error at Open, not auto-fixed |
| `TestPassphrase_KeyfileGroupReadableRejected` | mode 0640 keyfile → hard error |
| `TestPassphrase_KeychainBootstrap` (cmdRunner fake; `runtime.GOOS` test hook set to `"darwin"`) | env unset, no keyfile, runner returns passphrase → that value used |
| `TestPassphrase_KeychainBootstrapExit44` | runner returns exit 44 → fall through to TTY/error |
| `TestPassphrase_NonTTYNoSourcesFails` | env unset, no keyfile, no Keychain, no TTY → clear documented error message |

`internal/supervisor/config_test.go` extended:

| Test | Asserts |
|---|---|
| `TestSecretsConfig_Validate_UnsupportedBackend` | `backend = "keychain"` → error pointing to CGo branch |
| `TestSecretsConfig_Validate_AgeAccepted` | `backend = ""` and `backend = "age"` both pass |
| `TestSecretsConfig_Validate_KeyShape` | non-uppercase / hyphen-bearing key rejected |
| `TestSecretsConfig_Validate_ReservedKey` | `PATH`, `HOME`, etc. rejected |

CLI tests (`cmd/gc/cmd_supervisor_secret_test.go`) cover each subcommand using
the real `ageBackend` in `t.TempDir()` (passphrase from `t.Setenv`). Includes:

| Test | Asserts |
|---|---|
| `TestSet_NewKey` | secret stored, file mode 0600 |
| `TestSet_OverwritePromptsWithoutForce` | second `set` of an existing key prompts for confirmation; "n" aborts without changing the file |
| `TestSet_OverwriteWithForceSkipsPrompt` | `--force` overwrites silently |
| `TestSet_FromStdinNoPrompt` | `--from-stdin` does not prompt even on overwrite (caller is non-interactive) |

API tests (`internal/api/`) cover `/v1/supervisor/secrets/status` with a
grep-assert that the response body — across multiple seeded secret values —
never contains any loaded secret value as a substring (verifies the
`{name, length, sha256}` payload contract).

### Integration tests (`test/integration/secrets_integration_test.go`, `//go:build integration`)

- `TestSupervisor_LoadsSecretsAtStartup` — real supervisor binary + age backend; assert child has env var.
- `TestSupervisor_SIGHUPReload` — start, mutate age store, SIGHUP, spawn fresh child, assert new value. Old child has stale value (documents the Unix behavior).
- `TestSupervisor_KeychainPassphraseBootstrap` (`//go:build integration && darwin`) — seeds a `gc-supervisor-passphrase` Keychain item via `security add-generic-password` (reading password from stdin, no `-w`), starts the supervisor without `GC_SECRETS_PASSPHRASE`, asserts secrets loaded. Cleans up the Keychain item in `t.Cleanup`. Skipped on CI Linux runners.

### Deliberately not tested in CI

- **Real macOS Keychain bootstrap on Linux CI** — Linux runners lack `security`. The bootstrap logic is fully covered by the cmdRunner-fake unit tests; the integration test runs on Sean's macOS workstation as a manual smoke step.
- **age library internals** — covered by `filippo.io/age`'s own tests.
- **Signal-handler delivery wiring** — covered implicitly by `TestSupervisor_SIGHUPReload`.

## Migration

### One-time passphrase setup (macOS daily-driver)

Most ergonomic path: seed the passphrase into macOS Keychain so gc never
prompts on a cleanly-rebooted machine.

```bash
# Reads the passphrase from your terminal, NOT argv. Run interactively.
security add-generic-password -U \
  -s gc-supervisor-passphrase \
  -a "$USER@personal" \
  -T ""    # empty trusted-app list — every gc rebuild prompts once, then silent until next rebuild
# (no -w on argv → security reads password from the prompt, no process-table leak)
```

Alternative for headless / Linux daily-driver: keyfile.

```bash
umask 077
echo -n "your-passphrase" > "$HOME/.gc/.secrets-passphrase"
chmod 0600 "$HOME/.gc/.secrets-passphrase"
ls -l "$HOME/.gc/.secrets-passphrase"   # confirm -rw-------
```

Or for CI: `export GC_SECRETS_PASSPHRASE=...` in the supervisor's environment.

### Per-secret migration

For Sean's existing setup (the only known user):

```bash
# 1. Build & install patched gc binary from the fork
cd /Volumes/Code/github.com/seanb4t/gascity && go build -o /opt/homebrew/bin/gc ./cmd/gc

# 2. Set EXA_API_KEY (writes ~/.gc/secrets/EXA_API_KEY.age, plus the stamp file on first set)
gc supervisor secret set EXA_API_KEY   # prompts for value

# 3. Add key to ~/.gc/supervisor.toml
cat >> ~/.gc/supervisor.toml <<'EOF'

[secrets.age]
keys = ["EXA_API_KEY"]
EOF

# 4. Reinstall plist (now without the wrapper)
gc supervisor install

# 5. Verify
gc supervisor secret list   # expect EXA_API_KEY: OK

# 6. Cleanup old artifacts
security delete-generic-password -a "$USER" -s EXA_API_KEY    # if you'd previously stashed it in Keychain
rm /Users/sean/.gc/bin/supervisor-wrapper.sh
gc bd remember --key supervisor-keychain-wrapper "(superseded — see supervisor-secrets-v0.md)"
```

For new users post-merge: just steps 2-3-4. No wrapper, no plist patch.

### Switching from the CGo branch to this branch

Different products, not migration-compatible: the CGo branch stores secrets as
individual macOS Keychain items; this branch stores them as
age-encrypted files under `~/.gc/secrets/`. A user moving between branches
must re-run `gc supervisor secret set` for each key. The TOML schema also
differs (`[secrets.age]` only on this branch; no `[secrets.keychain]` section).
This is by design — the parallel branches are alternatives, not equivalents.

## Rollout / PR strategy

1. **Fork**: github.com/seanb4t/gascity
2. **Branch**: `feat/supervisor-secrets-age` off `feat/supervisor-secrets-keychain` HEAD (this branch reuses every commit of the CGo branch except the backend implementation and the goreleaser-cross switch).
3. **Atomic commits** (per AGENTS.md conventional commits) for the diff against the CGo branch:
   - `docs(supervisor): pivot supervisor-secrets-v0 to age-only design` (already committed at 769b156f → updated by a follow-up adversarial-fix commit)
   - `revert(release): drop goreleaser-cross switch and CGO_ENABLED=1`
   - `feat(supervisor/secrets): add Backend interface and ErrNotFound sentinel`
   - `feat(supervisor/secrets): add age backend with stamp-file passphrase verification`
   - `feat(supervisor/secrets): add passphrase resolution chain (env → keyfile → macOS Keychain → TTY)`
   - `refactor(supervisor/secrets): replace 99designs/keyring with internal Backend at call sites`
   - `refactor(supervisor): SecretsConfig schema — drop KeychainBackendConfig, rename file → age, prefixes → keys`
   - `feat(cli): overwrite confirmation in 'gc supervisor secret set'`
   - `chore(deps): drop github.com/99designs/keyring dependency`
4. **PR description**: link to this design doc; reference the parallel CGo branch and explain the choice presented to upstream. Note: this branch passes the Primitive Test (`engdocs/contributors/primitive-test.md`) for the same reason the CGo branch did, and additionally maintains the project's pre-existing `CGO_ENABLED=0` distribution invariant.
5. **Pre-flight before opening PR**:
   - `make test` (fast unit baseline)
   - `make test-integration-shards-parallel`
   - `go vet ./...`
   - `make dashboard-check` (since `internal/api/` is touched)
   - `CGO_ENABLED=0 go build ./...` succeeds (the distribution invariant)
   - Manual smoke: end-to-end migration on Sean's macOS machine

## Design principles applied

- **ZFC** — gc contains no judgment about *what* secrets mean. It loads what config declares, sets `os.Setenv`, and gets out of the way. The decision logic ("is this the right value?") lives in the user's age store.
- **Bitter Lesson** — config-driven secret loading becomes *more* useful as secret-manager ergonomics improve (1Password integration, Linux Secret Service driver, etc., as future contributions). A hardcoded `EXA_*` allowlist would not.
- **Primitive Test** — single primitive (load named secrets from a configured backend), composable (any future backend that satisfies the `Backend` interface), atomic (no decomposition possible).
- **No premature abstraction** — `internal/supervisor/secrets/`, not `internal/secrets/`. Promote when a second consumer appears. The `Backend` interface is justified by the test-fake counting as a real second implementation plus the obvious slot for a future `secret-service` / `1password` backend without breaking call sites.
- **Don't Swallow Errors** — every failure mode produces a WARN or ERROR log entry; nothing silently disappears. Wrong-passphrase fails fast at `Open()` via stamp verification, not silently per-secret. Wrong keyfile permissions hard-fail at `Open()`, not auto-fix.
- **Observability & Testability** — `t.TempDir()` + `t.Setenv` makes the age backend unit-testable with no fakes; the optional macOS Keychain bootstrap is unit-testable on Linux via cmdRunner injection; drift detection in `list` makes config-vs-runtime divergence visible.
- **Pure Go** — no CGo, no platform-specific link dependencies, distribution stays `CGO_ENABLED=0`. One narrow read-only `security` subprocess (passphrase bootstrap) instead of in-process Security framework binding; pure-Go age instead of libdbus.
