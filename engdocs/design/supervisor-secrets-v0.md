# Supervisor secrets v0 — Subprocess + age secret loading

**Status:** Design (2026-05-02, pivoted 2026-05-03 to subprocess+age)
**Author:** Sean Brandt
**Implementation target:** github.com/seanb4t/gascity → PR upstream
**Related:** `engdocs/design/machine-wide-supervisor-v0.md`, `engdocs/contributors/primitive-test.md`

> **Branch note.** This spec describes the **`feat/supervisor-secrets-age`**
> branch — pure-Go, no CGo, uses `/usr/bin/security` subprocess on macOS and
> `filippo.io/age` everywhere else. A parallel branch
> `feat/supervisor-secrets-keychain` exists with the same feature surface but
> using `github.com/99designs/keyring` (CGo). Both are offered upstream; this
> branch trades the in-process Keychain bindings for `CGO_ENABLED=0` simplicity
> at distribution time.

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

- 1Password / Vault / sops integration — `pass` backend covers GPG flows; richer integrations are a future contribution.
- Per-city secret allowlists — `city.toml`'s `allow_env_override` already filters which env vars reach which agents; do not duplicate.
- Hot rotation of secrets *into running children* — SIGHUP updates supervisor env + future spawns; existing children keep their pre-spawn env (Unix process env is immutable post-spawn).
- Encrypted-at-rest `supervisor.toml` — config remains plaintext; secrets themselves never appear in it.
- Auto-discovery of unconfigured store items — the supervisor never loads anything not declared in `keys`. `gc supervisor secret list` surfaces orphans as a hint only.
- Deprecation of `GC_SUPERVISOR_ENV` — coexists in v1; future call.

## Distribution constraints

This branch keeps the existing pure-Go (`CGO_ENABLED=0`) release pipeline
unchanged. No goreleaser-cross switch, no Docker-based release builds, no new
toolchain pins.

- **macOS**: secret store access via `/usr/bin/security(1)` subprocess. Ships
  with every macOS install; no third-party dependency. No CGo linkage to the
  Security framework.
- **Linux**: `filippo.io/age` (pure-Go, MIT) for encrypted-file storage. No
  Secret Service / D-Bus dependency. `secret-tool` integration is intentionally
  deferred to a future PR — we don't ship what we can't test.
- **Windows**: not a release target. `.goreleaser.yml` builds `linux + darwin`
  only; the existing `_windows.go` files are compile-time stubs for developer
  builds and remain so. WinCred integration is out of scope.

**Why this trade-off.** The CGo branch (`feat/supervisor-secrets-keychain`) put
the in-process Keychain abstraction first and accepted CGo cross-compilation as
the cost. This branch puts distribution simplicity first: every gc release is
still a single-step `goreleaser` run on a vanilla Linux runner producing four
static binaries. The cost paid here is a per-secret subprocess (~5–15 ms on
macOS) and giving up Linux Secret Service integration in v1.

**Cross-platform code shape.** No `//go:build` constraints on backend code.
Both backends (`keychain.go`, `age.go`) compile into every binary;
`runtime.GOOS` selects which is wired up at `Open()` time. This matches the
existing `internal/supervisor/secrets/keyring.go` pattern in the CGo branch and
keeps unit tests platform-agnostic — the keychain backend is testable on Linux
runners via an injected `cmdRunner` fake.

## Design decisions (settled)

| # | Decision | Rationale |
|---|---|---|
| 1 | Single `keys` list; every entry is an exact key name (no prefix matching) | Multi-key prefix matching from the CGo branch is dropped — OS-native CLIs lack good enumeration APIs and the degenerate exact-match case was the common one anyway. |
| 2 | Missing/empty matches: WARN-loud-and-continue | Supervisor is shared infrastructure; one missing third-party key must not bring it down. AGENTS.md "Don't Swallow Errors" satisfied by the WARN log entry. |
| 3 | Backend: macOS `/usr/bin/security` subprocess + `filippo.io/age` for everything else | No third-party keyring abstraction, no CGo. macOS uses the same Keychain user already manages with the GUI; non-darwin uses pure-Go age encryption. `secret-tool` (Linux Secret Service) intentionally deferred — we don't ship what we can't test against in CI. |
| 4 | Account: configurable, default `$USER@personal` | Matches your existing Keychain layout, leaves room for multi-account (sean@personal vs sean@work) without breaking change. Used only by the keychain backend. |
| 5 | New CLI subcommand: `gc supervisor secret {set,get,list,delete,reload,import-env}` with drift detection in `list` | Cross-platform UX win — users don't need to learn `security` vs age file conventions. Drift detection surfaces config-vs-store-vs-supervisor disagreement at a glance. |
| 6 | Backend enum: `auto`, `keychain`, `age`. `auto` portable, explicit values strict | `auto` resolves to `keychain` on darwin, `age` elsewhere. `backend = "keychain"` on non-darwin **fails loudly** at config-load — no silent fall-through. Users with one shared `supervisor.toml` use `auto`; users on a single-platform host pick the explicit value. |
| 7 | Loading model: startup load + SIGHUP reload (Approach 3) | ~50 lines beyond startup-only; meaningful UX win for rotation. Lazy spawn-time injection (better security) deferred to v2. |
| 8 | "Full sync" reload semantics | Keys removed from the store between reloads are `os.Unsetenv`'d. Tracked via `lastSet` map on the `Loader`. |
| 9 | Backend swap on reload requires restart | WARN + ignore. Backend swaps are uncommon; restart is fine. |
| 10 | age on-disk format: one file per secret under `cfg.Age.Dir` | `~/.gc/secrets/<KEY>.age` per secret. Per-file atomic rename, no global lock; corrupting one file doesn't lose the others. Whole-store designs require read-modify-write under lock and have a worse blast radius. |
| 11 | Passphrase resolution chain: env → keyfile → macOS Keychain → TTY prompt | Each step is more explicit than the next. CI uses env (`GC_SECRETS_PASSPHRASE`), daily-driver macOS usage uses Keychain (set once via `security`), Linux daily-driver uses keyfile or env, interactive prompt is the last resort. |

## Architecture

### Module layout

`internal/supervisor/secrets/` (sibling of `internal/supervisor/config.go`, `publications.go`, `registry.go`).

```
internal/supervisor/secrets/
├── backend.go        # Backend interface + Open() constructor + ErrNotFound sentinel
├── secrets.go        # public API: Loader, LoadAll, Reload (consumes Backend)
├── secrets_test.go   # unit tests using ageBackend in t.TempDir()
├── age.go            # ageBackend: per-file age encryption under cfg.Age.Dir
├── age_test.go       # round-trip + corruption + missing-passphrase tests
├── keychain.go       # keychainBackend: /usr/bin/security subprocess wrapper
├── keychain_test.go  # cmdRunner-fake-driven tests (run on every platform)
└── passphrase.go     # passphrase resolution chain: env → keyfile → Keychain → TTY
```

**Why a single `Backend` interface with two implementations rather than callers
knowing which backend they have:** the CLI (`cmd/gc/cmd_supervisor_secret.go`)
doesn't care whether a secret is stored in Keychain or in an age file — it
calls `Get`/`Set`/`Remove`/`Keys`. Same for the `Loader`. Hiding the choice
behind one interface makes the CLI cross-platform-portable for free, and lets
tests swap in a fake `Backend` when they want to exercise the CLI without
touching either real implementation.

This is not premature abstraction — it's the boundary between
backend-implementation types and domain types, a pattern gascity already
follows (e.g., `internal/api/genclient` insulates HTTP types from the domain
model).

### Wired into

- `cmd/gc/cmd_supervisor_lifecycle.go` — `runSupervisor` calls `secrets.LoadAll(cfg)` after config load, before API server bind. SIGHUP handler installed.
- `cmd/gc/cmd_supervisor_secret.go` — registers the `gc supervisor secret` subcommand tree. Consumes `secrets.Backend` interface only; no direct keyring-library types.
- `internal/supervisor/config.go` — extends `Config` with `Secrets SecretsConfig` field + validation, including the cross-platform validation rule (`backend = "keychain"` rejected on non-darwin).
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
    Backend  string                `toml:"backend,omitempty"`  // "auto" | "keychain" | "age"
    Keychain KeychainBackendConfig `toml:"keychain,omitempty"`
    Age      AgeBackendConfig      `toml:"age,omitempty"`
}

type KeychainBackendConfig struct {
    ServiceName string   `toml:"service_name,omitempty"` // default "gc-supervisor"
    Account     string   `toml:"account,omitempty"`      // default fmt.Sprintf("%s@personal", currentUser())
    Keys        []string `toml:"keys"`                   // exact-match key names
}

type AgeBackendConfig struct {
    Dir  string   `toml:"dir,omitempty"`  // default "$GC_HOME/secrets" (typically ~/.gc/secrets)
    Keys []string `toml:"keys"`            // exact-match key names
}
```

### On-disk shape (`~/.gc/supervisor.toml`)

```toml
[supervisor]
port = 9876

[secrets]
backend = "auto"   # or omit entirely; "auto" → keychain on macOS, age elsewhere

[secrets.keychain]
keys = ["EXA_API_KEY", "FIRECRAWL_KEY", "LINEAR_TOKEN"]
# Each entry is an exact key name matched against Keychain items under
# service_name="gc-supervisor". Missing keys log a WARN and continue.
# Defaults: service_name="gc-supervisor", account="$USER@personal"

# Or, for age-backed deploys:
# [secrets.age]
# dir  = "/var/lib/gc/secrets"   # optional; defaults to $GC_HOME/secrets
# keys = ["EXA_API_KEY", "FIRECRAWL_KEY"]
```

### Validation

Implemented as `func (c SecretsConfig) Validate(reservedKey func(string) bool) error` in `internal/supervisor/config.go`. The `reservedKey` predicate is injected by the caller (cmd/gc passes its `isReservedSupervisorEnvKey`) to avoid an `internal/supervisor` → `cmd/gc` import cycle. Same-package tests pass `nil`, which falls back to a minimal default recognizing only `PATH` and `GC_HOME`. Fail-fast at config-load time, not at backend query time.

| Rule | Error |
|---|---|
| `Backend` not in allowed values (or empty → "auto") | `secrets.backend: unknown value %q (allowed: auto, keychain, age)` |
| `Backend = "keychain"` on non-darwin | `secrets.backend: "keychain" is only available on macOS; use "age" or "auto" on this platform` |
| Key doesn't match env-var-name shape | `secrets.<backend>.keys[%d]: %q is not a valid env-var name`. **Reuse `supervisorServiceEnvNameRE` from `cmd_supervisor_lifecycle.go:381`** — promote it to a package-level export rather than duplicating the regex literal. |
| Key shadows reserved env var | `secrets.<backend>.keys[%d]: %q would shadow reserved env var`. Check against the union of `supervisorServiceFixedEnvKeys` (GC_HOME, PATH, XDG_RUNTIME_DIR — supervisor sets these itself) and `supervisorServiceEnvKeys` (HOME, USER, SHELL, LANG, etc. — auto-persist whitelist). Implementation: extract a single `isReservedSupervisorEnvKey(name) bool` helper in `cmd/gc/cmd_supervisor_lifecycle.go` that consults both maps; call it from both the install path's existing checks and the new `SecretsConfig.Validate`. |

### Cross-platform behavior

The `auto` value is the only portable choice; explicit values are
platform-asserting.

| `cfg.Backend` | macOS | Linux | Other |
|---|---|---|---|
| `auto` (or empty) | keychain | age | age |
| `keychain` | keychain | **rejected at validate** | **rejected at validate** |
| `age` | age | age | age |

Users with one `supervisor.toml` synced across machines should use `auto`.
Users on a single-platform host who want explicit semantics pick `keychain` or
`age`. CI / headless deploys use `age` explicitly.

The rejection on non-darwin is fail-fast at config-load time — it does not
silently fall through to `age`. Silent fallthrough would be a "Don't Swallow
Errors" violation (the user thinks their secrets are in Keychain; they are
actually in `~/.gc/secrets/*.age`).

### Passphrase resolution (age backend only)

The age backend encrypts every file with a single passphrase, resolved at
`Open()` time and cached on the backend instance for its lifetime. The
resolution chain — most explicit user intent wins:

1. **`GC_SECRETS_PASSPHRASE` env var.** Non-empty value used directly. Intended
   for CI, headless systemd-managed gc, and container deployments.
2. **Keyfile at `<cfg.Age.Dir>/.passphrase`.** Plain UTF-8, mode `0600` (mode
   verified — refused if world- or group-readable to prevent accidental
   leakage). Use case: "save once, never type again" on Linux daily-drivers.
3. **macOS Keychain bootstrap (darwin only).** Looks up
   `security find-generic-password -s gc-supervisor-passphrase -a $account -w`.
   Use case: macOS users who want their age-encrypted secrets unlocked by
   Keychain without per-secret subprocess calls (one Keychain hit at startup,
   then plain age decryption per secret). Set once via
   `security add-generic-password -U -s gc-supervisor-passphrase -a $account -w`.
4. **Interactive TTY prompt.** `golang.org/x/term.ReadPassword` from the
   controlling TTY. Last resort — fails with a clear error in non-TTY contexts
   (`"no passphrase: set GC_SECRETS_PASSPHRASE, place a 0600 keyfile at <path>, or run interactively"`)
   rather than hanging.

The `keychain` backend (`backend = "keychain"`) does not use this chain — it
relies on Keychain's own ACL and `security`'s native auth flow per-secret.

### Coexistence with `GC_SUPERVISOR_ENV`

- `GC_SUPERVISOR_ENV` mechanism unchanged in v1.
- If a key is set by both: Keychain wins. Document precedence.
- `gc supervisor install` help text gains a one-line note pointing users to `[secrets.keychain]` for new secret needs. Hard deprecation deferred.

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

Keychain load happens **after** config load and validation, **before** the API server binds — surfaces backend misconfiguration before any city tries to connect.

### Per-command opt-in for non-supervisor entry points

The supervisor process loads secrets in `runSupervisor`. Other gc entry points that perform MCP template expansion in their own process (not via the supervisor) must call `loadStartupSecrets` themselves — `MCPTemplateData` consults `os.Environ()` for keys listed in `cfg.AgentDefaults.AllowEnvOverride`, and that env needs to contain the keychain values.

**Current opt-in sites:**
- `gc start` (`cmd/gc/cmd_start.go`, `doStartStandalone`) — projects MCP for stage-1 validation.
- `gc mcp list` (`cmd/gc/cmd_mcp.go`) — inspection command that runs the same projection.
- `gc doctor` (`cmd/gc/cmd_doctor.go`) — `mcp-config` health check runs projection.

**Why per-command, not `cobra.PersistentPreRunE`:** loading secrets on every gc invocation triggers a macOS Keychain access for every `gc version`, `gc bd ready`, etc. Each rebuild of the gc binary changes its code signature, invalidating the trusted-app ACL and producing a fresh prompt — a daily-driver-ergonomics catastrophe during dev cycles. Per-command opt-in localizes the cost to commands that actually need projection. The maintenance burden is "remember to add the call when you write a new projection-touching command" — small enough that the alternative isn't worth it.

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

1. `secrets.Open(cfg)` — selects backend by `cfg.Backend` + `runtime.GOOS`,
   returns `Backend`. If this fails, return `(Result{}, err)`. Caller logs
   ERROR and continues; supervisor stays up with no secrets loaded.
2. For the age backend, `Open` resolves the passphrase via the chain in
   "Passphrase resolution" above. Failure here surfaces as the open error.
3. For each configured key (exact match — no prefix expansion):
   - `backend.Get(key)`.
     - `ErrNotFound` → append to `Result.Missing`, continue.
     - Other error → append to `Result.Errors`, continue.
     - Success with empty bytes → append to `Result.Skipped`, do not
       `os.Setenv`.
     - Success with non-empty bytes → `os.Setenv(key, string(data))`, append to
       `Result.Set`.
4. Update `l.lastSet` (used by `Reload` for full-sync semantics).

`backend.Keys()` is **not** called by `LoadAll` — keys come from the config's
exact-match `keys` list. `Keys()` is exclusively used by the CLI's `list`
command for drift detection (orphan reporting).

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

### Subprocess-specific failure handling (keychain backend)

The keychain backend wraps `/usr/bin/security`. Each subcommand has its own
exit-code idioms; the wrapper translates them to the `Backend` interface
contract:

| Op | Command | Exit code → behavior |
|---|---|---|
| Get | `security find-generic-password -a $account -s $key -w` | 0 = stdout is value; 44 = `ErrNotFound`; other non-zero = wrap stderr in error |
| Set | `security add-generic-password -U -a $account -s $key -w $value -T '' -A` | 0 = success; non-zero = wrap stderr (`-U` ensures upsert, no "already exists" on re-set) |
| Remove | `security delete-generic-password -a $account -s $key` | 0 = success; 44 = idempotent success (already gone); other non-zero = wrap stderr |
| Keys | `security dump-keychain` filtered by service-name match | 0 with parsed lines; non-zero = wrap stderr |

The wrapper also pre-checks `exec.LookPath("security")` once at construction;
absence is fatal at `Open()` (only meaningful on darwin since the
cross-platform validation rule rejects keychain elsewhere).

The `cmdRunner` interface (`Run(name string, args ...string) (stdout []byte, exitCode int, err error)`)
is a package var that production sets to a real `os/exec`-backed implementation
and tests swap for a fake. This keeps every backend method unit-testable on
Linux runners without `security` installed.

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

1. Re-open the backend (config may have changed; `Open` is cheap for both
   implementations).
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

Re-reads `supervisor.toml` AND re-runs Keychain load. Edge cases:

- **Backend swap between reloads** (e.g., `backend = "file"` → `backend = "keychain"`): WARN + ignore the backend change; reload using old backend. Backend swap requires restart. ~30 lines saved by punting on this.
- **Validation fails on reload**: WARN + ignore. Old config remains active.
- **Concurrent SIGHUPs**: serialize via mutex on the Loader.

### Unix env-immutability wrinkle (documented behavior)

SIGHUP updates the supervisor's own env. Children spawned **before** the HUP keep their pre-spawn env until they cycle. This is a Unix process-env property, not a design flaw. Mention explicitly in user-facing docs for `gc supervisor secret reload`.

## CLI surface

New file: `cmd/gc/cmd_supervisor_secret.go`.

| Command | Behavior |
|---|---|
| `gc supervisor secret set <NAME>` | Prompts for value (no echo). Writes to configured backend. |
| `gc supervisor secret set <NAME> --from-stdin` | Reads value from stdin (single line, no trailing newline). |
| `gc supervisor secret get <NAME>` | Prints value to stdout (no trailing newline). Exit 1 if not found. `--quiet` suppresses stderr "not found" message. |
| `gc supervisor secret list` | Tabular output (or `--json`). Shows drift across config / Keychain / live supervisor. |
| `gc supervisor secret delete <NAME>` | Removes from backend. `--force` skips confirmation. Idempotent (exit 0 if NAME didn't exist). |
| `gc supervisor secret import-env` | Reads keys named in `GC_SUPERVISOR_ENV` from current shell env, writes each to backend, prints suggested `[secrets.<backend>] keys` block (`[secrets.keychain]` on darwin, `[secrets.age]` elsewhere). |
| `gc supervisor secret reload` | Discovers supervisor PID, sends SIGHUP. Works regardless of how supervisor was launched. |

### `list` drift detection

Reconciles three sources:

1. Configured `keys` list in `supervisor.toml`.
2. Items currently in the configured backend (via `Backend.Keys()`).
3. Env vars currently set in the *running supervisor* (queried via the new HTTP endpoint below).

```
NAME              CONFIGURED  IN-KEYCHAIN  LIVE-IN-SUPERVISOR  STATUS
EXA_API_KEY       yes         yes          yes                 OK
FIRECRAWL_KEY     yes         no           no                  MISSING
LINEAR_TOKEN      yes         yes          no                  STALE (run: gc supervisor secret reload)
ORPHAN_KEY        no          yes          no                  ORPHAN (in store, not in configured keys)
```

Status semantics:

- **OK** — configured + in backend + live in supervisor.
- **MISSING** — configured but absent from backend (the WARN-loud-continue case).
- **STALE** — configured + in backend + not in supervisor → user added secret but didn't reload.
- **MISMATCH** — configured + in backend + in supervisor but values differ (length-and-hash compare; we never display values).
- **ORPHAN** — in backend under our `service_name` / `Age.Dir` umbrella but not in the configured `keys` list. Harmless; usually means user added a key directly without updating config.

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
`errors.Is(err, secrets.ErrNotFound) || os.IsNotExist(err)` to cover both
backends.

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
| `TestReload_BackendSwapIgnored` | reload logs WARN, env unchanged |
| `TestReload_Idempotent` | second call's `Added/Updated/Removed` all empty |

`internal/supervisor/secrets/age_test.go`:

| Test | Asserts |
|---|---|
| `TestAge_RoundTrip` | Set + Get returns same bytes; file mode 0600 |
| `TestAge_GetMissing` | returns `ErrNotFound` |
| `TestAge_RemoveIdempotent` | Remove on missing key returns nil |
| `TestAge_KeysListsOnlyAgeFiles` | `*.age` filter; non-age files in dir ignored |
| `TestAge_WrongPassphraseFailsClearly` | decryption error wrapped with key name |
| `TestAge_KeyfileWorldReadableRefused` | mode 0644 keyfile rejected at Open |
| `TestAge_NoPassphraseNonTTY` | clear error message, no hang |

`internal/supervisor/secrets/keychain_test.go` (driven by `cmdRunner` fake;
runs on every platform):

| Test | Asserts |
|---|---|
| `TestKeychain_GetSuccess` | runner returns stdout + exit 0 → `Get` returns those bytes |
| `TestKeychain_GetExit44` | runner returns exit 44 → `ErrNotFound` |
| `TestKeychain_GetOtherFailure` | runner returns exit 1 + stderr → wrapped error including stderr |
| `TestKeychain_SetUsesUpsertFlag` | recorded args include `-U` |
| `TestKeychain_RemoveExit44Idempotent` | exit 44 from delete returns nil |
| `TestKeychain_OpenOnNonDarwinReturnsClearError` | with `osDetect = "linux"`, `Open` errors out cleanly |

`internal/supervisor/secrets/passphrase_test.go`:

| Test | Asserts |
|---|---|
| `TestPassphrase_EnvWins` | env set + keyfile present → env value used |
| `TestPassphrase_KeyfileWhenEnvUnset` | env unset, 0600 keyfile present → keyfile content used |
| `TestPassphrase_KeychainBootstrap` (darwin only, `cmdRunner` fake) | env unset, no keyfile, runner returns passphrase → that value used |
| `TestPassphrase_NonTTYNoSourcesFails` | env unset, no keyfile, no Keychain, no TTY → clear error |

`internal/supervisor/config_test.go` extended:

| Test | Asserts |
|---|---|
| `TestSecretsConfig_Validate_UnknownBackend` | clear error |
| `TestSecretsConfig_Validate_KeychainOnLinuxRejected` | uses injected `osDetect`, asserts platform error message |
| `TestSecretsConfig_Validate_KeyShape` | non-uppercase / hyphen-bearing key rejected |
| `TestSecretsConfig_Validate_ReservedKey` | `PATH`, `HOME`, etc. rejected |

CLI tests (`cmd/gc/cmd_supervisor_secret_test.go`) cover each subcommand using
`ageBackend` in `t.TempDir()` (passphrase from `t.Setenv`). The keychain code
path's CLI behaviors are covered through unit tests on the keychain backend
plus an integration smoke test in `test/integration/secrets_integration_test.go`
(`//go:build integration && darwin`).

API tests (`internal/api/`) cover `/v1/supervisor/secrets/status` with a
fuzzing-style assertion that response body never contains loaded secret values
(grep-assert).

### Integration tests (`test/integration/secrets_integration_test.go`, `//go:build integration`)

- `TestSupervisor_LoadsSecretsAtStartup` — real supervisor binary + age backend; assert child has env var.
- `TestSupervisor_SIGHUPReload` — start, mutate age store, SIGHUP, spawn fresh child, assert new value. Old child has stale value (documents the Unix behavior).
- `TestSupervisor_KeychainBackend` (`//go:build integration && darwin`) — exercises the real `/usr/bin/security` subprocess against a temporary service-name; cleans up keychain entries in `t.Cleanup`. Skipped in CI Linux runners.

### Deliberately not tested in CI

- **Real macOS Keychain integration in non-darwin CI** — runners lack `security`. The keychain backend's logic is fully covered by `cmdRunner`-fake unit tests; the integration test runs on Sean's macOS workstation as a manual smoke step.
- **age library internals** — covered by `filippo.io/age`'s own tests.
- **Signal-handler delivery wiring** — covered implicitly by `TestSupervisor_SIGHUPReload`.

## Migration

For Sean's existing setup (the only known user):

```bash
# 1. Build & install patched gc binary from the fork
cd /Volumes/Code/github.com/seanb4t/gascity && go build -o /opt/homebrew/bin/gc ./cmd/gc

# 2. Re-store EXA_API_KEY under the new layout (writes to macOS Keychain on darwin)
gc supervisor secret set EXA_API_KEY   # prompts for value

# 3. Add key to ~/.gc/supervisor.toml
cat >> ~/.gc/supervisor.toml <<'EOF'

[secrets.keychain]
keys = ["EXA_API_KEY"]
EOF

# 4. Reinstall plist (now without the wrapper)
gc supervisor install

# 5. Verify
gc supervisor secret list   # expect EXA_API_KEY: OK

# 6. Cleanup old artifacts
security delete-generic-password -a "$USER" -s EXA_API_KEY
rm /Users/sean/.gc/bin/supervisor-wrapper.sh
gc bd remember --key supervisor-keychain-wrapper "(superseded — see supervisor-secrets-v0.md)"
```

For new users post-merge: just steps 2-3-4. No wrapper, no plist patch.

**Switching from the CGo branch to this branch:** the on-disk layout under
`backend = "keychain"` is **byte-identical** between branches (both read and
write the same Keychain items via the same service-name and account). A user
who has been running the CGo branch and switches to this branch needs no
migration — `gc supervisor secret list` works immediately. The age backend's
on-disk format **does** differ from the CGo branch's `file` backend (age
vs. JOSE), so a user moving between branches with `backend = "age"` (this
branch) and `backend = "file"` (CGo branch) needs to re-run
`gc supervisor secret set` for each key. The TOML schema also differs (`keys`
vs `prefixes`, `[secrets.age]` vs `[secrets.file]`).

## Rollout / PR strategy

1. **Fork**: github.com/seanb4t/gascity
2. **Branch**: `feat/supervisor-secrets-age` off `feat/supervisor-secrets-keychain` HEAD (this branch reuses every commit of the CGo branch except the backend implementation and the goreleaser-cross switch).
3. **Atomic commits** (per AGENTS.md conventional commits) for the diff against the CGo branch:
   - `revert(release): drop goreleaser-cross switch and CGO_ENABLED=1`
   - `feat(supervisor/secrets): add Backend interface and ErrNotFound sentinel`
   - `feat(supervisor/secrets): add age backend with passphrase resolution chain`
   - `feat(supervisor/secrets): add macOS keychain subprocess backend`
   - `refactor(supervisor/secrets): replace 99designs/keyring with internal Backend at call sites`
   - `feat(supervisor): cross-platform validation rule (keychain darwin-only)`
   - `chore(deps): drop github.com/99designs/keyring dependency`
   - `docs(supervisor): pivot supervisor-secrets-v0 to subprocess+age design`
4. **PR description**: link to this design doc; reference the parallel CGo branch and explain the choice presented to upstream. Note: this branch passes the Primitive Test (`engdocs/contributors/primitive-test.md`) for the same reason the CGo branch did, and additionally maintains the project's pre-existing `CGO_ENABLED=0` distribution invariant.
5. **Pre-flight before opening PR**:
   - `make test` (fast unit baseline)
   - `make test-integration-shards-parallel`
   - `go vet ./...`
   - `make dashboard-check` (since `internal/api/` is touched)
   - `CGO_ENABLED=0 go build ./...` succeeds (the distribution invariant)
   - Manual smoke: end-to-end migration on Sean's macOS machine

## Design principles applied

- **ZFC** — gc contains no judgment about *what* secrets mean. It loads what config declares, sets `os.Setenv`, and gets out of the way. The decision logic ("is this the right value?") lives in the user's Keychain (or age store).
- **Bitter Lesson** — config-driven secret loading becomes *more* useful as secret-manager ergonomics improve (e.g., 1Password's `op` CLI, future Linux Secret Service driver). A hardcoded `EXA_*` allowlist would not.
- **Primitive Test** — single primitive (load named secrets from a configured backend), composable (any backend that satisfies the `Backend` interface), atomic (no decomposition possible).
- **No premature abstraction** — `internal/supervisor/secrets/`, not `internal/secrets/`. Promote when a second consumer (per-agent secrets?) appears. The two-implementations-behind-one-interface split is justified by real second use case (age) at design time, not anticipated future use.
- **Don't Swallow Errors** — every failure mode produces a WARN or ERROR log entry; nothing silently disappears. Cross-platform `backend = "keychain"` mismatch is a fail-fast at validate, not a silent fallthrough.
- **Observability & Testability** — `cmdRunner` injection makes the keychain backend unit-testable on every platform; `t.TempDir()` + `t.Setenv` makes the age backend unit-testable with no fakes at all; drift detection makes config-vs-runtime divergence visible.
- **Pure Go** — no CGo, no platform-specific link dependencies, distribution stays `CGO_ENABLED=0`. Subprocess to `/usr/bin/security` instead of in-process Security framework binding; pure-Go age instead of libdbus.
