# Supervisor secrets v0 — Keychain-backed secret loading

**Status:** Design (2026-05-02)
**Author:** Sean Brandt
**Implementation target:** github.com/seanb4t/gascity → PR upstream
**Related:** `engdocs/design/machine-wide-supervisor-v0.md`, `engdocs/contributors/primitive-test.md`

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
- Auto-discovery of unconfigured Keychain items — the supervisor never loads anything not declared in `prefixes`. `gc supervisor secret list` surfaces orphans as a hint only.
- Deprecation of `GC_SUPERVISOR_ENV` — coexists in v1; future call.

## Distribution constraints

This feature requires CGo on every supported platform:

- **macOS**: `99designs/keyring` Keychain backend links against Apple's Security framework.
- **Linux**: Secret Service backend links against libdbus.
- **Windows**: WinCred backend uses `syscall` only and does not strictly require CGo, but the build is consistent across platforms.

Pre-feature, gc shipped as a pure-Go (`CGO_ENABLED=0`) binary via goreleaser. This feature requires switching the release pipeline to CGo cross-compilation using `ghcr.io/goreleaser/goreleaser-cross`, which bundles `osxcross` and Linux cross-gcc toolchains.

The change is one-time infrastructure work — see Pre-Task in `plans/supervisor-secrets-keychain.md`. After this switch, every gc release is CGo-enabled across all platforms.

**Trade-off accepted:** release artifact size grows modestly (~10-20%) due to libsystem linkage; release pipeline run time increases from ~3 min to ~10 min due to docker image pull and cross-compile overhead. Both costs are acceptable to keep the in-process-keyring design instead of pivoting to subprocess shelling.

**Go version:** the goreleaser-cross image embeds the Go toolchain version that prefixes its tag (currently Go 1.26.2 in `v1.26.2-3-v2.15.4`). This is intentionally newer than the floor in `go.mod` (currently 1.25.9) — release builds use the most recent stable Go to pick up security patches and compiler improvements, while the module's `go` directive states the minimum source-compatibility floor.

**Bumping goreleaser-cross:** find the latest tag at `https://github.com/goreleaser/goreleaser-cross/pkgs/container/goreleaser-cross`, update the image reference in both `.github/workflows/release.yml` and `.github/workflows/rc-gate.yml`, re-resolve the SHA256 digest (`docker inspect --format='{{index .RepoDigests 0}}' <new-tag>`), update the digest pins, and run `make rc-gate-snapshot` (or push to a branch and let CI exercise the snapshot path) to verify before merging.

## Design decisions (settled)

| # | Decision | Rationale |
|---|---|---|
| 1 | Single `prefixes` list; every entry is a service-name prefix | Exact env-var names work as one-result prefixes — one mechanism, no syntax sugar. |
| 2 | Missing/empty matches: WARN-loud-and-continue | Supervisor is shared infrastructure; one missing third-party key must not bring it down. AGENTS.md "Don't Swallow Errors" satisfied by the WARN log entry. |
| 3 | Library: `github.com/99designs/keyring` | Multi-backend abstraction (macOS Keychain, Linux Secret Service, Windows Credential Manager, file, pass, KWallet). Battle-tested in `aws-vault`. Satisfies AGENTS.md "Prefer Well-Known, High Quality OSS Libraries". |
| 4 | Account: configurable, default `$USER@personal` | Matches your existing Keychain layout, leaves room for multi-account (sean@personal vs sean@work) without breaking change. |
| 5 | New CLI subcommand: `gc supervisor secret {set,get,list,delete,reload,import-env}` with drift detection in `list` | Cross-platform UX win — users don't need to learn `security` vs `secret-tool` vs `wincred`. Drift detection surfaces config-vs-keyring-vs-supervisor disagreement at a glance. |
| 6 | Backend: explicit with `auto` default | `auto` picks `keychain` on macOS, `secret-service` on Linux, `wincred` on Windows. Enables clean unit tests (pin `backend = "file"` in CI) and headless deploy scenarios. |
| 7 | Loading model: startup load + SIGHUP reload (Approach 3) | ~50 lines beyond startup-only; meaningful UX win for rotation. Lazy spawn-time injection (better security) deferred to v2. |
| 8 | "Full sync" reload semantics | Keys removed from Keychain between reloads are `os.Unsetenv`'d. Tracked via `lastSet` map on the `Loader`. |
| 9 | Backend swap on reload requires restart | WARN + ignore. Backend swaps are uncommon; restart is fine. |

## Architecture

### Module layout

New package: `internal/supervisor/secrets/` (sibling of `internal/supervisor/config.go`, `publications.go`, `registry.go`).

```
internal/supervisor/secrets/
├── secrets.go        # public API: Loader, LoadAll, Reload
├── secrets_test.go   # unit tests using FileBackend in t.TempDir()
├── keyring.go        # thin wrapper over 99designs/keyring
└── keyring_test.go   # unit tests for backend opening + enumeration
```

**Why a thin wrapper around 99designs/keyring rather than direct use at call sites:**
- Insulates supervisor code from library types (`keyring.Config`, `keyring.Item`) leaking into our domain model. Backend-specific fields (KWallet folder names, file backend paths) stay contained.
- Enables a small `secrets.Backend` interface for testing.

This is not premature abstraction — it's the boundary between library and domain types, a pattern gascity already follows (e.g., `internal/api/genclient` insulates HTTP types from the domain model).

### Wired into

- `cmd/gc/cmd_supervisor_lifecycle.go` — `runSupervisor` calls `secrets.LoadAll(cfg)` after config load, before API server bind. SIGHUP handler installed.
- `cmd/gc/cmd_supervisor_secret.go` — new file; registers the `gc supervisor secret` subcommand tree.
- `internal/supervisor/config.go` — extends `Config` with `Secrets SecretsConfig` field + validation.
- `internal/api/` — new endpoint `GET /v1/supervisor/secrets/status` for drift detection.

## Config schema

### Go types

```go
type Config struct {
    Supervisor  Section           `toml:"supervisor"`
    Publication PublicationConfig `toml:"publication,omitempty"`
    Secrets     SecretsConfig     `toml:"secrets,omitempty"` // NEW
}

type SecretsConfig struct {
    Backend  string                `toml:"backend,omitempty"`  // "auto" | "keychain" | "secret-service" | "file" | "pass"
    Keychain KeychainBackendConfig `toml:"keychain,omitempty"`
    File     FileBackendConfig     `toml:"file,omitempty"`     // populated only if backend = "file"
}

type KeychainBackendConfig struct {
    ServiceName string   `toml:"service_name,omitempty"` // default "gc-supervisor"
    Account     string   `toml:"account,omitempty"`      // default fmt.Sprintf("%s@personal", currentUser())
    Prefixes    []string `toml:"prefixes"`
}

type FileBackendConfig struct {
    Dir      string   `toml:"dir"`
    Prefixes []string `toml:"prefixes"`
}
```

### On-disk shape (`~/.gc/supervisor.toml`)

```toml
[supervisor]
port = 9876

[secrets]
backend = "auto"   # or omit entirely

[secrets.keychain]
prefixes = ["EXA_API_KEY", "FIRECRAWL_", "LINEAR_TOKEN"]
# Each entry is a service-name prefix matched against Keychain items
# under service_name="gc-supervisor". Exact env-var names work as
# one-result prefixes. Missing/empty matches log a WARN and continue.
# Defaults: service_name="gc-supervisor", account="$USER@personal"
```

### Validation

Implemented as `func (c SecretsConfig) Validate() error` in `internal/supervisor/config.go`. Fail-fast at config-load time, not at Keychain query time.

| Rule | Error |
|---|---|
| `Backend` not in allowed values (or empty → "auto") | `secrets.backend: unknown value %q` |
| Prefix doesn't match env-var-name shape | `secrets.keychain.prefixes[%d]: not a valid env-var name`. **Reuse `supervisorServiceEnvNameRE` from `cmd_supervisor_lifecycle.go:381`** — promote it to a package-level export rather than duplicating the regex literal. |
| Prefix shadows reserved env var | `secrets.keychain.prefixes[%d]: would shadow reserved env var %q`. Check against the union of `supervisorServiceFixedEnvKeys` (GC_HOME, PATH, XDG_RUNTIME_DIR — supervisor sets these itself) and `supervisorServiceEnvKeys` (HOME, USER, SHELL, LANG, etc. — auto-persist whitelist). Implementation: extract a single `IsReservedSupervisorEnvKey(name) bool` helper in `cmd/gc/cmd_supervisor_lifecycle.go` that consults both maps; call it from both the install path's existing checks and the new `SecretsConfig.Validate`. |
| `backend = "file"` with empty `[secrets.file].dir` | `secrets.file.dir: required when backend = "file"` |

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

### `LoadAll` algorithm

```go
type Result struct {
    Set     []string  // env vars successfully set, sorted
    Missing []string  // configured prefixes that matched zero items
    Skipped []string  // matched but empty value
    Errors  []error   // per-prefix errors during enumeration
}

func (l *Loader) LoadAll(ctx context.Context, cfg SecretsConfig) (Result, error)
```

Per-load:

1. `keyring.Open(cfg.toKeyringConfig())` — if this fails, return `(Result{}, err)`. Caller logs ERROR and continues; supervisor stays up with no secrets loaded.
2. `keyring.Keys()` once, cache result. One enumeration per `LoadAll`, not per prefix.
3. For each prefix:
   - Filter cached keys for `strings.HasPrefix(key, prefix)`.
   - Zero matches → append to `Result.Missing`.
   - For each match: `keyring.Get(key)`. If `len(Data) > 0`, `os.Setenv(key, string(Data))` and append to `Result.Set`. If empty, append to `Result.Skipped`. Per-key errors append to `Result.Errors` and continue.
4. Update `l.lastSet` (used by `Reload` for full-sync semantics).

### Failure-mode matrix

| Failure | Behavior | Log level |
|---|---|---|
| `keyring.Open()` fails | Return error; supervisor logs ERROR and continues. Not fatal. | ERROR |
| `keyring.Keys()` fails after Open | Same — log ERROR, return empty Result. | ERROR |
| Prefix matches zero items | Append to `Missing`, continue. | WARN |
| `keyring.Get(key)` fails for one match | Append to `Errors`, continue with other matches. | WARN |
| Match has empty data | Append to `Skipped`, do not call `os.Setenv`. | WARN |

**No Keychain failure brings down the supervisor.** Worst case: secrets unavailable; agents that need them fail when invoked, with a clear chain of evidence in `supervisor.log`.

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

1. Compute new key set via the same enumeration as `LoadAll`.
2. For keys in `l.lastSet` but not in new set: `os.Unsetenv(key)`, append to `Removed`.
3. For keys in new set with values different from `os.Getenv(key)`: `os.Setenv`, append to `Updated`.
4. For keys in new set not in `l.lastSet`: `os.Setenv`, append to `Added`.
5. Replace `l.lastSet` with new set.

Reload is idempotent — calling twice with no changes yields empty Added/Updated/Removed.

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
| `gc supervisor secret import-env` | Reads keys named in `GC_SUPERVISOR_ENV` from current shell env, writes each to backend, prints suggested `[secrets.keychain] prefixes` block. |
| `gc supervisor secret reload` | Discovers supervisor PID, sends SIGHUP. Works regardless of how supervisor was launched. |

### `list` drift detection

Reconciles three sources:

1. Configured prefixes in `supervisor.toml`.
2. Items currently in Keychain backend matching any prefix.
3. Env vars currently set in the *running supervisor* (queried via the new HTTP endpoint below).

```
NAME              CONFIGURED  IN-KEYCHAIN  LIVE-IN-SUPERVISOR  STATUS
EXA_API_KEY       yes         yes          yes                 OK
FIRECRAWL_KEY     yes         no           no                  MISSING
LINEAR_TOKEN      yes         yes          no                  STALE (run: gc supervisor secret reload)
ORPHAN_KEY        no          yes          no                  ORPHAN (in Keychain, no prefix matches)
```

Status semantics:

- **OK** — configured + in Keychain + live in supervisor.
- **MISSING** — configured but no Keychain match (the WARN-loud-continue case).
- **STALE** — configured + in Keychain + not in supervisor → user added secret but didn't reload.
- **MISMATCH** — configured + in Keychain + in supervisor but values differ (length-and-hash compare; we never display values).
- **ORPHAN** — in Keychain under our `service_name` umbrella but no configured prefix matches. Harmless; usually means user added a key directly without updating config.

If supervisor is down, `list` falls back to "config + Keychain only" and marks live status as `(supervisor down)`.

### Live-supervisor query: `/v1/supervisor/secrets/status`

New Huma-registered endpoint. Returns per-secret `{name, length, sha256}`. **Never the value.** Inherits whatever auth `/v1/supervisor/*` already has (per `engdocs/architecture/api-control-plane.md`).

Per gascity's typed-wire invariant: response struct registered via `huma.Register` with typed Output; OpenAPI regeneration captures the new endpoint (`make dashboard-check`).

### Backend lookup in CLI

Each subcommand independently reads `supervisor.toml` and calls `keyring.Open(cfg)` with the same config the supervisor uses. **No coupling between CLI and running supervisor for backend access** — `gc supervisor secret set EXA_API_KEY` works whether the supervisor is up or down.

## Testing strategy

### Unit tests (next to code, no build tag)

`internal/supervisor/secrets/secrets_test.go`:

| Test | Asserts |
|---|---|
| `TestLoadAll_EmptyKeychain` | `Result.Set` empty, all configured prefixes in `Missing`, no error |
| `TestLoadAll_ExactMatch` | env var set, `Set = ["EXA_API_KEY"]`, `Missing` empty |
| `TestLoadAll_PrefixMatchesMultiple` | both env vars set from prefix `["LINEAR_"]` |
| `TestLoadAll_EmptyValueSkipped` | env var NOT set, item in `Skipped` |
| `TestLoadAll_BackendOpenFails` | returns error, supervisor caller continues |
| `TestLoadAll_ReservedPrefixRejected` | validation error before any Keychain call |
| `TestReload_AddedUpdatedRemoved` | `ReloadResult` populated correctly; `os.Unsetenv` called for removed |
| `TestReload_BackendSwapIgnored` | reload logs WARN, env unchanged |
| `TestReload_Idempotent` | second call's `Added/Updated/Removed` all empty |

`internal/supervisor/config_test.go` extended with `TestSecretsConfig_Validate_*` covering each rejection rule.

CLI tests (`cmd/gc/cmd_supervisor_secret_test.go`) cover each subcommand using FileBackend in `t.TempDir()`.

API tests (`internal/api/`) cover `/v1/supervisor/secrets/status` with a fuzzing-style assertion that response body never contains loaded secret values (grep-assert).

### Integration tests (`test/secrets_integration_test.go`, `//go:build integration`)

- `TestSupervisor_LoadsSecretsAtStartup` — real supervisor binary + file backend; assert child has env var.
- `TestSupervisor_SIGHUPReload` — start, mutate keyring, SIGHUP, spawn fresh child, assert new value. Old child has stale value (documents the Unix behavior).

### Deliberately not tested in CI

- **Real macOS Keychain integration** — interactive ACL prompts break CI; CI runners lack a login Keychain. Manual smoke test in PR template instead.
- **99designs/keyring internals** — covered by the library's own tests.
- **Signal-handler delivery wiring** — covered implicitly by `TestSupervisor_SIGHUPReload`.

## Migration

For Sean's existing setup (the only known user):

```bash
# 1. Build & install patched gc binary from the fork
cd /Volumes/Code/github.com/seanb4t/gascity && go build -o /opt/homebrew/bin/gc ./cmd/gc

# 2. Re-store EXA_API_KEY under the new layout
gc supervisor secret set EXA_API_KEY   # prompts for value

# 3. Add prefix to ~/.gc/supervisor.toml
cat >> ~/.gc/supervisor.toml <<'EOF'

[secrets.keychain]
prefixes = ["EXA_API_KEY"]
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

## Rollout / PR strategy

1. **Fork**: github.com/seanb4t/gascity
2. **Branch**: `feat/supervisor-secrets-keychain` off main
3. **Atomic commits** (per AGENTS.md conventional commits):
   - `feat(supervisor): add SecretsConfig schema and validation`
   - `feat(supervisor): add internal/supervisor/secrets package`
   - `feat(supervisor): wire secrets.LoadAll into runSupervisor startup`
   - `feat(supervisor): add SIGHUP reload handler`
   - `feat(cli): add gc supervisor secret subcommand tree`
   - `feat(api): add /v1/supervisor/secrets/status endpoint`
   - `docs(supervisor): add supervisor-secrets-v0 design doc`
   - `test(supervisor): integration coverage for startup load + SIGHUP reload`
4. **PR description**: link to this design doc; reference bd memory `supervisor-keychain-wrapper` for original problem context. Note: this passes the Primitive Test (`engdocs/contributors/primitive-test.md`) — single primitive, ZFC-clean, gets more useful as model and secret-manager ergonomics improve.
5. **Pre-flight before opening PR**:
   - `make test` (fast unit baseline)
   - `make test-integration-shards-parallel`
   - `go vet ./...`
   - `make dashboard-check` (since `internal/api/` is touched)
   - Manual smoke: end-to-end migration on Sean's machine

## Design principles applied

- **ZFC** — gc contains no judgment about *what* secrets mean. It loads what config declares, sets `os.Setenv`, and gets out of the way. The decision logic ("is this the right value?") lives in the user's Keychain.
- **Bitter Lesson** — config-driven Keychain integration becomes *more* useful as secret-manager ergonomics improve (e.g., 1Password's `op` CLI improving). A hardcoded `EXA_*` allowlist would not.
- **Primitive Test** — single primitive (load named secrets from a configured backend), composable (any backend the library supports), atomic (no decomposition possible).
- **No premature abstraction** — `internal/supervisor/secrets/`, not `internal/secrets/`. Promote when a second consumer (per-agent secrets?) appears.
- **Don't Swallow Errors** — every failure mode produces a WARN or ERROR log entry; nothing silently disappears.
- **Observability & Testability** — file-backend strategy makes the entire feature unit-testable without real Keychain; drift detection makes config-vs-runtime divergence visible.
