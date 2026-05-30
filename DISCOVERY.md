# DISCOVERY.md — RTK fork technical overview

> Working notes produced while onboarding to this fork and preparing the
> `feature/remove_security_issue` branch. Date: 2026-05-30.

## 1. What RTK is

**rtk (Rust Token Killer)** is a single-binary CLI proxy that minimizes LLM
token consumption by filtering/compressing the output of common dev commands
(git, cargo, npm, pytest, docker, aws, …). It claims 60–90% token savings.

- Upstream: `rtk-ai/rtk`
- This fork: `Yui-Qi-Tang/rtk` (remote `origin`), default branch `develop`.
- Language: **Rust** (edition per `Cargo.toml`), single-threaded, **no async** by design (startup target < 10 ms).

## 2. Toolchain (installed during onboarding)

Rust was not present on this machine; installed via `rustup` (minimal profile):

| Tool | Version |
|------|---------|
| `cargo` | 1.96.0 |
| `rustc` | 1.96.0 |
| `rust-analyzer` (LSP) | 1.96.0 (rustup component) |

Activate in a shell with `source "$HOME/.cargo/env"`.

Build/test commands (from `CLAUDE.md`):

```bash
cargo build                 # debug build
cargo test --all            # all tests
cargo fmt --all             # format
cargo clippy --all-targets  # lints (zero-tolerance policy)
# Pre-commit gate (mandatory after any Rust edit):
cargo fmt --all && cargo clippy --all-targets && cargo test --all
```

Baseline (`develop`): `cargo build` succeeds; full test suite is the gate.

## 3. Architecture

Command proxy: `main.rs` routes a Clap `Commands` enum to filter modules in
`src/cmds/*/`. Each module executes the underlying command and compresses its
output. Token savings are tracked in SQLite (`src/core/tracking.rs`).

```
src/
├── main.rs              Commands enum + routing (entry point)
├── core/
│   ├── config.rs        ~/.config/rtk/config.toml (RtkConfig, TrackingConfig, TelemetryConfig, TeeConfig)
│   ├── tracking.rs      SQLite token metrics; Tracker, TimedExecution, get_db_path()
│   ├── tee.rs           Raw output recovery to ~/.local/share/rtk/tee/*.log
│   ├── telemetry.rs     Opt-in analytics ping; device-salt file (0600 precedent)
│   ├── utils.rs         strip_ansi, truncate, execute_command, count_tokens
│   ├── filter.rs        language-aware code filtering
│   └── toml_filter.rs   TOML DSL filter engine
├── hooks/
│   ├── rewrite_cmd.rs   `rtk rewrite` — single source of truth for hook rewrites
│   ├── trust.rs         project trust/untrust
│   └── integrity.rs     SHA-256 hook verification
├── cmds/                per-ecosystem filters (git, rust, js, python, go, dotnet, cloud, system, ruby)
│   └── cloud/aws_cmd.rs aws filters incl. secretsmanager get-secret-value
├── discover/            Claude Code history analysis + rewrite registry (rules)
├── analytics/           gain / usage reporting
└── filters/            60 TOML filter configs

hooks/                   Per-agent hook installers (claude, cursor, codex, opencode, pi, hermes, …)
  claude/rtk-rewrite.sh  PreToolUse hook → calls `rtk rewrite`, emits permissionDecision
```

### Hook / rewrite flow

LLM agents install a `PreToolUse` hook (`hooks/<agent>/rtk-rewrite.sh`). The
hook pipes the proposed command JSON in, extracts `.tool_input.command`, and
calls `rtk rewrite "$CMD"`. Exit-code protocol:

| Exit | Meaning | Hook action |
|------|---------|-------------|
| 0 + stdout | rewrite found, no permission rule matched | auto-`allow` rewritten cmd |
| 1 | no RTK equivalent | pass through unchanged |
| 2 | deny rule matched | pass through (native deny) |
| 3 + stdout | ask rule matched | rewrite, but prompt user |

`rtk rewrite` is defined in `src/main.rs` (`Rewrite { args: Vec<String> }`,
`trailing_var_arg + allow_hyphen_values`) and delegates to
`src/discover/registry::rewrite_command`.

## 4. Coding rules (from `.claude/rules/`)

- `anyhow::Result` + `.context()` everywhere; **no `unwrap()`** in prod (tests use `expect`).
- All regex via `lazy_static!`.
- **Fallback pattern**: if a filter fails, pass the raw command/output through — never block the user.
- Exit-code propagation via `std::process::exit(code)`.
- Tests live in-module (`#[cfg(test)] mod tests`); fixtures in `tests/fixtures/`; snapshots via `insta`.
- Every filter asserts ≥60% token savings.

## 5. Security-issue inventory (upstream `rtk-ai/rtk`, `area:security` + keyword scan)

Snapshot taken 2026-05-30. The link in the request points at `/pulls`, but the
tracked **security work lives in the issue tracker**. Open items:

| # | Title | Nature | In scope here |
|---|-------|--------|---------------|
| 1350 | rtk-rewrite.sh missing `--` → flag-injection | shell + CLI | ✅ |
| 1770 | rewrite: normalize abs paths + shell-escape prefix | rewrite | ✅ (related) |
| 1160 | tracking.db exposes full command history | local data | ✅ |
| 1790 | Harden perms for history DB and tee logs (0600/0700) | local data | ✅ |
| 656  | restrict tee file/dir perms to 0600/0700 | local data | ✅ |
| 1875 | privacy: secret output filtering, history, tracking toggle | mixed | ✅ (findings 1 & 3) |
| 1986 | redact `secretsmanager get-secret-value` payload | filter | ✅ |
| 1785 | telemetry `low_savings_commands` leaks args | telemetry | ⬜ (touches telemetry payload) |
| 1784 | telemetry auth secret embedded in release binaries | build/CI | ⬜ (CI infra) |
| 1158 | install.sh `curl\|sh` without integrity verification | release infra | ⬜ |
| 1155 | hook auto-allow bypasses agent permission model | design | ⬜ (large) |
| 2070 / 1782 | Windows Defender false-positive | not code-fixable | ⬜ |

Open security-related **PRs** worth knowing: #2050 (TOCTOU in filter loading),
#2048 (gate `eprintln!` behind `RTK_HOOK_MODE`), #2072 (hermes-safe default +
redaction), #1988/#1987/#1986 (tee/tracking/aws redaction).

### Scope chosen for `feature/remove_security_issue` (the "core bundle")

1. **#1790 / #1160 / #656** — restrictive `0600`/`0700` permissions on the
   tracking DB (file + parent dir) and tee logs (file + parent dir), following
   the `telemetry.rs` device-salt precedent (`0o600`).
2. **#1350 / #1770** — flag-injection: add the `--` end-of-options terminator to
   `rtk rewrite` calls in the hook scripts, plus a defensive guard in the hook
   that refuses to auto-allow empty/multiline rewrite output.
3. **#1875 finding 3** — actually honor `tracking.enabled = false`.
4. **#1875 finding 1 / #1986** — redact `aws secretsmanager get-secret-value`
   secret material by default, with an explicit opt-in to reveal.

Deferred (with reasons): telemetry payload changes (#1785/#1784 — adjacent to
shared salt/hash logic; require coordinated client/release changes), install.sh
integrity (#1158 — depends on release-published checksums), hook permission
redesign (#1155 — larger behavioral change), Windows AV false-positives
(#2070/#1782 — not addressable in source).

## 6. Verification approach

Each fix ships with tests (unit tests in-module for Rust; a regression case in
the bash hook test harness for the flag-injection fix). Full gate
(`cargo fmt --all && cargo clippy --all-targets && cargo test --all`) must pass
before the change is considered done. A diff summary is recorded in `DIFF.md`.
