# DIFF.md — security remediation on `feature/remove_security_issue`

Branch: `feature/remove_security_issue` (off `develop`). Date: 2026-05-30.
Scope: the "core bundle" agreed up front (see [DISCOVERY.md](DISCOVERY.md) §5).

## Summary

| Issue(s) | Fix | Files | Tests added |
|----------|-----|-------|-------------|
| #1790 #1160 #656 | `0600`/`0700` perms on tracking DB + tee logs | `utils.rs`, `tracking.rs`, `tee.rs` | 2 |
| #1350 #1770 | flag-injection: `--` terminator + hook guard | 5 hook files | 4 (bash) |
| #1875 (3) | honor `tracking.enabled = false` | `tracking.rs` | 2 |
| #1875 (1) #1986 | redact `aws secretsmanager get-secret-value` | `aws_cmd.rs` | 4 (2 rewritten + 2 new) |

`git diff develop --stat`: 10 files, +293 / −18. New file: `DISCOVERY.md`, `DIFF.md`.

**Verification:** `cargo fmt --all` clean · `cargo clippy --all-targets` 0 warnings ·
`cargo test --all` → **1988 passed, 0 failed, 7 ignored**. Bash hook harness:
4/4 new flag-injection cases pass; the 7 unrelated failures (audit-log + compound-`&`)
are **pre-existing on `develop`** (verified by running the baseline script — identical 7).

---

## Fix 1 — Restrictive permissions on local data (#1790 / #1160 / #656)

**Problem:** the tracking DB (`~/.local/share/rtk/history.db`) holds full command
history + project paths, and tee logs hold raw unfiltered output (can contain
secrets). Both were created with default umask perms (typically world-readable
`0644` dir / files), unlike the device-salt file which already used `0600`.

**Change:** new shared helper, applied at both creation points.

`src/core/utils.rs` — new helper (no-op off Unix):
```rust
pub fn restrict_permissions(path: &std::path::Path, mode: u32) {
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)); }
    #[cfg(not(unix))] { let _ = (path, mode); }
}
```

`src/core/tracking.rs` — `new()` now delegates to `open_at(path)`, which after
`create_dir_all` / `Connection::open`:
```rust
crate::core::utils::restrict_permissions(parent, 0o700); // dir → covers WAL/SHM sidecars
...
crate::core::utils::restrict_permissions(&db_path, 0o600); // db file
```
(`new()` → `open_at()` was extracted so a test-only `new_at(path)` can verify
perms without mutating the global `RTK_DB_PATH`.)

`src/core/tee.rs` — `write_tee_file()`:
```rust
crate::core::utils::restrict_permissions(tee_dir, 0o700);   // after create_dir_all
...
crate::core::utils::restrict_permissions(&filepath, 0o600); // after write
```

**Tests:** `tracking::tests::test_new_sets_restrictive_permissions` and
`tee::tests::test_write_tee_file_sets_restrictive_permissions` (both `#[cfg(unix)]`)
assert mode `0600` on the file and `0700` on the dir.

---

## Fix 2 — Flag-injection in rewrite hooks (#1350 / #1770)

**Problem (reproduced on this fork):**
```
$ rtk rewrite "--help"      # → prints HELP TEXT, exit 0
$ rtk rewrite -- "--help"   # → no output, exit 1   ✅ safe
```
With exit 0, the hook fed the help text back as `updatedInput.command` with
`permissionDecision: "allow"` — the agent would then shell-execute attacker- or
LLM-controlled text. Any command starting with `-`/`--` triggered it.

**Change:** added the `--` end-of-options terminator to every hook that shells
out to `rtk rewrite`, so a leading-dash command can never be parsed as a flag of
`rtk rewrite` itself:

| File | before | after |
|------|--------|-------|
| `hooks/claude/rtk-rewrite.sh` | `rtk rewrite "$CMD"` | `rtk rewrite -- "$CMD"` |
| `hooks/cursor/rtk-rewrite.sh` | `rtk rewrite "$CMD"` | `rtk rewrite -- "$CMD"` |
| `hooks/opencode/rtk.ts` | `` $`rtk rewrite ${command}` `` | `` $`rtk rewrite -- ${command}` `` |
| `hooks/pi/rtk.ts` | `["rewrite", cmd]` | `["rewrite", "--", cmd]` |
| `hooks/hermes/rtk-rewrite/__init__.py` | `["rtk","rewrite",command]` | `["rtk","rewrite","--",command]` |

**Defense-in-depth guard** (claude + cursor): a legitimate rewrite is always a
single, non-empty line. If a rewrite-bearing exit code (0/3) yields empty or
multi-line output, the hook now passes through instead of auto-allowing:
```sh
if { [ "$EXIT_CODE" -eq 0 ] || [ "$EXIT_CODE" -eq 3 ]; } &&
   { [ -z "$REWRITTEN" ] || [ "$(printf '%s' "$REWRITTEN" | wc -l)" -gt 0 ]; }; then
  exit 0
fi
```

The CLI already accepts `--` (clap `allow_hyphen_values` + `--` terminator), so
no Rust change was needed there.

**Tests:** `hooks/claude/test-rtk-rewrite.sh` gains a "Flag-injection regression
(#1350)" section asserting `--help`, `--version`, `-h`, `-rf /` all pass through
(no rewrite). All 4 pass against the patched script + binary.

---

## Fix 3 — Honor `tracking.enabled = false` (#1875 finding 3)

**Problem:** `Config.tracking.enabled` existed but was never checked; rows were
inserted unconditionally.

**Change (`src/core/tracking.rs`):** new
```rust
pub fn is_tracking_enabled() -> bool {
    crate::core::config::Config::load().map(|c| c.tracking.enabled).unwrap_or(true)
}
```
gated at the three write entry points — `TimedExecution::track`,
`track_passthrough`, and `record_parse_failure_silent`. Defaults to `true` on
config-load error so a missing/unreadable config never silently disables a
default-on feature. Read paths (`gain`, telemetry stats) are untouched.

`track` delegates to `track_with(..., enabled)` which returns `bool` (recorded
or gated), making the gate observable in tests without touching the DB/env.

**Tests:** `test_track_respects_enabled_flag` (false → not recorded, true →
recorded) and `test_is_tracking_enabled_defaults_true`.

---

## Fix 4 — Redact `aws secretsmanager get-secret-value` (#1875 finding 1 / #1986)

**Problem:** the filter emitted the raw `SecretString` (`Secret: {"password":...}`)
straight into agent context/transcripts; tests even asserted the cleartext was
present.

**Change (`src/cmds/cloud/aws_cmd.rs`):** `filter_secrets_get` now reads
`RTK_AWS_SHOW_SECRETS` and delegates to a testable `filter_secrets_get_impl(json,
reveal)`. Default (`reveal = false`) redacts the value while keeping useful,
non-secret metadata:
- JSON secret → `Secret: [redacted JSON, N keys: <key names> — set RTK_AWS_SHOW_SECRETS=1 to reveal]`
- opaque string → `Secret: [redacted N chars — set RTK_AWS_SHOW_SECRETS=1 to reveal]`

`RTK_AWS_SHOW_SECRETS=1` restores the original full-value behavior (explicit opt-in).

**Tests:** the 2 old tests that asserted leakage were rewritten to assert
redaction by default; 2 new tests cover the opt-in reveal path (JSON + plain).

---

## Step 5 — Self security re-review of these changes

Reviewed each change for newly-introduced risk:

- **`restrict_permissions`** is best-effort (ignores errors) and only *tightens*
  perms — it can never widen them. No-op off Unix is documented.
- **Tracking dir `0700`** is correct for a per-user data dir and also protects
  the WAL/SHM sidecars (which `0600` on the main file alone would not).
- **`--` terminator + guard** close the injection without changing any valid
  rewrite (verified: `git status` etc. still rewrite; 63→… baseline cases hold).
  The guard uses `printf '%s'` (no backslash interpretation) and `wc -l`.
- **tracking gate** introduces no parsing/injection surface; fail-open to `true`
  is the safe default for an opt-out flag.
- **aws redaction** reveals only JSON *key names* (not values) by default — a
  large reduction in exposure; values require explicit opt-in.

**Residual / out of scope (noted, not introduced by us):** tee still writes raw
output (incl. secrets) to disk on failure — now `0600`/`0700`, but not content-
redacted; full tee redaction is tracked separately (#1988). Telemetry arg
leakage (#1785), install.sh integrity (#1158) and the hook auto-allow redesign
(#1155) were deferred by agreement (see DISCOVERY.md §5).

## How to verify locally

```bash
source "$HOME/.cargo/env"
cargo fmt --all && cargo clippy --all-targets && cargo test --all
# flag-injection hook regression:
PATH="$PWD/target/debug:$PATH" \
  HOOK="$PWD/hooks/claude/rtk-rewrite.sh" bash hooks/claude/test-rtk-rewrite.sh
```
