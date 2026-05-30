# DIFF.md — security remediation on `feature/remove_security_issue`

Branch: `feature/remove_security_issue` (off `develop`). Date: 2026-05-30.
Goal: a **security-hardened internal build** of rtk (not for upstream). Driven by
the upstream #640 audit + DailyCVE trust finding. Detail sections below are
chronological; this table is the at-a-glance overview.

## Overview — every hardening on this branch

| Area | Issue | What changed | Status |
|------|-------|--------------|--------|
| Local data perms | #1790 #1160 #656 | tracking DB + tee logs → `0600`/`0700` | ✅ fixed |
| Hook flag-injection | #1350 #1770 | `--` terminator in all rewrite hooks + empty/multiline guard | ✅ fixed |
| Tracking opt-out | #1875 | `[tracking] enabled = false` now enforced | ✅ fixed |
| AWS secrets | #1986 #1875·1 | `secretsmanager get-secret-value` redacted by default (opt-in reveal) | ✅ fixed |
| ANSI/OSC | #640 G-1 | `strip_ansi` also strips OSC 8 hyperlinks (URL exfil) | ✅ fixed |
| Path traversal | #640 F-1 | `RTK_TEE_DIR` must be absolute | ✅ fixed |
| Cmd-history secrets | #640 E-1 E-2 | `record()` redacts passwords/tokens/Authorization/URL creds before storage (covers `proxy`) | ✅ fixed |
| Filter integrity | #640 D-2 | global `~/.config/rtk/filters.toml` now trust-gated (SHA-256), `rtk trust` covers it | ✅ fixed |
| Filter tampering | #640 A-1 | user filters can't `replace`/`match_output` (rewrite/swallow output) — built-in only | ✅ fixed |
| Shell injection | #640 B-1a | `err/test/summary` exec directly (no `sh -c`); refuse shell metachars/inline-env | ✅ fixed |
| Hook auto-allow | #640 B-1b | `err/test/summary/proxy/sh` never auto-allowed — force human confirm | ✅ fixed |
| CI trust bypass | #640 D-1 | removed `RTK_TRUST_PROJECT_FILTERS` env override entirely | ✅ fixed |
| Env secrets | #640 E-3 | `rtk env` always masks secrets (even `--show-all`); +passwd/pwd/passphrase | ✅ fixed |
| Audit log growth | #640 H-1 | `hook-audit.log` rotates past 5 MB | ✅ fixed |
| Installer integrity | #640 A-4 | `install.sh` verifies `.sha256` (fail-closed) | ✅ fixed |
| Telemetry egress | #640 C-1 | network ping hard-disabled unless `RTK_TELEMETRY_FORCE_SEND=1` | ✅ fixed |
| Exit codes | #640 G-2 | verified already correct (no change needed) | ✓ verified |
| Telemetry arg leak | #1785 | `low_savings_commands` still sends first 3 tokens, but secrets pre-redacted (E-1) + egress off (C-1) | ⚠️ mitigated, not isolated-fixed |

**Deferred (architectural / by-design):** A-1 middle-layer trust (inherent),
A-2 non-shell hook auto-allow (already default→ask), I-2 SQLite GLOB on Windows.
Not tamper-proof vs a same-uid attacker (could swap the binary); filters still
truncate (use `rtk proxy` for full output).

**Quality gate (every phase):** `cargo fmt` clean · `cargo clippy --all-targets`
0 warnings · `cargo test --all` **2000 passed / 0 failed / 7 ignored**.

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

---

## Follow-up fixes (from full #640 checklist review)

After auditing the upstream #640 checklist (full report in
`claudedocs/RTK-security-review-2026-05-30.md`, gitignored/local), three more
low-risk, in-tree items were fixed on this branch:

| Issue | Fix | File | Tests |
|-------|-----|------|-------|
| #640 G-1 | `strip_ansi` now also strips OSC sequences (BEL/ST-terminated), incl. OSC 8 hyperlinks whose embedded URLs were reaching the LLM context | `core/utils.rs` | 2 |
| #640 F-1 | `RTK_TEE_DIR` must be an absolute path; a relative value (settable via a tool call to redirect raw output) is warned about and ignored | `core/tee.rs` | 1 |
| #640 E-1/E-2 | `Tracker::record()` runs `redact_sensitive_args()` before persisting `original_cmd`/`rtk_cmd` — strips values after credential flags (`--password`/`--token`/…), `Authorization:` headers, sensitive `KEY=value` env, and inline URL creds (`scheme://u:p@`). Covers the `rtk proxy` path too. | `core/tracking.rs` | 2 |

**Verification:** `cargo fmt` clean · `cargo clippy --all-targets` 0 warnings ·
`cargo test --all` → **1993 passed, 0 failed, 7 ignored**.

**Still NOT fixed on this branch (higher risk / upstream-coordinated):**
B-1 `sh -c` injection (upstream PR #1194 OPEN), D-1 CI-trust hardening,
A-4 release checksum, E-3 `--show-all` confirm, H-1 audit-log rotation.
See the review report for rationale.

---

## Filter trust hardening (A + B) — anti-tampering of the middle layer

Goal: make RTK's output-filtering layer trustworthy — only filter noise, can't
be silently tampered to hide/rewrite the truth. RTK has three filter sources:
project `.rtk/filters.toml`, global `~/.config/rtk/filters.toml`, and built-in
(`src/filters/*.toml`, embedded at compile time). The runtime-loaded user
sources were the tamper surface.

**A — trust-gate the global filter (#640 D-2).** `~/.config/rtk/filters.toml`
was loaded unconditionally; now it goes through the same `check_trust()` +
SHA-256 pinning as project filters (`core/toml_filter.rs::load`). Untrusted or
changed → skipped with a warning until reviewed. `rtk trust` / `rtk untrust`
were extended to review/trust/revoke the global file too (`hooks/trust.rs`,
new `global_filter_path()` + `review_and_trust()` helpers; `main.rs` doc).

**B — drop rewrite primitives from user filters (#640 A-1).**
`parse_and_compile`/`compile_filter` now take `allow_rewrite`: only built-in
filters may use `replace` / `match_output` (rewrite or swallow output).
User filters (project + global) get those rules dropped with a notice — they
may only strip/keep/truncate noise lines, never fabricate or hide via rewrite.
`rtk verify` mirrors this (builtin=allow, project=deny).

| File | Change | Tests |
|------|--------|-------|
| `core/toml_filter.rs` | `allow_rewrite` threading; global trust-gate in `load()` | 1 (`test_user_filter_rewrite_primitives_disabled`) |
| `hooks/trust.rs` | `rtk trust/untrust` cover global file | 1 (`test_global_filter_path_*`) |
| `main.rs` | `Trust`/`Untrust` doc updated | — |

**Verification:** `cargo fmt` clean · `cargo clippy --all-targets` 0 warnings ·
`cargo test --all` → **1995 passed, 0 failed, 7 ignored**.

**⚠️ Behavior change for existing users:** anyone who already has a
`~/.config/rtk/filters.toml` will see it stop applying after this change until
they run `rtk trust` (fail-closed, same model as project filters). Any
`replace`/`match_output` rules in their user filters become inert (noticed on
stderr). This is intentional hardening.

**Honest limits (not solved by A+B):** this raises the bar and makes tampering
tamper-*evident*, but is not tamper-*proof* against an attacker with your uid
(they could replace the `rtk` binary itself, alter PATH, or change the Claude
Code hook config — OS-level controls are out of scope). Built-in filters still
truncate, so "noise-only" is best-effort, not a guarantee — use `rtk proxy` /
raw output when you need the complete, unfiltered result.

---

## Internal hardened-fork batch (B-1, D-1, E-3, H-1, A-4)

Remaining #640 risks fixed for the internal security-first build.

| ID | Fix | Files | Tests |
|----|-----|-------|-------|
| **B-1a** | `rtk err/test/summary` no longer use `sh -c`. New `build_exec_command()` tokenizes and execs directly; refuses shell metacharacters (`\| & ; > < $ \` ( ) { } * ?`) and leading inline env assignments. | `core/utils.rs`, `cmds/rust/runner.rs`, `cmds/system/summary.rs` | 3 |
| **B-1b** | The hook never auto-allows shell-executing rtk subcommands (`err/test/summary/proxy/sh`) — they always force a human confirmation (exit 3 / ask), even if an allow rule matches. | `hooks/rewrite_cmd.rs` | 1 |
| **D-1** | Removed the `RTK_TRUST_PROJECT_FILTERS` env override entirely (and the `TrustStatus::EnvOverride` variant). Trust is granted only via `rtk trust` — a repo's own scripts can no longer self-authorize filters. | `hooks/trust.rs`, `core/toml_filter.rs` | 1 (rewritten) |
| **E-3** | `rtk env` always masks sensitive vars (`--show-all` no longer reveals secrets; it only un-truncates long non-sensitive values). Added `passwd`/`passphrase`/`pwd`/`session` patterns (catches `MYSQL_PWD`, `DB_PASSWD`, …). | `cmds/system/env_cmd.rs` | 1 |
| **H-1** | `hook-audit.log` rotates to `hook-audit.log.1` once it passes 5 MB instead of growing unbounded. | `hooks/hook_cmd.rs` | 1 |
| **A-4** | `install.sh` downloads and verifies a `.sha256` for the release tarball; fail-closed (refuses to install) unless `RTK_ALLOW_UNVERIFIED=1`. | `install.sh` | — (shell) |

**Verification:** `cargo fmt` clean · `cargo clippy --all-targets` 0 warnings ·
`cargo test --all` → **2000 passed, 0 failed, 7 ignored**.

**⚠️ Behavior changes (internal fork, intentional):**
- `rtk err/test/summary "<cmd with | && 2>&1 $() etc.>"` is now **refused** — run
  such compound commands directly in your shell. Inline env (`FOO=bar cmd`) too.
- `rtk test`/`rtk proxy`/`rtk sh` invocations are never auto-approved by the
  hook — the agent will prompt for confirmation.
- CI that relied on `RTK_TRUST_PROJECT_FILTERS=1` must now `rtk trust` the filter
  file (or pre-populate the trust store).
- `rtk env --show-all` no longer prints secret values.

**Still deferred (architectural / by-design):** A-1 (RTK is a middle layer —
inherent), A-2 hook auto-allow for *non-shell* rewrites (already default→ask),
I-2 SQLite GLOB on Windows (macOS unaffected). These need design-level decisions
rather than a localized patch.

---

## Reviewer follow-up (C-1 telemetry egress, G-2 exit codes)

Two points raised in external review, both investigated directly:

**C-1 — telemetry network egress → now hard-disabled.** Confirmed `maybe_ping()`
→ `send_ping()` → `ureq::post()` (telemetry.rs) is a real network path,
independent of the local SQLite tracking. In base it was already off-by-default
(compile-time `option_env!` URL + `consent_given` defaulting to `None`), but for
this build we invert it to fail-shut: `maybe_ping()` now returns immediately
unless `RTK_TELEMETRY_FORCE_SEND=1` is set per-process. Result: rtk never
contacts the network by default, regardless of config or a compiled-in URL. The
salt/`device_hash` logic is left untouched (not changed, just never invoked).
Files: `core/telemetry.rs`, `main.rs`.

**G-2 — exit-code propagation → verified correct, no change needed.** Tested the
built binary directly:

| command | rtk exit | raw exit |
|---------|----------|----------|
| `rtk err "false"` | 1 | 1 |
| `rtk err "ls /nonexistent"` (fails *with* output) | 1 | 1 |
| `rtk test "false"` | 1 | — |
| `rtk test "true"` | 0 | — |

`run_err`/`run_test`/`summary::run` return the child's exit code and `main.rs`
ends with `std::process::exit(code)`. The original "exit 0 on failure" scenario
does not reproduce on current `develop` — it was already fixed upstream, which is
why there is no commit for it in this branch.

### Verification pass (hand-checked the audit's subagent-sourced claims)

The original report was assembled partly from read-only subagents; this pass
re-checked the load-bearing conclusions directly. Results:

| Claim | Verdict |
|-------|---------|
| G-2 exit codes propagate | ✅ verified (ran the binary) |
| C-1 telemetry has independent network egress, off-by-default | ✅ verified (grep + now hard-disabled) |
| C-1 *"all payload fields are tool-names only"* | ❌ **corrected** — `low_savings_commands` sends the first 3 tokens of `rtk_cmd`, which can include args (#1785). `top_commands`/`passthrough_top` *are* tool-name-only. On this branch it's mitigated by E-1 redaction (args stripped before storage) + telemetry being off by default. |
| A-2 no-rule → default *ask* | ✅ verified (`permissions.rs`) |
| I-1 telemetry on `thread::spawn` fire-and-forget | ✅ verified |
| J-1 `.semgrep.yml` rules (incl. `interpreter-execution` → `Command::new("sh")`) | ✅ verified |
| J-2 CI security workflow (`ci.yml`) | ✅ verified |
| D-3 trust mechanism (`rtk trust`, SHA-256 pin) present | ✅ verified (read during A/B work) |

Net correction: one over-broad telemetry claim fixed. Everything else held.

---

## Red/blue adversarial round (executed red-team → fixes)

Ran a white-box red-team pass (playbook + verbatim prompts in `RED_BLUE.md`):
attacker subagents generated payloads, every payload was **executed** against the
real binary/functions, confirmed gaps were fixed and locked with regression
tests. Findings:

| Surface | Result | Fix |
|---------|--------|-----|
| B-1 `build_exec_command` (shell injection) | **no leaks** — held vs escaped `;`, glob, tab/`\r`, fullwidth `；`, line-continuation | — (locked with tests) |
| **Hook `&` separator** (NEW, critical) | `gh pr list & rm -rf ~` rode the `gh pr *` allow rule → auto-allowed `rm` | `discover/lexer.rs`: lone `&` is now a permission segment boundary |
| E-1 redaction | 21 leaks (glued `-p`, `-u user:pass`, `MYSQL_PWD`/`DB_PASS`/`PASSPHRASE`, `X-Api-Key`/`Cookie`/`PRIVATE-TOKEN`, `Authorization: ApiKey/Digest`, JSON bodies, empty-user URL) | `tracking.rs`: added short-flag/header/JSON/env/empty-user patterns |
| G-1 strip_ansi | survivors: unterminated OSC, ESC-in-URL, DCS/APC/PM/SOS, 8-bit C1 OSC | `utils.rs`: regex now covers string escapes + C1 + unterminated |

Accepted residuals (documented in RED_BLUE.md): name-less secrets (`STRIPE_SK=`)
can't be caught by a denylist; malformed CSI leaves a mangled (non-clickable)
fragment. Gate after: clippy 0 warnings, `cargo test --all` **2005 passed / 0 failed**.
