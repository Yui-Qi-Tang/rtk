# RED_BLUE.md — red/blue adversarial testing playbook for rtk

Reusable recipe for red-team (find bypasses) / blue-team (fix + lock with tests)
passes against rtk's security-relevant code paths. Built for the
`feature/remove_security_issue` hardened fork.

## Core rule

> A subagent's *opinion* ("I think this bypasses it") is worthless.
> Only **executed, observed behavior** counts. Every payload must be run against
> the real binary / real function, and every confirmed gap must become a
> committed `#[cfg(test)]` (or bash) regression test before we call it fixed.

## Method (4 steps)

1. **Red (generate):** spawn one white-box subagent per attack surface. Give it
   the *actual* current code so it targets real logic, not guesses. Ask only for
   a payload corpus + observed results — not conclusions.
2. **Execute (ground truth):** run every payload against the real target
   (`target/debug/rtk …`, a temporary `#[test]`, or the bash hook with crafted
   JSON). Record what actually happened.
3. **Blue (fix):** for each confirmed leak, fix the code and bake the payload
   into a permanent regression test.
4. **Re-run:** `cargo fmt --all && cargo clippy --all-targets && cargo test --all`
   until clean. Then commit.

## Surfaces & how to drive them

| Surface | Target | How to execute a payload |
|---------|--------|--------------------------|
| Shell injection | `core::utils::build_exec_command` (used by `rtk err/test/summary`) | `target/debug/rtk test "<payload>"` — observe refused vs ran; probe side effects in `/tmp` |
| Secret redaction | `core::tracking::redact_sensitive_args` (not on CLI) | temp `#[test]` calling the fn, `cargo test redact -- --nocapture`, then `git checkout` the file |
| ANSI/escape strip | `core::utils::strip_ansi` (not on CLI) | temp `#[test]` calling the fn with a unique URL marker; revert after |
| Hook auto-allow | `hooks/claude/rtk-rewrite.sh` + permission/lexer | `echo '{"tool_input":{"command":"<P>"}}' \| PATH="$PWD/target/debug:$PATH" bash hooks/claude/rtk-rewrite.sh` (rm `~/.cache/rtk-hook-version-ok` first) |

Build first: `source "$HOME/.cargo/env" && cargo build`. (Ignore the
`GVM_ROOT not set` stderr line — it's unrelated shell-init noise.)

## Red-team subagent prompts (verbatim — reuse these)

Spawn these in parallel (general-purpose agent). Each is white-box: paste the
**current** code into the prompt before running so the attacker sees the logic.

### 1) Shell injection (`build_exec_command`)
> White-box RED TEAM against rtk's anti-shell-injection fix. DO NOT edit source.
> [paste `contains_shell_metacharacters` + `build_exec_command`]. Goal: a string
> via `rtk err/test/summary` must never cause shell interpretation (chaining,
> subshell, redirection, eval) — run directly or be refused. Find payloads that
> are NOT refused AND produce shell-style behavior. Think: metachars not in the
> denylist, lowercase inline env, tab/`\r`, `~`, `!`, backslash line-continuation,
> non-ASCII lookalikes, leading `-` flags, argv0 tricks. METHOD: actually run
> `target/debug/rtk test "$P"` and side-effect probes in /tmp; record OBSERVED
> result. Return payloads with LEAKS flagged at top; if none, say so.

### 2) Secret redaction (`redact_sensitive_args`)
> White-box RED TEAM against rtk's command-arg secret redaction. [paste the
> regexes]. Goal: any secret must become `***` before storage. Find command
> strings where a real secret SURVIVES. Think: short flags (`-p`/`-W`/`-u`),
> `MYSQL_PWD=`/`PGPASSWORD=`, query-param tokens, non-`Authorization` headers
> (`X-Api-Key`, `Cookie`, `PRIVATE-TOKEN`), auth schemes beyond bearer/basic,
> JSON bodies, `-e KEY=val`, empty-user URLs. METHOD: append a throwaway `#[test]`
> to `src/core/tracking.rs`, `cargo test redact`, then `git checkout` to revert
> (confirm `git status` clean). Return LEAKS at top; be exhaustive on short-flag
> and env-var-name variants.

### 3) ANSI/escape strip (`strip_ansi`)
> White-box RED TEAM against `strip_ansi`. [paste regex]. Goal: escape sequences
> that embed a URL/payload (esp. OSC 8 hyperlinks) must be stripped. Find
> sequences carrying a URL that SURVIVE. Think: DCS/APC/PM/SOS, 8-bit C1
> (`\x9b`/`\x9d`), unterminated OSC, embedded ESC, incomplete CSI, OSC 8 with
> `id=`. METHOD: temp `#[test]` calling `strip_ansi` with marker
> `http://EXFIL.example/PAYLOAD`; revert after. Return SURVIVED at top; mark each
> realistic vs theoretical (does a real terminal render it / is the URL hidden?).

### 4) Hook auto-allow (`rtk-rewrite.sh`)
> White-box RED TEAM against the Claude Code hook. [describe exit-code protocol +
> `--` guard + multiline guard]. Goal: a command must never come back as
> `permissionDecision:"allow"` with attacker text or by riding an allow rule.
> Find a `command` value that gets auto-allowed unsafely. Think: leading `-`/`--`,
> rtk-rewrite's own flags, `-- --help`, embedded newline, env prefix, compound
> separators (`&&`, `;`, `|`, **`&`**), commands rewriting to `rtk test`/`proxy`.
> METHOD: `echo '{"tool_input":{"command":"<P>"}}' | PATH=... bash
> hooks/claude/rtk-rewrite.sh`; observe emitted JSON for `"allow"`. LEAKS at top.

## Blue-team: rerun the locked-in regression tests

```bash
source "$HOME/.cargo/env"
cargo test --bin rtk redact          # E-1 secret redaction corpus
cargo test --bin rtk strip_ansi      # G-1 escape-strip survivors
cargo test --bin rtk build_exec      # B-1 injection refusal
cargo test --bin rtk split_on_operators background   # & segmentation
cargo test --bin rtk compound_allow  # permission compound-separator
# full gate:
cargo fmt --all && cargo clippy --all-targets && cargo test --all
# hook (needs built binary):
rm -f ~/.cache/rtk-hook-version-ok
echo '{"tool_input":{"command":"gh pr list & rm -rf ~"}}' | \
  PATH="$PWD/target/debug:$PATH" bash hooks/claude/rtk-rewrite.sh   # must NOT be "allow"
```

## Findings from the 2026-05-30 run

**Surfaces tested:** B-1 shell injection, E-1 redaction, G-1 strip_ansi, hook.

| Surface | Result | Action |
|---------|--------|--------|
| B-1 `build_exec_command` | **No leaks.** Deny-on-raw-then-argv-exec held vs backslash-escaped `;`, glob `[]`, tab/`\r`, fullwidth `；`, line-continuation, `~`, `!`. | locked with `test_build_exec_command_*` |
| **Hook `&` separator** | **CRITICAL leak**: `gh pr list & rm -rf ~` stayed one segment, matched the `gh pr *` allow rule → auto-allowed → `rm` runs. `split_on_operators` didn't treat lone `&` as a boundary (cf. #1213). | **fixed** `discover/lexer.rs`; tests `test_split_on_operators_background_amp`, `test_compound_allow_background_amp_separator` |
| E-1 redaction | **21 leaks**: glued short `-phunter2`, `-u user:pass`, `MYSQL_PWD`/`DB_PASS`/`PASSPHRASE`, `X-Api-Key`/`Cookie`/`PRIVATE-TOKEN`, `Authorization: ApiKey/Digest`, JSON `{"password":…}`, `redis://:pass@`. | **fixed** (added short-flag/header/JSON/env/empty-user patterns); `test_redact_sensitive_args_redteam_corpus` |
| G-1 strip_ansi | **survivors**: unterminated OSC, ESC-in-URL OSC 8, DCS/APC/PM/SOS, 8-bit C1 OSC. | **fixed** (regex covers string escapes + C1 + unterminated); `test_strip_ansi_redteam_survivors` |

### Accepted residuals (documented, not fixed)
- **E-1 cannot catch arbitrarily-named secrets** (e.g. `STRIPE_SK=…`, bare `pw=…`) —
  name-based denylist has no signal. Spaced DB `-p <db>` deliberately NOT redacted
  (it's usually the database name, not the password — mysql needs the password
  glued). Mitigated overall by telemetry being off by default (C-1).
- **G-1 malformed CSI** like `\x1b[38;5;http…` consumes one letter and leaves a
  mangled fragment (`ttp://…`). Inherent to lenient CSI matching; not a clean
  clickable link. CSI-wrapped URLs are intentionally kept (visible text, not a
  hidden link → not exfil).

### Net
1 critical + ~21 medium + several low gaps found and fixed; B-1 held. Gate after:
`cargo clippy` 0 warnings, `cargo test --all` **2005 passed / 0 failed**.
