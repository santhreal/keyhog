# Dogfood findings (real tool)

Issues found by running the freshly-built release binary across its surfaces.
NOT detection accuracy (that is the SecretBench scorer's job).

## Confirmed robust (2026-05-30, v0.5.37 rebuild)
- All 7 output formats (`text json jsonl sarif csv junit html`) on a planted-secret dir: valid output, correct exit codes, NO panics. JSON/JSONL parse; SARIF has version+runs; HTML has DOCTYPE; CSV has header.
- Edge cases NO panic: nonexistent path (exit 2, correct), empty dir (exit 0), `--stdin`, 2MB binary file.
- Subcommands clean: `detectors` (44KB), `backend`, `doctor`, `completion bash` (41KB), `explain <valid-id>` (exit 0 with suggestions).
- **DoS robustness GOOD**: 20MB single line w/ no newline (exit 0, <20s), 12-deep base64 nesting (exit 0), symlink loop A↔B (exit 1, no hang). No timeouts, no panics, no OOM.
- baseline/diff/incremental round-trips: `--create-baseline` writes, `--baseline` rescan baselines correctly (exit 0), `--incremental-cache` written, `diff` identical→0. Exit-code contract 0=clean / 1=findings / 2=error holds for `scan`.

## Issues
- **DF-01 · med · detectors** — `detectors --format json` fails (exit 2); the flag is `--json`. Convention mismatch with `scan --format`. → CLI-01.
- **DF-02 · low · explain + FP_AUDIT** — `explain aws-access-key-id` → exit 2 "no detector with id". The audit/doc id has drifted from the registry. → MC-10. (explain itself is fine: it returns a helpful "Did you mean:" suggestion list.)
- **DF-03 · med · sources/git (--git-staged outside a repo)** — running `scan --git-staged` (or other `--git-*`) outside a git repository leaks a raw git error to the user: `git diff failed: error: unknown option 'cached'` with `git diff --no-index` usage, exit 2. It should detect "not a git repository" and emit a clean, actionable message. Works correctly *inside* a repo (exit 0). Likely the no-repo fallback routes `--cached` into a `git diff --no-index` invocation.
- **DF-04 · low · diff / exit-code contract** — `diff` uses exit codes 2 (unreadable/garbage baseline) and 3 (missing baseline file); `scan` uses 0/1/2. The full contract spans 0/1/2/3 but is documented NOWHERE (`--help` has no exit-code section). Document the contract and add an exit-code assertion test per entry path. → CLI-08.
- **DF-07 · HIGH · detectors/discord-bot-token.toml:34** — the detector is DEAD: `keyhog detectors` loads 890 of 891 TOMLs. discord-bot-token.toml fails to parse (`TOML parse error at line 34, column 35`): the regex is a single-quoted TOML literal `'...'` whose char class `[A-Za-z0-9_."'' :=-]` embeds both `'` and `"` — a literal string cannot contain `'`, so `''` ends the string. Discord bot tokens are currently UNDETECTABLE (recall hole). Introduced by cc817964. Fix: use a triple-quoted TOML literal `'''...'''` (allows single quotes) or escape via a basic string. → MC-16 (this should have been a release blocker, not a silent stderr warning).

## Still to dogfood (keep loading)
- Every output format BYTE-compared to a committed fixture (not just well-formed) — feeds the test-expansion vector.
- `diff` two baselines; `calibrate`; `hook` install/run; `baseline`/`--create-baseline`/`--update-baseline` round-trip.
- `--git-diff` / `--git-staged` / `--git-history` on a real repo; `--incremental` cache round-trip.
- `watch`/`daemon` real socket lifecycle; `tui` render via vt100.
- Malformed inputs: truncated archives, deep base64 nesting, giant single line (DoS), symlink loops, no-read-permission files, UTF-8/binary boundary.
- Exit-code contract: assert 0=clean / 1=findings / 2=runtime error across every entry path.
