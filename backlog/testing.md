# Testing backlog

Goal: test the ACTUAL TOOL and its integrations (whole-path, real binary). Keep
this STRICTLY separate from the bench. Detection accuracy (precision/recall/F1)
is measured ONLY by `tools/secretbench` — never asserted in `cargo test`. And
the bench must never carry test-framework logic.

## Inventory (2026-05-30)
- ~2,629 test files, ~14,988 `#[test]` fns. scanner alone: **1,234 files / 12,840 tests**. core 466, sources 548, verifier 306, cli 828.
- Bench dir (`tools/secretbench`): ZERO `#[test]`/cargo-test cruft → that direction is clean, no fix needed.

## Separation violations (bench logic living in `cargo test`)
- **T-01 · high · scanner/tests** — detection-ACCURACY runners live in the unit/integration suite: `cve_corpus_runner.rs`, `multi_secret_runner.rs`, `path_shape_runner.rs`, `unicode_confusable_runner.rs`, `*_recall_*.rs`, `readme_claims.rs`. Aggregate accuracy belongs in the bench. KEEP per-rule positive/negative CONTRACT tests (they assert tool BEHAVIOR on a known input — legit) but MOVE any test that computes/asserts a recall/precision/F1 *rate* over a corpus into the scorer. Triage each: behavior-assert (keep) vs accuracy-rate (move to bench).

## Decoration / hand-rolled
- **T-02 · med · 46× `assert!(!findings.is_empty())`** — shape asserts that pass if the function returned a single junk finding. Replace with truth asserts (exact rule + file + line + count + exit code).
- **T-03 · med · 81 unique hand-rolled `AKIA…/ghp_…/sk_…` fixtures in tests** — where the secret is the POINT (a detection-accuracy claim), move to the bench corpus. Where it's INPUT to a tool-behavior test (parsing, decode, reassembly), keep it but make the assertion about behavior, not "we detected a secret."

## Test-effectiveness gaps
- **T-04 · high · scanner/tests/all_detectors_self_validate.rs** — `every_detector_loads` asserts loaded-count == file-count (the RIGHT gate), but the dead `discord-bot-token` (TOML parse error, DET-01) still reached the rebuilt+benched binary. The gate is not enforced on the working tree / pre-push. Make detector-load-integrity a pre-push + release blocker that runs against the actual embedded set, not just on-disk TOMLs. → MC-16.
- **T-05 · med · embedded vs on-disk parse divergence** — the test parses TOMLs from disk via `toml::from_str`; the binary embeds them at build time. Assert the EMBEDDED set count == on-disk count so an embed-time drop can't pass.

## Real tests to ADD (tool + integration, NOT detection)
- Every subcommand × default + ≥3 flag combos: snapshot stdout/stderr/exit.
- Every output format (text/json/jsonl/sarif/csv/junit/html) byte-compared to a committed fixture (well-formed is not enough).
- Exit-code contract asserted per entry path: 0 clean / 1 findings / 2 runtime error / 3 file error (DF-04 — and document it).
- `daemon`/`watch` via the real socket; `tui` via vt100 render; `hook` install+run; `--git-staged/--git-diff/--git-history` on a real repo; `--incremental` cache round-trip; baseline create/update/diff round-trip.
- GitHub Action, SARIF upload, pre-commit hook: end-to-end against a recorded backend.
- CLI flag-surface snapshot per subcommand so the 68-flag surface can't grow silently (CLI-08).

## Organize / dedup
- **T-06 · med** — 1,234 scanner test files is itself a maintenance/bloat surface. Consolidate byte-identical helpers (the audit found dup `detector_dir` helpers already deduped once) and per-detector micro-files into table-driven suites where it doesn't lose per-rule failure attribution.
