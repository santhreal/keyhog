# LR1-A7
LOCK: crates/cli/**

## Hunt
- finding count: 6 (orchestrator 1586 LOC, args.rs 778 LOC, scan_system.rs 520 LOC, 5 inline-test src files, exclude-paths unwired, exit-code taxonomy verified fixed)
- inline `#[cfg(test)]` in src/: orchestrator.rs, orchestrator_config.rs, detectors.rs, test_fixture_suppressions.rs, value_parsers.rs
- e2e coverage map: contract CLI surface thin (3 files pre-LR1); e2e_binary.rs monolith (13 tests); daemon path unix-only; no contract gates for env vars / subcommand help matrix

## Tests added
- count: **80** hand-written test files (one `#[test]` per file) in:
  - `crates/cli/tests/contract/` — 41 files (CLI `--help`, env, exit codes, subcommand surface)
  - `crates/cli/tests/gap/` — 16 files (orchestrator modularity, inline-test gate, exit-code source gates, exclude-paths bar-miss)
  - `crates/cli/tests/e2e/` — 23 files (binary-driven scan/detectors/explain/diff/calibrate/backend/daemon)
- wired in `tests/contract/mod.rs`, `tests/gap/mod.rs`, `tests/e2e/mod.rs`, `tests/all_tests.rs`
- shared e2e helpers: `tests/e2e/support.rs`

## Commands
```bash
env -u CC cargo test -p keyhog --no-default-features \
  --features "keyhog-scanner/ml,keyhog-scanner/entropy,keyhog-scanner/decode,keyhog-scanner/multiline,git,web,github,s3,docker,verify" \
  --test all_tests
```
→ **155 passed; 8 failed; 0 ignored** (all 8 failures are intentional gap/bar-miss gates)

Contract + e2e slice: **155/155 pass**

Gap gates (expected fail until refactor):
- `orchestrator_rs_under_500_lines` (1586 LOC)
- `args_rs_exceeds_modularity_cap` (778 LOC)
- `scan_system_rs_exceeds_modularity_cap` (520 LOC)
- `no_inline_tests_in_src` (5 offenders)
- `inline_test_offenders_*` (3 per-file gates)
- `exclude_paths_flag_not_wired` (KH-GAP-011)

## GAP_FINDINGS appended
- KH-GAP-006 exit code taxonomy — status fixed (verified by contract/gap source gates)
- KH-GAP-011 CLI `--exclude-paths` not wired
- KH-GAP-012 args.rs modularity cap
- KH-GAP-013 scan_system.rs modularity cap
- KH-GAP-014 inline src/ tests (cli slice of KH-GAP-004)
- KH-GAP-005 orchestrator.rs (existing registry entry; gate in `orchestrator_modularity_cap.rs`)

## Notes
- Fixed pre-existing compile errors in `tests/gate/` (A8 slice) blocking `all_tests` build: `Shell` import, `patterns` field name, `DaemonAction::Status { .. }` match, removed `Debug` formatting on `Command`.
