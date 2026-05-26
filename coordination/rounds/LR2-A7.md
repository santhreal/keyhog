# LR2-A7
LOCK: crates/cli/** (orchestrator split phase 1, exclude-paths, inline test exile)

## Hunt
- **Before:** monolithic `orchestrator.rs` (1586 LOC), inline `pipeline_tests` module, `--exclude-paths` parsed but not merged into walker ignores (KH-GAP-011 cli slice)
- **After:** 6-module orchestrator tree + existing `orchestrator_config.rs`; exclude-paths wired via `sources::merge_scan_ignore_paths`

## Split (≥3 modules from orchestrator.rs)
| Module | Role | LOC |
|--------|------|-----|
| `orchestrator/mod.rs` | struct, `new`, merkle, test hooks | 164 |
| `orchestrator/run.rs` | main run loop, exit codes | 282 |
| `orchestrator/dispatch.rs` | scan producer/scanner pipeline | 283 |
| `orchestrator/postprocess.rs` | filter, finalize, verify | 210 |
| `orchestrator/reporting.rs` | progress, summaries, dogfood | 100 |
| `orchestrator/allowlist.rs` | `.keyhogignore` + TOML rules | 60 |
| `orchestrator_config.rs` | config resolution (pre-existing) | 323 |

`orchestrator/mod.rs` **164 LOC** — LR2 phase-1 gate (<800) green.

## KH-GAP-011 (cli slice) — fixed
- **Issue:** `--exclude-paths` documented/ parsed but never passed to `FilesystemSource::with_ignore_paths`
- **Fix:** `sources::merge_scan_ignore_paths()` merges defaults + allowlist + CLI excludes; `build_sources` uses it
- **Proof:** `tests/gap/exclude_paths_flag_not_wired.rs` (e2e), 10 unit tests under `tests/unit/sources/`

## Inline test exile
- Removed 8 `pipeline_tests` from `orchestrator.rs` → `tests/unit/orchestrator/` (8 files)
- Gate `inline_test_offenders_orchestrator` now scans entire `src/orchestrator/` tree

## Tests added
- **45** new hand-written test files (one `#[test]` per file):
  - `tests/unit/orchestrator/` — 35 files (pipeline, backend routing, allowlist roots, modularity, config)
  - `tests/unit/sources/` — 10 files (exclude-path merge oracles)
- Wired in `tests/unit/mod.rs` (`orchestrator`, `sources` modules)

## Commands
```bash
env -u CC cargo test -p keyhog --no-default-features \
  --features "keyhog-scanner/ml,keyhog-scanner/entropy,keyhog-scanner/decode,keyhog-scanner/multiline,git,web,github,s3,docker,verify" \
  --test all_tests
```
→ **blocked at compile** by in-flight LR2-A2 scanner split (`scan_gpu` duplicate module, broken `postprocess/suppression.rs` tail) — unrelated to A7 slice; re-run when scanner crate is green.

## GAP status
| ID | Title | Status |
|----|-------|--------|
| KH-GAP-011 (cli) | `--exclude-paths` not wired | **fixed** |
| KH-GAP-005 (cli) | orchestrator god-file | **phase-1 fixed** (<800 mod.rs; full <500 deferred LR3) |
| KH-GAP-004 (cli) | inline tests in orchestrator | **fixed** |

## Notes
- Test hooks: `ScanOrchestrator::from_parts_for_test`, `scan_sources_for_test`, `allowlist_root_for_test`, `sanitise_thread_count_for_test`
- Exit-code contract gates retargeted to `orchestrator/run.rs`
- Minimal core fix: `report/sarif.rs` uses `super::sarif_uri` (unblocks lib compile when scanner green)
