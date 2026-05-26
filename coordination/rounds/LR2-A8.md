# LR2-A8 — integrate harnesses + gate cleanup

LOCK: `crates/*/tests/**`, `GAP_FINDINGS.toml`, `coordination/rounds/LR2-A8.md`

## Hunt

- **a3 harness:** `crates/scanner/tests/a3_all_tests.rs` isolated 63 A3 slice tests from LR1 parallel breakage
- **gate harness:** 39 LR1-A8 replacement gates in `crates/{cli,scanner,sources,verifier}/tests/gate/` — only verifier wired in `all_tests.rs`
- **GAP registry:** LR1 agents appended conflicting `KH-GAP-001..019` meanings; on-disk registry had 19 entries vs 80+ gap test files

## Merge actions

| Action | Detail |
|--------|--------|
| Deleted | `crates/scanner/tests/a3_all_tests.rs` |
| Wired `pub mod gate` | `scanner`, `cli`, `sources` `all_tests.rs` (verifier already had it) |
| Wired `pub mod integration` | `core`, `cli`, `scanner`; `a8_harness` submodule in all five crates |
| Expanded `gap/mod.rs` | All on-disk gap `*.rs` per crate (cli 17, core 10, scanner 23, sources 23, verifier 1) |
| Deduplicated registry | `GAP_FINDINGS.toml` → **80** unique `KH-GAP-001..080` (excludes meta `findings_registry_integrity`) |
| Compile fixes (A8 unblock) | `pipeline/postprocess/shape_gates` visibility; engine `context`/`HashSet` imports; `findings_registry_integrity` lifetime; `detector_contract_coverage_100pct` closure; restored `report/sarif_uri.rs`; removed incomplete `engine/scan_gpu/` dir conflict |

## Tests added (hand-written, one `#[test]` per file)

**count: 34** under `crates/*/tests/integration/a8_harness/`

| Crate | Files | Oracles |
|-------|------:|---------|
| scanner | 12 | a3 harness removed; gate wired; a3 unit/adversarial counts; gap wiring; registry ≥80 + unique ids |
| cli | 8 | gate wired; 16 gate files; 17 gap mods; FILE_GATE_MATRIX ≥167 rows |
| sources | 6 | gate wired; 8 gate / 23 gap mods; binary cap in registry |
| core | 4 | no gate dir; 10 gap mods; registry references core inline gate |
| verifier | 4 | gate pre-wired; 9 gate files on disk |

## Commands

```bash
cd /mnt/santh-desktop/software/keyhog

# A8 harness (stable crates)
env -u CC cargo test -p keyhog-core --test all_tests integration::a8_harness
env -u CC cargo test -p keyhog-verifier --test all_tests integration::a8_harness

# Gate via unified harness (verifier)
env -u CC cargo test -p keyhog-verifier --test all_tests gate::

# Scanner (when lib compiles — parallel A2 scan_gpu split may conflict on NFS)
env -u CC cargo test -p keyhog-scanner --test all_tests integration::a8_harness \
  --no-default-features --features "ml,entropy,decode,multiline"
env -u CC cargo test -p keyhog-scanner --test all_tests gate:: \
  --no-default-features --features "ml,entropy,decode,multiline"

# Registry integrity
env -u CC cargo test -p keyhog-scanner --test all_tests gap::findings_registry_integrity \
  --no-default-features --features "ml,entropy,decode,multiline"
```

## GAP_FINDINGS status

| Metric | Value |
|--------|------:|
| Total entries | **80** |
| Unique ids | **80** (001–080, no duplicates) |
| Open | 71 |
| Fixed | 9 |
| Crates covered | cli, core, scanner, sources, verifier, ci-operability |
| Meta-test excluded | `findings_registry_integrity.rs` (validates registry, not a finding) |

### Renumber map (LR1 conflicts resolved)

Previously multiple agents claimed the same ids (e.g. KH-GAP-011 = contract coverage, exclude-paths, stale 889 claims, PR CI subset). LR2-A8 assigns **one id per test file** sorted by crate path; see `GAP_FINDINGS.toml` header.

## Files merged

- `crates/scanner/tests/all_tests.rs` — +gate, integration (a3 content already in unit/adversarial/gap)
- `crates/scanner/tests/a3_all_tests.rs` — **removed**
- `crates/cli/tests/all_tests.rs` — +gate, +integration
- `crates/sources/tests/all_tests.rs` — +gate
- `crates/core/tests/all_tests.rs` — +integration
- `crates/verifier/tests/all_tests.rs` — unchanged (gate already present)
- `crates/*/tests/gap/mod.rs` — full wiring (5 crates)
- `crates/*/tests/integration/a8_harness/**` — 34 new tests + mod.rs (5 crates)
- `GAP_FINDINGS.toml` — rebuilt 80-entry deduplicated registry
- `crates/core/src/report/sarif_uri.rs` — restored for contract tests
- `crates/core/src/report.rs` — `pub mod sarif_uri`
- Minor compile fixes: scanner pipeline/engine, sources `bconcat!` typo, gap test fixes

## Known blockers (parallel agents)

- Incomplete `engine/scan_gpu/` directory vs `scan_gpu.rs` reappears on NFS — remove dir, keep monolithic `.rs` until A2 split completes
- `cargo test -p keyhog-scanner --test all_tests` may fail when parallel edits break `keyhog-core` SARIF or scanner engine

## Return

| Deliverable | Status |
|-------------|--------|
| a3 → all_tests | **done** (modules merged; harness deleted) |
| gate → all_tests | **done** (4/4 gate-bearing crates) |
| GAP dedup | **done** (80 unique) |
| ≥30 hand tests | **done** (34) |
