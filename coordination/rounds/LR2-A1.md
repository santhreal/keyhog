# LR2-A1

LOCK: `crates/core/src/**`, `crates/core/tests/**`

## Hunt

- Scanned remaining 17 `#[cfg(test)]` modules in `crates/core/src/**` (LR1 left these after partial exile)
- Plus `finding.rs` `hostile_metadata_tests` module (18th offender discovered at gate red)
- God files over 500 LOC: `merkle_index.rs`, `spec/validate.rs`, `report/sarif.rs`, `allowlist.rs`

## Fix

- Migrated **all** inline `#[cfg(test)]` blocks from core `src/**` → `tests/unit/` (one `#[test]` per file)
- Split modules:
  - `merkle_spec_hash.rs` ← `compute_spec_hash` + hex helpers from `merkle_index.rs`
  - `spec/validate_regex.rs` ← regex complexity / ReDoS validation
  - `report/sarif_uri.rs`, `report/sarif_taxonomies.rs` ← URI + taxonomy helpers from `sarif.rs`
  - `allowlist_metadata.rs` ← inline metadata parsing helpers
- Removed duplicate lint preamble block from `lib.rs` (KH-GAP-018 core slice)
- Added `Calibration::test_seed_counters` hook for external saturation oracle

## Migration status (18 modules)

| Module | Inline tests removed |
|--------|---------------------|
| `source.rs` | yes |
| `registry.rs` | yes |
| `auto_fix.rs` | yes |
| `safe_bin.rs` | yes |
| `hardening.rs` | yes |
| `calibration.rs` | yes |
| `credential.rs` | yes |
| `report.rs` | yes |
| `rule_filter.rs` | yes |
| `merkle_index.rs` | yes |
| `spec/load.rs` | yes |
| `spec/validate.rs` | yes |
| `report/banner.rs` | yes |
| `report/json.rs` | yes |
| `report/text.rs` | yes |
| `report/sarif.rs` | yes |
| `finding.rs` | yes (`hostile_metadata_tests`) |
| *(LR1 already done: config, dedup, allowlist partial, banner, spec, encoding)* | — |

## Tests added

- **count: 91** new hand-written one-test files in `tests/unit/` (this round)
- Cumulative LR2-A1 unit files wired in `tests/unit/mod.rs`
- Includes 4 hostile-metadata finding oracles, 7 credential/json splits, 11 merkle cache oracles, 4 OOB validation oracles, 11 rule-filter oracles, etc.

## GAP

- **KH-GAP-004 (core slice): CLOSED** — `gap::no_inline_tests_in_src` green; zero `#[cfg(test)]` in `crates/core/src/**`
- Scanner-wide KH-GAP-004 entry remains open (other crates)

## Commands

```bash
cd /mnt/santh-desktop/software/keyhog
env -u CC cargo test -p keyhog-core --test all_tests
```

→ **273 passed; 0 failed; 0 ignored**
