# LR1-A1

LOCK: crates/core/src/**, crates/core/tests/**

## Hunt

- Scanned 22 `#[cfg(test)]` modules in `crates/core/src/**` (pre-migration)
- Grep: unwrap/expect in prod paths gated by `#![cfg_attr(not(test), deny(...))]` — violations confined to test modules
- Edge cases mapped: dedup cross-detector determinism, SARIF URI encoding, allowlist expiry/metadata, merkle spec-hash invalidation, encoding size cap
- **finding count: 8** (KH-GAP-018..025 appended)

## Review

- KH-GAP-004 remains OPEN (17 inline modules left after partial exile)
- KH-GAP-018 FIXED (duplicate lint preamble removed from `lib.rs`)
- Red tests wired for merkle spec gate, allowlist DoS glob, inline-test gate

## Fix

- Removed duplicate `#![cfg_attr(not(test), deny(...))]` block from `src/lib.rs`
- Migrated inline tests → external one-file tests from **6 modules**: `lib.rs`, `config.rs`, `spec.rs`, `dedup.rs`, `allowlist.rs`, `banner.rs`
- Split `tests/unit/encoding.rs` (multi-test) into four one-test files

## Tests added

- **count: 58** new hand-written files (one `#[test]` per file)
- **unit/**: 40 new (+ 9 pre-existing multi-test modules retained)
- **gap/**: 5 new (9 total one-test files)
- **contract/**: 6 new (8 total)
- **adversarial/**: 7 new (9 total)
- All wired in `tests/{unit,gap,contract,adversarial}/mod.rs` via `all_tests.rs`

## Commands

```bash
cd /mnt/santh-desktop/software/keyhog
env -u CC cargo test -p keyhog-core --test all_tests
```

→ **131 passed; 1 failed; 0 ignored**

Expected failure: `gap::no_inline_tests_in_src` (17 offenders remain — KH-GAP-019 red inventory)

## GAP_FINDINGS appended

- KH-GAP-018 lib.rs duplicate lint preamble (**fixed**)
- KH-GAP-019 17 remaining inline test modules (**open**)
- KH-GAP-020 merkle legacy save vs load_with_spec (**open**)
- KH-GAP-021 SARIF URI helper private (**open**)
- KH-GAP-022 allowlist metadata helpers private (**open**)
- KH-GAP-023 merkle_index inline test bulk (**open**)
- KH-GAP-024 sarif inline test duplication (**open**)
- KH-GAP-025 allowlist oversized glob skip (**open**)

## Migration status

| Module | Inline tests removed |
|--------|---------------------|
| `lib.rs` | yes |
| `config.rs` | yes |
| `spec.rs` | yes |
| `dedup.rs` | yes |
| `allowlist.rs` | yes |
| `banner.rs` | yes |
| `encoding.rs` | already external (split this round) |

Remaining inline: 17 files (R2 exile target)
