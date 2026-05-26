# LR1-A8

LOCK: crates/*/tests/**, tests/FILE_GATE_MATRIX.toml, audits/LR1-weak-tests.md

## Hunt

- finding count: 47 weak tests in `file_gate.rs` + 1 in `http.rs`; 0 `#[ignore]`; 47 runtime SKIP call sites inventoried (not deleted)
- patterns: `assert!(is_ok)` (24), tautologies (8), mislabeled error (6), no-op (6), duplicate twins (3)

## Fixes

| Action | Count |
|--------|-------|
| Weak tests deleted | 47 |
| Weak tests hardened in place | 2 (`http.rs`, `decode_unicode_escape_error`) |
| Replacement gate files added | 39 |
| `FILE_GATE_MATRIX.toml` rows | 167/167 (header audit note) |

### Replacement directories

- `crates/cli/tests/gate/` — 16 files
- `crates/verifier/tests/gate/` — 9 files
- `crates/sources/tests/gate/` — 8 files
- `crates/scanner/tests/gate/` — 6 files

Wired via `gate/mod.rs` + `all_tests.rs` in each crate.

## Commands

```bash
env -u CC cargo test -p keyhog --test all_tests gate --no-default-features --features portable
# → 61 passed (includes file_gate + gate)

env -u CC cargo test -p keyhog-sources --test all_tests gate::
# → 25 passed

env -u CC cargo test -p keyhog-scanner --test all_tests 'gate::' --no-default-features --features "ml,entropy,decode,multiline"
# → 6 gate tests (scanner tree has concurrent compile issues in other agents' slices)

env -u CC cargo test -p keyhog-verifier --test all_tests gate::
# → blocked by pre-existing compile error in rate_limit_typical_intervals.rs (private method)
```

## GAP_FINDINGS appended

- KH-GAP-008 — weak file_gate tests purged (A8)

## Artifacts

- `audits/LR1-weak-tests.md` — full inventory
- `tests/FILE_GATE_MATRIX.toml` — 167 module rows, LR1-A8 header
