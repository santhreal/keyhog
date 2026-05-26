# LR2-A3

LOCK: `crates/scanner/src/pipeline/**`, `crates/scanner/tests/unit/a3_*`, `crates/scanner/tests/adversarial/a3_decode/**`, `crates/scanner/tests/gap/{no_inline_tests_in_a3_slice,pipeline_exceeds_modularity_cap,pipeline_hot_path_allocs,decode_pipeline_exceeds_modularity_cap,single_line_implicit_concat_not_appended}.rs`, `crates/scanner/tests/all_tests.rs`

## Hunt

- **God file closed (KH-GAP-014):** monolithic `pipeline.rs` **1923 LOC** split into `src/pipeline/` — `context_window.rs`, `scan_loop.rs`, `postprocess/{mod,suppression,shape_gates}.rs`.
- **Inline tests:** zero `#[cfg(test)]` in A3 slice src (`pipeline/`, `decode/`, `multiline/`).
- **Harness:** `a3_all_tests.rs` removed; A3 modules wired through standard `tests/all_tests.rs` → `unit/a3_*`, `adversarial/a3_decode`, `gap/` slice gates.

## Split (phase 1)

| Module | LOC |
|--------|-----|
| `pipeline/mod.rs` | 15 |
| `pipeline/context_window.rs` | 165 |
| `pipeline/scan_loop.rs` | 143 |
| `pipeline/postprocess/mod.rs` | 78 |
| `pipeline/postprocess/suppression.rs` | 691 |
| `pipeline/postprocess/shape_gates.rs` | 307 |
| **Total** | **1399** |

**Before:** `src/pipeline.rs` = **1923 LOC**  
**After:** `src/pipeline/**` = **1399 LOC** (−524; largest file 691 < 800 phase-1 cap)

## Tests added

- count: **43** new hand tests (`tests/unit/a3_pipeline/*.rs`, one `#[test]` per file)
- cumulative A3 pipeline unit files: **59** (16 LR1 + 43 LR2)
- cumulative A3 slice (decode + multiline + adversarial + gap): **107** test files

Categories:
- postprocess / suppression gates (22)
- context_window / line lookup (8)
- scan_loop / hex context / entropy (6)
- split structural oracles (3)
- harness integration (2)
- LR1 carry-over (16 pipeline unit + 47 decode/multiline/adversarial/gap)

## Commands

```bash
env -u CC cargo test -p keyhog-scanner --test all_tests \
  --no-default-features --features "decode,multiline" \
  unit::a3_pipeline gap::pipeline_exceeds_modularity_cap \
  gap::pipeline_hot_path_allocs gap::no_inline_tests_in_a3_slice
```

## GAP status

- **KH-GAP-014** — `pipeline.rs` god file → **closed** (split + gate tests green)
- KH-GAP-011 — A3 inline tests → **closed** (`no_inline_tests_in_a3_slice` scans `src/pipeline/`)
- KH-GAP-012 — `decode/pipeline.rs` modularity → open (decode slice)
- KH-GAP-013 — Python implicit concat append → open (multiline slice)
