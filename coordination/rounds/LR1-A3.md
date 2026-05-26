# LR1-A3

LOCK: crates/scanner/src/pipeline.rs, crates/scanner/src/decode/**, crates/scanner/src/multiline/**, crates/scanner/tests/unit/a3_*, crates/scanner/tests/adversarial/a3_decode/**, crates/scanner/tests/gap/{no_inline_tests_in_a3_slice,decode_pipeline_exceeds_modularity_cap,pipeline_hot_path_allocs,single_line_implicit_concat_not_appended}.rs, crates/scanner/tests/a3_all_tests.rs

## Hunt

- finding count: **4** (KH-GAP-011..014)
- **God file:** `pipeline.rs` = **1923 LOC** (cap 500) — suppression helpers, companion search, hex-context, placeholder gates, and scan-loop glue in one file; hot-path `String`/`Vec` allocations throughout.
- **Decode splice:** `push_decoded_text_chunk_spliced` in `decode/pipeline.rs` is the recall lever — base64, hex, json, url, html, mime, reverse use splice; **caesar** and **unicode-escape** intentionally use legacy bare-chunk push (caesar: 25-shift explosion; unicode-escape: full-line candidate accidentally preserves context).
- **Phantom append:** Fixed in `multiline/preprocessor.rs` via `any_real_join` gate (#16) — single-line trailing `\n` no longer duplicates into `final_text`. Remaining gap: **single-line Python implicit concat** joins locally but never appends (same `any_real_join` gate).
- **Inline src tests (A3 slice):** 6 files — `pipeline.rs`, `decode/{hex,caesar,reverse,util}.rs`, `multiline/fragment_cache.rs`.

## Tests added

- count: **63** (one `#[test]` per file)
  - `tests/unit/a3_decode/` — 25 unit (base64/hex/z85/decode_chunk splice/dedup/budget)
  - `tests/unit/a3_pipeline/` — 16 unit (line offsets, entropy, hex context, companions)
  - `tests/unit/a3_multiline/` — 13 unit (phantom append, passthrough, concat flags, structural)
  - `tests/adversarial/a3_decode/` — 5 adversarial (decode bomb, malformed input, phantom dedup)
  - `tests/gap/` — 4 new bar-miss gates (+ pre-existing `pipeline_exceeds_modularity_cap`)
- harness: `tests/a3_all_tests.rs` (isolated from broken parallel-agent modules in `all_tests`)

## Commands

```bash
env -u CC cargo test -p keyhog-scanner --test a3_all_tests \
  --no-default-features --features "decode,multiline"
# → 60 passed; 5 failed (expected bar-miss gap gates)
```

Note: `cargo test --test all_tests` currently blocked by syntax errors in parallel A4 context test files outside this slice.

## GAP_FINDINGS appended

- KH-GAP-011 — A3 slice inline `#[cfg(test)]` in src (6 files)
- KH-GAP-012 — `decode/pipeline.rs` 463 LOC > 400 cap
- KH-GAP-013 — single-line Python implicit concat not appended to preprocessed text
- KH-GAP-014 — `pipeline.rs` 1923 LOC god file (extends KH-GAP-005)
