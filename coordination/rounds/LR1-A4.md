# LR1-A4

LOCK: crates/scanner/src/context/**, crates/scanner/src/confidence/**, crates/scanner/src/entropy/**, crates/scanner/src/compiler*.rs, crates/scanner/tests/unit/{context_,confidence_,entropy_,compiler_}*.rs, crates/scanner/tests/gap/{context_,confidence_,entropy_,compiler_,*inline*}*.rs, crates/scanner/tests/property/{shannon,normalized,compute_confidence,char_diversity,is_known}*.rs

## Hunt

- finding count: **7** (KH-GAP-011..017)
- Inline `#[cfg(test)]` in A4 slice: **5 files** (false_positive, penalties, keywords, compiler, compiler_prefix)
- Weak oracle hunt: confidence normalizes against **full** `max_possible` (1.0), not active signals — pinned with exact-weight unit tests
- Context hole: `#[tokio::test]` + `async fn integration()` body → **Assignment** not **TestCode** (KH-GAP-016)
- Entropy policy holes: `secrets.rs` excluded, `secrets.yaml` included, `Cargo.toml` excluded — pinned
- Compiler holes: empty GPU literal disables GPU set; fallback keywords `<4` chars skipped — pinned
- Float micro-flaw: `normalized_entropy` can return `1.0 + ε` (KH-GAP-017)

## Tests added

- count: **72** (one `#[test]` per file)
  - `tests/unit/`: **56** — context (23), confidence (12), entropy (10), compiler (11)
  - `tests/gap/`: **9** — inline-test exile (5), tokio context (1), keyword-only entropy (1), sequential placeholder (1), calibration passthrough (1)
  - `tests/property/`: **5** — entropy bounds, confidence interval, char_diversity, is_known_example panic-free

## Commands

```bash
env -u CC cargo test -p keyhog-scanner --test all_tests \
  --no-default-features --features "entropy,decode,ml,multiline" --no-run
# → compile ok

# A4 slice only (72 tests):
# pass 65 | fail 7 (expected red gap tests)
```

Per-test run summary: **65 passed**, **7 failed** (all registered gap bar-misses: inline-test exile ×5, global no_inline_tests_in_src, A3 no_inline_tests_in_a3_slice picked up by filter).

Unit + property + green gap tests: **65/65 pass**.

## GAP_FINDINGS appended

- KH-GAP-011 context/false_positive inline tests
- KH-GAP-012 confidence/penalties inline tests
- KH-GAP-013 entropy/keywords inline tests
- KH-GAP-014 compiler inline tests
- KH-GAP-015 compiler_prefix inline tests
- KH-GAP-016 tokio async test body misclassified
- KH-GAP-017 normalized_entropy float overshoot
