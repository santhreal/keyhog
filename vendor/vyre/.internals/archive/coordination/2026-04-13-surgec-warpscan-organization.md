# surgec + warpscan Organization Assessment

Author: claude-opus-4.6
Date: 2026-04-13

## Should surgec and warpscan merge?

**No.** The boundary is correct:

- **surgec** = compiler + evaluator. Reusable by anything that needs SURGE rules.
- **warpscan** = product scanner. CLI, npm feeds, coordinator, distributed scanning.

Merging would couple the rule compiler to a specific product. surgec should remain
a library crate that warpscan (and future tools) consume.

## Layering violation to fix

warpscan's `rules/pattern_builder.rs` and `npm/patterns.rs` build
`warpstate::PatternSet` directly, bypassing surgec. This means warpscan
has its own pattern compilation path that doesn't go through surgec's
compiler. When warpstate is replaced with vyre ops, both surgec AND
warpscan need updating.

**Fix:** warpscan should ONLY call surgec for pattern compilation.
Delete `rules/pattern_builder.rs` pattern building and route through
`surgec::compile_paths()` instead.

## warpscan files over 500 lines that need splitting

| File | Lines | Split strategy |
|---|---|---|
| pipeline/tests.rs | 2448 | Split by test category (walk, scan, dedup, format) |
| feeds/npm/mod.rs | 1039 | Extract NpmFeed methods into feed.rs, polling into poll.rs |
| pipeline/scan.rs | 846 | Extract prefilter, format detection, extraction into submodules |
| feeds/threat_intel/mod.rs | 790 | Extract STIX parsing, merge logic into subfiles |
| pipeline/walk/tenshift.rs | 748 | Extract batch processing, GPU direct read into helpers |
| rules/tests.rs | 662 | Split by test category |
| rules/loader.rs | 557 | Extract validation, JIT builder, GPU parity into subfiles |
| pipeline/content_dedup.rs | 531 | Extract hash computation, store impl into subfile |

## surgec dead code removed this session

- compiler/bytecode.rs + bytecode_tests.rs (523 lines) — dead bytecode VM
- parser/grammar/{document,predicate,rule}.rs (841 lines) — orphaned refactor
- Error::Warpstate → Error::PatternEngine (naming cleanup)
- warpstate references → pattern_engine across 8 files
- vyre-std phantom dependency removed

## What "legendary" means for these codebases

1. **Every function documented** — ✓ already done
2. **Every module has //! docs** — ✓ already done  
3. **No dead code** — ✓ cleaned this session (1364 lines removed)
4. **No files over 500 lines** — ✗ warpscan has 8 files over 500
5. **ARCHITECTURE.md** — ✓ written for both
6. **warpstate fully removed** — ✗ warpscan still depends on it (45 refs)
7. **Layering violations fixed** — ✗ warpscan builds patterns directly
8. **surgec uses vyre backend trait** — ✗ does raw wgpu dispatch
9. **All tests pass** — ✗ blocked on vyre-core 467 errors
