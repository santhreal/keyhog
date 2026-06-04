# Changelog

## Unreleased

- Fix windowed-scan line attribution: findings in files past the 1 MiB
  windowing threshold (`filesystem/windowed`) reported the per-window line
  instead of the absolute file line, so a secret on line 584307 of a 70 MiB
  file was reported at line ~2 (and reported lines were non-monotonic). Added
  `ChunkMetadata::base_line` (the line analog of `base_offset`), populated
  per-window by the filesystem source (mmap + buffered paths) and the
  cross-window boundary reassembler, and added it at every line emit site
  (primary, entropy fallback, generic-secret, multiline reassembly, decode
  pipeline, and the simdsieve hot path). Byte offsets were already absolute;
  this brings line numbers to parity. Regressioned by
  `cli/tests/regression/windowed_line_numbers.rs`.
- Remove the orphaned `pipeline/postprocess/raw_match.rs` — a never-compiled
  stale duplicate of `build_raw_match` (no `mod`/`#[path]` referenced it),
  superseded by the `pattern_client_safe`-aware constructor in
  `pipeline/postprocess/mod.rs`.
- Align Vyre usage docs with the workspace-pinned crates.io `vyre` 0.6.1 release and add a scanner gap test that fails on stale Vyre pin/documentation claims.
- Fix stale `RawMatch` scanner test fixtures to use the production `[u8; 32]` credential hash contract.
- Split structured parser implementations by format family and move remaining parser inline tests into the external scanner test harness.
- Add a GPU phase2 empty-hit fast path matching SIMD coalesced no-hit fallback admission, with a regression gate for the skip-before-prepare contract.
- Keep high-entropy base64-like secrets with internal `+`/`/` punctuation through generic and entropy fallbacks by bypassing binary-decoy suppression on the punctuation payload class, closing `encoded_binary`-driven false negatives.
- Add adversarial coverage for the base64 punctuated high-entropy class and a fixed-token regression for `TVo...+...` shape that previously dropped at `is_encoded_binary`.

## 0.2.1

- Align package metadata with the Santh Standard.
- Keep scanner compilation, scan execution, entropy, decode, and context scoring APIs available for the 0.2 line.
