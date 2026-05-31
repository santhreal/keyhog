# Changelog

## Unreleased

- Align Vyre usage docs with the workspace-pinned crates.io `vyre` 0.6.1 release and add a scanner gap test that fails on stale Vyre pin/documentation claims.
- Fix stale `RawMatch` scanner test fixtures to use the production `[u8; 32]` credential hash contract.
- Split structured parser implementations by format family and move remaining parser inline tests into the external scanner test harness.

## 0.2.1

- Align package metadata with the Santh Standard.
- Keep scanner compilation, scan execution, entropy, decode, and context scoring APIs available for the 0.2 line.
