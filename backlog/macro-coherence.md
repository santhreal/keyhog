# Macro coherence backlog

Architecture-level coherence: where the project has multiple sources of truth,
divergent conventions, or structural drift. These are the "shape of the whole"
issues, distinct from per-site micro fixes.

## Configuration

- **MC-01 · high · core/src/config.rs, scanner/src/scanner_config.rs, cli/src/config.rs + orchestrator_config.rs** — Detection config is a 3-way triad (`ScanConfig` owned truth, `ScannerConfig` near-duplicate, cli `ConfigFile`) joined by a lossy `From` (renames `decode_size_limit`→`max_decode_bytes`, invents `validate_decode=true`, drops `min_secret_len`/`max_file_size`/`dedup`). Collapse to ONE `ScanConfig`; make `ScannerConfig` a thin newtype/alias. (audit W1)
- **MC-02 · high · cli/src/orchestrator_config.rs** — `build_scanner_config` early-returns on `--fast`/`--deep`, silently dropping `--min-confidence`/keyword overrides that follow. Preset must be a BASE, then continue into per-flag overrides. (audit W3)
- **MC-03 · med · 4 divergent `min_confidence` defaults** — `ScanConfig::default`=0.5, cli post-scan floor `unwrap_or(0.3)` gated on `!no_ml`, `ScannerConfig::sanitise` NaN-fallback, `.keyhog.toml.example` — pick ONE authoritative value end-to-end.
- **MC-04 · med · scanner engine** — `ml_weight` config field is DEAD: the engine blends with `const ML_WEIGHT=0.6`, ignoring config. Wire it or delete the field+flag+example line. (audit W2)
- **MC-05 · low · core/src/config.rs** — `ScanConfig::fast/thorough/paranoid` presets have zero prod callers and diverge from the live `ScannerConfig` presets (depth 2 vs 0). Delete or route `build_scanner_config` through them — one preset path only.

## Provenance & "what is benched/shipped"

- **MC-06 · high · core/build.rs (no stamp)** — the binary carries no commit hash; result JSONs have `version=""`. This directly caused a false "F1 0.89→0.80 regression" panic (a stale `~/.local/bin/keyhog` was benched, not HEAD). Stamp `GIT_HASH` via build.rs `env!`, print in `--version`, embed in every report. Until then `tuned==benched==shipped` is unverifiable. (audit W11)
- **MC-07 · med · tools/secretbench** — the bench loads NO `.keyhog.toml`, so benched config == compiled `ScanConfig::default().into()` by accident, not by design. Pin the benched config explicitly so it can't silently drift from shipped defaults.

## Detector architecture

- **MC-08 · high · scanner/src/engine/scan.rs + suppression** — TWO detector classes with divergent gating: `generic-*` get an entropy floor + hash/UUID shape-gates; named detectors (the other ~880) get NEITHER, so a broad/hex capture fires on git SHAs, hashes, UUIDs (FP_AUDIT: 7 HIGH + 290 MED traps). The gate policy should be one coherent path keyed on capture shape, not on `id.starts_with("generic-")`.
- **MC-09 · med · detectors/ (891 TOMLs) + Tier-A defaults** — confirm no Tier-A(compiled)/Tier-B(TOML) schema duplication or drift; one schema shared by both tiers (per crates-of-crates law).
- **MC-10 · low · FP_AUDIT_REPORT.md references id `aws-access-key-id`** which does not resolve via `keyhog explain` — detector-id naming has drifted from docs/audits. Establish canonical ids + a doc-vs-registry consistency test.

## Dual sources of truth / duplication

- **MC-11 · med · vendor/vyre/ (excluded) vs `vyre =0.6.1` from crates.io** — the engine has a vendored tree kept "for reference" plus the published dep. Two copies of the GPU/SIMD engine source is a divergence trap; document the policy or drop the vendored tree.
- **MC-12 · med · scanner (6× FNV-1a loops, 5× thread-local FNV caches; 2× base64-blob gates)** — consolidate into one `util_hash` module + one `is_random_base64_blob` helper. (audit W14/W8)
- **MC-13 · low · suppression surfaces** — `.keyhogignore` (path/hash/inline), `.keyhog/strict`, `audit.toml`, inline `keyhog:ignore`, bundled `test-fixtures.toml` are 5 overlapping allow/suppress mechanisms. Map them in one doc; collapse where they overlap.
- **MC-15 · high · `--no-suppress-test-fixtures` does not fully disable fixture suppression** — a path-context test-fixture confidence penalty survives the flag. Proven on the bench: the SAME 15k byte-identical fixtures scored **1880** findings when the scan dir was named `fixtures/` vs **2484** under a neutral name (`corpus/`/`data/`), with `--no-suppress-test-fixtures` set in both. The flag's name promises suppression-off; a residual path-based penalty contradicts it — either the flag clears the path penalty too, or rename/redocument. This silently skewed bench numbers until the corpus scan dir was renamed; `benchmarks/` now forbids fixture-shaped scan-dir names. (bench audit)

## Crate boundaries

- **MC-14 · low · crates/{core,scanner,sources,verifier,cli}** — verify responsibility split is clean (scanner=27k LOC is large; candidates to split: engine vs detectors vs suppression vs confidence). No upward deps; configs live in core only.
