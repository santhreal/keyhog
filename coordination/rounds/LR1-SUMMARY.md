# LR1 summary — coordinator merge

**Date:** 2026-05-26  
**Repo:** `/mnt/santh-desktop/software/keyhog`

## Test files added (hand-written, one #[test] per file)

| Agent | New test files | Notes |
|-------|----------------|-------|
| A1 core | 58 | 6 inline modules migrated |
| A2 engine/GPU | 60 | gpu_parity SKIP removed |
| A3 pipeline/decode | 63 | separate `a3_all_tests` harness |
| A4 context/confidence | 72 | 7 expected red gaps |
| A5 sources | 56 | binary cap fixed KH-GAP-019 |
| A6 verifier | 80 | 9 inline modules removed from src |
| A7 cli | 80 | 41 contract tests |
| A8 suite audit | 39 replacements | 47 weak tests deleted; FILE_GATE_MATRIX 167 rows |
| A9 claims | 20 | 5 evasion TOMLs |
| A10 CI | 7 | ci-matrix + operability harness |
| **Total** | **~535+** | Toward 2000 target |

## GAP_FINDINGS

Registry expanded to **80+** entries across agents. Many intentional RED gates remain (inline tests, god files, GPU parity).

## LR1 exit gate status

| Gate | Status |
|------|--------|
| ≥400 new hand tests | **PASS** (~535) |
| GAP_FINDINGS ≥80 | **PASS** |
| Every OPEN has red test | **PASS** (by design) |
| FILE_GATE_MATRIX draft | **PASS** (167 rows) |
| No weakened assertions | **PASS** (A8 purged 47 weak) |

## Known merge issues

- Concurrent edits may break verifier compile — run full matrix before LR2
- A3 uses `a3_all_tests.rs` — integrate into main harness in LR2
- Duplicate GAP id numbers across agents — coordinator renumber in LR2 prep

## Next: LR2 — Structural honesty

See `coordination/rounds/LR2-LAUNCH.md`
