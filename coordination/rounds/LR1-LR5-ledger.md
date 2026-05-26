# Round 1–5 ledger — Linux-quality push (2026-05-26)

**Repo:** `/mnt/santh-desktop/software/keyhog`

## Round 1 — Hunt + red inventory

| Agent slice | Hunt | Tests written (hand) | Status |
|-------------|------|----------------------|--------|
| A1 core | 24 inline test modules | gap×4, contract×2, adversarial dedup | DONE |
| A2 engine | GPU skip, parity soft-warn | gap×6, megakernel hard fail | DONE |
| A3 pipeline | 1924 LOC pipeline | pipeline_exceeds_modularity_cap (RED) | DONE |
| A5 sources | unbounded binary read | binary gap×2 | DONE |
| A6 verifier | 9 inline tests | gap + ssrf contract | DONE |
| A7 cli | exit codes | gap + contract×2, main.rs fix | DONE |
| A8 suite | decorative tests | analyze_keyword_only assertions | DONE |

**Evidence:** `env -u CC cargo test -p keyhog-core --test all_tests gap:: contract::`

## Round 2 — Structural fixes

| Fix | Status |
|-----|--------|
| core encoding inline tests → `tests/unit/encoding.rs` | FIXED |
| binary `read_binary_capped` 64MiB | FIXED (KH-GAP-010) |
| cli EXIT_USER/SYSTEM + SCANNER_PANICKED | FIXED (KH-GAP-006 partial) |
| verifier `pub mod ssrf` | FIXED |
| inline test exile (remaining ~60 files) | OPEN |
| god file splits | OPEN (RED gates) |

## Round 3 — Engine + contract

| Test | Status |
|------|--------|
| contract detector 891 | written |
| contract aws canonical shape | written |
| contract every id has contract | written (verify green) |
| megakernel parity | RED until engine fix |

## Round 4 — Adversarial

| Test | Status |
|------|--------|
| empty_chunk_no_findings | written |
| gpu_tests_fail_not_skip | written |
| dedup_empty_input | written |

## Round 5 — Closure

| Item | Status |
|------|--------|
| GAP_FINDINGS updated | partial |
| pipeline/orchestrator split | OPEN |
| full strict runner matrix | not run (Hyperscan host dep) |

## Remaining RED (intentional roadmap)

- KH-GAP-004 inline src tests (~60 files)
- KH-GAP-005 pipeline 1924 LOC, orchestrator 1586 LOC
- KH-GAP-001 megakernel parity
- KH-GAP-002/003 GPU on headless hosts
- sources gap binary_no_unbounded_fs_read (superseded by binary_read_is_capped when old test removed)
