# Confirmed phase-two scratch reuse

Confirmed shared-anchor collection now borrows its eligible-pattern and literal-id vectors from the existing bounded candidate scratch pool.

| Allocation metric | Legacy | Candidate | Change |
|---|---:|---:|---:|
| Temporary helper vectors per pass | 2 | 0 | 100% eliminated |
| Vectors in bounded scratch | 1 | 3 | one aggregate owner |
| Aggregate retained bytes per buffer | 1 MiB | 1 MiB | unchanged ceiling |
| Idle scratch buffers | 4 | 4 | unchanged process bound |

Candidate ordering, sorting, deduplication, sparse literal search, and shared-automaton fallback are unchanged. Only storage ownership moves. The aggregate capacity check includes candidate pairs, active pattern indices, and literal ids; an outlier releases all three before reuse.

The feature-neutral scanner library compiles with the pooled scratch. Retention regressions cover candidate outliers, helper-vector aggregate overflow, four-buffer process bounds, and partition cleanup.

The output candidate vector remains required. This receipt claims elimination of the two helper-vector allocation sites, not zero allocations for the complete phase-two pass.

Receipt: [`phase2-scratch-reuse.json`](phase2-scratch-reuse.json)
