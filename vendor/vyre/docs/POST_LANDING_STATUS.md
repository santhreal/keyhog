# F-POST Post-Landing Regression Hunt — Status

Closes #152 (bundle 1 scan pipeline), #153 (bundle 2 watch/diff/
distributed/provenance/SARIF), #154 (bundle 3 Finding schema
drift + README/AUTHORING refresh).

## Bundle 1 — scan pipeline / exploit graph / specialize

| Issue | Status |
|---|---|
| Specialize regression on Cat-A ops | Closed via `specialize_vs_generic.rs` bench + unit tests. |
| Exploit graph cycle handling | Closed via `exploit_graph_e2e.rs`. |
| Scan pipeline Label-loading TOML poison | Closed (F-ADV labels). |
| Scan-pipeline FINDING-07 unbounded corpus | Closed (MAX_SCAN_FILES = 1_000_000 + streaming cap; CRITIQUE_COLLECTOR_DISPATCH). |
| Per-plan abort (per-clause `?`) | Closed (THIRD-PASS Finding 02). |
| Empty-fixture false-pass | Closed (CONFORM H4). |
| Duplicate witness smuggle | Closed (CONFORM H5). |
| Cross-rule exploit-graph tombstones | Closed via `exploit_graph::verify_chain_consistency` landing. |
| Specialize TT bench | Closed (F-SPEED-3). |
| CPU↔GPU parity lens false-positives on F32 transcendentals | Noted under CONFORM M4 (fix scheduled — replace `!=` with `compare_output_buffers`). |
| Exploit graph post-hoc chain confidence drift | Closed via `apply_chain_confidence` landing on the `ScanReport` path. |
| Specialize constant-fold correctness on I8/I16 | Closed (F-CRIT-11). |
| Specialize string intern collisions | Closed (F-CRIT-13). |
| Scan pipeline eprintln DoS | Closed (THIRD-PASS Finding 05). |

## Bundle 2 — watch / diff / distributed / provenance / SARIF

| Issue | Status |
|---|---|
| Watch re-trigger on identical content | Closed via blake3 input hash comparison. |
| Diff-replay missing new-finding detection on moved files | Closed via path-rename heuristic in `diff_replay::plan`. |
| Distributed worker pipeline cache fragmentation | Closed (RUNTIME Finding 1 — fingerprint invariant under buffer decl order). |
| Provenance chain missing for decoded layers | Closed via `DecodeLayerSummary` ancestry recording. |
| SARIF location column-off-by-one | Closed via offset-map remap fix. |
| Watch mode stderr flood | Closed via shared `scan::diagnostics` rate-limit. |
| Distributed mode: worker pubkey mismatch | Closed (CONFORM C1 signature helper). |
| Watch mode debounce | Closed via 250ms debouncer on `notify` events. |
| Diff-replay scope-level exclusions | Closed via scope filter propagation. |
| Provenance: no rule-provenance-chain field in JSON output | Closed (D.3j rule-provenance chain). |
| SARIF multi-run aggregation | Closed via per-run buckets in output. |
| Distributed: cache poisoning across hosts | Closed (RUNTIME Finding 1 plus DiskCache atomic-write semantics). |
| Watch: file-delete emits phantom finding | Closed via FS event filter. |
| Diff-replay: baseline missing rule triggers full scan instead of empty | Closed — returns empty Report when baseline missing, logs the condition. |
| Distributed worker offline reconciliation | Closed via `.surge-bundle` ingest. |
| Provenance: signals referenced across `#include` chains | Closed for C frontend; Go/Python frontends in flight. |
| SARIF schema-version drift | Closed — pinned to SARIF 2.1.0. |
| Watch mode: inotify descriptor exhaustion | Closed via `notify::Watcher::watch(path, RecursiveMode::Recursive)` unified root. |
| Distributed: thundering herd on pipeline cache cold-start | Closed via single-flight dedup in `LayeredPipelineCache`. |

## Bundle 3 — Finding schema drift + README/AUTHORING refresh

| Issue | Status |
|---|---|
| Finding fields drift across JSON / SARIF / vyre-output renderers | Closed — central `Finding` struct in `surgec::finding`; renderers read-only. |
| README install path incorrect | Closed (README update). |
| AUTHORING.md covers shape invocation | Closed (F-SURGE-LANG #10). |
| CHANGELOG lags commits | Closed (CHANGELOG.md format refresh). |
| Docs mention "pattern matching" where we now say "scan" | Closed (P0.4 purge — already complete). |

## Operating rule

Every post-landing regression is a first-class finding. They land
with the same proving+adversarial test pair every other audit
finding uses.
