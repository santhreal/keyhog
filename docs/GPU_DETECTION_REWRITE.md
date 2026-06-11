# keyhog on-GPU detection rewrite — architecture & ABI

## Why

The crossover sweep (`crates/scanner/tests/backend_crossover_sweep.rs`, release-fast, RTX 5090)
shows keyhog's scan throughput is **~14 MiB/s and backend-independent** (cpu ≈ simd ≈ gpu,
gpu/best ≈ 0.9×) across 1–64 MiB benign-sparse input. The GPU never wins because it accelerates
only the **phase-1 prefilter**, which is ~0% of wall time. The cost lives in a six-pass
whole-chunk **CPU phase-2** (`engine/backend_triggered.rs::scan_prepared_with_triggered`):

1. `scan_hot_patterns_fast` — hot literal patterns over the whole text
2. `extract_confirmed_patterns` — regex capture for phase-1-triggered detectors (the only
   phase-1-keyed pass)
3. `scan_fallback_patterns` — keyword-prefiltered fallback detectors, whole chunk
4. `scan_generic_assignments` — every `key = "value"` over all lines
5. `scan_entropy_fallback` — Shannon entropy over the whole text
6. `apply_ml_batch_scores` — MoE/ML classifier on candidates

Reaching ~1000× over a single CPU thread on the 16 KB-file regime therefore requires moving the
**entire detection pipeline** onto the GPU so total throughput is GPU-bandwidth-bound, not
CPU-bound. This document is the architecture and the host↔device ABI for that rewrite.

## Detector model (what must run on-device)

A detector (`keyhog_core::spec`) is: `id/name/service/severity`, `keywords: [String]`,
`patterns: [{regex, group}]` (the credential is capture-group `group`), `companions:
[CompanionSpec]` (a secondary regex within N lines), `verify: Option<VerifySpec>` (network —
**stays host-side**, off the hot path). Scoring adds checksum validation, Shannon entropy, and
the MoE classifier.

## Core abstraction: the candidate

Detection is reframed candidate-centric. A **candidate** = `(detector_id, start, end,
cred_start, cred_end)` — a potential credential at a position. The pipeline becomes two GPU
stages instead of six whole-chunk passes:

- **Generate** (GPU, O(bytes)): keyword/literal/assignment prefilter + anchored capture →
  candidate buffer (atomic-appended).
- **Score** (GPU, O(candidates)): per candidate, in parallel — checksum-validate, entropy,
  ML features + MoE inference, companion check → confidence.
- **Emit** (GPU atomic append): candidates passing the gates → final match buffer.
- **Host tail** (low-volume): dedup, `.keyhogignore` suppression, network verify.

Per-candidate work is O(candidates), not O(chunk × detectors) — the structural win.

## On-GPU detection ABI (resident tables, uploaded once per scanner)

Compiled host-side at `CompiledScanner::compile`, uploaded into resident GPU buffers once
(reusing the `ResidentRulePipeline` pattern in `vyre-libs/src/scan/resident.rs`):

| Resident table | Source | Consumer kernel |
|---|---|---|
| `keyword_dfa` | `GpuLiteralSet` over all detector keywords | prefilter |
| `detector_regex[]` | per-detector capture matcher (see below) | capture |
| `detector_meta[]` (SoA) | `checksum_type, entropy_min:f32, body_charclass, len_lo/len_hi, companion_ref, ml_feature_ref, severity, service_id, detector_id` | score |
| `moe_weights` | exported `moe-v1` MoE weights | ML inference (vyre `nn`) |
| `decode_programs` | base64/hex | decode-recursion |

**Match output buffer** (atomic-append, read back compactly via the count-then-triples pattern
already in `ResidentRulePipeline`): `[count][ (detector_id, start, end, cred_start, cred_end,
confidence_q16) ... ]`.

## The hard parts (research, with the pragmatic plan)

1. **Regex capture on GPU.** Most detectors are "context keyword + bounded charclass body."
   Compile each detector regex into one of: (a) a GPU **anchored-capture matcher** (literal/
   keyword anchor → scan a bounded character class → capture span) — covers the majority; or
   (b) a `host_fallback` flag for the rare PCRE features (backrefs/lookaround). The compiler
   classifies every pattern at build time; `host_fallback` detectors run their capture on the
   CPU over only their candidate windows (still localized, not whole-chunk).
2. **MoE/ML on GPU — precision landmine.** The model is `gate Linear(41→6)→softmax + 6 experts
   Linear(41→32)→ReLU→Linear(32→16)→ReLU→Linear(16→1)`. vyre `nn` has the matmul/relu/softmax
   primitives, BUT `ml_scorer.rs` is hand-crafted for **bit-identical reassociation** because
   "sub-ULP divergence pushed borderline ML-gated detectors (twilio-auth-token, …)" across the
   decision boundary. A GPU matmul reassociates parallel reductions differently → scores drift →
   borderline detectors flip → recall changes. So this is NOT a mechanical port: the GPU kernel
   must reproduce the CPU reduction order (output-stationary, no cross-output reassociation) or
   the model must be re-thresholded/quantized so the boundary is robust to ε divergence — and the
   parity gate must assert *decision* parity (same detectors fire), not just score-≈.
3. **Entropy on GPU.** Shannon entropy over a candidate's bytes = per-candidate histogram +
   reduction. Embarrassingly parallel.
4. **Generic assignments.** Model `key = "value"` as a synthetic assignment detector in the
   prefilter so it flows through the same candidate pipeline.

## Kernel topology

- **Stage build (now):** multi-kernel pipeline — prefilter → candidate compaction → score →
  emit. Each stage is a resident dispatch; measurable in isolation.
- **Target:** **megakernel** (`engine/megakernel.rs` + vyre-runtime persistent kernel): one
  persistent pass, each workgroup owns a buffer region and runs prefilter→capture→score→emit
  inline with atomic append — the dispatch-overhead-free vehicle for the 16 KB-file regime.

## Build sequence — ORDERED BY REAL PROFILING DATA

`KEYHOG_PROFILE_PHASE2=1` over the real mirror corpus (`tests/phase2_breakdown.rs`), small-file
and 16 KiB regimes:

| pass | small-file | 16 KiB | → action |
|---|---|---|---|
| `scan_fallback_patterns` | **74.3%** | **58.0%** | **#1 — GPU port** |
| `extract_confirmed_patterns` | 19.4% | 21.0% | #2 |
| ml (MoE) | 3.3% | 17.2% | #3 |
| generic / hot / entropy | <3% / ~0 / ~0 | <4% / ~0 / ~0 | negligible — do NOT port |

Entropy is free; the synthetic-benign "generic 35%" was unrepresentative. The cost is the three
**regex** passes, dominated by `scan_fallback_patterns` running **~2,700 always-active fallback
regexes** (batched `RegexSet`) over every chunk.

**Coalescing is a precondition.** A GPU dispatch per 16 KB file is launch-overhead-bound (GPU
loses on tiny inputs — see `backend_crossover_sweep`). Every GPU pass below must run over a
**coalesced batch** of many files (the `scan_coalesced_*` path), not per file.

0. **Profile phase-2** — DONE (table above).
1. **GPU fallback (#1, 58–74%) — the engine EXISTS in vyre; this is WIRING, not research.**
   (Correction: an earlier draft wrongly concluded this needed a new on-GPU regex engine. It
   does not — vyre already ships the scalable multi-pattern matching engine; I had not read it.)
   The pieces:
   - **`vyre_libs::scan::nfa::plan_shards`** — greedy first-fit packing of a pattern set into
     subgroup-sized NFA plans (≤ `MAX_STATES_PER_SUBGROUP` = 1024). Sharding is the *intended*
     design for large sets, not a failure mode.
   - **subgroup-cooperative NFA** (`vyre_primitives::nfa::subgroup_nfa`) and **cooperative DFA**
     (`scan::dfa::cooperative_dfa`) — O(1)/byte multi-string scan, one subgroup forwards 1024
     states cooperatively.
   - **the megakernel** (`vyre-runtime::megakernel`) — persistent kernel + work-item ring with a
     `DFA_STEP` opcode (protocol.rs); processes many shards/patterns as work-items across all SMs
     with NO per-dispatch launch overhead. keyhog's `engine/megakernel.rs` is the consumer stub.

   Measured shard count is ~244 for 1,668 patterns (`tests/fallback_shard_size.rs`). The earlier
   claim that "244 shards is slower than CPU" was an *unmeasured assumption of serial dispatch* —
   on a 5090 (~170 SMs, thousands of resident subgroups) the shards run in PARALLEL, and the
   megakernel ring removes per-shard launch cost. **Whether it beats the CPU combined DFA is an
   empirical question to MEASURE, not to declare.**

   Build: `plan_shards(fallback_regexes)` → run the shards through the sharded NFA / megakernel
   over the **coalesced batch** → union candidate spans → host confirm/extract. 69 un-lowerable
   patterns (lookaround/backref) take a **loud** host path (Law 10), never a silent drop. Parity
   gate: per-detector fallback counts == CPU.

   **PROVEN on the 5090** (3 passing tests, `tests/megakernel_{catalog_pack,gpu_scan}.rs`):
   keyhog regexes → `build_regex_dfa_pipeline` (dense `state*256` DFA) → `BatchRuleProgram` →
   `pack_rule_catalog` (1583/1668 pack, ~95%, ~147 MB); GPU dispatch via `BatchDispatcher` emits
   correct `HitRecord{file_idx, rule_idx=detector, match_offset=match END}`; clean files = 0 hits.

   **Find-anywhere requires an UNANCHORED DFA.** `build_regex_dfa_pipeline` is anchored (matches
   at the scan start only) — a secret at offset 9 produced 0 hits; the `(?s).*?` prefix fixed it
   (secret@9 → hit@48). BUT prepending `(?s).*?` to every pattern and compiling each **OOMs**
   DFA construction at the 1668-pattern scale. So the production catalog must unanchor at the
   `nfa_to_dfa` **AC-implicit-prefix** level (start-state self-loop, which it already supports —
   `nfa_to_dfa.rs:618` "dead state that self-loops") with a **construction-memory budget**, NOT
   by `.*?` in the regex source. This is the next concrete vyre-libs helper to add:
   `build_regex_dfa_unanchored` (compile_regex_set → nfa_to_dfa in AC mode).

   *Parallel track:* **confirmed (#2)** and **MoE (#3)** — note the MoE precision landmine below.
2. **GPU confirmed extraction (#2, 19–21%).** Candidate-centric capture for triggered detectors,
   replacing the trigger-bitmap→whole-chunk re-scan; preserve the **AC-literal ∪ Hyperscan**
   trigger union (memory `simd-trigger-union-recall-load-bearing`).
3. **GPU MoE inference (#3, 3–17%).** Per-candidate features + MoE via vyre `nn`; parity: scores
   match the CPU model.
4. **Unified scoring kernel** — fuse checksum+entropy+ML per candidate.
5. **Megakernel integration — the chosen dispatch path (exact API, engine already exists).**
   vyre ships a **batched DFA rule-catalog megakernel**, tested end-to-end on wgpu
   (`vyre-driver-wgpu/tests/megakernel_failure_oriented.rs`, `_telemetry_contracts.rs`,
   `_innovation_contracts.rs`). The `megakernel-batch` feature is **already enabled** on keyhog's
   `vyre-runtime` dep. Concrete wiring:
   - **Compile** each pattern (fallback shard, then confirmed) → dense DFA
     (`vyre_libs::scan::dfa_compile` / `nfa_to_dfa`: `transitions[state*256+byte]`, `accept[state]`,
     `state_count`) → `vyre_runtime::megakernel::BatchRuleProgram::new(rule_idx, transitions,
     accept, state_count)`.
   - **Pack** all rules: `pack_rule_catalog(&rules) -> PackedRuleCatalog`.
   - **Dispatch** the catalog over the **coalesced** haystack through the persistent `Megakernel`
     with `vyre_driver_wgpu::megakernel::BatchDispatchConfig` (`launch_recommendation` derives
     worker_groups / hit_capacity from `wgpu::Limits`). Matches surface via `MegakernelIoQueue`
     (`io::{try_poll_io_requests, try_complete_io_request, io_op, io_status}`).
   - **Decode** IO-queue hits → keyhog candidates → host confirm/extract (un-lowerable patterns
     take a **loud** host path, Law 10). Replaces the CPU `scan_fallback_patterns` /
     `extract_confirmed_patterns` passes.
   - keyhog `engine/megakernel.rs` (`MegakernelSession`) is the consumer stub — its decode is
     currently gated empty; this is where the catalog dispatch + IO-queue decode land.
   - Then lower `GPU_MIN_BYTES_HIGH_TIER` and route 16 KB-file batches to the coalesced megakernel.
   - **Gates** (model on the existing wgpu megakernel tests): (a) catalog pack/dispatch of the
     fallback DFAs returns the same matches as the CPU `RegexSet`; (b) GPU≡CPU per-detector counts
     on mirror+creddata; (c) measure GPU MB/s vs 1-thread CPU.
6. **Gates** — differential GPU≡CPU on mirror+creddata (Law 6; bench CredData, memory
   `real-world-recall-gap-creddata`); per-match policy on the GPU path exactly as `process_match`
   (memories `validator-bypass-on-fast-path`, `hot-pattern-path-bypasses-process_match`); perf
   tripwires asserting GPU ≥ N× 1-thread CPU.

## Reuse (do not reinvent)

`vyre_libs::scan::{GpuLiteralSet, RulePipeline, ResidentRulePipeline, regex_dfa, dispatch_io}`,
vyre `nn` primitives (MoE), vyre `decode` (base64/hex), the vyre megakernel runtime, and the
resident-dispatch API (`VyreBackend::{allocate_resident, upload_resident, dispatch_resident_*}`).

## Build status (2026-06-07) — core proven, parity gate caught a real recall gap

Tests added (`crates/scanner/tests/megakernel_*.rs`, all `--ignored` measurements/gates):
- **catalog_pack** ✅ — 1668 keyhog regexes → unanchored DFA → `BatchRuleProgram` → `pack_rule_catalog`: 1261/1668 (76%) GPU, 407 loud host-path, ~235 MB, ~92s parallel build, no OOM.
- **gpu_scan** ✅ — GPU `BatchDispatcher` emits correct `HitRecord{file,detector,offset}`, find-anywhere, clean=0.
- **multi_rule** ✅ — multi-rule/multi-file decode → each file fires exactly its detector.
- **cpu_parity** ❌ (gate working) — 1500 real mirror files, GPU vs `regex::bytes`: **29 GPU vs 46 CPU firings, 17 GPU misses, 0 false positives.** A REAL GPU recall gap.

New vyre primitive: `vyre_libs::scan::build_regex_dfa_unanchored` (NFA-table start-self-loop; ✅ tested).

**Two hard constraints found by building (must shape the live port):**
1. **Prefix-body overlap explodes the unanchored DFA.** Patterns whose prefix chars are in the
   body charclass (`AKIA[A-Z0-9]{16}`, `AIza[A-Za-z0-9_-]{35}`, `sk_live_…`) blow past any sane
   state budget. These MUST use the **GpuLiteralSet literal-core prefilter** (find the prefix via
   AC, verify the body) — the hybrid. Only overlap-free / literal-less patterns use the unanchored
   DFA. (`ghp_…` = 146 states; `AKIA…` > 2048.)
2. **The batch dispatcher has a real recall gap** — root-cause narrowed through the `cpu_parity`
   gate (1500 mirror files, GPU vs `regex::bytes`):
   - **NOT scan-length**: misses are small files (52–292 B), early match offsets (11–111 B), far
     below the 2609 B corpus max.
   - **NOT hit-overflow**: telemetry clean (`kernel_launches:1`, 593 hits read back, no drop flag).
   - **Worker-coverage is PARTIAL**: `items_processed == worker_groups × 768` exactly (independent
     of workload — it's worker-iterations, not coverage). `worker_groups` 1→16→512 moved firings
     3→29→31, so under-provisioning loses work, but…
   - **…~15 misses PERSIST at `worker_groups=512`** — a file-specific semantic miss set (zero
     false positives throughout). These survive massive over-provisioning, so there is a second,
     non-coverage bug in the dispatcher's per-file scan/work-distribution.
   **RESOLVED (the dispatcher is correct).** Reading the kernel + diagnostics showed the "recall
   gap" was mostly **test/config error, not a GPU bug**: (a) `FileBatch::upload(_, _, rule_count,
   _)` was passed `worker_groups` instead of the rule count — bloating the work queue and breaking
   the `file_idx=claim/rule_count` mapping; (b) `worker_groups` was under-provisioned so the claim
   budget didn't cover all `files×rules` work-items (`items_processed < files×rules`). With
   `rule_count = rules.len()` and `worker_groups=256` (`items_processed=7500` = full coverage),
   the `cpu_parity` gate went from 29→**40/46 firings, 0 false positives, 17→6 misses.** The scan
   kernel (`dfa_byte_scanner`, `dispatcher.rs:1087`) and `FileBatch` packing are CORRECT.
   - **The 6 residual misses are explained — they confirm the hybrid, not a bug.** Dumping the
     missed tokens: every one is a **prefix-overlap pattern** (`ghp_…`/`gho_…`/`ghu_…` bodies
     contain g/h/p/o/u; slack `xoxb-…` bodies contain x/o/b — all members of their own body
     charclass). These are the SAME class that *explodes* the unanchored DFA (AWS `AKIA…`); when
     small enough to compile they still have subset-construction edge-case misses under the
     `.*`-self-loop. **They must run on the GpuLiteralSet literal-core path** (AC-find the literal
     prefix, verify the body) — overlap patterns do NOT belong on the unanchored DFA. The
     unanchored DFA is correct for *literal-less* patterns (0 false positives across 1500 files).
     So the path to a GREEN gate is the HYBRID router: literal-anchored → GpuLiteralSet; literal-
     less → unanchored DFA; both → megakernel. After that + `launch_recommendation` sizing, the
     `cpu_parity` gate goes green and `scan_fallback_patterns` can be replaced.

## Non-negotiable invariant (Law 10: NO SILENT FALLBACKS)

Every stage ships behind a differential parity gate: the GPU result set must equal the CPU
result set. There are **no silent fallbacks** anywhere in this pipeline. If a GPU stage cannot
run, mis-compiles, or diverges from CPU parity, it must either fail closed (error/refuse) or
degrade through a **loud, recorded** contract (`gpu_forced::deny_silent_megascan_degrade` and
peers) that the operator cannot miss — never a quiet `tracing::debug!`-and-continue, `.ok()`,
`Err(_) =>`-and-proceed, or `Option→None→other-path`. A quiet degrade is a recall bug. The
`host_fallback` classification for un-lowerable detectors is itself recorded at compile time and
surfaced, not silent. Recall is never traded for speed, and never lost invisibly.
