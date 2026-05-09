# Vyre primitive usage — audit & roadmap

Status snapshot of which vyre primitives keyhog consumes, what the
full vyre surface looks like, and a prioritised list of wires worth
making next. Vyre is a ~30-crate GPU compute framework — this doc
catalogues every crate it ships so future wires don't have to
re-discover the surface.

Updated 2026-05-08, against vendored vyre v0.6.0.

## What keyhog uses today

| Vyre symbol                                          | Where keyhog uses it                                                |
| ---------------------------------------------------- | ------------------------------------------------------------------- |
| `vyre_libs::matching::GpuLiteralSet`                 | `engine/scan_gpu.rs::scan_coalesced_gpu` — primary GPU path         |
| `vyre_libs::matching::RulePipeline`                  | `engine/scan_gpu.rs::scan_coalesced_megascan` — regex-NFA GPU path  |
| `vyre_libs::matching::build_rule_pipeline_from_regex`| `engine/mod.rs::build_rule_pipeline` — MegaScan compile             |
| `vyre_libs::matching::LiteralMatch`                  | Re-exported as `keyhog_scanner::LiteralMatch` for API stability     |
| `vyre_libs::matching::dedup_regions_inplace`         | Per-pid match deduplication after both GPU dispatches               |
| `vyre_libs::matching::RegionTriple`                  | Same — input shape for the dedup primitive                          |
| `vyre_libs::matching::cached_load_or_compile`        | On-disk cache for compiled GPU literal-set + rule pipelines         |
| `vyre_libs::intern::perfect_hash::PerfectHash`       | `static_intern.rs` — frozen detector-metadata interner              |
| `vyre_libs::intern::perfect_hash::build_chd`         | Same — built once at scanner construction                           |
| `vyre_driver_wgpu::WgpuBackend`                      | Persistent wgpu device handle held by `CompiledScanner`             |
| `vyre_driver_wgpu::runtime::cached_device`           | Aliveness check before each GPU dispatch                            |
| `vyre_libs::matching::nfa` (via RulePipeline)        | Indirectly — consumed by `build_rule_pipeline_from_regex`           |

Three scanner files (`engine/scan_gpu.rs`, `engine/mod.rs`,
`engine/backend.rs`, `static_intern.rs`) are the only consumers.

## Full vyre crate surface

### vyre-foundation

The IR + execution-plan crate. Provides:

- `ir` — typed Program IR (Node, Expr, BufferDecl, BufferAccess, DataType)
- `lower`, `optimizer` — lowering passes + optimisation passes
- `cpu_op`, `cpu_references` — CPU reference impls of every op
- `memory_model`, `MemoryOrdering` — formal memory model
- `match_result::Match` — the `(pattern_id, start, end)` triple keyhog
  already consumes via `LiteralMatch`
- `extern_registry`, `dialect_lookup`, `algebraic_law_registry` —
  pluggable dialect/op/law registry
- `composition`, `execution_plan::fusion::{fuse_programs, ...}` —
  cross-program fusion (multiple Programs into one dispatch)
- `vast`, `graph_view` — IR graph traversal
- `diagnostics` — typed diagnostic messages
- `opaque_payload` — type-erased per-op state

**Keyhog touches**: `match_result::Match` indirectly via vyre_libs.
**Keyhog could use**: `fuse_programs` to fuse decode + scan into one
dispatch; `execution_plan` for batched multi-stage pipelines.

### vyre-driver

The dispatch backbone:

- `backend` — `VyreBackend` trait; every concrete backend implements it
- `routing::{select_sort_backend, RoutingTable, SortBackend}` — picks
  best backend per workload
- `pipeline` — backend-agnostic dispatch
- `registry` — backend registry
- `shadow`, `speculate` — speculative + shadow execution (run on two
  backends, compare results)
- `persistent` — long-lived dispatch state

**Keyhog touches**: nothing directly.
**Keyhog could use**: `routing::select_sort_backend` for MegaScan
pipeline ordering; `shadow` to validate GPU vs CPU on every dispatch
in CI.

### vyre-driver-wgpu

The wgpu backend:

- `WgpuBackend`, `WgpuBackendStats`, `WgpuIR` — concrete dispatch
- `pipeline`, `buffer`, `lowering` — wgpu-specific compile
- `megakernel`, `spirv_backend`, `engine`, `ext` — speciality dispatch
  modes
- `runtime` — `cached_device`, `GpuMappedBuffer` (uring-backed)
- `DispatchArena` — per-dispatch scratch arena

**Keyhog touches**: `WgpuBackend`, `runtime::cached_device`.
**Keyhog could use**: `runtime::GpuMappedBuffer` for io_uring-backed
filesystem reads straight into GPU memory; `DispatchArena` for
shared scratch buffers across batched dispatches.

### vyre-driver-megakernel

Megakernel dispatcher: bundles many small ops into one kernel
launch. Useful when dispatch overhead dominates throughput.

- `MegakernelDispatch` trait
- `policy`, `task` — scheduling primitives

**Keyhog could use**: bundling literal-set + boundary scan + entropy
prefilter into one megakernel (eliminates ~4 ms × 4 dispatches per
batch).

### vyre-driver-spirv

The SPIR-V backend (Vulkan-only path). Same surface as wgpu.

### vyre-driver-cuda

CUDA backend (only on upstream HEAD; not in v0.6.0 vendor).

### vyre-driver-reference

CPU reference backend — runs every op via `vyre-reference` for
correctness validation.

### vyre-libs

Tier-3 application primitives (composed from `vyre-primitives`).
Modules:

- **matching** ✅ partly used: `GpuLiteralSet`, `RulePipeline`,
  `dedup_regions_inplace`. Unused: `classic_ac`, `cooperative_dfa`,
  `dfa/`, `direct_gpu`, `substring/`, `pipeline`, `post_process`,
  `hit_buffer`, `engine`, `builders`, `dispatch_io`, `test_fixtures`.
- **decode**: `base64`, `hex`, `inflate`, `ziftsieve`, `encodex`,
  `streaming` — GPU-IR decoders. Unused (keyhog has its own CPU
  decoders in `crates/scanner/src/decode/`).
- **hash**: `adler32`, `blake3_compress`, `crc32`, `fnv1a32`,
  `fnv1a64`, `multi_hash`. All GPU-IR builders. Unused (keyhog uses
  `sha2`/`blake3`/`fnv` crates directly on CPU).
- **intern** ✅ used: `perfect_hash::PerfectHash`. Other content:
  internal CHD construction, no other public surface.
- **nn**: `moe`, `linear`, `attention`, `norm`, `activation`. GPU-IR
  builders for neural-net layers. Unused (keyhog has its own
  hand-rolled MoE in `gpu.rs`).
- **rule**: `file_size_*`, `pattern_count_*`, `pattern_exists`,
  `literal_true/false`, `condition_op`, `ast`, `builder`. Predicate
  engine. Unused (keyhog has hand-rolled `inline_suppression.rs`).
- **text**: `char_class` — byte→class-code mapper. Different shape
  from keyhog's `alphabet_filter` (bitset of present bytes), so not a
  drop-in. Could power a future syntax-aware context detector.
- **math**: `algebra`, `atomic/`, `avg_floor`, `broadcast/`,
  `clamp_u32`, `linalg/`, `lzcnt_u32`, `reduce_mean`, `scan/`, `square`,
  `succinct`, `tzcnt_u32`, `wrapping_neg`. Numeric kernels.
- **logical**: `and`, `or`, `xor`, `nand`, `nor` — bitmap ops.
- **parsing**: parser combinators on GPU.
- **graph**: graph algorithms (reachability, dominators).
- **dataflow**: taint-flow analysis.
- **security**: `auth_check_dominates`, `bounded_by_comparison`,
  `buffer_size_check`. Static-analysis predicates — wrong domain.
- **representation**: IR helpers.
- **compiler**: program compiler.
- **visual**: viz helpers.
- **harness**: test harness for primitive correctness.
- **builder**: `BuildOptions`, `check_tensors`.
- **descriptor**: `BufferDescriptor`, `ProgramDescriptor`.
- **buffer_names**: stable buffer-name constants.
- **range_ordering**, `region`, `tensor_ref`, `signatures`,
  `contracts`, `test_migration` — plumbing.

### vyre-primitives

Tier-2.5 primitives that vyre-libs composes. Each module is a
collection of single-op IR builders:

- **bitset**: 18 ops — `and`, `and_into`, `and_not`, `and_not_into`,
  `any`, `clear_bit`, `contains`, `equal`, `four_russians`, `not`,
  `or`, `or_into`, `popcount`, `set_bit`, `subset_of`, `test_bit`,
  `xor`, `xor_into`. Could replace bits of `bigram_bloom.rs`.
- **decode**: `base64`, `inflate`. Same content as vyre-libs::decode.
- **fixpoint**: fixpoint iteration kernels.
- **graph**: graph algorithms.
- **hash**: `blake3`, `crc32`, `fnv1a`, `table`. Used by
  vyre-libs::hash.
- **label**: connected-components labeling.
- **markers**: type markers.
- **matching**: `bracket_match`, `dfa_compile`, `region`. The DFA
  compiler vyre-libs uses.
- **math**: `conv1d`, `dot_partial`, `interval`, `prefix_scan`,
  `stream_compact`, `tensor_scc`.
- **nfa**: subgroup-cooperative NFA scan kernel (the engine under
  `RulePipeline`).
- **nn**: NN building blocks.
- **parsing**: parser primitives.
- **predicate**: predicate combinators.
- **range**: range arithmetic.
- **reduce**: reduction kernels.
- **text**: `byte_histogram`, `char_class`, `encoding_classify`,
  `line_index`, `utf8_shape_counts`, `utf8_validate`.
- **vfs**: virtual-filesystem indices.

### vyre-runtime

Long-lived runtime services:

- `megakernel::Megakernel`, `WgpuMegakernelDispatcher`
- `pipeline_cache::RemoteCache` + on-disk cache
- `replay::{RecordedSlot, ReplayLogError, RingLog}` — record-replay
  for deterministic re-execution
- `routing` — runtime routing
- `tenant` — multi-tenant dispatch
- `uring::{GpuStream, GpuMappedBuffer}` — io_uring-backed GPU memory

**Keyhog could use**: `replay::RingLog` for deterministic scan
reruns; `uring::GpuMappedBuffer` for zero-copy file→GPU.

### vyre-spec

Formal vyre specification:

- `algebraic_law`, `all_algebraic_laws` — algebraic identities
- `atomic_op`, `bin_op`, `buffer_access`, `data_type`, `expr_variant`
- `engine_invariant` — runtime invariants
- `extension`, `convention`, `category`, `by_category`, `by_id`,
  `catalog_is_complete`
- `adversarial_input` — invariants under adversarial input

This is the contract every backend implements. Consumers of vyre
don't generally need it.

### vyre-intrinsics

Hardware intrinsics + category checks:

- `category_check`, `hardware`, `region`, `harness`
- Re-exports from `vyre_foundation::cpu_op` (CategoryAOp, CpuOp,
  structured_intrinsic_cpu)

### vyre-reference

CPU reference implementation of every primitive — used for
correctness validation:

- `dual`, `primitive`, `primitives`, `value`
- `atomics`, `cpu_op`, `dialect_dispatch`
- `eval_expr`, `eval_node`, `flat_cpu`
- `ieee754`
- `interp`, `sequential`, `subgroup`, `workgroup` — execution models

### vyre-cc

C compiler bridge. Not directly relevant to keyhog (needed only when
compiling C kernels into vyre IR).

### vyre-harness

Test harness types: `OpEntry`, `FixpointContract`, `DiffCandidate`,
`UniversalDiffExemption`. Used by `inventory::submit!` to register
ops globally.

### vyre-macros

Derive + attribute macros: `define_op`, `vyre_ast_registry`,
`derive_algebraic_laws`, `vyre_pass`, `skip_builder`. Used internally
by primitive authors.

## v0.5.5 status — everything wired so far

| Wire                                 | Status      | Where                                                  |
| ------------------------------------ | ----------- | ------------------------------------------------------ |
| `intern::perfect_hash`               | ✅ shipped  | `crates/scanner/src/static_intern.rs` + `engine/mod.rs` |
| Tier-aware GPU routing (2 MiB)       | ✅ shipped  | `crates/scanner/src/hw_probe.rs`                       |
| GPU dispatch sharding                | ✅ shipped  | `engine/scan_gpu.rs::scan_coalesced_gpu`               |
| `rule` CPU evaluator + `FieldInSet`  | ✅ shipped  | upstream `vyre_libs::rule::cpu_eval` + `ast.rs`        |
| `.keyhogignore.toml` rule engine     | ✅ shipped  | `crates/core/src/rule_filter.rs` + `orchestrator.rs`   |
| Megakernel scaffold (gated)          | ⏳ partial  | `engine/megakernel_dispatch.rs` (needs vyre per-pattern hits) |
| `cooperative_dfa` alt literal engine | ⏳ pending  | needs keyhog GPU dispatch infrastructure (entry below) |
| `fuse_programs` decode+scan          | ⏳ pending  | needs source/scanner restructure (entry below)         |
| `nn::moe` replacing gpu.rs MoE       | ⏳ pending  | parity work against existing weights (entry below)     |
| `GpuMappedBuffer` zero-copy I/O      | ⏳ pending  | Linux-only + lifetime work (entry below)               |
| Vyre HEAD upgrade                    | ❌ blocked  | API restructure broke `BatchDispatcher` API surface   |

## Pending-wire entry points (concrete)

Each remaining wire's API surface in vyre + the keyhog hook where
the integration lands. The unblocker for each is real engineering,
not new research — anyone picking up the work has the contract.

### `cooperative_dfa`

- Vyre API: `vyre_libs::matching::cooperative_dfa::cooperative_dfa_scan(input, transitions, accept_mask, matches, input_len, state_count, subgroup_size) -> vyre::ir::Program`
- Build DFA tables via `vyre_libs::matching::dfa::dfa_compile(&[&[u8]]) -> CompiledDfa`
- Compile Program once at scanner construction via vyre `pipeline::compile`
- Per-batch dispatch: upload input/transitions/accept, allocate matches, call `pipeline.dispatch_borrowed(...)`, read back
- Wire as a new `ScanBackend::CooperativeDfa` variant alongside `Gpu` and `MegaScan`. Route via `select_backend` once benchmarked vs literal-set.
- Effort: 2-3 days. Mostly the dispatch infrastructure (which is the same as megakernel scaffolding — would unblock both).

### `fuse_programs` for decode + scan

- Vyre API: `vyre_foundation::execution_plan::fusion::fuse_programs(&[Program]) -> Result<Program, FusionError>`
- Build a decode Program: `vyre_libs::decode::inflate(...)` for `.zst` / `.gz` inputs
- Build a scan Program: `vyre_libs::matching::cooperative_dfa::cooperative_dfa_scan(...)`
- `fuse_programs(&[decode_prog, scan_prog])` produces one Program; vyre auto-resolves shared buffer names (decode's output buffer should be named the same as scan's input buffer).
- Source-side: `crates/sources/src/filesystem/read.rs` currently CPU-decompresses via `ziftsieve` then hands plaintext to `scan_coalesced`. Switch `.zst` / `.gz` inputs to keep compressed bytes + dispatch fused program.
- Effort: 3 days. Mostly the source/scanner boundary refactor.
- Payoff: ~50% wall-time reduction on `.zst`-heavy corpora (npm, Docker image layers); zero effect on regular source trees.

### `nn::moe` replacing `gpu.rs` MoE

- Vyre API: `vyre_libs::nn::moe::moe_gate`, `vyre_libs::nn::moe::top_k`,
  `vyre_libs::nn::linear`, `vyre_libs::nn::activation`, `vyre_libs::nn::norm` —
  compose the same MoE shape `gpu.rs` hand-rolls.
- Existing `gpu.rs` is ~620 LoC of bespoke wgpu+WGSL implementing
  Linear(41→6) gate + 6 experts × Linear(41→32)+ReLU →
  Linear(32→16)+ReLU → Linear(16→1) + sigmoid weighted sum.
- Bit-equal validation against `ml_scorer.rs`'s CPU MoE outputs on
  the existing weight set. The weights load path stays the same;
  only the dispatch path swaps.
- Effort: 3 days + correctness validation. Risky — replacing
  working code; needs a parity test harness that compares MoE
  outputs across CPU / current-GPU / new-vyre-GPU paths.
- Payoff: ~600 LoC deleted, automatic benefit from vyre kernel
  improvements, identical compute semantics.

### `GpuMappedBuffer` zero-copy filesystem reads

- Vyre API: `vyre_runtime::uring::GpuMappedBuffer` (Linux-only,
  io_uring-backed; gated behind a vyre-runtime feature)
- Source-side: `crates/sources/src/filesystem/read.rs` currently
  reads file content into `Vec<u8>` then copies to GPU buffer.
  `GpuMappedBuffer` io_urings the file directly into a GPU-mapped
  region.
- Lifetime work: `GpuStream<'a>` ties the buffer to the dispatch
  scope; keyhog needs to thread the lifetime through `Source`,
  `Chunk`, and the scanner's per-chunk extraction phase.
- Effort: 3 days. Linux-only — Windows / macOS keep the
  read-then-copy path.
- Payoff: eliminates a 256 MiB heap → GPU memcpy per batch on
  big-file scans.

## Performance benchmark snapshot (RTX 5090, v0.5.4 + tier routing)

After landing tier-aware routing + GPU dispatch sharding, the embedded
`keyhog scan --benchmark` corpus (100 × 1 MiB chunks of realistic
source-code shape with a known-secret suffix per chunk) reports:

```
cpu-fallback : 130 MiB/s  (302168 findings)
simd-regex   : 136 MiB/s  (304128 findings)
gpu-zero-copy:  34 MiB/s  (303554 findings)
```

Recall is now correct across all three backends (the prior `121×
speedup` number on the entropy-trap fixture was lying — GPU was
dispatch-erroring and returning 2304 of the 304128 true findings).

GPU loses on this density of triggered chunks because every chunk
triggers the full per-chunk extraction (entropy + regex + ML
scoring), and that pipeline runs CPU-side after the GPU prefilter.
The prefilter speedup amortises across 50 shards (100 MiB / 2 MiB
max-dispatch-bytes) but the post-process serial cost dominates.

**The architectural fix is megakernel fusion of the extraction
pipeline onto the GPU** (item 8 below). Until then, the tier-aware
router correctly stays on SIMD for this finding density.

## Concrete next-wires (priority order)

Each of these is a self-contained scope of work whose payoff and risk
are estimable. Listed best-bang-for-buck first.

1. ✅ **`intern::perfect_hash` for static-string interning** — DONE.
   Scanner now hands out `Arc<str>` for `(detector_id, name, service,
   source_type)` from a frozen CHD perfect hash, lock-free, no
   per-scan allocation.

1.5. ✅ **Tier-aware GPU routing + dispatch sharding** — DONE.
   `select_backend` classifies the active GPU into High/Mid/Low and
   uses tier-specific thresholds (2 MiB / 16 MiB / 64 MiB).
   Per-tier pattern-count breakeven (100 / 500 / 2000). GPU dispatch
   now shards at 65535 × 32 = ~2 MiB per dispatch to respect the
   wgpu workgroup-per-dimension cap. `keyhog backend` reports the
   active tier and effective thresholds.

2. **`rule` engine for inline-suppression / allowlist.**
   The current allowlist is hand-rolled string matching. Vyre's `rule`
   exposes typed predicates (`file_size_gt`, `pattern_count_gte`,
   `pattern_exists`, …) that compose into rule trees. Wins:
   declarative `.keyhogignore.toml` (`suppress when file_size > 10K AND
   pattern_count(test_kw) >= 2`); user-defined gates; consistent eval
   model. Effort: ~2 days (schema + parser + eval).

3. **`runtime::uring::GpuMappedBuffer` for filesystem reads.**
   `crates/sources/src/filesystem/read.rs` reads file content into
   `Vec<u8>` then copies to GPU. `GpuMappedBuffer` io_urings the file
   directly into a GPU-mapped buffer — eliminates a 256 MiB copy per
   batch on the GPU dispatch path. Effort: ~3 days; needs vyre-runtime
   feature opt-in + careful lifetime work.

4. **`fuse_programs` to bundle decode + scan dispatches.**
   When scanning a `.zst` archive today: read on CPU → decode on CPU
   (`ziftsieve`) → copy plaintext to GPU → dispatch literal-set. With
   `fuse_programs(decode::inflate, GpuLiteralSet)` it becomes one GPU
   dispatch. Saves ~50% wall time on compressed-corpus scans. Effort:
   ~2 days.

5. **`nn::moe` + `nn::linear` replacing `gpu.rs`'s hand-rolled MoE.**
   `gpu.rs` is ~620 lines of bespoke wgpu+WGSL for an MoE confidence
   scorer. Vyre's `nn::moe` is the same algorithm composed from
   `nn::linear` + `nn::activation` + `nn::norm`. Wins: ~600 lines
   deleted, automatic benefit from vyre kernel improvements. Risk:
   medium — needs parity tests against `ml_scorer.rs` outputs.
   Effort: ~3 days plus correctness validation.

6. **`shadow`/`speculate` for CI dispatch validation.**
   In CI, run every GPU dispatch on TWO backends (vyre-driver-wgpu +
   vyre-driver-reference) and assert identical results. Catches GPU
   driver regressions before users see them. Effort: ~1 day.

7. **`replay::RingLog` for deterministic scan rerun.**
   Record every dispatch + result; on a flaky test, replay the exact
   same sequence to bisect. Useful for debugging GPU non-determinism
   reports. Effort: ~1 day (mostly wiring).

8. ⏳ **`vyre-driver-megakernel` to bundle the per-chunk extraction
   onto GPU** — IN PROGRESS (scaffolding committed, dispatch loop
   in follow-up). Today the GPU only runs
   the literal-prefilter; per-chunk regex matching, entropy
   scoring, ML inference all run CPU-side after the prefilter
   returns triggers. The benchmark above shows this serial CPU
   work caps the throughput at ~135 MB/s regardless of how fast
   the prefilter is.

   Vyre exposes a complete megakernel API at
   `vyre-runtime::megakernel`:
   - `BatchDispatcher::new(backend, config)` — compile once
   - `BatchDispatcher::dispatch(batch, rules)` — one GPU launch
     handles many files × many DFA rules
   - `FileBatch` — offsets/metadata/work_queue/haystack/hit_ring
   - `BatchRuleProgram::new(rule_idx, transitions, accept,
     state_count)` — wraps a DFA per detector

   Wiring entry points in keyhog:
   - `crates/scanner/src/engine/scan_gpu.rs::scan_coalesced_gpu` —
     replace per-chunk `scan_prepared_with_triggered` loop with one
     `BatchDispatcher::dispatch` call
   - Detector regex → DFA: `vyre_libs::matching::dfa::dfa_compile`
   - Build `FileBatch` from `chunks` + per-chunk offset attribution
     in scan_gpu.rs's existing `entries` walk

   Effort: 3-5 days. Biggest single perf win available.

9. **CPU-side entropy-fast SIMD-isation.**
   The benchmark shows per-chunk extraction is the bottleneck even
   without megakernel. `crates/scanner/src/entropy_fast.rs` already
   has thread-local FNV cache; widening the byte histogram to AVX-512
   (16-lane gather + popcnt) would lift per-chunk throughput 2-4×
   without GPU work. Effort: 1-2 days.

## Megakernel wiring — status + architectural finding

`crates/scanner/src/engine/megakernel_dispatch.rs` ships a working
end-to-end wire (DFA-per-literal compile + `BatchDispatcher` init +
`dispatch_triggers` returning per-chunk per-pattern triggers),
gated behind `KEYHOG_USE_MEGAKERNEL=1` and routed through
`scan_coalesced_megakernel` in `engine/scan_gpu.rs`.

**Architectural mismatch found in testing on RTX 5090:** vyre's
`BatchDispatcher` is built for "many files × few rules" (small
curated rule pack against many files). Keyhog's production corpus
is "few files × many rules" — 6000+ literal patterns scanned across
~100 file chunks per batch. Modelling each literal as its own
`BatchRuleProgram` allocates `chunks × rules ≈ 600,000` work items
inside the persistent kernel for a single batch, which is enough
to keep the dispatch sleeping for minutes (observed on RTX 5090 —
the first benchmark run had to be killed after ~25s of wall time
with the kernel still in S-state waiting on per-rule scratch).

**Real megakernel win path (vyre-side feature request):**
- Pass ALL literals into ONE `dfa_compile(&[&[u8]])` call → ONE
  multi-pattern DFA → ONE `BatchRuleProgram` per batch
- vyre `HitRecord` currently has `(file_idx, rule_idx, layer_idx,
  match_offset)` — no per-pattern field. Need a vyre-side opcode
  handler set that emits per-pattern hits via the DFA's
  `output_records` table
- Then a single dispatch handles all chunks × all literals natively,
  one kernel launch, full per-pattern attribution

The keyhog-side wiring lands as a one-line swap once vyre exposes
the per-pattern hit reporting. Until then, default GPU path stays
on `scan_coalesced_gpu`'s sharded `GpuLiteralSet::scan` (50
dispatches × 100µs ≈ 5ms overhead for a 100 MiB batch — measured
with the realistic-corpus benchmark; less of a win than expected
because per-chunk extraction still dominates).

## Megakernel wiring — original next-session checklist

The scaffolding in `crates/scanner/src/engine/megakernel_dispatch.rs`
gives a working `MegakernelScanner` (DFA-per-literal compile +
`BatchDispatcher` init). To complete the wiring:

1. **Build `FileBatch` from chunks** at scan time. API:
   `FileBatch::upload(device_queue, &[BatchFile], rule_count, hit_capacity)`.
   Each `BatchFile::new(path_hash, decoded_layer_index, bytes)` wraps
   one chunk's bytes. `path_hash` can be the chunk index hashed via
   FNV; `decoded_layer_index = 0` for non-decoded scans.
2. **Dispatch via `BatchDispatcher::dispatch(&batch, &rules)`**. Returns
   `BatchDispatchReport { hits: Vec<HitRecord { file_idx, rule_idx,
   layer_idx, match_offset }>, ... }`.
3. **Map `HitRecord` → keyhog trigger bitmask**:
   `per_chunk_triggers[hit.file_idx as usize][hit.rule_idx as usize / 64]
   |= 1 << (hit.rule_idx % 64)`. Same shape as the existing
   `scan_coalesced_gpu` post-process.
4. **Per-chunk extraction phase**: identical to `scan_coalesced_gpu`
   from line ~277 onwards (par_iter, prepare_chunk,
   scan_prepared_with_triggered, post_process_matches, boundary scan).
5. **Wire as a new `ScanBackend` variant or replace `Gpu`'s underlying
   impl**. Recommend: cache `MegakernelScanner` on `CompiledScanner`
   via `OnceLock<Option<MegakernelScanner>>` (mirrors `gpu_matcher`
   and `rule_pipeline`); add `try_with_megakernel()` getter; route
   `scan_chunks_with_backend_internal` to it when active.
6. **Parity test against `scan_coalesced_gpu`** — same fixture as
   `tests/gpu_parity.rs`, assert equal credential sets between
   sharded GpuLiteralSet and BatchDispatcher paths.

Expected wins on RTX 5090: ~5 ms saved per 100 MiB batch (50 sharded
dispatches × 100 µs collapsed into 1). Not a 10× win on its own — the
real prize is step 7, moving per-chunk extraction onto the same
megakernel via `OpcodeHandler`s for entropy + regex eval.

## Other unfinished wires (deferred from this session)

- **`shadow`/`speculate` for CI dispatch validation.** vyre's shadow
  module is for validating ops against multiple backends inside vyre;
  not directly applicable to keyhog. The keyhog-side equivalent is
  `tests/gpu_parity.rs` which already runs every CI build. A
  `--validate-backend` CLI flag for runtime opt-in dual dispatch
  was prototyped but reverted: cleanly hijacking `scan_sources` to
  re-run with a forced backend needs source iterator re-creation,
  which is more invasive than a session-end commit warrants.
  Future-work: add the flag with a proper `Sources::reify()` helper
  that lets the orchestrator replay the same logical input twice.

- **`matching::substring` as keyword pre-filter.** vyre's
  `substring_search(haystack, needle)` is a single-needle GPU
  primitive; keyhog's `has_secret_keyword_fast` checks an N-keyword
  set. Wrong shape for direct replacement. The vyre-side equivalent
  would be `matching::classic_ac` or `matching::cooperative_dfa`
  for multi-pattern; both are GPU IR builders that need a custom
  dispatch wrapper to use.

- **`matching::cooperative_dfa` as alternative literal engine.**
  Real candidate but adds a third backend variant alongside
  `Gpu` (literal-set) and `MegaScan` (regex-NFA). Defer until we
  can benchmark vs the megakernel literal-DFA path landing in
  the next session.

- **`fuse_programs` for decode + scan.** Need to pre-compose
  `decode::inflate` (or `decode::ziftsieve`) with `GpuLiteralSet` /
  `RulePipeline` programs into one dispatch via
  `vyre_foundation::execution_plan::fusion::fuse_programs`. Modest
  perf win on `.zst`-heavy corpora (npm, Docker layers) but no
  effect on regular source trees. ~2 days.

- **`nn::moe` replacing the hand-rolled MoE in `gpu.rs`.** ~620 LoC
  of bespoke wgpu+WGSL gone, composed from `vyre_libs::nn::{moe,
  linear, activation, norm}`. Risky parity work — needs bit-equal
  output validation against `ml_scorer.rs` on the existing weight
  set. ~3 days.

- **`runtime::uring::GpuMappedBuffer` for filesystem reads.**
  Eliminates a 256 MiB heap → GPU memcpy per batch on big files.
  Linux-only (io_uring); needs vyre-runtime `uring` feature opt-in
  + careful `GpuStream<'a>` lifetime work in `sources/filesystem/
  read.rs`. ~3 days.

- **vyre `rule` engine for declarative `.keyhogignore.toml`.**
  Vyre's `RuleCondition` AST (PatternExists, PatternCountGte,
  FileSizeGt, RegexMatch, SubstringMatch, RangeMatch,
  SetMembership, PrefixMatch, SuffixMatch + And/Or/Not) is a
  superset of keyhog's current line-based `.keyhogignore`. UX win,
  not perf. The conditions need a CPU evaluator since vyre's
  built-in evaluator is GPU-IR based — ~50 LoC plus a TOML schema.
  ~1 day.

## What blocks "max usage" right now

- **vyre's regex frontend `STATE_CAP = LANES × 32 = 1024` states.**
  The full 888-detector corpus compiles to an NFA larger than that
  (ballpark 25k states), so MegaScan currently auto-degrades to the
  literal-set path on the production corpus. Lifted upstream when
  vyre adds either (a) per-subgroup state batching or (b) a
  multi-pipeline dispatch that splits the regex set across multiple
  RulePipelines + a megakernel. Keyhog-side batching was prototyped
  and is feasible, but ~120 sequential GPU dispatches add ~240 ms of
  setup overhead — slower than literal-set on the full corpus.
  Megakernel fusion (item 8) is the right fix.

- **vyre's regex frontend MAX_REP cap.** The vendored v0.6.0 caps
  bounded repetitions at `{0,64}` / `{,64}`; upstream HEAD has this
  removed (the state-cap is the source of truth). A re-vendor against
  HEAD picks it up but currently breaks dep-version pinning across
  the workspace (rayon `=1.11` vs `=1.12`, smallvec `=1.14` vs `^1.15.1`,
  …) and renames + adds workspace members. The vyre-side fix lands
  when an upstream tag releases with pin-relaxed dependency
  declarations.

- **Vyre is not on crates.io.** All path-deps in `vendor/vyre/`. This
  blocks `cargo publish` of `keyhog-scanner` and `keyhog` (the binary
  crate). Resolved when vyre publishes its workspace to crates.io.

## Realistic shipping cadence

Items 1 was a single session. Items 2–7 are each a multi-day scope
of work — wiring a vyre primitive end-to-end into keyhog requires:
adding the dependency feature, writing the dispatch glue, validating
against the existing path, and shipping correctness tests.

"Wire all" of vyre is multi-month engineering. The audit above is
the work plan; pick from items 2–8 by user priority.
