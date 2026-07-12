# Vyre primitive usage - audit & roadmap

Status snapshot of which vyre primitives keyhog consumes, what the
full vyre surface looks like, and a prioritised list of wires worth
making next. Vyre is a ~30-crate GPU compute framework - this doc
catalogues every crate it ships so future wires don't have to
re-discover the surface.

Updated 2026-06-19. The workspace pins all five runtime `vyre*` crates at
`=0.6.4` (vyre v0.6.4) from crates.io (root `Cargo.toml`, `[workspace.dependencies]`). That
release carries the literal-set region APIs Keyhog imports, including
`GpuLiteralSet::scan_presence_by_region_with_scratch`
(`engine/gpu_region_dispatch.rs` via `engine/gpu_literal_scratch.rs`). The
repository carries no `vendor/` source tree; the exact crates.io pins are the
only Vyre source for builds.

## What keyhog uses today

| Vyre symbol                                          | Where keyhog uses it                                                |
| ---------------------------------------------------- | ------------------------------------------------------------------- |
| `vyre_libs::scan::GpuLiteralSet`                     | `engine/gpu_lazy.rs::gpu_matcher` - literal trigger producer        |
| `GpuLiteralSet::scan_presence_with_scratch`          | `engine/gpu_literal_scratch.rs` - per-chunk trigger presence without hot-loop scratch allocation |
| `GpuLiteralSet::scan_presence_by_region_with_scratch` | `engine/gpu_literal_scratch.rs` called by `engine/gpu_region_dispatch.rs` - one batched region row per chunk |
| `vyre_libs::scan::build_regex_dfa_unanchored`        | `engine/phase2_gpu_dfa.rs` - GPU regex-DFA admission for prefixless detectors (production); also exercised by `tests/vyre_megakernel_primitive_probe.rs` |
| `vyre_runtime::megakernel::BatchRuleProgram`         | Standalone `tests/vyre_megakernel_primitive_probe.rs` only (the retired per-rule catalog primitive; not a production engine path) |
| `vyre_driver_wgpu::megakernel::{BatchDispatcher, FileBatch, HitRecord}` | Standalone `tests/vyre_megakernel_primitive_probe.rs` only |
| `vyre_libs::scan::LiteralMatch`                      | Re-exported as `keyhog_scanner::LiteralMatch` for API stability     |
| `vyre_libs::scan::cached_load_or_compile`            | On-disk cache for compiled GPU literal-set programs                 |
| `vyre_libs::intern::perfect_hash::PerfectHash`       | `static_intern.rs` - frozen detector-metadata interner              |
| `vyre_libs::intern::perfect_hash::build_chd`         | Same - built once at scanner construction                           |
| `vyre_driver_wgpu::WgpuBackend`                      | `engine/compile.rs` acquires it as an `Arc<dyn VyreBackend>` when CUDA is unavailable |

Current production scanner consumers are `engine/gpu_lazy.rs`,
`engine/gpu_literal_scratch.rs`, `engine/gpu_region_dispatch.rs`,
`engine/phase2_gpu_dfa.rs`, `engine/compile.rs`, `gpu.rs`, and
`static_intern.rs`. The per-rule megakernel catalog is not a production engine
module.

## Full vyre crate surface

### vyre-foundation

The IR + execution-plan crate. Provides:

- `ir` - typed Program IR (Node, Expr, BufferDecl, BufferAccess, DataType)
- `lower`, `optimizer` - lowering passes + optimisation passes
- `cpu_op`, `cpu_references` - CPU reference impls of every op
- `memory_model`, `MemoryOrdering` - formal memory model
- `match_result::Match` - the `(pattern_id, start, end)` triple keyhog
  already consumes via `LiteralMatch`
- `extern_registry`, `dialect_lookup`, `algebraic_law_registry` -
  pluggable dialect/op/law registry
- `composition`, `execution_plan::fusion::{fuse_programs, ...}` -
  cross-program fusion (multiple Programs into one dispatch)
- `vast`, `graph_view` - IR graph traversal
- `diagnostics` - typed diagnostic messages
- `opaque_payload` - type-erased per-op state

**Keyhog touches**: `match_result::Match` indirectly via vyre_libs.
**Keyhog could use**: `fuse_programs` to fuse decode + scan into one
dispatch; `execution_plan` for batched multi-stage pipelines.

### vyre-driver

The dispatch backbone:

- `backend` - `VyreBackend` trait; every concrete backend implements it
- `routing::{select_sort_backend, RoutingTable, SortBackend}` - picks
  best backend per workload
- `pipeline` - backend-agnostic dispatch
- `registry` - backend registry
- `shadow`, `speculate` - speculative + shadow execution (run on two
  backends, compare results)
- `persistent` - long-lived dispatch state

**Keyhog touches**: nothing directly.
**Keyhog could use**: `routing::select_sort_backend` for MegaScan
pipeline ordering; `shadow` to validate GPU vs CPU on every dispatch
in CI.

### vyre-driver-wgpu

The wgpu backend:

- `WgpuBackend`, `WgpuBackendStats`, `WgpuIR` - concrete dispatch
- `pipeline`, `buffer`, `lowering` - wgpu-specific compile
- `megakernel`, `spirv_backend`, `engine`, `ext` - speciality dispatch
  modes
- `runtime` - `cached_device`, `GpuMappedBuffer` (uring-backed)
- `DispatchArena` - per-dispatch scratch arena

**Keyhog touches**: `WgpuBackend`, `runtime::cached_device`.
**Keyhog could use**: `runtime::GpuMappedBuffer` for io_uring-backed
filesystem reads straight into GPU memory; `DispatchArena` for
shared scratch buffers across batched dispatches.

### vyre-driver-megakernel

Megakernel dispatcher: bundles many small ops into one kernel
launch. Useful when dispatch overhead dominates throughput.

- `MegakernelDispatch` trait
- `policy`, `task` - scheduling primitives

**Keyhog could use**: bundling literal-set + boundary scan + entropy
prefilter into one megakernel (eliminates ~4 ms × 4 dispatches per
batch).

### vyre-driver-spirv

The SPIR-V backend (Vulkan-only path). Same surface as wgpu.

### vyre-driver-cuda

CUDA backend, shipped through the workspace `cuda` feature via
`vyre-driver-cuda = 0.6.4`.

### vyre-driver-reference

CPU reference backend - runs every op via `vyre-reference` for
correctness validation.

### vyre-libs

Tier-3 application primitives (composed from `vyre-primitives`).
Modules:

- **matching** ✅ partly used: `GpuLiteralSet`, `RulePipeline`,
  `dedup_regions_inplace`. Unused: `classic_ac`, `cooperative_dfa`,
  `dfa/`, `direct_gpu`, `substring/`, `pipeline`, `post_process`,
  `hit_buffer`, `engine`, `builders`, `dispatch_io`, `test_fixtures`.
- **decode**: `base64`, `hex`, `inflate`, `ziftsieve`, `encodex`,
  `streaming` - GPU-IR decoders. Unused (keyhog has its own CPU
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
- **text**: `char_class` - byte→class-code mapper. Different shape
  from keyhog's `alphabet_filter` (bitset of present bytes), so not a
  drop-in. Could power a future syntax-aware context detector.
- **math**: `algebra`, `atomic/`, `avg_floor`, `broadcast/`,
  `clamp_u32`, `linalg/`, `lzcnt_u32`, `reduce_mean`, `scan/`, `square`,
  `succinct`, `tzcnt_u32`, `wrapping_neg`. Numeric kernels.
- **logical**: `and`, `or`, `xor`, `nand`, `nor` - bitmap ops.
- **parsing**: parser combinators on GPU.
- **graph**: graph algorithms (reachability, dominators).
- **dataflow**: taint-flow analysis.
- **security**: `auth_check_dominates`, `bounded_by_comparison`,
  `buffer_size_check`. Static-analysis predicates - wrong domain.
- **representation**: IR helpers.
- **compiler**: program compiler.
- **visual**: viz helpers.
- **harness**: test harness for primitive correctness.
- **builder**: `BuildOptions`, `check_tensors`.
- **descriptor**: `BufferDescriptor`, `ProgramDescriptor`.
- **buffer_names**: stable buffer-name constants.
- **range_ordering**, `region`, `tensor_ref`, `signatures`,
  `contracts`, `test_migration` - plumbing.

### vyre-primitives

Tier-2.5 primitives that vyre-libs composes. Each module is a
collection of single-op IR builders:

- **bitset**: 18 ops - `and`, `and_into`, `and_not`, `and_not_into`,
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
- `replay::{RecordedSlot, ReplayLogError, RingLog}` - record-replay
  for deterministic re-execution
- `routing` - runtime routing
- `tenant` - multi-tenant dispatch
- `uring::{GpuStream, GpuMappedBuffer}` - io_uring-backed GPU memory

**Keyhog could use**: `replay::RingLog` for deterministic scan
reruns; `uring::GpuMappedBuffer` for zero-copy file→GPU.

### vyre-spec

Formal vyre specification:

- `algebraic_law`, `all_algebraic_laws` - algebraic identities
- `atomic_op`, `bin_op`, `buffer_access`, `data_type`, `expr_variant`
- `engine_invariant` - runtime invariants
- `extension`, `convention`, `category`, `by_category`, `by_id`,
  `catalog_is_complete`
- `adversarial_input` - invariants under adversarial input

This is the contract every backend implements. Consumers of vyre
don't generally need it.

### vyre-intrinsics

Hardware intrinsics + category checks:

- `category_check`, `hardware`, `region`, `harness`
- Re-exports from `vyre_foundation::cpu_op` (CategoryAOp, CpuOp,
  structured_intrinsic_cpu)

### vyre-reference

CPU reference implementation of every primitive - used for
correctness validation:

- `dual`, `primitive`, `primitives`, `value`
- `atomics`, `cpu_op`, `dialect_dispatch`
- `eval_expr`, `eval_node`, `flat_cpu`
- `ieee754`
- `interp`, `sequential`, `subgroup`, `workgroup` - execution models

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

## v0.5.41 integration status

| Wire                                 | Status      | Where                                                  |
| ------------------------------------ | ----------- | ------------------------------------------------------ |
| `intern::perfect_hash`               | ✅ shipped  | `crates/scanner/src/static_intern.rs` + `engine/mod.rs` |
| Measured-safe GPU heuristic routing  | ✅ shipped  | `crates/scanner/src/hw_probe.rs`                       |
| GPU region-presence dispatch         | ✅ shipped  | `engine/gpu_region_dispatch.rs::scan_coalesced_gpu_region_presence` |
| GPU regex-DFA admission (prefixless)  | ✅ shipped  | `engine/phase2_gpu_dfa.rs` via `build_regex_dfa_unanchored`            |
| `rule` CPU evaluator + `FieldInSet`  | ✅ shipped  | upstream `vyre_libs::rule::cpu_eval` + `ast.rs`        |
| `.keyhogignore.toml` rule engine     | ✅ shipped  | `crates/core/src/rule_filter.rs` + `orchestrator.rs`   |
| Standalone Vyre megakernel probe     | measured    | `crates/scanner/tests/vyre_megakernel_primitive_probe.rs` |
| `cooperative_dfa` alt literal engine | not integrated | requires a distinct KeyHog GPU dispatch contract (entry below) |
| `fuse_programs` decode+scan          | not integrated | requires a unified source/scanner execution contract (entry below) |
| `nn::moe` replacing gpu.rs MoE       | not integrated | requires parity proof against the shipped weights (entry below) |
| `GpuMappedBuffer` zero-copy I/O      | not integrated | requires an explicit Linux lifetime/ownership contract (entry below) |
| Vyre crate upgrade                   | current     | crates.io latest verified as `0.6.4` on 2026-06-17    |

## Performance direction

The performance path that can dominate competitors is not more regexes; it is
fewer host/device round trips and less CPU post-processing after a GPU prefilter
hit. The lane is:

1. Make GPU routing non-silent on known GPU hosts through `--require-gpu`
   gates and benchmark backend traces.
2. Keep the current sharded `GpuLiteralSet` path as the production floor.
3. Upgrade Vyre as soon as a published release exposes per-pattern hit reporting
   for the megakernel DFA path.
4. Fuse decode, literal matching, boundary extraction, entropy scoring, and
   confidence prefeatures into one resident GPU program when parity gates pass.
5. Measure against CPU/SIMD/GPU on the same corpus artifact before changing
   routing thresholds.

This is the categorical advantage over Betterleaks, Titus, Nosey Parker, and
Kingfisher: one scanner surface with GPU-prefilter, decode-through recall,
structured-source expansion, verification, and deterministic backend parity.

## Available integration entry points

Each remaining wire's API surface in vyre + the keyhog hook where
the integration lands. The unblocker for each is real engineering,
not new research - anyone picking up the work has the contract.

### `cooperative_dfa`

- Vyre API: `vyre_libs::matching::cooperative_dfa::cooperative_dfa_scan(input, transitions, accept_mask, matches, input_len, state_count, subgroup_size) -> vyre::ir::Program`
- Build DFA tables via `vyre_libs::matching::dfa::dfa_compile(&[&[u8]]) -> CompiledDfa`
- Compile Program once at scanner construction via vyre `pipeline::compile`
- Per-batch dispatch: upload input/transitions/accept, allocate matches, call `pipeline.dispatch_borrowed(...)`, read back
- Wire as a new `ScanBackend::CooperativeDfa` variant alongside `Gpu` and `MegaScan`. Route via `select_backend` once benchmarked vs literal-set.
- Scope: new backend variant, dispatch wrapper, parity tests, and benchmark
  threshold update.

### `fuse_programs` for decode + scan

- Vyre API: `vyre_foundation::execution_plan::fusion::fuse_programs(&[Program]) -> Result<Program, FusionError>`
- Build a decode Program: `vyre_libs::decode::inflate(...)` for `.zst` / `.gz` inputs
- Build a scan Program: `vyre_libs::matching::cooperative_dfa::cooperative_dfa_scan(...)`
- `fuse_programs(&[decode_prog, scan_prog])` produces one Program; vyre auto-resolves shared buffer names (decode's output buffer should be named the same as scan's input buffer).
- Source-side: `crates/sources/src/filesystem/read.rs` currently CPU-decompresses via `ziftsieve` then hands plaintext to `scan_coalesced`. Switch `.zst` / `.gz` inputs to keep compressed bytes + dispatch fused program.
- Scope: source/scanner boundary refactor, fused-program construction, parity
  tests against CPU decompression, and compressed-corpus benchmark artifact.
- Payoff: ~50% wall-time reduction on `.zst`-heavy corpora (npm, Docker image layers); zero effect on regular source trees.

### `nn::moe` replacing `gpu.rs` MoE

- Vyre API: `vyre_libs::nn::moe::moe_gate`, `vyre_libs::nn::moe::top_k`,
  `vyre_libs::nn::linear`, `vyre_libs::nn::activation`, `vyre_libs::nn::norm` -
  compose the same MoE shape `gpu.rs` hand-rolls.
- Existing `gpu.rs` is ~620 LoC of bespoke wgpu+WGSL implementing
  Linear(41→6) gate + 6 experts × Linear(41→32)+ReLU →
  Linear(32→16)+ReLU → Linear(16→1) + sigmoid weighted sum.
- Bit-equal validation against `ml_scorer.rs`'s CPU MoE outputs on
  the existing weight set. The weights load path stays the same;
  only the dispatch path swaps.
- Scope: replace the existing GPU MoE dispatch path and add a parity test harness
  that compares MoE
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
- Scope: Linux-only source/scanner lifetime threading and routing fallback;
  Windows / macOS keep the read-then-copy path.
- Payoff: eliminates a 256 MiB heap → GPU memcpy per batch on
  big-file scans.

## Performance benchmark snapshot (RTX 5090, v0.5.4 + tier routing)

After landing tier-aware routing + GPU dispatch sharding, the embedded
`keyhog scan --benchmark` corpus (100 × 1 MiB chunks of realistic
source-code shape with a known-secret suffix per chunk) reports:

```
cpu-fallback : 130 MiB/s  (302168 findings)
simd-regex   : 136 MiB/s  (304128 findings)
gpu-region-presence:  34 MiB/s  (303554 findings)
```

Recall is now correct across all three backends (the prior `121×
speedup` number on the entropy-trap fixture was lying - GPU was
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

1. ✅ **`intern::perfect_hash` for static-string interning** - DONE.
   Scanner now hands out `Arc<str>` for `(detector_id, name, service,
   source_type)` from a frozen CHD perfect hash, lock-free, no
   per-scan allocation.

1.5. ✅ **Measured-safe GPU heuristic routing + dispatch sharding** - DONE.
   `select_backend` classifies the active GPU into High/Mid/Low and
   uses conservative tier-specific thresholds (128 MiB / 256 MiB /
   512 MiB) after the live RTX 5090 region-presence sweep failed to
   beat CPU/SIMD through 64 MiB. Per-tier pattern-count breakeven
   remains 100 / 500 / 2000. GPU dispatch
   now shards at 65535 × 32 = ~2 MiB per dispatch to respect the
   wgpu workgroup-per-dimension cap. `keyhog backend` reports the
   active tier and effective heuristic thresholds; install-time
   autoroute calibration remains the fastest-correct selection path.

2. **`rule` engine for inline-suppression / allowlist.**
   The current allowlist is hand-rolled string matching. Vyre's `rule`
   exposes typed predicates (`file_size_gt`, `pattern_count_gte`,
   `pattern_exists`, …) that compose into rule trees. Wins:
   declarative `.keyhogignore.toml` (`suppress when file_size > 10K AND
   pattern_count(test_kw) >= 2`); user-defined gates; consistent eval
   model. Scope: schema, parser, evaluator wiring, and suppressions parity
   tests.

3. **`runtime::uring::GpuMappedBuffer` for filesystem reads.**
   `crates/sources/src/filesystem/read.rs` reads file content into
   `Vec<u8>` then copies to GPU. `GpuMappedBuffer` io_urings the file
   directly into a GPU-mapped buffer - eliminates a 256 MiB copy per
   batch on the GPU dispatch path. Scope: vyre-runtime feature opt-in, source
   lifetime work, and read-vs-mapped throughput gates.

4. **`fuse_programs` to bundle decode + scan dispatches.**
   When scanning a `.zst` archive today: read on CPU → decode on CPU
   (`ziftsieve`) → copy plaintext to GPU → dispatch literal-set. With
   `fuse_programs(decode::inflate, GpuLiteralSet)` it becomes one GPU
   dispatch. Saves ~50% wall time on compressed-corpus scans. Scope:
   fused-program builder, compressed-input source contract, and compressed-corpus
   benchmark gate.

5. **`nn::moe` + `nn::linear` replacing `gpu.rs`'s hand-rolled MoE.**
   `gpu.rs` is ~620 lines of bespoke wgpu+WGSL for an MoE confidence
   scorer. Vyre's `nn::moe` is the same algorithm composed from
   `nn::linear` + `nn::activation` + `nn::norm`. Wins: ~600 lines
   deleted, automatic benefit from vyre kernel improvements. Risk:
   medium - needs parity tests against `ml_scorer.rs` outputs.
   Scope: GPU MoE replacement plus CPU/current-GPU/new-Vyre-GPU parity.

6. **`shadow`/`speculate` for CI dispatch validation.**
   In CI, run every GPU dispatch on TWO backends (vyre-driver-wgpu +
   vyre-driver-reference) and assert identical results. Catches GPU
   driver regressions before users see them. Scope: backend shadow dispatch
   contract and CI-only routing.

7. **`replay::RingLog` for deterministic scan rerun.**
   Record every dispatch + result; on a flaky test, replay the exact
   same sequence to bisect. Useful for debugging GPU non-determinism
   reports. Scope: replay log plumbing and deterministic rerun test.

8. 🟡 **Move the per-chunk extraction tail onto the GPU** - PARTIALLY SHIPPED.
   The first stage landed: `engine/phase2_gpu_dfa.rs` runs a GPU regex-DFA
   *admission* pass (`vyre_libs::scan::build_regex_dfa_unanchored`) after
   region-presence, so the regex check for prefixless detectors - the ones the
   literal-set prefilter cannot trigger - now runs on the GPU instead of the CPU
   (`gpu_region_dispatch.rs::scan_coalesced_gpu_region_presence` builds the
   admission workload, dispatches it, and treats CPU admission as authoritative
   if the GPU pass errors). Still CPU-side after the prefilter: full per-detector
   regex *extraction* of the admitted candidates, entropy scoring, and ML
   inference. The benchmark above shows that remaining serial CPU work is what
   caps throughput at ~135 MB/s, so finishing entropy + ML fusion is the
   next win.

   This did NOT and must NOT use Vyre's per-rule `vyre-runtime::megakernel`
   `BatchDispatcher` / `BatchRuleProgram` API. That primitive models one DFA per
   detector, which is the `chunks × rules` shape the RTX 5090 testing found to be
   the wrong production primitive (see "Production GPU trigger route" below); it
   is retired from the scan path and survives only as a Vyre validation probe in
   `tests/vyre_megakernel_primitive_probe.rs`. The GPU extraction work uses the coalesced
   region/regex-DFA primitives instead, for the same one-pass-over-the-batch
   reason region-presence replaced the literal megakernel.

   Scope for the remaining stage: lower entropy + MoE scoring to GPU IR (or fuse
   them into the admission dispatch), CPU/GPU parity on the admitted candidate
   set, and a benchmark-threshold update. Biggest single perf win still
   available.

9. **CPU-side entropy-fast SIMD-isation.**
   The benchmark shows per-chunk extraction is the bottleneck even
   without megakernel. `crates/scanner/src/entropy_fast.rs` already
   has thread-local FNV cache; widening the byte histogram to AVX-512
   (16-lane gather + popcnt) would lift per-chunk throughput 2-4×
   without GPU work. Scope: AVX-512 implementation, scalar fallback, and criterion
   perf gate.

## Production GPU trigger route

The production batched GPU path is `engine/gpu_region_dispatch.rs`:
`scan_coalesced_gpu_region_presence` reuses one thread-local coalesced
lowercase haystack scratch from `engine/gpu_region_batch.rs`, records one
`region_starts` entry per chunk, calls
`GpuLiteralSet::scan_presence_by_region_with_scratch` through
`engine/gpu_literal_scratch.rs`, converts each region row through
`triggered_patterns_from_gpu_presence`, and then hands the bitmap to the shared
`scan_coalesced_phase2` tail.

The retired per-rule megakernel catalog is not a production module.
`engine/megakernel.rs`, `engine/megakernel_triggers.rs`,
`engine/megakernel_wire.rs`, the concrete `wgpu_backend` scanner field,
and the `MegakernelCatalog` dispatch hook were removed. The standalone
`tests/vyre_megakernel_primitive_probe.rs` target remains a Vyre primitive probe only; it
do not describe the shipped Keyhog scan route.

Architectural finding from RTX 5090 testing: Vyre's `BatchDispatcher`
fits "many files × few rules" better than Keyhog's "few files × many
rules" detector set. Modelling each literal as a separate
`BatchRuleProgram` created `chunks × rules` work and was the wrong
production primitive. Region presence uses one literal-set automaton
pass over the coalesced batch and returns the exact per-chunk trigger
bitmap Keyhog needs.

## Remaining Vyre Wires

- **`shadow`/`speculate` for CI dispatch validation.** vyre's shadow
  module is for validating ops against multiple backends inside vyre;
  not directly applicable to keyhog. The keyhog-side equivalent is
  `tests/gpu_parity.rs` which already runs every CI build. A
  `--validate-backend` CLI flag for runtime opt-in dual dispatch
  was prototyped but reverted: cleanly hijacking `scan_sources` to
  re-run with a forced backend needs source iterator re-creation,
  which requires a proper `Sources::reify()` helper that lets the
  orchestrator replay the same logical input twice.

- **`matching::substring` as keyword pre-filter.** vyre's
  `substring_search(haystack, needle)` is a single-needle GPU
  primitive; keyhog's `has_secret_keyword_fast` checks an N-keyword
  set. Wrong shape for direct replacement. The vyre-side equivalent
  would be `matching::classic_ac` or `matching::cooperative_dfa`
  for multi-pattern; both are GPU IR builders that need a custom
  dispatch wrapper to use.

- **`matching::cooperative_dfa` as alternative literal engine.**
  Real candidate but adds a third backend variant alongside
  `Gpu` (literal-set) and `MegaScan` (regex-NFA). Benchmark it
  against the megakernel literal-DFA path before adding the route.

- **`fuse_programs` for decode + scan.** Need to pre-compose
  `decode::inflate` (or `decode::ziftsieve`) with `GpuLiteralSet` /
  `RulePipeline` programs into one dispatch via
  `vyre_foundation::execution_plan::fusion::fuse_programs`. Modest
  perf win on `.zst`-heavy corpora (npm, Docker layers) but no
  effect on regular source trees.

- **`nn::moe` replacing the hand-rolled MoE in `gpu.rs`.** ~620 LoC
  of bespoke wgpu+WGSL gone, composed from `vyre_libs::nn::{moe,
  linear, activation, norm}`. Risky parity work - needs bit-equal
  output validation against `ml_scorer.rs` on the existing weight
  set.

- **`runtime::uring::GpuMappedBuffer` for filesystem reads.**
  Eliminates a 256 MiB heap → GPU memcpy per batch on big files.
  Linux-only (io_uring); needs vyre-runtime `uring` feature opt-in
  + careful `GpuStream<'a>` lifetime work in `sources/filesystem/
  read.rs`.

- **vyre `rule` engine for declarative `.keyhogignore.toml`.**
  Vyre's `RuleCondition` AST (PatternExists, PatternCountGte,
  FileSizeGt, RegexMatch, SubstringMatch, RangeMatch,
  SetMembership, PrefixMatch, SuffixMatch + And/Or/Not) is a
  superset of keyhog's current line-based `.keyhogignore`. UX win,
  not perf. The conditions need a CPU evaluator since vyre's
  built-in evaluator is GPU-IR based - ~50 LoC plus a TOML schema.
  ~1 day.

## What blocks "max usage" right now

- **vyre's regex frontend `STATE_CAP = LANES × 32 = 1024` states.**
  The full 902-detector corpus compiles to an NFA larger than that
  (ballpark 25k states), so MegaScan currently auto-degrades to the
  literal-set path on the production corpus. Lifted upstream when
  vyre adds either (a) per-subgroup state batching or (b) a
  multi-pipeline dispatch that splits the regex set across multiple
  RulePipelines + a megakernel. Keyhog-side batching was prototyped
  and is feasible, but ~120 sequential GPU dispatches add ~240 ms of
  setup overhead - slower than literal-set on the full corpus.
  Megakernel fusion (item 8) is the right fix.

- **vyre regex/frontend release cadence.** crates.io's latest published Vyre
  release used by Keyhog is `0.6.4`. The workspace resolves the five runtime
  `vyre*` crates from exact registry pins, and the GPU regex-DFA admission path imports
  `vyre_libs::scan::build_regex_dfa_unanchored` from that release. Future
  upgrades bump the workspace pins, run
  `python3 scripts/gates/vyre_pin_consistency.py`, then run scanner GPU/CPU
  parity plus source aggregate gates. Do not recreate repository vendored
  source trees for Vyre or any other dependency.

## Shipping gates

Each wire requires the same gates: dependency feature, dispatch glue, CPU/GPU
parity, adversarial corpus replay, benchmark artifact, and routing-threshold
update. The work is complete only when the benchmark and parity artifacts agree
at the same commit.
