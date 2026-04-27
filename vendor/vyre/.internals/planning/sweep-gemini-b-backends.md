# Sweep Plan — Gemini B: Backends & Performance

**Agent:** Gemini 3.1-pro, launched in Antigravity, unlimited.
**Peer:** Gemini A is running in parallel on a different tree (ops +
dialects). Claude is running the substrate (types, workspace-wide match
rewrite, wire format, deletion, docs, parity). You do not talk to A; you
read the git log for handshake points.

**Scope lock:**
- You may edit: `vyre-wgpu/src/{backend,pipeline,engine,lowering/naga_emit}.rs`
  and anything else in `vyre-wgpu/src/` EXCEPT the subtrees owned by
  Gemini C. `vyre-reference/src/**` (all of it). `vyre-wgpu/tests/*baseline*.rs`
  + the dispatch-correctness tests.
- You may NOT edit: `vyre-wgpu/src/{buffer,runtime,lowering/fusion,
  spirv_backend,megakernel}/**` or `vyre-wgpu/src/lib.rs` (Gemini C
  appends to lib.rs for its new modules — you don't touch lib.rs after
  your B-B1 initial edit), `vyre-core/src/ir/**`, `vyre-core/src/dialect/**`
  (Gemini A), `vyre-dialect-crypto/**` (Gemini A), `vyre-primitives/**`.

**Division of vyre-wgpu/src between B and C:**
- B owns: `backend.rs`, `pipeline.rs`, `engine/**`, `lowering/naga_emit.rs`,
  `lib.rs` (one-time edit to add module tree).
- C owns: `buffer/**`, `runtime/**`, `lowering/fusion.rs` (new),
  `spirv_backend.rs` (new), `megakernel.rs` (new), perf benches and
  perf-specific tests.

**Handshake — when to start each step:**
- **Step 0 (start condition):** wait for commit whose subject begins
  `A-B0:` (Gemini A foundation types). Fast (~5-10 min).
- **Step B3 pause:** after B-B2 lands, wait for `A-B3:` (Gemini A
  finished built-in ops migration) before starting B-B3.
- **Step B5 is your last step.** After B-B5 lands, Gemini C picks up
  for the perf blitz (you do NOT run perf work — that's Gemini C's
  scope).

**Commit prefix:** every commit subject must begin with `B-B<step>:`.
Claude and Gemini A watch the log for these.

**Rules of engagement:**
- Direct to main. No branches, no worktrees.
- Narrow `cargo check -p vyre-wgpu` during iteration. Full workspace
  check only at step end.
- No `todo!()`, `unimplemented!()`, `panic!("not implemented")`,
  "documented limitation" comments, or test-weakening.
- No `#[cfg(not(feature="gpu"))]` fallbacks — GPU is always present
  (RTX 5090). Write GPU code; do not write conditional CPU fallback for
  the same op.
- Every test you add asserts something meaningful. No `let _ = result;`.

---

## Step B-B1 — vyre-wgpu consumes LoweringTable

Drop every `OpSpec::intrinsic` read path in `vyre-wgpu`. Replace with:

1. Backend walks `DialectRegistry::get_lowering(op_id, Target::Wgsl)` to
   get a `fn(&LoweringCtx) -> naga::Module`.
2. Calls the fn to build the naga::Module.
3. Validates via `naga::valid::Validator`.
4. Emits WGSL via `naga::back::wgsl::write_string`.
5. Feeds WGSL to `wgpu::Device::create_shader_module`.

Register the backend's capability:
```rust
inventory::submit! {
    vyre::dialect::BackendRegistration {
        name: "wgpu",
        supports_dialects: &[
            ("core",           SemverReq::caret("1.0")),
            ("math",           SemverReq::caret("1.0")),
            ("bitwise",        SemverReq::caret("1.0")),
            ("compare",        SemverReq::caret("1.0")),
            ("logical",        SemverReq::caret("1.0")),
            ("float",          SemverReq::caret("1.0")),
            ("atomics",        SemverReq::caret("1.0")),
            ("compression",    SemverReq::caret("1.0")),
            ("hash",           SemverReq::caret("1.0")),
            ("string_matching",SemverReq::caret("1.0")),
            ("decode",         SemverReq::caret("1.0")),
            ("workgroup",      SemverReq::caret("1.0")),
            ("security_detection", SemverReq::caret("1.0")),
            ("pattern",        SemverReq::caret("1.0")),
        ],
        validate: validate_wgpu_program,
        execute: execute_wgpu_program,
    }
}
```

A Program whose `dialect_manifest` references a dialect not in this list
fails Law C (capability negotiation) cleanly.

### Verification

- `cargo check -p vyre-wgpu` → 0 errors.
- `cargo test -p vyre-wgpu --lib` passes.
- No `OpSpec::intrinsic`, no `wgsl_only`, no `IntrinsicDescriptor`
  anywhere in `vyre-wgpu/src`.

### Commit

`B-B1: vyre-wgpu dispatches via LoweringTable (drop OpSpec::intrinsic read path)`

---

## Step B-B2 — Persistent GPU tier (folds D3)

This is the work codex failed at twice when attempted standalone. It slots
in now because B-B1 just removed the old `OpSpec::intrinsic` allocation
path that fought against persistent buffers.

### New files

- `vyre-wgpu/src/buffer/handle.rs` — `GpuBufferHandle`:
  ```rust
  pub struct GpuBufferHandle {
      buffer: Arc<wgpu::Buffer>,
      byte_len: u64,
      element_count: u64,
      usage: wgpu::BufferUsages,
  }

  impl GpuBufferHandle {
      pub fn upload(device: &wgpu::Device, queue: &wgpu::Queue,
                    data: &[u8], usage: wgpu::BufferUsages) -> Self;
      pub fn alloc(device: &wgpu::Device, len: u64,
                   usage: wgpu::BufferUsages) -> Self;
      pub fn readback(&self, device: &wgpu::Device, queue: &wgpu::Queue,
                      out: &mut Vec<u8>) -> Result<(), BackendError>;
      // Clone is cheap (Arc).
  }
  ```

- `vyre-wgpu/src/buffer/pool.rs` — `BufferPool`:
  - `acquire(len, usage) -> Pooled<GpuBufferHandle>` returns the smallest
    free buffer ≥ `len.next_power_of_two()` with matching usage, or
    allocates fresh.
  - `Pooled<T>` is a smart pointer: on `Drop` it returns the underlying
    buffer to the pool. Cheap.
  - LRU eviction once retained VRAM > 1 GiB (configurable via
    `VYRE_BUFFER_POOL_BUDGET_BYTES` env var).
  - Pool exposes atomic counters: `allocations_total`, `reuses_total`,
    `current_bytes`, `peak_bytes`.

### New dispatch entry point

`vyre-wgpu/src/pipeline.rs` adds alongside the legacy `dispatch(&[u8])`:

```rust
impl WgpuPipeline {
    pub fn dispatch_persistent(
        &self,
        inputs: &[GpuBufferHandle],
        outputs: &mut [GpuBufferHandle],
        params: Option<&GpuBufferHandle>,
        workgroups: [u32; 3],
    ) -> Result<(), BackendError>;

    pub fn dispatch_persistent_batched(
        &self,
        items: &[DispatchItem<'_>],
    ) -> Result<(), BackendError>;  // one queue.submit for many dispatches
}
```

BindGroup caching: `(pipeline_hash, binding_signature) -> wgpu::BindGroup`
keyed by the concrete GpuBufferHandle pointer identities. Hit ratio
tracked via atomic counters.

### DFA double-round-trip collapse

Find the match-ops dispatch path that currently does:
1. dispatch count-matches kernel
2. readback count
3. allocate output sized to count
4. dispatch extract-matches kernel
5. readback matches

Collapse to: one dispatch, output sized to `workload × max_matches_per_element`,
atomic-append counter, one readback. On overflow, re-dispatch with doubled
capacity. Measured 2-3× throughput win.

### Legacy compatibility

`dispatch(&[u8])` keeps working. It becomes a thin wrapper that uploads
inputs on demand and calls `dispatch_persistent`. Existing call sites
must not break.

### Tests

`vyre-wgpu/tests/persistent_dispatch.rs`:
- **Allocation count assertion:** compile a XOR program, upload input once,
  dispatch 1000×, pool stats show allocations_total ≤ 6 after warmup (1
  input + 1 output + 1 params + 1 readback + ≤2 reuse overhead).
- **BindGroup cache:** assert cache hit ratio ≥ 99% after the first
  dispatch in a 1000-iteration tight loop with identical handles.
- **Cache miss on bit change:** mutate one input byte → new BindGroup
  key → cache miss is recorded.
- **LRU eviction:** set `VYRE_BUFFER_POOL_BUDGET_BYTES=1048576`,
  allocate enough handles to exceed the budget, assert the oldest handle
  is evicted and re-allocating it produces `allocations_total` increase.
- **Batched submission:** dispatch_persistent_batched with 16 items asserts
  `queue.submit` was called exactly once (mock the queue in the test, or
  count submissions via a wgpu profiling wrapper).

### Verification

- `cargo check -p vyre-wgpu` → 0 errors.
- `cargo test -p vyre-wgpu --test persistent_dispatch` on the RTX 5090 →
  all pass.
- `cargo clippy -p vyre-wgpu --all-targets -- -D warnings` clean.

### Commit

`B-B2: persistent GPU tier — GpuBufferHandle + BufferPool + BindGroup cache`

---

## Step B-B3 — Cat C IO intrinsics (after A-B3 lands)

**Pause until `A-B3:` exists in `git log`.** A-B3 finishes Gemini A's
remaining-built-ins migration and ensures the stdlib dialect scaffolding
is stable.

Create a new `io` dialect at `vyre-core/src/dialect/io/`:

- `io.dma_from_nvme(fd: RawFd, offset: u64, length: u64) -> GpuBufferHandle`
- `io.write_back_to_nvme(handle: GpuBufferHandle, fd: RawFd, offset: u64)`
- `mem.zerocopy_map(fd: RawFd) -> GpuBufferHandle`
- `mem.unmap(handle: GpuBufferHandle)`

Each `OpDef` has:
- `category: Category::Intrinsic`
- `signature: Signature { ... }` declaring the RawFd + offset + length params
- `lowerings: LoweringTable { naga_wgsl: None, naga_spv: None, ptx: None,
                              metal_ir: None, cpu_ref: unsupported_cpu }`
  where `unsupported_cpu` returns `BackendError::Unsupported { op_id,
  backend, hint }`.

No backend opts into these ops in this commit. A Program that calls
them fails Law C cleanly. The op existence alone opens the door for an
opt-in crate (`vyre-dialect-io` — future work, not in this sweep) to
inventory-register the real io_uring / GDS lowerings.

### Tests

- `vyre-wgpu/tests/io_caps_negotiation.rs`:
  - Build a Program that calls `io.dma_from_nvme`. Dispatch through
    `WgpuBackend`. Assert `BackendError::Unsupported { op_id:
    "io.dma_from_nvme", backend: "wgpu" }`.
  - Manually register a dummy lowering for the op via test-only
    inventory; dispatch succeeds.

### Commit

`B-B3: io dialect — Cat C zero-copy intrinsics (backend opt-in skeleton)`

---

## Step B-B4 — vyre-reference consumes LoweringTable

Mirror B-B1 in the CPU reference interpreter.

- `vyre-reference/src/interp.rs` and `hashmap_interp.rs` walk
  `DialectRegistry::get_lowering(op_id, Target::CpuRef)` to get a
  `fn(&[u8], &mut Vec<u8>, &AttrMap) -> Result<()>`. Call it instead of
  pattern-matching on a legacy enum.

- Reference backend's capability registration:
  ```rust
  inventory::submit! {
      BackendRegistration {
          name: "reference",
          supports_dialects: &[ /* same list as wgpu, minus workgroup,
                                  minus security_detection (if the
                                  reference doesn't implement them — be
                                  honest in the capability list) */ ],
          execute: execute_reference_program,
          validate: ...,
      }
  }
  ```

### Tests

- `cargo test -p vyre-reference` green.
- `cargo test -p vyre --test kat_parity` — 82/82 still pass via the
  reference path.

### Commit

`B-B4: vyre-reference dispatches via LoweringTable.cpu_ref`

---

## Step B-B5 — Backend trait split (F8) + Progressive lowering (F10)

Split `Backend` into three capability traits:

```rust
pub trait Executable: Send + Sync {
    fn execute(&self, program: &Program, inputs: &[&[u8]]) -> Result<Vec<Vec<u8>>, BackendError>;
    fn execute_persistent(
        &self, program: &Program,
        inputs: &[GpuBufferHandle], outputs: &mut [GpuBufferHandle],
    ) -> Result<(), BackendError> { Err(BackendError::PersistentNotSupported) }
}

pub trait Compilable {
    type BackendIR: Send + Sync;
    fn compile(&self, program: &Program) -> Result<Self::BackendIR, BackendError>;
}

pub trait Streamable {
    fn stream_in(&self, src: impl Read + Send + 'static) -> Result<GpuBufferHandle, BackendError>;
    fn stream_out(&self, handle: GpuBufferHandle) -> Result<Box<dyn Read + Send>, BackendError>;
}
```

Legacy `trait Backend` becomes a blanket impl for `T: Executable` — existing
callers keep working.

Progressive lowering:
```rust
pub struct WgpuIR {
    pub module: naga::Module,
    pub entry: String,
    pub bindings: Vec<BindingSpec>,
    pub workgroup_size: [u32; 3],
}

impl Compilable for WgpuBackend {
    type BackendIR = WgpuIR;
    fn compile(&self, program: &Program) -> Result<WgpuIR, BackendError> {
        // Program -> build naga::Module via LoweringTable walk
        // -> validate -> package into WgpuIR
    }
}
```

Dispatch path becomes:
- `program → Compilable::compile → WgpuIR` (cached via pipeline cache)
- `WgpuIR → naga::back::wgsl::write_string → wgpu::ShaderModule` (cached)
- `ShaderModule → ComputePipeline` (cached)
- `ComputePipeline::dispatch(handles, workgroups) → Executable::execute`

Each stage independently testable.

### Tests

- `vyre-wgpu/tests/progressive_lowering.rs`:
  - Compile a XOR program to `WgpuIR`, assert the naga::Module has
    exactly one entry_point, expected binding count.
  - Emit WGSL from the `WgpuIR`, re-parse, validate — round-trip clean.
  - Dispatch from `WgpuIR` directly, bypass the top-level Program entry.

### Commit

`B-B5: Backend trait split (Executable/Compilable/Streamable) + progressive lowering (Program → WgpuIR → WGSL)`

---

## Step B-B6 — [MOVED to Gemini C]

All perf work (subgroup ops, specialization constants, indirect dispatch,
async readback ring, auto-tuner, SPIR-V backend, cross-dispatch fusion,
persistent megakernel, adapter-caps-aware passes, backend auto-picker)
now lives in `sweep-gemini-c-perf.md`. Gemini C starts after your B-B5
lands. You stop after B-B5.

Ignore everything below until the "Legendary bar for Gemini B" section.

## [Historical — MOVED to Gemini C] Perf sweep (after A-C7 lands)

**Pause until `A-C7:` exists in `git log`.** Claude has landed the Expr/Node
open-IR workspace rewrite. Safe to do perf work now.

Six perf landings, one commit each. Serialize; don't stack.

### B-B6a — Subgroup ops

`vyre-wgpu/Cargo.toml` already declares `wgpu_subgroups` feature. Wire it:

- Every op in dialects `math`, `bitwise`, `compare`, `float`, `hash`,
  `pattern` that builds a reduce / scan / shuffle / histogram kernel
  checks `device.features().contains(wgpu::Features::SUBGROUP)` and emits
  the subgroup-intrinsic path when available.
- naga::Module builders now have a `use_subgroups: bool` context flag.
  When true, they emit `subgroupBroadcast`, `subgroupAdd`, `subgroupMax`,
  `subgroupInclusiveAdd`, `subgroupShuffleXor` naga intrinsics. When
  false (downlevel device), fall back to the SRAM-scan paths.
- Bench: `vyre-wgpu/benches/subgroup_speedup.rs` — compares subgroup-on
  vs subgroup-off on a prefix-sum of 16 MB u32 buffer. Target: 4-8×
  speedup on the RTX 5090.

Commit: `B-B6a: subgroup-ops intrinsics (4-8× on reduce/scan/histogram when available)`

### B-B6b — Shader specialization constants

Pipeline cache key today includes shader source + bindings + workgroup
size. Extend:
- Op attributes that are literal u32/i32/f32 become naga
  `Override` specialization constants.
- Pipeline is compiled once per (shader, bindings, wg size) triple and
  specialized per call via `ComputePipelineDescriptor::constants`.
- Cache key changes to include the constant-value hash.
- XOR with key=0xa5 compiles to a specialized shader that is consistently
  15-30% faster than the parameterized version.

Commit: `B-B6b: shader specialization constants via naga Override + wgpu constants`

### B-B6c — Indirect dispatch

Add a `Node::IndirectDispatch` variant to the IR (coordinate with Claude —
this touches Expr/Node, but Claude's A-C7 has already finished the open-IR
rewrite so adding a new variant plus its Opaque-compatible handling is safe).

Actually correction: IR changes are Claude's scope. You add the
`vyre-wgpu` dispatch side:

- New `WgpuBackend::dispatch_indirect(pipeline, handle, offset)` that
  submits `ComputePassDescriptor::dispatch_workgroups_indirect(buffer,
  offset)`.
- A dialect op `core.indirect_dispatch(workgroup_count: GpuBufferHandle<[u32;3]>)`
  lowers to this call.

Commit: `B-B6c: indirect dispatch path + core.indirect_dispatch op`

### B-B6d — Async readback ring

Current readback blocks the submit queue. Implement a ring buffer:
- N=4 staging buffers (configurable via `VYRE_READBACK_RING_SIZE`).
- On dispatch `i`, submit copy to `ring[i % N]`; map it async.
- Readback call for `i` awaits `ring[i % N]` map complete, returns the
  data, frees the slot.
- Overlap: dispatch `i+1` runs in parallel with readback `i`'s copy.
- Bench: streaming 1 GB through the scan pipeline saturates bandwidth
  instead of blocking.

Commit: `B-B6d: async readback ring — dispatch-readback overlap`

### B-B6e — Auto-tuner

`vyre-wgpu/src/runtime/tuner.rs`:
- On first dispatch of a (program, device) pair, sweep workgroup sizes
  `{32, 64, 128, 256, 512, 1024}` timing each via GPU timestamp queries.
- Pick the fastest, cache result to `~/.cache/vyre/tuner/<device_fp>.toml`.
- Subsequent dispatches read the cache; fall back to `[64,1,1]` if
  device not recognized.
- Respect `VYRE_AUTOTUNER=off` to disable (useful for reproducible
  benchmarks).

Commit: `B-B6e: workgroup-size auto-tuner (cached per device)`

### B-B6f — SPIR-V backend module

Inside `vyre-wgpu/src/spirv_backend.rs` (new file, same crate):
- Reuse every LoweringTable `naga_wgsl` builder — the naga::Module is
  identical; emit SPIR-V via `naga::back::spv::write_vec(&module, &info,
  Options::default(), None)` instead of WGSL.
- `SpirvBackend { adapter, device, queue, instance }` — Vulkan compute
  path via wgpu with Vulkan backend selected.
- Register BackendRegistration for `"spirv"` with the same dialect list
  as wgpu (minus workgroup if SRAM-atomic ops need Vulkan extensions
  we don't yet enable — be honest in capability).
- Tests: run the XOR program through SpirvBackend, compare output
  byte-for-byte to WgpuBackend. Must match.

Commit: `B-B6f: SPIR-V backend module — naga::back::spv reuse, same dialect coverage as wgpu`

### B-B6g — Cross-dispatch kernel fusion

Current `Fusion` pass is intra-Program. Extend: when dispatch N's output
is consumed only by dispatch N+1 with matching workgroup layout AND the
combined shader fits within adapter caps, fuse them into a single
`ComputePipeline`. Kills one readback + one upload per fusion point.

- New pass `vyre-wgpu/src/lowering/cross_dispatch_fusion.rs` runs after
  the generic optimizer, before pipeline compilation.
- Uses `AdapterCaps` (see B-B6h) to check the fused shader's
  workgroup-shared-memory footprint against the device budget.
- Fallback: if the fused shader exceeds caps, keep the two dispatches
  separate. No panic, no abort.
- Bench: a 5-op pipeline (load → xor → shift → and → store) pre-fusion
  vs post-fusion on 64 MB buffer. Fused must be ≥30% faster end-to-end.

Commit: `B-B6g: cross-dispatch kernel fusion (eliminates readback→upload round trips)`

### B-B6h — Adapter-caps-aware pass scheduling

Passes today run blind to the target adapter. Thread an `AdapterCaps`
struct through `PassCtx`:
```rust
pub struct AdapterCaps {
    pub subgroup_size: Option<u32>,
    pub max_workgroup_invocations: u32,
    pub max_workgroup_shared_memory_bytes: u32,
    pub max_storage_buffers_per_shader_stage: u32,
    pub max_push_constants_bytes: u32,
    pub supports_indirect_dispatch: bool,
    pub supports_subgroup_ops: bool,
    pub supports_atomics: AtomicFamily,
    pub supports_cooperative_matrix: bool,
}
```

- `WgpuBackend::adapter_caps(&self) -> AdapterCaps` fills the struct
  from `wgpu::Adapter::get_info()` + `Adapter::features()` + `limits()`.
- Passes read caps at `run()` time and adapt:
  - Workgroup-shared-memory allocator picks max feasible size.
  - Fusion pass (B-B6g) checks fused workgroup budget against caps.
  - Subgroup ops (B-B6a) emit hardware intrinsics only when
    `supports_subgroup_ops == true`.
- `vyre-wgpu/tests/caps_aware_passes.rs`: mock two adapter caps profiles
  (low-end + high-end), assert the same Program compiles to
  different pipelines on each.

Commit: `B-B6h: adapter-caps-aware pass scheduling (passes adapt to the real device)`

### B-B6i — Persistent megakernel mode

Single long-running shader pops work items from a GPU-side ring buffer
instead of many small dispatches. Amortizes all PCIe dispatch overhead
completely — 10-100× throughput win for high-rate streaming.

- `vyre-wgpu/src/engine/megakernel.rs` — new module:
  ```rust
  pub fn dispatch_megakernel(
      &self,
      program: &Program,
      work_queue: &GpuBufferHandle,
      worker_count: u32,
      max_wall_time: Duration,
  ) -> Result<(), BackendError>;
  ```
- The shader template launches `worker_count` workgroups, each runs an
  infinite loop: pop work item from `work_queue` (atomic index), execute
  the program on it, push result to an output buffer. Loop exits when
  the queue is empty or `max_wall_time` timer fires.
- Bench: 100K XOR invocations via dispatch_persistent vs
  dispatch_megakernel. Megakernel must be ≥10× faster on the overall
  walltime.
- Opt-in only — not default dispatch path. Consumer explicitly calls
  `dispatch_megakernel` when they know the workload shape.

Commit: `B-B6i: persistent megakernel mode (10-100× throughput on streaming workloads)`

### B-B6j — Backend auto-picker

Given a Program, pick the best backend automatically from the inventory
of registered backends and the adapter's actual capabilities:

- Precedence (when present + adapter supports): PTX > SPIR-V > WGSL > CPU reference.
- Capability negotiation: the picker filters out backends that don't
  cover the Program's dialect manifest (Law C already returns this
  information).
- Caching: `~/.cache/vyre/router/<adapter_fp>.toml` records the
  decision per program fingerprint. Second run reads the cache.
- Override: `VYRE_BACKEND=spirv` env var forces a specific backend,
  returns error if that backend isn't present or doesn't support the
  dialects.

- `vyre-wgpu/src/runtime/router.rs` — new module. `BackendRouter` walks
  the inventory::iter of `BackendRegistration`, filters, picks,
  constructs.

Commit: `B-B6j: backend auto-picker (runtime routes to best available, cached per adapter)`

---

## Legendary bar for Gemini B

When you are done:
- `vyre-wgpu::dispatch_persistent` allocates O(1) GPU buffers across a
  1000-iteration dispatch loop.
- BindGroup cache hit ratio ≥ 99% on repeated identical dispatches.
- DFA fast-path is single-round-trip (one dispatch, one readback).
- Subgroup ops deliver ≥ 4× speedup on reduce/scan/histogram on the RTX 5090.
- Specialization constants deliver 15-30% speedup on literal-heavy ops.
- SPIR-V backend runs the full test suite with byte-identical output to wgpu.
- Indirect dispatch and async readback ring are measurable (benches committed).
- Auto-tuner cache present, hot-path respects it.
- **Lock-free `BufferPool`** passes 16-thread concurrent-storm test
  without deadlock.
- **Command-buffer pre-recording** (`PrerecordedDispatch::replay`) is
  ≥2× faster than re-encoding on hot loops.
- **Cross-dispatch kernel fusion** merges adjacent dispatches on a
  5-op pipeline; fused version is ≥30% faster.
- **Adapter-caps-aware passes** demonstrably produce different
  pipelines for low-end vs high-end adapter profiles.
- **Persistent megakernel** delivers ≥10× throughput vs
  `dispatch_persistent` on a 100K-invocation streaming workload.
- **Backend auto-picker** routes a program to the best backend
  available; `VYRE_BACKEND=<name>` override works; cached decisions
  reused across runs.
- `cargo clippy --all-targets -- -D warnings` clean across `vyre-wgpu`
  and `vyre-reference`.
- Zero `OpSpec::intrinsic` or `wgsl_only` references remain in your
  trees.

Commit subjects all start `B-B<n>:`, `B-B2<letter>:`, or `B-B6<letter>:`.
No other prefix.
