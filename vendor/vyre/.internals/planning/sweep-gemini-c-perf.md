# Sweep Plan — Gemini C: Performance Blitz

**Agent:** Gemini 3.1-pro, launched in Antigravity, unlimited. Third
Gemini of three. Runs in parallel with Gemini A (ops/dialects), Gemini B
(backend baseline), and Claude (substrate/IR/docs).

**Scope lock:**
- **You may edit:** `vyre-wgpu/src/buffer/**`, `vyre-wgpu/src/runtime/**`,
  `vyre-wgpu/src/lowering/fusion.rs` (new), `vyre-wgpu/src/spirv_backend.rs`
  (new), `vyre-wgpu/src/megakernel.rs` (new), `vyre-wgpu/benches/**`,
  `vyre-wgpu/tests/*perf*.rs`, `vyre-wgpu/tests/*fusion*.rs`,
  `vyre-wgpu/tests/*megakernel*.rs`, `xtask/src/bench_crossback.rs` (new),
  `scripts/bench/**` (new dir).
- **You may APPEND (not edit existing lines) to:** `vyre-wgpu/src/lib.rs`
  (add `pub mod ...` declarations for your new modules).
- **You may NOT edit:** `vyre-wgpu/src/{backend,pipeline,engine,lowering/naga_emit}.rs`
  (Gemini B owns these), any `vyre-core/**` file (Claude + Gemini A),
  any `vyre-reference/**` file (Gemini B), any `vyre-dialect-crypto/**`
  file (Gemini A).

**Handshake — when each step can start:**
- **Step 0 start:** wait for commit `A-B0:` (Gemini A foundation types)
  AND `B-B2:` (Gemini B persistent-buffer baseline). C-B1 layers on B-B2.
- **Steps C-B2 … C-B7:** can start after `B-B5:` (Gemini B baseline
  complete). Run serially inside your session.
- **Step C-B8 (cross-dispatch fusion):** wait for `A-C7b:` (Claude
  pass-system-as-first-class). Fusion registers as a Pass.
- **Step C-B10 (adapter-caps pass):** wait for `A-C7b:` + B-B5.
- **Step C-B11 (auto-picker):** last step; wait for C-B7 (SPIR-V backend
  present) + all other C-B* done.

**Commit prefix:** `C-B<n>:`.

**Rules:** direct to main; no stubs; no test weakening; no
`#[cfg(not(feature="gpu"))]` — GPU is always present.

---

## Step C-B1 — Lock-free BufferPool + command-buffer pre-recording

Builds on Gemini B's B-B2 persistent-buffer work.

- Replace `Mutex<Vec<FreeEntry>>` in `BufferPool` with a lock-free MPMC
  queue (`crossbeam-queue::SegQueue<FreeEntry>` or ArrayQueue sized to
  pool budget).
- New `PrerecordedDispatch { cb: wgpu::CommandBuffer, bind_group,
  handles }` + `replay(&self, queue: &wgpu::Queue)`. Bypass
  `CommandEncoder` on hot loops.
- Tests: 16-thread acquire/release storm completes without deadlock;
  `replay()` ≥ 2× faster than re-encoding per call.

Commit: `C-B1: lock-free BufferPool + command-buffer pre-recording`

---

## Step C-B2 — Subgroup-op intrinsics

Wire the `wgpu_subgroups` feature into every reduce/scan/shuffle/
histogram op. Emit `subgroupBroadcast`, `subgroupAdd`, `subgroupMax`,
`subgroupInclusiveAdd`, `subgroupShuffleXor` naga intrinsics when
`Features::SUBGROUP` is available; SRAM-scan fallback otherwise.

- Bench: `vyre-wgpu/benches/subgroup_speedup.rs` — prefix-sum over 16 MB
  u32 buffer, subgroup on vs off. Target: ≥ 4× speedup on RTX 5090.

Commit: `C-B2: subgroup-ops intrinsics (4-8× on reduce/scan/histogram)`

---

## Step C-B3 — Shader specialization constants

Op attributes that are literal `u32`/`i32`/`f32` become naga `Override`
constants. Pipeline compiled once per (shader, bindings, wg size) triple
and specialized per-call via `ComputePipelineDescriptor::constants`.
Pipeline-cache key extended to include the constant-value hash.

- Bench: XOR parameterized vs XOR with key=0xa5 specialized. Target:
  15-30% speedup on the specialized path.

Commit: `C-B3: shader specialization constants via naga Override + wgpu constants`

---

## Step C-B4 — Indirect dispatch path

New `WgpuBackend::dispatch_indirect(pipeline, handle, offset)` submits
`ComputePass::dispatch_workgroups_indirect(buffer, offset)`. A dialect
op `core.indirect_dispatch(workgroup_count: GpuBufferHandle<[u32;3]>)`
lowers to this call. (The op itself is added by Gemini A into the `core`
dialect; you ship the wgpu-side dispatch implementation.)

Commit: `C-B4: indirect dispatch — GPU-decided workgroup count`

---

## Step C-B5 — Async readback ring buffer

N-deep staging ring (default N=4, configurable via
`VYRE_READBACK_RING_SIZE`). On dispatch `i`, submit copy to
`ring[i % N]`; map async. Readback for `i` awaits `ring[i % N]`.
Dispatch `i+1` overlaps with readback `i`'s copy.

- Bench: streaming 1 GB through the scan pipeline saturates PCIe bandwidth
  instead of blocking.

Commit: `C-B5: async readback ring — dispatch-readback overlap`

---

## Step C-B6 — Workgroup-size auto-tuner

- `vyre-wgpu/src/runtime/tuner.rs` — on first dispatch of a (program,
  adapter) pair, sweep workgroup sizes `{32, 64, 128, 256, 512, 1024}`
  via GPU timestamp queries. Pick fastest.
- Cache: `~/.cache/vyre/tuner/<adapter_fp>.toml`. Subsequent dispatches
  read it.
- Kill switch: `VYRE_AUTOTUNER=off` disables sweep, uses `[64,1,1]`
  default.

Commit: `C-B6: workgroup-size auto-tuner (cached per adapter)`

---

## Step C-B7 — SPIR-V backend module

`vyre-wgpu/src/spirv_backend.rs` — new file in vyre-wgpu, not a new
crate. Reuses every LoweringTable `naga_wgsl` builder; naga::Module is
identical, emit SPIR-V via `naga::back::spv::write_vec`. `SpirvBackend`
struct runs through wgpu with Vulkan backend selected.

- Register `BackendRegistration` for `"spirv"` with the same dialect
  coverage as wgpu.
- Test: run XOR through SpirvBackend, compare to WgpuBackend output
  byte-for-byte. Must match.

Commit: `C-B7: SPIR-V backend module — naga::back::spv reuse`

---

## Step C-B8 — Cross-dispatch kernel fusion (after A-C7b lands)

Pause until Claude's pass-system commit `A-C7b:` lands. Then register a
new `Pass` in `vyre-wgpu/src/lowering/fusion.rs`:

- Runs after the generic optimizer, before pipeline compilation.
- When dispatch N's output is consumed only by dispatch N+1 with
  matching workgroup layout AND the combined shader fits adapter caps
  (see C-B10), fuse into one `ComputePipeline`.
- Fallback: exceed caps → keep separate, no panic.
- Bench: 5-op pipeline pre-fusion vs post-fusion on 64 MB buffer.
  Target: ≥ 30% end-to-end speedup.

Commit: `C-B8: cross-dispatch kernel fusion pass (eliminates readback round-trips)`

---

## Step C-B9 — Persistent megakernel

`vyre-wgpu/src/megakernel.rs`:
```rust
pub fn dispatch_megakernel(
    &self,
    program: &Program,
    work_queue: &GpuBufferHandle,
    worker_count: u32,
    max_wall_time: Duration,
) -> Result<(), BackendError>;
```
Launch `worker_count` workgroups; each runs infinite loop popping work
items from `work_queue` via atomic index, executing `program`, pushing
result. Loop exits on empty queue or timer.

- Opt-in only — consumer calls `dispatch_megakernel` explicitly.
- Bench: 100K XOR invocations via `dispatch_persistent` vs
  `dispatch_megakernel`. Target: ≥ 10× walltime improvement.

Commit: `C-B9: persistent megakernel mode (10-100× streaming throughput)`

---

## Step C-B10 — Adapter-caps-aware pass scheduling

Extend Claude's `PassCtx` (lands in A-C7b) with an `AdapterCaps` field.
Fill it from `wgpu::Adapter::get_info() + features() + limits()`. Passes
adapt:
- Workgroup-shared-memory allocator picks feasible size.
- Fusion pass (C-B8) checks budget.
- Subgroup ops (C-B2) emit intrinsics only when `supports_subgroup_ops`.

Commit: `C-B10: adapter-caps-aware pass scheduling (passes adapt to real device)`

---

## Step C-B11 — Backend auto-picker

`vyre-wgpu/src/runtime/router.rs` — `BackendRouter` walks
`inventory::iter::<BackendRegistration>()`, filters by program's dialect
manifest, picks by precedence (PTX > SPIR-V > WGSL > CPU ref when
present). Cache: `~/.cache/vyre/router/<adapter_fp>.toml`. Override:
`VYRE_BACKEND=spirv` forces specific backend or errors.

Commit: `C-B11: backend auto-picker (runtime routes to best available)`

---

## Step C-B12 — Cross-backend comparison harness + BENCHMARKS telemetry

`xtask/src/bench_crossback.rs` — `cargo run -p xtask -- bench-crossback
<program>` runs every available backend on the given program, emits
markdown comparison table. Complements Claude's `BENCHMARKS.md` contract
(A-C14b).

`scripts/bench/cross_backend_comparison.sh` wraps the xtask for CI
invocation.

Numerical-stability instrumentation hook: emit max-ULP error vs CPU
reference alongside timing numbers. Claude's A-C14b enforces the bounds
in TOML; you provide the measurement path from the GPU side.

Commit: `C-B12: xtask bench-crossback + ULP instrumentation hooks`

---

## Legendary bar for Gemini C

When done:
- Lock-free pool passes 16-thread concurrent storm.
- Pre-recorded dispatch ≥ 2× faster than re-encoding.
- Subgroup-ops speedup ≥ 4× on reduce/scan/histogram (RTX 5090).
- Specialization constants 15-30% speedup on literal-heavy ops.
- Indirect dispatch + async readback ring both committed with benches
  showing measurable wins.
- Auto-tuner cache is present and observed in the hot path.
- SPIR-V backend emits byte-identical output to WGSL backend on the
  full test suite.
- Cross-dispatch fusion on 5-op pipeline ≥ 30% speedup.
- Persistent megakernel ≥ 10× speedup on streaming workloads.
- Adapter-caps visibly change pass decisions on mock low-end vs
  high-end profiles.
- Backend auto-picker routes correctly; env-var override works;
  cached decisions reused.
- `cargo clippy -p vyre-wgpu --all-targets -- -D warnings` clean.
- `xtask bench-crossback` emits a comparison table for 3+ backends.

Commit subjects all start `C-B<n>:`. No other prefix.
