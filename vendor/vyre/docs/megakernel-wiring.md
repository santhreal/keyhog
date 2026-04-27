# Megakernel wiring — ground-truth map (Phase 0)

Written 2026-04-21. Authoritative snapshot of the persistent-kernel path
before we start Phase 1. Every claim cites `file:line`. Read this before
editing anything in `vyre-runtime/megakernel` or `vyre-driver-wgpu`.

## What exists (the parts that work)

### Protocol — `vyre-runtime/src/megakernel/protocol.rs`
- 16-word slot layout, `STATUS_WORD=0`, `OPCODE_WORD=1`, `TENANT_WORD=2`,
  `ARG0_WORD=3`, `ARGS_PER_SLOT=13`.
- Slot state machine: `EMPTY → PUBLISHED → CLAIMED → DONE`
  (`protocol.rs:29-43`).
- Control layout: `SHUTDOWN=0`, `DONE_COUNT=1`, `TENANT_BASE=2`,
  `OBSERVABLE_BASE=32`, `METRICS_BASE=64`, `EPOCH=96`
  (`protocol.rs:46-72`).
- Built-in opcodes: NOP(0), STORE_U32(1), ATOMIC_ADD(2), LOAD_U32(3),
  COMPARE_SWAP(4), MEMCPY(5), DFA_STEP(6), BATCH_FENCE(7), PRINTF(0xFFFE),
  SHUTDOWN(u32::MAX) (`protocol.rs:75-125`).
- Debug log: CURSOR_WORD(0), RECORDS_BASE(1), RECORD_WORDS(4)
  (`protocol.rs:130-137`).

### Program builder — `vyre-runtime/src/megakernel/builder.rs`
- `build_program_sharded(workgroup_size_x, opcodes)` returns a
  `Program` with 3 buffers (control[binding=0], ring_buffer[1],
  debug_log[2]) and body `Node::forever(persistent_body(...))`
  (`builder.rs:21-31`).
- `build_program_jit(workgroup_size_x, payload_processor)` — same
  shape but splices user-provided nodes instead of the If-tree
  (`builder.rs:33-48`).
- `persistent_body` (`builder.rs:53-103`) reads `shutdown_flag`
  from control, early-returns on non-zero, computes
  `lane_id = wgid.x * WG_SIZE + lid.x`, `slot_base = lane_id *
  SLOT_WORDS`, loads `tenant_id` from ring_buffer, loads
  `tenant_base` from control, loads `tenant_mask` from
  `control[tenant_base + tenant_id]`, gates the slot body on
  `tenant_mask != 0`.
- `execute_slot_body` (`builder.rs:105-126`) CAS'es
  `ring_buffer[slot_base + STATUS_WORD]` from PUBLISHED → CLAIMED.
  On success, executes `claimed_slot_body(opcodes)` from
  `handlers.rs`.

### Opcode handlers — `vyre-runtime/src/megakernel/handlers.rs`
(Renamed from `opcode.rs` by codex-622ee963 during this session —
do NOT edit while codex runs.)
- `claimed_slot_body` (`handlers.rs:143-214`) loads opcode +
  arg0/arg1/arg2 from ring_buffer, dispatches via
  `opcode_if(...)` chain over 8 built-ins + user-provided extensions,
  `atomic_add(control, DONE_COUNT, 1)`, stores DONE into status.
- `printf_body` atomically reserves 4 words via `atomic_add(debug_log,
  CURSOR_WORD, 4)` + writes (fmt_id, arg0, arg1, arg2, slot_base) into
  the reserved region (`handlers.rs:46-80`).

### Node + Expr surface the megakernel uses
| Used by megakernel | Exists in IR | Emittable by naga_emit/node.rs |
| --- | --- | --- |
| `Node::Loop { var, from, to, body }` (forever = `from=0, to=u32::MAX`) | `impl_node.rs:152` — `forever` is `loop_for("__forever__", 0, u32::MAX, body)` | ✅ `node.rs:119-176` emits a bounded for-loop |
| `Node::Return` | yes | ✅ `node.rs:115-118` |
| `Node::let_bind / Assign / Store / If / Block / Region / Barrier` | yes | ✅ `node.rs:15-111` |
| `Node::loop_for` (for MEMCPY opcode body) | yes | ✅ same as above |
| `Expr::load(buf, idx)` | yes | ✅ `expr.rs` |
| `Expr::atomic_add(buf, idx, val)` → returns prev | yes | ✅ `expr.rs:97` `AtomicOp::Add` |
| `Expr::atomic_exchange(buf, idx, val)` | yes | ✅ `expr.rs:104-107` `AtomicOp::Exchange` |
| `Expr::atomic_compare_exchange(buf, idx, exp, desired)` | yes | ⚠️ `expr.rs:108-117` emits `AtomicFunction::Exchange { compare: Some }` but returns `atomic_compare_exchange_u32_ty` (a struct {old_value, exchanged}). builder.rs:112-120 binds `prev_status` as if it were a scalar `u32` and compares it to `slot::PUBLISHED` directly — this needs the `.old_value` field projection or CAS returns a struct the rest of the IR cannot consume. **Gate #1.** |
| `Expr::workgroup_x()` / `Expr::local_x()` | yes | ✅ BuiltIn::WorkGroupId / LocalInvocationId in `naga_emit/mod.rs:278-289` |

### Buffer lowering — `vyre-driver-wgpu/src/lowering/naga_emit/mod.rs`
- `add_buffer` (`mod.rs:216-267`) emits `array<u32>` elements for
  DataType::U32 (via `storage_scalar_type`). For ReadWrite + Global
  MemoryKind, `storage_access = LOAD|STORE`
  (`utils.rs:66-71`).
- **Gate #2:** WGSL atomic operations require `array<atomic<u32>>`,
  not `array<u32>`. The megakernel's three buffers
  (control / ring_buffer / debug_log) are all used with
  `atomic_add / atomic_exchange / atomic_compare_exchange`. Currently
  `storage_scalar_type` returns a plain u32 for DataType::U32. Naga
  validation will reject the emitted Statement::Atomic against a
  non-atomic pointer.

## What does NOT exist (the gates)

1. **No test emits a megakernel Program through the wgpu emitter.**
   `vyre-runtime/tests/multi_tenant_scheduler.rs:84` constructs
   `build_program_sharded(1024, &[])` but never dispatches.
   `vyre-driver-wgpu/tests/` contains zero megakernel tests.
   `vyre-driver-wgpu/src/megakernel.rs` module doc explicitly says
   "the ring-consumer shader is a standalone effort … not yet
   landed" (`megakernel.rs:11-17`).

2. **`engine/megakernel_emit.rs` does not exist.** `ls
   vyre-driver-wgpu/src/engine/` gives
   `graph.rs  multi_gpu.rs  persistent.rs  record_and_readback.rs
   streaming streaming.rs` — no `megakernel_emit.rs`.

3. **`MegakernelDispatch` trait is declared but unimplemented on
   `WgpuBackend`.** `megakernel.rs:128-141` defines the trait;
   `grep -rn "impl MegakernelDispatch" vyre-driver-wgpu/src` returns
   nothing. There is no `WgpuBackend` impl.

4. **io_uring ↔ megakernel ring never connected.** Both halves exist
   (`vyre-runtime/src/uring/stream.rs` + `megakernel::publish_slot`),
   but no function composes them. No `uring_publish_read` helper
   exists. Stream emits completion callbacks into nowhere.

## Gate list for Phase 1 (ranked)

**Gate A — atomic element types.** `add_buffer` in `naga_emit/mod.rs`
must detect buffers used atomically in the program body and emit
`array<atomic<u32>>` (or interior atomic via `TypeInner::Atomic`
wrapping the element) instead of `array<u32>`. Easiest: a pre-pass that
walks the IR and collects the set of buffer names touched by
`Expr::Atomic`; during `add_buffer`, if the name is in that set, wrap
element in `TypeInner::Atomic`.

**Gate B — atomic CAS result projection.** `expr.rs:108-130` emits an
`AtomicResult` with `ty: atomic_compare_exchange_u32_ty` (the struct).
`builder.rs:112` binds the return directly as if it were u32 and then
compares `prev_status == PUBLISHED`. Options:
- (i) always emit a `.old_value` AccessIndex after the atomic result,
  so the IR-visible return is u32.
- (ii) change the Expr::Atomic arm to return the struct only for the
  compare-exchange case and make the builder pull `.old_value`
  explicitly.
Option (i) is less invasive.

**Gate C — persistent entry point verification.** Once Gates A+B are
fixed, emit the program through `emit_module` and run
`naga::back::wgsl::write_string(&module, &info, flags)`. Assert no
validation errors. Add
`vyre-driver-wgpu/tests/megakernel_emit.rs` with: build_program_jit(64,
&[]) → emit_module → naga validate → wgsl emit → assert starts with
`@compute @workgroup_size(64, 1, 1)` and contains `loop { … break if
(…); continuing { … } }` shape.

**Gate D — `impl MegakernelDispatch for WgpuBackend`.** The trait is
declared (`megakernel.rs:128-141`). Implementation: compile the
megakernel Program via `pipeline::compile`, allocate control +
ring_buffer + debug_log with `MAP_READ|MAP_WRITE`, kick off a single
dispatch (workgroup_count = slot_count / workgroup_size_x), poll
`DONE_COUNT` / `SHUTDOWN` flag from host side. This is what makes the
Megakernel::bootstrap call actually do something on wgpu.

**Gate E — shutdown / drain.** After Gates A-D, validate a full
lifecycle test: host publishes N slots, observes DONE_COUNT == N,
writes SHUTDOWN=1, waits for kernel to exit. Without this test passing
end-to-end, Phase 2 (fusion) cannot be meaningfully benchmarked.

## wgpu capability requirements (for `runtime/adapter_caps_probe.rs`)

The persistent shader requires:
- `wgpu::Features::empty()` baseline. No exotic features.
- `Limits::max_compute_workgroup_size_x ≥ workgroup_size_x` (default
  256 today).
- `Limits::max_compute_invocations_per_workgroup ≥ workgroup_size_x`.
- Storage buffer bindings: 3 (control, ring_buffer, debug_log).
  `max_storage_buffers_per_shader_stage ≥ 3`. wgpu default = 8 ✅.
- No subgroup features needed (subgroup intrinsics are feature-gated
  and not used by the megakernel body).
- Atomic ops on storage buffers — unconditional in WGSL core.
- Long-running kernel tolerance: some platforms (Windows TDR) reset
  the GPU after ~2s without progress. `max_wall_time` in
  MegakernelConfig is the user-facing guard; the impl must either
  periodically yield (not straightforward on wgpu) or break the work
  into slot-batches with `max_wall_time` observed host-side. Document
  this cliff.

## What Phase 1 actually is

Not: "implement megakernel_emit.rs from scratch."

Is: (1) fix two emitter gaps (atomic element type, CAS result
projection) that block a 25-line IR from emitting valid WGSL; (2) add
the `impl MegakernelDispatch for WgpuBackend` that runs the compiled
pipeline; (3) add a lifecycle test that exercises the full cycle
publish → claim → execute → done → shutdown. No new emitter module —
the existing `naga_emit` IS the emitter. The "engine/megakernel_emit.rs
not yet landed" doc comment is stale; delete or rewrite in the Phase 1
commit.

## Cross-session hazard

Codex-622ee963 is actively running "V7 deferred findings (perf + IR
refactors)" in this workspace. It has the scope lock and is modifying
at least: vyre-foundation (Program OnceLock fields), vyre-libs/tensor_ref,
vyre-driver-wgpu/buffer, vyre-libs/tests/universal_harness.rs. Do NOT
start Phase 1 edits to `vyre-driver-wgpu/src/lowering/naga_emit/` or
`vyre-driver-wgpu/src/buffer/` until codex-622ee963 is done —
conflicts likely. Phase 2 (surgec fusion) is outside the vyre scope
lock and safe to start now.

## Source paths summary

- Protocol: `vyre-runtime/src/megakernel/protocol.rs`
- Builder: `vyre-runtime/src/megakernel/builder.rs`
- Handlers (renamed from opcode.rs): `vyre-runtime/src/megakernel/handlers.rs`
- Megakernel host API: `vyre-runtime/src/megakernel/mod.rs`
- io_uring: `vyre-runtime/src/uring/{ring,stream}.rs`
- wgpu emitter: `vyre-driver-wgpu/src/lowering/naga_emit/{mod,node,expr,utils}.rs`
- wgpu MegakernelDispatch trait (unimpl): `vyre-driver-wgpu/src/megakernel.rs`
- wgpu engine (no megakernel_emit.rs): `vyre-driver-wgpu/src/engine/`
- Runtime caps probe: `vyre-driver-wgpu/src/runtime/adapter_caps_probe.rs`
