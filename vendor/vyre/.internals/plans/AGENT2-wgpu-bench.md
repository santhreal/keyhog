# Agent 2 — GPU Backend + Bench + Tests + Macros

**Exclusive ownership (zero overlap with Agent 1):**
- `vyre-wgpu/**`
- `backends/spirv/**`
- `benches/**`
- `xtask/**`
- `tests/**` (root-level integration tests)
- `vyre-macros/**`

**Forbidden paths (belong to Agent 1):** `vyre-core/`, `vyre-spec/`, `vyre-reference/`, `conform/`, `ops-facades/`, `backends/photonic/`, `examples/`, `demos/`, `docs/`, `scripts/`, root Cargo.toml, README.md.

**Do not coordinate. Do not wait. Commit directly to `main`.**

If `vyre-core` adds a new trait or type you need to consume (e.g., `NagaBuilder`), pull latest `main` and implement the consumer side. Never edit `vyre-core` source yourself.

---

## A. Dispatch hot path

### A1. Validation-cache redesign
`vyre-wgpu/src/lib.rs:246-371`.

Problems:
- `validate_with_cache` calls `program.to_wire()` on EVERY dispatch (line 356) — full-program serialization on the hot path.
- `RwLock<FxHashMap>` (line 347) — single contention point under concurrent dispatch.
- No eviction. Unbounded memory growth.
- Four hot sites (`:251, :266, :286, :337`) all call this unconditionally.

Fix:
- Content-address the program ONCE at construction. Store `OnceLock<blake3::Hash>` on the `Program` value itself (coordinate via public API if `Program` is in `vyre-core`; otherwise wrap in a local newtype inside `vyre-wgpu`).
- If `Program`'s public API lacks the cache slot, memoize via `dashmap::DashMap<*const Program, blake3::Hash>` keyed on pointer identity inside `WgpuBackend`.
- Replace `RwLock<FxHashMap>` with `dashmap::DashMap` or `scc::HashMap`.
- Add bounded LRU: `MAX_VALIDATION_CACHE_ENTRIES = 1024` (TOML-configurable).
- Benchmark the dispatch hot path before/after; commit before/after numbers to `benches/` as CSV.

### A2. Buffer pool fixes
`vyre-wgpu/src/buffer/pool.rs`.

Problems:
- `acquire()` (`:128-139`) pops entries whose `usage` doesn't match and pushes them back — O(n) churn on usage mismatch.
- Eviction loop (`:227-243`) walks `0..64` every release even when most classes are empty.
- `ArrayQueue::new(1024)` per class is hardcoded.
- `MAX_RETAINED_BYTES = 1 << 30` is baked in.
- Silent overflow: `push.is_ok()` path drops buffer without a stat bump.

Fix:
- Per-usage sub-queue: `[[ArrayQueue<FreeEntry>; NUM_USAGE_KEYS]; 64]` OR a `SmallVec<(BufferUsages, &ArrayQueue); 4>` per class and match by usage.
- Track non-empty classes in a `u64` bitset so eviction picks the highest non-empty bit directly.
- Make `ARRAY_QUEUE_CAPACITY` and `MAX_RETAINED_BYTES` read from `WgpuBackend` config (not env).
- Count overflow drops in `BufferPoolStats::overflow_drops`.
- Property test: random acquire/release pattern, assert allocations ≤ log₂(max_size) · usage_count.

### A3. DFA optimizer
`vyre-wgpu/src/engine/dfa.rs`.

Problems:
- `:310` copies `max_matches * 12` bytes every scan even if zero matched.
- `:317-319` has `match self.device.poll(...) { _ => {} }` — swallows `MaintainResult`; can read uninitialized bytes if queue returns Empty/Queued.
- `:206-226` `acquire_scan_resources`/`release_scan_resources` use `Mutex<Vec<ScanResources>>` with linear scan at `:210`.
- Deprecated `scan` method (`:166`) still in public API.

Fix:
- Indirect readback: dispatch `copy_buffer_to_buffer` conditional on `match_count` via a dedicated indirect-dispatch kernel OR read the 4-byte count, submit the payload copy only when count > 0.
- Replace the swallowed `poll` with a loop on `Maintain::wait_for(submission)` until it reports done; surface a `BackendError` on disconnected channel (not `unwrap()` at `:320`).
- Size-classed resource pool: `[ArrayQueue<ScanResources>; NUM_CLASSES]` indexed by `input_len.next_power_of_two().trailing_zeros()`. Replaces linear scan + Mutex.
- Delete `#[deprecated]` `scan` method per LAW 9 (deprecated-waiting-room is evasion); migrate callers to `scan_immediate` / `scan_record`.

### A4. Streaming dispatch
`vyre-wgpu/src/engine/streaming.rs`.

Problems:
- `Arc<Mutex<mpsc::Receiver<Job>>>` (`:41-46`) — every worker serializes at `receiver.lock()`.
- Worker count hardcoded `min(available_parallelism(), 4)` (`:44-46`) — on a 128-core machine, 32× scaling regression.
- Panic recovery (`:86-93`) calls `catch_unwind` — hides crashes. LAW 9.

Fix:
- Replace with `crossbeam_channel::unbounded()` (cloneable receiver, lock-free).
- Make worker count configurable via `DispatchConfig::stream_workers` (default: all cores, or TOML override).
- Remove `catch_unwind`. If a chunk panics, surface it as `BackendError`; the process can decide to abort.

### A5. Async copy pool
`vyre-wgpu/src/engine/streaming/async_copy.rs`.

Problems:
- `thread::spawn(copy)` (`:42`) — one OS thread per `async_load` call. 10K tags = 10K threads.

Fix:
- Shared `rayon::ThreadPool` owned by the scheduler (or `crossbeam_deque::{Worker,Stealer}`).
- `async_load` enqueues a task that sets a `OnceLock<Result<(), BackendError>>`.
- `async_wait` spin-reads the `OnceLock`, yielding if not yet set (`std::hint::spin_loop` or `std::thread::park`).
- Adversarial test: 10,000 concurrent async_loads on a 32-thread pool; max threads spawned ≤ 32.

### A6. Tiered cache O(n²) `make_room`
`vyre-wgpu/src/runtime/cache/tiered_cache.rs:291-308`.

Problems:
- `make_room` calls `policy.eviction_candidate` per iteration; `eviction_candidate` (`:96-108`) iterates `tracker.iter_coldest()` — O(n²) under pressure.

Fix:
- Change `TierPolicy::eviction_candidates` to return a bounded iterator the caller drains.
- Keep the LRU intrusive list authoritative; `make_room` pops cold entries until fit.

### A7. Readback ring O(n) `begin_dispatch`
`vyre-wgpu/src/runtime/readback_ring.rs:206-211`.

Problems:
- `inflight = slots.iter().filter(...).count()` iterates every slot on every dispatch.

Fix:
- Maintain `inflight: AtomicU64` incremented in `begin_dispatch`, decremented in `complete_slot` and `release_slot`.
- Remove the filter-count; just `load` the atomic.

### A8. Pipeline disk cache audit
`vyre-wgpu/src/pipeline_disk_cache.rs`, `pipeline_persistent.rs` (546 lines — splits too).

Audit:
- fsync on write? Without it, power loss = corrupted cache.
- Checksums? Without them, a flipped bit = wrong shader.
- Version skew handling? Old caches on new binaries must be rejected cleanly.
- Concurrent open from two processes: file-locking (`fs2::FileExt::try_lock_exclusive`).

Fix whichever are broken; add proptest for each.

---

## B. Unwrap + panic discipline (wgpu-only)

### B1. Sweep `.unwrap()` in vyre-wgpu src
- `vyre-wgpu/src/lib.rs` (2 sites — the validation cache `.read().unwrap()` / `.write().unwrap()`)
- `vyre-wgpu/src/engine/dfa.rs:320` (`receiver.recv().unwrap()`)
- `vyre-wgpu/src/runtime/readback_ring.rs` (3 sites)
- `vyre-wgpu/src/runtime/router.rs` (2 sites)
- `vyre-wgpu/src/runtime/cache/buffer_pool.rs` (2 sites)

Replace each with `?` or `.expect("Fix: <actionable reason>")`. The `Fix:` prose is mandatory (enforced by `scripts/check_expect_has_fix.sh`).

### B2. `#![forbid(unsafe_code)]` on each crate
Add to `vyre-wgpu/src/lib.rs`, `backends/spirv/src/lib.rs`, `vyre-macros/src/lib.rs`.

---

## C. Config surface

### C1. Centralize wgpu-backend knobs
- `MAX_RETAINED_BYTES` (buffer pool)
- `DEFAULT_MAX_MATCHES`, `MAX_DFA_MATCHES` (DFA)
- `DEFAULT_RING_SIZE` (readback ring)
- `StreamingPool` worker count
- `IntrusiveLru::DEFAULT_INTRUSIVE_LRU_CAPACITY`
- `ArrayQueue` capacity per buffer class
- `MAX_VALIDATION_CACHE_ENTRIES`

Unified struct in `vyre-wgpu/src/config.rs` with TOML loader. Env-vars (like `VYRE_READBACK_RING_SIZE`) become overlays; document all in one place.

### C2. Remove duplicate constants
Audit every literal `1 << 30`, `65_536`, `1024`, `4 * 1024 * 1024` in wgpu source — each either becomes a named config field or stays as a doc'd algorithmic constant.

---

## D. SPIR-V backend

### D1. `backends/spirv/src/lib.rs` audit
- 1 `.unwrap()` site — fix.
- Confirm capability-negotiation: `inventory::submit!(BackendRegistration{..})` carries `supported_ops`.
- Confirm `supports_dispatch=true` and a real Vulkan path exists (or the backend shouldn't register).

### D2. Parity with wgpu backend
- Every optimization landed in `vyre-wgpu` (buffer pool, validation cache, readback ring) must have a SPIR-V equivalent OR the SPIR-V backend documents why it doesn't need one.

---

## E. Benchmarks — honesty

### E1. `benches/vs_cpu_baseline.rs` — include allocation
Currently measures steady-state without upload. Fortune-500 perf engineers read this first.

Fix:
- Keep the warm-path bench, rename it `warm_dispatch_only`.
- Add a new headline bench `cold_dispatch_end_to_end` that includes: Program build, validation, shader compilation, buffer upload, dispatch, readback.
- CSV-export both; chart in `docs/performance.md`.

### E2. `benches/registration_overhead.rs` — adversarial variant
Current claim: 1.95 ns warm lookup. Add:
- Cold-path variant (fresh process, first call).
- Collision-heavy variant (10,000 registered extensions with adversarial IDs).
- Both committed to baselines under `benches/baselines/`.

### E3. Missing: memory-bandwidth roofline
Author `benches/roofline.rs`:
- Per primitive: measured GB/s vs theoretical GDDR bandwidth.
- Proves primitives are bandwidth-bound (or documents why not).
- CSV export; CI gate: regression > 10% fails.

### E4. Un-ignore the `#[ignore]` benches
- `benches/vs_cpu_baseline.rs:N` has 1 `#[ignore]`. Remove the ignore, fix the underlying cause.

---

## F. Root integration tests

### F1. `tests/launch_smoke_test.rs`
Confirm it runs. Add additional smoke tests for each public entry point in `WgpuBackend`.

### F2. Un-ignore adversarial/gap/migration tests
Files with `#[ignore]`:
- `vyre-wgpu/tests/migration_shader_parity.rs` (2)
- `vyre-wgpu/tests/dispatch_hot_path_invariants.rs` (4)
- `vyre-wgpu/tests/gap/test_primitive_select_gap.rs` (1)
- `vyre-wgpu/tests/gap/primitive_math_gap.rs` (1)
- `vyre-wgpu/tests/gap/test_primitive_math_gap.rs` (1)
- `vyre-wgpu/tests/gap/test_primitive_clamp_gap.rs` (1)

Each `#[ignore]` is a confession. Fix the engine, not the test.

### F3. `#[allow(dead_code)]` / `#[allow(unused_*)]` in tests
- `vyre-wgpu/tests/kat_parity.rs` — audit; if the allow hides a real gap, fix the test.

### F4. Adversarial suite expansion
- `vyre-wgpu/tests/adversarial/float/common.rs` (588 lines) — split per SQLite/Linux standard.
- Per LAW 5: every module needs unit + adversarial + property + benchmark + gap tests.
- OOM injection for every dispatch entry point.
- Fuzz harness via `cargo-fuzz` at `vyre-wgpu/fuzz/` (if not present).

---

## G. Large-file splits (Agent 2 territory)

### G1. Files > 500 lines in Agent 2 paths
Use `splitrs` (memory: `rust-module-tooling.md`). Do not hand-roll.

- `vyre-wgpu/src/lowering/naga_emit.rs` (1008)
- `vyre-wgpu/src/engine/decode/codec/ast.rs` (689)
- `vyre-wgpu/src/pipeline_persistent.rs` (546)
- `vyre-wgpu/src/pipeline.rs` (495)
- `vyre-wgpu/tests/adversarial/float/common.rs` (588)
- `vyre-wgpu/tests/support/mock_backend.rs` (520)
- `vyre-wgpu/src/engine/decode.rs` (459)
- `vyre-wgpu/src/engine/dataflow.rs` (441)
- `vyre-wgpu/tests/lower/wgsl.rs` (432)
- `vyre-wgpu/src/engine/dataflow/bfs/bfs_reachability.rs` (420)
- `vyre-wgpu/tests/proptest_invariants.rs` (405)
- `benches/primitives_showcase_support/gpu.rs` (409)

---

## H. Macros

### H1. `vyre-macros/src/lib.rs` audit
- Has `#[allow(dead_code)]` / `#[allow(unused_*)]` — if the allow hides real dead code, delete it.
- Every public macro (`define_op!`, etc.) needs doctest demonstrating minimal usage.
- Proc-macro span coverage: every generated code block must pass `-D missing_docs`.

---

## I. Input validation / security (wgpu boundary)

### I1. Cap output + input bytes
Per completion audit (#24):
- `DispatchConfig::max_output_bytes` — honored in every dispatch path.
- `MAX_INPUT_BYTES` constant — enforced before buffer upload.
- Per-dispatch output size tracked; exceeding cap returns `BackendError::OutputTooLarge`.

### I2. Fuzz the entry points
`cargo-fuzz` targets:
- `fuzz_target!(|program_bytes: &[u8]| { Program::from_wire(program_bytes); })` — already in `vyre-core/fuzz` presumably; mirror at wgpu boundary.
- `fuzz_target!(|(program, inputs): (Program, Vec<Vec<u8>>)| WgpuBackend::acquire().and_then(|b| b.dispatch(...)))`.

---

## J. Execution rules for Agent 2

- Commit directly to `main`. No worktrees.
- No `todo!()`, `unimplemented!()`, `// TODO`, `// FIXME` left behind. LAW 1 + LAW 9.
- No weakening of tests. If a test fails, fix the engine.
- Run `bash scripts/check_legendary_signoff.sh` after each task.
- Do NOT touch any file under `vyre-core/`, `vyre-spec/`, `vyre-reference/`, `conform/`, `ops-facades/`, `backends/photonic/`, `examples/`, `demos/`, `docs/`, `scripts/`, or root-level files. Those are Agent 1.
- If a fix needs an API added to `vyre-core`, consume whatever exists on `main`. If genuinely blocked, write a brief note to `.internals/coordination/agent2-to-agent1-needs-api.md` and pick a different task.
- You can consume `NagaBuilder` from `vyre-core` once Agent 1 publishes it; until then, work on hot-path / bench / test tasks which don't depend on it.
