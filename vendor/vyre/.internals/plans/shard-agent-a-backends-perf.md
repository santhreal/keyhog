# SHARD AGENT-A — Backends + Performance

You own 11 tasks from `.internals/planning/LEGENDARY.md`. Work for hours. Direct
commits to `main`. Each commit references the task id (`vyre §5: ...`).

Read `.internals/planning/LEGENDARY.md` once before starting — the §-numbers
below index into it and the full spec for each task lives there. Read
`docs/THESIS.md` and `docs/ARCHITECTURE.md` for the invariants.

## Global invariants (non-negotiable)

1. **Zero runtime cost on the dispatch hot path.** No locks, no per-call
   allocations, no per-call hashing beyond one FxHash, no per-call syscalls
   unless strictly required. Build time and abstraction depth are free to grow.
   Runtime cycles are not. Every optimization is a fix (CLAUDE.md: "optimizations
   are fixes at internet scale").
2. **No stubs (LAW 1).** Never `todo!()`, `unimplemented!()`, empty `match` arms,
   or functions that lie about what they do. If you can't implement it, iterate
   until you can — 100 iterations acceptable, 1 stub not.
3. **Don't delete, implement (LAW 7 / feedback_dont_delete_implement).** Broken
   imports / orphans / "dead" code after a refactor = migration signal, not
   delete-permission. Rewire to the current API unless the whole subsystem is
   gone from the product.
4. **Honor Law H substrate-neutrality** inside `vyre-core/src/` — no `workgroup`,
   `subgroup`, `warp`, `wgsl`, `ptx`, `msl` in that tree. But those words are
   first-class and correct inside your owned backend directories.
5. **IEEE-754 strict floating-point.** No fast-math, no polynomial
   approximations, no `_vyre_fast_*` wrappers. GPU backends emit naga's precise
   variants. CPU reference uses the `libm` crate (deterministic, IEEE conformant).
   Conform enforces bit-identical CPU outputs and ≤1 ULP GPU drift.
6. **Every commit compiles.** Run `cargo check --workspace --all-features` before
   every commit. If you introduce churn that takes multiple commits to stabilize,
   use a scratch branch and squash — never land a red commit on main.

## Owned files — you may edit these

**Backend crates (full ownership):**
- `vyre-wgpu/**`
- `backends/photonic/**`
- `backends/spirv/**`

**Per-dialect shader directories** (the sub-dialect subdirectories; each
contains `op.rs`, `wgsl.rs` / `naga.rs`, and op-specific helpers):
- `vyre-core/src/dialect/buffer/**`
- `vyre-core/src/dialect/decode/**`
- `vyre-core/src/dialect/encode/**`
- `vyre-core/src/dialect/hash/**`
- `vyre-core/src/dialect/logical/**`
- `vyre-core/src/dialect/math/**`
- `vyre-core/src/dialect/security_detection/**`
- `vyre-core/src/dialect/stats/**`
- `vyre-core/src/dialect/string_matching/**`

**Optimizer passes + scheduler:**
- `vyre-core/src/optimizer/passes/**`
- `vyre-core/src/optimizer/scheduler.rs`
- `vyre-core/src/optimizer/rewrite.rs`
- `vyre-core/src/optimizer/tests.rs`
- `vyre-core/src/optimizer/fusion_cert.rs`

**Low-level lowering (IEEE math lives here):**
- `vyre-core/src/lower/**` (IEEE math wgsl emit — §24)

**Benches (all yours):**
- `benches/**` (every file)
- `scripts/bench/**`
- `scripts/check_benchmarks.sh`
- `scripts/run-benchmarks.sh`

## Forbidden files — never touch

- `vyre-core/src/dialect/registry.rs`, `migration.rs`, `mutation.rs`,
  `op_def.rs`, `enforce.rs`, `lowering.rs`, `interner.rs`, `dialect.rs`,
  `mod.rs`, `io.rs`, `core_indirect.rs` (Claude owns the dialect infrastructure)
- `vyre-core/src/ir/**` (everything — Claude owns IR + wire)
- `vyre-core/src/ops/**` (Claude owns this entire tree; you never touch it.
  If you need an op's cpu_ref or a signature detail, read-only is fine.
  When OpDefRegistration legacy is gone and ops/ is mostly empty, Claude will delete
  the tree — not you.)
- `vyre-spec/**` (Claude owns IR data types)
- `vyre-macros/**` (Claude owns proc macros)
- `vyre-reference/**` (Agent-B)
- `conform/**` (Agent-B)
- `docs/**` (Claude — except `docs/benchmarks.md` if you create it, which is
  fine)
- `scripts/check_no_*.sh`, `check_architectural_invariants.sh`,
  `check_trait_freeze.sh`, `check_registry_consistency.sh`,
  `check_capability_negotiation.sh`, `check_unsafe_justifications.sh`,
  `check_expect_has_fix.sh` (Claude owns the Law gates; your additions to
  `benches/budgets.toml` and `scripts/check_benchmarks.sh` are yours)
- `.github/workflows/architectural-invariants.yml`, `ci.yml`, `conform.yml`
  (Agent-B owns CI gates; you add `.github/workflows/bench-regression.yml`)
- `vyre-core/Cargo.toml`, workspace `Cargo.toml` (Claude)
- `examples/**`, `demos/**` (Agent-B for examples, untouched for demos)
- Every `Cargo.toml` **except** the crates you own. You may edit
  `vyre-wgpu/Cargo.toml`, `backends/photonic/Cargo.toml`,
  `backends/spirv/Cargo.toml`.

## Known issues at plan start (fold into existing tasks)

These are concrete, verified bugs. Each maps to one of your tasks below.
When you land the task, the issue must be GONE — not documented, not
deferred. No evasion (LAW 9).

- **Validation re-runs on every dispatch** (`vyre-wgpu/src/lib.rs:251,266,286,337`)
  → fold into #15 §7. Implement the validation cache and prove the re-run
  sites are eliminated.
- **Buffer pool O(N) scan** (`vyre-wgpu/src/buffer/pool.rs:125-140`)
  → fold into #13 §5. The size-class array rewrite makes this O(1).
- **DFA readback waste** (`vyre-wgpu/src/engine/dfa.rs:290`) — two sequential
  round-trips (count, then positions) → fold into #13 §5. Use indirect
  dispatch writing match positions into a populated prefix; readback maps
  only the populated range.
- **CSE ExprKey recursive allocation** (`impl_exprkey.rs`)
  → fold into #16 §13.2. Flat atom vec + `u32` child-ids as spec'd.
- **Group 0 hardcoding** (`vyre-core/src/lower/mod.rs:170`,
  `vyre-wgpu/src/pipeline_bindings.rs:12`)
  → fold into #13 §5.17. Honor `BufferDecl::group: u8`. Emit
  `var<push_constant>` for small uniforms.
- **Raw WGSL string parsing in dialect lowerings** (`build_stack_naga`,
  `build_hashmap_naga`) → fold into #17 §8. These are part of the
  `parse_str` sweep to naga structural emission.
- **Benchmark excludes buffer allocation from timed loop** → fold into #31.
  The criterion harness must run the actual `run_full_upload_and_dispatch`
  inside the timed scope. Any bench that measures only steady-state
  compute is **mis-labeled "upload-inclusive"** — either fix the loop or
  relabel to "steady-state-only." No silent-fraud benches.

## Your 11 tasks

### #13 — §5 Dispatch hot path (no per-call alloc) — BIG

**Where:** `vyre-wgpu/src/pipeline.rs`, `pipeline_persistent.rs`,
`pipeline_bindings.rs`, `engine/**`, `buffer/**`, `runtime/**`.

**What:**
- `record_and_readback` allocates `input_buffer`, `output_buffer`,
  `params_buffer`, `readback_buffer` per call. Route every one through the
  existing `BufferPool`. Make the pool path the **only** path. Delete
  `legacy_handles_from_inputs`.
- `BindGroupCache` becomes default for `dispatch()`, not opt-in.
- Grow `DispatchConfig` — Claude's file is `vyre-core/src/backend.rs`. You
  own the fields you need by ADDING a separate struct
  `vyre-wgpu::DispatchHints { workgroup_hint, adapter, persistent_buffers,
  expected_output_bytes, blocking }` in `vyre-wgpu/src/dispatch_hints.rs`
  (new, your file). The hot path reads hints via
  `DispatchConfig::hints<T>()` pattern — a downstream-extendable carrier.
  This avoids editing Claude's file and keeps your config additive. If the
  hints carrier ends up on `DispatchConfig` itself later, migration is one
  rename.
- Cache `blake3(naga::Module)` on `CompiledPipeline`. Hot-path compare = 32 bytes
  compare.
- `BufferPool` rewrite: from `Vec<Entry>` O(N) scan to
  `[Vec<Entry>; NUM_SIZE_CLASSES]` indexed by
  `size.next_power_of_two().trailing_zeros()`. O(1) acquire.
- Streaming engine (`engine/streaming.rs`, `engine/streaming/async_copy.rs`):
  replace `thread::spawn` per chunk with `crossbeam_deque` lock-free worker
  pool. Or a rayon-style pool sized by `available_parallelism().min(4)` with
  bounded queue.
- `TieredCache::get` O(N) → intrusive LRU: embed prev/next pointers in each
  entry, O(1) unlink+push on promote, O(1) pop_back on evict.
- `BufferDecl::group` is honored; emit `var<push_constant>` for small uniforms.
- `Program::buffer_index` String keys → intern to `Arc<str>` or `BufferId(u32)`.
  Hot-path lookups = pointer compare.
- Output zero-init: `mapped_at_creation: true` + `get_mapped_range_mut().fill(0)`
  + `buffer.unmap()`. Zero host allocation, zero bus transfer.
- Replace `write_buffer(..0-vec..)` with `CommandEncoder::clear_buffer(..)`
  where wgpu supports it, else SCRATCH_ZEROS static.
- Async readback: single future, not mpsc channel. `DispatchConfig::blocking=true`
  falls back to blocking.

**Success:**
- `cargo bench --bench vs_cpu_baseline` shows ≥5× speedup on repeated dispatches
  vs the old hot path (baseline landed in `benches/baselines/vs_cpu_baseline.json`).
- `cargo test -p vyre-wgpu` green.
- `vyre-wgpu/src/` grep for `Vec::new()`, `vec![0u8;`, `Box::new` inside
  `pub fn dispatch` / `pub fn record_and_readback` returns zero hits on the
  hot path.

### #14 — §6 Disk pipeline cache wiring

**Where:** `vyre-wgpu/src/pipeline_disk_cache.rs`, `pipeline.rs`, `runtime/**`.

**What:**
- `compile_with_config` consults `DiskPipelineCache` on miss.
  key = `blake3(naga::Module) ⊕ DeviceFingerprint`.
- `DeviceFingerprint::for_adapter` reads `AdapterInfo { vendor, device,
  driver_info }` and folds into stable PCIe id triple.
- On hit, deserialize into `wgpu::PipelineCacheDescriptor`, pass to
  `Device::create_compute_pipeline`.
- Platform defaults: `XDG_CACHE_HOME` / `~/.cache` / `LOCALAPPDATA`.
  Env overrides `VYRE_PIPELINE_CACHE_DIR`, disable via `VYRE_PIPELINE_CACHE=0`.
- LRU eviction by mtime. Bound with `VYRE_PIPELINE_CACHE_MAX_BYTES`
  (default 256 MiB).

**Success:**
- New bench `benches/disk_cache_cold_vs_warm.rs`: warm ≥10× faster than cold.
- Lands two rows in `benches/RESULTS.md`.

### #15 — §7 Validation cache on hot path

**Where:** `vyre-wgpu/src/pipeline.rs`, a new module
`vyre-wgpu/src/validation_cache.rs`.

**What:**
- `verify_program_certificate` result content-addressed by
  `blake3(program.to_wire())`. `LazyLock<DashMap<[u8;32], Certified>>`.
- `CompiledPipeline` holds `validated: AtomicBool` set once on successful
  compile. Hot path skips revalidation entirely.
- Debug builds opt-in via `debug_assertions || VYRE_VALIDATE_ALWAYS=1`.
- `to_wire()` lives in `vyre-core::ir::serial::wire` — call through.

**Success:** criterion bench shows cache hit takes <100 ns, miss takes
real validation time. Release profile skips path on hit.

### #16 — §13 Optimizer correctness + fusion certs

**Where:** `vyre-core/src/ir/transform/optimize/cse/**`,
`optimize/dce/**`, `vyre-core/src/optimizer/passes/**`,
`vyre-core/src/optimizer/scheduler.rs`, `vyre-core/src/optimizer/fusion_cert.rs`.

**What:**
- `ExprKey` is recursive-Box today. Rewrite as flat atom vec + `u32` child-ids.
  Dramatic improvement on deep IR.
- CSE scope stack must clone `ExprKey` only (content-addressed key), never
  `Expr`. Audit.
- DCE + dead_buffer_elim route through `ExprVisitor`/`NodeVisitor`. Claude
  lands these visitor traits in `vyre-core/src/ir/visit/**` — read them and
  use them. If a trait method you need isn't there yet, extend your local
  matcher on the open set of variants you handle and push it as a visitor
  impl via your normal commit. **Never stub.** Never write `todo!()`.
  Never leave a `// TODO`. Implement the match arms you can, even if the
  Opaque variant rides through as a pass-through call to `ExprNode::visit`
  or its Node counterpart.
- `FusionCertificate` is already scaffolded in
  `vyre-core/src/optimizer/fusion_cert.rs`. Wire into `passes::fusion`:
  every `FusionDecision` builds a cert comparing unfused vs fused on the
  `U32Witness` set (witness set type in `conform/vyre-conform-spec/src/witness.rs`
  — read-only for you). Attach cert to transformed Program's metadata.
  Compile step that rejects `parity_holds=false` refuses to emit the fused
  kernel.
- Verify `fingerprint_program = blake3(Program::to_wire())`. Fix if not.
- Scheduler: every registered pass has explicit `requires`/`invalidates`.
  Topologically sort. Missing invalidates = stale cache = silently wrong
  output — CI-fail if any pass omits.
- `PassAnalysis::RUN/SKIP` honored. Add xtask subcommand
  `cargo xtask --dump-passes <program>` that prints pass order.

**Success:** optimizer tests green, fusion cert attached to every fused
program, `xtask --dump-passes` produces correct ordering for the primitive corpus.

### #17 — §8 Structured shader emission only — BIG, mechanical

**Where:** every `vyre-core/src/dialect/<dialect>/<op>/wgsl.rs`.

**What:** the `scripts/check_no_parse_str.sh` tracker currently counts ~80+
call sites to `naga::front::wgsl::parse_str`. Rewrite each to construct the
naga module programmatically via a shared `ModuleBuilder` surface. Cluster
targets are the same §8.3 families in
`.internals/planning/LEGENDARY.md`: workgroup structures, security
detectors, sliding entropy, string matching, and decode lowerings.

**Per-rewrite contract:** rename the file from `wgsl.rs` to `naga.rs`. Build a
`naga::Module` via a reusable `ModuleBuilder` (grow it in
`vyre-wgpu/src/lowering/naga_emit.rs` — that's yours). Add a **byte-parity
test**: new output vs `naga::back::wgsl::write_string` of the new builder's
module should match the old `parse_str` output byte-for-byte. Drift means
behavior change — investigate.

**Success:**
- `scripts/check_no_parse_str.sh` baseline drops to zero.
- Tests green per dialect.
- When shader asset cannot yet be expressed structurally, document in
  `vyre-wgpu/src/shaders/` with a `// TODO(structural-emit): <naga capability>`
  comment naming what naga must ship. These are the only surviving `.wgsl`
  files in the tree.

### #18 — §34 Pattern engines (regex-automata + aho-corasick)

**Where:** `vyre-core/src/dialect/string_matching/**`.

**What:**
- `df_assemble` concatenates patterns with `|` alternation. Replace with
  `regex-automata::meta::Regex` multi-pattern API. Proper NFA→DFA subset
  construction over multi-pattern NFA avoids exponential blowup.
- `aho_corasick_scan` uses the `aho-corasick` crate's internals (do not
  reimplement). The wgpu backend compiles the AC DFA into a GPU transition
  table (that lowering lives in `vyre-wgpu/src/engine/dfa.rs` — yours).
- Retire `nfa_scan` (Phase 7). Pattern ops compose in vyre IR directly — no
  micro-interpreter.

**Success:** tests green, bench vs hyperscan + ripgrep on a 100 MB corpus
lands two rows in `benches/RESULTS.md`.

### #19 — §33 Memory model correctness

**Where:** `vyre-core/src/dialect/**` (audit BufferDecl::kind across every op).

**What:** every `BufferDecl::kind` declaration gets a human verification —
Global / Shared / Uniform / Readonly is the correct tier for the access
pattern. Every `Expr::Atomic` carries a `MemoryOrdering`; default when unset
is `SeqCst`.

**Success:** a new test `vyre-core/tests/memory_model_audit.rs` iterates every
registered op, reads each BufferDecl, and fails if any declaration looks
inconsistent with the op's category (e.g. a Cat-C intrinsic with Global Uniform
probably wrong). Test is informational at first (just prints); agent-B
promotes to hard-fail once coverage is manual-reviewed.

### #22 — §31 Observability via tracing

**Where:** `vyre-wgpu/src/**` (instrumentation), `vyre-wgpu/Cargo.toml` (tracing
dep).

**What:**
- Tracing spans on dispatch hot path: one parent span per `dispatch`, child
  spans per `compile`, `record`, `readback`. Target `vyre::dispatch`.
- Zero overhead when disabled (default). Never `format_args!` in the hot path
  — field-only events.
- Fields: `dispatch_ns`, `compile_ns`, `readback_ns`,
  `buffer_pool_hit_rate`, `bind_group_cache_hit_rate`, `disk_cache_hit_rate`.
- `BackendError` variants hook `tracing::error!` with variant name as message
  and fields as structured data.

**Success:** `cargo test -p vyre-wgpu --features tracing-test` exercises the
spans. bench comparing no-tracing vs tracing-off shows zero overhead.

### #24 — §9 IEEE-754 math (no approximations)

**Where:** `vyre-core/src/lower/**` (wgsl emit), any dialect that currently
has `_vyre_fast_*` (grep it), `vyre-reference`-adjacent (leave that for
Agent-B — you don't touch reference; just remove the fast-math WGSL path).

**What:**
- Delete all `_vyre_fast_sin / _vyre_fast_cos / _vyre_fast_exp / _vyre_fast_log`
  identity wrappers.
- WGSL/SPIR-V backends emit naga's precise variants. No `fastSin`.
- AlgebraicLaw set for every float op declares "IEEE-754 conformant" — push a
  commit adding the laws to each op's OpDef (inside your owned dialect dirs).
  Conform enforces bit-identical CPU outputs (libm is deterministic) and ≤1
  ULP GPU drift.

**Success:** `cargo test -p vyre-core --features full-ieee-math` green. Grep
for `fast_sin|fast_cos|fast_exp|fast_log|fastSin|fastExp` returns zero.

### #10 — §26 Photonic stub integrity

**Where:** `backends/photonic/**`.

**What:**
- Registers successfully with the runtime.
- `supports_dispatch` returns `false`.
- `dispatch` returns `Err(BackendError::UnsupportedFeature { feature:
  "dispatch", backend: "photonic" })`.
- Conform run treats photonic as "registration + capability query" subset-only.
  Parity pages show `photonic: not_applicable` column.
- Core trait changes that photonic can't compile against = CI fails (forcing
  function for substrate leaks).

**Success:** `cargo test -p photonic` green, `cargo test -p
vyre-conform-runner` green with photonic included.

### #31 — §16 + §36 Benchmarks + perf budgets

**Where:** `benches/**`, `scripts/bench/**`, `scripts/check_benchmarks.sh`,
`benches/budgets.toml` (new), `benches/baselines/*.json` (new),
`benches/RESULTS.md`, `.github/workflows/bench-regression.yml` (new —
coordinate with Agent-B who owns other CI files).

**What:**
- Verify `vs_cpu_baseline.rs` compares against a real hand-tuned reference
  (HAND_TUNED_REFERENCE constant or labeled "single-backend measurement").
  No self-compare.
- Verify `primitives_showcase.rs` runs the actual ops inside the timed loop
  (not `black_box(len())`). The support already has
  `run_full_upload_and_dispatch` — confirm every bench uses it.
- `benches/baselines/<bench>.json` per bench.
- `benches/RESULTS.md` gains wgpu + spirv + reference columns. Upload-inclusive
  + steady-state rows.
- `xtask --compare-spirv-vs-wgpu` emits diff table in ms + GB/s.
- Memory amplification bench via stats_alloc: `(heap_bytes +
  gpu_buffer_bytes) / theoretical_minimum` ≤ 1.5×.
- `benches/budgets.toml` has `<bench>.max_ns_per_element = N`. CI fails
  overruns unless commit carries `allow-perf-regression: <reason>` AND bumps
  the budget explicitly in the same diff.
- `.github/workflows/bench-regression.yml`: criterion --quick over the reduced
  bench suite. 5% regression = fail; 2% for hand-tuned paths.

**Success:** `cargo bench --all` produces stable numbers. CI gate wired. No
self-comparisons in the benchmarks.

## Merge protocol

- Commit to `main` directly. Each commit touches only owned files and is
  self-contained.
- Commit message prefix: `vyre §<N>: <one-line summary>`.
- Before committing: `cargo check --workspace --all-features` must pass (or
  error count monotonically decreasing). Never raise the count.
- You never wait on another shard. If you need functionality in a file you
  don't own, add it to YOUR side (new module in a crate you own, new method
  on a struct you own, new trait you define and implement). If that leaves
  an awkward seam, it gets fixed in a later pass — but progress never stops.
- No `// TODO` markers. No `// FIXME`. No placeholders. Implement what you
  own. Leave nothing partially done.

## What "done" looks like for your shard

- All 11 tasks committed.
- `cargo check --workspace --all-features --all-targets` green OR monotonically
  closer to green than when you started.
- `cargo bench --all` runs and `benches/RESULTS.md` has real numbers.
- Every file you own passes `cargo clippy --workspace -- -D warnings` within
  the files you touched.
- No stubs in any file you touched. No `todo!()`, no `unimplemented!()`, no
  empty match arms.

Go.
