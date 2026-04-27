# LEGENDARY — vyre execution plan

Assembled 2026-04-19. Linus-style. No timelines. No deferrals. No scope
inflation toward breadth (multi-GPU, io_uring, telemetry, metal/cuda are
OUT). Scope is correctness, extensibility, performance, organization,
cleanliness — the dimensions on which vyre is either legendary or a lie.

Every item is named, concrete, and load-bearing against THESIS.md. If
you can't tell from the item what file to touch, the item is not
concrete enough and needs rewriting before starting it.

Items are ordered by dependency. Earlier items unblock later ones.

---

## §1 — IR OPENNESS

**The thesis says new IR nodes ship in downstream crates without editing
core. Today some pieces exist (`Expr::Opaque`, `Node::Opaque`,
ExprNode/NodeNode traits) but other pieces do not, and the open surface is
not actually exercised by every pass in the pipeline. Close the gaps.**

1.1  `DataType` (vyre-spec/src/data_type.rs:14) is `#[non_exhaustive]`
but has **no** `Opaque` variant. Add
`DataType::Opaque(ExtensionDataTypeId)`. Register payload metadata via
`inventory::collect!(ExtensionDataTypeRegistration)`. Implement
`size_bytes / min_bytes / max_bytes / is_float_family / is_host_shareable`
via the registered trait. Tag on wire as `0x80 + u32 extension_id`.

1.2  `BinOp`, `UnOp`, `AtomicOp` (vyre-spec/src/{bin_op,un_op,atomic_op}.rs)
are `#[non_exhaustive]` but have no `Opaque` variant. Add one to each
with `ExtensionBinOpId(u32)` etc. Extension ops supply cpu_ref / naga
builder / spv builder / fingerprint / encode via the registered trait.
Without this the DataType Opaque is mute — you can declare a new data
type but not operate on it.

1.3  `RuleCondition` (vyre-core/src/ops/rule/ast.rs) is closed. Add
`RuleCondition::Opaque(Arc<dyn RuleConditionExt>)`. The builder in
`vyre-core/src/ops/rule/builder.rs` hardcodes six buffer declarations —
replace with a `RuleConditionExt::required_buffers() -> Vec<BufferDecl>`
trait method so extensions declare their own buffer shape.

1.4  `Backend` enum (vyre-core/src/ops/metadata.rs:41) is
`{ Wgsl, Cuda, SpirV, Metal }`. That is a closed list of sacred ids
pretending to be data. Replace with `struct BackendId(Arc<str>)` (or
`&'static str` for const-initialized callers). Every `match b { ... }`
becomes a `BackendRegistry::get(&id)` lookup or a string compare.
`#[non_exhaustive]` is not extensibility; it only shifts the compile
break to the matcher.

1.5  `ExprNode::stable_fingerprint` must be **injective** for distinct
payloads that are not semantically equal. Today `PartialEq` for
`Expr::Opaque` relies on extension_kind + fingerprint equality. Add a
property test that asserts: for two distinct `ExprNode` impls,
`stable_fingerprint()` values differ with overwhelming probability.

1.6  `ExprVisitor` and `NodeVisitor` exist but are not actually used by
transforms. Audit: grep `match ... {` in `vyre-core/src/ir/transform/*.rs`
and `vyre-core/src/optimizer/passes/*.rs`. Every site that reaches into
Expr or Node variants must route through `.visit(visitor)`. Closed-match
enforcement lives in `scripts/check_no_closed_ir_enums.sh`. Ratchet the
baseline down on every commit that migrates one site.

1.7  Concrete visitor refactors required (each is one PR):
- `vyre-core/src/ir/transform/optimize/cse/impl_exprkey.rs`
- `vyre-core/src/ir/transform/optimize/cse/impl_csectx.rs`
- `vyre-core/src/ir/transform/optimize/dce/collect_expr_refs.rs`
- `vyre-core/src/ir/transform/optimize/dce/expr_has_effect.rs`
- `vyre-core/src/ir/transform/dead_buffer_elim/*.rs`
- `vyre-core/src/ir/validate/expr_type.rs`
- `vyre-core/src/ir/validate/binop_rules.rs`
- `vyre-core/src/ir/validate/comparison_rules.rs`
- `vyre-core/src/ir/transform/inline/expand/*.rs`
- `vyre-core/src/ir/serial/wire/encode/put_expr.rs`
- `vyre-core/src/ir/serial/wire/decode/impl_reader.rs`
- `vyre-wgpu/src/lowering/naga_emit.rs`

1.8  `Expr::Call` is the last remaining primitive that forces the
optimizer to know about the DialectRegistry to inline. Inlining is
structurally fine but must route through the visitor API too, not via an
explicit `if let Expr::Call` branch. The "after optimizer" invariant that
no Call remains must be encoded as a visitor that rejects Call variants
at validate time post-inline.

1.9  `Node` already has Opaque via NodeNode trait. Verify every Node
match site mirrors §1.7 coverage. Remove every `_ =>` wildcard arm that
silently swallows unknown Node variants. A compile break is the right
outcome when a new Node ships.

1.10  Add **extension round-trip tests** covering: custom ExprNode /
custom NodeNode / custom ExtensionDataType / custom RuleConditionExt
each of which (a) registers via inventory, (b) round-trips a Program
through `to_wire` / `from_wire` byte-identical, (c) survives CSE + DCE
+ fusion passes unchanged, (d) validates without violating
`validate_extension()`. These live in
`vyre-core/tests/extension_round_trip.rs`. They are the proof that the
open-IR claim is real.

---

## §2 — SUBSTRATE-NEUTRAL VOCABULARY

**The thesis rule: substrate-specific words live in backend crates. If
`workgroup`, `subgroup`, `warp`, `WGSL`, `PTX`, `MSL` appear in
`vyre-core/src/`, that is a bug.**

2.1  `vyre-core` currently uses `workgroup_size` as a field name and
method on `Program`. Rename to `parallel_region_size` on the core API.
Keep `workgroup_size` as a backend-facing alias inside `vyre-wgpu` only.
`WorkgroupId` Expr variant → `ParallelRegionId` with axis.

2.2  `LocalId` Expr variant → `InvocationLocalId`. The WGSL-specific word
"local" is fine; it's the lack of a crisp neutral name that hurts.
Confirm the emitter still produces `local_invocation_id`.

2.3  `Node::Barrier` remains — "barrier" is already abstract. But audit
for `workgroupBarrier()` strings anywhere in vyre-core: zero tolerance.

2.4  Every reference to "WGSL" in `vyre-core/` comments and docs becomes
"the default backend shader" or names the backend directly. WGSL-named
tests that live in `vyre-core/tests/` move to `vyre-wgpu/tests/`.

2.5  `scripts/check_architectural_invariants.sh` (the Law H gate) grows
a vocabulary check: grep vyre-core/src for `/\bworkgroup\b|\bsubgroup\b|
\bwarp\b|\bwgsl\b|\bptx\b|\bmsl\b/i` and fail on any hit outside of a
comment explicitly marked `// WORD-OK:` (used in migration bridges only).

2.6  `docs/memory-model.md` and `docs/targets.md` already use neutral
vocabulary — confirm `scripts/check_no_string_wgsl.sh` whitelists those
paths.

---

## §3 — SINGLE REGISTRY

**Today `DialectRegistry` (post-V0.5 contract) and `OpSpec` (pre-V0.5
compat) both exist. Every op registers twice: via
`inventory::submit! { OpSpecEntry { ... } }` AND (sometimes) via
`OpDefRegistration`. This is drift fuel.**

3.1  Delete `vyre-core/src/ops/spec.rs`. The `OpSpec` struct goes with
it. Any remaining `OpSpec::composition_inlinable(...)` site migrates to
`::vyre::dialect::OpDefRegistration::new(|| OpDef { ... })` built via
the `define_op!` macro (vyre-macros/src/define_op.rs).

3.2  Delete `vyre-core/src/ops/registry/registry.rs` — its
`RUNTIME_REGISTRY: OnceLock<RwLock<Vec<&'static OpSpec>>>` is the
run-time compat path. `DialectRegistry::global()` is the only lookup.

3.3  Delete `vyre-core/src/ops/registry/static_generated/walked_ops.rs`
and the build-time code that produces it. The build_scan crate writes
these; remove both.

3.4  Delete `vyre-core/src/ops/OpSpecEntry` and the bridge
`register_op_spec!` macro.

3.5  Rewrite `vyre-core/src/ir/transform/inline.rs` to resolve compose
via `DialectRegistry::global().lookup(op_id).and_then(|d| d.compose)`.

3.6  Migrate **every** `pub const SPEC: OpSpec = OpSpec::...(...)` site
(count on last run: 119 composition + 6 composition + ~35 Cat C). Use
`define_op!` where possible, explicit `OpDefRegistration::new` where the
macro isn't expressive enough.

3.7  Delete `Compose::{Composition, Intrinsic}` dichotomy in
`vyre-core/src/ops/metadata.rs`. `OpDef.compose: Option<fn() -> Program>`
is sufficient: `None` is an intrinsic, `Some(f)` is a composition.

3.8  Law A, B, C, D, H all grow a sub-gate: no `OpSpec` token may appear
anywhere in the workspace after this §. Scripted, CI-enforced.

---

## §4 — INVENTORY HYPOCRISY

**`ARCHITECTURE.md` bans `inventory::submit`. `vyre-macros` and
`vyre-core/src/optimizer.rs` use it. CI never scans `vyre-macros`. Either
the ban is real and those usages are sin, or the ban is dead and must be
retracted. Decide.**

4.1  Retract the ban. `inventory` is load-bearing for registrations
(backends, passes, extensions, ops). The right constraint is "registration
at link time, not runtime dispatch." Rewrite ARCHITECTURE.md §B to say
exactly that.

4.2  Delete the Cat-B tripwire in conform that greps for
`inventory::submit`. It is the only place that believes the ban.

4.3  Extend `scripts/check_architectural_invariants.sh` to scan
`vyre-macros/src/` for the registration patterns. Blind spots are not
policy; they are bugs.

4.4  Document the inventory contract in one place: a single
`docs/inventory-contract.md` that names every inventory collection
(`OpDefRegistration`, `BackendRegistration`, `PassRegistration`,
`ExtensionRegistration`, `MigrationRegistration`) and the iteration
order guarantees (none — consumers must sort).

---

## §5 — DISPATCH HOT PATH

**Every audit hit this — buffer alloc, bind-group creation, readback
allocation per call. A GPU-first claim is a lie until the fast path
doesn't allocate.**

5.1  `vyre-wgpu/src/pipeline.rs::record_and_readback` still allocates
`input_buffer`, `output_buffer`, `params_buffer`, `readback_buffer` per
dispatch. Route every one through the existing `BufferPool`. The pool
exists; it isn't used on the default path.

5.2  `BindGroupCache` (vyre-wgpu/src/pipeline_persistent.rs): bind group
creation is the second-largest per-dispatch cost after buffer alloc.
Make it the default for `dispatch()`, not an opt-in.

5.3  `DispatchConfig` (vyre-core/src/backend.rs) grows: `workgroup_hint:
Option<[u32;3]>`, `adapter: Option<AdapterId>`, `persistent_buffers:
bool`, `expected_output_bytes: Option<usize>`. Anemic two-field config
today cannot drive the hot path.

5.4  `queue.write_buffer(buffer, offset, &vec![0u8; N])` — zero-fill via
fresh Vec per call is gone (S5.9 landed). Verify no site regressed. The
next wave: replace `write_buffer(..0-vec..)` entirely with
`CommandEncoder::clear_buffer(..)` where the wgpu feature is available,
else fall through to the SCRATCH_ZEROS static.

5.5  Pipeline cache `PIPELINE_CACHE: LazyLock<[RwLock<FxHashMap<...>>;
SHARDS]>` is sharded. Good. But the key is `blake3(naga::Module)` —
recompute per dispatch. Cache the blake3 on `CompiledPipeline` so the
hot path's compare is 32 bytes, not hash-on-every-look.

5.6  `legacy_handles_from_inputs` in pipeline.rs still allocates
GpuBufferHandle per input. The persistent-pool path exists; delete the
legacy path and make the pool path the only path.

5.7  `WgpuBackend::dispatch()` calls into `WgpuPipeline::compile_with_config`
on every call today, pays the cache lookup but still touches the pool for
each buffer. The compile path must be "resolve `CompiledPipeline` →
reuse existing buffer set if signature matches → `dispatch_persistent`
direct."

5.8  Readback overhead: `readback_buffer.slice(..)` + `mpsc::channel` +
blocking `recv()` is 3 syscalls minimum per dispatch. Replace with a
single future on the device's scheduler where wgpu supports it; fall
through to the blocking path only when the caller sets
`DispatchConfig::blocking = true`.

5.9  `WgpuBackend` is a ZST today. Replace with `WgpuBackend { device,
queue, adapter_caps, buffer_pool, pipeline_cache }`. `acquire()` takes
a `DispatchConfig::adapter` hint. The global singleton becomes a default
instance, not the only instance.

5.10  Indirect dispatch (`compute_pass.dispatch_workgroups_indirect`) is
emitted by `vyre-core::dialect::core_indirect`. Verify the wgpu backend
honors it without reconstructing the workgroup buffer. This path is for
streaming and for variable-size outputs.

5.11  `vyre-wgpu/src/engine/dfa.rs::dispatch` does two sequential
round-trips (count read → positions read). Replace with indirect
dispatch writing match positions into a populated prefix; readback maps
only the populated prefix range.

5.12  `BufferPool` (vyre-wgpu/src/buffer/pool.rs) today holds
`Vec<Entry>` and scans O(N) on acquire. Rewrite as `[Vec<Entry>;
NUM_SIZE_CLASSES]` indexed by `size.next_power_of_two().trailing_zeros()`.
O(1) acquire.

5.13  Streaming engine (vyre-wgpu/src/engine/streaming.rs) used
`thread::spawn` per chunk in the audit; current code routes through
`StreamingPool`. Verify the pool is lock-free. If it uses a
`Mutex<Receiver>` that serializes every worker, replace with
`crossbeam_deque::{Worker, Stealer}`.

5.14  `vyre-wgpu/src/engine/streaming/async_copy.rs` spawns a worker
thread per copy task. Replace with a rayon-style pool sized by
`available_parallelism().min(4)` with bounded queue.

5.15  `TieredCache::get` (vyre-wgpu/src/runtime/cache/tiered_cache.rs)
scans tiers linearly and calls `record_access` + `promote` per lookup.
Replace with an intrusive LRU: every entry embeds prev/next pointers;
promotion is O(1) unlink+push, eviction is O(1) pop_back.

5.16  `AccessTracker::stats` (vyre-wgpu/src/runtime/cache/lru.rs) is
O(N) in LRU size. The intrusive LRU eliminates this — remove the
standalone `AccessTracker` once the rewrite lands.

5.17  Hardcoded `@group(0)` (vyre-wgpu/src/pipeline_bindings.rs and
lowering). WGSL allows multiple groups + push constants. The lowering
must honor `BufferDecl::group: u8` (default 0 for compat) and emit
`var<push_constant>` bindings when a uniform buffer is small and
declared const.

5.18  `Program::buffer_index` (vyre-core/src/ir/model/program.rs) uses
`String` keys. Intern to `Arc<str>` via the existing StringInterner or a
new `BufferId(u32)` on the way in. Hot-path lookups become pointer
compares.

5.19  `DispatchConfig::default()` full-struct equality check on every
dispatch is `O(fields)` including `Option<String>`. Cache a sentinel
`const DEFAULT: DispatchConfig = ...` and compare by pointer where the
caller threads the default through.

5.20  Output-buffer zero-initialization (`vec![0u8; output_bytes]` in
`vyre-wgpu/src/lib.rs`) — replace with `BufferDescriptor { mapped_at_creation:
true, ... }` followed by `buffer.slice(..).get_mapped_range_mut().fill(0)`
and `buffer.unmap()`. Zero host allocation, zero bus transfer.

---

## §6 — COMPILE CACHE ON DISK

**`DiskPipelineCache` lands but nothing consumes it. Wire it.**

6.1  `WgpuPipeline::compile_with_config` consults `DiskPipelineCache` on
cache miss: `key = blake3(naga::Module) ⊕ DeviceFingerprint`.

6.2  On hit, deserialize the compiled pipeline bytes into
`wgpu::PipelineCacheDescriptor` and pass to
`Device::create_compute_pipeline`. Verify wgpu honors the cache
descriptor — if not, fall through to recompile and log.

6.3  `DeviceFingerprint::for_adapter(adapter)` — real implementation
reads `AdapterInfo { vendor, device, driver_info }` and folds into u32
triple. Drop vendor strings in favor of the stable PCIe IDs.

6.4  Bench: cold compile (disk empty) vs warm compile (disk hit). Land
a pair of rows in `benches/RESULTS.md` — not prose, numbers. If warm
isn't >=10× faster, the wiring is wrong.

6.5  `XDG_CACHE_HOME` / `HOME/.cache` / `LOCALAPPDATA` defaults match
platform. Environment override `VYRE_PIPELINE_CACHE_DIR`. Disabling via
`VYRE_PIPELINE_CACHE=0`.

6.6  Cache eviction: LRU by mtime across entries. Bound size by
`VYRE_PIPELINE_CACHE_MAX_BYTES` (default 256 MiB).

---

## §7 — VALIDATION SKIP ON HOT PATH

**`C6` in the audit: every dispatch re-runs `validate_program`.**

7.1  `verify_program_certificate` result is content-addressed by
`blake3(program.to_wire())`. Cache under `LazyLock<DashMap<[u8; 32],
Certified>>`. Re-validate only on miss.

7.2  `CompiledPipeline` holds a `validated: AtomicBool`. Set once on
successful compile, read on every dispatch, skip revalidation. Reset on
any mutating operation (there should be none post-compile; confirm).

7.3  Debug builds opt in to revalidation via `debug_assertions ||
VYRE_VALIDATE_ALWAYS=1`. Release skips the entire path on hits.

---

## §8 — WGSL: STRUCTURED EMISSION ONLY

**`parse_str` of a generated WGSL string is a round-trip: build a string,
hand it to a parser, parse it back into the AST we already had in mind.
Every one of the 84 remaining sites is theater.**

8.1  `scripts/check_no_parse_str.sh` tracker exists. Flip to `exit 1`
when count == 0. Ratchet: bump baseline down on every commit that
eliminates a site.

8.2  Shared naga::Module builder family lives in
`vyre-wgpu/src/lowering/naga_emit.rs`. Grow a reusable `ModuleBuilder`
surface that the dialect lowerings call into. Same backend builders are
reused by the SPIR-V backend.

8.3  Mechanical sweep — every `vyre-core/src/dialect/*/wgsl.rs` file
becomes a `*/naga.rs` that constructs the module programmatically. The
cluster targets:
- workgroup primitives (queue_fifo, queue_priority, stack, visitor,
  union_find, hashmap, typed_arena, string_interner, state_machine)
- security_detection (~30 files)
- stats/sliding_entropy
- string_matching (aho_corasick, dfa, nfa)
- decode family (the big ones)

8.4  Each rewrite includes a **parity test**: the previously-generated
WGSL is compared byte-for-byte against `naga::back::wgsl::write_string`
output from the new builder. Drift means a subtle behavior change.

8.5  The `vyre-wgpu/src/shaders/` directory (moved from core in Phase 0)
contains `.wgsl` assets for kernels that naga can't yet express
structurally. Each such asset must have a `// TODO(structural-emit):
...` comment naming the missing naga capability. When naga ships it,
the asset dies.

8.6  Once the tracker hits zero, delete
`naga::front::wgsl::parse_str` from vyre-wgpu's allowed-imports list
(scripts/check_dialect_coverage.sh gains a grep gate).

---

## §9 — REFERENCE INTERPRETER

**Per thesis axiom 4, reference owns execution. Today core still carries
hash/compress/decode references. And the interpreter is recursive with
Box-per-Expr. Both wrong.**

9.1  Move `vyre-core/src/ops/*/reference/*.rs` into `vyre-reference/src/`.
Current offenders:
- `vyre-core/src/ops/hash/reference/` (2,040 LOC)
- `vyre-core/src/ops/compression/*/cpu_ref.rs`
- `vyre-core/src/ops/crypto/*/reference.rs`
- `vyre-core/src/ops/string_matching/*/reference.rs`

9.2  After the move: `vyre-core` has zero `*/reference/` directories.
`vyre-reference` depends on `vyre` for IR types only. Nothing in vyre
depends on `vyre-reference` except conform and tests.

9.3  `vyre-reference/src/eval_expr.rs` is recursive with `Box<Expr>`. A
cold-recursive tree walker is fine for tests but makes property-based
conform runs 10-100× slower than necessary. Rewrite as an iterative
stack machine with a value stack and an op stack. Matches the GPU
model anyway.

9.4  `vyre-reference/src/workgroup.rs` simulates workgroups with a
complex scheduler + per-invocation state. `vyre-reference/src/sequential.rs`
(landed) gives the right model. Delete the old scheduler. Every conform
path uses the sequential driver.

9.5  Add `vyre-reference::evaluate_program(program, inputs) -> Outputs`
as the **only** public entry. No workgroup internals leaked.

9.6  The reference becomes an `impl VyreBackend for Reference` so
`registered_backends()` sees it alongside wgpu/spirv/photonic. Its
`dispatch` just runs the interpreter. Mock-backend tests in `vyre-core`
depend on this backend registration, not on `vyre-reference` internals.

---

## §10 — CONFORM: REAL, NOT THEATRE

**Conform crates are scaffolded compile-green but the prover runs on
witnesses the caller supplies — it doesn't walk DialectRegistry, doesn't
dispatch to backends, doesn't emit signed certs. Fix every piece.**

10.1  `vyre-conform-runner` gains the core loop: for each op in
`DialectRegistry::global().iter()` × each backend in
`registered_backends()`, instantiate `LawProver`, run every declared
AlgebraicLaw against the op's `WitnessSet::enumerate`, emit a
`Certificate` to `.internals/certs/<backend>/<op_id>.json`.

10.2  `LawProver::verify_*` needs backend dispatch: today it takes a
raw `Fn(u32, u32) -> u32`. Add `verify_commutative_via_backend(op: &OpDef,
backend: &dyn VyreBackend, witnesses: &[u32]) -> LawVerdict` that
packages the program, dispatches, and compares.

10.3  **Composition prover** — the novel contribution. Given two ops
with declared laws, compute the intersection (`CompositionLaw`), build
the composed program, verify on composed witness pairs. Today
`CompositionLaw` in conform-spec is a stub. Implement the real law
algebra:
- Commutative ∩ Commutative = Commutative iff composition is
  binary-symmetric.
- Associative + Associative requires bracketing-independence test.
- Identity composition requires element-transport proof.
- Distributive holds under specific composition patterns.
Each rule is documented in conform-spec source with a reference.

10.4  Signed certificates: `vyre-conform-runner` ships with a fresh
ed25519 keypair per run (for local gen) or reads `VYRE_CONFORM_SIGNING_KEY`
from env (for release gen). Certificate JSON has `signature` computed
over canonical bytes (sorted keys, no whitespace). `--verify` subcommand
checks a cert against a pubkey and rebuilds the witness set to confirm.

10.5  `Certificate.program_blake3` and `Certificate.witness_set_blake3`
become real blake3 digests of `Program::to_wire()` and
`WitnessSet::fingerprint_canonical()`. Delete every `"TBD"` string.

10.6  `Certificate.timestamp` — ISO 8601 UTC via `chrono`. Deterministic
when passed through `--freeze-time` env var (for cert-diff CI gates).

10.7  CI: `.github/workflows/conform.yml` runs `vyre-conform run
--backend wgpu` on every PR. Cert diff vs `main`-baseline rejects any
cert-surface change without an accompanying CHANGELOG entry.

10.8  `vyre-conform-generate` ships real proptest strategies for each
DataType. Shrinking finds minimal witnesses. The counterexample minimizer
integrates with LawProver: if `verify_commutative` returns
`CommutativeFails { a, b, .. }`, the shrinker reduces both `a` and `b`
to the smallest pair that still fails.

10.9  Determinism enforcer uses `seeded_nonzero_bytes` already. Grow
witness coverage: not just `all-zero`, not just `seeded`, but the full
`U32Witness` set. "Zero triggers no races" was the core audit bug. Fix
it by never using zero as the sole witness.

10.10  Combinatorial explosion in conform runs is a real risk (320k ops
per determinism check per op per backend). Bound: witness count × op
count × backend count ≤ 10M per CI run; shard across CI matrix when
above.

---

## §11 — CRATE ORGANIZATION

**1240 files in vyre-core. Ops scattered. Façades exist but the physical
split is planned for 0.6 "eventually." Do it.**

11.1  `vyre-core` keeps: `ir/`, `dialect/{registry,op_def,enforce,mutation,
interner,lowering,dialect,migration}.rs`, `optimizer/` (the pass scheduler,
not the passes themselves), `backend/{trait,error,config,registration}.rs`,
`validate/`, `serial/wire/`, `lower/` (trait definitions only), and
crate-level docs.

11.2  Ops split per the façade crates already present:
- `ops/primitive/` → `vyre-ops-primitive/src/`
- `ops/hash/` → `vyre-ops-hash/src/`
- `ops/string/`, `ops/string_matching/`, `ops/string_similarity/` →
  `vyre-ops-string/src/`
- `ops/security_detection/` → `vyre-ops-security/src/`
- `ops/compression/` + `ops/decode/` + `ops/encode/` →
  `vyre-ops-compression/src/`
- `ops/graph/` → `vyre-ops-graph/src/`
- `ops/workgroup/` → `vyre-ops-workgroup/src/`
- `ops/data_movement/`, `ops/reductions/`, `ops/sort/`, `ops/scan/`,
  `ops/stats/`, `ops/match_ops/` → decide per domain

11.3  The 0.6 split is `git mv` preserving history. Update every
`use vyre::ops::foo::...` call site. The façade crate `src/lib.rs` that
was `pub use vyre::ops::foo::*;` becomes the owner of the module.

11.4  Passes split out too: `vyre-core::optimizer::passes::fusion/cse/dce`
become standalone ops that register via PassRegistration from their own
crate files. The optimizer crate carries the scheduler only.

11.5  `vyre-reference` stops depending on `vyre` for anything except IR
types. Core does not depend on reference (currently it doesn't, confirm).

11.6  `vyre-wgpu` moves to `backends/wgpu/` — the thesis layout. Every
downstream `path = "../vyre-wgpu"` updates. Consumers of the published
crate are unaffected because the crate name doesn't change.

11.7  Workspace members list gets a fixed ordering: specs + macros +
core + refs + ops + backends + conform + demos + examples + xtask.
Refuse to add members in the middle of the list without following this
order.

---

## §12 — WIRE FORMAT (VIR0)

**`vir0-spec.md` declares stability. `docs/wire-format.md` gives the
table. But encode/decode don't round-trip `Expr::Opaque` through
extension-id payloads, and the `bytes_extraction` flag still isn't
wire-encoded.**

12.1  Wire encoder (`vyre-core/src/ir/serial/wire/encode/put_expr.rs`)
grows an `Expr::Opaque` branch: emits tag `0x80`, followed by
`extension_id: u32`, followed by `payload_len: u32`, followed by bytes
from `ExprNode::encode()`. Same for Node::Opaque.

12.2  Wire decoder (`vyre-core/src/ir/serial/wire/decode/impl_reader.rs`)
tag `0x80` dispatches through
`inventory::iter::<ExtensionRegistration>`. On miss:
`DecodeError::UnknownExtension { extension_id, kind, payload_bytes }`.
The payload bytes must be preserved so the caller can install the
extension and re-decode.

12.3  `BufferDecl.bytes_extraction` wire-encodes as a single flag bit in
the memory_hints u8. Bump wire version to 2 when landing.

12.4  Migration from wire v1 to v2 lives in `dialect::migration::v1_to_v2`.
Fall through: a v1 blob sets `bytes_extraction: false` on every buffer.

12.5  Deterministic encoding contract in VIR0: sorted metadata map keys
(lexicographic), canonical f32 encoding (no NaN payload bits), canonical
integer encoding (fixed-width big-endian for IDs, LEB128 for lengths).
Every backend reimplementing the wire reads the same sequence.

12.6  `docs/wire-format.md` gains a round-trip contract: an encoded
program decodes into a structurally-equal Program that re-encodes to
byte-identical bytes. CI test asserts this across the entire KAT corpus.

12.7  Separate the wire spec into `docs/wire-format-v1.md` (archived,
frozen) and `docs/wire-format-v2.md` (current). `vir0-spec.md` at root
points to the current.

---

## §13 — OPTIMIZER

13.1  `CSE` uses a FxHashMap + undo_log per the audit improvements.
Verify the scope stack doesn't clone `Expr` on every branch — it should
clone `ExprKey` only (the content-addressed key).

13.2  `ExprKey` (`vyre-core/src/ir/transform/optimize/cse/impl_exprkey.rs`)
currently recursive-Box. Rewrite as flat atom vec + `u32` child-id
indices. Dramatic improvement on deep IR.

13.3  `DCE` + `dead_buffer_elim`: both must route through visitors (see
§1.7) so extension Exprs don't get dropped as "unknown = dead."

13.4  **Fusion certificates** — `FusionCertificate` landed. Wire it into
`optimizer::passes::fusion`: every `FusionDecision` builds a cert comparing
the unfused program against the fused program on the U32Witness set. The
cert is attached to the transformed Program's metadata. A compile step
that rejects a cert with `parity_holds = false` refuses to emit the
fused kernel.

13.5  `fingerprint_program(program)` — verify this is blake3 of
`Program::to_wire()`. If it's anything else, fix.

13.6  Pass scheduler (`scheduler.rs`) has DAG-of-passes ordering via
`requires/invalidates`. Verify: every registered pass has an explicit
`invalidates` list and the scheduler topologically sorts. Missing
invalidates = stale cache = silently wrong output.

13.7  `PassAnalysis::RUN / SKIP` — verify the skip path is honored. A
pass that unconditionally returns RUN never gets cached.

13.8  Add `--dump-passes` CLI to xtask that prints the pass order for a
given program. Helps diagnose why a pass isn't running.

---

## §14 — DIAGNOSTICS

14.1  `Diagnostic` struct exists with `E-*` / `W-*` codes. Grow the
catalog to cover every error path in the workspace. Current gaps:
- Wire decode errors (`UnknownExtension` etc.)
- Backend dispatch errors (per-variant BackendError)
- Conform verdict errors
- Validation V### errors (today they're strings)

14.2  LSP JSON output: every Diagnostic serializes to LSP's
`PublishDiagnosticsParams` shape so an editor can render vyre errors
natively.

14.3  rustc-style render: `error[E-IR-003]: primary message\n  --> file:line:col\n  |\n  | ...` matches the rustc vocabulary for zero-learning-curve ergonomics.

14.4  `Fix:` prose is normative. Every Diagnostic carries one. CI lint
that rejects new Diagnostic variants without `Fix:`.

14.5  `Diagnostic::source_span` is optional. When present, the renderer
highlights the span. When absent, the renderer names the op_id.

---

## §15 — EXPECT / UNWRAP / MISSING_DOCS

15.1  `scripts/check_expect_has_fix.sh` baseline currently 111. Ratchet
to zero. Every landing commit that removes a site bumps the baseline
downward by the count removed.

15.2  Similar ratchet for `unwrap()` — 287 sites today in production
paths. Add `scripts/check_no_raw_unwrap.sh` with a baseline.

15.3  `#![deny(missing_docs)]` is on core. Confirm every pub item has
rustdoc. A brief `///` is not enough — must explain the invariant, the
example, and the why. Absent those, `#[allow(missing_docs)]` with a
visible TODO is better than a one-line lie.

15.4  Clippy ratchet: `cargo clippy --workspace --all-targets -- -D
warnings` must be green. Every `#[allow(clippy::...)]` must carry a
comment naming why the lint is wrong here.

15.5  `cargo doc --workspace --no-deps --all-features -D broken_intra_doc_links`
in CI.

---

## §16 — BENCHMARKS

16.1  `vs_cpu_baseline.rs` was benchmark fraud (compared the same string
to itself). Verify current state: diff the WGSL against a real
hand-tuned shader (ship the hand-tuned as a string constant labeled
`HAND_TUNED_REFERENCE`). If no hand-tuned exists, the bench is labeled
"single-backend measurement" and doesn't claim a ratio.

16.2  `primitives_showcase.rs` was a no-op (benchmarked `Vec::len()`).
Verify the criterion harness now runs the actual ops inside the timed
loop. The support already grew `run_full_upload_and_dispatch` —
confirm every bench in `benches/` uses a dispatch variant that
represents the workload honestly.

16.3  Every bench has a named comparator baseline file in
`benches/baselines/<bench>.json`. The `scripts/check_benchmarks.sh` gate
fails on >5% regression. Hand-tuned cuDF / hyperscan / ripgrep baselines
are real data files, not placeholders.

16.4  Cross-backend comparison table (`benches/RESULTS.md`) has wgpu +
spirv + reference columns. Each commit that touches a backend updates
the table or explicitly justifies the omission.

16.5  Upload-inclusive vs steady-state rows (both, per primitive).
BENCHMARKS.md §C8 specifies the methodology; numbers land.

16.6  `--compare-spirv-vs-wgpu` xtask subcommand emits a diff table in
ms + GB/s per op. CI gates on cross-backend parity (bit-identical
outputs, ±2% perf envelope).

16.7  Memory amplification bench: stats_alloc over a full dispatch to
report `(heap_bytes + gpu_buffer_bytes) / (theoretical_minimum)`. Target
≤1.5× per BENCHMARKS.md §9.

---

## §17 — BUILD SYSTEM

17.1  `vyre-core/build.rs` runs `vyre_build_scan::scan_core()` via the
`vyre-build-scan` crate. That crate parses the source tree with `syn` on
every `cargo build`. Delete.

17.2  Replace with a minimal `walkdir`-based discovery that emits
`cargo:rerun-if-changed=src/` and nothing else. Every op-registration
that needed static_generated goes through inventory at link time
(§3 delivers this).

17.3  `vyre-build-scan` crate dies entirely. Any remaining consumer in
xtask is rewritten to walk the filesystem directly.

17.4  `conform/*/build.rs` (if any) same treatment: no syn parsing at
build time.

17.5  `rust-toolchain.toml` pinned at 1.85 today. Move to 1.87 (or
whatever is current stable) when all dependents support it. Pinning
stabilizes reproducible builds but drifts further from the ecosystem
each month.

17.6  `.cargo/config.toml` grows `[target.'cfg(all())']` sections for
link args (mold for Linux, lld for Windows). Builds 2-5× faster in CI
with no correctness impact.

17.7  `xtask` grows subcommands: `xtask check-all` (every CI gate in
sequence), `xtask bench-regen` (rebuild all baselines),
`xtask conform-run` (conform runner wrapper), `xtask publish-dry`
(calls scripts/publish-dryrun.sh).

---

## §18 — CLEANLINESS

18.1  `vyre-sigstore/` orphan crate. Delete (nothing in the workspace
depends on it) OR fold into conform-runner as the signing backend.
Decide. Current state is neither.

18.2  `vyre-build-scan/` follows §17.1 — delete.

18.3  `vyre-primitives/` — verify nothing else replaces it before
deletion. The name suggests it overlaps with `vyre-ops-primitive/`
(façade). If it's distinct (shared CPU primitives like xxhash), rename
to `vyre-cpu-primitives` to make the boundary obvious.

18.4  Dead features: `wgpu_subgroups = []`, `test-helpers = []` in
`vyre-core/Cargo.toml` (if still present). Either wire a real `#[cfg]`
gate to them or delete.

18.5  `vyre-core/src/ops.rs` coexists with `vyre-core/src/ops/`. Merge
to `vyre-core/src/ops/mod.rs` — no 2KB file living next to a directory
of the same name.

18.6  Documentation consolidation:
- One `README.md` at the workspace root.
- One `CHANGELOG.md` at the workspace root.
- Crate-level rustdoc only; per-crate `README.md` is just a pointer
  back to the workspace README.
- Delete `vyre-conform/docs/` subdirectories if/when conform crates
  move to `conform/vyre-conform-*/`.

18.7  `.internals/` gets a fixed structure:
- `audits/` — one file per audit run, append-only, dated.
- `planning/` — this file lives here.
- `release/` — per-release checklists.
- `catalogs/` — regenerated from code; never hand-edited.
- `archive/` — anything older than 60 days that isn't pinned.

18.8  `scripts/` gets a naming convention: every check script starts
with `check_`, every run script starts with `run_`, every generator
starts with `gen_`. Delete any script whose name doesn't match.

18.9  `target/` hygiene: `.gitignore` covers every `target/` at any
depth. Ratchet: `git status --porcelain` after `cargo build` shows no
target-related files.

18.10  `Cargo.lock` is committed. `Cargo.lock.old` in `.gitignore`.
Periodic `cargo update -w` to pull in patch-level fixes; minor/major
bumps are explicit PRs.

---

## §19 — CI GATES

The CI must fail loudly on every regression of every invariant.

19.1  `.github/workflows/architectural-invariants.yml` — every scripts/
check that validates structure. Current set:
- `check_architectural_invariants.sh` (Law H: vocabulary)
- `check_no_closed_ir_enums.sh` (Law A: IR openness)
- `check_no_shader_assets.sh` (Law B: no .wgsl assets in core)
- `check_no_string_wgsl.sh` (Law B: no string concat shaders)
- `check_capability_negotiation.sh` (Law C)
- `check_unsafe_justifications.sh` (Law D)
- `check_dialect_coverage.sh` (Cat A/B/C classification)
- `check_trait_freeze.sh` (7 frozen traits)
- `check_registry_consistency.sh` (single registry)
- `check_no_parse_str.sh` (structural emission)
- `check_expect_has_fix.sh` (expect ratchet)
- `check_no_raw_unwrap.sh` (unwrap ratchet, new)

19.2  `.github/workflows/ci.yml`: `cargo test --workspace --no-fail-fast`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo doc
--workspace --no-deps --all-features -D broken_intra_doc_links`,
`cargo fmt --check`.

19.3  `.github/workflows/semver-checks.yml`: `cargo semver-checks` over
every publishable crate. Any breaking change surfaces in CI, not on
publish.

19.4  `.github/workflows/public-api.yml`: `cargo public-api` diffed
against `docs/public-api/<crate>.txt`. API changes require updating the
baseline AND the CHANGELOG.

19.5  `.github/workflows/fuzz.yml`: nightly fuzz targets on wire
encode/decode round-trip, optimizer passes, validator.

19.6  `.github/workflows/loom.yml`: concurrency tests on
pipeline_cache, bind_group_cache, streaming pool.

19.7  `.github/workflows/miri.yml`: pointer-chasing unsafe blocks
(BufferPool, intrusive LRU) run under miri.

19.8  `.github/workflows/conform.yml`: `vyre-conform run --backend
wgpu --ops all` + cert diff against baseline.

19.9  `.github/workflows/bench-regression.yml`: criterion --quick
across the reduced bench suite; 5% regression = CI fail; 2% for
hand-tuned paths.

19.10  `.github/workflows/deny.yml`: `cargo-deny` per `deny.toml`.

19.11  `.github/workflows/udeps.yml`: `cargo-udeps` nightly; unused
deps surface as CI warnings.

19.12  `.github/workflows/dependency-audit.yml`: `cargo-audit` against
RustSec DB. Any advisory fails CI.

---

## §20 — PUBLISH

20.1  `scripts/publish-dryrun.sh` order is fixed (§Phase 30). Verify
every listed crate has README + LICENSE-MIT + LICENSE-APACHE +
description + keywords + categories + repository + homepage.

20.2  Crate name collisions on crates.io: verify vyre-ops-* and
vyre-conform-* and vyre-spirv / vyre-photonic are unowned. Squat-defense
by publishing v0.0.1 placeholders with the committed name before
legendary ships.

20.3  Publish order under §Phase 30 list.

20.4  First publish ships under v0.5.0 (core) + v0.1.0 (new crates).
Semver policy documented in `docs/semver-policy.md`: every
API-visible Opaque variant is additive-only; adding a new inventory
collection is a minor bump; changing an existing collection's struct
shape is a major bump.

20.5  Each crate ships with a `CHANGELOG.md` that delegates to the
workspace CHANGELOG by link. No per-crate changelog text.

20.6  `docs.rs` config: `[package.metadata.docs.rs]` sets
`all-features = true`, `rustdoc-args = ["--cfg", "docsrs"]`. `#[cfg(docsrs)]`
feature-gates the `all-features`-only pieces.

---

## §21 — EXTENSION DEMO

Without a working demonstration of the extension story, the thesis is
rhetoric.

21.1  `examples/external_ir_extension/` — new crate, not in the
workspace, depends on vyre from crates.io (via path= for local dev).
Registers:
- A custom `ExprNode` implementing a hypothetical `tensor.gather` op
- A custom `ExtensionDataType` (`Tensor{rank=3}`)
- A custom `RuleConditionExt` (`FileSizeGt`)
- A custom `Backend` (a CPU-only mock that runs the extension op)

21.2  The example crate's integration test:
- Builds a Program using the extension Expr
- Round-trips it through VIR0 wire
- Passes through CSE + DCE (proves visitor-based passes ride)
- Validates cleanly
- Dispatches on the mock backend
- Produces correct output

21.3  This test runs in CI as `cargo test -p external_ir_extension`.
Zero edits to `vyre-core`, `vyre-wgpu`, `vyre-reference` required.

21.4  Example fits under 200 LOC per §10 of BENCHMARKS.md. The cap is
the contract.

---

## §22 — THREE-SUBSTRATE PARITY

22.1  `examples/three_substrate_parity/` (landed scaffold) produces
byte-identical outputs across wgpu + spirv + reference backends on the
xor-1M corpus.

22.2  Grow to the full primitive showcase: one program per primitive,
dispatched on every non-stub backend, asserted byte-identical.

22.3  The parity demo runs in CI nightly and publishes the table to
`docs/parity/<commit>.md`.

22.4  Any byte-difference between substrates produces a failure whose
message names the specific bytes that differ.

---

## §23 — DOCUMENTATION

23.1  README.md (root) gets a strict 5-section shape:
- One-paragraph claim
- Three-example quickstart (program build, dispatch, parity)
- Crate map (one line per published crate)
- Link to THESIS / VISION / ARCHITECTURE
- License

23.2  `docs/` stays canonical (ARCHITECTURE.md, THESIS.md, VISION.md
at root, memory-model.md, targets.md, wire-format.md, semver-policy.md,
inventory-contract.md).

23.3  No `CHANGELOG.md` inside sub-crates. No duplicate schema docs. No
README.md that is longer than 30 lines.

23.4  `docs/catalogs/` is generated from code: op catalog, coverage
matrix, public-api snapshots. Each has a generator script in
`scripts/gen_*.sh`. CI re-runs the generators and fails if the output
drifts.

23.5  Rustdoc cross-links: every op page links to its KAT vectors
(`rules/kat/<path>.toml`), its cert file
(`rules/op/<id>.toml`), and its declaring dialect module.

---

## §24 — HONEST FAST-MATH

24.1  `vyre-core/src/lower/wgsl/emit_wgsl.rs` `_vyre_fast_sin_ulp` etc.
were identity wrappers. The audit noted one was replaced with a real
Taylor series. Verify all four (sin, cos, exp, log) are real polynomial
approximations with declared max-ULP error in the op's AlgebraicLaw
set.

24.2  Max-ULP bounds live in `rules/numerical_stability/primitive.float.toml`.
Conform enforces them per backend. Any wgpu path that does not achieve
the declared bound fails conform.

24.3  No fast-math approximation without a declared bound. Identity
functions disguised as approximations are banned.

---

## §25 — ADVERSARIAL TESTS

25.1  Fuzz targets (cargo-fuzz):
- `wire_round_trip` — fuzz bytes → Program → bytes; assert identity or
  typed error.
- `validate_no_panic` — fuzz Program → validate_program; assert result
  or typed error; never panic.
- `optimizer_fixpoint` — fuzz Program → optimize; assert fixpoint
  reaches a fixed state within the cap.
- `parser_no_panic` — fuzz arbitrary bytes through every public
  `from_*` entry.

25.2  Property tests for every AlgebraicLaw: 1000 witnesses per run,
shrinking on failure. Output captured to `.internals/audits/proptest-log-<date>.md`.

25.3  Adversarial tests designed to FAIL:
- Nested IR hitting the depth limit (`V018` triggers)
- Cyclic buffer refs
- Size-class overflow in BufferPool
- Race between two dispatchers on the same pipeline
- Corrupted wire bytes (every byte of a valid program flipped)

25.4  Each adversarial test lives next to the module it probes, named
`adversarial_*` to signal its intent.

---

## §26 — PHOTONIC STUB INTEGRITY

The photonic stub is the forcing function. Keep it strict.

26.1  `backends/photonic/src/lib.rs` registers successfully with the
runtime. `supports_dispatch` returns false. `dispatch` returns
`Err(BackendError::UnsupportedFeature { feature: "dispatch", backend:
"photonic" })`.

26.2  The photonic backend participates in the conform run — it
passes the "registration + capability query" subset of the suite. Every
other backend's cert has a `photonic: not_applicable` column so parity
pages show the stub's presence.

26.3  Any change to the core backend trait that the photonic stub can't
compile against signals that the trait leaked substrate. CI fails.

---

## §27 — DIALECT-COVERAGE MATRIX

27.1  `docs/catalogs/coverage-matrix.md` is generated by
`scripts/gen_coverage_matrix.sh` and shows for each op: category, wgpu
supported, spirv supported, reference supported, photonic supported,
laws verified, cert present, parity-bench run.

27.2  The matrix is load-bearing — missing columns for new backends
flag the backend as incomplete. Publishing with holes in the matrix is
blocked by `scripts/check_coverage_matrix_complete.sh`.

---

## §28 — INPUT VALIDATION

28.1  Every `pub fn` that accepts user bytes (`dispatch(inputs: &[Vec<u8>]
)`, `from_wire(bytes: &[u8])`, `Program::deserialize(...)`) validates
alignment + length + reasonable size before passing to bytemuck or
naga. `bytemuck::try_cast_slice` with structured error on failure.

28.2  `DispatchConfig::max_output_bytes` is honored — outputs above
the cap are truncated with a typed error, not returned silently oversized.

28.3  Input size limits: `MAX_INPUT_BYTES = 4 GiB` for safety. Any caller
needing more gates it via `DispatchConfig::unbounded = true` (opt in).

28.4  `catch_unwind` in conform (noted in audit) is removed — panics
are bugs that need fixing, not strings to swallow.

---

## §29 — ERROR CODES REGISTRY

29.1  `E-*` error codes (compile-time) are append-only. Renames are
migrations, not edits. `docs/error-codes.md` lists every code with its
meaning and `Fix:` template.

29.2  `V###` validation codes same discipline.

29.3  `BackendError` variants are named, not stringly-typed (current
state — verify no string-only variants remain).

29.4  Every Diagnostic carries structured fields — a CI tool can parse
`"E-VAL-013"` and look up the fix template without reading the rendered
message.

---

## §30 — FROZEN TRAITS

30.1  Seven frozen traits per ARCHITECTURE.md:
`VyreBackend`, `ExprVisitor`, `NodeVisitor`, `Lowerable`,
`AlgebraicLaw`, `EnforceGate`, `MutationClass`.

30.2  `scripts/check_trait_freeze.sh` asserts each trait's signature is
byte-for-byte stable against `docs/frozen-traits/<name>.txt` snapshot.
Any diff is a frozen-trait violation.

30.3  Extending a frozen trait = new trait + default impl delegating to
the old trait. Old trait never removed. The freeze is forever.

---

## §31 — OBSERVABILITY

31.1  `tracing` instrumentation on the dispatch hot path: one span per
`dispatch`, child spans per `compile`, `record`, `readback`. Target
`vyre::dispatch`. Zero overhead when disabled (the default).

31.2  Metrics exported as `tracing` fields: `dispatch_ns`, `compile_ns`,
`readback_ns`, `buffer_pool_hit_rate`, `bind_group_cache_hit_rate`,
`disk_cache_hit_rate`. Users aggregate via `tracing-subscriber`.

31.3  Never `tracing::error!()` with format args in the hot path — use
field-only events so the instrumentation stays zero-alloc.

31.4  `BackendError` variants hook into `tracing::error!` with the
variant name as the event message and fields as structured data.

---

## §32 — SECURITY

32.1  `#![forbid(unsafe_code)]` on every published crate except vyre-wgpu
(needs unsafe for bytemuck casts) and vyre-core (needs unsafe for
inventory if any). Every allowed crate has a `// SAFETY:` comment per
unsafe block.

32.2  No process-wide panic hooks. Panics propagate.

32.3  No `unwrap` / `expect` in the wire decoder. Any malformed byte
sequence returns `DecodeError`, not a panic.

32.4  `cargo-deny`: banned crates, banned licenses, banned git URLs.

32.5  `cargo-audit` nightly.

---

## §33 — MEMORY MODEL

33.1  `docs/memory-model.md` gives the three-tier model. Verify every
op declaration's `BufferDecl::kind` (Global / Shared / Uniform / Readonly)
is correct. Linear scan of the dialect for mis-declared tiers.

33.2  `MemoryOrdering` on atomics: `Relaxed`, `Acquire`, `Release`,
`AcqRel`, `SeqCst`. Core enforces that every `Expr::Atomic` carries one.
Default when unset is `SeqCst` — the safe default.

33.3  Extension `DataType::Opaque` declares its own memory model via the
trait — `fn memory_model(&self) -> MemoryModel`. Core doesn't try to
reason about extension memory.

---

## §34 — PATTERN ENGINES

34.1  `df_assemble` concatenates all patterns with `|` alternation.
Replace with `regex-automata::meta::Regex` multi-pattern API. NFA→DFA
subset construction over a proper multi-pattern NFA avoids exponential
blowup.

34.2  `aho_corasick_scan` uses the `aho-corasick` crate's internals. Do
not reimplement. The wgpu backend compiles the AC DFA into a GPU
transition table.

34.3  `nfa_scan` is retired (Phase 7). Pattern ops compose in vyre IR
directly — no micro-interpreter.

---

## §35 — CONFORM COMPOSITION ALGEBRA

**This is vyre's novel contribution. It must be real.**

35.1  Define `CompositionLaw::intersect(a_laws: &[AlgebraicLaw], b_laws:
&[AlgebraicLaw]) -> Vec<AlgebraicLaw>` with the full algebra:
- `Commutative ⊗ Commutative = Commutative` iff compose is symmetric
- `Associative ⊗ Associative = Associative` for linear composition
- `Identity(e_a) ⊗ Identity(e_b) = Identity(composition_of_identity(e_a, e_b))`
- `Bounded{a,b} ⊗ Bounded{c,d} = Bounded{compose_bound(...)}`
- `Monotonic ⊗ Monotonic = Monotonic`
- `Involution ⊗ Involution = Identity`
- `Distributive` interacts with itself via the specific operator algebra

35.2  Each rule is tested: construct two ops with declared laws,
compose them, verify on witnesses that the resulting program satisfies
the intersected laws.

35.3  The algebra is documented in `docs/composition-algebra.md` with
proof sketches citing standard algebra texts (Mac Lane, Baez).

35.4  Negative tests: `Commutative ⊗ NonCommutative = {}` (empty set).
Composition of two ops where at least one lacks a given law yields a
program that does not claim the law.

---

## §36 — PERFORMANCE BUDGET ENFORCEMENT

36.1  Every bench has a named target in `benches/budgets.toml`:
`<bench>.max_ns_per_element = N`. The bench harness fails if measured
ns/element exceeds the target.

36.2  CI publishes budget overrun as a hard error, not a warning. If a
regression is justified, the commit carries
`allow-perf-regression: <reason>` and bumps the budget explicitly in the
same diff.

36.3  `scripts/check_benchmarks.sh` runs the gate; `scripts/gen_budgets.sh`
regenerates from the current baselines.

---

## §37 — SECURITY OF THE WIRE

37.1  Wire format reader has a `MAX_NESTING_DEPTH` cap (existing) and a
`MAX_PROGRAM_BYTES` cap (e.g. 64 MiB). Attacker-controlled wire bytes
cannot force unbounded recursion or unbounded allocation.

37.2  Wire decoder uses `Reader::leb_len` with a typed max. Never
`as usize` without a prior bound check.

37.3  `Expr::Opaque` extension payloads carry their own size limit via
the registered trait: `ExprNode::max_encoded_bytes() -> usize`. Decoder
rejects blobs exceeding the declared max.

---

## §38 — CONSISTENCY CONTRACTS

38.1  Every pair (op_id, category) in the registry is unique. CI
enforces via `scripts/check_registry_consistency.sh`.

38.2  Every op's KAT file path follows `rules/kat/<dialect_path>/<op_name>.toml`.
Naming drift = CI fail.

38.3  Every op's cert file path follows `rules/op/<op_id>.toml`.

38.4  Every dialect registered in `DialectRegistry` has at least one
op. Empty dialects = fail.

38.5  Op ids are stable strings. The catalog in
`docs/catalogs/op-id-catalog.md` is append-only; renames ship as
migrations.

---

## §39 — WHAT "LEGENDARY" LOOKS LIKE

Every item in §1-§38 landed. Then:

- A downstream crate adds a `tensor.gather` op with a custom DataType
  and a custom backend in <200 LOC of Rust. CI passes. No vyre-core
  edit. (§21)
- Two real compute backends (wgpu + spirv) produce byte-identical
  outputs across the full primitive corpus. (§22)
- The reference interpreter is the CPU source of truth; zero reference
  code lives in vyre-core. (§9)
- Every op in the registry ships a signed conformance certificate; the
  cert's contents are byte-identical across machines. (§10)
- The benchmark numbers in `benches/RESULTS.md` are real, reproducible,
  and defended by CI. No self-comparison, no `black_box(len())`. (§16)
- The workspace is physically split — core is under 400 files, each
  domain lives in its own crate with its own CHANGELOG. (§11)
- Every `expect` starts with `Fix:` and every `pub` item has real
  rustdoc. (§15)
- The 7 frozen traits have byte-for-byte stable signatures. (§30)
- Adding a backend is one crate and an `inventory::submit!`. Period. (§26)

When every §-item is green, `v1.0.0` is publishable. Until then, we are
making progress toward legendary, not declaring it.

---

## ORDERING

Do in this order. Each block unblocks the next. No skipping.

**Block A — foundation:**
§4 inventory hypocrisy (delete the ban), §3 single registry (delete
OpSpec), §1 IR openness (DataType Opaque, BinOp Opaque, RuleCondition
Opaque, Backend string-id, visitor migration).

**Block B — substrate:**
§2 vocabulary purge, §12 wire format v2, §30 frozen traits snapshot.

**Block C — backends + conform:**
§9 reference interpreter inversion, §10 conform real prover, §26
photonic integrity, §22 three-substrate parity.

**Block D — hot path:**
§5 dispatch path, §6 disk cache wiring, §7 validation cache, §13
optimizer, §8 structured emission.

**Block E — polish:**
§14 diagnostics, §15 expect/unwrap/docs, §31 observability, §25
adversarial tests.

**Block F — release:**
§11 physical split, §19 CI gates, §20 publish, §17 build system,
§18 cleanliness, §23 documentation, §27 coverage matrix, §36 perf
budgets, §37 wire security, §38 consistency contracts, §39 legendary
sign-off.

---

## NON-NEGOTIABLES

- No timeline. Timelines lie. Timelines justify shortcuts. The only
  pace is: next item complete, commit, next item.
- No "deferred to 0.6". Every item in this plan ships in the 0.5.x
  series. 0.6 is the next vision, not a junk drawer.
- No scaffolds. No "compile-green façade with a TODO." Either the item
  is real or the item is not landed.
- No "we'll see how it goes." Every item has a specific file and a
  specific diff shape. Ambiguity is the enemy.
- No apologies for the size of a PR that lands a full item. One item,
  one PR, one real change.

This is the plan. Execute.
