# Solo execution plan — every item, ordered, no postponement

Goal: pristine organization, full extensibility, publish-ready 0.5.0 on crates.io. One Claude, 5090 available. No deferrals.

## Phase 0: Commit current session delta (20 min)

Single cohesive commit. Recovery baseline.

- docs: THESIS.md, ARCHITECTURE.md, memory-model.md, targets.md, wire-format.md
- photonic stub crate (backends/photonic/)
- naga_emit 804-line structural restore + new UnOp variants (Cos/Sin/Popcount/Clz/Ctz/ReverseBits/IsNan/IsInf/IsFinite) + new BinOp variants (Min/Max/AbsDiff) + Bool-storage HOST_SHAREABLE fix + Negate/LogicalNot type repairs + builtin-axis InvalidPointer fix
- OpSpecEntry inventory bridge + register_op_spec! macro + 129 auto-register submissions
- OpDef.compose field + Default impl
- EnforceGate trait + MutationClass enum (frozen contracts)
- dialect::dialect::BackendRegistration → OpBackendTarget rename (disambiguate from backend::registry::BackendRegistration)
- CI-law updates: Law A allowlist extended (7 value-lattice enums), dialect-coverage rewrites to Category::Intrinsic-only, shader assets relocated out of core/ops into vyre-wgpu/src/shaders/, .github/workflows/architectural-invariants.yml expanded to 9 jobs
- 8 duplicate LICENSE files deleted from sub-crates
- Root trash: 16 py scripts + 6 rlibs + scratch/test_*/check*/test_metadata.patch deleted
- target/ scrubbed (27.9 GB)
- Orphan `core/` dir + empty `coordination/` dir + empty `vyre-core/src/lower/` dir deleted
- Damerau-Levenshtein rewrite to true Lowrance-Wagner (fixes "ca"→"abc"=2)
- glob_match / wildcard_match signature swap to (input, pattern)
- wildcard_match rewritten to substring-scan (Sigma convention)
- detect_command_injection: added rm/ls/mv/cp/chmod/chown/sh/bash/cmd.exe/bin/bash to command list
- xtask clippy green: deleted dead cargo-helper module, cfg(test) hash::tests, vec!→array, removed exit_with
- launch_smoke_test rewritten: replaced dead vyre-build-scan/vyre-selftest refs with photonic + publishable-crate check
- coverage_matrix regenerated
- Stale vyre-std/sigstore/crypto comment scrubs in 4 files
- README stale crate table updates (removed vyre-std/vyre-sigstore/rulefire rows)

## Phase 1: GPU test baseline (30–40 min)

Run `cargo test --workspace --no-fail-fast` on the 5090 for real. Capture output. Produce triage doc at `.internals/audits/gpu-failures-2026-04-19.md` with every failure, every hang, every binary timing.

Investigate `prerecorded_dispatch_replays_without_encoder_on_submit_path` hang — previous session timed out at 60s+.

## Phase 2: 7 primitive canonicalization fixes (2–3 hrs)

Each IR program authored to emit the assertion-expected canonical WGSL.

- **abs_diff** — author IR as `max(a,b) - min(a,b)` so emit maps through Min/Max→naga::Math path and the test finds the shape
- **div** — wrap in `select(b == 0, 0_u32, a / b)` in `Div::program()`
- **mod_op** — wrap in `select(b == 0, 0_u32, a mod b)` in `Mod::program()`
- **logical_not** — author as `select(x == 0, 1_u32, 0_u32)` matching "WGSL must check == 0"
- **negate** — author as `~a + 1` two's-complement form matching "WGSL must use twos complement"
- **shl** — author as `select(shift >= 32, 0_u32, a << shift)` zero-guard
- **shr** — author as `select(shift >= 32, 0_u32, a >> shift)` zero-guard

Re-run all_primitives tests after each change.

## Phase 3: Bytes V013 decode.base64 redesign (3–4 hrs)

- Locate V013 failures in `vyre-core/src/ir/validate/load_store.rs`
- Extend `DataType::Bytes` validation to allow load when the op declares `bytes_extraction: true` in its signature
- Add `#[non_exhaustive]` attr to `Signature` for extension
- Update validator + wire format
- Re-run: `decode_base64_coverage`, `decode_base64_program_constructs_without_error`, `decode immediate`, `record_batches_multiple_decodes_into_one_submission`, `compression.lz4_decompress program must validate cleanly`

## Phase 4: rules/op/ cert files (1 hr)

Author 5 TOML certs in `rules/op/`:
- `decode.base64.toml`
- `compression.lz4_decompress.toml`
- `match.dfa_scan.toml`
- `string_matching.aho_corasick_scan.toml`
- `graph.bfs.toml`

Each: op id, signature hash (blake3 of canonical wire form), allowed backends list, witness-set fingerprint. Re-run gated op tests.

## Phase 5: A-C11 phase 2 — single-registry migration (8–12 hrs)

Largest task. Delete OpSpec entirely; DialectRegistry becomes the sole contract.

1. Write `.internals/release/migrate_op_spec.py`:
   - Walk every `impl Type { pub const SPEC: OpSpec = OpSpec::composition_inlinable(id, ins, outs, laws, build); }`
   - Derive `dialect` from path (e.g. `vyre-core/src/ops/primitive/bitwise/xor.rs` → `primitive.bitwise`)
   - Emit: `inventory::submit! { OpDefRegistration::new(|| OpDef { id, dialect, category: Category::Intrinsic, signature: Signature::from_types(ins, outs), lowerings: LoweringTable { cpu_ref: <derived fn path>, naga_wgsl: <if registered>, naga_spv: None, ptx: None, metal: None, }, laws, compose: Some(Type::program) }) }`
   - Remove the `pub const SPEC` + `register_op_spec!` line + `use crate::ops::{IntrinsicDescriptor, OpSpec}` imports
2. Run across 113 composition_inlinable + 6 composition + Category::Intrinsic intrinsic sites
3. Rewrite `vyre-core/src/ir/transform/inline.rs` to resolve via `DialectRegistry::global().lookup(op_id).and_then(|d| d.compose)`
4. Delete:
   - `vyre-core/src/ops/spec.rs`
   - `vyre-core/src/ops/OpSpec` type export
   - `vyre-core/src/ops/OpSpecEntry` type + `register_op_spec!` macro
   - `vyre-core/src/ops/registry/lookup.rs` body (replace with DialectRegistry walker)
   - `vyre-core/src/ops/registry/lookup_program.rs` body (replace)
   - `vyre-core/src/ops/registry/registry.rs` (entire runtime register_op_spec compat)
   - `vyre-core/src/ops/registry/static_generated/` dir
5. Delete dead `Compose::Composition` / `Compose::Intrinsic` dichotomy from metadata.rs
6. Re-run full workspace tests; iterate on cascading breakages
7. Update docs/ARCHITECTURE.md to reflect single-registry post-migration

## Phase 6: Open-IR migration (12–16 hrs)

### 6a. Expr::Opaque + ExprVisitor (4 hrs)

- Define `pub trait ExprVisitor<'a> { type Out; fn visit_lit_u32(&mut self, v: u32) -> Self::Out; ... fn visit_opaque(&mut self, node: &'a dyn ExprNode) -> Self::Out; }`
- Default impl that walks structure via `walk_expr`
- Migrate every core match-on-Expr to `.visit()`:
  - `vyre-core/src/ir/transform/optimize/cse/impl_exprkey.rs`
  - `vyre-core/src/ir/transform/optimize/cse/impl_csectx.rs`
  - `vyre-core/src/ir/transform/dead_buffer_elim/*.rs`
  - `vyre-core/src/ir/validate/expr_type.rs` + `binop_rules.rs` + `comparison_rules.rs` + every load/store checker
  - `vyre-core/src/ir/transform/inline/expand.rs`
  - `vyre-core/src/ir/serial/wire/encode/put_expr.rs`
  - `vyre-core/src/ir/serial/wire/decode/*.rs`
  - `vyre-wgpu/src/lowering/naga_emit.rs` Expr match → visitor dispatch with per-variant methods
- Test: author `tests/extension_expr_round_trips_through_all_passes.rs` that registers a custom ExprNode, constructs a Program containing it, runs CSE + DCE + validate + wire round-trip, asserts identity

### 6b. Node::Opaque + NodeVisitor (3 hrs)

Same pattern. Every Node match migrates. Test `extension_node_round_trips.rs`.

### 6c. DataType::Opaque + wire extension registry (3 hrs)

- Add variant: `Opaque(ExtensionDataTypeId)` (just the id; payload lookup via inventory)
- `pub struct ExtensionDataTypeRegistration { pub id: ExtensionDataTypeId, pub vtable: &'static dyn ExtensionDataType }` + `inventory::collect!`
- Wire encoder: Opaque → `0x80 tag + u32 id + u32 len + bytes`
- Wire decoder: lookup extension id via inventory; `DecodeError::UnknownExtension { id }` on miss
- Extend `size_bytes`, `is_host_shareable`, scalar mapping through the ExtensionDataType trait
- Test: register test extension data type, round-trip Program, verify parity

### 6d. RuleCondition::Opaque + RuleConditionExt (2 hrs)

- Add `Opaque(Arc<dyn RuleConditionExt>)` to `vyre-core/src/ops/rule/ast.rs`
- Define `RuleConditionExt: Send + Sync + 'static { fn evaluate(&self, ctx: &RuleContext) -> bool; fn stable_fingerprint(&self) -> [u8; 32]; ... }`
- Update `vyre-core/src/ops/rule/builder.rs` exhaustive match to handle Opaque
- Update rule wire-format encoding

### 6e. Wire-format C2 Opaque cleanly + versioned (2 hrs)

- Implement full VIR0 header from `docs/wire-format.md`: magic `VIR0` + u8 version + u16 flags + u32 metadata_len + metadata + body
- Extension tag `0x80` dispatches through `inventory::iter::<ExtensionRegistration>`
- Decoder: `DecodeError::UnknownExtension { extension_id, kind }` with preserved payload bytes so consumers can install extension crate and re-decode
- Test: every KAT program round-trips byte-identical through `to_wire → from_wire → to_wire`

### 6f. Purge workgroup/subgroup/warp/WGSL from vyre-core (2 hrs)

- `grep -rn "workgroup\|subgroup\|warp\|wgsl\|WGSL" vyre-core/src/`
- Rename to substrate-neutral vocabulary: `parallel_region`, `invocation_group`, `sync_group`, `memory_barrier`
- Update docs/THESIS.md + docs/memory-model.md cross-references
- CI check_architectural_invariants extended to flag these tokens in vyre-core

## Phase 7: NFA bytecode VM nuke (6–8 hrs)

- Delete `vyre-core/src/ops/string_matching/nfa_scan/kernel/{opcodes.rs,parse_program.rs,match_from.rs,token.rs}`
- Rewrite `nfa_scan` as structured IR: DataType::U32 transition table + Load + BinOp + Select + Node::For over input bytes
- New CPU ref in `vyre-reference`: table-driven sequential NFA
- New naga builder: uniform-array-lookup compute kernel, no bytecode
- Add KAT parity tests against every existing regex pattern
- Update README line about NFA bytecode — delete the carve-out prose since it's gone

## Phase 8: 54 Law-B string-WGSL → naga::Module builders (30–40 hrs)

Largest mechanical pass. Each `vyre-core/src/dialect/*/lowering.rs` currently builds a WGSL string and parses it via `naga::front::wgsl::parse_str`. Rewrite each as programmatic naga::Module construction.

Order by dialect (independent per file):
1. `dialect/workgroup/queue_fifo/lowering.rs`
2. `dialect/workgroup/queue_priority/lowering.rs`
3. `dialect/workgroup/stack/lowering.rs`
4. `dialect/workgroup/primitives/visitor/lowering.rs`
5. `dialect/workgroup/primitives/union_find/lowering.rs`
6. `dialect/workgroup/primitives/hashmap/lowering.rs`
7. `dialect/workgroup/primitives/typed_arena/lowering.rs`
8. `dialect/workgroup/primitives/string_interner/lowering.rs`
9. `dialect/workgroup/primitives/state_machine/lowering.rs`
10. All `dialect/security_detection/*/wgsl.rs` files (~30 files) — these currently are `fn build_X_naga(...) -> Module { parse_str(wgsl).expect(...) }`
11. `dialect/stats/sliding_entropy/wgsl.rs`
12. Remaining workgroup + string_matching

For each file:
- Read existing WGSL
- Build a `ModuleBuilder` with types/global_variables matching current WGSL layout
- Translate the WGSL compute function to naga Expression/Statement graph
- Validate via `naga::valid::Validator::new(ValidationFlags::all(), Capabilities::all())`
- Ensure the WGSL backend emits byte-equivalent WGSL via `naga::back::wgsl::write_string`
- Add per-file parity test asserting naga::Module matches previous compiled shader

After each cluster, re-run `check_no_string_wgsl.sh` — count drops monotonically.

## Phase 9: A-B3 residue — 35 real CPU refs (6–8 hrs)

Replace `structured_intrinsic_cpu` placeholder with real implementations for:
- workgroup ops that have meaningful CPU semantics (stack, queue_fifo, queue_priority, typed_arena, string_interner, state_machine, visitor, union_find, hashmap)
- security_detection catalog entries with canonical byte-level CPU impl
- wgsl_byte_primitives: CPU equivalents via bytemuck

Each lives in `vyre-reference` — move logic from the scattered `ops/*/cpu_ref.rs` to a unified vyre-reference home.

## Phase 10: Reference interpreter design flip (4–6 hrs)

- `vyre-reference/src/workgroup.rs` currently simulates GPU barriers + workgroup scheduling on CPU
- Rewrite as obvious sequential CPU semantic: run invocation 0, then 1, then 2... inside a workgroup, with explicit barrier checkpoints that re-run from the barrier point
- Delete the "invocation scheduler" abstraction
- Test parity against wgpu backend on every workgroup KAT

## Phase 11: M5 split vyre-core into per-domain crates (12–20 hrs)

Current: 1,077 files. Target:
- `vyre-core` keeps: ir/, dialect/{registry,op_def,enforce,mutation,interner,lowering,dialect,migration}.rs, lib surface
- `vyre-ops-primitive` — `ops/primitive/**` + `dialect/{logical,math}/**`
- `vyre-ops-hash` — `ops/hash/**` + `dialect/hash/**`
- `vyre-ops-string` — `ops/string_matching/**` + `ops/string_similarity/**` + `dialect/string_*/**`
- `vyre-ops-security` — `ops/security_detection/**` + `dialect/security_detection/**`
- `vyre-ops-compression` — `ops/compression/**` + `dialect/decode/encode/**`
- `vyre-ops-graph` — `ops/graph/**`
- `vyre-ops-workgroup` — `ops/workgroup/**` + `dialect/workgroup/**`

Steps:
1. Create each crate with `Cargo.toml` referencing `vyre = { path = "../vyre-core", version = "0.5" }`
2. Move files preserving history (`git mv`)
3. Update inventory::submit! paths if needed
4. Update workspace Cargo.toml members list
5. Each publishable crate standalone
6. Update README crate table to reflect new surface

## Phase 12: Inventory-only registration sweep + define_op! macro (6 hrs)

- Grep workspace for any non-inventory registration path (`register_op_spec`, manual `RUNTIME_REGISTRY.push`)
- Route all through inventory
- Delete runtime register_op_spec compatibility layer
- Author `define_op!` proc macro in `vyre-macros`:
  ```
  define_op! {
      id = "primitive.bitwise.xor",
      dialect = "primitive.bitwise",
      category = A,
      inputs = [U32, U32],
      outputs = [U32],
      laws = [Commutative, Associative, Identity(0)],
      compose = |a, b| Expr::bitxor(a, b),
      naga_wgsl = xor_naga_builder,
  }
  ```
  Expands to: OpDef construction + inventory::submit! + public fn program() + const LAWS + ...

## Phase 13: backends/ reshuffle (4–6 hrs)

Per VISION layout:
- `git mv vyre-wgpu backends/wgpu`
- `git mv vyre-reference reference` (or keep vyre-reference name; update path)
- Update every `path = "../../vyre-wgpu"` dep
- Update CI workflows working_directory paths
- Update README crate paths
- Update docs/targets.md crate paths
- Verify cargo publish --dry-run still works for each

## Phase 14: SPIR-V backend (6–10 hrs)

`backends/spirv/` — second real backend.
- Cargo.toml: `vyre = { path = "../../vyre-core", version = "0.5" }`, `naga = { version = "*", features = ["spv-out"] }`, inventory
- Implement VyreBackend, reusing `LoweringTable::naga_wgsl` builders but consuming output via `naga::back::spv::write_vec`
- Register via inventory
- Full KAT corpus runs; parity against wgpu
- Add to dialect-coverage matrix

## Phase 15: Perf patches (8–12 hrs) — one file per patch, per-fix bench

Order by ROI.

- **S5.1 H3** — `vyre-wgpu/src/engine/dfa.rs:290` — read match-count buffer first, map only populated prefix
- **S5.2 H6** — `vyre-wgpu/src/pipeline_persistent.rs` add AtomicBool `validated`; skip on hot path
- **S5.3 H2** — `vyre-wgpu/src/buffer/pool.rs` + `runtime/cache/buffer_pool.rs` → `Vec<Vec<Entry>>` size-class buckets, index by `size.next_power_of_two().trailing_zeros() as usize`
- **S5.4 H7** — `vyre-core/src/ir/transform/optimize/cse/impl_exprkey.rs` — flat atom vec + child-id u32s; no recursive Box
- **S5.5 H8** — `vyre-wgpu/src/pipeline_bindings.rs` — multi-group + push constant support; WGSL reflection parser handles `@group(N)` for N>0 and `var<push_constant>`
- **S5.6 M1** — `vyre-wgpu/src/engine/streaming.rs` — crossbeam_deque::Worker/Stealer replaces Mutex<Receiver>
- **S5.7 M2** — `vyre-wgpu/src/engine/streaming/async_copy.rs` — bounded rayon-style worker pool; remove thread::spawn per task
- **S5.8 M3** — `vyre-wgpu/src/runtime/cache/tiered_cache.rs` — intrusive LRU per tier; O(1) eviction
- **S5.9 M4** — `vyre-wgpu/src/buffer/handle.rs:284` — `queue.clear_buffer(...)` replaces `write_buffer(vec![0u8; N])`
- **S5.10 M10** — `vyre-wgpu/src/pipeline.rs:206` — cache blake3 on CompiledPipeline, compute once
- **S5.11 M11** — `vyre-wgpu/src/engine/streaming.rs` + pool → keyed by `DeviceFingerprint { vendor: u32, device: u32, driver: u32 }` 
- **S5.12 M12** — `vyre-core/src/ir/model/program.rs:115` — after program load, `buffer_index: Arc<FxHashMap<u32, usize>>` with string→u32 intern on the load path

Per fix:
1. Write the patch
2. Criterion bench before/after via `cargo bench -p vyre-wgpu -- <bench>`
3. Record delta in BENCHMARKS.md under a "2026-04-19 perf sweep" section
4. Commit per-fix

## Phase 16: Criterion benchmarks + BENCHMARKS.md honest methodology (3–4 hrs)

- Rewrite `benches/primitives_showcase_support/gpu.rs` so `prepare_inputs` runs INSIDE the timed loop (C8 commitment)
- Run every registered primitive op at 1K / 10K / 100K / 1M
- Baselines: CPU scalar (rust std), CPU SIMD (std::simd), ripgrep for string match, hyperscan if available
- RTX 5090 numbers in BENCHMARKS.md with full methodology block
- Generate `benches/RESULTS.json` + `benches/RESULTS.md`
- Cross-backend comparison table after SPIR-V lands: wgpu vs spirv per op

## Phase 17: 4 conform crates (16–24 hrs)

Each under 10 kLOC per VISION.

### 17a. `vyre-conform-spec` crate (3 hrs)

- Move `AlgebraicLaw` from vyre-spec into vyre-conform-spec (re-export from vyre-spec)
- Define `WitnessDomain<T>`: stratified boundary sampler — 0, 1, MAX, MAX-1, ±0, ±Inf, NaN, subnormal, MSB-set, MSB-clear, and N random samples
- Per-DataType: `impl WitnessSet for U32 { ... }` produces the stratified set
- `CompositionLaw`: given two laws A and B, compute what compose(A,B) satisfies

### 17b. `vyre-conform-generate` crate (4 hrs)

- Proptest-integrated witness generator with shrinking
- Per DataType boundary enumeration
- `CounterexampleMinimizer`: binary-search shrink on the witness that triggered failure

### 17c. `vyre-conform-enforce` crate (8 hrs)

**The novel contribution.** Algebraic-law composition prover.
- Given op A with laws L_A and op B with laws L_B, compute the composable law set L_{A∘B}
- Generate witness set covering all boundary pairs of L_{A∘B}
- For every witness input w, compute `compose(A, B)(w)` on the reference interpreter
- Assert the law holds: e.g. for Commutative composition, `compose(A,B)(w1,w2) == compose(A,B)(w2,w1)` for all witness pairs
- Counterexample extraction on failure

### 17d. `vyre-conform-runner` crate (5 hrs)

- Orchestrates: loads registered backends, runs every registered op against every witness, emits a structured certificate
- Certificate format (JSON):
  ```
  {
    "version": "0.5",
    "op_id": "primitive.bitwise.xor",
    "wire_format_version": 1,
    "program_blake3": "...",
    "witness_set_blake3": "...",
    "backend_id": "wgpu",
    "backend_version": "0.5.0",
    "laws_verified": ["Commutative", "Associative", "Identity(0)"],
    "timestamp": "2026-04-19T01:23:45Z",
    "signature_ed25519": "...",
    "pubkey": "..."
  }
  ```
- Byte-identical cert across backends (modulo backend_id) = exchangeable
- CLI: `vyre-conform run --backend wgpu --ops all` / `--backend spirv` / etc.

### 17e. CI gate — conform on every PR (1 hr)

- `.github/workflows/conform.yml` — runs `vyre-conform run` against mock + wgpu + photonic + spirv
- Merge blocked on cert mismatch
- Upload cert artifacts for each PR

## Phase 18: Fusion certificates — innovation (4–6 hrs)

Every FusionDecision emits a cert proving the fused kernel ≡ unfused on a witness set.
- Hook `vyre-core/src/optimizer/passes/fusion.rs` to call conform-enforce
- Emit cert alongside every fused kernel
- Make fusions reversible: cert embedded in compiled output, allows "unfuse" diagnostic

## Phase 19: `#[derive(AlgebraicLaws)]` proc macro — innovation (4 hrs)

`vyre-macros` gains a derive macro. Applied to op types, it:
- Reads `#[vyre(laws = [Commutative, Identity(0)])]` attribute
- Emits `impl AlgebraicLawProvider for T` returning the law set
- Generates witness-set wiring at the type level so conform can pull it without runtime registration

## Phase 20: GPU compile cache on disk — innovation (4–6 hrs)

- `vyre-wgpu/src/runtime/cache/disk.rs`: blake3(wgsl) ⊕ DeviceFingerprint → path
- Location: `$XDG_CACHE_HOME/vyre/pipelines/` or platform equivalent
- Persist naga::Module bytes + wgpu::PipelineCacheDescriptor data
- On load: verify blake3 + adapter match; skip compile if cache hit
- Benchmark: cold compile vs warm cache — publish delta

## Phase 21: Three-substrate parity demo (2 hrs)

- Short Rust binary in `examples/three_substrate_parity/`
- Construct one Program (e.g. xor 1M u32s)
- Dispatch on wgpu → get output + cert
- Dispatch on spirv → get output + cert
- Dispatch on photonic (supports_dispatch=false → returns structured error)
- Print comparison: both real backends produce byte-identical output; certs match

## Phase 22: Versioned wire-format spec publication (2 hrs)

- Tag `vyre-spec` 0.5.0 as the VIR0 spec version
- Publish `docs/wire-format.md` as an independently versioned document
- Add `vir0-spec.md` at repo root as the stable external spec (short form)
- Other-language bindings can target the spec directly

## Phase 23: Polish sweeps

### 23a. expect/unwrap → Fix: (6–8 hrs)

Workspace-wide sweep. 396 sites. Each either:
- `.expect("Fix: <what>, cause: <why>")`
- `.unwrap_or_else(...)` with actionable fallback
- `?` propagation with wrapped error

Per-file mechanical pass.

### 23b. missing_docs deny (8–12 hrs)

1058 sites. By category:
- 502 module docs — `//! <what this module provides>`
- 255 function docs — `/// <one-line summary> + \n/// # Examples + ...`
- 180 constant docs — `/// <meaning + units + range>`
- 121 struct/enum/variant/field/method docs

Pass crate-by-crate; flip `missing-docs = warn` → `missing-docs = deny` at the end.

### 23c. cargo-semver-checks green (2 hrs)

`cargo install cargo-semver-checks`. Run per publishable crate. Any breaking change against 0.4.0 surfaces — bump to 1.0.0 if unavoidable, else restore compat.

## Phase 24: Audit .internals/ (2 hrs)

- `archive/` — archive staleness, purge artifacts older than 30 days unless explicitly pinned
- `audits/` — consolidate session audits; keep only load-bearing ones
- `catalogs/` — regen from current registry
- `perf/` — purge stale perf data; keep current 5090 baseline
- `planning/` — this file + prior session plans
- `public-api/` — snapshot current public surface
- `release/` — prep for publish: checklist + go/no-go

## Phase 25: GitHub workflows audit (3–4 hrs)

Review every workflow; fix stale paths or dead-crate refs:
- `architectural-invariants.yml` — already updated
- `bench-regression.yml` — check script paths
- `bench.yml` — check bench names
- `ci.yml` — main CI, verify all passes
- `coverage.yml` — test coverage threshold
- `deny.yml` — cargo-deny config in deny.toml; sync
- `dependency-audit.yml` — cargo-audit
- `fuzz.yml` — fuzz targets still valid
- `loom.yml` — loom tests
- `miri.yml` — miri lint
- `public-api.yml` — cargo-public-api
- `semver-checks.yml` — cargo-semver-checks
- `strict.yml` — -D warnings full build
- `udeps.yml` — cargo-udeps

## Phase 26: demos + examples audit (2 hrs)

- `demos/rust_lexer_gpu/` — compile? run? sample output?
- `demos/rust_parser_gpu/` — same
- `examples/hello_vyre/` — compile, produce expected output
- `vyre-core/src/bin/vyre_new_op/` — generate a new op scaffold, verify template matches post-migration shape

## Phase 27: Config + dep audit (2 hrs)

- `deny.toml` — update allowlist, purge dead-crate entries, add photonic
- `.cargo/config.toml` — verify settings
- `rust-toolchain.toml` — verify 1.85 or bump
- `Cargo.lock` — `cargo update` to resolve latest compat
- `cargo-audit` — security sweep
- `cargo-outdated` — which deps have majors available; plan bumps

## Phase 28: Final verification (3–4 hrs)

- `cargo test --workspace --no-fail-fast` on 5090 — 0 failures
- `cargo clippy --workspace --all-targets -- -D warnings` — 0 errors
- `cargo doc --workspace --no-deps --all-features` — 0 broken links
- All 9 CI laws green
- `cargo fmt --check` — clean
- `scripts/publish-dryrun.sh` — succeeds for every publishable crate
- `cargo-semver-checks` across all publishable crates
- `check_trait_freeze.sh` — 7 traits confirmed
- README / VISION / CHANGELOG / BENCHMARKS.md consistent
- docs/ referenced from code cross-matches
- VIR0 wire spec finalized and referenced

## Phase 29: CHANGELOG.md 0.5.0 entry (1 hr)

Honest delta-from-0.4.0:
- New: photonic stub backend, SPIR-V backend, 4 conform crates, algebraic-law composition prover, GPU compile cache on disk, define_op! macro, AlgebraicLaws derive
- Breaking: open IR (Expr/Node/DataType/RuleCondition Opaque variants), wire format v1 extensible, M5 split into per-domain crates, backends/ reshuffle, OpSpec removed
- Fixed: 173 test failures → 0, Damerau-Levenshtein correctness, 4 broken CPU refs, glob/wildcard arg order, builtin-axis validation, Bool storage HOST_SHAREABLE, Negate on u32, LogicalNot on u32, Min/Max/AbsDiff/Cos/Sin/Popcount/Clz/Ctz/ReverseBits/Is{Nan,Inf,Finite}
- Removed: NFA bytecode VM, OpSpec dual-registry, 54 string-WGSL sites, 8 duplicate LICENSE files, root-level trash (16 py + 6 rlib + scratch/test_*), orphan `core/` + `coordination/`, empty `lower/` dir
- Docs: THESIS, ARCHITECTURE, memory-model, targets, wire-format

## Phase 30: Publish 0.5.0 (2 hrs)

Sequence:
1. `vyre-spec` 0.5.0
2. `vyre` 0.5.0 (vyre-core crate)
3. `vyre-primitives` 0.5.0
4. `vyre-reference` 0.5.0
5. `vyre-ops-*` per-domain crates (if M5 landed)
6. `vyre-wgpu` 0.5.0
7. `vyre-photonic` 0.1.0
8. `vyre-spirv` 0.1.0
9. `vyre-conform-{spec,generate,enforce,runner}` 0.1.0

`cargo publish -p <crate>` per step; wait for index propagation between steps.

## Phase 31: Commit final + tag v0.5.0 (30 min)

- Final commit: "vyre 0.5.0 — substrate-neutral IR with open extension + conform certs"
- Git tag `v0.5.0`
- Push to GitHub
- GitHub release with CHANGELOG excerpt, benchmarks table, three-substrate parity demo screenshot

---

## Total estimated time

- Phase 0: 0.3 hr
- Phase 1: 0.6 hr
- Phase 2: 3 hr
- Phase 3: 4 hr
- Phase 4: 1 hr
- Phase 5: 12 hr
- Phase 6: 16 hr
- Phase 7: 8 hr
- Phase 8: 40 hr
- Phase 9: 8 hr
- Phase 10: 6 hr
- Phase 11: 20 hr
- Phase 12: 6 hr
- Phase 13: 6 hr
- Phase 14: 10 hr
- Phase 15: 12 hr
- Phase 16: 4 hr
- Phase 17: 24 hr
- Phase 18: 6 hr
- Phase 19: 4 hr
- Phase 20: 6 hr
- Phase 21: 2 hr
- Phase 22: 2 hr
- Phase 23: 22 hr
- Phase 24: 2 hr
- Phase 25: 4 hr
- Phase 26: 2 hr
- Phase 27: 2 hr
- Phase 28: 4 hr
- Phase 29: 1 hr
- Phase 30: 2 hr
- Phase 31: 0.5 hr

**Total: ~245 hours** ≈ 6 solid weeks of focused solo work, or ~30 sessions of 8 hours.

No phase is optional. No phase is deferred. Every item maps to a task in the list (#102–#152 + residuals).
