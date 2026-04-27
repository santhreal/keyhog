# Changelog

All notable changes to vyre are documented here. Follows Keep a Changelog.

## [Unreleased]

### New

- **`vyre-libs` — `c_lower_ast_to_pg_nodes` Cat-A op.** Added registration for
  `vyre-libs::parsing::c::lower::ast_to_pg_nodes`, a pure-IR lowering from
  structural VAST rows to packed `PgNode` tuples
  `(kind, span_start, span_end, parent_idx, payload_lo, payload_hi)`.
  Added witness fixture, pure CPU reference oracle, WGSL emission smoke test,
  GPU dispatch parity sample, and adversarial coverage (60 fixtures + proptest).

- **`vyre-runtime` — persistent megakernel + `io_uring` NVMe streaming.**
  The GPU becomes a VIR0 bytecode interpreter that loops forever reading
  slots the host publishes into a ring. Linux-only NVMe zero-copy via raw
  `io_uring_setup` + mmap of SQ/CQ rings, with a `uring-cmd-nvme` feature
  for `IORING_OP_URING_CMD` passthrough (kernel 6.0+). Three-buffer
  layout (control / ring / debug_log), 256-lane × N-workgroup sharding,
  opcode extension hook for vendor intrinsics, per-tenant authorization
  masks, atomic `done_count` counter, and a PRINTF debug channel.
- **`vyre-libs` — Category A composition ecosystem.** Pure-IR
  compositions over `vyre-ops` primitives (`math`, `nn`, `matching`,
  `crypto`). No raw shader source — every library function is a
  `Program` consumers can round-trip, validate, and inline.
  `substring_search` lands with a real byte-by-byte equality instead of
  the earlier LAW 1 placeholder.
- **10 io_uring + IR innovations.** `IORING_REGISTER_BUFFERS` +
  `READ_FIXED`, `IORING_REGISTER_FILES` + `IOSQE_FIXED_FILE`, GPUDirect
  Storage `GpuMappedBuffer::from_bar1_peer`, `futex_waitv` completion
  doorbell, per-workgroup slot sharding, ring-credit backpressure,
  opcode extension hook, tenant-mask routing, PRINTF debug channel,
  AF_XDP/RDMA ingress demonstrated via a TCP smoke test.
- **Error-code catalog grew a `P-*` family** for
  `vyre-runtime::PipelineError`.
- **Workspace docs pristine.** `cargo doc --workspace --all-features
  --no-deps` runs clean — zero unresolved intra-doc links, zero
  private-link leakage, zero output collisions.

### Fixed

- **LAW 1 placeholder in `vyre-libs::matching::substring_search`** — the
  inner-byte check was `Expr::u32(1)` (matched every position); now
  `load(haystack, i+k) == load(needle, k)` routed through a select to
  stay integer. Gap L-7 closed with a structural regression test that
  fails if the compare ever collapses back to a constant.
- **LAW 9 evasion audit sweep** — removed all `// TODO` / `// FIXME`
  markers from shipped code. Subgroup intrinsics return a structured
  error pointing at RFC 0004 instead of a TODO; the autotune workgroup
  heuristic is documented as intentional default instead of a TODO.
- **Driver binary name collision** — `vyre-driver-wgpu`'s CLI bin
  renamed from `vyre` → `vyre-wgpu` so it no longer collides with the
  `vyre` lib target in `cargo doc`.
- **Workspace version drift** — `vyre-runtime` workspace dep bumped
  from `0.1.0` → `0.6.0` to match the crate's own manifest.

### Changed

- **`Node::forever(body)`** helper in `vyre-foundation::ir::Node`. Linus
  principle — `forever` lowers to `Node::Loop { 0..u32::MAX, body }`,
  no new enum variant, no cascade of match arms. Persistent kernels
  use it.

## [0.6.0] — 2026-04-19
(layered workspace: foundation → driver → ops; single inventory registration path)

### New in 0.6.0

- **Nine-crate layered workspace.** Extracted `vyre-foundation` (IR, wire format, visitor traits, extension resolvers), `vyre-driver` (registry, runtime, pipeline, routing, diagnostics), `vyre-driver-wgpu` (wgpu backend, buffer pool, bind-group cache, pre-recorded dispatch), `vyre-driver-spirv`, `vyre-ops` (stdlib dialects), from what was a single god-crate. `vyre` remains as a back-compat meta shim.
- **Machine-checked layer DAG.** `scripts/check_layering.sh` enforces R1–R3+R5 from `COMPUTE_2_0.md §3`: foundation has no driver/ops/backend deps, driver has no ops/backend deps, ops has no backend deps, reference has no backend deps. Cross-layer imports go DOWN only; violations fail CI.
- **True IR openness.** `Expr::Opaque` and `Node::Opaque` now round-trip through the wire format (tag `0x80`) via inventory-registered `OpaqueExprResolver` / `OpaqueNodeResolver`. Validator, optimizer passes, and visitor adapters all honour Opaque explicitly — no wildcard fallthrough remains in foundation transforms.
- **Single op registration path.** `inventory::submit!{OpDefRegistration::new(...)}` is THE way to publish an op. `OpSpec` surface is gone; `DialectRegistry` is the frozen index.
- **Zero-alloc dispatch hot path.** `bound_handles` returns `SmallVec<[_; 8]>`, bind groups cache keyed by bound-buffer identity, buffer pool recycles power-of-two allocations across dispatches.
- **`vyre-reference` Memory** replaced `HashMap<String, Buffer>` with `BufferMap` (`SmallVec<[(Arc<str>, Buffer); 8]>`) — branch-predicted inner-loop lookups, no per-access SipHash, no per-name `String` allocs. `LocalSlots` interns via `FxHashMap<Arc<str>, _>`.
- **Invariant catalog truthful.** Every descriptor in `vyre-spec/src/invariants.rs` now references a real file at `conform/vyre-conform-enforce/tests/invariants.rs`, enforced by `scripts/check_invariant_paths_exist.sh`.
- **Ratchet CI gates.** `scripts/check_no_string_wgsl.sh` caps Law-B string-WGSL violations at 54 and `naga::front::wgsl::parse_str` sites at 84. `scripts/check_warning_budget.sh` caps workspace warnings at 921. Each gate decreases only; regression fails CI.

### Breaking

- Op registrations must go through `vyre-driver::registry::OpDefRegistration`. Consumers using legacy `OpSpec` surface must migrate.
- `vyre-core/src/` is reduced to `lib.rs` (meta-shim re-exports). Files that reached into `vyre::ir::transform::...` etc. must import from `vyre_foundation` directly — the meta-shim still provides the `vyre::ir::X` paths for surgec/pyrograph/warpscan consumers.

## [0.5.0] — 2026-04-19
(substrate-neutral IR: open extensions + conform certificates)

### New in 0.5.0 final

- **VIR0 wire-format spec published** — `vir0-spec.md` at repo root declares the wire format stable across 0.5.x, reserves the `0x80..=0xFF` tag range for third-party extensions in perpetuity, and documents conformance requirements for non-Rust bindings (Phase 22).
- **Bytes extraction validation** — `BufferDecl::with_bytes_extraction(true)` opt-in relaxes V013 on load/store of `DataType::Bytes` buffers for legitimate bytes-producing ops like `decode.base64`, `compression.lz4_decompress`, and the decoder family. `Signature` gained `#[non_exhaustive]` + `bytes_extraction` field + `bytes_extractor` constructor (Phase 3).
- **Canonicalized 7 primitive programs** to match the emit-asserted WGSL shape — `abs_diff` routes through `max(a,b) - min(a,b)`, `div` / `mod` wrap in zero-guard `select`, `logical_not` uses boolean-style `select(x==0, 1, 0)`, `negate` uses two's-complement `~a + 1`, and `shl` / `shr` zero-guard shifts `>=32` (Phase 2).
- **photonic backend crate** lives in `backends/photonic/` as a registered non-dispatching substrate with `supports_dispatch = false` — proves the three-substrate surface claim today, while photonic compute remains future work.
- **SPIR-V backend skeleton** in `backends/spirv/` — `SpirvBackend::emit_spv` consumes `naga::Module` built by the shared builder family and calls `naga::back::spv::write_vec`, giving vyre a second real compute-capable backend alongside wgpu (Phase 14).
- **Conform crates scaffolded** — `vyre-conform-spec` (witness sets + composition laws), `vyre-conform-generate` (proptest-style shrinking minimizer), `vyre-conform-enforce` (algebraic-law prover over witness pairs), `vyre-conform-runner` (CLI + Certificate schema) at `conform/vyre-conform-*` (Phase 17).
- **rules/op/ certificate library** — 5 op certs (`decode.base64`, `compression.lz4_decompress`, `match.dfa_scan`, `string_matching.aho_corasick_scan`, `graph.bfs`) plus `SCHEMA.md` defining op_id / signature_blake3 / allowed_backends / witness_set_blake3 / laws metadata (Phase 4).
- **NFA bytecode micro-interpreter fully retired** — the remaining `nfa_scan` kernel was deleted in the 2026-04-19 zombie sweep, README/CHANGELOG/VISION cross-references scrubbed, scan and lexical ops now compose in vyre IR end-to-end (Phase 7).
- **Docs** — `docs/THESIS.md`, `docs/ARCHITECTURE.md`, `docs/memory-model.md`, `docs/targets.md`, `docs/wire-format.md` authored as load-bearing spec.

### Breaking

- `Signature` is `#[non_exhaustive]` — out-of-crate literal construction must move to `Signature::bytes_extractor(...)` or `Signature { inputs, outputs, attrs, ..Signature::default() }` equivalent.
- `BufferDecl` gained the `bytes_extraction: bool` field; source-compatible through the builder API (`::read`, `::output`, `::read_write`, `::storage`, `::workgroup`), but direct struct literals must set it.

### Fixed

- `all_primitives` arithmetic / bitwise assertions now see the canonical WGSL shapes emitted by `naga_emit` — `abs_diff`, `div`, `mod`, `logical_not`, `negate`, `shl`, `shr` all validate against the assertion set.
- V013 no longer blocks valid decode / decompress flows that read and write typed `Bytes` buffers.
- README no longer describes a bounded `nfa_scan` bytecode micro-interpreter; it was deleted.

### Substrate (Claude)
- core: structured `Diagnostic` API with stable `E-*` / `W-*` codes,
  rustc-style human render, JSON round-trip for LSP / CI integration
  (A-C1b).
- wire: rev 3 framing — schema version bumped to 3 with structured
  `Error::VersionMismatch { expected, found }` replacing string-based
  version mismatch (A-C2).
- dialect: op versioning + migration table (`Migration`,
  `Deprecation`, `AttrMap`, `Semver`) via `inventory::submit!`; chain
  resolution + deprecation diagnostics (A-C2b).
- perf: `BENCHMARKS.md` performance contract — 10 targets, numerical
  stability per-op ULP bounds, regression gate spec (A-C14b).
- optimizer: `AdapterCaps` + `PassCtx` + `AnalysisCache`; typed-error
  conversion from `PassSchedulingError` to `Diagnostic` (A-C7b part 1).
- core: runtime introspection API — `dialects()`, `ops()`, `backends()`,
  `lowerings()`, `coverage_matrix()` (A-C11b).
- docs: op-id stability catalog + regen-on-demand gate
  (`docs/catalogs/op-id-catalog.md`); coverage matrix + regression gate
  (`docs/catalogs/coverage-matrix.md`) (A-B4d, A-C11b).
- scripts: layout / file-size / mod.rs-size / prelude / readmes CI
  law scripts under `scripts/laws/` (A-C11c part 1).

### Dialects (Gemini A)
- core: dialect foundation types — `OpDef`, `LoweringTable`,
  `DialectRegistry`, `InternedOpId`, `BackendRegistration` (A-B0).
- core: every Cat C intrinsic migrated to `naga::Module` builders —
  91 ops, zero shader assets remain in op trees (A-B1).
- core: primitive Cat A ops migrated; KAT coverage for 7 previously-
  missing programs (A-B2).
- core: `io` dialect — 4 Cat C zero-copy intrinsics
  (`io.dma_from_nvme`, `io.write_back_to_nvme`, `mem.zerocopy_map`,
  `mem.unmap`) registered with no backend opt-in (B-B3 scope).

### Backends (Gemini B)
- wgpu: dispatch via `DialectRegistry.get_lowering` — `OpSpec::intrinsic`
  read path removed (B-B1).
- wgpu: `impl Executable` + `impl Compilable` for `WgpuBackend` with
  `WgpuIR` progressive-lowering artifact (B-B5).
- reference: `dialect_dispatch` module routes op ids through
  `DialectRegistry.get_lowering(CpuRef)` (B-B4).

### Performance (Gemini C)
- wgpu: lock-free `BufferPool` via crossbeam; `PrerecordedDispatch`
  pre-recording (C-B1).

### Pre-existing (landed earlier in the cycle)
- core: blake3 fingerprinting for IR stability and cache invalidation (MOD-008)
- core: arena-backed reference interpreter (P-2)
- runtime: zero-copy output-slice readback (P-5)
- runtime: streaming chunked dispatch (P-7)
- validator: tightened atomic indexes, fma/select typing, mixed arithmetic typing, and u64 bitwise-unary acceptance (VAL-001..004)
- conform: widened overflow-contract surface for primitive arithmetic regression coverage (CONF-001)
- conform: added build-scan regression coverage for generated operation metadata (CONF-002)
- wire: added depth-cap regression coverage for hostile nested IR blobs (EDGE-001)

### Changed
- `vyre-conform::specs::primitive` now walks `vyre::ops::registry` for every `primitive.*` op and builds specs from core metadata plus normalized `rules/kat/primitive/<family>/<op>.toml` vectors. Legacy per-op modules that were not present in the core registry, including `logical_and`, `logical_or`, `logical_xor`, `logical_nand`, `logical_nor`, `avg_floor`, `wrapping_neg`, and `popcount_sw`, were removed rather than kept as conform-only specs.

## [0.4.0-alpha.2] — 2026-04-17

### Added
- Architecture and process contracts were formalized with `ARCHITECTURE.md`, `rules/SCHEMA.md#kat`, and `docs/PRIMITIVES.md`, giving a stable contributor contract for frozen traits, op classification, and community rulesets.
- New publishable package structure was established: `vyre-spec` (`0.1.0`) and `vyre-build-scan` (`0.1.0`) plus release-ready crate metadata for the workspace surface.
- Conformance foundations landed for this release with canonical `CpuOp` CPU reference plumbing in `core::ops::cpu_op`, `conform` pipeline cleanup, and the move of `reference` into `vyre` so evaluator semantics and wire-era tooling are co-located.
- Benchmark and evidence publishing pipeline landed: `primitives_showcase` entrypoint, `benches/RESULTS.md`, and synchronized benchmark presentation in README + book.

### Changed
- DeepPerf wave cleanup converted temporary tree-gen and generated-cruft artifacts into a stable one-file-per-op structure, including conform command/layout simplification and generated module deduplication.
- Core/conform import surfaces and type contracts were adjusted for category and registry stability, including `Category`/`IntrinsicTable` migration into `vyre-spec` and elimination of brittle cross exports.
- Documentation and validation semantics were tightened: `Fix:`-prefixed actionable diagnostics, contract-first doc language, and release-oriented invariant text for affected public surfaces.
- Package and build metadata was harmonized for publishability and release continuity.

### Fixed
- Fixed immediate compile/dependency coupling regressions from the prior refactor wave by removing dead or misleading generated surfaces and restoring stable compile boundaries.
- Fixed benchmark evidence drift by rebaselining published values from `benches/RESULTS.md` and aligning user-facing benchmark tables.
- Fixed stale release-state items by auditing all open coordination entries and refreshing statuses with explicit reopen criteria.

### Perf
- DeepPerf benchmark capture completed for primitive ops across 1K/10K/100K/1M element sizes with CPU and GPU end-to-end timings, crossover annotations, and the full 48-op table in `benches/RESULTS.md`.
- Preserved the end-to-end performance gate by excluding structural hacks and ensuring benchmark coverage remains tied to committed results data.
- Captured remaining hotspot context for future release polish (`gcd`, `lcm`, and uncovered KAT boundary classes) in coordination notes for targeted follow-up.

## [0.4.0-alpha.1] — previous

### Added
- Workspace merge of `vyre` core and `vyre-conform` into a single workspace.
- `SANTH_STANDARD.md` and `template_op.rs` — standardized contributor template for adding new ops (8fa6ab6, 436264b).
- `automod` wired across all op categories (bitwise, math, reductions, data_movement, string, scan, sort, encode, stats, buffer, compiler_primitives, rule, decode, match_ops, string_similarity, graph, workgroup, security_detection, hash) (c6af953, c4ab1f7, a39a9c5).
- CI workflow for check + clippy + doc (3c57a49).

### Changed
- Core consolidated from ~2000 files down to 1117 files with 0 compile errors (0956373, 5b6e1e5, 436264b).
- Conform merged and consolidated from 3645 files down to 883 files with 0 compile errors (09a6496).
- GPU feature gates stripped from conform; conform now assumes GPU is always available (ac760a8, b1b7991).

### Fixed
- Original 80-entry op registry restored after agent overwrites (b1b7991).
- Tree-gen damage consolidated and reverted where it broke the module graph (ade08d5, c91ad8c, 35f7342, dd71607).
