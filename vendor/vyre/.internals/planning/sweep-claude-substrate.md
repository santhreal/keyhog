# Sweep Plan — Claude: Substrate & Workspace Reshape

**Agent:** Claude, executing directly. No dispatches.
**Peers:** Gemini A (ops + dialects) and Gemini B (backends + perf) run in
parallel in Antigravity. I coordinate via git-log handshakes — no direct
messages.

**My scope (exclusive):**
- `vyre-core/src/ir/**` — Expr, Node, Program, serial/wire, transform, visit,
  validate, optimizer (entry points).
- `vyre-core/src/backend/**` — Backend trait surface (but Gemini B owns the
  concrete impls).
- `vyre-core/src/dialect/{op_def,lowering,dialect,registry,interner,toml_loader,
  prelude}.rs` — the substrate infrastructure of the dialect system. (Gemini
  A owns `dialect/<name>/**` stdlib dialect modules; I own the types.)
- `vyre-core/src/lib.rs`, `vyre-core/tests/**`, `vyre-core/benches/**`
  (except perf benches Gemini B adds).
- `Cargo.toml` workspace file, `scripts/**`, `docs/**`, `THESIS.md`,
  `ARCHITECTURE.md`, `VISION.md`, `CHANGELOG.md`, `README.md`.
- The two Gemini plan docs (`sweep-gemini-{a,b}-*.md`) if they need
  clarification.

**Off-limits while Geminis run:**
- `vyre-core/src/ops/**` (until Gemini A finishes moving it into
  `dialect/<name>/`; then it shouldn't exist).
- `vyre-core/src/dialect/<stdlib name>/**` — owned by Gemini A.
- `vyre-wgpu/**`, `vyre-reference/**` — owned by Gemini B.
- `vyre-dialect-crypto/**` — owned by Gemini A.

**Commit prefix:** every commit subject begins with `A-C<step>:`. Yes the
letter conflict is unfortunate — I own the `A-C<n>` space (Claude steps),
Gemini A owns `A-B<n>` (Gemini A steps). Keep them distinct.

**Rules:**
- Narrow `cargo check -p vyre` during iteration, workspace check at step
  end.
- No stubs, no test weakening, no TODOs left behind.
- Every commit must pass `cargo check -p vyre` before landing. If I break
  it, the Geminis will be blocked waiting — don't break it.

---

## Step A-C1 — [MOVED to Gemini A's A-B0]

Dialect foundation types now land as Gemini A's step A-B0. Gemini A
owns the dialect system end-to-end — claiming the types for myself was
defensive scope creep that created a false bottleneck. Both Geminis
start at t=0; I parallelize on everything that's truly cross-cutting.

My first step is now A-C1b (structured diagnostics), which I can
start in parallel with Gemini A's A-B0. The Diagnostic type gets
imported back into A-B0's types as their error-reporting contract,
but A-B0 uses Result<_, &'static str> as a placeholder until A-C1b
lands — trivial to upgrade later.

Skip to A-C1b below.

### Files

- `vyre-core/src/dialect/mod.rs` — re-exports the type surface.
- `vyre-core/src/dialect/op_def.rs`:
  ```rust
  pub struct OpDef {
      pub id: &'static str,               // "workgroup.queue_fifo" — dotted, dialect prefix
      pub dialect: &'static str,          // "workgroup"
      pub version: Semver,
      pub signature: Signature,
      pub laws: &'static [AlgebraicLaw],
      pub category: Category,             // A | B | C
      pub lowerings: LoweringTable,
  }

  pub struct Signature {
      pub inputs:  SmallVec<[TypedParam; 4]>,
      pub outputs: SmallVec<[DataType; 2]>,
      pub attrs:   AttrSchema,
  }

  pub struct TypedParam { pub name: &'static str, pub ty: DataType }

  pub struct AttrSchema { /* (name, AttrType) pairs */ }

  pub enum AttrType {
      U32, I32, F32, Bool, Bytes, String,
      Enum(&'static [&'static str]),
      Unknown,                            // escape hatch for dialects we don't control
  }

  pub enum Category { A, B, C }
  ```
  (Ensure `OpDef` derives nothing that would fail for fn pointers.)

- `vyre-core/src/dialect/lowering.rs`:
  ```rust
  pub struct LoweringCtx<'a> { /* bindings, program ref, attr map, target hints */ }

  pub type NagaBuilder  = for<'a> fn(&'a LoweringCtx<'a>) -> naga::Module;
  pub type SpirvBuilder = for<'a> fn(&'a LoweringCtx<'a>) -> naga::Module;
  pub type PtxBuilder   = for<'a> fn(&'a LoweringCtx<'a>) -> PtxModule;
  pub type MetalBuilder = for<'a> fn(&'a LoweringCtx<'a>) -> MetalModule;
  pub type CpuRef       = fn(inputs: &[&[u8]], attrs: &AttrMap, out: &mut Vec<u8>) -> Result<(), Error>;

  #[derive(Default)]
  pub struct LoweringTable {
      pub naga_wgsl: Option<NagaBuilder>,
      pub naga_spv:  Option<SpirvBuilder>,
      pub ptx:       Option<PtxBuilder>,
      pub metal_ir:  Option<MetalBuilder>,
      pub cpu_ref:   CpuRef,              // REQUIRED — enforced by constructor, not Option
  }

  impl LoweringTable {
      pub fn new(cpu_ref: CpuRef) -> Self;
      pub fn empty() -> Self { /* panics — use ::new instead */ }
  }

  // Placeholder types for future targets. Minimal structs, not empty
  // enums, so they survive into external crates that haven't implemented
  // real codegen yet.
  pub struct PtxModule { pub asm: String, pub version: u32 }
  pub struct MetalModule { pub ast: Vec<u8>, pub entry: String }
  ```

- `vyre-core/src/dialect/dialect.rs`:
  ```rust
  pub struct Dialect {
      pub id: &'static str,
      pub version: Semver,
      pub parent: Option<&'static str>,
      pub ops: &'static [OpDef],
      pub validator: fn(&Program) -> Result<(), ValidationError>,
      pub backends_required: &'static [BackendCapability],
  }

  pub fn default_validator(program: &Program) -> Result<(), ValidationError>;

  pub struct BackendRegistration {
      pub name: &'static str,
      pub supports_dialects: &'static [(&'static str, SemverReq)],
      pub validate: fn(&Program) -> Result<(), ValidationError>,
      pub execute: fn(&Program, &[&[u8]]) -> Result<Vec<Vec<u8>>, BackendError>,
  }

  inventory::collect!(OpDefRegistration);
  inventory::collect!(DialectRegistration);
  inventory::collect!(BackendRegistration);
  ```

- `vyre-core/src/dialect/registry.rs`:
  ```rust
  pub struct DialectRegistry { /* FxHashMap<DialectId, &'static Dialect>, op interner */ }

  impl DialectRegistry {
      pub fn global() -> &'static DialectRegistry;
      pub fn intern_op(&self, op_id: &str) -> Option<InternedOpId>;
      pub fn lookup(&self, id: InternedOpId) -> Option<&'static OpDef>;
      pub fn get_lowering(&self, id: InternedOpId, target: Target) -> Option<&'static fn /*...*/ >;
      pub fn load_runtime(&self);  // scans VYRE_DIALECT_PATH, inventory::iter
  }

  pub enum Target { Wgsl, Spirv, Ptx, MetalIr, CpuRef }
  ```

- `vyre-core/src/dialect/interner.rs`:
  - `InternedOpId(u32)` — global interner backed by `once_cell::OnceLock<
    Mutex<StringInterner>>` + the shuffle of `(dialect_id, op_id_within_dialect)`
    to a dense u32.

- `vyre-core/src/dialect/mod.rs`:
  ```rust
  pub mod op_def;
  pub mod lowering;
  pub mod dialect;
  pub mod registry;
  pub mod interner;

  pub use op_def::{OpDef, Signature, TypedParam, AttrSchema, AttrType, Category};
  pub use lowering::{LoweringTable, LoweringCtx, NagaBuilder, CpuRef};
  pub use dialect::{Dialect, BackendRegistration, default_validator};
  pub use registry::{DialectRegistry, Target};
  pub use interner::InternedOpId;
  ```

- `vyre-core/src/lib.rs` — add `pub mod dialect;` at the appropriate
  spot in the module declarations. Respect the `automod` convention the
  crate uses.

### Tests

`vyre-core/tests/dialect_types.rs` — smoke test:
- Construct a fake `OpDef`.
- Register via a test-only `inventory::submit!`.
- Look up via `DialectRegistry::global().intern_op("test.noop")`.
- Assert the interned u32 is stable across two lookups.
- Assert `get_lowering(id, Target::CpuRef)` returns `Some`.

### Verification

- `cargo check -p vyre` → 0 errors.
- `cargo test -p vyre --test dialect_types` → passes.
- `rg 'mod dialect' vyre-core/src/lib.rs` → one match.

### Commit

`A-C1: dialect foundation types (OpDef + LoweringTable + DialectRegistry + InternedOpId)`

After this lands, Geminis A and B start.

---

## Step A-C1b — Structured diagnostics

Errors today are strings with "Fix: " prefixes. Legendary is rustc-grade
structured diagnostics — every error has machine-readable fields the
IDE / tooling can consume.

### Changes

- `vyre-core/src/diagnostics/mod.rs` — new:
  ```rust
  pub struct Diagnostic {
      pub severity: Severity,           // Error | Warning | Note
      pub code: DiagnosticCode,          // e.g., "E-WIRE-VERSION"
      pub message: Cow<'static, str>,
      pub location: Option<OpLocation>,
      pub suggested_fix: Option<Cow<'static, str>>,
      pub doc_url: Option<&'static str>,
  }

  pub struct OpLocation {
      pub op_id: &'static str,
      pub operand_idx: Option<u32>,
      pub attr_name: Option<&'static str>,
  }

  pub enum Severity { Error, Warning, Note }
  ```
- Every error type (`WireError`, `ValidationError`, `BackendError`,
  `DialectLoadError`, etc.) grows a `Diagnostic::from(err)` impl.
- `Diagnostic::render_human()` prints rustc-style formatted output;
  `Diagnostic::to_json()` serializes for LSP/editor consumption.
- Existing "Fix: ..." strings become `suggested_fix` on the
  Diagnostic. No duplication.

### Tests

- `vyre-core/tests/diagnostics.rs`:
  - Construct every error variant, convert to Diagnostic, assert
    severity + code + human rendering.
  - JSON round-trip.

### Commit

`A-C1b: structured diagnostics (machine-readable Diagnostic with severity/code/location/fix/doc)`

---

## Step A-C2 — Wire format rev 3 (in parallel with Geminis)

After A-C1 lands, Geminis are migrating ops / reshaping backends. That work
doesn't touch `vyre-core/src/ir/serial/wire/**` — my turf. I write rev 3
concurrently.

### Changes

- `vyre-core/src/ir/serial/wire/mod.rs` — bump `SCHEMA_VERSION` constant
  to `3`. Encoder emits `[magic u32][schema_version u32][flags u16][
  dialect_manifest_len u16][dialect_manifest bytes][ops_len u32][ops
  bytes]`.
- `dialect_manifest` is `Vec<(name: &str, semver: [u32;3])>` — a Program
  records the dialects it uses + versions it was compiled against.
- Op payload shape: `[dialect_id u16][op_id u32][attr_blob_len u32][attrs
  bytes][operand_handles]`. Decoder interns `(dialect_name, op_name)`
  via `DialectRegistry::intern_op` on first read.
- `WireError::VersionMismatch { expected: u32, found: u32 }`.
- `WireError::UnknownDialect { name: String, requested: Semver }`.
- `WireError::UnknownOp { dialect: String, op: String }`.
- Law invariant: encoding is deterministic (sort dialect manifest by
  name, sort ops by encounter order, no HashMap iteration leaks into
  output).

### Tests

- `vyre-core/tests/wire_format_rev3.rs`:
  - Encode-decode round-trip for a program with 3 dialects and 20 ops.
  - Version mismatch test: craft bytes with `schema_version=2`, assert
    `VersionMismatch`.
  - Unknown dialect test: craft bytes with dialect `"fake"@0.0`, assert
    `UnknownDialect`.
  - Unknown op test: real dialect, fake op_id, assert `UnknownOp`.

### Commit

`A-C2: wire format rev 3 — schema version + dialect manifest + interned op handles`

---

## Step A-C2b — Versioning + migration table

Ops evolve. `math.add@1` may gain an `overflow_behavior` attribute in
`math.add@2`. Programs encoded against v1 should still decode and run.

### Changes

- `vyre-core/src/dialect/migration.rs` — new:
  ```rust
  pub struct Migration {
      pub from: (&'static str, Semver),   // (op_id, from_version)
      pub to:   (&'static str, Semver),   // (op_id, to_version)
      pub rewrite: fn(&mut AttrMap) -> Result<(), MigrationError>,
  }

  inventory::collect!(Migration);
  ```
- Wire decoder (A-C2) consults the migration table when it sees an
  `(op_id, version)` older than the highest registered version for
  that op. Applies rewrite, retries lookup.
- Deprecation: an `OpDef` can set `pub deprecated_since: Option<Semver>`
  + `pub deprecation_note: &'static str`. Decoder emits a
  `Diagnostic { severity: Warning }` when a deprecated op is decoded.

### Tests

- `vyre-core/tests/migration.rs`:
  - Register a dummy v1 op with attr `{mode: "wrap"}`, a v2 op with
    attr `{overflow_behavior: "wrap"}`, and a Migration that renames
    `mode → overflow_behavior`.
  - Encode a program against v1, decode it, assert the decoded attrs
    use the v2 name.
  - Deprecation test: decode a program using a deprecated op, assert
    the Diagnostic warning surfaces.

### Commit

`A-C2b: op versioning + migration table + deprecation warnings`

---

## Step A-C3 — Expr/Node fully open (workspace serialization point)

**Wait until Gemini A's `A-B3:` AND Gemini B's `B-B4:` commits have
landed.** At that point every op is an `OpDef` and the dispatch path goes
through `LoweringTable` — the match sites throughout the interpreter and
optimizer are the last callers of the closed enum.

**Signal Gemini B in the commit:** the subject prefix `A-C7:` per their
plan is what B's step B-B6 pause watches for. I land this commit with
subject starting `A-C7:`.

### Changes

- `vyre-core/src/ir/model/expr.rs` — the `Opaque(Arc<dyn ExprNode>)` variant
  already exists. Every place in the workspace that matches on `Expr`
  and does `_ => unreachable!()` or `_ => panic!()` gets a real
  `Opaque(ext) => ...` arm:
  - `optimizer/passes/*.rs` — const_fold, strength_reduce, fusion,
    dead_buffer_elim, const_buffer_fold, spec_driven: each pass treats
    Opaque as "don't optimize through it" (pass it through unchanged).
  - `validate/**.rs` — typecheck delegates to `ext.validate(&ctx)`;
    atomic_rules and expr_rules skip Opaque (extension-specific rules
    are the extension's job).
  - `transform/visit.rs`, `transform/optimize/cse/**.rs`, `transform/inline/**`
    — Opaque is a single opaque node; visitors call `ext.operands()` to
    descend.
- `vyre-core/src/ir/model/node.rs` — same treatment for `Node::Opaque(
  Arc<dyn NodeExtension>)`.
- Generic interpreter: `vyre-core/src/interpreter/` (new module or
  consolidate from existing) — dispatches via
  `DialectRegistry::get_lowering(op, Target::CpuRef)` rather than matching
  on variants. Closes F4.

### Tests

- `vyre-core/tests/open_ir.rs`:
  - Define a test-only `ExprNode` impl and a test-only `NodeExtension` impl.
  - Build a Program that uses both via `Expr::Opaque` and `Node::Opaque`.
  - Run through the reference interpreter, assert correct output.
  - Run optimizer passes, assert Opaque nodes survive unchanged (passes
    don't drop or corrupt them).

### Verification

- `cargo test -p vyre --lib` green.
- `cargo test -p vyre --test open_ir` passes.
- `rg 'match.*Expr.*\{[^}]*_ => unreachable' --multiline --type rust
  vyre-core/src/` returns zero matches.

### Commit

`A-C7: open Expr/Node — every match site handles Opaque; interpreter dispatches through DialectRegistry (closes F4)`

---

## Step A-C7b — Pass system as first-class (MLIR-style PassManager)

The optimizer today is loose functions under `optimizer/passes/`.
Formalize as a trait with declared dependencies, so passes can be
discovered, scheduled topologically, snapshot-tested, and extended by
downstream dialects.

### Changes

- `vyre-core/src/pass/mod.rs` — new:
  ```rust
  pub trait Pass: Send + Sync + 'static {
      fn id(&self) -> PassId;                      // e.g., "core.const_fold"
      fn requires(&self)    -> &[PassId] { &[] }   // passes that must run first
      fn invalidates(&self) -> &[PassId] { &[] }   // pass results this invalidates
      fn provides(&self)    -> &[PassId] { &[] }   // analysis results produced
      fn run(&self, ctx: &mut PassCtx) -> Result<(), Diagnostic>;
  }

  pub struct PassCtx<'a> {
      pub program: &'a mut Program,
      pub adapter_caps: &'a AdapterCaps,
      pub analyses: &'a mut AnalysisCache,
      pub diagnostics: &'a mut Vec<Diagnostic>,
  }

  pub struct PassManager { passes: Vec<Box<dyn Pass>> }

  impl PassManager {
      pub fn add(&mut self, pass: Box<dyn Pass>);
      pub fn run(&self, program: &mut Program, caps: &AdapterCaps) -> Result<(), Vec<Diagnostic>>;
      // Topologically sorts by requires/invalidates, catches cycles.
  }

  inventory::collect!(PassRegistration);
  ```
- Each existing pass (const_fold, strength_reduce, fusion,
  dead_buffer_elim, const_buffer_fold, spec_driven, cse, dce, inline)
  migrates from loose fn to a `Pass` impl in its own file.
- Each pass ships a snapshot test: `pass_const_fold_before.ir` + 
  `pass_const_fold_after.ir` in `tests/pass_snapshots/`. Test runs the
  pass on `before.ir`, asserts byte-identical match to `after.ir`.
- `vyre-core/tests/pass_manager.rs` — build a dependency cycle
  (`A requires B`, `B requires A`), assert PassManager returns
  `Diagnostic { code: "E-PASS-CYCLE" }` instead of deadlocking.

### Tests

- `cargo test -p vyre --test pass_manager` — topological sort + cycle
  detection.
- `cargo test -p vyre --test pass_snapshots` — every pass's
  before/after snapshot matches.

### Commit

`A-C7b: Pass system as first-class — trait + PassManager + per-pass snapshot tests`

---

## Step A-C4 — Delete legacy OpSpec + Law B asset ban

**Wait until Gemini A's `A-B4:` AND Gemini B's `B-B5:` have landed.** At
that point every op is in a stdlib dialect module and every backend
consumes `LoweringTable` — legacy `OpSpec` has zero callers.

### Changes

- `rg 'OpSpec|OpSpec::intrinsic|wgsl_only|IntrinsicDescriptor'
  --type rust vyre-core/src/ vyre-wgpu/src/ vyre-reference/src/
  vyre-primitives/src/` — MUST return zero matches before this step
  starts. If matches remain, Gemini A or B didn't finish their scope —
  coordinate via commit watchdog, do not proceed.
- Delete the following types from `vyre-core/src`:
  - `OpSpec` struct
  - `OpSpec::intrinsic` constructor
  - `IntrinsicDescriptor`
  - `wgsl_only` utility fn
  - `structured_intrinsic_cpu` helper
  - `crate::ops::cpu_op::*` module
  - any remaining `include!("../generated/*_registry.rs")` that pointed
    to the vyre-build-scan era (should already be gone from D4, but
    double-check)
- Rename `scripts/check_no_string_wgsl.sh` to
  `scripts/check_no_shader_assets.sh` (I already pre-staged the content;
  this step flips the name authoritative).
  - Actually two laws now: (1) `.rs` files can't `push_str` / `format_args!`
    WGSL tokens outside `vyre-wgpu/src/lowering/**` and (2) no
    `.wgsl/.spv/.ptx/.metal/.msl` files under `**/src/ops/**` or
    `**/src/dialect/**`. Merge into a single script with both checks.
- `scripts/rebuild_status.sh` — updated dashboard shows:
  ```
  Law A (open IR)        PASS
  Law B (naga only)      PASS
  Law B+ (no shader assets) PASS
  Law C (capability negotiation) PASS
  Law D (registry consistency)   PASS
  Law H (unsafe SAFETY) PASS
  Dialect coverage       PASS
  ```

### Verification

- `cargo check --workspace` → 0 errors.
- `bash scripts/check_no_shader_assets.sh` → passes.
- `bash scripts/check_dialect_coverage.sh` → passes.
- `bash scripts/rebuild_status.sh` → every law green.

### Commit

`A-C11: delete OpSpec + legacy intrinsic helpers; Law B extended to ban shader assets under src/ops and src/dialect`

---

## Step A-C11b — Coverage matrix + runtime introspection API

A consumer should be able to ask vyre at runtime "what do you know?"
and get a structured answer. A CI gate should prevent silent coverage
regression (a cell in the dialect × backend matrix that was green going
red without notice).

### Changes

- `vyre-core/src/registry/introspection.rs` — new public API:
  ```rust
  pub fn dialects() -> Vec<DialectSummary>;
  pub fn ops(dialect: &str) -> Option<Vec<OpSummary>>;
  pub fn backends() -> Vec<BackendSummary>;
  pub fn lowerings(op_id: &str) -> Vec<LoweringSummary>;  // which backends cover this op
  pub fn coverage_matrix() -> CoverageMatrix;             // (dialect, backend) → lowering state
  ```
- `cargo run -p xtask -- coverage` generates
  `docs/coverage-matrix.md` from the live registry:
  ```
                       | wgsl | spv | ptx | metal | cpu-ref |
  core@1               |  ✓   |  ✓  |  -  |  -    |   ✓     |
  math@1               |  ✓   |  ✓  |  -  |  -    |   ✓     |
  workgroup@1          |  ✓   |  ✓  |  -  |  -    |  stub   |
  io@1                 |  -   |  -  |  -  |  -    |   -     |
  security_detection@1 |  ✓   |  ✓  |  -  |  -    |   ✓     |
  ```
- `scripts/check_coverage_regression.sh` — regenerates the matrix,
  diffs against committed `docs/coverage-matrix.md`, fails if any
  cell went from `✓` to `-`. Additions are allowed; regressions aren't.
- Dashboard: `scripts/rebuild_status.sh` includes the coverage check.

### Tests

- `vyre-core/tests/introspection.rs`:
  - `dialects()` returns the registered stdlib dialects.
  - `ops("math")` returns every math op.
  - `backends()` includes `wgpu` and `reference` when those crates are
    linked (`#[cfg(...)]` gated appropriately).
  - `coverage_matrix()` output matches the committed markdown.

### Commit

`A-C11b: runtime introspection API + coverage matrix + regression CI gate`

---

## Step A-C11c — Linus layout commitment + file-size + layout law

The "intuitive organization" commitment: every directory has one
obvious purpose, every file has one obvious home, every op directory
has the same shape. Ship a new CI law that enforces the layout so it
can't rot.

### Committed directory tree

```
vyre-core/
├── README.md
├── Cargo.toml
├── src/
│   ├── lib.rs              (declares modules, re-exports; ≤ 100 lines)
│   ├── prelude.rs          (≤ 15 items)
│   ├── ir/
│   │   ├── mod.rs
│   │   ├── expr.rs
│   │   ├── node.rs
│   │   ├── program.rs
│   │   ├── validate/
│   │   └── serial/wire/
│   ├── dialect/
│   │   ├── mod.rs
│   │   ├── op_def.rs
│   │   ├── lowering.rs
│   │   ├── dialect.rs
│   │   ├── registry.rs
│   │   ├── interner.rs
│   │   ├── toml_loader.rs
│   │   ├── core/
│   │   ├── math/
│   │   │   ├── README.md
│   │   │   ├── mod.rs        (declares ops, ≤ 50 lines)
│   │   │   ├── add/
│   │   │   │   ├── op.rs
│   │   │   │   ├── cpu_ref.rs
│   │   │   │   ├── wgsl.rs
│   │   │   │   ├── spv.rs    (if present)
│   │   │   │   ├── tests.rs
│   │   │   │   └── README.md
│   │   │   └── ... (one dir per op)
│   │   └── ... (one dir per stdlib dialect)
│   ├── pass/
│   │   ├── mod.rs
│   │   ├── trait_def.rs
│   │   ├── manager.rs
│   │   ├── const_fold.rs
│   │   ├── fusion.rs
│   │   └── ... (one file per pass)
│   ├── backend/
│   ├── diagnostics/
│   ├── registry/
│   └── interpreter/
├── tests/
│   └── (one file per concern: kat_parity.rs, open_ir.rs, etc.)
├── benches/
│   └── (one file per bench group)
└── examples/
```

Banned file/directory names:
- `utils.rs`, `helpers.rs`, `common.rs`, `misc.rs`, `shared.rs`
  (except inside a module where the name is genuinely
  domain-specific, e.g., `decode/shared.rs` holding a specific helper
  that declares in the filename what it shares — borderline OK;
  prefer splitting).
- `utils/`, `helpers/`, `common/`, `misc/` as directories — always
  banned.

### Files to create

- `scripts/laws/check_layout.sh` — verifies:
  - Every op directory under `vyre-core/src/dialect/<name>/` has the
    shape: at least `op.rs`, `cpu_ref.rs`, `tests.rs`, `README.md`
    (others optional).
  - No banned names (`utils.rs`, etc.) anywhere under `vyre-core/src/`.
  - Every `<crate>/README.md` exists.
  - Every `<crate>/src/` directory has a `mod.rs` or `lib.rs`.
  - Directory depth ≤ 4 from any `src/` root.

- `scripts/laws/check_file_sizes.sh` — fails if any `.rs` file under
  a vyre-* crate exceeds 500 lines. Outputs a sorted-descending list
  of offenders.

- `scripts/laws/check_mod_rs_size.sh` — `mod.rs` files must be
  trivial (declarations + re-exports only). Fails if any `mod.rs`
  exceeds 80 lines.

- `scripts/laws/check_prelude_size.sh` — `vyre-core/src/prelude.rs`
  must re-export ≤ 15 items.

- `scripts/laws/check_readmes.sh` — every directory under
  `vyre-core/src/dialect/<name>/` and every op directory has a
  README.md.

### Changes

- `scripts/rebuild_status.sh` — dashboard grows the four new law
  rows.

- `README.md` at workspace root — 1-paragraph elevator pitch + a
  "where things live" map pointing at the tree above.

### Tests

- `bash scripts/laws/check_layout.sh` passes on clean main.
- Deliberately rename `vyre-core/src/dialect/math/add/op.rs` to
  `utils.rs` → script fails loudly with the offending path.
- Create a `vyre-core/src/misc/` directory → script fails.

### Commit

`A-C11c: Linus-style layout commitment + 4 CI laws (layout, file-size, mod.rs size, prelude size, readmes)`

---

## Step A-C5 — Documentation sweep

### Files to update

- `THESIS.md` — rewrite the "Extensibility" section. Document the dialect
  architecture as the load-bearing contract. Include a worked example of
  adding a new op in an external crate.
- `ARCHITECTURE.md` — crate topology remains "vyre + satellites"; add a
  `## Dialects` section showing the stdlib dialect list, wire format rev 3
  spec, backend capability negotiation flow, Law list updated.
- `VISION.md` — updated to describe the millions-of-ops end state
  concretely (dialects as community knowledge layer, runtime TOML loading,
  per-dialect versioning).
- `docs/dialect-cookbook.md` — copy-paste recipes:
  - "Add a new op to a stdlib dialect" (for vyre maintainers)
  - "Add a new external dialect crate" (for 3rd parties)
  - "Add a new backend that supports existing dialects"
  - "Write a naga::Module builder for a Cat C intrinsic"
- `docs/wire-format.md` — rev 3 spec, replacing rev 2.
- `CHANGELOG.md` — rewrite the "Unreleased" section summarizing the
  dialect sweep.
- `CONTRIBUTING.md` — updated op-addition workflow uses `dialect/<name>/`
  not `ops/<name>/`.
- `README.md` — 3-line XOR example using the new `vyre::prelude::*`
  surface. Should look like:
  ```rust
  use vyre::prelude::*;
  let out = vyre::xor(&input, 0xA5).run_gpu()?;
  ```
  (Requires a small `vyre::prelude` + helper fn implementation — Gemini A
  may add that as part of A-B5 if the time allows; if not, I add it in
  this step.)

### Verification

- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` clean.
- Every code example in the markdown files compiles (checked via doctests
  where relevant).

### Commit

`A-C13: docs for the dialect architecture (THESIS/ARCHITECTURE/VISION/cookbook/wire-format/CHANGELOG/CONTRIBUTING/README)`

---

## Step A-C6 — Parity closeout + publish gate

Last substantive step. All other work has landed.

### Changes

- Empty `KNOWN_FAILURES` in `vyre-core/tests/kat_parity.rs`. The
  primitive.bitwise.shl[1] fix should have landed via Gemini A's A-B2
  step (it registers shl and fixes drift in the same commit). If not,
  fix here: trace the bug in the shl lowering, fix, verify.
- Extend `kat_parity` to also run through `vyre-wgpu` when
  `VYRE_TEST_GPU=1` is set, asserting byte-identical output between CPU
  reference and GPU backend. This is the full parity guarantee.
- Run `bash scripts/publish-dryrun.sh`. Fix every failure.
- Bump workspace version to `0.5.0` in `Cargo.toml` (major architectural
  change warrants a minor bump given pre-1.0).
- Publish dry-run for every crate in dependency order.

### Verification

- `cargo test -p vyre --test kat_parity` → 82/82 pass, `KNOWN_FAILURES`
  empty.
- `VYRE_TEST_GPU=1 cargo test -p vyre --test kat_parity` → 82/82 pass via
  GPU path.
- `bash scripts/publish-dryrun.sh` → `READY TO PUBLISH`.

### Commit

`A-C14: parity closeout — empty KNOWN_FAILURES, GPU parity assertion, publish gate green`

---

## Step A-C14b — Performance instrumentation: BENCHMARKS.md + numerical stability

The "unarguably superior" claim has to be measurable and defended by
CI. Codify the targets.

### Changes

- `BENCHMARKS.md` at the workspace root — the performance contract:
  - Compile-to-dispatch latency target: **< 2 ms** (Program → first GPU instruction).
  - DFA scanning throughput target: **≥ 95% of hyperscan** on SecLists, **≥ 1.5× ripgrep** on code search.
  - Prefix-sum target (RTX 5090): **within 5% of hand-tuned CUDA cuDF** using subgroup ops.
  - Cross-adapter determinism: identical Program emits byte-identical output on WGSL + SPIR-V + CPU reference.
  - Zero-CPU streaming (when io_uring + GDS implementation lands): **≥ 25 GB/s** file → VRAM → scan, **0% CPU** on the data path.
  - Dispatch overhead: `dispatch_persistent` loop at **≥ 200K dispatches/sec** steady-state with BindGroup cache hit ratio ≥ 99%.
  - Memory amplification: vyre allocates **≤ 1.5×** the theoretical minimum VRAM per program.
  - Extensibility demo: ≤ 200-line external crate adds a new op with WGSL + SPIR-V lowerings, runs on three backends.

- `vyre-core/tests/numerical_stability.rs` — every float op runs on GPU
  and CPU reference, computes max ULP error, asserts within
  per-op bounds. Bounds live in a TOML table:
  ```toml
  # rules/numerical_stability/primitive.float.toml
  [primitive.float.fma]
  max_ulp = 0
  [primitive.float.fsqrt]
  max_ulp = 1
  ```
  Runs with `VYRE_TEST_GPU=1`.

- `scripts/check_benchmarks.sh` — runs a reduced bench suite (≤ 5 min),
  compares criterion output to baselines in `target/criterion-baselines/`,
  fails if any bench regresses > 5% without an explicit
  `allow-perf-regression: <reason>` label.

- `scripts/cross_backend_comparison.sh` (and `xtask bench-crossback`)
  — for each program in a small set, dispatches through every
  available backend, emits a markdown comparison table:
  ```
  | program       | wgpu  | spirv | cpu-ref |
  |---------------|-------|-------|---------|
  | xor-1M        | 0.8ms | 0.9ms | 120ms   |
  | prefix-sum-16M| 2.1ms | 2.3ms | 1800ms  |
  ```

### Tests

- `cargo test -p vyre --test numerical_stability -- --ignored` (runs
  on GPU when available) — every float op within bounds.
- `bash scripts/check_benchmarks.sh` — passes on clean main.

### Commit

`A-C14b: BENCHMARKS.md contract + numerical-stability instrumentation + bench regression CI + cross-backend comparison harness`

---

## Legendary bar for Claude

When I'm done:
- Zero `OpSpec::intrinsic`, `wgsl_only`, `IntrinsicDescriptor`
  references in the workspace.
- Zero `_ => unreachable!()` / `_ => panic!()` on Expr/Node matches.
- Zero shader asset files under any op or dialect tree.
- `KNOWN_FAILURES` empty.
- Every doc file lines up with reality.
- `scripts/publish-dryrun.sh` returns READY.
- **Structured diagnostics:** every error type round-trips through
  `Diagnostic` with severity / code / location / fix / doc URL.
- **Versioning + migration:** programs encoded at wire-format-rev3
  with op@v1 decode correctly on a workspace that only knows op@v2
  via a registered Migration; deprecation warnings surface as
  structured Diagnostics.
- **Pass system:** every optimizer pass implements `trait Pass` with
  declared requires/invalidates/provides; PassManager topologically
  schedules and catches cycles; every pass has a snapshot test.
- **Runtime introspection:** `vyre::registry::dialects()`, `ops`,
  `backends`, `lowerings`, `coverage_matrix` all return real data;
  `docs/coverage-matrix.md` regeneratable; CI gates against
  regression.
- **BENCHMARKS.md** committed at the workspace root with measurable
  superiority claims; CI enforces >5% regression gate.
- **Numerical stability:** per-op max-ULP bounds live in TOML, GPU
  path passes them.
- **Cross-backend comparison** harness emits a markdown table the
  user can cite.
- An external crate can inventory-register a new dialect without
  touching vyre-core source (`vyre-dialect-crypto` proves it).
- An external crate can inventory-register a new backend without
  touching vyre-core source (`vyre-wgpu`'s reshape proves it).
- A Program encoded with rev 3 wire format can be decoded by any
  backend that advertises the relevant dialect versions.

Commit subjects all start `A-C<n>:` or `A-C<n><letter>:`. No other
prefix.

---

## Handshake summary (4 agents)

All four agents start at t=0 in parallel. Gemini A lands the
foundation types quickly as A-B0; everyone else either waits on it or
works on scope that doesn't need it. Gemini C waits slightly longer
(depends on Gemini B's persistent-buffer baseline B-B2).

| Commit | Who | Waits for |
|--------|-----|-----------|
| A-B0   | Gemini A | (none — starts at t=0) |
| A-C1b  | Claude | (none — starts at t=0) |
| A-C2   | Claude | A-B0 |
| A-C2b  | Claude | A-C2 |
| A-B1   | Gemini A | A-B0 |
| B-B1   | Gemini B | A-B0 |
| A-B2   | Gemini A | A-B1 |
| B-B2   | Gemini B | B-B1 |
| C-B1   | Gemini C | B-B2 |
| A-B3   | Gemini A | A-B2 |
| B-B3   | Gemini B | A-B3 AND B-B2 |
| B-B4   | Gemini B | B-B3 |
| A-B4   | Gemini A | A-B3 |
| A-B4b  | Gemini A | A-B4 |
| A-B4c  | Gemini A | A-B4b |
| A-B4d  | Gemini A | A-B4c |
| B-B5   | Gemini B | B-B4 (Gemini B finishes here) |
| A-C7   | Claude | A-B3 AND B-B5 |
| A-C7b  | Claude | A-C7 |
| C-B2   | Gemini C | B-B5 |
| C-B3   | Gemini C | C-B2 |
| C-B4   | Gemini C | C-B3 |
| C-B5   | Gemini C | C-B4 |
| C-B6   | Gemini C | C-B5 |
| C-B7   | Gemini C | C-B6 |
| C-B8   | Gemini C | A-C7b AND C-B7 |
| C-B9   | Gemini C | C-B8 |
| C-B10  | Gemini C | A-C7b AND C-B9 |
| C-B11  | Gemini C | C-B10 |
| C-B12  | Gemini C | C-B11 |
| A-B5   | Gemini A | A-B4d (concurrent with Claude + Gemini C) |
| A-C11  | Claude | A-B4d AND C-B12 |
| A-C11b | Claude | A-C11 |
| A-C11c | Claude | A-C11b |
| A-C13  | Claude | A-C11c |
| A-C14  | Claude | A-C13 AND C-B12 |
| A-C14b | Claude | A-C14 |

Parallel fan-out: at t=0, four agents are moving. Gemini A and Claude
start with zero wait. Gemini B waits one commit (~5 min). Gemini C
waits two commits (A-B0 + B-B2, ~10-15 min). From t=15min forward,
all four agents run concurrently until B-B5 (where Gemini B finishes
and hands off to Gemini C, who runs solo in vyre-wgpu).

If anyone's commit lands broken, Claude diagnoses and lands fix-forward;
the plan's assumption is forward progress, not revert.

---

## Cross-cutting Unix-philosophy contract (applies to all three plans)

These invariants are checked by CI laws at every commit. Violating any
fails the gate and blocks merge.

- **One file, one responsibility.** If a `.rs` file needs a
  `// --- SECTION: FOO ---` comment, it's two files pretending to be
  one; split.
- **Every file ≤ 500 lines** (enforced by a new `scripts/check_file_sizes.sh`
  — emit the list of offenders sorted descending; fail on > 500).
- **No cross-dialect imports.** If math and bitwise share a helper,
  the helper lives in a separate module outside either dialect.
- **No god crates.** If a crate's README needs "and also..." it's two
  crates. (We just killed the god conform crate; this is the rule
  that keeps us from reinventing it.)
- **One op per file.** Never pack two ops into one `.rs`.
- **One dialect per directory.** Never pack two dialects into one.
- **Errors are data, not strings.** Every error constructs a
  `Diagnostic`; string-formatted errors in public APIs are a Law
  violation.
- **Laws are enforceable.** Every architectural law gets a `scripts/check_*.sh`
  script that runs in CI. Laws without scripts are decorations.
- **Every op is extensibility-testable.** A 200-line external crate
  adding an op must work without patching any file in this workspace.
  If the extension story requires "just edit this one file in
  vyre-core", the design has failed.

### CI laws present at end of sweep (16 total)

1. Pure-crate dependency invariant (existing)
2. Law A — no closed IR enums without Opaque escape (existing, extended)
3. Law B — no string WGSL in `.rs` (existing)
4. Law B+ — no shader asset files under `src/ops` or `src/dialect`
   (new in A-C11)
5. Law C — capability negotiation (existing)
6. Law D — registry consistency (existing)
7. Law H — unsafe SAFETY comments (existing)
8. Dialect coverage — every OpDef has ≥ 1 backend lowering
   (`check_dialect_coverage.sh` already committed)
9. File size — every `.rs` ≤ 500 lines (new in A-C11c)
10. mod.rs size — `mod.rs` files ≤ 80 lines, declarations only
    (new in A-C11c)
11. Prelude size — `vyre-core/src/prelude.rs` re-exports ≤ 15 items
    (new in A-C11c)
12. Op-directory layout — every op under `src/dialect/<name>/<op>/`
    has the canonical shape (`op.rs`, `cpu_ref.rs`, `tests.rs`,
    `README.md`) (new in A-C11c)
13. No banned names — `utils/`, `helpers/`, `common/`, `misc/`,
    `shared/` directories forbidden (new in A-C11c)
14. READMEs — every crate + dialect + op directory has README.md
    (new in A-C11c)
15. Op-ID stability — `docs/catalogs/op-id-catalog.md` matches
    registry (new in Gemini A's A-B4d)
16. Coverage matrix — `docs/catalogs/coverage-matrix.md` has no
    regressions (new in A-C11b)
17. Benchmark regression — > 5% slowdown in reduced bench suite fails
    (new in A-C14b)

Each law enforced by a `scripts/laws/check_*.sh` script, each gated
in CI, each dashboarded by `scripts/rebuild_status.sh`.
