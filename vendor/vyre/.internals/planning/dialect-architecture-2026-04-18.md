# Vyre Dialect Architecture — toward millions of ops

**Status:** design doc. Replaces the ad-hoc `OpSpec::intrinsic` pattern.
**Scope:** defines how ops are declared, organized, lowered, and extended at
scale. Every op in the workspace should be migratable to this model in one
pass once it lands.

---

## Goal

Let the universe of ops grow without bound — millions across thousands of
dialects — while keeping:

- Vyre's core crate compact (no per-op source code in vyre).
- Compile times proportional to **ops actually referenced**, not ops defined.
- Backends capable of declaring "I support these dialects" once, and
  inheriting every op in them.
- Every op target-portable by construction: no hand-written WGSL, SPIR-V,
  or PTX text anywhere in an op's definition.

---

## The unit

```rust
// vyre-core/src/dialect/op_def.rs
pub struct OpDef {
    pub id: InternedOpId,            // (dialect_id, op_id) → interned u32
    pub dialect: DialectId,          // u16
    pub version: SemverPin,          // per-dialect version this op belongs to
    pub signature: Signature,        // declarative inputs/outputs/attrs
    pub laws: &'static [AlgebraicLaw],
    pub category: Category,          // A (composable) / B (backend-aware) / C (intrinsic)
    pub lowerings: LoweringTable,    // per-target lowerings, see below
}

pub struct Signature {
    pub inputs:  SmallVec<[TypedParam; 4]>,
    pub outputs: SmallVec<[DataType; 2]>,
    pub attrs:   AttrSchema,         // key → expected type
}

pub struct AttrSchema { fields: SmallVec<[(StaticStr, AttrType); 4]> }

pub enum AttrType { U32, I32, F32, Bool, Bytes, String, Enum(&'static [&'static str]) }
```

**The IR never stores `OpDef` directly.** A Program stores `OpRef`:

```rust
pub struct OpRef {
    pub op: InternedOpId,        // u32 interned handle
    pub operand_handles: Range<u32>,  // index into Program.operands arena
    pub attrs: Range<u32>,       // index into Program.attrs arena
}
```

Flat. No trait objects in the Program. Lookups are one FxHashMap hit per op.

---

## The Category C intrinsic fix (the flaw Gemini found)

Today's broken pattern:

```rust
pub const SPEC: OpSpec = OpSpec::intrinsic(
    "workgroup.queue_fifo",
    INPUTS, OUTPUTS, LAWS,
    wgsl_only,                       // ← "yes, this op only supports WGSL"
    IntrinsicDescriptor::new(
        "workgroup_queue_fifo_enqueue",
        "workgroup-sram-atomic-tail",
        structured_intrinsic_cpu,
    ),
);
// ...and a sibling .wgsl file with hand-typed shader source.
```

The `wgsl_only` flag plus the sibling `.wgsl` file bypasses naga entirely.
The op is locked to WGSL, cannot be retargeted to SPIR-V/CUDA/Metal, and
Law B's script never sees the raw WGSL because it's in an asset file, not
a `.rs` file.

**Fix: every Cat C intrinsic ships a `LoweringTable`, not a wgsl-only
descriptor.**

```rust
pub struct LoweringTable {
    naga_wgsl: Option<fn(&LoweringCtx) -> naga::Module>,
    naga_spv:  Option<fn(&LoweringCtx) -> naga::Module>,
    ptx:       Option<fn(&LoweringCtx) -> PtxModule>,
    metal_ir:  Option<fn(&LoweringCtx) -> MetalModule>,
    cpu_ref:   fn(&[u8], &mut Vec<u8>, &AttrMap),  // always required
}
```

Each lowering function **builds a naga::Module (or equivalent AST)** from
scratch. No text. No asset files. Naga is the portable intermediate — the
same `naga::Module` can be emitted as WGSL via `naga::back::wgsl` or as
SPIR-V via `naga::back::spv`. One op function → two free targets. PTX and
MetalIR have their own AST types.

For `workgroup.queue_fifo` specifically: the atomic-tail enqueue kernel
is ~40 lines of naga::Module construction instead of ~40 lines of WGSL
string. Same work, portable output.

**Law B script must be extended** to forbid both:
- `push_str` / `format_args!` with WGSL tokens in `.rs` files (current).
- Any `.wgsl` / `.spv` / `.ptx` / `.metal` asset file checked in under a
  directory that contains an op spec (new). An op ships naga-builder code,
  not a pre-baked shader.

---

## Dialects

A dialect is a namespace + version + validator + op bundle:

```rust
pub struct Dialect {
    pub id: StaticStr,               // "math", "crypto", "bio", "workgroup"
    pub version: Semver,
    pub parent: Option<StaticStr>,   // optional, for inheritance
    pub ops: &'static [OpDef],
    pub validator: fn(&Program) -> Result<(), ValidationError>,
    pub backends_required: &'static [BackendCapability],
}
```

Built-in dialects (`core`, `math`, `io`, `workgroup`, `pattern`) ship in
vyre. Everything else is external — either a separate crate on crates.io
that inventory-submits its dialect, or a TOML bundle loaded at runtime.

The full op ID in the Program is `(dialect_id, op_id)` — both u16/u32.
String interning happens at parse/decode time; after that it's all ints.

---

## The two parallel registration paths

```
┌──────────────────────┐       ┌──────────────────────┐
│  Rust-compiled path  │       │   Runtime-TOML path  │
│                      │       │                      │
│  inventory::submit!  │       │  dialect.toml + ops/ │
│       │              │       │        │             │
│       ▼              │       │        ▼             │
│  DialectRegistry ────┼──►────┼──► DialectLoader     │
│       │              │       │        │             │
└──────────────────────┘       └──────────────────────┘
                    │               │
                    ▼               ▼
                  ┌───────────────────┐
                  │ InternedOpId table│    ← one global table
                  │ + LoweringTable   │      (indexed by u32)
                  │   per (op, target)│
                  └───────────────────┘
```

Both paths produce the same in-memory data. A backend cannot distinguish
a Rust-compiled op from a TOML-loaded one. Fast-path dispatch is
identical.

---

## What this buys us concretely

1. **Adding an op never touches vyre-core.** New dialect crate =
   `inventory::submit!(DialectDef { … })`. New TOML dialect = drop a file
   in `~/.vyre/dialects/` or any path in `VYRE_DIALECT_PATH`.

2. **Adding a backend inherits every op in the supported dialects.**
   New CUDA backend says `supports_dialect("math@1", "io@1")`; every op in
   those dialects is automatically dispatchable through CUDA if the op's
   `LoweringTable.ptx` is populated.

3. **Validation is schema-driven.** The signature + attr schema is data.
   The validator walks the schema and checks the Program. One validator,
   millions of ops.

4. **No more wgsl-only dead ends.** Every op ships naga-builder code, so
   WGSL + SPIR-V are both free. PTX and Metal are additional opt-ins.

5. **Law B tightens to cover assets.** No hand-typed shader anywhere in
   the workspace — every shader byte comes out of naga/spv/ptx backend
   emitters.

6. **Hot path stays flat.** Programs are arrays of u32 op handles, not
   trait-object graphs. Trait dispatch is limited to lowering-time
   function pointer lookups. Dispatching 10 M ops/sec remains feasible.

---

## Migration order

1. **Land the `OpDef` + `Signature` + `LoweringTable` types** in
   vyre-core. Alongside the existing `OpSpec`, not replacing — dual path
   during migration.

2. **Migrate Cat C intrinsics first.** They're the ones breaking today.
   `workgroup.queue_fifo`, `workgroup.hashmap`, `workgroup.union_find`,
   `workgroup.typed_arena`, `workgroup.string_interner`,
   `workgroup.state_machine`, `workgroup.stack`, `workgroup.queue_priority`,
   codec formatters. Each grows a `naga::Module` builder function and
   loses its sibling `.wgsl` file. The WGSL output of the builder must
   match the current hand-typed shader byte-for-byte through a transition
   test.

3. **Migrate Cat A composable ops.** These already build `Expr`/`Node`
   trees; their `OpDef` just wraps the existing IR builder.

4. **Delete the legacy `OpSpec` + `OpSpec::intrinsic`** once every op
   uses `OpDef`. Rip the `wgsl_only` flag.

5. **Add the TOML runtime loader.** Schema validator, attribute parser,
   lowering-function plugin loader (for Rust-compiled lowerings that
   pair with TOML-declared signatures).

6. **Extend Law B script.** Scan for `.wgsl`/`.spv`/`.ptx`/`.metal`
   asset files under `src/ops/**`; fail if any exist.

7. **Stdlib dialect split.** `core`, `math`, `io`, `workgroup`,
   `pattern` each become their own module hierarchy inside vyre-core with
   a single top-level `DIALECT: DialectDef` per module. No new crate
   boundaries — still one vyre crate.

8. **Publish a reference 3rd-party dialect crate.** Something like
   `vyre-dialect-crypto` that inventory-registers hash/MAC/KDF ops. This
   proves the external-dialect path end-to-end.

---

## Open questions for when we start building

- **Attribute type system.** Should attrs be strongly typed in the
  schema (AttrType::U32, AttrType::F32) or bag-of-values (
  AttrValue::String | Int | Float | Bool)? Former is safer, latter is
  more flexible for unknown dialects. I'd lean strongly typed with an
  `AttrType::Unknown` escape hatch.

- **Versioning strategy.** Per-op version or per-dialect version?
  Per-dialect is simpler (all ops in v2 move together), per-op gives
  finer granularity. I'd start per-dialect and add per-op only when
  someone actually hits the granularity limit.

- **Lowering function runtime representation.** `fn pointer` is fastest
  but can't be loaded from TOML. For TOML-declared-but-Rust-lowered ops
  we need a (dialect_name, op_name) → fn_ptr lookup table that Rust
  crates populate via inventory. Clean to design; need to spec it.

- **Shader binary caching.** Since every op now builds a naga::Module
  deterministically, we can cache the emitted WGSL/SPIR-V by
  content-hash of the builder function. Probably fits the existing
  pipeline-cache dir infrastructure (adapter-fingerprint-keyed).

---

*End of design doc. No code changed yet. Ready to implement in sequence.*
