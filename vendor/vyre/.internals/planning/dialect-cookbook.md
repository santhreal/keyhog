# dialect cookbook

Recipes for extending vyre: add an op, add a whole dialect, add a
backend, wire a Cat C intrinsic. Every recipe is copy-paste
friendly; no magic incantations.

The running theme: `DialectRegistry` + `inventory::submit!` is the
single extension mechanism. Adding features = adding rows to the
registry. Deleting features = deleting rows. There is no other
moving part to learn.

---

## Adding a new op to a stdlib dialect

Scope: you're a vyre maintainer adding an op to an existing
dialect (e.g. `math`, `bitwise`, `workgroup`).

### 1. Make the op directory

Canonical layout (enforced by
`scripts/laws/check_layout.sh`):

```
vyre-core/src/dialect/<name>/<op>/
├── op.rs           # OpDef registration
├── cpu_ref.rs      # pure-Rust reference
├── wgsl.rs         # naga::Module builder for WGSL
├── tests.rs        # conformance + adversarial
└── README.md       # 1-paragraph summary
```

### 2. `op.rs` — register the OpDef

```rust
use crate::dialect::op_def::{OpDef, Category, Signature};
use crate::dialect::lowering::{LoweringTable};
use crate::dialect::OpDefRegistration;
use naga::Module;

pub fn build_naga(_ctx: &crate::dialect::lowering::LoweringCtx) -> Module {
    // emit the naga::Module that represents this op's kernel body
    Module::default()
}

pub fn cpu_ref(input: &[u8], output: &mut Vec<u8>) {
    // pure-Rust reference implementation
    output.extend_from_slice(input);
}

inventory::submit! {
    OpDefRegistration::new(|| OpDef {
        id: "math.your_op",
        dialect: "math",
        category: Category::Intrinsic,
        signature: Signature { inputs: &[], outputs: &[], attrs: &[] },
        lowerings: LoweringTable {
            cpu_ref,
            naga_wgsl: Some(build_naga),
            ..LoweringTable::empty()
        },
        laws: &[],
    })
}
```

### 3. `tests.rs`

Include *at minimum*:

* A unit test constructing `DialectRegistry::global()` and looking
  up the op id. Assert the lookup succeeds and returns the right
  dialect + category.
* An adversarial proptest that invokes `cpu_ref` on malformed /
  oversized / empty input and asserts no panic.

### 4. Hook the op into CI

The op-id catalog + coverage matrix regenerate automatically. Run
both before committing:

```sh
VYRE_REGEN_OP_CATALOG=1 cargo test -p vyre --test op_id_catalog
VYRE_REGEN_COVERAGE=1   cargo test -p vyre --test coverage_matrix
```

Commit the regenerated markdown alongside the code so reviewers see
the catalog delta.

### 5. Op-id naming

* `<dialect>.<op_name>` — lowercase, snake_case.
* Use the specific name callers will type (`math.add`, not
  `math.addition`).
* Once the id is committed, **it is frozen**. Renaming an op
  requires a migration registration (see next recipe).

---

## Renaming / evolving an op (Migration)

When an op's attribute renames (`mode` → `overflow_behavior`) or
shape changes (new required attr), register a Migration instead of
breaking the wire format:

```rust
use vyre::dialect::migration::{Migration, Semver, AttrValue};

inventory::submit! {
    Migration::new(
        ("math.add", Semver::new(1, 0, 0)),
        ("math.add", Semver::new(2, 0, 0)),
        |attrs| {
            attrs.rename("mode", "overflow_behavior");
            if attrs.get("overflow_behavior").is_none() {
                attrs.insert(
                    "overflow_behavior",
                    AttrValue::String("wrap".into()),
                );
            }
            Ok(())
        },
    )
}
```

Programs encoded against v1 decode cleanly on a runtime that only
knows v2. Chains (v1 → v2 → v3) resolve automatically.

---

## Adding a new external dialect crate

Scope: you're a third party shipping a new dialect without
patching vyre-core.

### 1. Create the crate

```toml
# Cargo.toml
[package]
name = "vyre-dialect-myalgo"
version = "0.1.0"

[dependencies]
vyre.workspace = true
inventory.workspace = true
naga.workspace = true
```

### 2. Register ops

Same `inventory::submit! { OpDefRegistration::new(|| OpDef { ... }) }`
pattern as stdlib dialects. The registrations fire on first
`DialectRegistry::global()` call — no crate-specific init.

### 3. Test that consumers see your ops

```rust
#[test]
fn dialect_registers() {
    use vyre::dialect::registry::DialectRegistry;
    let reg = DialectRegistry::global();
    let id = reg.intern_op("myalgo.special");
    assert!(reg.lookup(id).is_some());
}
```

That's the entire recipe. Consumers `cargo add vyre-dialect-myalgo`
and the registrations fire on the first registry query.

### 4. Proof-of-work — the 200-LOC extensibility demo

BENCHMARKS.md target 10: external crate adds a new op with WGSL +
SPIR-V lowerings, runs on three backends, in ≤ 200 LOC. That's the
bar your crate should clear. Keep registrations terse.

---

## Adding a new backend

Scope: you're adding a new execution target (e.g. PTX via CUDA,
Metal on Apple, an FPGA backend).

### 1. Implement the Backend / Executable / Compilable traits

```rust
pub struct MyBackend { /* device handles, etc. */ }

impl vyre::VyreBackend for MyBackend { /* id, version, dispatch */ }
impl vyre::Executable   for MyBackend { /* execute */ }
impl vyre::Compilable   for MyBackend { type Compiled = MyIR; /* compile */ }
```

### 2. Register via inventory

```rust
inventory::submit! {
    vyre::dialect::BackendRegistration {
        op: "*",                    // wildcard = backend-level registration
        target: "my-backend",
    }
}
```

Per-op registrations can narrow support by submitting
`(op, "my-backend")` pairs.

### 3. Write a naga::Module consumer that targets your IR

If your backend's shader language is already naga-supported
(WGSL, SPIR-V), reuse the stdlib `naga_wgsl` / `naga_spv` builders
in `LoweringTable`. Your backend's `execute` function walks the
registry, calls `get_lowering(op, Target::Wgsl)` (or `::Spirv`),
validates the naga::Module, and emits target-specific code.

If your target needs a different IR (PTX, Metal IR), add a new
`Target::Ptx` / `Target::MetalIr` variant (already stubbed in
`dialect/registry.rs`) and have the ops ship `ptx` / `metal`
builders in their `LoweringTable`.

---

## Writing a naga::Module builder for a Cat C intrinsic

Cat C intrinsics are backend-specific — they don't have a portable
lowering. The canonical pattern:

```rust
pub fn build_subgroup_scan(ctx: &LoweringCtx) -> naga::Module {
    let mut m = naga::Module::default();
    // ... build the module imperatively ...
    // Use naga::Type / naga::Expression / naga::Statement helpers
    // to construct the shader structurally. Never concatenate WGSL
    // strings — `scripts/check_no_string_wgsl.sh` enforces.
    m
}
```

For ops that *can't* be expressed portably, leave the relevant
lowering `None` in `LoweringTable`. A program that references such
an op fails Law C (capability negotiation) cleanly — the backend
returns `BackendError::Unsupported` instead of crashing at dispatch
time.

---

## Testing the full chain

After you add an op or dialect:

```sh
# op-id + coverage matrix regeneration (if you accept the diffs)
VYRE_REGEN_OP_CATALOG=1 cargo test -p vyre --test op_id_catalog
VYRE_REGEN_COVERAGE=1   cargo test -p vyre --test coverage_matrix

# the informational layout / file-size / readme gates
bash scripts/laws/check_file_sizes.sh
bash scripts/laws/check_layout.sh
bash scripts/laws/check_readmes.sh

# the wire-format round-trip + diagnostic stability
cargo test -p vyre --test wire_format_rev3
cargo test -p vyre --test diagnostics

# if you touched a hot path, the perf contract
bash scripts/check_benchmarks.sh
```

---

## What NOT to do

* **Do not** put shader text under `src/ops/**` or `src/dialect/**`.
  Every shader is emitted through naga::back::wgsl::write_string
  from a naga::Module built in Rust. `scripts/check_no_shader_assets.sh`
  enforces.
* **Do not** modify `mod.rs` to sneak in a non-declarative
  statement.  `mod.rs` files are declarations + re-exports only
  (`scripts/laws/check_mod_rs_size.sh` caps at 80 lines).
* **Do not** rename an op id "to match a new convention." Ids are
  frozen. Use the Migration mechanism.
* **Do not** wildcard `pub use` in the prelude. `pub use foo::*;`
  is drift waiting to happen; use explicit `pub use foo::{A, B, C};`.
* **Do not** silently downgrade an op's coverage (✓ → -) without
  explaining in the commit. The coverage matrix gate surfaces this
  as a hard fail.
