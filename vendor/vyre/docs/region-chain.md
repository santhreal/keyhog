# Region chain — the compositional back-pointer invariant

Every vyre op, at every tier, wraps its body in `Node::Region`. The
`Region` carries a stable generator ID and, when the body was built by
composing another registered op, a `source_region` pointer to the
parent. This doc locks the invariant, the optimizer contract around
it, and the debug chain it enables.

Companion to:
- `docs/library-tiers.md` — where ops live.
- `docs/lego-block-rule.md` — when a composition must be decomposed
  into reusable Tier 2.5 blocks.

## The IR shape

```rust
Node::Region {
    generator: Ident,                         // "vyre-libs-nn::attention"
    source_region: Option<GeneratorRef>,      // Some(parent) when composed, None when anonymous
    body: Arc<Vec<Node>>,
}
```

Both fields exist in the 0.6 IR (`vyre-foundation::ir::Node`).
`source_region` is the back-pointer that makes a large composition
auditable after inlining.

## The invariant

1. **Every `OpEntry::build` returns a Program whose top-level Nodes
   include at least one `Node::Region`** wrapping the op's body with
   `generator = <OpEntry::id>`.
2. **When an op's body is constructed by calling another registered
   op's builder**, the resulting `Region` populates `source_region =
   Some(GeneratorRef { generator: <child op id>, .. })` for each
   child Region nested inside the outer body.
3. **Anonymous inline construction** — a helper building
   `vec![Node::if_then(...), Node::store(...)]` by hand — wraps with
   `wrap_anonymous(name, body)` which sets `source_region = None`.
4. **No op registers a Program whose top-level nodes contain a raw
   (non-Region-wrapped) statement**. `wrap_anonymous` is cheap; it
   enforces the invariant structurally.

## Helpers

Exported from the composition crates that build `Program`s, primarily
`vyre-libs::region` and `vyre-intrinsics::region`:

```rust
pub fn wrap_anonymous(name: &str, body: Vec<Node>) -> Node {
    Node::Region {
        generator: Ident::from(name),
        source_region: None,
        body: Arc::new(body),
    }
}

pub fn wrap_child(name: &str, parent: GeneratorRef, body: Vec<Node>) -> Node {
    Node::Region {
        generator: Ident::from(name),
        source_region: Some(parent),
        body: Arc::new(body),
    }
}
```

Every composite op reaches for one of these at build time. No op
constructs `Node::Region { ... }` directly; the helpers are the single
invariant point.

## Optimizer contract — `region_inline`

`transform::optimize::region_inline` has two modes:

### Release mode (default)

Flattens Regions — replaces `Node::Region { body, .. }` with the body
nodes directly. Produces dense IR with no per-region overhead.

### Debug mode

Flattens the same way **AND** records a side-channel map on the
Program:

```rust
pub struct RegionTrace {
    // For each top-level Node index in the flattened Program, the
    // region path from root to that Node (outermost first).
    pub node_index_to_path: Vec<Vec<Ident>>,
}
```

`Program.region_trace: Option<RegionTrace>` populated in debug builds,
`None` in release builds. Downstream tooling (print-composition,
shader comment emitter) reads the trace.

## Backend contract — region comments in emitted shaders

Backends MUST emit the region path at the top of each Region's
corresponding shader region:

- **Naga / WGSL**: write a leading line comment
  `// vyre-region: <path>` where `<path>` is the
  `>`-joined generator IDs from root to innermost Region at that
  point.
- **SPIR-V**: emit `OpLine` with the `OpString` set to the region
  path, anchoring back to a pseudo-source file entry
  `vyre-region/<generator>.vyre`.
- **Future backends**: preserve the same region path through that
  backend's native debug/source-map mechanism.

Result: reading a generated WGSL file and grepping
`// vyre-region:` produces the composition chain line-by-line.

## The audit tool

`cargo xtask print-composition <op_id>` resolves `<op_id>` against the
`OpEntry` inventory, calls `build()`, walks the root Region tree, and
prints a tree:

```
$ cargo xtask print-composition vyre-libs-nn::attention
vyre-libs-nn::attention  [48 nodes]
├─ softmax                           [14 nodes]
│  ├─ reduce_f32_max                 (vyre-primitives::reduce::max)
│  │  └─ subgroup_reduce_f32         (vyre-intrinsics::hardware::subgroup_add [f32 sum])
│  └─ scan_u32_add                   (vyre-primitives::reduce::sum)
│     └─ subgroup_add                (vyre-intrinsics::hardware::subgroup_add)
├─ matmul_tiled                      [22 nodes]
│  └─ fma_f32                        (vyre-intrinsics::hardware::fma_f32)
└─ layer_norm                        [12 nodes]
   ├─ inverse_sqrt_f32               (vyre-intrinsics::hardware::inverse_sqrt_f32)
   └─ reduce_u32_add                 (vyre-primitives::reduce::sum)
      └─ subgroup_add                (vyre-intrinsics::hardware::subgroup_add)
```

## Size cap enforcement

`cargo xtask gate1` iterates registered ops, builds each Program,
counts top-level body Nodes inside the outermost Region, and fails
when a reusable primitive exceeds the Tier 2.5 complexity budget
without being decomposed into smaller child Regions.

## What this enables

- **Audit a big Tier-3 op**: `cargo xtask print-composition
  vyre-libs-parse::surgec::parse_rule` shows every grammar-level node
  down to the `vyre-intrinsics::hardware::*` leaves.
- **Debug a GPU divergence**: shader has `// vyre-region:
  vyre-libs-nn::attention > softmax > workgroup_reduce_f32_max >
  subgroup_reduce_f32` — you know exactly which composition layer is
  live at the offending line.
- **Size-gate reusable primitives**: CI fails a PR that adds a
  500-Node Tier 2.5 primitive without decomposition. Forces the author
  to split the primitive or keep the logic in Tier 3.
- **Safe inlining**: release builds still flatten (no runtime cost),
  but debug builds always carry the trace — no tradeoff between
  production speed and audit clarity.

## Non-scope (explicit)

- Per-Node span info (file/line/col from user source) is a separate
  invariant, tracked under a future phase. Region chain operates at
  the op-composition level, not the textual-source level. The two
  compose (a surgec-sourced `parse_rule` op can carry both a region
  chain AND an AST-span map).
- Region identity across wire-format round-trip: the generator Ident
  survives encode/decode; the `source_region` does too (see
  `generated.rs` and `serial/wire/encode/put_node.rs`). No schema
  changes needed.
