# Adding Your First Op

By the end of this tutorial, you will have created `primitive.math.gcd` as a fully conformant Category A operation. You will have written a CPU reference oracle, a matching GPU kernel, declared its algebraic laws, added known-answer and adversarial test vectors, and verified the op end-to-end with `cargo test -p vyre-conform --lib`. The entire change requires no manual `mod.rs` edits and no hand-written central registry updates.

## Step 1: Pick an op

Operation IDs are dot-separated paths: `primitive.math.gcd`.

- `primitive` — Layer 1 building block.
- `math` — domain category.
- `gcd` — the operation itself.

Signature inference for `gcd` is straightforward: two unsigned 32-bit inputs, one unsigned 32-bit output. In code this is `(U32, U32) -> U32`.

**Category A vs Category C**

- **Category A** (compositional): the op can be expressed entirely from existing vyre IR primitives. The generic WGSL lowerer handles it. `gcd` is Category A because it composes from `Expr::rem`, `Node::loop_for`, and `Node::if_then`.
- **Category C** (custom lowerer): the op needs hand-written WGSL emission logic in `core/src/lower/wgsl/`. Only choose Category C when the generic lowerer cannot express the semantics.

## Step 2: Copy the template

Create the core op file from the template:

```bash
cp core/src/ops/template_op.rs core/src/ops/primitive/math/gcd.rs
```

vyre uses `automod` for discovery. `core/src/ops/primitive/math/mod.rs` contains:

```rust
explicit_mod_list!(pub "src/ops/primitive/math");
```

Drop `gcd.rs` into that directory and it is automatically discovered. No `mod.rs` edits needed.

## Step 3: Fill in identity

Open `core/src/ops/primitive/math/gcd.rs` and replace the template with the op identity and IR program:

```rust
use crate::ir::{BufferDecl, DataType, Expr, Node, Program};
use crate::ops::primitive::WORKGROUP_SIZE;
use crate::ops::{AlgebraicLaw, OpSpec, U32_U32_INPUTS, U32_OUTPUTS};

const LAWS: &[AlgebraicLaw] = &[
    AlgebraicLaw::Commutative,
    AlgebraicLaw::Associative,
    AlgebraicLaw::Identity { element: 0 },
    AlgebraicLaw::Idempotent,
];

/// Greatest common divisor operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct Gcd;

impl Gcd {
    pub const SPEC: OpSpec = OpSpec::composition_inlinable(
        "primitive.math.gcd",
        U32_U32_INPUTS,
        U32_OUTPUTS,
        LAWS,
        Self::program,
    );

    #[must_use]
    pub fn program() -> Program {
        let idx = Expr::var("idx");
        Program::new(
            vec![
                BufferDecl::read("a", 0, DataType::U32),
                BufferDecl::read("b", 1, DataType::U32),
                BufferDecl::output("out", 2, DataType::U32),
            ],
            WORKGROUP_SIZE,
            vec![
                Node::let_bind("idx", Expr::gid_x()),
                Node::if_then(
                    Expr::lt(idx.clone(), Expr::buf_len("out")),
                    vec![
                        Node::let_bind("x", Expr::load("a", idx.clone())),
                        Node::let_bind("y", Expr::load("b", idx.clone())),
                        Node::loop_for(
                            "i",
                            Expr::u32(0),
                            Expr::u32(64),
                            vec![Node::if_then(
                                Expr::ne(Expr::var("y"), Expr::u32(0)),
                                vec![
                                    Node::let_bind("t", Expr::var("y")),
                                    Node::assign(
                                        "y",
                                        Expr::rem(Expr::var("x"), Expr::var("y")),
                                    ),
                                    Node::assign("x", Expr::var("t")),
                                ],
                            )],
                        ),
                        Node::store("out", idx, Expr::var("x")),
                    ],
                ),
            ],
        )
    }
}
```

The loop is bounded to 64 iterations. That is sufficient for all 32-bit inputs; the worst-case Euclidean steps on `u32` is 48 for consecutive Fibonacci numbers.

## Step 4: Write cpu_fn

The CPU reference is the ground truth. It lives in the conformance crate, not in `core`. Create `conform/src/specs/primitive/math/gcd.rs` and add the oracle:

```rust
fn cpu(input: &[u8]) -> Vec<u8> {
    if input.len() < 8 {
        return vec![0; 4];
    }
    let mut a = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    let mut b = u32::from_le_bytes([input[4], input[5], input[6], input[7]]);
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a.to_le_bytes().to_vec()
}
```

Every byte matters. The GPU must produce identical output for every input.

## Step 5: Write wgsl_fn

In the same conform spec file, add the hand-written WGSL that mirrors `cpu_fn` byte-for-byte:

```rust
fn wgsl() -> String {
    r#"fn vyre_op(index: u32, input_len: u32) -> u32 {
    var x = input.data[0u];
    var y = input.data[1u];
    for (var i = 0u; i < 64u; i = i + 1u) {
        if (y != 0u) {
            let t = y;
            y = x % y;
            x = t;
        }
    }
    return x;
}"#
    .to_string()
}
```

This WGSL is what the conformance suite uses for byte-exact comparison against the lowered output of `Gcd::program()`.

## Step 6: Declare algebraic laws

In `core/src/ops/primitive/math/gcd.rs`, keep the `LAWS` array:

```rust
const LAWS: &[AlgebraicLaw] = &[
    AlgebraicLaw::Commutative,
    AlgebraicLaw::Associative,
    AlgebraicLaw::Identity { element: 0 },
    AlgebraicLaw::Idempotent,
];
```

In `conform/src/specs/primitive/math/gcd.rs`, wire them into the spec builder:

```rust
pub fn vyre_op() -> OpSpec {
    let id = "primitive.math.gcd";
    crate::specs::primitive::make_spec(id, crate::specs::primitive::binary_u32_sig(), cpu, wgsl)
        .category(crate::specs::primitive::category_a_self(id))
        .laws(vec![
            crate::specs::primitive::AlgebraicLaw::Commutative,
            crate::specs::primitive::AlgebraicLaw::Associative,
            crate::specs::primitive::AlgebraicLaw::Identity { element: 0 },
            crate::specs::primitive::AlgebraicLaw::Idempotent,
        ])
        .strictness(crate::Strictness::Strict)
        .version(1)
        .equivalence_classes(vec![EquivalenceClass::universal("all u32 pairs")])
        .boundary_values(crate::specs::primitive::binary_common_boundaries())
        .build()
        .expect("registry invariant violated")
}

/// Compatibility alias for older tests and callers.
pub fn spec() -> OpSpec {
    vyre_op()
}
```

## Step 7: Add test vectors

Still in the conform spec file, add golden samples, KAT vectors, and adversarial inputs:

```rust
use crate::specs::primitive::EquivalenceClass;
use crate::OpSpec;
use crate::verify::golden_samples::GoldenSample;

pub const VYRE_OP_METADATA: vyre_spec::OpMetadata = vyre_spec::OpMetadata {
    id: "primitive.math.gcd",
    layer: vyre_spec::Layer::L1,
    category: vyre_spec::MetadataCategory::Intrinsic,
    version: 1,
    description: "primitive math gcd",
    signature: "(U32, U32) -> U32",
    strictness: "strict",
    archetype_signature: "(U32, U32) -> U32",
};

pub const GOLDEN: &[GoldenSample] = &[
    GoldenSample {
        op_id: "primitive.math.gcd",
        input: &[0x30, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00],
        expected: &[0x06, 0x00, 0x00, 0x00],
        reason: "gcd(48, 18) = 6",
    },
];

pub const KAT: &[vyre_spec::KatVector] = &[
    vyre_spec::KatVector {
        input: &[0x30, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00],
        expected: &[0x06, 0x00, 0x00, 0x00],
        source: "gcd(48, 18) = 6",
    },
    vyre_spec::KatVector {
        input: &[0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00],
        expected: &[0x05, 0x00, 0x00, 0x00],
        source: "gcd(0, 5) = 5 (identity)",
    },
    vyre_spec::KatVector {
        input: &[0x11, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00],
        expected: &[0x01, 0x00, 0x00, 0x00],
        source: "gcd(17, 13) = 1 (coprime)",
    },
    vyre_spec::KatVector {
        input: &[0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00],
        expected: &[0x01, 0x00, 0x00, 0x00],
        source: "gcd(u32::MAX, 1) = 1",
    },
];

pub const ADVERSARIAL: &[vyre_spec::AdversarialInput] = &[
    vyre_spec::AdversarialInput {
        input: &[],
        reason: "empty input exercises validation and boundary handling",
    },
];

#[cfg(test)]
mod proptests {
    #[test]
    fn coverage_artifacts_are_registered() {
        assert!(!super::KAT.is_empty());
        assert!(!super::ADVERSARIAL.is_empty());
    }
}
```

## Step 8: Verify

Regenerate the conform discovery manifest so the suite sees your new file:

```bash
cd conform/codegen && cargo run --offline -- regenerate
```

Now run the conformance tests:

```bash
cargo test -p vyre-conform --lib
```

On a clean pass you will see output similar to:

```
running 3 tests
test primitive::math::gcd::proptests::coverage_artifacts_are_registered ... ok
test golden_samples_cpu_reference ... ok
test registry_consistency ... ok
```

If something fails, the output is actionable. For example, a law failure looks like:

```
FAIL primitive.math.gcd
  generator: Commutativity
  input: (12345, 67890)
  gpu: [0x03, 0x00, 0x00, 0x00]
  cpu: [0x09, 0x00, 0x00, 0x00]
  message: law violation or byte mismatch
```

Fix the `cpu_fn` or the IR `program()` until the bytes match exactly.

## Common gotchas

- **Stubbed cpu_fn.** A `todo!()` or `panic!()` in the CPU reference will crash the conformance suite. Implement the real algorithm.
- **Wrong byte order.** vyre uses little-endian for all scalar types. Always use `u32::from_le_bytes` and `to_le_bytes`.
- **Over-claiming laws.** If you declare `Associative` but `gcd(a, gcd(b, c))` does not equal `gcd(gcd(a, b), c)` for your implementation, the suite will catch it. Only declare laws you have verified.
- **Forgetting the empty-input case.** Every binary op must return `vec![0; 4]` when `input.len() < 8`. The conformance suite sends empty inputs to verify this guard clause.

## What NOT to do

- **Do not edit `mod.rs` files.** `automod` discovers ops in `core`; the conform codegen discovers specs in `conform`. Manual `mod` declarations are legacy.
- **Do not edit central registry lists by hand.** Run `conform/codegen` instead.
- **Do not use `panic!`, `todo!`, or `unimplemented!`.** At internet scale, a panicking op is a denial-of-service vector. Return defined outputs for all inputs.
- **Do not write the conform spec without the core op, or vice versa.** They are a matched pair. The `conform_ids_match_vyre_ids` test enforces this.
