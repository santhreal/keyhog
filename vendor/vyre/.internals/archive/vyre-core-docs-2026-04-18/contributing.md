# Contributing to vyre

vyre is designed for mass contribution — hundreds of contributors
adding operations, tests, and backends simultaneously without
stepping on each other's work. This guide explains how.

## The trust model

**Contributors supply implementations. Maintainers own the oracles,
the laws, and the gate.**

This is not a social convention. It is enforced mechanically by
CODEOWNERS, CI scripts, and the conformance suite.

### What you CAN do

- **Add new operations** under `core/src/ops/`. Each op is one Rust
  file. Drop it in the right category directory and the build scanner
  registers it automatically.
- **Add new test cases** under existing test directories. Tests are
  append-only — you can add, never delete.
- **Add fuzz targets** under `core/fuzz/`.
- **Add documentation** anywhere that is not a maintainer-only path.
- **Add new backends** by implementing the `VyreBackend` trait.
- **Add enforcement gates** under `conform/src/enforce/gates/`.
- **Add oracles** under `conform/src/oracles/`.
- **Add TOML rules** under `conform/rules/`.
- **File issues** for bugs, missing ops, or spec clarifications.

### What you CANNOT do

- **Edit the specification** (`spec/`). The spec defines what
  operations mean. Changing it changes the answer key.
- **Edit CPU reference functions** (`conform/src/specs/primitive/`).
  These are the oracles. If you could edit them, you could make your
  broken implementation "correct."
- **Edit the law checkers** (`conform/src/algebra/`). These verify
  that declared laws actually hold.
- **Edit the enforcement gates** (`conform/src/enforce/`). These
  catch Category B violations, OOB bugs, and structural errors.
- **Edit the mutation catalog** (`conform/src/mutations/`). This
  defines the quality floor.
- **Delete regression tests.** Regression tests are permanent.
  Deleting one means the bug can return.

These paths require `@santhsecurity/core-maintainers` review via
CODEOWNERS.

## How to add an op

Every op is exactly one file. Copy the template, edit the struct,
and run the tests. No directory creation, no `mod.rs` edits, no
registry updates.

```bash
cp core/src/ops/template_op.rs core/src/ops/primitive/bitwise/my_op.rs
```

Edit the file:

```rust
use crate::ir::{Expr, Program};
use crate::ops::{AlgebraicLaw, OpSpec, U32_OUTPUTS, U32_U32_INPUTS};
use crate::ops::primitive;

pub const LAWS: &[AlgebraicLaw] = &[
    AlgebraicLaw::Commutative,
    AlgebraicLaw::Associative,
];

#[derive(Debug, Clone, Copy, Default)]
pub struct MyOp;

impl MyOp {
    pub const SPEC: OpSpec = OpSpec::composition_inlinable(
        "primitive.bitwise.my_op",
        U32_U32_INPUTS,
        U32_OUTPUTS,
        LAWS,
        Self::program,
    );

    #[must_use]
    pub fn program() -> Program {
        primitive::binary_u32_program(Expr::bitwise_xor)
    }
}
```

Validate:

```bash
cargo check -p vyre
cargo test -p vyre-conform -- my_op
```

`explicit_mod_list!` discovers the file at compile time.
`vyre-build-scan` adds it to `ALL_OPS` at build time.
Your PR touches exactly one file.

## How to add an enforcement gate

Create a single file in the gate directory, implement `EnforceGate`,
and export a `REGISTERED` const. `vyre-build-scan` wires it into
`ALL_GATES` automatically.

```bash
# conform/src/enforce/gates/my_gate.rs
```

```rust
use vyre_conform::enforce::{EnforceContext, EnforceGate};
use vyre_conform::spec::{Finding, OpSpec};

pub struct MyGate;

impl EnforceGate for MyGate {
    fn id(&self) -> &'static str {
        "my_gate"
    }

    fn name(&self) -> &'static str {
        "My Gate"
    }

    fn run(&self, _ctx: &EnforceContext<'_>) -> Vec<Box<dyn Finding>> {
        // Return empty when the gate passes.
        Vec::new()
    }
}

pub const REGISTERED: MyGate = MyGate;
```

Validate:

```bash
cargo check -p vyre-conform
cargo test -p vyre-conform -- my_gate
```

Zero other file edits.

## How to add an oracle

Oracles follow the same drop-a-file pattern as gates.

```bash
# conform/src/oracles/my_oracle.rs
```

```rust
use vyre_conform::oracles::{Oracle, Property, Verdict};
use vyre_conform::spec::{OpSpec, OracleKind};

pub struct MyOracle;

impl Oracle for MyOracle {
    fn kind(&self) -> OracleKind {
        OracleKind::PointParity
    }

    fn applicable_to(&self, _op: &OpSpec, _property: &Property) -> bool {
        true
    }

    fn verify(&self, _op: &OpSpec, _input: &[u32], observed: &[u32]) -> Verdict {
        if observed.is_empty() {
            return Verdict::Fail {
                reason: "Empty output. Fix: return at least one u32 word.".into(),
            };
        }
        Verdict::Pass
    }
}

pub const REGISTERED: MyOracle = MyOracle;
```

Validate:

```bash
cargo check -p vyre-conform
cargo test -p vyre-conform -- my_oracle
```

Zero other file edits.

## How to add a backend

Implement the frozen `VyreBackend` trait, pass the conformance suite,
and generate a certificate.

```rust
use vyre::{BackendError, DispatchConfig, Program, VyreBackend};

pub struct MyBackend;

impl VyreBackend for MyBackend {
    fn id(&self) -> &'static str {
        "my_backend"
    }

    fn dispatch(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        // Dispatch logic here.
        // Every error must contain "Fix: ..." guidance.
        todo!("Implement real dispatch or delete the stub.")
    }
}
```

Validate and certify:

```bash
cargo test -p vyre-conform --features gpu
cargo run -p vyre-conform --bin certify
```

Ship the backend only if the certificate is green. A backend without
a valid certificate will be rejected by downstream CI.

## How to add a TOML rule

Community extensions that need no Rust code live in `conform/rules/`.
Copy an example, edit it, and run the suite.

```bash
cp conform/rules/examples/witness.toml conform/rules/my_rule.toml
# Edit the TOML to target your op or declare a new law.
cargo test -p vyre-conform
```

Every `.toml` file in `conform/rules/**/*.toml` is auto-discovered at
startup. If two files conflict, the runner logs a warning and picks
one. See `conform/rules/README.md` for the full schema.

## Code quality rules

These rules come from the Santh Standard (`STANDARD.md`):

- **No `unwrap()` in production code.** Use `?` or return `Result`.
- **No `todo!()` or `unimplemented!()`.** Implement fully or delete.
- **No files over 500 lines.** Split.
- **No commented-out code.** Delete or extract.
- **No inline tests.** Tests live in `tests/`, not `src/`.
- **Every public type has doc comments.**
- **Every error message includes "Fix: ..."** with actionable
  guidance.

## The review process

1. Open a PR against `main`.
2. CI runs `cargo check`, `cargo test`, conformance suite, and
   mutation testing.
3. If your PR touches a maintainer-only path, CODEOWNERS adds
   `@santhsecurity/core-maintainers` as a required reviewer.
4. If CI passes and reviews approve, the PR merges.
5. The append-only script verifies no protected files were deleted.

## The conformance levels

Your op can achieve four conformance levels:

| Level | What it proves | Requirements |
|-------|----------------|--------------|
| L1 | Parity | GPU output matches CPU reference |
| L2 | Algebraic | L1 + all declared laws verified |
| L3 | Composition | L2 + composition theorems hold |
| L4 | Full | L3 + engine invariants I1-I15 |

Most new ops should target L2 on first submission. L3 and L4 are
everned over time as composition tests and engine integration mature.

## Where to get help

- **Issues:** `github.com/santhsecurity/vyre/issues`
- **Discussions:** `github.com/santhsecurity/vyre/discussions`
- **The vyre book:** `core/docs/` — the complete specification
- **The coordination directory:** `coordination/` — architectural
  decisions and cross-agent coordination

## spec.toml reference

Every op's identity lives in `spec.toml`. The schema is versioned
(`schema_version = 1`). Here is a complete example:

```toml
schema_version = 1
id = "primitive.bitwise.xor"
archetype = "binary-bitwise"
display_name = "Bitwise XOR"
summary = "Per-bit exclusive OR of two unsigned integer inputs."
category = "C"
laws = ["Commutative", "Associative", "SelfInverse", "LeftIdentity", "RightIdentity"]
equivalence_classes = ["zero", "max_value", "alternating_bits"]
workgroup_size = [64, 1, 1]
tags = ["bitwise"]

[intrinsic]
wgsl = " ^ "
spirv = "OpBitwiseXor"
cuda = " ^ "
metal = " ^ "

[signature]
inputs = ["U32", "U32"]
output = "U32"
```

### Required fields

| Field | Type | Description |
|---|---|---|
| `schema_version` | integer | Must be `1` |
| `id` | string | Hierarchical dot-separated identifier. ASCII `[a-z0-9._]` only. |
| `archetype` | string | From the locked vocabulary (see below) |
| `category` | string | `"A"` (compositional) or `"C"` (hardware intrinsic) |
| `laws` | array | Declared algebraic laws. Every entry must be a known law name. |
| `signature.inputs` | array | Input data types: `"U32"`, `"I32"`, `"U64"`, `"Bytes"`, etc. |
| `signature.output` | string | Output data type |

### Known archetypes

`binary-bitwise`, `unary-bitwise`, `binary-arithmetic`, `unary-arithmetic`,
`binary-comparison`, `binary-logical`, `unary-logical`, `hash-bytes-to-u32`,
`hash-bytes-to-u64`, `decode-bytes-to-bytes`, `compression-bytes-to-bytes`,
`match-bytes-pattern`, `graph-reachability`, `tokenize-bytes`, `rule-bytes-to-bool`

The archetype determines the minimum law count:
- `binary-bitwise`: at least 2 laws
- `binary-arithmetic`, `unary-bitwise`: at least 1 law
- Others: no minimum (for now)

### Validation rules

The TOML loader rejects:
- Non-ASCII characters in `id` (blocks Unicode homoglyph attacks)
- `id` longer than 128 characters
- `display_name` or `summary` containing `<`, `>`, backticks, `javascript:`,
  `data:`, ANSI escapes, or bidi override characters
- Unknown archetype names
- Unknown law names
- Archetype/signature mismatches (e.g., binary archetype with 1 input)
- Unknown data type names
- `schema_version` other than 1
- Unknown TOML keys (`deny_unknown_fields`)

## Writing WGSL kernels

Every op must have a real WGSL kernel. **No stubs.** `return 0u;` is a
LAW 1 violation — the GPU must produce the correct output, not a
placeholder.

### The op function signature

Your WGSL defines:

```wgsl
fn vyre_op(index: u32, input_len: u32) -> u32 {
    // index = global invocation ID (which output element to compute)
    // input_len = number of input bytes
    // return = the output u32 for this invocation
}
```

The conformance wrapper (`wrap_shader()`) provides:
- `input.data: array<u32>` — read-only input buffer (binding 0)
- `output.data: array<u32>` — read-write output buffer (binding 1)
- `params` — uniform buffer with `input_len` and `output_len` (binding 2)

### Byte extraction pattern

For Bytes-input ops, input bytes are packed into u32 words. Extract
individual bytes with:

```wgsl
let word_idx = byte_index / 4u;
let byte_offset = byte_index % 4u;
let byte_val = (input.data[word_idx] >> (byte_offset * 8u)) & 0xFFu;
```

This is little-endian: byte 0 is in bits 0-7 of word 0.

### Common mistakes

1. **Forgetting the shift mask.** `value << shift` in WGSL wraps at 32.
   If your spec says shift >= 32 returns 0, add the check.

2. **Using signed arithmetic for unsigned ops.** WGSL `i32` and `u32`
   are different types. Use `u32` for unsigned ops.

3. **Byte order confusion.** The input is little-endian. Byte 0 is the
   least significant byte of word 0.

4. **Not handling empty input.** Every op must handle `input_len == 0`
   gracefully. Hash ops should return the initial hash value. Pattern
   ops should return empty output.

5. **Writing a stub.** `return 0u;` will fail every parity test. If
   you can't write the real kernel, don't ship the op.

## Choosing algebraic laws

Use `cargo run -p vyre-conform --bin contribute -- infer <op_id>` to
discover which laws your CPU reference satisfies. The inference engine
tests every applicable law against your function.

### Common law sets by archetype

| Archetype | Typical laws |
|---|---|
| binary-bitwise | Commutative, Associative, Identity, SelfInverse or Idempotent |
| binary-arithmetic | Commutative, Associative, Identity (for add/mul) |
| unary-bitwise | Involution (for not, reverse_bits), Bounded (for popcount, clz, ctz) |
| hash-bytes-to-u32 | Bounded(0, u32::MAX) |
| comparison | Bounded(0, 1) |

### Laws that DON'T hold for boolean-output ops

If your op returns 0 or 1 (like logical_and, eq, lt), these laws
**do not hold** even though they look like they should:

- **Identity** — `f(5, 1) = 1`, not `5`
- **Idempotent** — `f(5, 5) = 1`, not `5`
- **SelfInverse** — `f(5, 5) = 1`, not the declared result element

Boolean ops can declare: Commutative, Associative, Absorbing, Bounded(0, 1).

## The conformance pipeline

When your PR is submitted, the following pipeline runs:

1. **TOML validation** — `spec.toml` is parsed and validated
2. **Build check** — `cargo check -p vyre` passes
3. **Law verification** — every declared law is exhaustively verified
   on u8 (256² cases for binary) plus 1M random u32 witnesses
4. **GPU parity** — WGSL output compared byte-for-byte against CPU
   reference at workgroup sizes 1 and 64
5. **Mutation testing** — each mutation of the WGSL must be killed
   by at least one test
6. **Golden freeze** — the CPU reference output for canonical inputs
   is frozen as the immutable stability canon
7. **Certificate** — a conformance certificate is generated proving
   the op passes at the claimed level
