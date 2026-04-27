# Lowering Contract

This contract applies to every target lowering. A backend may lower to WGSL,
SPIR-V, PTX, MSL, CPU code, or another representation, but the obligations are
the same.

## Valid Program Acceptance

For every valid `ir::Program` in the backend's claimed spec surface, lowering
must either produce target code that compiles for the target or return an
explicit unsupported-target error. It must not produce code that is known to be
syntactically invalid, relies on undefined target behavior, or depends on
unlisted host-side resources.

If a backend claims full support for a spec version, every valid program in that
spec version must lower and compile.

## Byte-Identical Execution

Executing lowered code must produce output bytes identical to the CPU reference
for every valid input. This includes all bytes in declared output buffers and
any other observable buffers mutated through `ReadWrite` access.

"Identical" means exact byte equality. Differences in padding, boolean
encoding, integer overflow, atomic ordering, or out-of-bounds handling are
conformance failures unless the ground truth explicitly permits them.

## Complete Node Coverage

A lowering must handle every statement node variant in its claimed spec level:

- `Let`
- `Assign`
- `Store`
- `If`
- `Loop`
- `Return`
- `Block`
- `Barrier`

Unsupported node variants must produce an error that names the variant and the
fix, such as implementing the lowering or reducing the claimed conformance
surface. A lowering must never skip a node to keep code generation moving.

## Complete Expression Coverage

A lowering must handle every expression variant in its claimed spec level:

- `LitU32`
- `LitI32`
- `LitBool`
- `Var`
- `Load`
- `BufLen`
- `InvocationId`
- `WorkgroupId`
- `LocalId`
- `BinOp`
- `UnOp`
- `Call`
- `Select`
- `Cast`
- `Atomic`

Unsupported expression variants must produce an actionable error. Returning a
fake literal, defaulting to zero, or erasing an expression is invalid because it
creates silent data corruption.

## Unknown Variants

IR enums are non-exhaustive. A lowering compiled against an older crate may see
a newer variant through serialized IR or registry boundaries. Unknown variants
must be rejected explicitly. They must not be treated as no-ops, defaults, or
target intrinsics.

Recommended error format:

```text
lowering <target>: unsupported IR variant `<variant>`. Fix: implement this variant or do not claim support for spec <version>.
```

## Target Code Requirements

Generated target code must:

- Declare all buffers required by the program with the correct access modes.
- Use the program's workgroup size exactly.
- Preserve lexical scoping and no-shadowing assumptions.
- Preserve bounded loop ranges with inclusive `from` and exclusive `to`.
- Preserve `Select` eager branch evaluation.
- Preserve `Atomic` return-before semantics.
- Emit both storage and workgroup synchronization for `Barrier`.
- Use deterministic integer semantics for all binary and unary operations.

If the target lacks a native feature, the lowering may emulate it only when the
emulation is byte-identical and concurrency-correct. Non-atomic emulation of an
atomic operation is not allowed.

## Conformance

A lowering is acceptable only when it passes the conformance suite for the
claimed target and spec surface. Passing compilation alone is insufficient.
Backend authors must compare lowered execution against the CPU reference across
parity cases, algebraic laws, boundary values, adversarial inputs, and engine
invariants where applicable.
