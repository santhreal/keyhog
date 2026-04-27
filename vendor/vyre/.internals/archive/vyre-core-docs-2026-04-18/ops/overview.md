# Operations Overview

The standard operation library is the reusable layer above vyre IR. An operation
is not a shader string and not a runtime callback. It is a named, versioned
producer of a complete `ir::Program` plus metadata that lets validators,
optimizers, lowerings, and conformance tools reason about it.

## OpSpec

Every standard operation is declared as a `const OpSpec`:

```rust
pub const SPEC: OpSpec = OpSpec::composition(
    "primitive.bitwise.xor",
    &[DataType::U32, DataType::U32],
    &[DataType::U32],
    &[Law::Commutative, Law::Deterministic, Law::BoundedOutput],
    Self::program,
);
```

`OpSpec` is a plain data struct, not a trait. No trait objects, no vtables,
no dynamic dispatch. Every operation is a compile-time constant. The compiler
sees through it completely. See [OpSpec](trait.md) for the full specification
of the struct, its fields, the `vyre-spec` crate, and the algebraic law system.

## Layers

Layer 1 operations are primitives. They are the atoms: bitwise operations,
arithmetic operations, comparisons, unary bit operations, and other small
deterministic functions. They should be specified with exhaustive small-domain
coverage and algebraic laws where applicable.

Layer 2 operations are compounds. They are built from Layer 1 operations using
IR composition and `Call` expressions. Examples include decode, hash, string,
collection, graph, and match operations.

Layer 3 operations are engines. They are complete compute pipelines that
compose lower layers into a self-contained workflow such as DFA scanning,
parallel evaluation, scatter, prefix computation, or dataflow iteration.

No layer may depend upward. L1 does not know about L2. L2 does not know about
engines. Engines may orchestrate lower-layer programs but do not alter their
semantics.

## How To Read An Op Spec

An op spec must answer these questions:

- What is the op identifier?
- What op version is being described?
- What input and output `DataType` values form the signature?
- Which calling convention and buffers are required?
- Which lower-layer ops are dependencies?
- What exact `ir::Program` does `program()` return?
- What CPU reference behavior defines conformance?
- Which laws, equivalence classes, and boundary values prove correctness?

The identifier and version select the behavior. The signature describes the
value contract. The program describes the executable IR. The conformance spec
describes how independent implementations prove they match it.

## What program() Must Return

`program()` must return a complete, valid `ir::Program`. The returned program
must declare all buffers it references, choose a valid workgroup size, and
contain an entry body that implements the op's documented behavior for every
valid input.

The program must not rely on hidden backend state, implicit host bindings,
global mutable registries, stringly shader snippets, or undocumented runtime
conventions. If the op requires another op, it must declare that dependency and
represent the composition through IR.

The same returned program is the input to optimization, lowering,
serialization, CPU reference execution, and conformance. Any target-specific
specialization must be a semantics-preserving optimization of that program, not
a different definition of the operation.

## Layer 1 — Primitive Operations

Documented in the `primitive/` subdirectory:

- [Arithmetic](primitive/arithmetic.md) — add, sub, mul, div, mod, min, max, clamp, abs, negate
- [Bitwise](primitive/bitwise.md) — xor, and, or, not, shl, shr, rotl, rotr, popcount, clz, ctz, reverse_bits, extract_bits, insert_bits
- [Comparison](primitive/comparison.md) — eq, ne, lt, gt, le, ge, select, logical_not
- [Overview](primitive/overview.md) — summary table of all 32 Layer 1 primitives

All Layer 1 ops operate on `u32` scalars (or packed parameter words) and are
fully specified with algebraic laws, boundary values, and exhaustive small-domain
conformance coverage.

## Layer 2 — Compound Operations

Documented in domain-specific subdirectories:

- [Decode](decode/overview.md) — base64, hex, URL percent-encoding, Unicode escape decoding. Currently legacy WGSL-only; migration to IR-first in progress.
- [Hash](hash/overview.md) — FNV-1a, rolling hash, CRC32, entropy measurement. Planned; module is currently empty.
- [String](string/overview.md) — JavaScript tokenization. Currently legacy WGSL-only.
- [Graph](graph/overview.md) — BFS, multi-source reachability, CSR graph representation. Mix of legacy WGSL and CPU reference.
- [Match](match_ops/overview.md) — DFA scan operation. Currently legacy WGSL-only.
- [Compression](compression/overview.md) — LZ4 block decompression, Zstd raw/RLE block handling. Currently legacy WGSL-only.
- [Collection](collection/overview.md) — Sort, filter, reduce, scan, scatter, gather. Planned; module is currently empty.

Layer 2 ops compose Layer 1 primitives into domain-specific functions. They
operate on variable-length byte buffers (`Bytes`) or complex multi-buffer
layouts. Most are currently implemented as legacy WGSL shaders and are being
migrated to the IR-first architecture.

## Layer 3 — Engines

Documented in the [engine/](../engine/overview.md) section:

- [DFA](../engine/dfa.md) — pattern matching over bytes with deterministic finite automata
- [Eval](../engine/eval.md) — rule condition evaluation (being rebuilt on IR-first architecture)
- [Scatter](../engine/scatter.md) — match-to-rule bitmap distribution
- [Dataflow](../engine/dataflow.md) — graph fixpoint and reachability analysis

Engines orchestrate lower-layer ops into complete workflows with resource
management, shader specialization, and deterministic readback.

## OpSpec Migration Status

All operations now use the `OpSpec` declarative struct. The old `trait Op`,
`emit_wgsl()`, `emit_ir()`, and `OpIR` have been deleted.

| Domain | Ops | `OpSpec` | `program()` | Status |
|--------|-----|----------|-------------|--------|
| Primitive | 10 impl / 32 spec | Yes | Yes | 10 implemented, 22 remaining (mechanical — each is one `const OpSpec`) |
| Decode | 4 ops | Yes | Yes | Migrated to IR compositions |
| Hash | 0 ops | — | — | Module empty; planned as IR-first from day one |
| String | 1 op | Partial | Partial | Tokenize being rebuilt |
| Graph | 2 ops | Partial | Partial | CSR + reachability, BFS being rebuilt |
| Match | 1 op | Partial | Partial | DFA scan being rebuilt |
| Compression | 2 ops | Partial | Partial | LZ4/Zstd being rebuilt |
| Collection | 0 ops | — | — | Module empty; planned as IR-first from day one |

The legacy `trait Op`, `OpIR`, `emit_wgsl()`, and `emit_ir()` no longer exist
in the codebase. The bytecode module and the eval shader VM have been deleted.
All operations express themselves through `OpSpec` with `Compose::Composition`
(Category A) or `Compose::Intrinsic` (Category C).
