# MLIR

MLIR is a compiler infrastructure for building many intermediate
representations under one framework. Its central idea is dialect composition:
each domain can define its own operations, attributes, types, parsing,
verification, and lowering paths while still using shared pass infrastructure.
That makes MLIR well suited for staged lowering pipelines such as tensor algebra
to loops, loops to affine forms, affine forms to GPU dialects, and then to LLVM
or target-specific code.

vyre makes the opposite tradeoff. It has one IR and one semantic model. Standard
domains are libraries of `Program` compositions and intrinsic declarations, not
new dialects with independent semantics.

## Where MLIR is stronger

MLIR is excellent when a project needs several abstraction levels to coexist.
A machine-learning compiler can preserve high-level tensor intent, lower it to
structured control flow, tile it, map it onto GPU constructs, and still keep
each stage inspectable. Dialects allow teams to encode domain-specific
properties without forcing every concept into one universal instruction set.

MLIR also gives implementers a mature framework for passes, rewrites,
canonicalization patterns, parsing, printing, and verification. Projects with
complex lowering stacks can share that infrastructure instead of inventing a
custom compiler framework.

## Where vyre differs

vyre rejects dialect proliferation. A Layer 2 rule or pattern domain does not
define a new semantic universe. It composes Layer 1 primitives into a normal
`ir::Program`. The validator and conformance suite remain the authority for the
same IR regardless of whether the program came from a hash operation, a graph
operation, a DFA scan, or a downstream frontend.

This matters for downstream tooling. A stored vyre wire blob does not need a
dialect registry to recover semantics. It decodes into one program type with one
set of validation rules. Tools can round-trip, diff, validate, and lower without
loading product-specific dialect definitions.

MLIR uses per-dialect verifiers as part of its type and operation discipline.
vyre pushes that role into the conformance suite. Conformance is not just a
syntax verifier; it is the executable specification for operation behavior,
laws, edge cases, and backend equivalence. In vyre, the conformance suite plays
the role that dialect-specific invariants often play in MLIR projects.

## The practical boundary

MLIR is a good fit when the product needs many IR levels and owns a compiler
pipeline. vyre is a good fit when the product needs to emit deterministic GPU
compute programs, reuse a standard operation library, serialize those programs
losslessly, and require backend conformance. A future frontend could use MLIR
internally and still lower into vyre IR as the stable GPU compute contract.
