# The vyre Book

## Getting Started

<!-- Start here. Five minutes from zero to a working vyre program. -->

- [Getting Started](getting-started.md) — install, build, lower, dispatch, verify
- [Adding Your First Op](tutorial-new-op.md) — create a new operation from scratch
- [Benchmarks](benchmarks.md) — primitive CPU/GPU ns-per-element and crossover table
- [Contributing](contributing.md) — the trust model, what you can/cannot do, the review process
- [Trust Model](trust-model.md) — who is trusted with what, attack prevention, conformance levels
- [Parallel Contribution](parallel-contribution.md) — how 100 contributors work without conflict
- [Clippy Allow Audit](clippy-allow-audit.md) — every crate-root allow with its justification

## Part I — Why vyre Exists

<!-- Part I explains why this matters and what principles guide every decision. -->

- [Why vyre](why-vyre.md) — the first-principles argument
- [Vision](vision.md) — the abstraction thesis and why GPU compute has failed to generalize
- [Universality](universality.md) — every compute workload is eventually absorbable
- [Stability](stability.md) — what is published is permanent
- [Extensibility](extensibility.md) — how vyre grows without breaking what exists
- [Zero-Conflict Architecture](zero-conflict.md) — how vyre scales to 100 parallel contributors
- [vyre and vyre-conform](vyre-and-conform.md) — the split between substrate and prover

## Part 1.5 — Contracts

<!-- The frozen traits that govern extensibility. -->

- [The 6 Frozen Traits](contracts.md) — extensibility contracts

## Part II — The Language

<!-- The intermediate representation is the constitution. Every frontend,
backend, optimizer, and conformance tool is judged against it.
Part II is the complete specification of the IR — what programs look
like, what they mean, and what guarantees they carry. -->

- [IR Overview](ir/overview.md) — the contract between frontends and backends
- [Types](ir/types.md) — DataType, BufferAccess, Convention, OpSignature, Tensor, Float semantics
- [Expressions](ir/expressions.md) — every value-producing node
- [Statement Nodes](ir/nodes.md) — Let, Assign, Store, If, Loop, Return, Block, Barrier
- [Programs](ir/program.md) — BufferDecl, workgroup_size, entry point body
- [Binary Operations](ir/binary-ops.md) — arithmetic, bitwise, comparison, logical
- [Unary Operations](ir/unary-ops.md) — Negate, BitNot, LogicalNot, Popcount, Clz, Ctz, ReverseBits
- [Cast Semantics](ir/casts.md) — the complete cast table
- [Atomic Operations](ir/atomics.md) — Add, Or, And, Xor, Min, Max, Exchange, CompareExchange
- [Memory Model](ir/memory-model.md) — storage, workgroup, visibility, data races
- [Execution Model](ir/execution-model.md) — invocations, barriers, determinism
- [Invocation Model](ir/invocation-model.md) — dispatch shape, identity expressions, excess invocations
- [Out-of-Bounds Behavior](ir/out-of-bounds.md) — loads return zero, stores are no-ops
- [Op Categories](ir/categories.md) — Category A (compositional), Category C (intrinsic), Category B (forbidden)
- [Composition](ir/composition.md) — Call semantics, inline expansion, zero-cost property
- [Error Model](ir/errors.md) — valid inputs, resource limits, no panics
- [Validation](ir/validation.md) — V001 through V013, actionable error messages
- [Wire Format](ir/wire-format.md) — lossless binary serialization of `ir::Program`
- [Calling Conventions](conventions.md) — V1 (standard), V2 (with lookup table)

## Part III — The Standard Library

<!-- Operations are the reusable layer above the IR. An operation is a
named, versioned producer of a complete `ir::Program`. Part III
documents every operation in the standard library — what it computes,
why it exists, how it composes, and how it is tested. -->

- [Operations README](ops/README.md) — section index

### The Op Contract
- [OpSpec](ops/trait.md) — the declarative operation struct, Category A/C, algebraic laws, vyre-spec crate
- [Operations Overview](ops/overview.md) — layers, op catalog, how to read an op spec

### Layer 1 — Primitives
- [Primitive Overview](ops/primitive/overview.md) — the Layer 1 primitive operations
- [Bitwise](ops/primitive/bitwise.md) — xor, and, or, not, shl, shr, rotl, rotr, popcount, clz, ctz, reverse_bits, extract_bits, insert_bits
- [Arithmetic](ops/primitive/arithmetic.md) — add, sub, mul, div, mod, min, max, clamp, abs, negate
- [Comparison](ops/primitive/comparison.md) — eq, ne, lt, gt, le, ge, select, logical_not

### Layer 2 — Compound Operations
- [Decode](ops/decode/overview.md) — base64, hex, URL, Unicode escape decoding
- [Hash](ops/hash/overview.md) — FNV-1a, rolling hash, CRC32, entropy
- [String](ops/string/overview.md) — tokenization, search, normalization
- [Graph](ops/graph/overview.md) — BFS, reachability, CSR representation
- [Match](ops/match_ops/overview.md) — DFA scan, proximity, scope
- [Compression](ops/compression/overview.md) — LZ4 block decompression, Zstd raw/RLE
- [Collection](ops/collection/overview.md) — sort, filter, reduce, scan, scatter, gather

## Part IV — The Compiler

<!-- Lowering translates the IR into executable code. It is a compiler
step, not a semantic layer. Part IV specifies the obligations every
lowering must meet and documents the reference WGSL lowering. -->

- [Lowering Overview](lower/overview.md) — the pipeline from Program to dispatch
- [Lowering Contract](lower/contract.md) — obligations for every target
- [WGSL Lowering](lower/wgsl.md) — the reference backend: type mapping, node mapping, expression mapping

## Part V — The Engines

<!-- Engines are complete compute pipelines. They compose primitives and
compound ops into self-contained workflows with resource management,
shader specialization, and deterministic readback. Part V documents
the four engines that power vyre's security scanning infrastructure. -->

- [Engine Overview](engine/overview.md) — what engines are and how they relate to ops
- [DFA Engine](engine/dfa.md) — pattern matching over bytes
- [Eval Engine](engine/eval.md) — rule condition evaluation
- [Scatter Engine](engine/scatter.md) — match-to-rule distribution
- [Dataflow Engine](engine/dataflow.md) — graph fixpoint iteration

## Part V.5 — The Standard Library (`vyre-std`)

<!-- The Layer 2 compositional helpers: the full GPU DFA assembly pipeline
plus arithmetic helpers built from Layer 1 primitives. -->

- [vyre-std Overview](std/overview.md) — what ships, composition discipline, rulefire split
- [GPU DFA Assembly Pipeline](std/dfa-assembly.md) — regex_to_nfa → nfa_to_dfa → dfa_minimize → dfa_pack → dfa_assemble, plus aho_corasick_build and the compilation cache

## Part VI — The Wire Format

<!-- The IR wire format (`ir/wire.rs`) is the canonical binary serialization
of `ir::Program`. It is lossless: round-tripping a Program through
serialization and deserialization produces the identical Program.

The legacy bytecode format (102 stack-machine opcodes) has been removed
from the vyre source. Frontends that previously emitted bytecode now
emit IR directly. The bytecode opcode table is preserved in the spec
documentation for historical reference and backward compatibility with
archived rule sets.

See [IR Wire Format](ir/wire-format.md) for the canonical specification. -->

## Part VII — The Proof System

<!-- The test suite is the specification enforcement mechanism. It is not
a regression catcher — it is a conformance enforcer. Part VII is a
complete book within a book. -->

### Introduction
- [Testing README](testing/README.md) — section index and reading order
- [Introduction](testing/introduction.md) — the promise and what the suite must prove
- [A Tour of What Can Go Wrong](testing/a-tour-of-what-can-go-wrong.md) — seven failure modes
- [The Promises](testing/the-promises.md) — fifteen invariants the suite proves
- [Vocabulary](testing/vocabulary.md) — precise definitions for every testing term

### The Core Concepts
- [Oracles](testing/oracles.md) — the hierarchy of independent truth sources
- [Archetypes](testing/archetypes.md) — the shapes of bad inputs
- [Mutations](testing/mutations.md) — grading the suite against deliberate defects
- [Architecture](testing/architecture.md) — the test directory layout and decision tree

### Test Categories
- [Unit](testing/categories/unit.md)
- [Integration](testing/categories/integration.md)
- [Property](testing/categories/property.md)
- [Adversarial](testing/categories/adversarial.md)
- [Regression](testing/categories/regression.md)
- [Benchmarks](testing/categories/benchmarks.md)
- [Backend](testing/categories/backend.md)
- [Lowering](testing/categories/lowering.md)
- [Validation](testing/categories/validation.md)
- [Wire Format](testing/categories/wire_format.md)
- [Support](testing/categories/support.md)

### Writing Good Tests
- [Decision Tree](testing/writing/decision-tree.md)
- [Naming](testing/writing/naming.md)
- [Oracles in Practice](testing/writing/oracles-in-practice.md)
- [Support Utilities](testing/writing/support-utilities.md)
- [Templates](testing/writing/templates.md)

### Anti-Patterns
- [Anti-Patterns README](testing/anti-patterns/README.md)
- [The "Doesn't Crash" Trap](testing/anti-patterns/doesnt-crash.md)
- [Hidden Helpers](testing/anti-patterns/hidden-helpers.md)
- [Kitchen-Sink Tests](testing/anti-patterns/kitchen-sink.md)
- [Seedless Proptest](testing/anti-patterns/seedless-proptest.md)
- [Tautology Tests](testing/anti-patterns/tautology.md)
- [Other Test Smells](testing/anti-patterns/test-smells.md)

### Discipline
- [Daily Audit](testing/discipline/daily-audit.md)
- [Flakiness](testing/discipline/flakiness.md)
- [Regression Rule](testing/discipline/regression-rule.md)
- [Review Checklist](testing/discipline/review-checklist.md)
- [Seed Discipline](testing/discipline/seed-discipline.md)
- [Suite Performance](testing/discipline/suite-performance.md)

### Running the Suite
- [Local Workflow](testing/running/local-workflow.md)
- [Continuous Integration](testing/running/continuous-integration.md)
- [Debugging Failures](testing/running/debugging-failures.md)
- [Debugging Flakes](testing/running/debugging-flakes.md)

### Advanced
- [Property Generators](testing/advanced/property-generators.md)
- [Mutation at Scale](testing/advanced/mutation-at-scale.md)
- [Differential Fuzzing](testing/advanced/differential-fuzzing.md)
- [Concurrency and Ordering](testing/advanced/concurrency-and-ordering.md)
- [Cross-Backend](testing/advanced/cross-backend.md)
- [Floating Point](testing/advanced/floating-point.md)

### Meta
- [Testing as Design](testing/meta/testing-as-design.md)
- [Testing the Testers](testing/meta/testing-the-testers.md)
- [The Long Game](testing/meta/the-long-game.md)
- [Post-Mortem Discipline](testing/meta/post-mortem-discipline.md)

### vyre-conform Specific
- [Two-Tier Suite](testing/vyre-conform/two-tier-suite.md)
- [Contribution Flow](testing/vyre-conform/contribution-flow.md)
- [Generator Supersession](testing/vyre-conform/generator-supersession.md)
- [Never Replaced](testing/vyre-conform/never-replaced.md)

### Worked Example
- [01 — Intent](testing/worked-example/01-intent.md)
- [02 — First Test](testing/worked-example/02-first-test.md)
- [03 — Building Out](testing/worked-example/03-building-out.md)
- [04 — Catching a Bug](testing/worked-example/04-catching-a-bug.md)
- [05 — Mutation Gate](testing/worked-example/05-mutation-gate.md)

### Testing Appendices
- [A — Glossary](testing/appendices/A-glossary.md)
- [B — Invariants Catalog](testing/appendices/B-invariants-catalog.md)
- [C — Mutation Operators](testing/appendices/C-mutation-operators.md)
- [D — Archetypes](testing/appendices/D-archetypes.md)
- [E — Command Reference](testing/appendices/E-command-reference.md)
- [F — Review Checklist](testing/appendices/F-review-checklist.md)
- [G — Examples Index](testing/appendices/G-examples-index.md)
- [H — Change History](testing/appendices/H-change-history.md)

## Part VIII — Certificates

- [Certificates](certificates.md) — the durable proof document, tracks, registry hash, verification

## Part IX — Certification

- [The Binary Verdict API](certify.md) — the binary verdict API

## Part X — Competitive Landscape

<!-- Honest comparisons to the other systems you might consider. Each
chapter names where the alternative is stronger and where vyre's
trade-off wins. -->

- [Competitors README](competitors/README.md) — the landscape at a glance
- [vs LLVM](competitors/llvm.md) — general-purpose compiler IR
- [vs MLIR](competitors/mlir.md) — extensible dialect framework
- [vs Cranelift](competitors/cranelift.md) — CPU JIT
- [vs RE2](competitors/re2.md) — regex engine
- [vs Hyperscan](competitors/hyperscan.md) — multi-pattern matcher
- [vs Nuclei](competitors/nuclei.md) — rule-engine DSL

## Appendices

- [Glossary](glossary.md) — every term of art used in the vyre project
