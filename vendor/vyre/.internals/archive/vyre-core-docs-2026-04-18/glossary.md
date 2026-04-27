# Glossary

## Archetype

A structural test pattern defined by the `Archetype` trait; implementations live
in `vyre-conform/generate/archetypes/`. Archetypes enumerate input shapes
(identity, overflow, power-of-two boundary, and so on) that every conformant op
must exercise. See [Archetypes](testing/archetypes.md).

## Backend

A thing that executes vyre IR programs by implementing the `VyreBackend` trait.
A conformant backend produces byte-identical output to the CPU reference for
every registered op, law, and archetype. See [certify](certify.md).

## Black-box invariant

The rule that each layer is a sealed abstraction for the layer above: op
authors need not know lowering details, and consumers need not know GPU
dispatch. Breaking this with runtime dispatch, fallbacks, or leaked internals
is a Category B violation. See [Architecture](../../ARCHITECTURE.md).

## Build scan

`vyre-build-scan`, the filesystem-as-registry scanner that discovers trait
implementations at build time. It replaces hand-edited central registries by
generating static tables from per-file `REGISTERED` constants. See
[Zero-Conflict Architecture](zero-conflict.md).

## Category A

Compositional operation that inlines completely at lowering time and vanishes
at shader emission. The generated GPU code is identical to what a human would
write by hand; the abstraction is zero-overhead. See [Op Categories](ir/categories.md).

## Category B

Forbidden pattern: any runtime abstraction cost such as virtual dispatch,
interpreter loops, JIT, boxing, or dynamic polymorphism. Banned by the conform
suite because it breaks zero-cost composition. See [Op Categories](ir/categories.md).

## Category C

Hardware intrinsic operation that maps 1:1 to a specific hardware instruction.
Each Category C op declares per-backend availability; unsupported backends
return `UnsupportedByBackend` rather than falling back to slow software. See
[Op Categories](ir/categories.md).

## certify()

The single public entry point of `vyre-conform`: `certify(backend)` returns
`Ok(Certificate)` if every gate passes, or `Err(Violation)` with a concrete
counterexample and actionable `Fix:` hint on the first failure. See
[certify](certify.md).

## Conformance certificate

Durable proof that a backend is correct at a specific point in time. It
records the backend identity, registry hash, per-op verdicts, coverage
metrics, and the highest verification track achieved. See [Certificates](certificates.md).

## Counterexample

A specific `(input, expected, observed)` tuple that proves a violation.
Every `Err(Violation)` from `certify()` carries at least one concrete
counterexample, often with a byte-level diff. See [certify](certify.md).

## DAG invariant

The rule that imports in `vyre-conform` flow down only, producing a directed
acyclic graph with zero cycles. Any import cycle is a failed invariant and
causes CI to reject the PR. See [Architecture](../../ARCHITECTURE.md).

## EnforceGate

Trait for a single enforcement check in the conform pipeline. A gate returns
an empty `Vec` on pass or one or more `Finding` values on failure. See
[Contracts](contracts.md).

## Finding

Structured violation emitted by an `EnforceGate` or the conform pipeline,
always carrying a `Fix:` hint that tells the author exactly what to change.
Presence of any finding means FAIL. See [Contracts](contracts.md).

## Frozen contract

A trait signature that never changes post-1.0; new methods may be added only
with default implementations. The six frozen traits (`VyreBackend`, `Finding`,
`EnforceGate`, `Oracle`, `Archetype`, `MutationClass`) form the 5-year
extensibility contract. See [Contracts](contracts.md).

## IR

Intermediate representation: the portable, target-independent program form that
frontends emit and backends lower. vyre IR is the contract that allows GPU
compute workloads to be written once and executed by independent backends. See
[IR Overview](ir/overview.md).

## Law

Short for `AlgebraicLaw`: a mathematical property an operation must satisfy,
such as commutativity, associativity, identity, or self-inverse. Laws are
verified exhaustively on `u8` and witnessed on large `u32` samples. See
[Oracles](testing/oracles.md).

## MutationClass

Trait for an adversarial mutation category in the mutation gate. Each class
produces source-code rewrites (operator swaps, branch deletions, constant
changes) that the test suite must kill. See [Contracts](contracts.md).

## OpSpec

Declarative operation specification that defines an op's identity, category,
signature, laws, boundary values, and lowering targets. It is both
documentation and the test oracle. See [certify](certify.md).

## Oracle

Independent source of expected output for a test. The oracle hierarchy ranges
from strongest (algebraic law) to weakest (property); every test must use the
strongest applicable oracle. See [Oracles](testing/oracles.md).

## Parity

Byte-for-byte equality between a backend's output and the CPU reference output
for the same program and input. Parity is the first conformance level and the
baseline requirement for every backend. See [certify](certify.md).

## Parallel-native

An architecture where N contributors can add N leaf files with zero merge
conflicts, zero `mod.rs` edits, and zero central registry updates. vyre
achieves this through one-item-per-file, max-five-entries-per-directory,
no `mod.rs`, frozen `lib.rs`, and distributed slices. See
[Zero-Conflict Architecture](zero-conflict.md).

## Program

A complete, self-contained GPU compute dispatch expressed in vyre IR. It
contains buffer declarations, a three-dimensional workgroup size, and an entry
body of statement nodes executed by each invocation. See [IR Program](ir/program.md).

## REGISTERED

The convention that every discoverable leaf item in a responsibility
directory exports `pub const REGISTERED: MyType = MyType;`.
`vyre-build-scan` collects these constants to generate static registries
without central lists. See [Contributing](contributing.md).

## Tier A config

Operational configuration: CLI flags, TOML defaults, and binary settings that
control how vyre runs. Tier A lives in `vyre-config` and the application
binary. See [`rules/README.md`](../../rules/README.md).

## Tier B config

Community knowledge configuration: detection rules, fingerprints, and
heuristics contributed as plain `.toml` files under `rules/`. Loaded at
runtime without recompiling Rust. See [`rules/README.md`](../../rules/README.md).

## VyreBackend

The frozen trait that every execution backend must implement. It has one
required method, `dispatch`, which accepts an `ir::Program` and input buffers
and returns output buffers or an actionable `BackendError`. See
[Contracts](contracts.md).

## WGSL

WebGPU Shading Language, vyre's reference lowering target. Every op provides
a WGSL kernel; backends targeting SPIR-V, PTX, or MSL must produce
byte-identical results to the WGSL path. See [Lower — WGSL](lower/wgsl.md).

## Zero-conflict architecture

The five structural rules that make parallel contribution trivial: one
top-level item per file, max five entries per directory, no `mod.rs`,
frozen `lib.rs`, and no central enum or registry. See
[Zero-Conflict Architecture](zero-conflict.md).
