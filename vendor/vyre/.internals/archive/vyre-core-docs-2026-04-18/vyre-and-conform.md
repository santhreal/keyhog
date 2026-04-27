# vyre and vyre-conform — the implementation and the specification

![vyre architecture](../../docs/architecture.svg)

vyre ships as two crates: `vyre` and `vyre-conform`. They are a pair.
Neither works alone. This document explains what each crate is, why the
split exists, how they depend on each other, and how the workflow uses
them together.

## The two-sentence version

- **`vyre`** is what you *use*. It is the IR, the lowerings, the
  standard library of ops, and the GPU execution pipeline. Downstream
  code depends on `vyre` to compile computations into GPU kernels.
- **`vyre-conform`** is what you *pass*. It is the spec expressed as
  executable Rust, and it is the gate — every change to vyre that
  does not pass vyre-conform cannot be merged.

If you are a user of vyre, you import `vyre`. If you are a contributor
to vyre, you must pass `vyre-conform`. If you are a third-party backend
implementer, you run `vyre-conform` against your backend and either
receive a certificate or a list of failures.

## What vyre contains

vyre is the implementation. Its crate root is
`libs/performance/matching/vyre/`. Its public surface includes:

- **`vyre::ir`** — the IR data model. `Program`, `Expr`, `Node`,
  `BinOp`, `UnOp`, `AtomicOp`, `DataType`, `BufferDecl`, and the
  expression and statement variants that every program is built from.
- **`vyre::validate`** — the validator. Rules V001 through V0NN that
  every `ir::Program` must satisfy before it can be lowered.
- **`vyre::lower`** — the lowerings. WGSL is the reference. Future
  lowerings (CUDA, SPIR-V, MSL, PTX) are added as new modules; each
  one accepts the same valid IR programs and produces equivalent
  observable output.
- **`vyre::engine`** — the GPU dispatch runtime. Device acquisition,
  buffer management, shader cache, dispatch loop.
- **`vyre::primitives`** — the 10 Layer 1 primitive ops (add, and, eq,
  mul, not, or, popcount, shl, sub, xor) exposed as named operations
  with stable identifiers, signatures, and laws.
- **`vyre::ops`** — the Layer 2+ standard library of compositions.
  String, graph, decode, hash, distance, regex, and match ops, each
  expressed as a Category A composition over Layer 1 primitives.
- **`vyre::ir::wire`** — the IR wire format. `Program::to_wire()` and
  `Program::from_wire()` for lossless binary serialization.

vyre has **no CPU runtime path**. Every vyre program executes on a
GPU backend. The CPU reference interpreter that implements the spec
lives in `vyre-conform`, as a test oracle. It never runs inside
`vyre` at runtime.

## What vyre-conform contains

vyre-conform is the specification, expressed as executable code. Its
crate root is `libs/performance/matching/vyre-conform/` (which will
move to `libs/performance/matching/vyre/conform/` as a workspace
member during the reconciliation). Its contents:

- **Spec tables.** Authoritative `(input, expected)` pairs for every
  op. The spec table is the highest-level oracle in the
  [7-level oracle hierarchy](testing/oracles.md). When the spec
  table says `sub(5, 3) = 2`, every conforming vyre implementation
  produces exactly 2 for that input. A value other than 2 is wrong.
- **Algebraic laws.** Commutativity, associativity, identity,
  self-inverse, distributivity, De Morgan, idempotence, absorption,
  and op-specific identities. Each law is a universally quantified
  claim over a declared domain, verified by exhaustive or witnessed
  evaluation.
- **Reference interpreter.** A pure-Rust, obvious-correct,
  intentionally slow CPU evaluator for `ir::Program` values. Given
  the same inputs, the reference interpreter and every conforming
  backend produce bit-identical results. The reference interpreter
  is the meaning of the spec — if it disagrees with a backend, the
  backend is wrong.
- **Mutation catalog.** Classes of known-bad transformations that
  every vyre test must kill. If a test cannot distinguish the real
  implementation from a mutated one, the test is too weak and the
  mutation gate rejects the change.
- **Adversarial archetypes.** The input patterns every op must
  survive without panic, undefined behavior, data corruption, or
  unbounded resource use: overflow, underflow, boundaries, NaN,
  Inf, empty, maximum, off-by-one, minimum-program, maximum-nesting,
  zero-sized buffers, diamond dataflow, long dependency chains,
  wide fanout.
- **Harnesses H1 through H10.** The mechanical test drivers that
  run every op through every check. H1 = spec table, H2 = law
  check, H3 = reference interpreter agreement, H4 = CPU/GPU parity,
  H5 = property generators, H6 = mutation gate, H7 = composition
  proof, H8 = independence / separability, H9 = coverage
  verification, H10 = stability audit.

## The gate

**Every change to vyre runs through vyre-conform before it can merge.**
This is not a code review convention. It is a structural gate encoded
in the workspace: every workspace member that ships ops must declare
`vyre-conform` in `[dev-dependencies]` and include a
`tests/conform_gate.rs` that invokes
`vyre_conform::gate::assert_member_passes!()`. A workspace-level audit
xtask (`cargo conform-audit`) refuses to pass CI if any ops-shipping
member is missing either.

The gate checks:

1. **Spec tables** pass for every op the member declares. A spec row
   that doesn't match the implementation fails with the exact row and
   the observed value.
2. **Laws** hold over their declared domains. A failing law reports
   the witnessing counterexample.
3. **Reference interpreter agreement** — the implementation's lowered
   GPU output equals the reference interpreter's output bit-for-bit,
   for every input in the declared equivalence classes and archetypes.
4. **Mutation kill** — for each declared mutation class, the test
   suite detects the mutation. Surviving mutations are findings, not
   acceptable misses.
5. **Archetype coverage** — every op has tests hitting every
   applicable archetype.
6. **Independence / separability** — each V-rule fails independently
   when triggered, and no valid program coincidentally exercises a
   rule that should fail.
7. **Composition proof** — the DAG of op dependencies respects the
   layer topology: no op at layer N depends on an op at layer ≥ N.
   The topological check is mechanical, run over every registered op
   in the workspace.
8. **Stability** — no spec entry has been removed or had its meaning
   changed since the previous certified commit. Additions are
   allowed; changes and removals are forbidden.

A change that passes every gate gets a certificate. A change that
fails any gate is rejected with the exact failure list. There is no
subjective review step. Correctness is the gate, not the reviewer.

## Dependency direction

```
                    ┌─────────────────┐
                    │   vyre-conform  │
                    │   (the spec +   │
                    │    the gate)    │
                    └────┬────────────┘
                         │ depends on
                         │ (normal)
                         ▼
                    ┌─────────────────┐
                    │      vyre       │
                    │ (the implementation)
                    └────┬────────────┘
                         │
                         │ depends on vyre-conform
                         │ (dev-dependency only,
                         │  used by every vyre test)
                         │
                    ┌────┴────────────┐
                    │   vyre tests    │
                    └─────────────────┘
```

- `vyre-conform` → `vyre` as a normal dependency. Conform needs IR
  types to run its harnesses.
- `vyre` → `vyre-conform` as a dev-dependency. Every vyre test can
  invoke the gate.
- There is no runtime dependency from `vyre` to `vyre-conform`. At
  runtime, `vyre` alone is enough to build, validate, lower, and
  dispatch a program.

## Third-party backend implementers

If you are implementing a new backend for vyre (a CUDA backend, an
AMD-specific backend, an SPIR-V backend, a backend for a future
accelerator):

1. Implement the `Backend` trait in `vyre::lower::backend`.
2. Register your backend with vyre-conform via
   `vyre_conform::register_backend!()`.
3. Run `cargo test --package vyre-conform -- backend=<your-name>`.
4. The conformance suite runs every registered op against your
   backend, compares output bit-for-bit against the reference
   interpreter, and emits a certificate file listing the ops your
   backend conformed on and any that failed.
5. Ship your backend publicly if the certificate is complete for the
   conformance level you are claiming.

No coordination with vyre maintainers is required. The spec is the
authority. The certificate is the proof. If your backend passes, it
is conforming by definition. If it fails, the failure list is exact
and actionable.

## Why the split exists

The implementation and the specification have different properties:

- **Different release cadence.** `vyre` evolves continuously — new
  lowerings, new optimizations, new ops, new engine features.
  `vyre-conform` evolves slowly — new spec entries are additions,
  not edits, and every addition is an event.
- **Different stability guarantees.** `vyre` may add a new
  optimization pass in a patch release. `vyre-conform` cannot
  change the meaning of `Div(5, 0)` in any release; that would
  break certified backends.
- **Different audiences.** `vyre` is consumed by downstream crates
  and application authors who construct programs and dispatch them.
  `vyre-conform` is consumed by vyre contributors (every commit
  runs the gate) and by third-party backend implementers (who need
  the reference to test against).
- **Different test targets.** `vyre`'s own tests verify that the
  implementation works — plumbing, integration, regression.
  `vyre-conform`'s tests verify that the spec is coherent —
  laws hold on the reference interpreter, spec tables are
  consistent, mutations are killable.

Rolling them into one crate would force the spec and the
implementation to share a version line, a stability guarantee, and
a release cadence. None of those are natural to share. Splitting
them preserves the property that the spec is immutable-by-default
and the implementation is evolve-freely-underneath — the Linux
kernel's "don't break userspace" rule, applied at the library layer.

## Why the split is NOT more granular

Earlier drafts proposed publishing separate crates per domain
(`vyre-string`, `vyre-regex`, `vyre-distance`, `vyre-graph`,
`vyre-decode`). That was rejected. The domain modules are part of
the same product — the composable op library that downstream crates
depend on. Splitting them into separate crates would force every
consumer to manage many crate versions and would create surface
area on crates.io without adding value.

Instead, the domain modules live as **workspace members** under the
vyre workspace: `vyre/domains/crypto/`, `vyre/domains/linalg/`,
`vyre/libraries/ml/`, etc. They are organizational, not published.
Only three crates reach crates.io from this workspace: `vyre`,
`vyre-conform`, and `vyre-std` (which contains Layers 1 and 2). All
other domain and library crates ship via feature flags on those
three published crates or as private workspace members — promotion
to their own published crate is a product decision that requires
the same bar as tool promotion in Santh's crates-of-crates pattern.

## Related documents

- [Vision](vision.md) — the abstraction thesis and what vyre is for
- [Stability](stability.md) — the immutable-surface rule and additive
  evolution
- [Extensibility](extensibility.md) — the Category A/C discipline and
  the op proposal gate
- [Glossary: vyre-conform](glossary.md#vyre-conform) — the one-entry
  definition
- [IR wire format](ir/wire-format.md) — the binary serialization, the
  other "two representations, one spec" pairing
- [Testing book](testing/README.md) — the invariants and oracle
  hierarchy that vyre-conform enforces
