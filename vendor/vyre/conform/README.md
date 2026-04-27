# conform/

Conformance = certifiable parity between every vyre backend and the
CPU reference interpreter.

If WGSL emits `7.0`, SPIR-V emits `7.0`, and `vyre-reference` emits
`7.0` for the same program, the op conforms. If any one disagrees —
even by a single bit — the op is non-conformant and no backend is
allowed to ship.

The four crates in this directory cooperate to enforce that
guarantee end to end.

## The four crates

```text
             ┌─────────────────────────────┐
             │  vyre-conform-spec          │  DataType witness sets
             │    • U32Witness             │  Composition laws
             │    • WitnessSet trait       │  (deterministic, fingerprintable)
             └──────────────┬──────────────┘
                            │ consumed by
                            ▼
             ┌─────────────────────────────┐
             │  vyre-conform-enforce       │  Runs the op over witnesses
             │    • LawProver              │  Flags law violations
             │    • LawVerdict             │  (commutativity, associativity,
             └──────────────┬──────────────┘   identity, distributivity)
                            │ counterexamples flow into
                            ▼
             ┌─────────────────────────────┐
             │  vyre-conform-generate      │  Binary-search minimizer
             │    • CounterexampleMinimizer│  Finds smallest failing input
             └──────────────┬──────────────┘
                            │ feeds into
                            ▼
             ┌─────────────────────────────┐
             │  vyre-conform-runner        │  The CI gate
             │    • Matrix runner          │  Dispatches every op × every
             │    • Divergence reporter    │  backend × every witness tuple
             │    • Parity matrix          │  Bundle certificate on green
             │    • vyre-test-harness dep  │
             └─────────────────────────────┘
```

A fifth crate, `vyre-test-harness`, holds the shared CPU/GPU lens
and fixture loader used by both the runner and any backend crate's
dev-dependencies. It exists to break the dev/normal cross-link that
used to couple backend crates to the runner.

## Invariants

1. **Witness sets are deterministic.** `WitnessSet::enumerate()`
   produces the same sequence in the same order on every run; the
   enumeration is part of the conformance contract.
2. **Law verdicts are structural.** `LawVerdict::Failed` carries the
   counterexample tuple that proved the failure — no hashing, no
   summarisation. A law failure is reproducible byte-for-byte from
   the verdict alone.
3. **Minimization converges.** `CounterexampleMinimizer` halves the
   u32 input on every step and terminates in `O(log n)` calls; it
   never loops and never returns a larger counterexample than the
   input.
4. **No backend ships without a green matrix.** CI blocks publish on
   `vyre-conform-runner`'s matrix returning zero divergences.
5. **Exemptions are traceable.** The runner supports a
   `UniversalDiffExemption` mechanism for documented, audited
   divergences; each exemption is a structured record with a
   justification, an expiry, and an owner. Exemptions for security
   ops are forbidden (ops that must be byte-identical under all
   inputs, audited separately).

## Boundaries

This directory owns:

- The witness enumeration contract and the default `U32Witness`.
- The law prover that consumes witnesses and op compose functions.
- The counterexample minimizer.
- The CI runner that wires everything together and emits a bundle
  certificate.
- The shared test harness (lens + fixtures).

It does NOT own:

- The ops themselves (those live in `vyre-foundation`,
  `vyre-primitives`, `vyre-libs`, `vyre-intrinsics`).
- The CPU reference evaluator (`vyre-reference`).
- Backend implementations (`vyre-driver-wgpu`, `vyre-driver-spirv`).
- The benchmark harness (`vyre-runtime` + criterion harnesses in
  each crate).

## Per-crate READMEs

- `vyre-conform-spec/README.md` — witness sets, `WitnessSet` trait,
  `U32Witness`.
- `vyre-conform-enforce/README.md` — `LawProver`, `LawVerdict`,
  algebraic-law checks.
- `vyre-conform-generate/README.md` — `CounterexampleMinimizer`
  binary-search shrinker.
- `vyre-conform-runner/README.md` — the CI runner, parity matrix,
  and bundle certificate flow.
- `vyre-test-harness/README.md` — shared lens + fixtures between
  runner and backend dev-deps.

## Extension guide — adding a DataType / law / backend to conformance

1. **New DataType witness**: implement `WitnessSet` for the type in
   `vyre-conform-spec`; the enumeration order is part of the public
   contract, so pick it once and document why.
2. **New algebraic law**: add a variant to `LawVerdict` and the
   corresponding proof pass in `LawProver`; add at least three
   counterexample tuples that are known to fail for a broken op, and
   assert the prover finds them.
3. **New backend**: register the backend with `vyre-driver`, then
   add a matrix row in `vyre-conform-runner`'s parity matrix
   fixture. The runner will diff your backend's dispatch against the
   CPU reference automatically.
4. **Exemption (rare, audited)**: add a `UniversalDiffExemption`
   entry with justification + owner + expiry. Never add exemptions
   for security ops — those are non-exemptible by policy.

See `vyre-conform-runner/tests/parity_matrix.rs` for the end-to-end
wiring and `vyre-conform-enforce/src/prover.rs` for the verdict
shape.
