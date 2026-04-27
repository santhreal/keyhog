# certify — the binary verdict

This chapter documents the `certify()` entry point: how vyre-conform produces a binary pass/fail verdict for a backend, what the certificate contains, and what a violation looks like.

> For the full test architecture that underpins this API, see [Architecture](testing/architecture.md).

vyre-conform's public API is one function.
It accepts a backend, a set of operation specs, and a verification strength, and returns either a `Certificate` (the backend is Santh-worthy) or an error string with a concrete counterexample and a `Fix:` hint.
There is no '83% passing', no 'known limitations', no judgment calls.
Pass or fail.

## The signature

```rust
pub fn certify(
    backend: &dyn vyre::VyreBackend,
    specs: &[OpSpec],
    strength: CertificateStrength,
) -> Result<Certificate, String>;
```

The backend is tested against every registered op, every declared law, every archetype, and every mutation.
Any failure at any gate returns `Err(Violation)`.
Full pass returns `Ok(Certificate)`.

There is no middle ground.
A backend that passes every test except one is not conformant.
A backend that produces correct output for 99.99% of inputs but fails on a single edge case is not conformant.
The binary verdict is the community-facing promise: one call, one answer, no ambiguity.

## What certify runs (the 8-gate pipeline)

`certify` executes the following enforcement layers in order, aborting at the first failure:

1. **L1 Executable Spec** — The CPU reference function for every registered op exists, compiles, and produces deterministic output.
If the reference does not exist, the gate fails immediately.
The reference is the ground truth against which all other backends are measured.
Determinism is verified by running the same input multiple times and asserting identical output.
Nondeterministic backends fail here.

2. **L2 Law Inference** — Every declared algebraic law is verified exhaustively over the `u8` domain and witnessed over the `u32` domain.
Exhaustive means every possible `u8` input pair is tested.
Witnessed means a large random sample over `u32` is tested.
A law that cannot be proven or witnessed is a failure.
Laws include commutativity, associativity, identity, and any domain-specific invariants declared in the op registry.
A backend that violates even one law on one input fails this gate.

3. **L3 Reference Interpreter** — The pure-Rust IR interpreter agrees with the CPU reference on all canonical inputs.
If the interpreter diverges from the reference, the gate fails.
The interpreter is the portable oracle used when the CPU reference is not available on a target platform.
Agreement is tested for every op and every canonical program shape.
The interpreter must be trustworthy because it is used as the oracle for GPU backends that cannot run the CPU reference natively.

4. **L4 Mutation Gate** — Source-code mutations that would weaken semantics are caught and rejected by the test suite.
Mutations that survive indicate insufficient test coverage.
This gate uses mutation testing to verify that the test suite is sensitive to semantic changes.
A mutation that changes a law implementation but does not cause a test failure is a critical finding.
Mutants are generated automatically and run against the full suite.

5. **L5 Adversarial Gauntlet** — Three roles (implementor, prosecutor, defender) collaboratively probe the backend for weaknesses.
The implementor writes the backend, the prosecutor generates hostile inputs and edge cases, and the defender hardens the oracle and test suite.
A backend that survives the gauntlet has been actively stressed against real-world adversarial conditions.
The gauntlet includes resource bombs, malformed inputs, and boundary conditions.

6. **L6 Stability** — The public API is stable; no regression is introduced without a breaking-change announcement.
Backward-incompatible changes without justification fail this gate.
This includes ABI changes, wire-format changes, and op semantic changes that break existing certificates.
Stability is verified by running the full regression suite and comparing results against the previous release baseline.

7. **L7 Composition Proof** — Op compositions are proven correct via proof tokens that carry semantic guarantees.
If composed ops do not match their sequential equivalent, the gate fails.
Composition is where most backends fail because individual op correctness does not guarantee multi-op correctness.
The proof token links the composed program to its verified semantics.
Token verification is mandatory for the Full track.

8. **L8 Feedback Loop** — Every contribution is validated through the full pipeline before it can reach main.
Untested or unreviewed changes cannot enter the release branch.
This gate ensures that the certification criteria themselves are not degraded over time.
The feedback loop includes automated tests, manual review, and mutation gate results.
CI must be green before merge.

Beyond the eight core gates, the following specialized gates are also enforced:

- **Gate 7 (Coverage)** — Every op, every archetype, and every declared law has at least one dedicated test.
Missing coverage is a hard failure.
Coverage is measured by instrumented test runs and audited by maintainers.
A line that is not covered is treated as potentially broken.
The coverage threshold is 100% of registered ops and laws.

- **Gate 8 (No CPU Runtime)** — The backend must not silently fall back to CPU execution.
If it claims to dispatch to a GPU, it must run on the GPU.
Detected fallback triggers an immediate violation with the hint: `Fix: remove the fallback path or declare a CPU-only backend.`
Silent fallback undermines the entire purpose of backend certification.

- **Category A/B/C enforcement** — Ops are classified into categories A, B, and C.
Category A ops require full algebraic verification.
Category B ops require parity and witness coverage.
Category C ops require basic correctness.
Each category has its own track requirements, and all must be met.
No category is optional.
A backend cannot skip Category C ops by claiming they are unimportant.

- **OOB gate** — Out-of-bounds buffer access returns a structured error.
No undefined behavior, no silent clamping, no wraparound.
The backend must prove that every access is either in-bounds or reports an error.
This applies to all buffer types and all access modes.
OOB is tested at the exact boundary and one-past-the-boundary.

- **Atomics gate** — Atomic operations exhibit sequential consistency across workgroups.
Races, torn reads, or inconsistent visibility are violations.
This gate is run with multiple workgroup sizes to expose implementation-dependent behavior.
Atomic correctness is required for any backend that claims to support parallel dispatch.

- **Barriers gate** — Memory barriers make preceding writes visible to all invocations in the scope as specified.
Missing or incorrectly lowered barriers fail this gate.
Barriers are tested under divergent control flow to ensure correctness in all cases.
A backend that elides barriers for performance fails here.

- **Wire format gate** — IR round-trips through serialization and deserialization byte-for-byte.
Any deviation in encoding or decoding is a failure.
The wire format is part of the public contract; backward-incompatible changes are not permitted without a major version bump.
The wire format is tested with a committed corpus of canonical programs.

- **Overflow gate** — Arithmetic overflow is either detected or defined by specification.
It is never silent.
A backend that wraps on overflow without declaring it fails this gate.
Signed and unsigned integer overflow are both tested.
Floating-point overflow follows the IEEE-754 rules declared in the op registry.

- **No-silent-wrong invariant** — Any incorrect output is reported as a failure.
There is no partial credit and no rounding up.
Wrong is wrong.
A backend that produces incorrect output but does not report an error is the worst kind of failure.
This invariant is the moral center of the entire certification system.

## The Certificate

A `Certificate` is a durable proof of conformance.
It can be checked into version control and independently verified by any third party.
It contains:

- **Registry hash** — A deterministic cryptographic fingerprint of the entire op registry.
Replays use this hash to verify that the exact same ops and laws were tested.
If the registry changes, old certificates are invalidated.
This prevents stale certificates from being reused after semantic changes.

- **Backend id** — The name and version string of the backend under test.

- **Timestamp** — Unix seconds since epoch.
The value is always greater than or equal to `MIN_CERTIFICATE_UNIX_SECONDS`.
This prevents back-dating and establishes a minimum age for trust.
Certificates issued before this threshold are rejected by verification tools.

- **Coverage metrics** — Exact counts of ops exercised, laws verified, archetypes visited, and mutations rejected.
These numbers are auditable.
A certificate without coverage metrics is incomplete and will not verify.

- **Per-op verdicts** — A pass or fail result for every op in the registry.
No aggregate score is provided because aggregation would obscure individual failures.
You can inspect the certificate to see exactly which ops passed and which failed.

- **Levels** — The certificate records the highest conformance level reached for each data-type track:
  - **Integer track** — `L1` (parity) or `L2` (parity + algebraic laws).
  - **Float track** — `L1f` or `L2f` for strict IEEE-754 floating-point ops.
  - **Approximate track** — `L1a` for ops with declared ULP tolerance.
  A backend can achieve different levels on different tracks; each track is graded independently.

The certificate is not a suggestion. It is evidence.
It is the artifact you show when a downstream user asks, "How do I know this backend is correct?"
The answer is: here is the certificate, here is the registry hash, here is the timestamp.
Reproduce it yourself if you doubt it.

## The Violation

A `Violation` contains at least one concrete counterexample and an actionable `Fix: ...` hint.
It reports:

- Which gate failed.
- Which op triggered the failure.
- The exact input that produced the wrong output.
- The expected output according to the oracle.
- A byte-level diff when the output is a buffer or wire-format stream.

There is no ambiguity.
A violation tells you exactly what is broken and where to start fixing it.
You do not need to debug the backend from scratch.
You do not need to wonder whether the test is flaky.
You read the violation, apply the fix, and rerun `certify`.

If the violation comes from the adversarial gauntlet, it may include a minimized input that was found automatically.
If it comes from the mutation gate, it will name the mutant that survived.
If it comes from a law inference failure, it will show the counterexample input pair.
The `Fix:` hint is always present and always actionable.

## Usage

```rust
use vyre::VyreBackend;
use vyre_conform::{certify, to_json, CertificateStrength};

let backend = MyBackend::new();
let specs = vyre_conform::registry::all_specs();
let backend: &dyn VyreBackend = &backend;

match certify(&backend, &specs, CertificateStrength::Standard) {
    Ok(cert) => {
        std::fs::write("my_backend.cert.json", to_json(&cert)).unwrap();
        println!("Santh-worthy: certificate generated");
    }
    Err(e) => {
        eprintln!("NOT conformant:\n{}", e);
        std::process::exit(1);
    }
}
```

The typical integration is a single call in your backend's test suite or release script.
Save the certificate on success.
Print the violation and exit non-zero on failure.
This pattern is intended to be copy-pasted into CI pipelines and release automation.

## The invariant certify enforces

If `certify` returns `Ok`, the backend produces byte-identical output to the CPU reference for every op, every input, every time.
That is the whole contract.

There are no disclaimers.
There are no escape clauses.
Byte-identical means exactly that: the backend's output buffer, when compared to the reference buffer, matches at every offset.
Not approximately, not within tolerance, not for most inputs.
Every op, every input, every time.

## CI integration

Run `cargo test -p vyre-conform` in continuous integration.
Any red test means the backend is not Santh-worthy.
The deploy gate is the certificate: a backend without a current, valid certificate does not ship.

Commit the certificate to your repository so that downstream users can verify it independently.
The certificate is the deploy gate.
No certificate, no release.
If the certificate is stale because the registry has changed, regenerate it and commit the new one.

## See also

- [Certificates](certificates.md)
- [Testing Architecture](testing/architecture.md)
- [The Promises](testing/the-promises.md)
