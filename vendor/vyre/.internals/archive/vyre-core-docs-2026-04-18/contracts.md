# Contracts — the 6 frozen traits

vyre's extensibility depends on 6 traits whose signatures are frozen at 1.0.
New methods may be added with default implementations.
Existing method signatures never change.
This is the 5-year contract.

Community extensions implement one of these traits.
Backends, gates, oracles, archetypes, and mutation classes all plug in through these exact interfaces.
Stability matters because a breaking change here forces every downstream extension to rewrite.
The frozen surface is intentionally small: an id, a work method, and thread-safety bounds.
No trait will ever grow a required method without a major version bump.
These six signatures are the only places where external code is expected to implement a vyre trait.

## VyreBackend — execute a vyre IR program

The backend trait is the execution boundary between vyre IR and the target platform.
Backends translate the intermediate representation into concrete dispatch commands.

- **Canonical home:** `vyre/core`
- **Who implements:** backend authors (wgpu, reference interpreter, future hardware)
- **Signature:**

```rust
pub trait VyreBackend: Send + Sync {
    fn id(&self) -> &'static str;

    fn dispatch(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError>;
}
```

- **Invariant:** byte-identical output to CPU reference; actionable `Err` on failure

## Finding — a structured violation

The finding trait unifies all diagnostic output across gates, oracles, and verifiers.
A single structured shape makes it possible to aggregate results without knowing the producer.

- **Canonical home:** `vyre-conform/spec`
- **Who implements:** every gate/oracle/verifier emitting findings
- **Signature:**

```rust
pub trait Finding: Send + Sync + std::fmt::Debug {
    fn source(&self) -> &'static str;
    fn message(&self) -> String;
    fn fix_hint(&self) -> String;
    fn location(&self) -> Option<FindingLocation>;
}
```

- **Invariant:** presence of ANY finding = FAIL; `fix_hint` must start with `Fix:`

## EnforceGate — one enforcement check

Gates are static or dynamic checks that inspect specifications, programs, or backends.
Each gate is independent and can be enabled or disabled by the conformance runner.

- **Canonical home:** `vyre-conform/enforce`
- **Who implements:** gate authors
- **Signature:**

```rust
pub trait EnforceGate: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn run(&self, ctx: &EnforceContext<'_>) -> Vec<Box<dyn Finding>>;
}
```

- **Invariant:** empty findings vec = pass; any finding = fail

## Oracle — independent source of truth

Oracles provide expected results without trusting the system under test.
The oracle hierarchy resolves which independent verifier is strongest for a given operation.

- **Canonical home:** `vyre-conform/proof`
- **Who implements:** oracle authors
- **Signature:**

```rust
pub trait Oracle: Send + Sync {
    fn id(&self) -> &'static str;
    fn kind(&self) -> OracleKind;
    fn applicable_to(&self, op: &OpSpec, property: &Property) -> bool;
    fn verify(&self, op: &OpSpec, input: &[u32], observed: &[u32]) -> Verdict;
}
```

- **Invariant:** hierarchy resolver picks strongest applicable oracle

## Archetype — structural test pattern

Archetypes generate test inputs that exercise specific IR shapes or numerical boundaries.
They are reusable across operations that share a common signature pattern.

- **Canonical home:** `vyre-conform/generate`
- **Who implements:** archetype authors
- **Signature:**

```rust
pub trait Archetype: Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn applies_to(&self, signature: &OpSignature) -> bool;
    fn instantiate(&self, op: &OpSpec) -> Vec<TestInput>;
}
```

- **Invariant:** `instantiate` returns applicable inputs; `applies_to` returns `false` if inapplicable

## MutationClass — adversarial mutation category

Mutation classes produce semantically incorrect variants of a source program.
The test harness verifies that the backend or compiler rejects or correctly handles the mutation.

- **Canonical home:** `vyre-conform/adversarial`
- **Who implements:** mutation authors
- **Signature:**

```rust
pub trait MutationClass: Send + Sync {
    fn id(&self) -> &'static str;
    fn mutations_for(&self, source: &str) -> Vec<Mutation>;
}
```

- **Invariant:** each mutation produces a different, detectable wrong answer

## The freezing rules

- Method signatures never change post-1.0.
- New methods added only with default implementations (forward-compatible).
- Breaking changes require major version bump + CEO approval.
- CI enforces via `scripts/check_trait_freeze.sh`.

These rules exist so that a backend or gate written today compiles against vyre 1.5 without modification.
The only permitted evolution is additive: new optional methods with default bodies.
If a trait needs a fundamentally different contract, a new trait is introduced rather than breaking the old one.
This policy protects the ecosystem from churn and gives authors confidence to invest in long-lived extensions.

## Reading the signatures

Every trait has `id()` for stable identification plus a main method that does the work.
`Send + Sync` are required for parallel execution across threads and backends.
Object-safe bounds are kept minimal so trait objects remain practical.
Default implementations keep the barrier low for new authors while preserving compatibility for existing ones.

## Implementing a trait

See [`contributing.md`](contributing.md) for the how-to.
