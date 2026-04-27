# Trust Model

The authoritative trust model lives in `TRUST_MODEL.md` at the monorepo root. This chapter restates it for book readers.

vyre is built on a strict trust model: the value of the conformance system comes from the fact that no one party can game the verdict. This chapter describes who is trusted with what.

See also: `CONTRIBUTING.md`, `STABILITY.md`, and `ARCHITECTURE.md` at the monorepo root.

## The parties

### Consumers

Anyone using vyre in their application. Zero trust extended; zero required.

A consumer uses the library, gets the binary verdict, and ships or fixes. They do not need to read the source, trust the maintainers, or understand the proof system. The only required trust assumption is that `certify()` returns `Ok(Certificate)` only when the backend has passed every gate, oracle, and adversarial check.

### Community contributors

Anyone submitting a PR.

Contributors are trusted to add new ops, new laws, new archetypes, new oracles, new gates, new mutations, new backends, and new TOML rules. They are *not* trusted to edit frozen trait signatures, edit the spec crate's public types, delete regression tests, or edit law checkers or the mutation catalog. CODEOWNERS enforces this via required review on maintainer-only paths.

Contributors are expected to follow the first-contribution guide in `CONTRIBUTING.md` and to treat every audit finding as critical.

### Core maintainers

Review PRs to maintainer-only paths, approve trait signature changes (which require a major version bump), approve new frozen type variants in `vyre-spec`, and approve crates.io publish.

Maintainers are the human backstop, not the source of truth. The conformance suite is the source of truth. Maintainers exist to prevent social-engineering attacks on the repository and to enforce the stability contract.

### Backend authors

Trusted to publish a backend as a separate crate that implements `VyreBackend`. *Not* trusted to mark their own backend as conformant. Only `certify()` determines that.

The certificate is the trust proof. A backend author may claim their backend is correct, but the claim is worthless without a reproducible certificate issued by `vyre-conform`.

## What's trusted, what's verified

Every claim made by a contributor or backend author is verified, not trusted:

- CPU reference is verified against declared laws (cannot lie about laws).
- Declared laws are verified against the CPU reference (cannot lie about `cpu_fn`).
- GPU kernel is verified byte-for-byte against CPU reference (cannot lie about kernel).
- Composition theorems are proven against declared laws (cannot lie about composition).
- Backend dispatch output is verified against the reference implementation (cannot lie about correctness).
- Category A zero-overhead claims are verified by disassembling the lowered WGSL and comparing instruction counts (cannot lie about optimization).

The trust floor: if `certify()` passes, the backend produces byte-identical output to the CPU reference for every op, every input, every time.

No person is trusted to say "this backend is correct." The only valid statement is "`certify()` produced a certificate for this backend." The certificate includes the exact versions of the ops, the laws, the gates, and the oracles used. It is reproducible and independently verifiable.

## Attack surface and mitigations

### Broken `cpu_fn` + matching wrong `wgsl_fn`

A contributor intentionally writes a wrong CPU reference and a wrong WGSL kernel that agree with each other but are both incorrect.

Mitigation: the `reference_trust` enforcer in `vyre-conform` uses differential comparison against independent reference implementations, law-derived probes, boundary probes, and round-trip property checks. A pair-of-wrongs that agree with each other still fails law verification against the declared algebraic laws. The laws are mathematical invariants, not behavioral copies, so colluding errors cannot satisfy them unless they are actually correct.

### Falsely claimed Category A zero-overhead composition

A contributor marks an op as Category A and claims it composes with zero overhead, but the lowered WGSL contains hidden dispatch or allocation overhead.

Mitigation: `check_category_a_zero_overhead` disassembles the lowered WGSL and verifies the instruction count matches the composition reference. Any extra instructions, branches, or memory operations cause a finding. The gate is automated and requires no human judgment.

### Category B pattern injection

A contributor or compromised dependency introduces `typetag`, `inventory`, `downcast`, `async_trait`, or another forbidden pattern that breaks the closed-enum or static-dispatch invariants.

Mitigation: the CI tripwire scan fails the PR before merge. See `enforce/category/b_tripwire/text_scan.rs` for the exact pattern list. The scan is part of the required check suite and cannot be bypassed without maintainer override.

### Editing published op semantics after release

A contributor or maintainer changes the behavior of a published op, invalidating historical certificates silently.

Mitigation: every published op is recorded in the registry with a stable hash. The registry hash in every certificate changes if the op changes. Certificates from year 1 remain verifiable against the op as-it-was-at-year-1. Old certificates do not auto-upgrade to new semantics. See `STABILITY.md` for the permanence guarantee.

### Deleting or weakening a regression test

A contributor removes a test that would catch a known bug, making the suite quieter without making it truer.

Mitigation: CI enforces append-only behavior on regression and corpus paths. Tests may be replaced with stricter tests, but deletion requires maintainer review. The self-audit gate (`conform_self_audit_must_scream`) checks for missing coverage and placeholder tests.

### Social-engineering a maintainer into bypassing review

An attacker convinces a maintainer to force-merge a change that violates frozen contracts.

Mitigation: branch protection requires two maintainer approvals for changes to frozen trait files and the spec crate. CODEOWNERS is configured so that no single maintainer can unilaterally modify the trust boundary. The CI gates run on every merge, including maintainer merges.

### Poisoning the TOML rule corpus

A contributor adds a malicious or misleading TOML rule that hides a real vulnerability.

Mitigation: TOML rules are scanned, parsed, and executed by the same automated gates as Rust code. A rule that suppresses a finding without fixing the root cause is rejected by the self-audit. Rules are versioned by file and do not override gate logic.

## Deprecation process

When an interface or op is superseded, it follows the lifecycle defined in `STABILITY.md`:

- Marked `#[deprecated]` in version N, with a clear note pointing to the replacement.
- Still compiled, tested, and shipped in versions N+1 and N+2.
- Removed no earlier than 12 months after the deprecation first appears in a stable release.
- Or never removed at all, if removal would break published conformance certificates or violate the stability guarantee.

Deprecation is the tool of last resort. Preference is given to additive replacement: leave the old interface untouched and introduce a new one alongside it. A consumer who earned a certificate in year 1 must be able to verify it in year 5.

## Dispute process

A conformance violation is concrete. It includes:

1. Input bytes.
2. Expected bytes.
3. Observed bytes.
4. The law or invariant violated.
5. A `Fix:` hint naming the exact path or change required.

Disputes are resolved by re-running the violation. If the violation reproduces on a clean checkout of the referenced commit, the violation stands. If the violation does not reproduce, the certificate is reissued.

There is no appeal to authority. A maintainer cannot overrule a reproducible violation. The only valid resolution is to change the code so the violation no longer reproduces, or to prove that the violation itself is mathematically impossible (which is itself a code change to the gate or oracle).

## Summary of trust boundaries

| Party | Trusted with | NOT trusted with |
|-------|-------------|------------------|
| Consumers | Using the API, shipping certified backends | Nothing internal |
| Community contributors | New ops, laws, gates, oracles, archetypes, mutations, backends, TOML rules | Editing frozen traits, spec types, deleting tests, editing law checkers |
| Core maintainers | Reviewing maintainer-only paths, approving major version bumps, publishing crates | Overruling `certify()`, bypassing CI gates |
| Backend authors | Writing and publishing backend crates | Self-certifying conformance |

The only source of truth is `certify()`. Everything else is human process, and human process is fallible.

## Conformance testing roles

Within `vyre-conform`, three additional roles define how individual ops are tested. These roles exist because trust at scale is expensive. When 300 agents contribute operations simultaneously, the question is not "does this op work?" but "can a dishonest contributor make a broken op appear to work?"

### Implementor

The contributor. Submits an op: a `spec.toml`, a `kernel.rs` (CPU reference), and a `lowering/wgsl.rs` (GPU kernel). Their artifact is the thing the backend actually executes. Graded on: does it pass the full conformance pipeline?

### Prosecutor

Writes tests designed to break the implementation. Their artifact is a set of assertions on the reference function and, for L3, the reference interpreter. Graded on: how many mutations of the reference do the tests kill?

### Defender

The most important and most commonly omitted role. Submits an *intentionally wrong* CPU reference dressed up to look like a legitimate contribution. Every declared algebraic law has a handful of canonical sabotages — xor that flips the low bit, add that saturates, popcount that returns one more than it should — and each one should be caught by a well-written law set. Graded on: precision (does the sabotage preserve the MOST laws possible while still being wrong) and coverage (does the catalog exercise every declared law of every op).

## What each role controls

| Artifact | Owner | Review gate |
|---|---|---|
| `core/src/ops/**/spec.toml` | Implementor | TOML loader validation + maintainer review |
| `core/src/ops/**/kernel.rs` | Implementor | Law verification + dual-reference agreement |
| `core/src/ops/**/lowering/wgsl.rs` | Implementor | GPU parity test against CPU reference |
| `conform/src/reference/**` | Maintainer only | CODEOWNERS |
| `conform/src/algebra/**` | Maintainer only | CODEOWNERS |
| `conform/src/spec/**` | Maintainer only | CODEOWNERS |
| Law declarations | Implementor proposes | Mandatory inference verifies |
| Boundary values | Implementor provides | Minimum-coverage gate rejects < 4 |
| Equivalence classes | Implementor provides | Minimum-coverage gate rejects < 1 |

## What the system prevents

### Oracle poisoning

A contributor cannot edit the CPU reference interpreter — it lives under `conform/src/reference/` which is CODEOWNERS-protected. They submit their own `cpu_fn` in `kernel.rs`, but that function is verified against the declared algebraic laws (exhaustive on u8, witnessed on u32, GPU-backed).

### Decorative laws

A contributor cannot declare `Commutative` and have it pass without real verification. Every declared law runs through the algebra checker — exhaustive on 256² u8 pairs plus 1,000,000 random u32 witnesses. The checker produces concrete counterexamples on violation.

### Law deflation

A contributor cannot silently remove a law that their op actually satisfies. The `infer_binary_laws` / `infer_unary_laws` audit runs the full law enum against each op and flags any newly-satisfied law that isn't declared.

### Archetype gaming

A contributor cannot classify their `binary-bitwise` op as `unary-arithmetic` to dodge bitwise-specific test shapes. The TOML loader validates that the archetype matches the signature (input count and data types).

### Certificate replay

A contributor cannot submit a valid certificate JSON from one op as evidence for a different op. The `registry_hash` in the certificate is computed from the full op source (id, version, laws, signature, WGSL) and the `verify-cert` CLI recomputes it from current specs.

## The conformance levels

| Level | What it proves | What it requires |
|---|---|---|
| L1 | GPU output matches CPU reference for every generated input | Parity testing across workgroup sizes |
| L2 | L1 + every declared algebraic law holds | Exhaustive u8 + witnessed u32 + GPU-backed law verification |
| L1f | L1 for strict floating-point ops | Bit-exact IEEE 754 parity |
| L2f | L2 for strict floating-point ops | Float-specific law verification |
| L1a | L1 for approximate ops within declared ULP tolerance | Tolerance-verified parity |

A certificate cannot claim L2 without also satisfying L1. FastCheck mode (10,000 witnesses) is explicitly exploratory and cannot publish a conformance claim.
