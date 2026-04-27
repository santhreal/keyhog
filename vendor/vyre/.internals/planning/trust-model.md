# Trust Model

vyre is built on a strict trust model: the value of the conformance system comes from the fact that no one party can game the verdict. This document describes who is trusted with what.

See also: [CONTRIBUTING.md](CONTRIBUTING.md), [STABILITY.md](STABILITY.md), [ARCHITECTURE.md](ARCHITECTURE.md).

---

## The parties

### Consumers

- Anyone using vyre in their application. Zero trust extended; zero required.
- Use the library, get the binary verdict, ship or fix.
- A consumer does not need to read the source, trust the maintainers, or understand the proof system. The only required trust assumption is that `certify()` returns `Ok(Certificate)` only when the backend has passed every gate, oracle, and adversarial check.

### Community contributors

- Anyone submitting a PR.
- Trusted to: add new ops, new laws, new archetypes, new oracles, new gates, new mutations, new backends, new TOML rules.
- NOT trusted to: edit frozen trait signatures, edit the spec crate's public types, delete regression tests, edit law checkers or the mutation catalog.
- CODEOWNERS enforces this via required review on maintainer-only paths.
- Contributors are expected to follow the first-contribution guide in CONTRIBUTING.md and to treat every audit finding as critical.

### Core maintainers (@santhsecurity/core-maintainers)

- Review PRs to maintainer-only paths.
- Approve trait signature changes (require major version bump).
- Approve new frozen type variants in `vyre-spec`.
- Approve crates.io publish.
- Maintainers are the human backstop, not the source of truth. The conformance suite is the source of truth. Maintainers exist to prevent social-engineering attacks on the repository and to enforce the stability contract.

### Backend authors

- Trusted to: publish a backend as a separate crate that implements `VyreBackend`.
- NOT trusted to: mark their own backend as conformant. Only `certify()` determines that.
- The certificate is the trust proof. A backend author may claim their backend is correct, but the claim is worthless without a reproducible certificate issued by `vyre-conform`.

---

## What's trusted, what's verified

Every claim made by a contributor or backend author is VERIFIED, not TRUSTED:

- CPU reference is verified against declared laws (cannot lie about laws).
- Declared laws are verified against the CPU reference (cannot lie about `cpu_fn`).
- GPU kernel is verified byte-for-byte against CPU reference (cannot lie about kernel).
- Composition theorems are proven against declared laws (cannot lie about composition).
- Backend dispatch output is verified against the reference implementation (cannot lie about correctness).
- Category A zero-overhead claims are verified by disassembling the lowered WGSL and comparing instruction counts (cannot lie about optimization).

The trust floor: if `certify()` passes, the backend produces byte-identical output to the CPU reference for every op, every input, every time.

No person is trusted to say "this backend is correct." The only valid statement is "`certify()` produced a certificate for this backend." The certificate includes the exact versions of the ops, the laws, the gates, and the oracles used. It is reproducible and independently verifiable.

---

## Attack surface and mitigations

### Attack: submit a broken `cpu_fn` + matching wrong `wgsl_fn`

A contributor intentionally writes a wrong CPU reference and a wrong WGSL kernel that agree with each other but are both incorrect.

Mitigation: the `reference_trust` enforcer in `vyre-conform` uses differential comparison against independent reference implementations, law-derived probes, boundary probes, and round-trip property checks. A pair-of-wrongs that agree with each other still fails law verification against the declared algebraic laws. The laws are mathematical invariants, not behavioral copies, so colluding errors cannot satisfy them unless they are actually correct.

### Attack: claim Category A composition that is not really zero-overhead

A contributor marks an op as Category A and claims it composes with zero overhead, but the lowered WGSL contains hidden dispatch or allocation overhead.

Mitigation: `check_category_a_zero_overhead` disassembles the lowered WGSL and verifies the instruction count matches the composition reference. Any extra instructions, branches, or memory operations cause a finding. The gate is automated and requires no human judgment.

### Attack: inject a Category B pattern into vyre source

A contributor or compromised dependency introduces `typetag`, `inventory`, `downcast`, `async_trait`, or another forbidden pattern that breaks the closed-enum or static-dispatch invariants.

Mitigation: the CI tripwire scan fails the PR before merge. See `enforce/category/b_tripwire/text_scan.rs` for the exact pattern list. The scan is part of the required check suite and cannot be bypassed without maintainer override.

### Attack: edit a published op's semantics after release

A contributor or maintainer changes the behavior of a published op, invalidating historical certificates silently.

Mitigation: every published op is recorded in the registry with a stable hash. The registry hash in every certificate changes if the op changes. Certificates from year 1 remain verifiable against the op as-it-was-at-year-1. Old certificates do not auto-upgrade to new semantics. See STABILITY.md for the permanence guarantee.

### Attack: delete or weaken a regression test

A contributor removes a test that would catch a known bug, making the suite quieter without making it truer.

Mitigation: CI enforces append-only behavior on regression and corpus paths. Tests may be replaced with stricter tests, but deletion requires maintainer review. The self-audit gate (`conform_self_audit_must_scream`) checks for missing coverage and placeholder tests.

### Attack: social-engineer a maintainer into bypassing review

An attacker convinces a maintainer to force-merge a change that violates frozen contracts.

Mitigation: branch protection requires two maintainer approvals for changes to frozen trait files and the spec crate. CODEOWNERS is configured so that no single maintainer can unilaterally modify the trust boundary. The CI gates run on every merge, including maintainer merges.

### Attack: poison the TOML rule corpus

A contributor adds a malicious or misleading TOML rule that hides a real vulnerability.

Mitigation: TOML rules are scanned, parsed, and executed by the same automated gates as Rust code. A rule that suppresses a finding without fixing the root cause is rejected by the self-audit. Rules are versioned by file and do not override gate logic.

---

## Deprecation process

When an interface or op is superseded, it follows the lifecycle defined in STABILITY.md:

- Marked `#[deprecated]` in version N, with a clear note pointing to the replacement.
- Still compiled, tested, and shipped in versions N+1 and N+2.
- Removed no earlier than 12 months after the deprecation first appears in a stable release.
- Or never removed at all, if removal would break published conformance certificates or violate the stability guarantee.

Deprecation is the tool of last resort. Preference is given to additive replacement: leave the old interface untouched and introduce a new one alongside it. A consumer who earned a certificate in year 1 must be able to verify it in year 5.

---

## Dispute process

A conformance violation is concrete. It includes:

1. Input bytes.
2. Expected bytes.
3. Observed bytes.
4. The law or invariant violated.
5. A `Fix:` hint naming the exact path or change required.

Disputes are resolved by re-running the violation. If the violation reproduces on a clean checkout of the referenced commit, the violation stands. If the violation does not reproduce, the certificate is reissued.

There is no appeal to authority. A maintainer cannot overrule a reproducible violation. The only valid resolution is to change the code so the violation no longer reproduces, or to prove that the violation itself is mathematically impossible (which is itself a code change to the gate or oracle).

---

## Summary of trust boundaries

| Party | Trusted with | NOT trusted with |
|-------|-------------|------------------|
| Consumers | Using the API, shipping certified backends | Nothing internal |
| Community contributors | New ops, laws, gates, oracles, archetypes, mutations, backends, TOML rules | Editing frozen traits, spec types, deleting tests, editing law checkers |
| Core maintainers | Reviewing maintainer-only paths, approving major version bumps, publishing crates | Overruling `certify()`, bypassing CI gates |
| Backend authors | Writing and publishing backend crates | Self-certifying conformance |

The only source of truth is `certify()`. Everything else is human process, and human process is fallible.
