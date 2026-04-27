# vyre — Stability Policy

This document is the binding contract between the vyre project and its users, contributors, and downstream dependents. It applies from the 1.0 release onward.

---

## The contract

The following interfaces and invariants are frozen for the entire duration of a major version series. They change only at a major version boundary.

- **6 frozen trait signatures never change within a major version.** `VyreBackend`, `Finding`, `EnforceGate`, `Oracle`, `Archetype`, and `MutationClass` are defined in `ARCHITECTURE.md`. Method names, argument types, and return types are stable. New methods may be added only with a default implementation, which does not require implementors to update their code.
- **Cat A/B/C category discipline is permanent.** The semantic meaning of Category A (algebraic / CPU-provable), Category B (implementation-defined / observable), and Category C (hardware-dependent / intrinsic) will not be redefined within a major version.
- **`certify()` signature is permanent.** The function `pub fn certify(backend: &dyn VyreBackend) -> Result<Certificate, Violation>` and the public types `Certificate` and `Violation` retain their definitions and observable behavior for the lifetime of the major version.
- **Published `AlgebraicLaw` variants (24) are permanent.** The 24 laws published at 1.0 retain their exact semantic meaning. Adding a new law variant is a minor version bump. Removing or altering the meaning of an existing law variant is a major version bump. The enum is marked `#[non_exhaustive]` to permit additive growth.

---

## What may grow

The following additions are explicitly allowed in any minor or patch release:

- **New ops.** Added via the file-per-op model and discovered by `automod` and `build_scan`. New op ids do not conflict with existing ids.
- **New laws.** Added as variants to the `#[non_exhaustive]` `AlgebraicLaw` enum.
- **New archetypes, new gates, new oracles, new mutations.** Added as single files in their respective responsibility directories with a `REGISTERED` const.
- **New backends.** Implemented as additional `VyreBackend` trait implementations. Registration is opt-in and additive.

---

## What will never be removed

The following guarantees hold for the lifetime of the major version and, where noted, indefinitely:

- **A published op's id + signature + `cpu_fn` remain stable.** If an op is found to be flawed, it is marked deprecated. It is never deleted, because removal would invalidate historical certificates and dependent code.
- **A published law's meaning is permanent.** Once a law variant is public, its mathematical interpretation is fixed. Reinterpretation requires a major version bump.
- **A conformance certificate from year 1 remains verifiable in year 5.** The certificate format, the verification algorithm, and the reference oracles needed to re-run a certificate are preserved for at least 5 years from the date of issuance.

---

## Deprecation policy

When an interface or op is superseded, it follows this lifecycle:

- Marked `#[deprecated]` in version N, with a clear note pointing to the replacement.
- Still compiled, tested, and shipped in versions N+1 and N+2.
- Removed no earlier than 12 months after the deprecation first appears in a stable release.
- **Or never removed at all**, if removal would break published conformance certificates or violate the stability guarantee.

Deprecation is the tool of last resort. Preference is given to additive replacement: leave the old interface untouched and introduce a new one alongside it.

---

## Breaking changes

A breaking change to any item in "The contract" section requires all of the following:

- A major version bump (e.g., 1.x to 2.0).
- 3 months' advance notice posted on the GitHub release page before the breaking release ships.
- A migration guide published in `CHANGELOG.md` that covers every affected public API.
- A compatibility crate (`vyre-compat-{version}`) providing the old behavior, maintained for at least 1 year after the major release.

If a change cannot satisfy all four requirements, it does not ship.

---

*This policy is enforced by CI gates, reviewed in every release, and binding on all maintainers. When in doubt, preserve the old behavior.*

