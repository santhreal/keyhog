# vyre Semver Policy

This document is binding. Every vyre crate follows
[Semantic Versioning 2.0.0](https://semver.org/) with the amendments
below. A release that violates these rules is a defect — file a YANK
request via `scripts/publish-dryrun.sh --yank-reason`.

## Scope

The policy applies to every crate published from this workspace:

- `vyre` (vyre-core library) — semver-major
- `vyre-spec` — semver-major
- `vyre-macros` — semver-minor allowed
- `vyre-reference` — semver-minor allowed
- `vyre-primitives` — semver-major
- `vyre-driver-wgpu`, `vyre-driver-spirv` — per-backend semver
- `vyre-conform-*` — semver-minor (testing crates; API churn allowed)
- `vyre-libs` / future `vyre-libs-*` façades — semver follows `vyre`

## What counts as a breaking change

A breaking change requires a major-version bump on the affected crate.

### Unambiguous breaking changes

- Removing or renaming any public item (type, function, trait, method,
  const, module, feature flag, macro).
- Changing the signature of a public function, trait method, or macro.
- Adding a required trait method without a default impl.
- Changing the value of a `pub const` that downstreams embed literally.
- Changing wire-format bytes (§12).
- Removing, renaming, or reusing a stable error code (`V###`, `E-*`,
  `W-*`, `B-*`, `C-*`). See `docs/error-codes.md`.
- Changing any of the seven frozen contracts listed in
  `docs/frozen-traits/`.
- Changing the behavior of a method in a way that breaks an existing
  caller (e.g., tightening an argument's accepted domain).

### Additive changes that stay minor

- Adding a new method to a trait **with a default impl**.
- Adding a new variant to a `#[non_exhaustive]` enum **plus** any
  required match-arm handling in consumer crates.
- Adding a new public item (function, struct, module, constant) that
  doesn't overlap an existing name.
- Adding a new `Opaque` extension id (open IR does not bump major).
- Adding a new inventory collection.
- Adding a new `AlgebraicLaw` variant (only if the existing variants'
  discriminants stay stable).
- Widening an accepted input domain (inverse of the breaking case
  above).

## Extension-surface additivity

The open-IR contract (§1) is explicit:

> **Every API-visible `Opaque` variant is additive-only.**

The `DataType::Opaque(ExtensionDataTypeId)`, `BinOp::Opaque(...)`,
`UnOp::Opaque(...)`, `AtomicOp::Opaque(...)`, `RuleCondition::Opaque(...)`
variants are frozen in name. Their payload types (the `ExtensionXxxId`
tuple structs) are frozen in layout. Adding a new `Opaque` variant to
another IR enum in the future is a minor bump *only if*:

1. The enum is already `#[non_exhaustive]`.
2. The new `Opaque` stores only `ExtensionId`-compatible payload.
3. Wire format assigns the `0x80` extension tag space (see `wire-format.md`).

## Inventory collections

- Adding a new inventory collection (new `inventory::collect!(T)`) is a
  **minor** bump. Consumers opt in by declaring `inventory::submit!`.
- Changing the struct shape of an existing registration type is a
  **major** bump — every downstream `inventory::submit!` block depends
  on the field layout.
- Deprecating a collection is a major bump because consumers must
  migrate their registrations.

## Wire format

- Adding an `Opaque` tag (high-bit range `0x80..0xFFFFFFFF`) is additive.
- Adding a new concrete DataType/BinOp/UnOp/AtomicOp tag is **major**
  because older decoders reject unknown tags.
- Bumping the VIR0 version header is a major bump on `vyre` and every
  backend crate.

## Error codes

- Adding a new code is a minor bump.
- Removing a code is major.
- Renaming a code is major (retired codes leave a stub row in
  `docs/error-codes.md` for historical reference).
- Changing a code's *meaning* is a breaking change even if the string
  stays the same — tooling hangs rules off the code.

## Frozen contracts

The seven traits/enums in `docs/frozen-traits/` must not drift. Changes
require:

1. A deliberate major-version bump on the owning crate.
2. Running `scripts/check_trait_freeze.sh --refresh-snapshots` to update
   the snapshot.
3. A CHANGELOG entry naming the new/removed/changed signature.
4. A migration path for downstream implementors (new trait + default
   impl delegating to the old; never delete a method).

## Yanking

Publish a `X.Y.(Z+1)` with the fix and file a retroactive yank against
`X.Y.Z` via `cargo yank --version X.Y.Z <crate>`. Include the yank
reason in the CHANGELOG under a `## Yanked releases` section.

## Coordinated releases

A single release usually bumps multiple crates together. The
workspace-level `Cargo.toml` `[workspace.package]` version is the
vyre-wide release number; individual crates may lag when they don't
need a change.

For a coordinated major-version release:

1. Update `CHANGELOG.md` with a `## vX.0.0` section.
2. Update `[workspace.package].version` in `Cargo.toml`.
3. Run `scripts/publish-dryrun.sh` and verify every crate passes.
4. Tag `vX.0.0` on the main branch.
5. `cargo publish` each crate in the order listed in
   `scripts/publish-dryrun.sh` (dependency-respecting).
