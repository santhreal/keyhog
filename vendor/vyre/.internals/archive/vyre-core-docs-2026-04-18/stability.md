# Stability

vyre is a specification before it is an implementation. Backend authors, op
authors, optimizer authors, serializers, and conformance tools must be able to
depend on a published definition without asking which crate release, GPU vendor,
or lowering path happened to run it. Once a behavior is admitted into the ground
truth specification, that behavior is permanent.

## Immutable Surface

The stable surface is the semantic contract documented in `vyre-conform/SPEC.md`
and mirrored by the public IR data model in `vyre/src/ir`. It includes data type
semantics, binary and unary operation semantics, atomic semantics, program
structure, statement nodes, expression nodes, calling conventions, validation
rules, and conformance levels.

"Stable" means that a valid program continues to mean the same thing forever.
The lowered code may improve, optimizers may become stronger, runtimes may
dispatch differently, and new backends may appear, but the output bytes required
for a given valid program and input are unchanged.

The following classes of change are forbidden for stable entries:

- Reinterpreting an existing `DataType`.
- Changing the result of an existing `BinOp`, `UnOp`, `AtomicOp`, node, or
  expression.
- Changing a validation rule so that an already valid program gains different
  semantics.
- Reusing an existing op identifier for different behavior.
- Reusing an existing calling convention version for different bindings.
- Removing a documented enum variant, op, or calling convention.

## Versioning Policy

vyre uses additive semantic versioning at the specification layer. A spec
version is a named set of permanent entries. Implementations may lag behind the
latest spec, but they must declare the exact spec entries they implement and
must not claim conformance for entries they do not support.

A behavior change to an operation increments that operation's `version()`.
`primitive.bitwise.xor` version 1 and `primitive.bitwise.xor` version 2 are
different conformance targets even if they share most implementation code. A
backend certificate must record both the op identifier and the op version.

Crate versions are release packaging. They do not override spec stability. A
crate may add a faster WGSL lowering in a patch release, but it may not change
the meaning of `Div(a, 0)` in any release without adding a new spec entry.

## Additions

New behavior is added by adding a new entry. Additions are allowed when they do
not change the meaning of any existing valid program.

Valid additions include:

- A new `DataType` variant with fully specified size, representation, casts, and
  lowering requirements.
- A new `BinOp`, `UnOp`, `AtomicOp`, node, or expression variant with complete
  CPU reference semantics.
- A new operation identifier under the standard library hierarchy.
- A new op version for behavior that intentionally differs from an older op.
- A new calling convention version.
- A new lowering target.
- A new conformance law, invariant, generator, or certificate field.

Every addition must include conformance coverage. An operation addition must
define a CPU reference, algebraic laws where applicable, equivalence classes,
boundary values, and deterministic input generation. An IR addition must define
validation behavior, CPU reference behavior, and lowering obligations.

## Deprecation

Deprecated entries remain valid. Deprecation is a warning to authors that a
newer entry should be preferred; it is not permission for a backend to reject an
old program.

A deprecated entry must keep:

- Its identifier or numeric value.
- Its original semantics.
- Its validation behavior.
- Its conformance tests.
- Its lowering obligation for any backend claiming the spec level that contains
  it.

Documentation may mark why an entry is deprecated and which replacement should
be used. The replacement must be additive. Existing serialized programs,
IR wire format blobs, certificates, and op graphs must continue to decode and
execute.

## Never Remove

No stable entry is removed from the specification. If a definition is discovered
to be wrong, the fix is a new versioned definition plus a deprecation note on the
old one. The old entry remains testable because deployed programs and
certificates may depend on it.

This rule is stricter than ordinary library compatibility. GPU backends may be
implemented independently by organizations that do not share release schedules.
Removing a spec entry would turn a valid backend into a broken backend without
any defect in that backend's code.

## Why Stability Matters

The IR is the contract between frontends and backends. A frontend can emit vyre
IR only if it knows that every conforming backend will run that IR with the same
meaning. A backend vendor can invest in a lowering only if the target semantics
will not move underneath it.

Stability also makes conformance meaningful. A certificate is useful only when
the tested target is fixed. If `BitXor` or `Store` can change after
certification, a past certificate stops proving anything. By making spec entries
permanent, vyre makes old certificates interpretable, old programs executable,
and independent backends comparable byte-for-byte.

## The golden freeze

Published operation behavior is enforced by **golden samples** — frozen
input/output pairs computed from the CPU reference at publication time.
Once frozen, a golden sample is permanent. If a future change to the
CPU reference produces different output for a frozen input, the build
fails.

Golden samples are stored in `conform/goldens/<op_id>/v<version>/`.
Each file is a JSON document containing the input bytes, expected
output bytes, and a SHA-256 hash for integrity. The `freeze-goldens`
binary generates them; the `golden_samples` test verifies them.

This is how "what is published is permanent" becomes a mechanical
guarantee rather than a social convention. You cannot change what an
op produces for a given input without either:

1. Incrementing the version (which creates a new golden set), or
2. Breaking the build (which blocks the PR).

The golden freeze is the vyre equivalent of a sealed court record.
Once entered, it cannot be altered without creating a visible,
auditable new version.
