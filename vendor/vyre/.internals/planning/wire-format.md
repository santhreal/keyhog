# Vyre Wire Format

> Authoritative spec for `Program::to_wire` and `Program::from_wire`.
> Implementations of this format outside `vyre-ir` must match this
> document byte-for-byte. A deviation is a spec bug, not a freedom.

## Motivating constraint

The IR graph holds `Box<dyn NodeKind>` trait objects in its `Extern`
escape hatch (plus the hot-path tagged union `NodeStorage` for common
ops). Neither serializes directly — `Box<dyn Trait>` has no stable
layout and the tagged union enum carries no schema version.

Serialization therefore goes through a shape that (a) carries a schema
version so old consumers can refuse new payloads gracefully, (b) names
each node by a stable `OpId` so a third-party crate that registers a
custom primitive can round-trip its Programs, (c) tolerates the plugin
registry at deserialization time (the deserializer knows how to fail
clearly when a linked binary lacks the plugin that wrote the payload).

## Shape

```text
Wire := Header || Nodes || MemoryRegions || OutputSet

Header := {
    magic: [u8; 4]            // "VYRE"
    schema_version: u16        // currently 1, increments on every non-additive change
    flags: u16                 // bit 0: compressed; bit 1: sealed with signature; bits 2-15 reserved
    program_blake3: [u8; 32]   // blake3 of Nodes || MemoryRegions || OutputSet (NOT including header)
}

Nodes := LebU64 (count) || Node*

Node := {
    op_id: LenPrefixedStr       // identifier from the NodeKindRegistration, e.g. "vyre.bin_op" or "yaragpu.rule_match"
    payload_len: LebU64
    payload: [u8; payload_len]  // op-specific payload — the NodeKindRegistration::serialize produces this
    operand_count: LebU64
    operand_ids: [LebU32; operand_count]  // indices into the Node table (not pointers)
}

MemoryRegions := LebU64 (count) || MemoryRegion*

MemoryRegion := {
    id: LebU32
    kind: u8                   // discriminant: 0=Global 1=Shared 2=Uniform 3=Local 4=Readonly 5=Push
    access: u8                 // discriminant: 0=Read 1=Write 2=ReadWrite 3=Atomic 4=Shared
    element: u8                // DataType discriminant
    shape_tag: u8              // 0=Dense 1=Sparse 2=VarLen 3=CSR
    shape_payload_len: LebU64
    shape_payload: [u8; shape_payload_len]
    hints_payload_len: LebU64
    hints_payload: [u8; hints_payload_len]
}

OutputSet := LebU64 (count) || LebU32*  // node indices that produce program outputs

LebU64: variable-length unsigned integer (LEB128)
LebU32: variable-length unsigned 32-bit (up to 5 bytes)
LenPrefixedStr: LebU64 (byte length) || UTF-8 bytes
```

Fields not named here do not exist in the wire. An implementation that
adds a field must bump `schema_version` and provide a migration path
that fills the new field with a documented default when reading an old
payload.

## Round-trip contract

```rust
// Always holds:
assert_eq!(Program::from_wire(&program.to_wire()?)?, program);
```

A Program that deserializes but does not re-serialize to the identical
bytes is a spec bug — there is exactly ONE canonical encoding per
Program. Writers never emit the "compressed" flag (bit 0) unless the
caller explicitly opted in; readers accept either.

## Deserialization errors

Every failure mode has a structured variant in `WireError` with a
`Fix:` message. Non-exhaustive:

- `UnknownOp { op_id, fix }` — the node's `op_id` has no matching
  `NodeKindRegistration`. The fix message names the op id and points
  the caller at the crate they probably need to link.
- `UnknownSchemaVersion { found, supported, fix }` — the payload was
  written by a newer Vyre.
- `IntegrityMismatch { expected, actual, fix }` — the `program_blake3`
  in the header does not match the recomputed hash; the payload was
  truncated or tampered.
- `MagicMismatch { found, fix }` — the payload does not begin with
  `"VYRE"`.
- `TruncatedPayload { at, fix }` — a LEB128 or length-prefixed field
  ran past the end of the buffer.
- `InvalidDiscriminant { field, value, fix }` — a kind/access/element
  byte was outside the defined set (e.g. `kind=7`).

## Capability negotiation integrates here

`Backend::execute(program, inputs, config)` begins by calling
`validate_program(program, self)` (see `docs/memory-model.md` and
ARCHITECTURE.md Law C). The validator iterates `program.nodes()` and
checks each `op_id` against `backend.supported_ops()`. An op the
backend does not support produces `ValidationError::UnsupportedOp`
with a clear error message — *before* the wire format or any
substrate machinery runs. Deserialization and capability negotiation
are complementary guards: the former catches "the bytes are
meaningful," the latter catches "the meaningful bytes can run here."

## Versioning

Every non-additive change to this document bumps `schema_version`.
Additive changes (new NodeKind variants registered via inventory,
new MemoryKind discriminants reserved in advance) do not bump the
version, because they already pass through the opaque `payload` bytes
and are gated on the registry at deserialization.

The migration table from version N to N+1 lives in
`vyre-ir/src/wire/migrate.rs` and is tested by
`vyre-ir/tests/wire_migration.rs`. A test that inserts a v_N payload
and asserts a round-trip through v_{N+1} back to v_N must preserve
every v_N-supported concept.

## What this format does NOT carry

- Backend-specific compiled artifacts (wgpu pipeline handles, CUDA
  PTX, Metal library blobs). Those are *caches*, not *programs*; they
  live in `vyre-wgpu/src/pipeline_disk_cache.rs` and are not portable
  across machines.
- Dispatch configuration (`workgroup_size`, profile string, ULP
  budget, timeout). Those are per-dispatch decisions that belong in
  `DispatchConfig`, not in the Program.
- Backend capability metadata. Which backends can run this Program
  is a runtime query against the registered `BackendRegistration`
  set, not a field in the Program itself.
- Diagnostic / replay metadata. Replay logs carry Program-bytes +
  inputs + outputs separately (`vyre-conform/src/runner/replay.rs`).

## Security posture

The wire format is an untrusted input boundary. A malicious payload
may claim arbitrary `payload_len` values, craft operand cycles, or
encode node counts that would exhaust memory if naively allocated.
`Program::from_wire` enforces:

- Maximum Program size in bytes (`MAX_WIRE_BYTES = 64 MiB` default,
  configurable via `DispatchConfig::max_wire_bytes`).
- Operand ids must be in bounds of the preceding Node table —
  forward references, negative indices, and out-of-range indices
  reject as `TruncatedPayload`.
- No operand id may equal the node's own index (self-loops forbidden).
- LEB128 parsing is bounded — a payload crafted to loop indefinitely
  is cut off at 10 bytes per integer.

Violations are errors, not panics. `Program::from_wire` never panics
on any input, valid or adversarial.

---

## Rev 3 (current)

`WIRE_FORMAT_VERSION = 3`. Changes from rev 1 (rev 2 was never
released):

1. **Structured version-mismatch surfacing.** A payload whose
   `VERSION` bytes don't equal `3` surfaces
   `Error::VersionMismatch { expected, found }` (diagnostic code
   `E-WIRE-VERSION`) instead of being absorbed into the generic
   `WireFormatValidation` bucket. Tooling that hangs off stable
   codes can now tell "you're on the wrong version" apart from
   "your bytes are malformed."
2. **New error variants** for dialect-level drift:
   * `Error::UnknownDialect { name, requested }` — the payload
     references a dialect the runtime does not know. Code
     `E-WIRE-UNKNOWN-DIALECT`.
   * `Error::UnknownOp { dialect, op }` — the dialect is known but
     the specific op is not. Code `E-WIRE-UNKNOWN-OP`.
3. **Deprecation warnings surface structurally.** An op marked
   `Deprecation::new(...)` in the `migration` inventory produces a
   `Diagnostic { severity: Warning, code: "W-OP-DEPRECATED" }`
   alongside successful decode — the payload still decodes.
4. **Op versioning + migration table.** Per-op version migrations
   (attribute rename, attribute default fill-in) register via
   `Migration::new(...)` and apply chain-wise during decode. See
   [dialect-cookbook.md](dialect-cookbook.md) for the recipe.

The frame shape (magic, 16-bit version, 16-bit flags, 32-byte
digest, LEB128 body) is unchanged from rev 1 — rev 3's changes are
behavioral, not structural. That's deliberate: rev-1 encoders can
still produce byte streams a rev-3 decoder would have to reject on
version alone, so there's no worth in reshuffling the framing.

A future rev 4 that adds the dialect-manifest section (described
in the original plan) will change the frame — that's the next bump
and it's backwards-compatible via the version gate.

## Diagnostic codes surfaced by the wire format

* `E-WIRE-VERSION` — schema version mismatch.
* `E-WIRE-UNKNOWN-DIALECT` — the payload's dialect manifest
  references a dialect this runtime does not know.
* `E-WIRE-UNKNOWN-OP` — the payload references an op the runtime's
  dialect does not register.
* `E-WIRE-VALIDATION` — generic bucket for bounds / framing / tag
  failures (covered by the specific errors above first).
* `W-OP-DEPRECATED` — op is deprecated since a specific version.

See `vyre-core/src/diagnostics.rs` for the stable catalog of
codes; see [`docs/catalogs/op-id-catalog.md`](catalogs/op-id-catalog.md)
for the pinned set of op ids.
