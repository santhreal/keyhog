# Certificates

A conformance certificate is the durable proof document produced when
vyre-conform runs against a backend. It records exactly what was tested,
what passed, what failed, and at what strength the verification was
performed. Certificates are archival — they are the evidence that a
backend was conforming at a specific point in time.

## When a certificate is produced

Call `vyre_conform::certify::certify(backend, specs, strength)`. It
returns a `ConformanceCertificate` containing:

- The backend name and version
- The verification strength (FastCheck, Standard, or Legendary)
- Per-track conformance levels (integer, float, approximate)
- Per-operation parity and algebra results
- Engine invariant results (barrier, atomics, wire-format)
- A registry hash binding the certificate to the exact op source

## Certificate tracks

Operations are routed into independent tracks based on their strictness
and output type:

| Track | Operations routed here | Levels |
|---|---|---|
| Integer | Strict ops with integer/byte output | L1 (parity), L2 (algebraic) |
| Float | Strict ops with F16/BF16/F32 output | L1f, L2f |
| Approximate | Ops declared with ULP tolerance | L1a |

Each track is graded independently. A backend can achieve L2 on the
integer track while the float track is at L1f — the tracks do not
block each other.

## Registry hash

The `registry_hash` field is a deterministic fingerprint of every op
spec in the registry. It covers:

- Op identifier (catches typo-squatting)
- Op version (catches monotonic weakening)
- Every declared algebraic law name (catches law drift)
- Input and output data types (catches signature lying)
- The WGSL kernel source text (catches kernel swapping after certification)

Two certificates with different registry hashes were run against
different specs. They are not comparable.

## Verification strength

| Strength | Witnesses per law | Can claim conformance? |
|---|---|---|
| FastCheck | 10,000 | No — explicitly exploratory |
| Standard | 1,000,000 | Yes |
| Legendary | 100,000,000 | Yes — nightly/release gate |

FastCheck is for iteration — "does this op probably work?" Standard is
for CI — "prove it works." Legendary is for release gates — "prove it
works so thoroughly that a silent regression is negligible probability."

## Engine invariants

The certificate includes engine-level results for:

- **I7 — Atomic consistency**: Sequential consistency of atomic
  operations across workgroups.
- **I8 — Barrier visibility**: Post-barrier writes are visible to
  all invocations in the workgroup.
- **I4 — Wire-format equivalence**: Serialized IR round-trips
  byte-for-byte through the backend.

## Verifying a certificate

The `verify-cert` CLI re-reads the current specs, recomputes the
registry hash, and compares it against the certificate's hash:

```bash
cargo run -p vyre-conform --bin verify-cert -- path/to/certificate.json
```

If the registry has changed since the certificate was produced (new ops
added, laws changed, WGSL updated), the hash will differ and the
certificate is no longer valid for the current registry. This is by
design — certificates bind to a specific point in time.

## JSON format

Certificates serialize to JSON via `vyre_conform::certify::to_json()`.
The schema is documented in `coordination/conform-certificate-schema.md`.
The human-readable rendering is produced by `to_human()`.
