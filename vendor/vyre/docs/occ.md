# Open Conformance Certificates (OCC)

OCC is vyre's trust mechanism. Every op × every backend × every
release ships a signed JSON certificate asserting byte-identity
against the CPU reference on a published witness set. Consumers
verify the badge before binding a dispatch path; a backend without
a valid OCC for an op doesn't execute that op.

## Why

1. **Anti-fraud.** A backend vendor cannot claim conformance without
   proving it; every claim is pinned to a witness corpus and a public
   fingerprint.
2. **Deterministic trust.** Two crates picking the same op over
   different backends can verify they share the same OCC hash before
   dispatching; mixed-backend workflows stay safe-by-construction.
3. **Audit trail.** The certificate carries `tool_version`, `witness_count`,
   `output_hash`, `signer_pubkey`, and `issued_at` — reproducible
   provenance for every byte of GPU work.

## Schema v1

```json
{
  "schema_version": "1",
  "op_id": "vyre-libs::matching::aho_corasick",
  "op_fingerprint": "blake3-64-hex",
  "backend_id": "wgpu",
  "backend_version": "24.0.5",
  "witness_set_fingerprint": "blake3-64-hex",
  "witness_count": 20,
  "output_hash": "blake3-64-hex over (sorted, concatenated witness outputs)",
  "tool_version": "vyre-conform-runner 0.6.0",
  "issued_at": "2026-04-20T00:00:00Z",
  "signer_pubkey": "base64 ed25519 pubkey",
  "signature": "base64 ed25519 signature over all fields above"
}
```

Every field is frozen in the 0.6 series. Extensions go in a
`"extensions": { ... }` map guarded by `#[non_exhaustive]`.

## Where certificates live

1. **Per-crate `certificates/` directory** — dialect crates ship
   OCC JSON alongside the op source. `vyre-libs/certificates/<op>.json`.
2. **Global registry** — `certificates.vyre.dev` (planned) mirrors
   every public OCC by fingerprint. CI uploads on publish.
3. **Embedded in pipeline-cache bundles** — `vyre-pipeline-cache`
   bundles include the OCC as a sibling `<fp>.occ.json` file so
   consumers verify trust at load time.

## Trust policy

- A dispatch MAY reject a backend that doesn't present a valid OCC
  for the requested op × `tool_version`.
- A backend MUST issue a new OCC on every bump to either `backend_version`
  or `op_fingerprint`.
- OCCs are append-only; revocation is a SEPARATE signed "revoked"
  certificate that references the OCC hash being revoked.

## Verifying a certificate

```rust
use vyre_conform_runner::{verify_certificate, Certificate};

let cert: Certificate = serde_json::from_str(&std::fs::read_to_string("x.occ.json")?)?;
verify_certificate(&cert, &trusted_signer_pubkey)?;
// cert.output_hash is trustworthy from here.
```

## Issuing a certificate

```rust
use vyre_conform_runner::{issue_certificate, IssueInput};

let cert = issue_certificate(IssueInput {
    op_id: "vyre-libs::matching::aho_corasick",
    op_fingerprint: &op_fp,
    backend_id: "wgpu",
    backend_version: "24.0.5",
    witnesses: &witness_corpus,
    outputs: &backend_outputs,
    signer: &ed25519_secret_key,
})?;
std::fs::write("vyre-libs/certificates/aho_corasick.occ.json",
    serde_json::to_vec_pretty(&cert)?)?;
```

Post-0.6 the `certificates.vyre.dev` registry gains a queryable API:
`GET /by-op/<op_id>` returns every OCC for that op, filterable by
`backend_id` and `tool_version`.

## Certificates are not OCC replacements

OCC is about trust. The complementary mechanism is the
**pipeline fingerprint** (`blake3(canonicalize(program).to_wire())`)
which identifies an IR *unambiguously* across backends. OCC proves
that for fingerprint X on backend Y, the output is byte-Z.
