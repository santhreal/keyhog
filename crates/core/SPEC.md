# keyhog-core SPEC

`keyhog-core` defines the shared data model for KeyHog. It owns detector specifications, match and finding types, source traits, allowlist handling, report structures, and detector validation.

## Guarantees

- Detector specifications are validated before scanner use.
- Credential hashes and allowlist checks are deterministic.
- Explicit report-safe DTOs and versioned envelopes are serializable for CLI and downstream tooling. Secret-bearing `Credential`, `SensitiveString`, `RawMatch`, `DedupedMatch`, and `Chunk` reject implicit serialization; any protected internal transport must use a private, explicit adapter at its authenticated boundary.
- Error paths return typed errors with actionable messages where exposed through public APIs.

## Boundaries

This crate does not scan input, verify credentials, or enumerate sources. Scanner execution lives in `keyhog-scanner`; live verification lives in `keyhog-verifier`; source enumeration lives in `keyhog-sources`.
