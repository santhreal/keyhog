# keyhog-core SPEC

`keyhog-core` defines the shared data model for Keyhog. It owns detector specifications, match and finding types, source traits, allowlist handling, report structures, and detector validation.

## Guarantees

- Detector specifications are validated before scanner use.
- Credential hashes and allowlist checks are deterministic.
- Public output types are serializable for CLI and downstream tooling.
- Error paths return typed errors with actionable messages where exposed through public APIs.

## Boundaries

This crate does not scan input, verify credentials, or enumerate sources. Scanner execution lives in `keyhog-scanner`; live verification lives in `keyhog-verifier`; source enumeration lives in `keyhog-sources`.
