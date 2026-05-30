# Changelog

## Unreleased

- Mark `s3_ambient_credential_forward` with `required-features = ["s3"]` so default `keyhog-sources` tests no longer compile an S3-only integration test without the S3 module.
- Move inline helper tests into registered external source tests via a hidden internal test facade, and clear the no-inline/no-production-unwrap gates for filesystem, binary literals/sections, GitHub org, HTTP, and web sources.
- Move GitHub org git-error redaction into `github_org/sanitize.rs`, bringing `github_org.rs` under the 500-line modularity target.
- Move WebSource SSRF/redaction/DNS-pinning helpers into `web/ssrf.rs`, bringing `web.rs` under the 500-line modularity target.
- Move filesystem per-entry extraction into `filesystem/extract.rs` and walker/filter policy into `filesystem/filter.rs`, bringing `filesystem.rs` under the 500-line modularity target and wiring the zip archive skip-list regression into the aggregate source tests.

## 0.2.1

- Align package metadata with the Santh Standard.
- Keep filesystem, archive, git, web, Docker, GitHub, Slack, and S3 source APIs available for the 0.2 line.
