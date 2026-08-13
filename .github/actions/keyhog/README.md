# KeyHog GitHub Action

Use this Action to scan one checked-out file or directory. It installs an
authenticated KeyHog release, validates the report, retains a workflow artifact,
and uploads SARIF to GitHub Code Scanning by default.

For the complete workflow guide, see
[GitHub Action](../../../docs/src/workflows/github-action.md). For organization
inventories and cloud sources, use
[Mass scanning](../../../docs/src/guides/mass-scanning.md).

## Scan a repository

```yaml
name: keyhog

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: santhreal/keyhog@v0
        with:
          path: .
          severity: high
```

This job scans the working tree and fails on findings at `high` or `critical`
severity. It also fails on installation, configuration, source coverage,
backend, and report-publication errors.

The default `sarif` report is uploaded to Code Scanning and retained as a
workflow artifact. Set `upload-sarif: 'false'` when the job cannot grant
`security-events: write`; the artifact remains enabled. The Action retries one
failed upload on trusted pushes and same-repository pull requests, then fails
closed if both attempts fail. Fork PRs can lack `security-events: write`, so
their upload failure is advisory. Findings and operational failures still fail
the job.

The Action accepts one checked-out path. Use the KeyHog CLI directly for Git
history, reachable blobs, hosted Git organizations, cloud buckets, and report
formats that the Action does not expose.

## Inputs

| Input | Default | Contract |
| --- | --- | --- |
| `path` | `.` | Checked-out file or directory to scan. |
| `severity` | `high` | Minimum reported tier: `info`, `client-safe`, `low`, `medium`, `high`, or `critical`. |
| `format` | `sarif` | Action report format: `text`, `json`, `sarif`, or `jsonl`. |
| `verify` | `'false'` | Enables provider verification only when exactly `'true'`. |
| `version` | empty | Scanner release selected by the Action ref. A value pins one canonical final `vX.Y.Z` release. |
| `upload-sarif` | `'true'` | Uploads Code Scanning results when `format` is `sarif`. The artifact is retained independently. |
| `analysis-category` | `keyhog` | Stable identity for one report and Code Scanning partition. |
| `fail-on-findings` | `'true'` | Set to `'false'` to make ordinary findings advisory. Verified-live credentials and operational errors still fail. |
| `baseline` | empty | Path to a committed KeyHog baseline. |
| `backend` | empty | Release refs use calibrated `auto` when empty. Other values are `cpu`, `simd`, `gpu-cuda`, and `gpu-wgpu`. |
| `preset` | `default` | Detection policy: `default`, `fast`, `deep`, or `precision`. |
| `lockdown` | `'false'` | Enables Linux memory-locking protections when exactly `'true'`. |

Boolean inputs are strings. Use quoted `'true'` and `'false'`. Invalid values
fail before scanning.

`default` passes no preset flag, so a discovered `.keyhog.toml` may choose one
preset. An explicit `fast`, `deep`, or `precision` input takes normal CLI
precedence. Lockdown is independent and works with default, deep, or precision.
KeyHog rejects fast with lockdown. Lockdown requires a provisioned Linux runner
with enough locked-memory capacity; standard GitHub-hosted Linux runners do not
currently provide it.

Verification is explicit credential data egress. Eligible detector policy may
send credential or companion material to provider endpoints in a URL, query,
header, or body. Review the detector corpus and outbound trust boundary before
setting `verify: 'true'`. A verified-live credential exits `10` and always
fails, including when `fail-on-findings` is `false`.

## Outputs

Give the Action step an `id` before reading outputs:

```yaml
- id: keyhog
  uses: santhreal/keyhog@v0
  with:
    fail-on-findings: 'false'

- name: Record the finding count
  env:
    KEYHOG_FINDINGS: ${{ steps.keyhog.outputs.findings }}
  run: printf 'KeyHog findings: %s\n' "$KEYHOG_FINDINGS"
```

| Output | Meaning |
| --- | --- |
| `findings` | Number of reported findings at or above the severity floor. |
| `exit-code` | Raw KeyHog exit code. Common results are `0` clean, `1` findings, `10` verified-live findings, and `13` incomplete coverage. |
| `duration-ms` | Wrapper wall-clock scan duration in milliseconds. |
| `scan-status` | Wrapper state: `success`, `partial`, `cancelled`, or `failed`. |
| `report-present` | `true` only when the Action published a receipt-verified private report snapshot. |
| `report` | Private report snapshot path available to later steps in the same job. |
| `analysis-category` | Validated report and Code Scanning partition identity. |

Check `report-present` before consuming `report`. The path exists only for the
current runner job. Use the uploaded artifact for retention across jobs or runs.
A `partial` status records incomplete coverage and is not a clean result.

## Adopt an existing repository

Create and review a baseline locally:

```sh
keyhog scan . --create-baseline .keyhog-baseline.json
git add .keyhog-baseline.json
git commit -m "chore: add KeyHog baseline"
```

Then pass it to the Action:

```yaml
- uses: santhreal/keyhog@v0
  with:
    baseline: .keyhog-baseline.json
```

The baseline suppresses findings it already contains. New findings still fail.
Do not regenerate the baseline inside CI.

## Scan a monorepo

Use a stable `analysis-category` for each partition:

```yaml
strategy:
  matrix:
    include:
      - path: services/api
        category: services-api
      - path: services/web
        category: services-web

steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  - uses: santhreal/keyhog@v0
    with:
      path: ${{ matrix.path }}
      analysis-category: ${{ matrix.category }}
```

A category contains 1 to 64 lowercase letters, digits, dots, underscores, or
dashes. It starts and ends with a letter or digit. Keep it unchanged across
commits so GitHub updates the same Code Scanning partition.

## Pin releases

`santhreal/keyhog@v0` follows the latest published `v0` Action. Use
`santhreal/keyhog@v0.5.72` when Action code must stay fixed. The optional
`version: v0.5.72` input pins only the scanner crate, so it is not a substitute
for pinning the Action ref.

Release refs install the exact published crate from crates.io. A missing crate
fails the job. A reviewed branch or commit ref builds the portable source
profile and requires `backend: cpu`; it does not replace a missing published
version with the checked-out source.
