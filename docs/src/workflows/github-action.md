# GitHub Action

Use the KeyHog Action when you want to scan one checked-out repository path in a
GitHub Actions job. A published Action ref installs its exact KeyHog crate with
the lean `ci` feature. A reviewed branch or commit ref builds the checked-out
portable source profile and requires `backend: cpu`. Both paths run the scan,
retain the report as a workflow artifact, and upload SARIF to GitHub Code
Scanning by default.

For GitLab, CircleCI, Jenkins, and other CI systems, use the
[CI integration guide](./ci.md). For organization-wide repository or cloud
inventory scans, use the [mass-scanning guide](../guides/mass-scanning.md).

## Scan a repository

Create `.github/workflows/keyhog.yml`:

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

This workflow scans the checked-out working tree. It fails when KeyHog reports a
finding at `high` or `critical` severity. It also fails on configuration,
coverage, backend, installation, and report-publication errors.

The default `sarif` report appears in two places:

- **Security > Code scanning** contains the uploaded SARIF results.
- The workflow run contains a `keyhog-report-*` artifact for later review.

The Action retries one failed Code Scanning upload on trusted pushes and
same-repository pull requests. It fails the job if both attempts fail. GitHub
removes `security-events: write` from fork pull requests, so the upload is
advisory for that event. The workflow artifact is still retained, and findings
still fail the scan.

## Choose the workflow for the source

The Action scans one file or directory already present in the runner workspace.
Use the CLI directly when the scan source needs additional flags.

| Use case | Recommended workflow |
| --- | --- |
| Pull request or push | Action with `path: .` |
| Monorepo partitions | One Action step or matrix job per path, with a unique `analysis-category` |
| Git history or reachable blobs | CLI with `--git-history` or `--git-blobs` after a full checkout |
| GitHub, GitLab, or Bitbucket organization | CLI inventory source in the mass-scanning workflow |
| S3, GCS, or Azure Blob inventory | CLI inventory source in the mass-scanning workflow |
| GitLab, CircleCI, Jenkins, or another CI provider | CLI recipe in the CI integration guide |

Do not use a single repository Action job as an organization-wide inventory
scanner. Inventory scans need explicit partitions, independent reports, source
limits, and retry boundaries.

## Adopt KeyHog without blocking existing findings

Create a baseline from a reviewed local scan:

```sh
keyhog scan . --create-baseline .keyhog-baseline.json
git add .keyhog-baseline.json
git commit -m "chore: add KeyHog baseline"
```

Then pass the committed file to the Action:

```yaml
- uses: santhreal/keyhog@v0
  with:
    path: .
    baseline: .keyhog-baseline.json
```

A baseline suppresses findings it already contains. New findings still fail the
job. Review baseline changes like source changes. Do not regenerate the baseline
inside CI.

An entry matches on the detector and the credential value, never on the file
path. Moving or renaming a baselined file keeps it suppressed, and copying the
same credential into a new file keeps it suppressed too. See
[Baselines](../suppressions.md#baselines-suppress-what-already-existed) for the
complete matching rules and how to retire an entry after rotation.

For an advisory rollout, set `fail-on-findings: 'false'`. Ordinary findings then
remain visible without blocking the job. A verified-live credential and every
operational failure still fail.

```yaml
- uses: santhreal/keyhog@v0
  with:
    path: .
    fail-on-findings: 'false'
```

## Scan a monorepo

Give each partition a stable, unique `analysis-category`. GitHub uses this value
to keep Code Scanning result sets separate across commits.

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

Keep a category unchanged when the partition remains the same. Use a different
category for every KeyHog scan in the same job. A category contains 1 to 64
lowercase letters, digits, dots, underscores, or dashes, and it starts and ends
with a letter or digit.

Add `baseline` per partition when each team reviews its own exceptions:

```yaml
  - uses: santhreal/keyhog@v0
    with:
      path: ${{ matrix.path }}
      analysis-category: ${{ matrix.category }}
      baseline: ${{ matrix.path }}/.keyhog-baseline.json
```

One root baseline works just as well when a single team reviews every
exception, because matching ignores the path. Choose by ownership. The
[CI guide](./ci.md#monorepos-one-baseline-or-several) compares both layouts.

## Select detection policy

The `preset` input selects one detection policy:

| Value | Use it when |
| --- | --- |
| `default` | You want the standard detector, decode, entropy, and confidence policy. |
| `fast` | You accept reduced coverage for a shorter feedback path. |
| `deep` | You want broader recovery and can accept more work and more review. |
| `precision` | You prefer fewer findings and accept lower recall. |

`default` passes no preset flag. A discovered `.keyhog.toml` may therefore select
`fast = true`, `deep = true`, or `precision = true`. An explicit non-default
Action preset takes normal CLI precedence over the file.

`lockdown: 'true'` is separate from the preset. It can be used with `default`,
`deep`, or `precision`. KeyHog rejects `fast` with lockdown instead of weakening
either request. Lockdown requires Linux and enough locked-memory capacity for
the scanner process. Standard GitHub-hosted Linux runners do not currently
provide that capacity. Use a provisioned self-hosted runner when lockdown is a
required control.

## Control credential verification

Verification is off by default:

```yaml
- uses: santhreal/keyhog@v0
  with:
    verify: 'false'
```

The Action always passes either `--verify` or `--no-verify`, so the input
overrides a committed `verify` setting. When verification is enabled, eligible
detectors may send credential or companion material to provider endpoints in a
URL, query, header, or request body. Review the detector corpus and your outbound
trust boundary before setting `verify: 'true'`.

A confirmed live credential exits with code `10` and always fails the Action,
even when `fail-on-findings` is `false`.

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
| `fail-on-findings` | `'true'` | Set to `'false'` to make ordinary findings advisory. |
| `baseline` | empty | Path to a committed KeyHog baseline. |
| `backend` | empty | Published refs install the lean `ci` feature and accept empty/`auto` or `cpu`. Branch and commit source refs require `cpu`. Run `simd` or GPU diagnostics with a separately installed self-hosted CLI binary. |
| `preset` | `default` | Detection policy: `default`, `fast`, `deep`, or `precision`. |
| `lockdown` | `'false'` | Enables Linux memory-locking protections when exactly `'true'`. |

Boolean inputs are strings in GitHub Actions. Use quoted `'true'` and `'false'`.
Invalid values fail before scanning.

The Action wrapper supports four report formats because it validates the report
and finding count before publication. Use the CLI directly for CSV, HTML, JUnit,
GitLab SAST, and envelope formats.

## Outputs

Give the step an `id` before reading its outputs:

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

Check `report-present` before consuming `report`. The report path is private to
the job and disappears during runner cleanup. Do not reconstruct its parent path
or treat it as a persistent artifact. Use the uploaded workflow artifact for
retention across jobs or runs.

## Pin Action code and scanner releases

The floating major ref follows the latest published `v0` release:

```yaml
- uses: santhreal/keyhog@v0
```

Use an exact Action ref when workflow code must change only through review:

```yaml
- uses: santhreal/keyhog@v0.5.74
```

The optional `version` input pins the scanner crate. It does not pin the Action
implementation. Pin both when both contracts must remain fixed.

Release refs install the exact scanner version from crates.io. A missing
version fails the job. A reviewed branch or commit ref builds the portable
source profile with the repository's pinned Rust toolchain and requires
`backend: cpu`. It does not silently substitute source for a missing crate.

## Failure behavior

Treat these states separately:

- `findings > 0` means the scan completed and reported credentials at the chosen
  severity floor.
- `scan-status: partial` means the report contains a coverage gap. Inspect the
  report and raw `exit-code`; do not treat it as clean.
- `scan-status: failed` or `report-present: false` means the Action did not
  publish a trusted report.
- Exit `10` means verification confirmed a live credential. It always blocks.
- Installation, configuration, source, backend, and report validation failures
  remain failures even in advisory mode.

See the [exit-code reference](../reference/exit-codes.md) for the complete CLI
contract and the [output-format guide](../output-formats.md) for report fields.
