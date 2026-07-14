# KeyHog GitHub Action

Use this complete job to scan checked-out repository content and upload SARIF:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: santhreal/keyhog/.github/actions/keyhog@v0.5.41
```

The Action scans the checked-out workspace, fails on `high` or above, writes
SARIF, uploads it to Code Scanning, and attaches the report as a workflow
artifact. The job summary includes the scan path, severity floor, report name,
raw exit code, finding count, and scan duration.

With `upload-sarif: 'true'`, Code Scanning
upload failures fail closed on trusted pushes and same-repo PRs. Fork PRs can
lack `security-events: write`; those upload failures stay advisory and the
SARIF report remains attached as a workflow artifact. Trusted upload failures
also keep the artifact so the failed job is still diagnosable.

Set `upload-sarif: 'false'` when the workflow cannot grant
`security-events: write`. The artifact upload remains available.

`analysis-category` is the stable identity for one Code Scanning partition.
Keep it unchanged across commits so GitHub updates that partition. Give every
KeyHog scan of the same commit a distinct category so monorepo and matrix
results coexist instead of replacing each other. Duplicate categories in one
workflow fail through SARIF or artifact upload. Categories use 1-64 lowercase
letters, digits, dots, underscores, or dashes and start and end alphanumeric.

```yaml
- uses: santhreal/keyhog/.github/actions/keyhog@v0.5.41
  with:
    path: services/api
    analysis-category: services-api

- uses: santhreal/keyhog/.github/actions/keyhog@v0.5.41
  with:
    path: services/web
    analysis-category: services-web
```

## Full reference

Keep the checkout step and permissions from the complete job above, then add
inputs to the KeyHog step:

```yaml
- uses: santhreal/keyhog/.github/actions/keyhog@v0.5.41
  with:
    path: .                     # file or directory to scan
    severity: high              # info | low | medium | high | critical
    format: sarif               # text | json | sarif | jsonl
    verify: 'false'             # 'true' to live-verify credentials
    upload-sarif: 'true'        # 'false' to keep the report local-only
    analysis-category: keyhog   # stable and unique per scan partition
    fail-on-findings: 'true'    # 'false' makes unverified findings advisory;
                                # verified-live credentials still fail
    baseline: ''                # path to a committed baseline file; only NEW
                                # findings (absent from the baseline) fail the job
    version: ''                 # pin a specific release (default: action ref)
```

### Adopting on a repo that already has findings

Generate a baseline once, commit it, then point the action at it. The job
then blocks only **new** secrets instead of failing on the existing backlog:

```bash
keyhog scan --create-baseline keyhog-baseline.json
git add keyhog-baseline.json && git commit -m "chore: keyhog baseline"
```

```yaml
- uses: santhreal/keyhog/.github/actions/keyhog@v0.5.41
  with:
    baseline: keyhog-baseline.json
```

## Outputs

```yaml
- id: keyhog
  uses: santhreal/keyhog/.github/actions/keyhog@v0.5.41
  with:
    fail-on-findings: 'false'

- name: Comment on PR if anything found
  if: steps.keyhog.outputs.findings != '0'
  run: gh pr comment ${{ github.event.number }} -b "KeyHog flagged ${{ steps.keyhog.outputs.findings }} potential secret(s)."
```

| Output | Description |
| --- | --- |
| `findings` | Number of findings at or above `severity`. |
| `exit-code` | Raw `keyhog` process exit: `0` clean, `1` findings, `10` live findings under `--verify`. |
| `duration-ms` | Wall-clock scan duration in milliseconds from the action wrapper. |
| `report`   | Path to the produced report file. |
| `analysis-category` | Validated identity shared by Code Scanning, the report filename, and the artifact. |

## Runtime and dependencies

| Resource | Value |
| --- | --- |
| Prebuilt binary download | Release binary plus `.sha256`; checksum verified before execution |
| Scan duration | Reported by the Action as `duration-ms`; varies by host, cache, config, and input |
| Runtime dependencies | `libhyperscan5` (auto-installed via apt on Ubuntu runners); none on macOS/Windows |
| Toolchains required | none for release-tag prebuilts; Rust only for branch/SHA source builds |
| GPU | optional; the Action parity-checks eligible backends on the exact requested workload and persists the fastest correct route |

Before the report scan, the Action resolves the effective configuration and
runs one throwaway calibration scan. Calibration reads incremental state for
exact workload filtering but never persists Merkle cache changes, so the report
scan receives the same cache state and input workload.

No Python, no JVM, no Docker daemon. Single static binary plus the
auto-installed Hyperscan shared library on Linux.

## Platforms

| OS | arch | Prebuilt binary | Branch/SHA source build |
| --- | --- | --- | --- |
| Linux | x86_64 | yes (full features) | yes |
| macOS | aarch64 | yes (no Hyperscan) | yes (`portable` feature) |
| macOS | x86_64 | yes (no Hyperscan) | yes (`portable` feature) |
| Windows | x86_64 | yes (portable feature set) | yes (`portable` feature) |

Release tags and explicit `version:` inputs require a matching prebuilt binary
and checksum; missing or unverifiable release assets fail closed instead of
silently source-building different code. Branch/SHA action refs may build from
source. The Action intentionally uses the portable feature set for both macOS
prebuilts and branch/SHA source fallbacks. A manual macOS source build can use
Hyperscan after `brew install vectorscan pkg-config`; that is a different build
from the Action asset. Both include entropy, multiline reassembly, ML scoring,
decode-through, and the portable git, web, hosted-Git, cloud, and Docker source
backends. Ghidra binary extraction remains opt-in and is absent from the
portable asset.

## Recipes

See [integration recipes](../../../docs/src/workflows/integrations.md) for
pre-commit hooks, Husky, lefthook, GitLab CI, CircleCI, Drone, Jenkins,
BuildKite, Docker, library integration, and SARIF/Slack/Discord
webhook recipes.
