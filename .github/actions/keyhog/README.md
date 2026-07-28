# KeyHog GitHub Action

> **Release candidate:** the orthogonal `preset` and `lockdown` inputs documented
> here ship with 0.5.48. They are not in the current public `v0` release yet.
> Use the `@v0` examples after the publication verifier proves that `v0` points
> to `v0.5.48`; until then, test this contract only from a reviewed source ref.

This complete Marketplace workflow scans checked-out repository content,
uploads SARIF, and retains the report:

```yaml
# .github/workflows/keyhog.yml
name: keyhog
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - id: keyhog
        uses: santhreal/keyhog@v0
        with:
          path: .
          severity: high
          format: sarif
          preset: default
          lockdown: 'false'
```

With those values, the Action scans the workspace, fails on `high` or above,
writes the requested stable-basename SARIF copy in the workspace, and publishes
a receipt-bound private snapshot to Code Scanning and the workflow artifact.
The job summary includes the scan path, severity floor, preset, lockdown state,
requested report name, snapshot publication state, raw exit code, finding count,
and scan duration.

The Action wrapper supports `text`, `json`, `sarif`, and `jsonl`. The CLI also
offers envelope, CSV, GitLab SAST, HTML, and JUnit formats; use the installed
`keyhog` binary directly for those outputs so the wrapper does not miscount a
report it cannot parse.

With `upload-sarif: 'true'`, Code Scanning
upload failures fail closed on trusted pushes and same-repo PRs. Fork PRs can
lack `security-events: write`; those upload failures stay advisory and the
SARIF report remains attached as a workflow artifact. Trusted upload failures
also keep the artifact so the failed job is still diagnosable.

Set `upload-sarif: 'false'` when the workflow cannot grant
`security-events: write`. The artifact upload remains available.

The scan step records its report before the Action restores a findings or live
credential exit status. A missing, malformed, or unreadable report always fails
the job, including when `fail-on-findings` is `false`.

## Select scan policy and hardening

The `preset` input selects detection policy:

| `preset` | CLI selection | Behavior |
| --- | --- | --- |
| `default` | no preset flag | Canonical decode depth 10, entropy and ML enabled, global confidence floor 0.40 |
| `fast` | `--fast` | Named regex and multiline detection remain; recursive decode, entropy discovery, and ML scoring are disabled |
| `deep` | `--deep` | Source-file entropy, comments at full confidence, heuristic entropy evidence beside ML, depth 10, and prepared decode chunks up to 1 MiB |
| `precision` | `--precision` | Entropy discovery and the relaxed keyword bridge off, ML on, decode depth 1, every confidence floor at least 0.85 |

`default` deliberately passes no preset flag. A committed `.keyhog.toml`
discovered from the scan root may therefore select exactly one of
`fast = true`, `deep = true`, or `precision = true`. An explicit Action
`preset: fast|deep|precision` has normal CLI precedence over a file preset.
Compatible committed and explicit knobs then refine the selected base; precision
confidence settings may raise but never lower 0.85.

`lockdown` is an independent boolean. `lockdown: 'true'` adds `--lockdown` and
can compose with default, deep, or precision exactly as the CLI permits. Fast
plus lockdown is refused rather than weakened. `[lockdown] require = true`
requires the true Action input but never enables lockdown by itself. Lockdown
is Linux-only. The Action requires a runner with a sufficient memlock limit for
the real process. `CAP_IPC_LOCK` or unlimited `ulimit -l` can provide it, but a
sufficiently large finite limit also works. Standard hosted Linux currently
fails early and closed when KeyHog applies `mlockall`; hosted cross-platform
positive scans use `lockdown: 'false'`, while the direct hosted lockdown lane
proves that rejection.

The maintained push/PR source lane runs real root and nested composite Actions
with explicit `backend: cpu` plus lockdown inside a digest-pinned Rust container
provisioned with `IPC_LOCK` and unlimited memlock. Cross-platform source lanes
also exercise explicit-CPU clean and precision scans. Source refs reject auto
without persisted routing proof. A local production Docker run separately
completes release-like calibration and auto scan with `mlocked` status. After
0.5.48 is public, the authenticated manual-dispatch release lane proves signed
release auto+lockdown.

For example, this committed policy makes `preset: default` a precision scan:

```toml
# .keyhog.toml
precision = true
```

The Action always passes `path`, `severity`, `format`, `verify`, and its report
path, so those explicit values override matching file settings. `verify:
'true'` maps to `--verify`; `'false'` maps to `--no-verify`, so a committed
`verify = true` cannot silently cause egress under the default Action input. A
nonempty `backend`, `baseline`, or `version`, a non-default `preset`, and
`lockdown: 'true'` are also explicit Action requests. Other scan settings follow
the ordinary compiled default → discovered `.keyhog.toml` → explicit CLI
precedence.

`analysis-category` is the stable identity for one Code Scanning partition.
Keep it unchanged across commits so GitHub updates that partition. Give every
KeyHog scan of the same commit a distinct category so monorepo and matrix
results coexist instead of replacing each other. Duplicate categories in one
workflow fail through SARIF or artifact upload. Categories use 1-64 lowercase
letters, digits, dots, underscores, or dashes and start and end alphanumeric.

```yaml
- uses: santhreal/keyhog@v0
  with:
    path: services/api
    analysis-category: services-api

- uses: santhreal/keyhog@v0
  with:
    path: services/web
    analysis-category: services-web
```

## Inputs

The values below show the full interface and its defaults:

```yaml
- uses: santhreal/keyhog@v0
  with:
    path: .
    severity: high
    format: sarif
    verify: 'false'
    version: ''
    upload-sarif: 'true'
    analysis-category: keyhog
    fail-on-findings: 'true'
    baseline: ''
    backend: ''
    preset: default
    lockdown: 'false'
```

| Input | Default | Contract |
| --- | --- | --- |
| `path` | `.` | One checked-out file or directory to scan. |
| `severity` | `high` | Minimum report tier: `info`, `client-safe`, `low`, `medium`, `high`, or `critical`. |
| `format` | `sarif` | Wrapper-supported report: `text`, `json`, `sarif`, or `jsonl`. |
| `verify` | `'false'` | Authoritative boolean: `'true'` passes `--verify`; `'false'` passes `--no-verify` and overrides committed `verify = true`. Enabling verification is credential data egress: eligible policy may send credential or companion material in a provider request URL, query, header, or body. |
| `version` | empty | Empty derives the scanner release from a release Action ref; branch/SHA refs build source. A nonempty value must be canonical final SemVer `v0.5.48` or newer. Older versions, prereleases (including `v0.5.48-*`), build metadata, malformed values, and missing signed assets fail closed. |
| `upload-sarif` | `'true'` | Uploads when `format: sarif`; use `'false'` when `security-events: write` is unavailable. The workflow artifact is still retained. |
| `analysis-category` | `keyhog` | Stable, unique partition/report identity; 1–64 lowercase letters, digits, dots, underscores, or dashes, starting and ending alphanumeric. |
| `fail-on-findings` | `'true'` | `'false'` makes ordinary exit-1 findings advisory after report handling. Exit 10 and every operational failure still fail. |
| `baseline` | empty | Path to a committed baseline; only findings absent from it remain reportable. |
| `backend` | empty | Authenticated release refs use proof-backed `auto` when empty; `cpu` is the portable explicit route. Branch/SHA source refs require explicit `cpu` and reject source auto without persisted routing proof. Accelerated diagnostics (`simd`, `gpu-cuda`, `gpu-wgpu`) require a compatible release binary and runner. |
| `preset` | `default` | `default`, `fast`, `deep`, or `precision`; a non-default value selects the matching CLI preset. |
| `lockdown` | `'false'` | `'true'` independently adds `--lockdown`; compatible with default/deep/precision and refused with fast. Requires Linux with a sufficient memlock limit; `CAP_IPC_LOCK`, unlimited `ulimit -l`, or a sufficiently large finite limit may provide it. The maintained push/PR source lane proves real root+nested explicit-CPU lockdown; authenticated manual dispatch proves release auto+lockdown. |

### Adopting on a repo that already has findings

Generate a baseline once, commit it, then point the action at it. The job
then blocks only **new** secrets instead of failing on the existing backlog:

```bash
keyhog scan --create-baseline keyhog-baseline.json
git add keyhog-baseline.json && git commit -m "chore: keyhog baseline"
```

```yaml
- uses: santhreal/keyhog@v0
  with:
    baseline: keyhog-baseline.json
```

## Outputs

```yaml
- id: keyhog
  uses: santhreal/keyhog@v0
  with:
    fail-on-findings: 'false'

- name: Comment on PR if anything found
  if: steps.keyhog.outputs.findings != '0'
  run: gh pr comment ${{ github.event.number }} -b "KeyHog flagged ${{ steps.keyhog.outputs.findings }} potential secret(s)."
```

| Output | Description |
| --- | --- |
| `findings` | Number of report findings at or above `severity`. |
| `exit-code` | Raw KeyHog exit: commonly `0` clean, `1` findings, `10` verified-live findings, `13` incomplete coverage; other documented nonzero exits remain failures. |
| `duration-ms` | Wall-clock scan duration in milliseconds from the wrapper. |
| `scan-status` | Normalized wrapper terminal state: `success`, `partial`, `cancelled`, or `failed`, published even before a report exists. `partial` preserves clean/findings/live exits `0`/`1`/`10` for advisory coverage gaps and uses exit `13` for fail-class incomplete coverage. A CLI report status of `complete_after_recovery` maps to wrapper `success`; with the default SARIF, read `runs[0].properties["keyhog.scan.status"]` and `["keyhog.backend.recoveries"]` to distinguish recovered completion. |
| `report-present` | `true` only when a receipt-bound private report snapshot was published; cancellation or an untrusted/missing report leaves it `false`. |
| `report` | Unpredictable private snapshot path under `RUNNER_TEMP/keyhog-action-runtime.*/report-snapshot.*/`, retained only for the runner job. Its stable basename is `keyhog-results-<analysis-category>.<ext>` and its mode is `0400`; an unpublished snapshot yields an empty path. |
| `analysis-category` | Validated identity shared by Code Scanning, the stable report basename, and the artifact name. |

The requested workspace copy keeps the stable
`keyhog-results-<analysis-category>.<ext>` name, but it is not the upload
authority or the public `report` output and must not be trusted after the Action
returns. The wrapper verifies that copy against the scanner receipt, copies the
verified bytes into a mode-`0400` snapshot inside the unique mode-`0700`
runtime, and re-verifies the snapshot against the same receipt. Immediately
before SARIF and artifact upload, the composite checks the snapshot SHA-256
again. Downstream steps in the same job must require
`report-present == 'true'` and consume `report` directly; do not reconstruct its
unpredictable parent path or expect the snapshot to survive job cleanup.
Publication does not make the snapshot immutable: another process under the
same runner UID can change permissions or bytes. `report-present` proves the
receipt-bound copy existed at publication time, while consumers that need
continued integrity must establish it at their own time of use.

## Runtime and dependencies

| Resource | Value |
| --- | --- |
| Prebuilt bundle | Binary and GPU literal sidecar; both minisign signatures and SHA-256 files verified before execution |
| Scan duration | Reported by the Action as `duration-ms`; varies by host, cache, config, and input |
| Runtime dependencies | Release refs bootstrap minisign `0.11` from platform archives pinned by hardcoded SHA-256; the Linux prebuilt statically links Hyperscan and needs no `libhyperscan5` |
| Toolchains required | none for release-tag prebuilts; branch/SHA refs use pinned Rust `1.89.0` and the `portable` profile |
| Routing | Branch/SHA portable builds require explicit `cpu`; source auto without a persisted routing proof is rejected. Authenticated release refs retain proof-backed default auto and pass one ephemeral `RUNNER_TEMP` receipt/cache from calibration to report scan before deleting it. |

Before the report scan, the Action applies the same path, baseline, severity,
preset, lockdown state, and discovered detection policy to effective-config
preflight and the throwaway autoroute calibration scan. Verification stays
disabled for calibration, so `verify: 'true'` does not send a credential twice.
Calibration reads incremental state for exact workload filtering but never
persists Merkle cache changes, so the report scan receives the same cache state
and detection-policy workload.

For authenticated release refs using `backend: auto` with `lockdown: 'true'`,
the Action creates an ephemeral autoroute receipt/cache under `RUNNER_TEMP`,
passes that exact file from calibration to the report scan, and deletes it
during cleanup. This preserves calibrated routing without creating a persistent
user cache; it is distinct from the Merkle incremental cache and GPU-literal
disk cache. The postpublication manual-dispatch lane proves this signed release
flow after v0.5.48 becomes public.

Push/PR source refs instead pass explicit `backend: cpu`. The maintained
digest-pinned container lane proves real root and nested CPU+lockdown with
`IPC_LOCK` and unlimited memlock. A local production Docker execution separately
proves release-like calibration and auto scan with `mlocked` status.

No Python, `jq`, `grep`, JVM, Docker daemon, or dynamically loaded Hyperscan
runtime is required by the Action itself. After flushing the report, the scanner
emits ordered fields `schema=keyhog-action-report-v1`, `format`, `findings`,
`report-bytes`, `report-sha256`, `scan-status`, and `exit-code`. A hidden
Action-only verifier rehashes the exact report bytes, validates the seven-field
receipt, and prints the count dependency-free. Coverage state does not rewrite
the scan outcome: advisory partial reports keep exit `0`, `1`, or `10`, while
fail-class incomplete coverage uses exit `13`. Cleanup deletes the receipt only
if its observed SHA-256 remains unchanged; replaced or type-changed receipt
paths fail instead of being blindly removed. Neither internal surface is a
public CLI API.

Release refs always authenticate and count the complete binary/sidecar proof
set. Ordinary mode atomically stages sidecar `.bin` files before scanning;
lockdown deliberately leaves that disk cache absent after authentication so the
CLI's cache-refusal protection can apply. The Linux release binary statically
links Hyperscan.

## Platforms

| OS | arch | Prebuilt binary | Branch/SHA source build |
| --- | --- | --- | --- |
| Linux | x86_64 | yes (full features) | yes (`portable`; explicit `cpu`) |
| macOS | aarch64 | yes (no Hyperscan) | yes (`portable`; explicit `cpu`) |
| macOS | x86_64 | yes (no Hyperscan) | yes (`portable`; explicit `cpu`) |
| Windows | x86_64 | yes (portable feature set) | yes (`portable`; explicit `cpu`) |

Exact release tags, the floating major tag (`@v0`), and explicit `version:`
inputs require the complete signed binary and GPU literal bundle. The floating
tag resolves the exact version from its checked-out manifest. Missing,
malformed, or unverifiable release payloads fail closed instead of silently
source-building different code. Release downloads bootstrap minisign `0.11`
only from per-platform archives whose SHA-256 values are hardcoded in the
wrapper.

Branch/SHA source builds skip release lookup and compile the checked-out source with
pinned Rust `1.89.0` and the `portable` profile on every platform. Those builds
require explicit `backend: cpu`; source auto without a persisted routing proof
is rejected. Selecting `simd`, `gpu-cuda`, or `gpu-wgpu` requires a compatible
release binary and runner. Explicit
`version:` accepts canonical final SemVer `v0.5.48` or newer. It rejects older
versions, prereleases such as `v0.5.48-rc.1`, and build metadata because they
cannot satisfy this Action revision's stable runtime contract.

macOS prebuilts also use the portable feature set. A manual macOS source build
can use Hyperscan after `brew install vectorscan pkg-config`; that is a
different build from the Action asset. Both feature sets include entropy,
multiline reassembly, ML scoring, decode-through, and the portable git, web,
hosted-Git, cloud, and Docker source backends. Ghidra binary extraction remains
opt-in and is absent from the portable asset.

## Recipes

See [integration recipes](../../../docs/src/workflows/integrations.md) for
pre-commit hooks, Husky, lefthook, GitLab CI, CircleCI, Drone, Jenkins,
BuildKite, Docker, library integration, and SARIF/Slack/Discord
webhook recipes.
