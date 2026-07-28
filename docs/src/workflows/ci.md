# CI integration

Add KeyHog in two stages: make findings visible with a durable report, then
turn new findings into a merge gate. The recipes below keep scanning,
enforcement, and report retention explicit so a missing upload or unsupported
source cannot look like a clean run.

The shell recipes use an Ubuntu worker. `minisign` is required because the
installer refuses unverified release assets. The Linux release binary
statically links Hyperscan and does not require `libhyperscan5`; branch/commit
Action refs build the portable profile. macOS and Windows release assets are
also portable but still require `minisign` for installation.

| Workflow | Recommended scan | Why |
|---|---|---|
| Developer commit | `keyhog hook install` | Fast staged-file feedback before push. |
| Pull request | Working tree, baseline enabled | Blocks newly introduced credentials. |
| Main branch | Full reachable Git history | Finds secrets already merged into history. |
| Release | History plus explicit live verification | Prevents publishing with a confirmed live credential. |
| Large scheduled inventory | Partitioned repository/cloud scopes | Keeps ownership, coverage, and artifacts independently retryable. |

## GitHub Actions

```yaml
# .github/workflows/secrets.yml
name: secrets

on:
  push:
    branches: [main]
  pull_request:

jobs:
  keyhog:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: santhreal/keyhog@v0
        with:
          path: .
          severity: high
          format: sarif
          upload-sarif: 'true'
          fail-on-findings: 'true'
          preset: default
          lockdown: 'false'
```

This example scans the checked-out working tree. Use the explicit
`--git-history` recipe below to inspect added lines across reachable commit
ancestry. Add `--git-blobs` for complete reachable blob coverage.

The composite Action installs KeyHog, scans the tree, writes the requested
stable-basename SARIF copy, publishes a receipt-bound private snapshot to
**Security > Code scanning** and the workflow artifact, and writes a job
summary. Its outputs are the finding count, raw KeyHog exit, duration, private
snapshot path and publication state, analysis category, and normalized wrapper
`scan-status`.

This wrapper value is not the report's `scan_status`. Wrapper `success` covers
ordinary clean/findings exits and a complete scan after visible backend
recovery. Metadata-bearing CLI reports additionally preserve
`complete_after_recovery`; with the Action's SARIF default, inspect
`runs[0].properties["keyhog.scan.status"]` and
`["keyhog.backend.recoveries"]` when that distinction is a gate. Wrapper
`partial` preserves clean, findings, or live-findings exit `0`, `1`, or `10`
when the report records advisory coverage gaps. Fail-class incomplete coverage
uses partial exit `13`. A missing or untrusted report is `failed`, never clean.

The requested workspace copy is named
`keyhog-results-<analysis-category>.<ext>`, but it is not the upload authority
and is untrusted after the Action returns. After verifying the scanner's
receipt, the wrapper copies those bytes to a mode-`0400` snapshot inside the
unique mode-`0700` runtime below the unpredictable
`RUNNER_TEMP/keyhog-action-runtime.*/report-snapshot.*/` parent and verifies it
again. The public `report` output is that private path; `report-present` is
`true` only when the receipt-bound snapshot was published, and is `false` with
an empty path after cancellation or an untrusted/missing report. SARIF and
artifact uploads SHA-check the snapshot immediately before use. A downstream
step in the same job may consume `report` after checking `report-present`, but
must not reconstruct the path or expect it to survive runner job cleanup.
The snapshot is private, not immutable against another process under the same
runner UID; a consumer that needs continued integrity must establish it at its
own time of use.

Choose detection policy with `preset: default|fast|deep|precision`. `default`
passes no preset flag, so a committed `.keyhog.toml` may select exactly one of
`fast = true`, `deep = true`, or `precision = true`; an explicit non-default
Action preset has normal CLI precedence over the file preset.
`lockdown: 'true'` independently adds `--lockdown`: default, deep, and precision
may compose with it, while fast plus lockdown is refused. `[lockdown]
require = true` requires that input and does not enable lockdown. Positive
lockdown requires Linux with a sufficient memlock limit for the real process.
`CAP_IPC_LOCK` or unlimited `ulimit -l` are provisioning options, but a
sufficiently large finite limit also works. Standard hosted Linux currently
fails closed during the real `mlockall` application; hosted positive lanes use
`lockdown: 'false'`, while the direct hosted lockdown lane asserts rejection.

The maintained push/PR source lane runs real root and nested composite Actions
with explicit `backend: cpu` plus lockdown in a digest-pinned Rust container
provisioned with `IPC_LOCK` and unlimited memlock. Cross-platform source lanes
exercise explicit-CPU clean and precision scans. Source refs reject auto without
persisted routing proof. A local production Docker run separately proves
release-like calibration and auto scan with `mlocked` status.

After v0.5.48 is public, the authenticated manual-dispatch release lane retains
proof-backed default auto. It passes one ephemeral `RUNNER_TEMP` autoroute
receipt/cache from calibration to report scan and deletes it during cleanup.
The Action always passes `path`, `severity`, `format`, `verify`, and the report
path, so those values override matching file settings.
See the
[complete input/output inventory](https://github.com/santhreal/keyhog/blob/main/.github/actions/keyhog/README.md#inputs).

This page documents the 0.5.48 Action candidate. The `@v0` example becomes
copyable only after the publication verifier proves that the floating tag points
to `v0.5.48`; it currently points to the prior public release. After publication,
`santhreal/keyhog@v0.5.48` is the reproducible exact pin, and an explicit
`version: v0.5.48` selects that scanner asset even when Action code comes from a
reviewed branch or commit. Pin the Action ref too when workflow code must not
change without review.
This Action revision requires canonical final scanner `v0.5.48` or newer because
it always passes either `--verify` or `--no-verify`. Older versions, prereleases
including `v0.5.48-*`, and build metadata fail closed rather than weakening that
contract.

Release refs and explicit `version:` inputs require the signed binary and GPU
literal bundle. The Action bootstraps minisign `0.11` only from per-platform
archives whose SHA-256 values are hardcoded, then verifies the payload
signatures, checksums, and sidecar before execution. A missing or unverifiable
runtime payload fails the job. The 0.5.48 candidate's signed SPDX SBOM set is a
separate release-completeness contract and is not public before that release
succeeds.

Branch and commit Action refs build their checked-out source on pinned Rust
`1.89.0` with the portable profile on every platform and require explicit
`backend: cpu`. Source auto without persisted routing proof is rejected;
`simd`, `gpu-cuda`, and `gpu-wgpu` require a compatible release binary and
runner. Authenticated release refs retain proof-backed default auto.

The `format` input intentionally supports the four formats `text`, `json`,
`sarif`, and `jsonl`. Use the installed CLI directly for the other formats in
[Output formats](../output-formats.md).
After report flush, the scanner emits the ordered fields
`schema=keyhog-action-report-v1`, `format`, `findings`, `report-bytes`,
`report-sha256`, `scan-status`, and `exit-code`. A hidden Action-only verifier
rehashes the exact report bytes, validates the seven-field receipt, and prints
the count with no `jq`, Python, or `grep` dependency. Cleanup removes the receipt
only if its observed SHA-256 is unchanged; replaced or type-changed paths fail
rather than being blindly deleted. These are integration details, not public
CLI commands.

The `security-events: write` permission enables Code Scanning upload on pushes
and same-repository pull requests. GitHub downgrades the token for a fork pull
request. The Action treats only that fork upload as advisory and still retains
the SARIF artifact. A scan finding still fails the fork job. On trusted events,
a missing report or failed SARIF upload fails closed.

`fail-on-findings: 'false'` makes exit `1` findings advisory after report
handling. It does not hide scanner, configuration, source-coverage, backend, or
report failures. With `verify: 'true'`, a confirmed live credential exits `10`
and always fails after report handling. Verification is credential data egress:
eligible detector policy may place credential or companion material in a
provider request URL, query, header, or body. Review the committed detector
corpus and outbound trust boundary before enabling it. The Action input is
authoritative: `'true'` passes `--verify`, while the default `'false'` passes
`--no-verify` and overrides a committed `verify = true`.

Self-hosted GPU runners can add `keyhog backend --self-test --json` before the
scan. On an eligible GPU host, the JSON includes `ok`, `status`, `exit_code`,
`healthy_gpu_backends`, `route_selection`, and records for `moe_kernel`, the
diagnostic `vyre_literal_set`, and the production `gpu_region_presence` route. Exit `4`
means the binary is present but a required GPU capability or the production
route failed; fail the GPU
lane or intentionally start a separate explicit SIMD/CPU lane. Normal automatic
scans recover a transient accelerated-backend fault against the same stable bytes
and expose the recovered byte count; `--require-gpu` keeps absence or runtime
failure as a hard lane contract. The self-test sets `route_selection` to
`not_measured`. Read `keyhog backend --autoroute` for the calibrated route. A
runner without an eligible physical GPU instead returns one `gpu_adapter` probe with status
`skip` and exits `0`; add `--require-gpu` when absence must fail the lane.

To adopt on a repo that already has known findings, generate and commit a
baseline once, then wire it into the action:

```bash
keyhog scan . --create-baseline .keyhog-baseline.json
git add .keyhog-baseline.json && git commit -m 'chore: keyhog baseline'
```

```yaml
      - uses: santhreal/keyhog@v0
        with:
          baseline: .keyhog-baseline.json
```

### Manual installation

Use the verified installer when the workflow must own installation explicitly:

```yaml
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Install KeyHog runtime and verifier prerequisites
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y --no-install-recommends minisign
      - name: Install KeyHog
        run: |
          TAG=v0.5.48
          BASE="https://github.com/santhreal/keyhog/releases/download/$TAG"
          PUB='RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go'
          curl -fSLO "$BASE/install.sh" -fSLO "$BASE/install.sh.minisig"
          minisign -Vm install.sh -P "$PUB"
          KEYHOG_VERSION="$TAG" sh install.sh
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - name: Scan working tree
        id: keyhog
        run: |
          set +e
          keyhog scan . --severity high --format sarif --output keyhog.sarif
          status=$?
          echo "exit-code=$status" >> "$GITHUB_OUTPUT"
          exit 0
      - name: Upload SARIF
        if: always() && hashFiles('keyhog.sarif') != ''
        continue-on-error: ${{ github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name != github.repository }}
        uses: github/codeql-action/upload-sarif@dd903d2e4f5405488e5ef1422510ee31c8b32357 # v3
        with:
          sarif_file: keyhog.sarif
      - name: Retain SARIF report
        if: always() && hashFiles('keyhog.sarif') != ''
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: keyhog-sarif-${{ github.run_attempt }}
          path: keyhog.sarif
      - name: Enforce scan result
        if: steps.keyhog.outputs.exit-code != '0'
        env:
          KEYHOG_EXIT: ${{ steps.keyhog.outputs.exit-code }}
        run: exit "$KEYHOG_EXIT"
```

The scan step records the exact process status before report handling. The last
step restores that status, so findings, verified-live findings, configuration
errors, incomplete coverage, backend failures, and internal errors remain
distinct. The SARIF upload is advisory only for fork pull requests. The artifact
is retained whenever the scanner produced it.

### Scan only changed files in a PR (faster)

Fetch the pull request base before using `--git-diff`:

```yaml
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
      - name: Scan pull request diff
        if: github.event_name == 'pull_request'
        run: keyhog scan --git-diff "origin/${{ github.base_ref }}" --severity high
```

## Exclusions and adoption policy

Use exclusions for content that should not be scanned, and a baseline for known
findings that should remain visible but not block adoption:

- Put generated trees, vendored fixtures, and intentionally synthetic corpora
  in `.keyhogignore` as `path:` rules. Keep a short comment explaining each
  exclusion; broad globs can hide real coverage.
- Put finding-specific exceptions in `.keyhogignore` or
  `.keyhogignore.toml`, preferably with reason, expiry, and approval metadata.
- Commit a baseline when introducing KeyHog to an existing repository. Do not
  regenerate it automatically in CI; review baseline changes like code.
- Never convert a source failure or coverage gap into an exclusion. KeyHog uses
  distinct nonzero exit semantics for invalid configuration, system failures,
  unavailable required GPU execution, and incomplete sources.

For a monorepo, keep one root policy when ownership is shared. When teams need
independent gates, run explicit subdirectory jobs with their own reports and
baselines; do not hide one team's paths behind another team's ignore file.

## GitLab CI

```yaml
# .gitlab-ci.yml
keyhog:
  stage: test
  image: ubuntu:24.04
  before_script:
    - apt-get update -qq && apt-get install -y --no-install-recommends curl minisign
    - export TAG=v0.5.48
    - export BASE="https://github.com/santhreal/keyhog/releases/download/$TAG"
    - export PUB='RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go'
    - curl -fSLO "$BASE/install.sh" && curl -fSLO "$BASE/install.sh.minisig"
    - minisign -Vm install.sh -P "$PUB"
    - KEYHOG_VERSION="$TAG" sh install.sh
  script:
    # Exits non-zero on findings, which fails the job and gates the MR.
    - ~/.local/bin/keyhog scan . --format gitlab-sast --output gl-sast-report.json
  artifacts:
    when: always           # keep the report even when the scan fails the job
    reports:
      sast: gl-sast-report.json
    paths:
      - gl-sast-report.json
```

The job's exit status gates the merge request. KeyHog emits GitLab's SAST JSON
schema directly, so `artifacts:reports:sast` publishes findings to the merge
request security widget without a converter. The same report remains a
downloadable artifact when the scan fails.

## CircleCI

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  keyhog:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: Install keyhog
          command: |
            sudo apt-get update -qq
            sudo apt-get install -y --no-install-recommends minisign
            TAG=v0.5.48
            BASE="https://github.com/santhreal/keyhog/releases/download/$TAG"
            PUB='RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go'
            curl -fSLO "$BASE/install.sh" -fSLO "$BASE/install.sh.minisig"
            minisign -Vm install.sh -P "$PUB"
            KEYHOG_VERSION="$TAG" sh install.sh
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> $BASH_ENV
      - run:
          name: Scan repo
          command: keyhog scan . --format sarif --output keyhog.sarif
      - store_artifacts:
          path: keyhog.sarif
          destination: keyhog.sarif

workflows:
  build:
    jobs:
      - keyhog
```

## Drone CI

```yaml
# .drone.yml
kind: pipeline
type: docker
name: default

steps:
  - name: keyhog
    image: ubuntu:24.04
    commands:
      - apt-get update -qq
      - apt-get install -y --no-install-recommends curl minisign
      - export TAG=v0.5.48
      - export BASE="https://github.com/santhreal/keyhog/releases/download/$TAG"
      - export PUB='RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go'
      - curl -fSLO "$BASE/install.sh" -fSLO "$BASE/install.sh.minisig"
      - minisign -Vm install.sh -P "$PUB"
      - KEYHOG_VERSION="$TAG" sh install.sh
      - |
        printf '{"schema_version":{"major":1,"minor":7},"scan_status":"failed","coverage_gap_summary":[],"findings":[]}\n' > keyhog.json
        scan_status=0
        $HOME/.local/bin/keyhog scan . --format json-envelope --output keyhog.json \
          2>keyhog.stderr || scan_status=$?
        printf '%s\n' "$scan_status" > keyhog.exit-code
        cat keyhog.stderr >&2 || true
        exit "$scan_status"

  - name: publish-keyhog-report
    image: plugins/s3
    settings:
      endpoint:
        from_secret: keyhog_artifacts_endpoint
      bucket:
        from_secret: keyhog_artifacts_bucket
      access_key:
        from_secret: keyhog_artifacts_access_key
      secret_key:
        from_secret: keyhog_artifacts_secret_key
      source: keyhog.*
      target: keyhog/${DRONE_REPO}/${DRONE_BUILD_NUMBER}
    when:
      status:
        - success
        - failure
```

The S3-compatible publisher runs after clean scans, findings, and operational
errors. Configure its four `keyhog_artifacts_*` secrets for your artifact
store. The scan step exits with KeyHog's exact status after writing
`keyhog.exit-code` and replaying `keyhog.stderr` to the job log.

## Generic shell

Use the same scan wrapper in Jenkins, Buildkite, Woodpecker, Concourse, or any
CI that can run a POSIX shell:

```sh
#!/bin/sh
set -eu

printf '{"schema_version":{"major":1,"minor":7},"scan_status":"failed","coverage_gap_summary":[],"findings":[]}\n' > keyhog.json
scan_status=0
keyhog scan . --format json-envelope --output keyhog.json \
  2>keyhog.stderr || scan_status=$?
printf '%s\n' "$scan_status" > keyhog.exit-code
cat keyhog.stderr >&2 || true
exit "$scan_status"
```

Configure the CI artifact publisher to retain `keyhog.json`, `keyhog.stderr`,
and `keyhog.exit-code` on both success and failure. KeyHog atomically replaces
the initial empty JSON envelope after a completed scan. If setup or scanning
fails before report generation, the valid empty report remains, while the saved
stderr and nonzero status record that the scan did not complete. Always
evaluate the report together with `keyhog.exit-code`.

## Buildkite

Use a dedicated artifact path so the report survives a finding exit:

```yaml
# .buildkite/pipeline.yml
steps:
  - label: ":mag: keyhog secret scan"
    command: |
      sudo apt-get update -qq
      sudo apt-get install -y --no-install-recommends curl minisign
      TAG=v0.5.48
      BASE="https://github.com/santhreal/keyhog/releases/download/$TAG"
      PUB='RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go'
      curl -fSLO "$BASE/install.sh" -fSLO "$BASE/install.sh.minisig"
      minisign -Vm install.sh -P "$PUB"
      KEYHOG_VERSION="$TAG" sh install.sh
      export PATH="$HOME/.local/bin:$PATH"
      keyhog scan . --severity high --format json-envelope --output keyhog.json
    artifact_paths:
      - keyhog.json
```

## Jenkins

Archive the report in `post` so it remains available when the scan blocks the
stage:

```groovy
// Jenkinsfile
pipeline {
    agent any
    stages {
        stage('keyhog') {
            steps {
                sh '''
                    sudo apt-get update -qq
                    sudo apt-get install -y --no-install-recommends curl minisign
                    TAG=v0.5.48
                    BASE="https://github.com/santhreal/keyhog/releases/download/$TAG"
                    PUB='RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go'
                    curl -fSLO "$BASE/install.sh" -fSLO "$BASE/install.sh.minisig"
                    minisign -Vm install.sh -P "$PUB"
                    KEYHOG_VERSION="$TAG" sh install.sh
                    export PATH="$HOME/.local/bin:$PATH"
                    keyhog scan . --severity high --format json-envelope --output keyhog.json
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'keyhog.json', allowEmptyArchive: true
                }
            }
        }
    }
}
```

## Pinning a version

For the composite Action, pin the Action ref:

```yaml
- uses: santhreal/keyhog@v0
```

The floating ref selects the current verified v0 Action implementation and its
matching scanner release. After 0.5.48 publication, replace it with
`santhreal/keyhog@v0.5.48` when the workflow must remain immutable.
`version: v0.5.48` pins only the scanner asset and is not a substitute for
pinning Action code.

For a manual installation, authenticate the installer before execution and pass
the same release tag to it:

```sh
TAG=v0.5.48
BASE="https://github.com/santhreal/keyhog/releases/download/$TAG"
PUB='RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go'
curl -fSLO "$BASE/install.sh" -fSLO "$BASE/install.sh.minisig"
minisign -Vm install.sh -P "$PUB"
KEYHOG_VERSION="$TAG" sh install.sh
```

Review and update either pin when adopting a new release.

## Scan commit additions on main and release, not per PR

An added-line history scan is useful on `main` post-merge and on release tags,
but it is overkill for every PR. Add `--git-blobs .` when the policy must cover
the complete set of blobs reachable from the selected repository. A typical setup:

| Trigger        | Scan                            | Purpose |
|----------------|----------------------------------|---------|
| Pull request   | `keyhog scan .` (working tree)  | Fast feedback over proposed files |
| Push to main   | `keyhog scan --git-history .`   | Cover added lines from reachable commit patches |
| Release tag    | `keyhog scan --git-history . --verify` | Add explicit live verification before publication |

Duration depends on history size, changed bytes, verification endpoints,
rate limits, runner hardware, and cache state. Record it from the actual job.

The PR scan keeps the dev feedback loop fast. The post-merge history
scan catches anything that slipped through pre-commit + PR review.
The release scan verifies what's live, useful for the changelog
("rotated these N credentials before shipping").

## Mass scanning

For many repositories or remote collections, make each organization, group,
bucket, or repository partition its own retryable job and retain one
machine-readable report per partition. Keep hosted-Git credentials out of the
process list by injecting `KEYHOG_GITHUB_TOKEN`, `KEYHOG_GITLAB_TOKEN`, or
`KEYHOG_BITBUCKET_USERNAME` plus `KEYHOG_BITBUCKET_TOKEN` through the CI secret
store. Then select the scope explicitly:

```bash
keyhog scan --github-org acme --format jsonl-envelope --output acme.jsonl
keyhog scan --gitlab-group platform --format jsonl-envelope --output platform.jsonl
keyhog scan --s3-bucket audit-archive --s3-prefix production/ \
  --format jsonl-envelope --output audit-archive.jsonl
```

Use `--precision` only when its explicit lower-recall policy is appropriate. It
disables generic entropy discovery and the relaxed keyword bridge, then raises
the confidence floor to 0.85.

Use the source limits from the [CLI reference](../reference/cli.md) to define the
intended coverage boundary. Reaching one is an incomplete-source result, not a
clean scan; size the limit deliberately or split the inventory into more jobs.

Start in report-only mode, review coverage gaps separately from findings, then
enable enforcement once baselines and exclusions are owned. Runtime and route
choice vary with detector policy, source shape, cache state, host CPU/GPU, and
network limits. Calibrate autoroute on the actual worker class; do not copy a
routing cache between machines or force GPU/CPU based only on input size.

The [daemon workflow](./daemon.md) can avoid repeated startup for compatible
stdin and single-file scans under the daemon's standard scan policy. Remote,
cloud, Git, directory, and multi-source inventory scans use the ordinary process
path. Ephemeral hosted CI should normally do the same.

## Failure modes worth knowing

- **Forked PR + secret credentials:** GitHub Actions doesn't expose
  org secrets to forked-PR runners, so a verifier endpoint that needs
  authentication won't run. Findings still get reported as
  unverified; that's correct behavior.
- **Advisory mode:** `fail-on-findings: 'false'` keeps unverified
  findings from blocking a PR, but verified-live credentials still
  fail after uploads so the report is preserved and the merge stays
  blocked.
- **Shallow clones:** `actions/checkout` defaults to `fetch-depth: 1`,
  which normally exposes only the checked-out HEAD commit. A `--git-history`
  scan walks only the ancestry present in that clone. Set `fetch-depth: 0` to
  scan the complete HEAD ancestry.
- **LFS files:** keyhog reads the LFS pointer file, not the
  contents. To scan LFS-stored binaries, enable LFS in checkout
  (`lfs: true`) and let the scanner pull the real file.
