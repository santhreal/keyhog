# CI integration

Add KeyHog in two stages: make findings visible with a durable report, then
turn new findings into a merge gate. The recipes below keep scanning,
enforcement, and report retention explicit so a missing upload or unsupported
source cannot look like a clean run.

The shell recipes use an Ubuntu worker. `minisign` is required because the
installer refuses unverified release assets. The Linux release binary also
requires the `libhyperscan5` runtime package. macOS and Windows release assets
use the portable scanner build, but still require `minisign` for installation.

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
      - uses: actions/checkout@v4
      - uses: santhreal/keyhog/.github/actions/keyhog@v0.5.41
        with:
          path: .
          severity: high
          format: sarif
```

This Action example scans the checked-out working tree. Use the explicit
`--git-history` recipe below to inspect added lines across reachable commit
ancestry. Add `--git-blobs` for complete reachable blob coverage.

The composite action installs KeyHog, writes a SARIF report, uploads it
to **Security -> Code scanning**, attaches the report as a workflow
artifact, and prints a job summary with the finding count, raw exit code,
and scan duration.

Exact release tags, the floating major tag (`@v0`), and explicit `version:`
inputs require the complete binary and GPU literal bundle. The floating tag
resolves the exact version from its checked-out manifest. The Action verifies
both minisign signatures with KeyHog's pinned public key, verifies both SHA-256
files, validates the sidecar archive, and seeds its matcher artifacts before
execution. A missing or unverifiable payload fails closed. Branch/SHA Action
refs skip release lookup and build from source using the checked-out tree.

Release refs use `vMAJOR.MINOR.PATCH` with an optional prerelease suffix.
Build metadata (`+...`) is rejected because release assets are not published
under a build-metadata namespace.

When `upload-sarif: 'true'`, SARIF upload is fail-closed on trusted pushes
and same-repo pull requests. Fork pull requests often lack
`security-events: write`; in that case the upload step is advisory and the
downloadable SARIF artifact remains available for review. Trusted upload
failures also keep the report artifact, so the failed job remains
diagnosable.

`fail-on-findings: 'false'` makes ordinary findings advisory after the
report/SARIF/artifact are written. A `--verify` scan that confirms a live
credential still fails the action with KeyHog exit code `10`.

Self-hosted GPU runners can add `keyhog backend --self-test --json`
before the scan. On an eligible GPU host, the JSON includes `ok`, `status`, `exit_code`,
`recommended_backend`, and records for `moe_kernel`, the diagnostic
`vyre_literal_set`, and the production `gpu_region_presence` route. Exit `4`
means the binary is present but a required GPU capability or the production
route failed; fail the GPU
lane or intentionally start a separate explicit SIMD/CPU lane. A selected GPU
scan never changes backend inside the failed route. A runner without an
eligible physical GPU instead returns one `gpu_adapter` probe with status
`skip` and exits `0`; add `--require-gpu` when absence must fail the lane.

To adopt on a repo that already has known findings, generate and commit a
baseline once, then wire it into the action:

```bash
keyhog scan . --create-baseline .keyhog-baseline.json
git add .keyhog-baseline.json && git commit -m 'chore: keyhog baseline'
```

```yaml
      - uses: santhreal/keyhog/.github/actions/keyhog@v0.5.41
        with:
          baseline: .keyhog-baseline.json
```

### Manual installation

Use the verified installer when the workflow must own installation explicitly:

```yaml
      - uses: actions/checkout@v4
      - name: Install KeyHog runtime and verifier prerequisites
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y --no-install-recommends libhyperscan5 minisign
      - name: Install KeyHog
        run: |
          TAG=v0.5.41
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
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: keyhog.sarif
      - name: Enforce scan result
        if: steps.keyhog.outputs.exit-code != '0'
        env:
          KEYHOG_EXIT: ${{ steps.keyhog.outputs.exit-code }}
        run: exit "$KEYHOG_EXIT"
```

The scan step records the exact process status before uploading the report. The
last step restores that status, so findings, live findings, configuration
errors, incomplete coverage, backend failures, and internal errors remain
distinct.

### Scan only changed files in a PR (faster)

Fetch the pull request base before using `--git-diff`:

```yaml
      - uses: actions/checkout@v4
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
    - apt-get update -qq && apt-get install -y --no-install-recommends curl libhyperscan5 minisign
    - export TAG=v0.5.41
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
            sudo apt-get install -y --no-install-recommends libhyperscan5 minisign
            TAG=v0.5.41
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
      - apt-get install -y --no-install-recommends curl libhyperscan5 minisign
      - export TAG=v0.5.41
      - export BASE="https://github.com/santhreal/keyhog/releases/download/$TAG"
      - export PUB='RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go'
      - curl -fSLO "$BASE/install.sh" -fSLO "$BASE/install.sh.minisig"
      - minisign -Vm install.sh -P "$PUB"
      - KEYHOG_VERSION="$TAG" sh install.sh
      - |
        printf '{"schema_version":{"major":1,"minor":5},"scan_status":"success","coverage_gap_summary":[],"findings":[]}\n' > keyhog.json
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

printf '{"schema_version":{"major":1,"minor":5},"scan_status":"success","coverage_gap_summary":[],"findings":[]}\n' > keyhog.json
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
      sudo apt-get install -y --no-install-recommends curl libhyperscan5 minisign
      TAG=v0.5.41
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
                    sudo apt-get install -y --no-install-recommends curl libhyperscan5 minisign
                    TAG=v0.5.41
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

Pin and authenticate the installer before execution. The installer then pins
the binary to the same release:

```sh
TAG=v0.5.41
BASE="https://github.com/santhreal/keyhog/releases/download/$TAG"
PUB='RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go'
curl -fSLO "$BASE/install.sh" -fSLO "$BASE/install.sh.minisig"
minisign -Vm install.sh -P "$PUB"
KEYHOG_VERSION="$TAG" sh install.sh
```

Update the pin via a Renovate / Dependabot config or just bump it
by hand when a new release lands.

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
