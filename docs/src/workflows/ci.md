# CI integration

Add KeyHog in two stages: make findings visible with a durable report, then
turn new findings into a merge gate. The recipes below keep scanning,
enforcement, and report retention explicit so a missing upload or unsupported
source cannot look like a clean run.

The shell recipes use an Ubuntu worker. Published Action refs install KeyHog
from crates.io and build the full default feature set. Branch and commit Action
refs build the portable profile from their checked-out source and require
`backend: cpu`.

| Workflow | Recommended scan | Boundary |
|---|---|---|
| Developer commit | `keyhog hook install` | Scans exact staged blobs before the commit. |
| Pull-request checkout | `keyhog scan . --baseline <FILE>` | Scans the checked-out tree and suppresses only reviewed baseline findings. |
| Pull-request changes only | `keyhog scan --git-diff <BASE>` | Scans changed lines relative to the selected base. This is narrower than the checkout. |
| Main branch commit additions | `keyhog scan --git-history .` | Scans added patch lines from reachable commits present in the checkout, bounded by `max_commits`. |
| Complete reachable blob gate | `keyhog scan --git-blobs .` | Scans deduplicated reachable blobs when patch additions are not complete enough. |
| Release verification | `keyhog scan --git-history . --git-blobs . --verify` | Adds live checks for eligible detectors. Unverifiable findings remain unverified, and verification sends credential-derived requests to providers. |
| Large scheduled inventory | Partitioned repository or cloud scopes | Keeps ownership, coverage, reports, and retries independent. |

## CI speed and concurrency

One KeyHog process uses the available CPU cores by default. Leave
`--threads` unset on a dedicated runner. When a matrix runs several KeyHog jobs
on one shared worker, divide the worker's CPU budget across them with
`--threads <N>` so every process does not claim the full host. Set
`--reader-threads` only after `--profile` shows a storage-reader bottleneck.

Use `--incremental` only when the CI cache is bound to the same trusted
repository and partition. Give each monorepo partition a separate
`--incremental-cache` path and cache key. A cache hit changes work reuse, not
the selected source boundary or detection policy.

Do not use `--fast` as the only merge or release gate. It intentionally omits
decode, entropy, and ML work. It is suitable for an additional short feedback
job when the default policy still runs before merge. Directory and Git jobs run
in process; a warm daemon does not accelerate them.

Live verification has a separate network budget. Use
`--verify-concurrency`, `--verify-rate`, or `--verify-batch` based on provider
limits rather than CPU count.

## GitHub Actions

Use the [GitHub Action guide](./github-action.md) for the maintained composite
Action, its inputs and outputs, monorepo categories, baseline adoption, report
retention, and failure semantics.

Use the CLI directly in GitHub Actions when you need a source option that the
Action does not expose. For example, fetch complete ancestry before scanning
reachable commit additions:

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  with:
    fetch-depth: 0
- name: Scan reachable history
  run: keyhog scan --git-history . --format sarif --output keyhog.sarif
```

Install KeyHog before these steps. Capture the exact scan status, upload the
report, then restore that status after the upload:

```yaml
- name: Scan reachable history
  id: keyhog
  shell: bash
  run: |
    scan_status=0
    keyhog scan --git-history . --format sarif --output keyhog.sarif \
      || scan_status=$?
    printf 'exit-code=%s\n' "$scan_status" >> "$GITHUB_OUTPUT"
- name: Upload KeyHog SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@dd903d2e4f5405488e5ef1422510ee31c8b32357 # v3
  with:
    sarif_file: keyhog.sarif
- name: Enforce scan result
  if: always()
  env:
    KEYHOG_EXIT: ${{ steps.keyhog.outputs.exit-code }}
  shell: bash
  run: exit "$KEYHOG_EXIT"
```

The capture step exits successfully so the upload can run. The enforcement
step then restores every KeyHog finding, live-credential, panic, backend,
system, and coverage status without translating it to a generic failure.

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
  image: rust:1.89-bookworm
  before_script:
    - cargo install --locked --version '=0.5.61' keyhog
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
      - image: cimg/rust:1.89
    steps:
      - checkout
      - run:
          name: Install keyhog
          command: |
            cargo install --locked --version '=0.5.61' keyhog
            echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> $BASH_ENV
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
    image: rust:1.89-bookworm
    commands:
      - cargo install --locked --version '=0.5.61' keyhog
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
      cargo install --locked --version '=0.5.61' keyhog
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
                    cargo install --locked --version '=0.5.61' keyhog
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

## Pin the scanner version

Manual CI installation can pin one exact crates.io version:

```sh
cargo install --locked --version '=0.5.61' keyhog
```

Review the release before changing the version. GitHub Action code and scanner
crate pinning are separate contracts; see [Pin Action code and scanner
releases](./github-action.md#pin-action-code-and-scanner-releases).

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

Use the [mass-scanning guide](../guides/mass-scanning.md) for repository
organizations, hosted Git groups, cloud buckets, local partitions, source
limits, report aggregation, and retry boundaries. A mass scan is an inventory
workflow, not a larger version of a pull-request job.

Run each partition as an independent CI job. Retain its machine-readable report,
raw exit code, source inventory, and coverage state before aggregating results.

## Failure modes worth knowing

- **Forked PR + secret credentials:** GitHub Actions doesn't expose
  org secrets to forked-PR runners, so a verifier endpoint that needs
  authentication won't run. Findings still get reported as
  unverified; that's correct behavior.
- **Advisory findings:** preserve the raw KeyHog exit separately from report
  publication, then decide explicitly whether exit `1` blocks the job. A
  verified-live credential exits `10` and should remain blocking.
- **Shallow clones:** `actions/checkout` defaults to `fetch-depth: 1`,
  which normally exposes only the checked-out HEAD commit. A `--git-history`
  scan walks only the ancestry present in that clone. Set `fetch-depth: 0` to
  scan the complete HEAD ancestry.
- **LFS files:** keyhog reads the LFS pointer file, not the
  contents. To scan LFS-stored binaries, enable LFS in checkout
  (`lfs: true`) and let the scanner pull the real file.
