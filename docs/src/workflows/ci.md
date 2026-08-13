# CI integration

Add KeyHog in two stages: make findings visible with a durable report, then
turn new findings into a merge gate. Most repositories already contain
credentials, so start at
[Fail only on new secrets](#fail-only-on-new-secrets) for the complete path
from a first scan to a passing gate. The provider recipes below keep scanning,
enforcement, and report retention explicit so a missing upload or unsupported
source cannot look like a clean run.

The shell recipes use an Ubuntu worker and install the full default `portable`
crate profile. The GitHub Action has a different installation contract:
published refs install the lean `ci` feature, while branch and commit refs build
the portable profile from checked-out source and require `backend: cpu`.

| Workflow | Recommended scan | Boundary |
|---|---|---|
| Developer commit | `keyhog hook install` | Scans exact staged blobs before the commit. |
| Pull-request checkout | `keyhog scan . --baseline <FILE>` | Scans the checked-out tree and suppresses only reviewed baseline findings. See [Fail only on new secrets](#fail-only-on-new-secrets). |
| Pull-request changes only | `keyhog scan --git-diff <BASE>` | Scans changed lines relative to the selected base. This is narrower than the checkout. |
| Main branch commit additions | `keyhog scan --git-history .` | Scans added patch lines from reachable commits present in the checkout, bounded by `max_commits`. |
| Repository object database | `keyhog scan --git-blobs .` | Scans deduplicated blobs from refs, reflogs, stashes, tags, and unreachable objects still present in the clone. |
| Release verification | `keyhog scan --git-history . --git-blobs . --verify` | Adds live checks for eligible detectors. Unverifiable findings remain unverified, and verification sends credential-derived requests to providers. |
| Large scheduled inventory | Partitioned repository or cloud scopes | Keeps ownership, coverage, reports, and retries independent. |

## Fail only on new secrets

This is the usual adoption path for a repository that already holds credentials
you cannot rotate today. The findings that exist now stay visible in a committed
baseline. Only findings added after that point fail the build.

### 1. Create and commit the baseline

Run this once, on a clean local checkout of the branch CI scans:

```sh
keyhog scan . --create-baseline .keyhog-baseline.json
```

The command writes the file, prints no findings, and exits `0`. Read the file
before committing it. Every entry is a credential you are choosing to accept.

```sh
git add .keyhog-baseline.json
git commit -m "chore: add KeyHog baseline"
```

### 2. Gate the build

```sh
keyhog scan . --baseline .keyhog-baseline.json --format json-envelope --output keyhog.json
```

Exit `0` means no new findings. Exit `1` means a credential is present that the
baseline does not list. Exit `13` means the scan could not cover its input; a
baseline never suppresses that, so do not read it as clean. Keep `keyhog.json`
on every outcome. The [generic shell wrapper](#generic-shell) is the portable
way to retain the report and the exact exit code together.

A scan that reads zero source bytes exits `13` with a `scan covered nothing`
gap row, so an `--exclude-paths` glob that matches everything, a container
mount that landed empty, or a partition path that no longer exists fails the
job rather than passing it. Assert the byte count anyway when the input path
can change, because the assertion names the problem in the job log instead of
leaving a reader to decode an exit code:

```sh
jq -e '.metadata.source_bytes_scanned > 0' keyhog.json
```

See [tell a real clean from a skipped input](../reference/coverage-truth.md).

### 3. Respond when the gate fires

A failing gate means someone added a credential. Remove it from the code and
rotate it at the provider. When the finding is a reviewed exception instead,
pick the narrowest surface:

- One exact value in one path: add a `[[suppress]]` rule to
  `.keyhogignore.toml`.
- A credential the team accepts everywhere: run
  `keyhog scan . --update-baseline .keyhog-baseline.json` locally, review the
  diff, and commit it.

Never run `--update-baseline` inside CI. A job that rewrites its own baseline
accepts every secret it finds. The flag also still reports the new findings and
still exits `1`, so it cannot turn a red job green.

### Monorepos: one baseline or several

A baseline entry matches on the detector and the credential value, never on the
path. One root baseline therefore covers every partition, and moving code
between partitions never fires the gate. Choose by who reviews exceptions, not
by how matching works:

| Situation | Use |
|---|---|
| One security team reviews every exception | A single `.keyhog-baseline.json` at the repository root |
| Each team reviews its own exceptions | One baseline per partition, stored beside that partition's code |

Per-partition baselines have one consequence worth knowing. A credential
accepted in `services/api` is reported again when the same value appears in
`services/web`, because that job loads a different file. That is usually what
you want.

Run each partition as its own job so a failure names an owner:

```yaml
strategy:
  fail-fast: false
  matrix:
    partition: [services/api, services/web]
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  - name: Scan partition
    env:
      PARTITION: ${{ matrix.partition }}
    shell: bash
    run: |
      keyhog scan "$PARTITION" \
        --baseline "$PARTITION/.keyhog-baseline.json" \
        --format json-envelope \
        --output "keyhog-${PARTITION//\//-}.json"
```

`fail-fast: false` keeps the other partitions running after one fails, so a
single leak does not hide the rest. Give each partition its own
`--incremental-cache` path and cache key if you enable incremental scanning.

For what a baseline matches, how to retire an entry after rotation, and how to
compare two baselines, see
[Baselines](../suppressions.md#baselines-suppress-what-already-existed).

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
- Never convert a source failure or coverage gap into an exclusion. KeyHog uses
  distinct nonzero exit semantics for invalid configuration, system failures,
  unavailable required GPU execution, and incomplete sources.

An exclusion decides which bytes are read. A baseline decides which findings
count as new. Reach for an exclusion only when the content should not be
scanned at all; otherwise use
[Fail only on new secrets](#fail-only-on-new-secrets). In a monorepo, never
hide one team's paths behind another team's ignore file. Give each team its own
subdirectory job with its own report.

## GitLab CI

```yaml
# .gitlab-ci.yml
keyhog:
  stage: test
  image: rust:1.89-bookworm
  before_script:
    - cargo install --locked --version '=0.5.72' keyhog
  script:
    # Exits non-zero on findings, which fails the job and gates the MR.
    - keyhog scan . --format gitlab-sast --output gl-sast-report.json
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
            cargo install --locked --version '=0.5.72' keyhog
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
      - cargo install --locked --version '=0.5.72' keyhog
      - |
        scan_status=0
        keyhog scan . --format json-envelope --output keyhog.json \
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

scan_status=0
keyhog scan . --format json-envelope --output keyhog.json \
  2>keyhog.stderr || scan_status=$?
printf '%s\n' "$scan_status" > keyhog.exit-code
cat keyhog.stderr >&2 || true
exit "$scan_status"
```

Configure the CI artifact publisher to retain `keyhog.json`, `keyhog.stderr`,
and `keyhog.exit-code` on both success and failure. When the output path is
writable, KeyHog writes the report even when every source failed to read; that
report then carries `scan covered nothing` and the reason each source failed.
An output-path failure exits `2` and cannot produce that report. Evaluate a
present report together with `keyhog.exit-code`.

## Buildkite

Use a dedicated artifact path so the report survives a finding exit:

```yaml
# .buildkite/pipeline.yml
steps:
  - label: ":mag: keyhog secret scan"
    command: |
      cargo install --locked --version '=0.5.72' keyhog
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
                    cargo install --locked --version '=0.5.72' keyhog
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
cargo install --locked --version '=0.5.72' keyhog
```

Review the release before changing the version. GitHub Action code and scanner
crate pinning are separate contracts; see [Pin Action code and scanner
releases](./github-action.md#pin-action-code-and-scanner-releases).

## Scan commit additions on main and release, not per PR

An added-line history scan is useful on `main` post-merge and on release tags,
but it is overkill for every PR. Add `--git-blobs .` when the policy must also
cover reflogs, stashes, tag messages, and unreachable objects that remain in the
repository object database. A typical setup:

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
- **Shallow clones fail the job:** `actions/checkout` defaults to
  `fetch-depth: 1`, which exposes only the checked-out HEAD commit. A
  `--git-history` or `--git-blobs` scan of that clone now exits `13` with
  `"scan_status":"partial"` and a `Git object unreadable or wrong object kind`
  gap, because the graft boundary names parent commits the clone does not
  contain. Set `fetch-depth: 0` on any job that scans history. A depth-1 clone
  of a single-commit repository stays clean and correct, because its boundary
  is the root commit and hides no parent.
- **`--git-history` misses branches you did not check out:** it covers the
  ancestry present in the current checkout only. A credential on another local
  ref, in a reflog or stash, or left behind by `git commit --amend` can be
  reported by `--git-blobs` and missed by `--git-history` with no coverage gap.
  Use `--git-blobs` when the policy has to cover the repository object database,
  not only reachable added-line history. Objects already pruned from the clone
  cannot be scanned.
- **A base ref that resolves to HEAD:** `keyhog scan --git-diff <BASE>` exits
  `0` after scanning zero bytes when `<BASE>` and `HEAD` are the same commit,
  which is what a shallow clone gives you for `origin/main`. The gate passes
  without examining anything. A base ref that is missing from the clone is
  safe by comparison: that exits `13` and refuses to report clean.
- **LFS files:** keyhog reads the LFS pointer file, not the
  contents. To scan LFS-stored binaries, enable LFS in checkout
  (`lfs: true`) and let the scanner pull the real file.
