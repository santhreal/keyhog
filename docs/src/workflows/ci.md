# CI integration

Add KeyHog in two stages: make findings visible with a durable report, then
turn new findings into a merge gate. The recipes below keep scanning,
enforcement, and report retention explicit so a missing upload or unsupported
source cannot look like a clean run.

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
        with:
          fetch-depth: 0   # scan full history, not just HEAD
      - uses: santhsecurity/keyhog/.github/actions/keyhog@v0.5.41
        with:
          path: .
          severity: high
          format: sarif
```

The composite action installs KeyHog, writes a SARIF report, uploads it
to **Security -> Code scanning**, attaches the report as a workflow
artifact, and prints a job summary with the finding count, raw exit code,
and scan duration.

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
      - uses: santhsecurity/keyhog/.github/actions/keyhog@v0.5.41
        with:
          baseline: .keyhog-baseline.json
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
    - apt-get update -qq && apt-get install -y curl libhyperscan-dev
    - curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | sh
  script:
    # Exits non-zero on findings, which fails the job and gates the MR.
    - ~/.local/bin/keyhog scan . --format sarif --output keyhog.sarif
  artifacts:
    when: always           # keep the report even when the scan fails the job
    paths:
      - keyhog.sarif
```

The job's exit status gates the merge request (keyhog exits non-zero on
findings) and the SARIF is kept as a downloadable artifact. Note: GitLab's
`artifacts:reports:sast` expects GitLab's own SAST JSON schema, **not** SARIF,
so to surface findings in the MR security dashboard you must convert the SARIF
to that format (e.g. a SARIF-to-GitLab-SAST converter step) - pointing
`reports:sast` directly at a SARIF file does not work.

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
            curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | sh
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

## Drone CI / generic shell

```yaml
# .drone.yml
pipeline:
  keyhog:
    image: alpine:3.20
    commands:
      - apk add --no-cache curl
      - curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | sh
      - $HOME/.local/bin/keyhog scan .
```

Same pattern works in Jenkins, Buildkite, Woodpecker, Concourse, or
any CI that can run a shell. The two lines are the install command
and the scan command.

## Pinning a version

The install scripts pull the latest release by default. For
reproducible CI, pin a specific version:

```sh
curl -fsSL ...install.sh | KEYHOG_VERSION=v0.5.41 sh
```

Update the pin via a Renovate / Dependabot config or just bump it
by hand when a new release lands.

## Scan history once per release, not per PR

A full git-history scan is the right thing to run on `main` post-merge
and on release tags, but it's overkill for every PR. A typical setup:

| Trigger        | Scan                            | Purpose |
|----------------|----------------------------------|---------|
| Pull request   | `keyhog scan .` (working tree)  | Fast feedback over proposed files |
| Push to main   | `keyhog scan --git-history .`   | Cover reachable repository history |
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
keyhog scan --github-org acme --precision --format jsonl --output acme.jsonl
keyhog scan --gitlab-group platform --precision --format jsonl --output platform.jsonl
keyhog scan --s3-bucket audit-archive --s3-prefix production/ \
  --precision --format jsonl --output audit-archive.jsonl
```

Use the source limits from the [CLI reference](../reference/cli.md) to define the
intended coverage boundary. Reaching one is an incomplete-source result, not a
clean scan; size the limit deliberately or split the inventory into more jobs.

Start in report-only mode, review coverage gaps separately from findings, then
enable enforcement once baselines and exclusions are owned. Runtime and route
choice vary with detector policy, source shape, cache state, host CPU/GPU, and
network limits. Calibrate autoroute on the actual worker class; do not copy a
routing cache between machines or force GPU/CPU based only on input size.

For long-lived workers, the [daemon workflow](./daemon.md) avoids repeated
startup work. Ephemeral hosted CI should normally use the ordinary process path
unless the job performs enough scans to amortize daemon startup and explicitly
checks daemon compatibility.

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
  which only fetches HEAD. A `--git-history` scan against a shallow
  clone sees zero commits. Set `fetch-depth: 0` if you want history.
- **LFS files:** keyhog reads the LFS pointer file, not the
  contents. To scan LFS-stored binaries, enable LFS in checkout
  (`lfs: true`) and let the scanner pull the real file.
