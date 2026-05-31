# CI integration

A CI step that catches leaked credentials before they ship. Three
patterns: GitHub Actions, GitLab CI, generic shell. The examples gate
on findings and keep machine-readable reports available for triage.

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
      - uses: santhsecurity/keyhog/.github/actions/keyhog@v0.5.37
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
downloadable SARIF artifact remains available for review.

`fail-on-findings: 'false'` makes ordinary findings advisory after the
report/SARIF/artifact are written. A `--verify` scan that confirms a live
credential still fails the action with KeyHog exit code `10`.

Self-hosted GPU runners can add `keyhog backend --self-test --json`
before the scan. The JSON includes `ok`, `status`, `exit_code`,
`recommended_backend`, and one record per GPU probe; exit `4` means the
binary is present but the GPU scan path is not healthy and CI should route
to SIMD/CPU or fail the GPU lane.

To adopt on a repo that already has known findings, generate and commit a
baseline once, then wire it into the action:

```bash
keyhog scan --create-baseline .keyhog-baseline.json
git add .keyhog-baseline.json && git commit -m 'chore: keyhog baseline'
```

```yaml
      - uses: santhsecurity/keyhog/.github/actions/keyhog@v0.5.37
        with:
          baseline: .keyhog-baseline.json
```

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
curl -fsSL ...install.sh | KEYHOG_VERSION=v0.5.37 sh
```

Update the pin via a Renovate / Dependabot config or just bump it
by hand when a new release lands.

## Caching the install

The install script downloads a ~25 MB binary. On GitHub Actions, cache
it across runs:

```yaml
      - name: Cache keyhog
        id: cache-keyhog
        uses: actions/cache@v4
        with:
          path: ~/.local/bin/keyhog
          key: keyhog-${{ runner.os }}-v0.5.37
      - name: Install keyhog
        if: steps.cache-keyhog.outputs.cache-hit != 'true'
        run: curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | KEYHOG_VERSION=v0.5.37 sh
```

The `if: cache-hit != 'true'` guard is what makes the cache pay off - without
it the install step re-downloads on every run and the cache does nothing. Bump
both the cache key and the pinned `KEYHOG_VERSION` together when you upgrade.

## Scan history once per release, not per PR

A full git-history scan is the right thing to run on `main` post-merge
and on release tags, but it's overkill for every PR. A typical setup:

| Trigger        | Scan                            | Cost                                |
|----------------|----------------------------------|-------------------------------------|
| Pull request   | `keyhog scan .` (working tree)  | ~5 s on a typical repo              |
| Push to main   | `keyhog scan --git-history .`   | ~30 s on a year-old repo, scales linearly |
| Release tag    | `keyhog scan --git-history . --verify` | Adds 100 ms per finding for live verification |

The PR scan keeps the dev feedback loop fast. The post-merge history
scan catches anything that slipped through pre-commit + PR review.
The release scan verifies what's live, useful for the changelog
("rotated these N credentials before shipping").

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
