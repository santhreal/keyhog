# CI integration

A CI step that catches leaked credentials before they ship. Three
patterns: GitHub Actions, GitLab CI, generic shell. All exit non-zero
on findings, which is what CI wants.

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
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # scan full history, not just HEAD
      - name: Install keyhog
        run: curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | sh
      - name: Scan repo
        run: ~/.local/bin/keyhog scan . --format sarif > keyhog.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: keyhog.sarif
```

The `upload-sarif` action posts findings to the **Security -> Code
scanning** tab. `if: always()` makes sure findings show up even when
the scan exits non-zero.

To scan ONLY git history (the more common pre-merge gate):

```yaml
      - name: Scan history
        run: ~/.local/bin/keyhog scan --git-history . --format sarif > keyhog.sarif
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
    - ~/.local/bin/keyhog scan . --format sarif > keyhog.sarif
  artifacts:
    when: always
    reports:
      sast: keyhog.sarif
    paths:
      - keyhog.sarif
```

GitLab consumes SARIF as a `sast` report and surfaces findings in
the merge request security dashboard.

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
          command: keyhog scan .
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
curl -fsSL ...install.sh | KEYHOG_VERSION=v0.5.33 sh
```

Update the pin via a Renovate / Dependabot config or just bump it
by hand when a new release lands.

## Caching the install

The install script downloads a ~25 MB binary. On GitHub Actions, cache
it across runs:

```yaml
      - name: Cache keyhog
        uses: actions/cache@v4
        with:
          path: ~/.local/bin/keyhog
          key: keyhog-${{ runner.os }}-v0.5.33
```

Bump the cache key when you bump the pinned version.

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
- **Shallow clones:** `actions/checkout` defaults to `fetch-depth: 1`,
  which only fetches HEAD. A `--git-history` scan against a shallow
  clone sees zero commits. Set `fetch-depth: 0` if you want history.
- **LFS files:** keyhog reads the LFS pointer file, not the
  contents. To scan LFS-stored binaries, enable LFS in checkout
  (`lfs: true`) and let the scanner pull the real file.
