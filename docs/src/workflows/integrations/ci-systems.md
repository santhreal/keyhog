# CI systems

One recipe per CI system. [CI secret scanning](../ci.md) owns the contract:
what to fail on, how to preserve coverage, and which exit codes mean what.
These are the platform-specific ways to invoke it.

A source-built multi-backend binary must run `keyhog calibrate-autoroute`
before its first automatic scan. A portable single-backend build has no
routing choice.

## GitHub Actions

Use the [GitHub Action guide](../github-action.md) for the composite Action,
inputs and outputs, baseline adoption, monorepo partitions, SARIF publication,
and failure behavior. Use the [CI guide](../ci.md#github-actions) when a GitHub
workflow needs direct CLI flags such as `--git-history` or `--git-blobs`.

## GitLab CI

Use the canonical [GitLab CI workflow](../ci.md#gitlab-ci). It owns installation,
GitLab SAST output, artifact retention, and exit semantics.

## CircleCI

Use the canonical [CircleCI workflow](../ci.md#circleci). It owns shell setup,
scan status, and artifact handling.

## Drone CI

Use the canonical [Drone workflow](../ci.md#drone-ci). For another CI runner,
use the [generic shell workflow](../ci.md#generic-shell).

## Buildkite

Use the canonical [Buildkite workflow](../ci.md#buildkite).

## Jenkins

Use the canonical [Jenkins workflow](../ci.md#jenkins).

## Docker / Docker Compose

Scan a repo from a one-shot container without installing anything on
the host:

```bash
# No published registry image yet - build once from the repo (the Dockerfile
# ships in the repo root), then run the scan:
docker build -t keyhog:local https://github.com/santhreal/keyhog.git
docker run --rm -v "$PWD":/src keyhog:local \
  scan /src --backend cpu --format text
```

`docker-compose.yml`:

```yaml
services:
  keyhog:
    build: https://github.com/santhreal/keyhog.git
    volumes:
      - ./:/src:ro
    command: scan /src --backend cpu --format json-envelope
```

To scan a built image, use the Docker/OCI source so layers, manifests, and source
coverage are handled by KeyHog instead of manually unpacking an archive:

```bash
keyhog scan --docker-image my-image:latest
```
