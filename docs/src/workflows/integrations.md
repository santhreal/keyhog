# Integration recipes

Task-oriented recipes for running KeyHog locally, in hooks, and in CI. Install
the release with the [verified installer](../install.md), which also records the
host's autoroute evidence. A source-built multi-backend binary must run
`keyhog calibrate-autoroute` before its first automatic scan; a portable
single-backend build has no routing choice. An explicit `--backend cpu` in the
lightweight local-hook recipes below deliberately avoids machine-local routing
state.

For the full contract behind a command, use the focused reference instead of
treating a copied snippet as a second specification:

| Task | Start here |
|---|---|
| Protect local commits | [`keyhog hook install`](./precommit.md) |
| Gate a pull request | [CI integration](./ci.md) |
| Scan a large tree or choose a policy | [Detection settings and hardware](../detection.md#settings-hardware-and-result-parity) |
| Suppress an accepted finding | [Suppressions](../suppressions.md) |
| Interpret a failure | [Exit codes](../reference/exit-codes.md) |

If you only need one section, jump to:

- [Pre-commit hook (git)](#pre-commit-hook-git) - block secrets before they're committed
- [Pre-push hook (git)](#pre-push-hook-git) - block secrets before they leave the laptop
- [pre-commit framework](#pre-commit-framework) - `pre-commit` Python tool
- [Husky / lefthook](#husky--lefthook) - JavaScript ecosystem hooks
- [GitHub Actions](#github-actions) - PR + push CI
- [GitLab CI](#gitlab-ci)
- [CircleCI](#circleci)
- [Drone CI](#drone-ci)
- [BuildKite](#buildkite)
- [Docker / Docker Compose](#docker--docker-compose)
- [Jenkins](#jenkins)
- [As a library (Rust)](#as-a-library-rust)
- [Embedded in another CLI](#embedded-in-another-cli)
- [SARIF for GitHub Advanced Security](#sarif-for-github-advanced-security)
- [Slack / Discord / webhook alerts](#slack--discord--webhook-alerts)
- [Allowlists and baselines](#allowlists-and-baselines)
- [Exit codes](#exit-codes)

## Pre-commit hook (Git)

The maintained path is one command:

```bash
keyhog hook install
```

It installs a KeyHog-owned `.git/hooks/pre-commit` and refuses to overwrite an
unrelated hook unless you explicitly pass `--force`. See the
[pre-commit guide](./precommit.md) for ownership, uninstall, and staged-content
semantics.

If another hook manager owns the file, invoke the same canonical staged scan:

```bash
keyhog scan --fast --git-staged --backend cpu
```

`--backend cpu` makes this small local check independent of autoroute state. The
hook scans the Git index, not unstaged working-tree changes. Review and remove a
real secret; suppress an accepted result through `.keyhogignore` or
`.keyhogignore.toml`, never an invented `.keyhog.toml [suppress]` table.

## Pre-push hook (Git)

Pre-commit is the strongest gate. Pre-push catches secrets that landed
in earlier commits but were never pushed. Drop into `.git/hooks/pre-push`:

```bash
#!/usr/bin/env bash
set -euo pipefail
# Scan everything between the remote's HEAD and the local branch tip.
remote_sha="$(git ls-remote origin HEAD | awk '{print $1}')"
keyhog scan --git-diff "$remote_sha" \
  --backend cpu
```

This compact hook compares the checked-out branch with the remote's default
branch. Repositories that push several refs or use a different integration base
should enforce the exact ref range in CI, where the server supplies authoritative
base and head revisions. KeyHog's nonzero status is left intact so operational
errors cannot be mislabeled as findings.

## `pre-commit` framework

For projects that use the [pre-commit](https://pre-commit.com) Python
tool, add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/santhreal/keyhog
    rev: v0.5.41
    hooks:
      - id: keyhog
```

Then run `pre-commit install` once. KeyHog's repository-owned hook definition
supplies the canonical staged command; do not restate `entry`, filename, or
backend behavior in the consuming repository.

## Husky / lefthook

### Husky (`.husky/pre-commit`)

```bash
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

keyhog scan --fast --git-staged --backend cpu
```

### Lefthook (`lefthook.yml`)

```yaml
pre-commit:
  parallel: true
  commands:
    keyhog:
      run: keyhog scan --fast --git-staged --backend cpu
      fail_text: "secrets detected - see output above"
```

## GitHub Actions

### Recommended: composite action (3 lines + a baseline)

The most concise integration. Drop this file at
`.github/workflows/keyhog.yml` and that is the whole PR:

```yaml
name: keyhog
on: [push, pull_request]
permissions: { contents: read, security-events: write }
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: santhreal/keyhog/.github/actions/keyhog@v0.5.41
        with:
          path: .
          severity: high
          format: sarif
          baseline: .keyhog-baseline.json   # optional, see below
```

The Action downloads the platform release asset for release refs, verifies its
checksum, visibly calibrates every eligible backend when `backend` is omitted,
and uploads SARIF. Branch and SHA refs build the checked-out Action source.
Runtime and download size vary by release, host, cache warmth, and repository;
the job summary records the measured duration.

Release tags and explicit `version:` inputs require the matching published
asset and checksum and fail closed if either is unavailable. Only branch/SHA
Action refs may build from source, so a tagged workflow cannot silently execute
different code from the requested release.

Use `fail-on-findings: 'false'` when you want ordinary findings to be
advisory during rollout. If you also set `verify: 'true'`, any
verified-live credential still fails the job with exit code `10` after
the SARIF report and workflow artifact are uploaded.

**Adopt without breaking an existing repo.** If your tree already
contains findings keyhog would flag, generate a baseline once, commit
it, and the action will only fail on NEW secrets going forward:

```bash
keyhog scan --create-baseline .keyhog-baseline.json
git add .keyhog-baseline.json && git commit -m 'chore: keyhog baseline'
```

### Manual installation

If you want the install step explicit, use the verified installer:

```yaml
name: keyhog
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # full history for --git-diff / --git-history
      - name: Install keyhog
        run: |
          curl -fsSL https://raw.githubusercontent.com/santhreal/keyhog/main/install.sh | sh
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - name: Scan working tree
        id: keyhog
        continue-on-error: true
        run: keyhog scan . --severity high --format sarif -o keyhog.sarif
      - name: Upload SARIF
        if: always() && hashFiles('keyhog.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: keyhog.sarif
      - name: Enforce scan result
        if: steps.keyhog.outcome == 'failure'
        run: exit 1
```

`continue-on-error` applies only to the scan step so SARIF can upload. The final
step restores the failing job outcome for findings and operational errors; it
does not convert an incomplete scan into success.

### Scan only changed files in a PR (faster)

```yaml
- name: Scan PR diff
  if: github.event_name == 'pull_request'
  run: keyhog scan --git-diff origin/${{ github.base_ref }} --severity high
```

## GitLab CI

`.gitlab-ci.yml`:

```yaml
keyhog:
  stage: test
  image: ubuntu:24.04
  before_script:
    - apt-get update -qq && apt-get install -y -qq curl ca-certificates
    - curl -fsSL https://raw.githubusercontent.com/santhreal/keyhog/main/install.sh | sh
    - export PATH="$HOME/.local/bin:$PATH"
  script:
    - keyhog scan . --severity high --format gitlab-sast -o keyhog.json
  artifacts:
    when: always
    paths:
      - keyhog.json
    reports:
      sast: keyhog.json
  allow_failure: false
```

## CircleCI

`.circleci/config.yml`:

```yaml
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
            curl -fsSL https://raw.githubusercontent.com/santhreal/keyhog/main/install.sh | sh
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$BASH_ENV"
      - run:
          name: Scan working tree
          command: keyhog scan . --severity high --format json -o keyhog.json
      - store_artifacts:
          path: keyhog.json
          when: always
workflows:
  ci:
    jobs:
      - keyhog
```

## Drone CI

`.drone.yml`:

```yaml
kind: pipeline
name: keyhog
steps:
  - name: scan
    image: ubuntu:24.04
    commands:
      - apt-get update -qq && apt-get install -y -qq curl ca-certificates
      - curl -fsSL https://raw.githubusercontent.com/santhreal/keyhog/main/install.sh | sh
      - export PATH="$HOME/.local/bin:$PATH"
      - keyhog scan . --severity high --format json -o keyhog.json
```

## BuildKite

`.buildkite/pipeline.yml`:

```yaml
steps:
  - label: ":mag: keyhog secret scan"
    command: |
      curl -fsSL https://raw.githubusercontent.com/santhreal/keyhog/main/install.sh | sh
      export PATH="$HOME/.local/bin:$PATH"
      keyhog scan . --severity high --format json -o keyhog.json
    artifact_paths:
      - "keyhog.json"
```

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
    command: scan /src --backend cpu --format json
```

To scan a built image, use the Docker/OCI source so layers, manifests, and source
coverage are handled by KeyHog instead of manually unpacking an archive:

```bash
keyhog scan --docker-image my-image:latest
```

## Jenkins

Declarative pipeline (`Jenkinsfile`):

```groovy
pipeline {
    agent any
    stages {
        stage('keyhog') {
            steps {
                sh '''
                    curl -fsSL https://raw.githubusercontent.com/santhreal/keyhog/main/install.sh | sh
                    export PATH="$HOME/.local/bin:$PATH"
                    keyhog scan . --severity high --format json -o keyhog.json
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

## As a library (Rust)

Add to `Cargo.toml`:

```toml
[dependencies]
keyhog-core = "0.5"        # detector specs + Chunk/ChunkMetadata
keyhog-scanner = "0.5"     # CompiledScanner
```

(Detectors ship inside `keyhog-core` as a static-embedded TOML
corpus; there is no separate `keyhog-detectors` crate.)

Minimal scan:

```rust,ignore
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Built-in embedded detectors - no disk I/O, fail-closed on corrupt bundled TOML.
    let specs = keyhog_core::load_embedded_detectors_or_fail()?;
    // …or load from a directory of TOMLs:
    // let specs = load_detectors(std::path::Path::new("detectors"))?;

    let scanner = CompiledScanner::compile(specs)?;

    let bytes = std::fs::read("config.yaml")?;
    let chunk = Chunk {
        data: String::from_utf8_lossy(&bytes).into_owned().into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("config.yaml".into()),
            ..Default::default()
        },
    };
    for m in scanner.scan(&chunk) {
        println!(
            "{}:{} (detector {})",
            m.location.file_path.as_deref().unwrap_or("<memory>"),
            m.location.line.unwrap_or(0),
            m.detector_id
        );
    }
    Ok(())
}
```

For directory-tree / git / docker walking, drive `keyhog-sources`
or shell out to the CLI - `CompiledScanner` is one chunk at a time
by design.

The no-backend `scan` and `scan_coalesced` methods are deterministic portable
CPU calls. Explicit `scan_with_backend` and `scan_coalesced_with_backend` calls
are infallible at the type level and therefore enforce selection as a process
contract: missing selected SIMD exits `3`, while unavailable or failed selected
GPU execution exits `12`. They do not substitute another engine. Probe startup
eligibility with `warm_backend`; isolate the CLI in a subprocess when the host
application must survive a later accelerator runtime failure.

For finer-grained control of individual detector features:

```toml
[dependencies]
keyhog-scanner = { version = "0.5", default-features = false, features = ["ml", "decode", "entropy"] }
```

## Embedded in another CLI

Shell out:

```rust,ignore
use std::process::Command;
let out = Command::new("keyhog")
    .args(["scan", "--format", "jsonl", "--min-confidence", "0.4", "."])
    .output()?;
if !matches!(out.status.code(), Some(0 | 1)) {
    return Err(std::io::Error::other(format!(
        "keyhog did not complete the requested scan: {}",
        String::from_utf8_lossy(&out.stderr)
    )).into());
}
for line in out.stdout.split(|b| *b == b'\n') {
    if line.is_empty() { continue; }
    let finding: serde_json::Value = serde_json::from_slice(line)?;
    // ... do whatever
}
```

Or invoke the scan subcommand directly from a wrapper script:

```bash
keyhog scan /path/to/project --format jsonl --min-confidence 0.4
```

## SARIF for GitHub Advanced Security

```bash
keyhog scan . --format sarif -o keyhog.sarif
```

Then upload to GitHub Code Scanning (see the [CI integration guide](./ci.md)).
KeyHog tags every finding with CWE-798 (Use of Hard-coded
Credentials) and the OWASP A07:2021 (Identification and Authentication
Failures) category, so they surface in the right dashboards out of the
box.

## Slack / Discord / webhook alerts

Post a one-line summary on every finding:

```bash
#!/usr/bin/env bash
set -euo pipefail
set +e
findings_json="$(keyhog scan . --format json --min-confidence 0.4)"
scan_status=$?
set -e
case "$scan_status" in
  0|1) ;;
  *) echo "keyhog scan did not complete (exit $scan_status)" >&2; exit "$scan_status" ;;
esac
count="$(echo "$findings_json" | jq 'length')"
if [ "$count" -gt 0 ]; then
  curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"⚠ keyhog: $count secret(s) detected in $(basename "$PWD")\"}" \
    "$SLACK_WEBHOOK_URL"
  exit 1
fi
exit "$scan_status"
```

For Discord, replace `text` with `content`. For PagerDuty, use the
`events/v2/enqueue` endpoint with severity `critical` for `--severity
critical` findings.

## Allowlists and baselines

When you have known-but-unfixable findings (rotated test keys, public
demo creds, fixtures), use a baseline:

```bash
# Once
keyhog scan . --create-baseline .keyhog-baseline.json

# Forever after
keyhog scan . --baseline .keyhog-baseline.json
```

For per-file/per-line allowlists, the moving parts live in two separate files.
Scan execution policy has one canonical `[scan]` owner; unknown tables and
retired flat spellings fail closed:

`.keyhog.toml` at the repo root:

```toml
[scan]
severity       = "high"
min_confidence = 0.4
threads        = 8
exclude        = ["vendor/**", "node_modules/**", "**/*.lock"]
```

`.keyhogignore` (or `.keyhogignore.toml`) alongside it - gitignore-
style path globs plus `detector:<id>` and `hash:<sha256>` entries:

```gitignore
# silence all hits from this detector
detector:http-basic-auth

# gitignore-style path globs
vendor/**
node_modules/**
**/*.lock
```

See the [`.keyhogignore.toml` reference](../reference/keyhogignore-toml.md) for
the full schema.

## Exit codes

Use the canonical [exit-code reference](../reference/exit-codes.md) for the full
numeric contract. In CI, findings and verified-live credentials block the
change; configuration, system, backend, incomplete-coverage, panic, and
interruption outcomes also fail the job because the requested security control
did not complete. Never normalize every nonzero result to “findings found.”

---

## Choose a scan policy for scale

```bash
# Lightweight staged-content check; independent of host autoroute state
keyhog scan --fast --git-staged --backend cpu

# Deep release/security gate; uses calibrated automatic routing
keyhog scan . --deep --severity high

# High-precision policy for a large tree where false-positive review dominates
keyhog scan /large/tree --precision --severity high

# Force GPU for a diagnostic/benchmark run
keyhog scan . --backend gpu

# Write the final findings-only JSONL report to a file
keyhog scan . --format jsonl --output findings.jsonl
```

`--fast`, `--deep`, and `--precision` intentionally resolve different detection
policies and can produce different findings. Hardware and automatic backend
selection must not. Measure the chosen policy on the real corpus and let
persisted calibration choose among every measured-correct backend for that exact
host and workload. See [How detection works](../detection.md#configuration-presets)
and [Backends and routing](../backends.md) before changing policy or forcing an
engine.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Exit `12` with a selected-GPU diagnostic | Required, explicit, or autoroute-selected GPU execution could not start or complete | Run `keyhog backend --self-test`, recalibrate autoroute after fixing the GPU stack, or select another backend explicitly; KeyHog never substitutes CPU/SIMD inside the failed route |
| Findings count drops vs prior run | Baseline, detector corpus, scan policy, or `.keyhog.toml` changed | Compare the effective config, detector digest, baseline, and input scope from both runs |
| Pre-commit hook is slow | Scanning the whole repo on every commit | Use `--git-staged` not `scan .` |
| SARIF report is too large for the consumer | The selected scope produced more findings than the consumer accepts | Narrow the scanned source, use a reviewed baseline, or choose an explicit severity policy; do not hide an incomplete upload |
| Detection misses a known token | Detector absent from the loaded corpus / `--fast` disabled decode recursion or entropy discovery | Re-run with the embedded corpus and `--deep`; file an issue if it still misses |
