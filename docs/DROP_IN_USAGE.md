# Drop-in usage

Copy-paste integrations for KeyHog. Every snippet here is a complete,
self-contained config: drop it in the indicated file, commit, and it
works. No additional setup required beyond installing keyhog via the
[one-line installer](https://github.com/santhsecurity/keyhog#install)
(`curl -fsSL .../install.sh | sh` on Linux/macOS, `iwr .../install.ps1 -useb | iex`
on Windows) or a source build (`cargo build --release` inside the repo).

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
- [Bazel](#bazel)
- [As a library (Rust)](#as-a-library-rust)
- [Embedded in another CLI](#embedded-in-another-cli)
- [SARIF for GitHub Advanced Security](#sarif-for-github-advanced-security)
- [Slack / Discord / webhook alerts](#slack--discord--webhook-alerts)
- [Allowlists and baselines](#allowlists-and-baselines)
- [Exit codes](#exit-codes)

## Pre-commit hook (git)

Block any commit that contains a high-confidence secret. Drop this into
`.git/hooks/pre-commit` and `chmod +x` it.

```bash
#!/usr/bin/env bash
set -euo pipefail
keyhog scan --git-staged \
  --min-confidence 0.5 \
  --format text \
  --fast \
  || {
    echo
    echo "✘ keyhog found secrets in staged files."
    echo "  Either remove them, raise --min-confidence, or"
    echo "  add an allowlist entry to .keyhog.toml."
    exit 1
  }
```

Install it for every clone in your repo by committing the script under
`scripts/install-hooks.sh` and adding it to your README onboarding.

Or use the bundled installer:

```bash
keyhog hook install              # writes .git/hooks/pre-commit
```

The pre-push hook is the shell snippet shown above; there is no
`--pre-push` flag on `hook install` yet.

## Pre-push hook (git)

Pre-commit is the strongest gate. Pre-push catches secrets that landed
in earlier commits but were never pushed. Drop into `.git/hooks/pre-push`:

```bash
#!/usr/bin/env bash
set -euo pipefail
# Scan everything between the remote's HEAD and the local branch tip.
remote_sha="$(git ls-remote origin HEAD | awk '{print $1}')"
keyhog scan --git-diff "$remote_sha" \
  --min-confidence 0.4 \
  --format text \
  || {
    echo "✘ keyhog found secrets in commits about to be pushed."
    exit 1
  }
```

## pre-commit framework

For projects that use the [pre-commit](https://pre-commit.com) Python
tool, add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/santhsecurity/keyhog
    rev: v0.5.37
    hooks:
      - id: keyhog
        name: keyhog secret scan (staged)
        entry: keyhog scan --git-staged --min-confidence 0.5 --fast
        language: system
        pass_filenames: false
        always_run: true
```

Then `pre-commit install` once and every contributor's commits get
scanned automatically.

## Husky / lefthook

### Husky (`.husky/pre-commit`)

```bash
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

keyhog scan --git-staged --min-confidence 0.5 --fast
```

### Lefthook (`lefthook.yml`)

```yaml
pre-commit:
  parallel: true
  commands:
    keyhog:
      run: keyhog scan --git-staged --min-confidence 0.5 --fast --format text
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
      - uses: santhsecurity/keyhog/.github/actions/keyhog@v0.5.37
        with:
          path: .
          severity: high
          format: sarif
          baseline: .keyhog-baseline.json   # optional, see below
```

Cost to your CI: ~20 MB binary download (cacheable), ~400 ms cold-start
in CI (auto-disables GPU on hosted runners), ~10 s wall-clock for a
5,000-file repo, single `libhyperscan5` apt package auto-installed on
Ubuntu runners. No Python, no JVM, no Docker daemon. SARIF auto-uploads
to GitHub code-scanning.

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

### Manual (no composite-action dependency)

If you want the install step explicit, this is equivalent:

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
          mkdir -p "$HOME/.local/bin"
          curl -fsSL https://github.com/santhsecurity/keyhog/releases/latest/download/keyhog-linux-x86_64 \
            -o "$HOME/.local/bin/keyhog"
          chmod +x "$HOME/.local/bin/keyhog"
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - name: Scan working tree
        run: keyhog scan . --format sarif -o keyhog.sarif --min-confidence 0.3
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: keyhog.sarif
      - name: Fail on high-severity findings
        run: keyhog scan . --severity high --min-confidence 0.5
```

### Scan only changed files in a PR (faster)

```yaml
- name: Scan PR diff
  if: github.event_name == 'pull_request'
  run: keyhog scan --git-diff origin/${{ github.base_ref }} --min-confidence 0.4
```

## GitLab CI

`.gitlab-ci.yml`:

```yaml
keyhog:
  stage: test
  image: alpine:latest
  before_script:
    - apk add --no-cache bash curl ca-certificates
    - curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | sh
    - export PATH="$HOME/.local/bin:$PATH"
  script:
    - keyhog scan . --format json -o keyhog.json --min-confidence 0.3
    - keyhog scan . --severity high --min-confidence 0.5
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
            curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | sh
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$BASH_ENV"
      - run:
          name: Scan working tree
          command: keyhog scan . --format json -o keyhog.json --min-confidence 0.3
      - run:
          name: Fail on high-severity findings
          command: keyhog scan . --severity high --min-confidence 0.5
      - store_artifacts:
          path: keyhog.json
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
    image: alpine:latest
    commands:
      - apk add --no-cache bash curl ca-certificates
      - curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | sh
      - export PATH="$HOME/.local/bin:$PATH"
      - keyhog scan . --min-confidence 0.3 --format json -o keyhog.json
      - keyhog scan . --severity high --min-confidence 0.5
```

## BuildKite

`.buildkite/pipeline.yml`:

```yaml
steps:
  - label: ":mag: keyhog secret scan"
    command: |
      curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | sh
      export PATH="$HOME/.local/bin:$PATH"
      keyhog scan . --min-confidence 0.3 --format text
      keyhog scan . --severity high --min-confidence 0.5
    artifact_paths:
      - "keyhog.json"
```

## Docker / Docker Compose

Scan a repo from a one-shot container without installing anything on
the host:

```bash
# No published registry image yet - build once from the repo (the Dockerfile
# ships in the repo root), then run the scan:
docker build -t keyhog:local https://github.com/santhsecurity/keyhog.git
docker run --rm -v "$PWD":/src keyhog:local \
  scan /src --format text --min-confidence 0.3
```

`docker-compose.yml`:

```yaml
services:
  keyhog:
    build: https://github.com/santhsecurity/keyhog.git
    volumes:
      - ./:/src:ro
    command: scan /src --format json --min-confidence 0.3
```

To scan a built image's filesystem:

```bash
mkdir -p /tmp/imgfs
docker save my-image:latest | tar -x -C /tmp/imgfs
keyhog scan /tmp/imgfs --min-confidence 0.4
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
                    curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | sh
                    export PATH="$HOME/.local/bin:$PATH"
                    keyhog scan . --format json -o keyhog.json --min-confidence 0.3
                    keyhog scan . --severity high --min-confidence 0.5
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

## Bazel

`BUILD.bazel`:

```python
load("@rules_rust//rust:defs.bzl", "rust_binary")

# Pre-built binary check
sh_test(
    name = "keyhog_scan",
    srcs = ["//tools:keyhog_scan.sh"],
    args = ["--min-confidence", "0.3"],
    tags = ["secret-scan"],
)
```

`tools/keyhog_scan.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
keyhog scan "$@" $(bazel info workspace)
```

Run with `bazel test //:keyhog_scan`.

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

```rust
use keyhog_core::{load_detectors_from_str, Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Built-in embedded detectors - no disk I/O. Each entry is
    // (filename, toml_text); parse them all into a flat Vec<DetectorSpec>.
    let mut specs = Vec::new();
    for (_name, toml_text) in keyhog_core::embedded_detector_tomls() {
        specs.extend(load_detectors_from_str(toml_text)?);
    }
    // …or load from a directory of TOMLs:
    // let specs = keyhog_core::load_detectors(std::path::Path::new("detectors"))?;

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
        println!("{}: {} (detector {})", m.line, m.credential_redacted, m.detector_id);
    }
    Ok(())
}
```

For directory-tree / git / docker walking, drive `keyhog-sources`
or shell out to the CLI - `CompiledScanner` is one chunk at a time
by design.

For finer-grained control of individual detector features:

```toml
[dependencies]
keyhog-scanner = { version = "0.5", default-features = false, features = ["ml", "decode", "entropy"] }
```

## Embedded in another CLI

Shell out:

```rust
use std::process::Command;
let out = Command::new("keyhog")
    .args(["scan", "--format", "jsonl", "--min-confidence", "0.4", "."])
    .output()?;
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

Then upload to GitHub Code Scanning (see [GitHub Actions](#github-actions)
above). KeyHog tags every finding with CWE-798 (Use of Hard-coded
Credentials) and the OWASP A07:2021 (Identification and Authentication
Failures) category, so they surface in the right dashboards out of the
box.

## Slack / Discord / webhook alerts

Post a one-line summary on every finding:

```bash
#!/usr/bin/env bash
set -euo pipefail
findings_json="$(keyhog scan . --format json --min-confidence 0.4)"
count="$(echo "$findings_json" | jq 'length')"
if [ "$count" -gt 0 ]; then
  curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"⚠ keyhog: $count secret(s) detected in $(basename "$PWD")\"}" \
    "$SLACK_WEBHOOK_URL"
  exit 1
fi
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

For per-file/per-line allowlists, the moving parts live in two
separate files (the parser is flat, not the nested `[allowlist]` /
`[performance]` tables an earlier version of this doc advertised):

`.keyhog.toml` at the repo root - flat key/value, every field
mirrors a CLI flag:

```toml
severity        = "high"
min_confidence  = 0.4
threads         = 8
exclude_paths   = ["vendor/**", "node_modules/**", "**/*.lock"]
```

`.keyhogignore` (or `.keyhogignore.toml`) alongside it - gitignore-
style path globs plus `detector:<id>` and `hash:<sha256>` entries:

```
# silence all hits from this detector
detector:http-basic-auth

# gitignore-style path globs
vendor/**
node_modules/**
**/*.lock
```

See [keyhogignore-toml.md](keyhogignore-toml.md) for the full schema.

## Exit codes

- `0` - no findings
- `1` - findings at or above `--severity` / `--min-confidence`
- `2` - runtime error (bad flag, missing/unreadable path, config error)
- `10` - live credentials confirmed (only under `--verify`)
- `11` - scanner thread panicked mid-scan (state unreliable)

CI gates should treat `exit 1` and `exit 10` as build-blocking scan
outcomes. `exit 2` is an infrastructure/configuration problem to surface
to the on-call.

---

## Performance flags for tight CI budgets

```bash
# Skip ML + decode + entropy + multiline - pre-commit speed
keyhog scan . --fast --min-confidence 0.5

# Maximum detection depth - release/security gate
keyhog scan . --deep --min-confidence 0.3

# Pin worker count to host CPU
keyhog scan . --threads $(nproc)

# Force GPU when an RTX is present (5x faster on 60+ MB scans)
keyhog scan . --backend gpu

# Stream findings to a file (no buffer) for very large scans
keyhog scan . --format jsonl >> findings.jsonl
```

`--fast` typically runs in under 200 ms on a 100-file commit and is
the right default for pre-commit. `--deep` adds ~30% wall time but
catches multi-line and decoded secrets the fast path skips.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `error: GPU requested but not available` | `--backend gpu` on a non-GPU host | Drop the flag - `auto` falls back to SIMD |
| Findings count drops vs prior run | `.keyhog-baseline.json` is up-to-date or `.keyhog.toml` widened | `git diff .keyhog-baseline.json .keyhog.toml` |
| Pre-commit hook is slow | Scanning the whole repo on every commit | Use `--git-staged` not `scan .` |
| SARIF upload rejects file | `min_confidence` too low; thousands of findings | Raise to ≥0.3 for SARIF specifically |
| Detection misses a known token | Detector not enabled / `--fast` skipped the decoder | Re-run with `--deep` to confirm; file an issue if it still misses |
