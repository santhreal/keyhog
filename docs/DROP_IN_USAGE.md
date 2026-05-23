# Drop-in usage

Copy-paste integrations for KeyHog. Every snippet here is a complete,
self-contained config: drop it in the indicated file, commit, and it
works. No additional setup required beyond `cargo install keyhog`.

If you only need one section, jump to:

- [Pre-commit hook (git)](#pre-commit-hook-git) — block secrets before they're committed
- [Pre-push hook (git)](#pre-push-hook-git) — block secrets before they leave the laptop
- [pre-commit framework](#pre-commit-framework) — `pre-commit` Python tool
- [Husky / lefthook](#husky--lefthook) — JavaScript ecosystem hooks
- [GitHub Actions](#github-actions) — PR + push CI
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
keyhog hook install --pre-push   # adds .git/hooks/pre-push too
```

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
    rev: v0.5.12
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
      fail_text: "secrets detected — see output above"
```

## GitHub Actions

PR + push scan with SARIF upload to GitHub Code Scanning. Put this at
`.github/workflows/keyhog.yml`:

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
          curl -fsSL https://github.com/santhsecurity/keyhog/releases/latest/download/keyhog-linux-x86_64.tar.gz \
            | tar -xz -C /usr/local/bin
      - name: Scan working tree
        run: keyhog scan . --format sarif -o keyhog.sarif --min-confidence 0.3
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: keyhog.sarif
      - name: Fail on high-severity findings
        run: keyhog scan . --severity critical,high --min-confidence 0.5
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
  image: rust:latest
  before_script:
    - cargo install keyhog --locked
  script:
    - keyhog scan . --format json -o keyhog.json --min-confidence 0.3
    - keyhog scan . --severity critical,high --min-confidence 0.5
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
      - image: cimg/rust:1.83
    steps:
      - checkout
      - run:
          name: Install keyhog
          command: cargo install keyhog --locked
      - run:
          name: Scan working tree
          command: keyhog scan . --format json -o keyhog.json --min-confidence 0.3
      - run:
          name: Fail on high-severity findings
          command: keyhog scan . --severity critical,high --min-confidence 0.5
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
    image: rust:latest
    commands:
      - cargo install keyhog --locked
      - keyhog scan . --min-confidence 0.3 --format json -o keyhog.json
      - keyhog scan . --severity critical,high --min-confidence 0.5
```

## BuildKite

`.buildkite/pipeline.yml`:

```yaml
steps:
  - label: ":mag: keyhog secret scan"
    command: |
      cargo install keyhog --locked
      keyhog scan . --min-confidence 0.3 --format text
      keyhog scan . --severity critical,high --min-confidence 0.5
    artifact_paths:
      - "keyhog.json"
```

## Docker / Docker Compose

Scan a repo from a one-shot container without installing anything on
the host:

```bash
docker run --rm -v "$PWD":/src ghcr.io/santhsecurity/keyhog:latest \
  scan /src --format text --min-confidence 0.3
```

`docker-compose.yml`:

```yaml
services:
  keyhog:
    image: ghcr.io/santhsecurity/keyhog:latest
    volumes:
      - ./:/src:ro
    command: scan /src --format json --min-confidence 0.3
```

To scan a built image's filesystem:

```bash
docker save my-image:latest | tar -xO -C /tmp/imgfs
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
                    cargo install keyhog --locked
                    keyhog scan . --format json -o keyhog.json --min-confidence 0.3
                    keyhog scan . --severity critical,high --min-confidence 0.5
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
keyhog-scanner = "0.5"
keyhog-detectors = "0.5"
```

Minimal scan:

```rust
use keyhog_scanner::{Scanner, ScannerConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = Scanner::with_config(ScannerConfig {
        min_confidence: 0.5,
        ..Default::default()
    })?;
    let findings = scanner.scan_path("./my-project")?;
    for f in &findings {
        println!("{}:{} — {} (confidence {:.2})",
            f.path.display(), f.line, f.detector, f.confidence);
    }
    Ok(())
}
```

Scan in-memory bytes (no filesystem):

```rust
let bytes = std::fs::read("config.yaml")?;
let findings = scanner.scan_bytes(&bytes, "config.yaml")?;
```

Stream scanning of stdin:

```rust
use std::io::Read;
let mut buf = Vec::new();
std::io::stdin().read_to_end(&mut buf)?;
let findings = scanner.scan_bytes(&buf, "<stdin>")?;
```

For finer-grained control of individual detector families:

```toml
[dependencies]
keyhog-scanner = { version = "0.5", default-features = false, features = ["gpu", "ml"] }
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

Use the harness binary (deterministic, no GPU/network):

```bash
echo "scan /path/to/project --format jsonl" | keyhog --no-color
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

For per-file/per-line allowlists in source, drop a `.keyhog.toml` at
the repo root:

```toml
[allowlist]
paths = [
  "vendor/**",
  "node_modules/**",
  "**/*.lock",
]
detectors = ["http-basic-auth"]  # silence all hits from this detector
secrets = ["AKIA[A-Z0-9]+EXAMPLE"]  # regex over the matched value

[performance]
threads = "physical_cores"  # default "physical_cores/2" in TTY
gpu = "auto"                # "force" | "off" | "auto"
```

See [keyhogignore-toml.md](keyhogignore-toml.md) for the full schema.

## Exit codes

- `0` — no findings above `--min-confidence`
- `1` — one or more findings at or above `--min-confidence`
- `2` — scan error (path missing, IO failure, parse error)
- `64` — argument parse error (matches `EX_USAGE`)

CI gates should look for `exit 1` to mean "block the build" and treat
`exit 2` as an infrastructure problem to surface to the on-call.

---

## Performance flags for tight CI budgets

```bash
# Skip ML + decode + entropy + multiline — pre-commit speed
keyhog scan . --fast --min-confidence 0.5

# Maximum detection depth — release/security gate
keyhog scan . --deep --min-confidence 0.3

# Pin worker count to host CPU
keyhog scan . --threads $(nproc)

# Force GPU when an RTX is present (5x faster on 60+ MB scans)
keyhog scan . --gpu force

# Stream findings to a file (no buffer) for very large scans
keyhog scan . --format jsonl >> findings.jsonl
```

`--fast` typically runs in under 200 ms on a 100-file commit and is
the right default for pre-commit. `--deep` adds ~30% wall time but
catches multi-line and decoded secrets the fast path skips.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `error: GPU requested but not available` | `--gpu force` on a non-GPU host | Drop the flag — `auto` falls back to SIMD |
| Findings count drops vs prior run | `.keyhog-baseline.json` is up-to-date or `.keyhog.toml` widened | `git diff .keyhog-baseline.json .keyhog.toml` |
| Pre-commit hook is slow | Scanning the whole repo on every commit | Use `--git-staged` not `scan .` |
| SARIF upload rejects file | `min_confidence` too low; thousands of findings | Raise to ≥0.3 for SARIF specifically |
| Detection misses a known token | Detector not enabled / `--fast` skipped the decoder | Re-run with `--deep` to confirm; file an issue if it still misses |
