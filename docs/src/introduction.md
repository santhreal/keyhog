# KeyHog

A secret scanner. Built in Rust. Made to be fast on big repos, careful with
your time on small ones, and quiet about findings that aren't actually
credentials.

```text
$ keyhog scan .
K E Y H O G
───────────
v0.5.40 · secret scanner · 909 detectors
by santh

⚡ 16 cores | GPU: NVIDIA GeForce RTX 5090 | SIMD: AVX-512 | Hyperscan | 909 detectors (6054 patterns) io_uring | backend=simd-regex | gpu=none

scanned 12,841 files in 1.4 s
3 findings · 0 verified live · 1041 example fixtures suppressed
```

## What it does

Walks files - your working tree, your git history, a docker image, GitHub/GitLab/Bitbucket
repository collections, an S3, GCS, or Azure Blob bucket, a list of URLs - and reports leaked credentials. Every finding
has:

- a **detector** that fired (`stripe-secret-key`, `aws-access-key`, …)
- a **location** (file, line, offset, optionally commit hash and author)
- an **entropy score** + **confidence**
- an optional **live verification** result if you pass `--verify`

The list of detectors ships in TOML files under `detectors/`. There are 905
of them today, covering ~750 distinct services. Anyone can add or override
them without touching Rust code.

## What it doesn't do

- **No telemetry.** Findings stay local. The scanner never phones home.
- **No agent.** A daemon mode exists for IDE-save and stdin/single-file
  fast-path scans on Unix, but it's opt-in and stays on your machine.
- **No "AI-powered" detection.** Every detector is a regex with a
  service-specific anchor and a real verification endpoint. The ML
  scorer that bumps confidence on ambiguous matches is a tiny on-device
  MoE; no network calls.

## Why another scanner

Three things, in order of how much they matter:

1. **Precision.** A scanner that emits one false positive per ten findings
   teaches developers to ignore it. KeyHog suppresses example credentials
   (the Stripe docs key, the AWS sample key, the RFC 7519 specimen JWT),
   vendored bundles (minified jQuery, node_modules), and CI workflow
   `${{ secrets.NAME }}` references by default. The 22-repo dogfood
   corpus has 22 non-PEM findings, all true positives.

2. **Recall.** The detector corpus is built service-by-service. For every
   detector, the test suite carries positive shapes (env-var, JSON,
   YAML, header, URL), negative shapes (placeholder, EXAMPLE marker),
   and adversarial evasions (split across lines, hex/base64-encoded,
   reversed via Caesar cipher). If a shape isn't in the suite, the
   detector isn't shipped.

3. **Speed.** Hyperscan SIMD prefilter, AVX-512 entropy gate, GPU
   literal scan for big workloads. A million-LOC monorepo scans in
   under three minutes on a modern laptop without warming any caches.
   Pre-commit incremental scans are sub-100 ms.

## Get going

```sh
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | sh

# Windows (PowerShell)
iwr https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.ps1 -useb | iex
```

Then:

```sh
keyhog scan .
```

The [Install](./install.md) page has package-manager, build-from-source,
and offline-install paths. The [Your first scan](./first-scan.md) page
walks through what the output means and where to go from there.

## Where things live

- **Source:** [github.com/santhsecurity/keyhog](https://github.com/santhsecurity/keyhog)
- **Issues:** [github.com/santhsecurity/keyhog/issues](https://github.com/santhsecurity/keyhog/issues)
- **Releases:** [github.com/santhsecurity/keyhog/releases](https://github.com/santhsecurity/keyhog/releases)
- **Security:** report vulnerabilities to `security@santh.dev` (PGP-encrypted preferred - key in repo `SECURITY.md`)

License: MIT.
