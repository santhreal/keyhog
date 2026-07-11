# KeyHog

A secret scanner. Built in Rust. Made to be fast on big repos, careful with
your time on small ones, and quiet about findings that aren't actually
credentials.

```text
$ keyhog scan .
    K E Y H O G
    ───────────
    v0.5.40 · secret scanner · 923 detectors
    by santh

  ┌    CRITICAL ─── Stripe Secret Key
  │ Secret:     sk_l...p7dc
  │ Location:   src/config/staging.env:14
  │ Confidence: ■■■■■■ 100%
  │ Action:     Roll the exposed Stripe secret key in the Dashboard, update production consumers, then delete the old key.
  │ Docs:       https://docs.stripe.com/keys#roll-api-key
  └─────────────────────────────────────────────

  ━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1 secret found · 1 unverified

Scan complete. Found 1 secret in 1.42s.
```

## What it does

Walks files - your working tree, your git history, a docker image, GitHub/GitLab/Bitbucket
repository collections, an S3, GCS, or Azure Blob bucket, a list of URLs - and reports leaked credentials. Every finding
has:

- a **detector** that fired (`stripe-secret-key`, `aws-access-key`, …)
- a **location** (file, line, offset, optionally commit hash and author)
- an **entropy score** + **confidence**
- an optional **live verification** result if you pass `--verify`

The detector corpus ships as TOML files under `detectors/`. Run
`keyhog detectors --format json` to inspect the exact corpus embedded in the
installed binary. A custom `--detectors <DIR>` selects an explicit replacement
corpus, so detector policy can change without changing scanner code and without
a hidden merge with embedded rules.

## What it doesn't do

- **No telemetry.** Findings stay local. The scanner never phones home.
- **No agent.** A daemon mode exists for IDE-save and stdin/single-file
  fast-path scans on Unix, but it's opt-in and stays on your machine.
- **No remote "AI-powered" detection.** Service detectors use TOML regexes and
  structural validators; generic detectors compose assignment shape, entropy,
  BPE token efficiency, context, and local confidence policy. The small
  on-device MoE scores ambiguous candidates without sending content away.
  Verification is optional and is the only detection-adjacent step that calls a
  service endpoint.

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

3. **Speed.** Hyperscan SIMD prefilter, vectorized entropy, and a GPU
   region-presence route can accelerate different workloads. The winning route
   depends on the binary, detector/config digest, source shape, candidate
   density, cache state, CPU, GPU, driver, and storage. KeyHog records
   fastest-correct calibration for the installed host instead of treating a
   benchmark from another machine as a routing threshold.

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
