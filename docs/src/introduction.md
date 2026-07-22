# KeyHog

A secret scanner. Built in Rust. Made to be fast on big repos, careful with
your time on small ones, and quiet about findings that aren't actually
credentials.

```text
$ keyhog scan .
    K E Y H O G
    ───────────
    v0.5.44 · secret scanner · 923 detectors
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

Most of what KeyHog offers is not visible from `keyhog scan .` alone: eleven
source types (git history, GitHub/GitLab/Bitbucket orgs, S3/GCS/Azure buckets,
docker images, whole-machine audits), seventeen subcommands, GPU acceleration,
and always-on process hardening. [What KeyHog can do](./capabilities.md) is the
map, with every capability linking to its chapter.

The detector corpus ships as TOML files under `detectors/`. Run
`keyhog detectors --format json` to inspect the exact corpus embedded in the
installed binary. A custom `--detectors <DIR>` selects an explicit replacement
corpus, so detector policy can change without changing scanner code and without
a hidden merge with embedded rules.

## What it doesn't do

- **No telemetry.** Findings stay local. The scanner never phones home.
- **No agent.** A daemon service exists for IDE-save and stdin/single-file
  fast-path scans on Unix. Starting it is explicit and it stays on your
  machine; once you start a compatible daemon, the ordinary Unix scan default
  (`--daemon=auto`, including an omitted flag) uses it for eligible requests.
  Use `--daemon=off` to force the in-process path.
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
   `${{ secrets.NAME }}` references by default. Repository dogfood and
   detector-specific negative twins keep those decisions exercised through the
   same scanner path users run.

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

   VYRE CUDA and WGPU can match region presence for the whole compiled corpus
   in one resident dispatch, then feed the same confirmation pipeline as the
   CPU backends. An RTX 5090 diagnostic recorded a 24.6 ms VYRE CUDA median and
   69.6 ms for Hyperscan with identical findings. That run did not attest a
   clean source tree, so it is historical performance evidence rather than a
   release crossover claim. See [Backends and routing](./backends.md).

## Get going

The canonical install path is:

```sh
curl -fsSL https://santh.dev/keyhog/install.sh | sh
```

On Windows PowerShell:

```powershell
iwr https://santh.dev/keyhog/install.ps1 -UseBasicParsing | iex
```

Before this pinned release example, install `minisign`; Debian/Ubuntu also
needs the Linux asset's `libhyperscan5` runtime. The complete platform-specific
prerequisite commands live in the [install guide](./install.md#pinned-verified-install-linux--macos).

```sh
# Linux / macOS, pinned and authenticated before execution
TAG=v0.5.44
BASE="https://github.com/santhreal/keyhog/releases/download/$TAG"
PUB='RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go'
curl -fSLO "$BASE/install.sh" -fSLO "$BASE/install.sh.minisig"
minisign -Vm install.sh -P "$PUB"
KEYHOG_VERSION="$TAG" sh install.sh
```

Windows uses the same signed release flow. Copy the PowerShell commands from
the [Install](./install.md#pinned-verified-install-windows) page.

Then:

```sh
keyhog scan .
```

The [Install](./install.md) page has package-manager, build-from-source,
and offline-install paths. The [Your first scan](./first-scan.md) page
walks through what the output means and where to go from there.

## Where things live

- **Source:** [github.com/santhreal/keyhog](https://github.com/santhreal/keyhog)
- **Issues:** [github.com/santhreal/keyhog/issues](https://github.com/santhreal/keyhog/issues)
- **Releases:** [github.com/santhreal/keyhog/releases](https://github.com/santhreal/keyhog/releases)
- **Security:** use [GitHub private vulnerability reporting](https://github.com/santhreal/keyhog/security/advisories/new) first. If the form is unavailable, email `security@santh.dev`; PGP is not required. See the [security policy](https://github.com/santhreal/keyhog/blob/main/SECURITY.md).

License: MIT OR Apache-2.0.
Read the [MIT terms](https://github.com/santhreal/keyhog/blob/main/LICENSE-MIT) and
[Apache-2.0 terms](https://github.com/santhreal/keyhog/blob/main/LICENSE-APACHE).
