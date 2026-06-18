<p align="center">
  <img src="docs/assets/keyhog-banner.svg" alt="keyhog - secret scanner - 902 detectors - gpu" width="560" />
</p>

<p align="center">
  <a href="https://github.com/santhsecurity/keyhog/releases/latest"><img src="https://img.shields.io/github/v/release/santhsecurity/keyhog?style=flat-square&color=ffd60a&label=release&labelColor=0a0a0a" alt="latest release" /></a>&nbsp;
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-9aa0b4?style=flat-square&labelColor=0a0a0a" alt="MIT OR Apache-2.0" /></a>&nbsp;
  <a href="https://github.com/santhsecurity/keyhog/actions"><img src="https://img.shields.io/github/actions/workflow/status/santhsecurity/keyhog/ci.yml?style=flat-square&label=CI&labelColor=0a0a0a" alt="CI" /></a>&nbsp;
  <a href="https://star-history.com/#santhsecurity/keyhog&Date"><img src="https://img.shields.io/github/stars/santhsecurity/keyhog?style=flat-square&color=ffd60a&label=stars&labelColor=0a0a0a" alt="GitHub stars" /></a>
</p>

<p align="center">
  <sub>Part of <a href="https://santh.dev">Santh</a> &nbsp;·&nbsp; <a href="https://santh.dev/blog/keyhog/">blog</a> &nbsp;·&nbsp; <a href="https://x.com/SanthProject">@SanthProject</a></sub>
</p>

---

**keyhog** scans source trees, git history, Docker images, GitHub/GitLab/Bitbucket
repository collections, S3/GCS/Azure Blob buckets, and running systems for leaked credentials. **902 service-specific detectors**,
decode-through (base64/hex/url/protobuf), confidence scoring, SARIF output,
zero runtime configuration. Default `keyhog scan .` works out of the box.

### Add it to your CI (one workflow file)

```yaml
# .github/workflows/keyhog.yml
name: keyhog
on: [push, pull_request]
permissions: { contents: read, security-events: write }
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: santhsecurity/keyhog/.github/actions/keyhog@v0.5.40
        with: { path: ., severity: high, format: sarif }
```

Cost to your CI: ~20 MB binary download (cacheable), ~400 ms cold-start
on hosted runners (GPU auto-disabled, SIMD path), ~10 s wall-clock for
a 5,000-file repo. Single `libhyperscan5` apt package, no Python, no
JVM, no Docker daemon. Findings auto-upload to GitHub code-scanning as
SARIF; adopt without breaking an existing tree by committing a baseline
(`keyhog scan --create-baseline .keyhog-baseline.json`) so the action
fails only on NEW secrets.

For ultra-lean CI installs there's now `cargo install keyhog
--no-default-features --features ci`: 13 MB binary (vs 22 MB full),
~140 ms cold-start, no Hyperscan dependency, no wgpu/Vulkan probe,
no libstdc++ link. Same 902 detectors, same ML/entropy/decode/multiline
data paths. Use this profile in self-built CI images where binary size
or container cold-start matters; the prebuilt installer above stays the
default for a turnkey single-binary download.

GitLab CI, CircleCI, Drone, BuildKite, Jenkins, Bazel, pre-commit, Husky,
lefthook recipes: [`docs/DROP_IN_USAGE.md`](docs/DROP_IN_USAGE.md).

### How it works

keyhog compiles its 902 detectors into a single Hyperscan NFA database,
decodes nested encodings before matching, and calibrates confidence per
detector via Bayesian Beta(α,β) feedback. Hardware acceleration is an
explicit backend selection layer; every selected backend must preserve the
same detector ids and findings contract:

| Layer / Backend | When | How |
|---|---|---|
| `simdsieve` prefilter | AVX-512 / AVX2 / NEON | Layer 1: skims every file for the 8 highest-value secret prefixes (AWS `AKIA`/`ASIA`, GitHub `ghp_`, OpenAI `sk-proj-`, Slack `xoxb-`/`xoxp-`, SendGrid `SG.`, Square `sq0csp-`) at up to **50 GB/s**, before the regex backend runs |
| `gpu-zero-copy` | discrete GPU + ≥256 MiB scan | vyre AC automaton on GPU via WGPU (cross-platform) or optional CUDA backend |
| `simd-regex` | AVX-512 / AVX2 / NEON + Hyperscan | parallel multi-pattern NFA at ~500 MB/s |
| `cpu-fallback` | no SIMD, no GPU | Aho-Corasick prefix + Rust `regex` extraction |

### Autoroute Contract

The goal of autoroute is simple and strict: for every scan, on every supported
OS, architecture, CPU, GPU, driver stack, detector set, config, and workload
shape, keyhog must pick the fastest backend that returns the same findings.

That means autoroute is not a fixed threshold table, not a hardware-name
heuristic, and not a fallback hierarchy. There is no "GPU primary with CPU
fallback", no "CPU safe default", and no preferred backend that runs when the
decision table is missing. GPU, Hyperscan/SIMD, scalar CPU, and any new engine
are peer candidates. A backend is eligible only after calibration proves two
things for the current binary, detector digest, host profile, and workload
class:

- **Correctness parity:** the candidate backend returns the same detector ids,
  locations, hashes, and finding counts as the reference scanner path for the
  sampled workload.
- **Measured speed:** the candidate is faster than the alternatives on this
  host and workload class, including batching, detector digest, file-size
  distribution, accelerator state, and platform overhead. Calibration records
  store repeated parity-checked trials, not a single lucky timing sample.

The selected decision must be explainable and reproducible. Any cached routing
decision is keyed by binary version, OS/arch, CPU features, GPU identity,
detector digest, resolved scan-config digest, backend-affecting runtime env
knobs, calibration schema, and workload-shape buckets; changing any of those
invalidates the decision and requires a fresh calibration probe during install
or explicit recalibration. Invalid existing cache records are rejected instead
of being silently trusted. The installer runs a visible autoroute calibration
phase and persists those measured decisions on disk. Normal scans do not
benchmark candidates or rewrite routing records; they either find a valid
persisted fastest-correct decision for the scan class or report an invalid
autoroute state. A missing, stale, invalid, or incomplete decision is not
permission to run SIMD/CPU/GPU as a substitute. Rerun `install.sh --calibrate`
or `install.ps1 -Calibrate` to replace the persisted calibration. Explicit
`--backend` overrides are for diagnostics and benchmarking,
not evidence that autoroute is correct.

The `simdsieve` prefilter is a performance layer, not a separate detector: a
hit surfaces under its **canonical detector id** (`aws-access-key`,
`github-classic-pat`, `slack-bot-token`, …) - identical on every platform and
build, whether the fast path or the full regex engine made the find.

Backend selection is reported on startup:

```
keyhog v0.5.40 | 16 cores | SIMD: AVX-512 | Hyperscan | 902 detectors
```

**Full documentation:** [santhsecurity.github.io/keyhog](https://santhsecurity.github.io/keyhog/) - install, first scan, output formats, detection internals, suppressions, verification, pre-commit + CI integration, CLI reference, exit codes, env vars, contributing. Source under `docs/`.

---

## Install

```bash
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | sh

# Windows (PowerShell)
iwr https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.ps1 -useb | iex

# From source — Linux (default = Hyperscan SIMD; needs libhyperscan-dev + pkg-config)
git clone https://github.com/santhsecurity/keyhog.git
cd keyhog && cargo build --release -p keyhog

# From source / crates.io — macOS, Windows, or any host without Hyperscan
# (the system-lib-free vyre CPU build — no pkg-config, no GPU stack)
cargo install keyhog --no-default-features --features portable
```

> `install.sh` / `install.ps1` (signed prebuilt) is the recommended path: it
> auto-selects the right per-host variant and is a ~20 MB download in ~1 s,
> versus a ~3-minute source build. For a source build, note that the **default**
> features link Hyperscan (a system lib available on Linux x86_64); on **macOS**
> (incl. Apple Silicon) and any host without the Hyperscan dev libraries, build
> with `--no-default-features --features portable` — the vyre CPU path, every
> detection feature, no system-lib or pkg-config dependency.

Works on **Linux**, **macOS** (Intel + Apple Silicon), **Windows**. Zero
configuration. `keyhog scan .` works out of the box.

The installer auto-detects host state and picks a sensible default:
**WGPU + SIMD everywhere**, including on Linux NVIDIA hosts - WGPU runs
the same vyre AC / RulePipeline dispatch on the GPU via the vulkan
backend, with a smaller binary and no `libcuda.so` runtime dependency.
The dedicated `keyhog-linux-x86_64-cuda` variant is only auto-picked
when the full CUDA toolkit is present (nvcc on PATH, `$CUDA_HOME` set,
or `/usr/local/cuda` exists) - the signal that you actively run a CUDA
development setup, not just an NVIDIA driver. Apple Silicon hosts get
an explicit "Metal GPU acceleration coming soon" note. Each download
is SHA256-verified against the release-side checksum file before
install.

Override the variant with `KEYHOG_VARIANT=cuda` (force the native CUDA
build, requires `libcuda.so` at runtime) or `KEYHOG_VARIANT=cpu` (force
the default WGPU + SIMD build, skip GPU detection entirely). Pin a
version with `KEYHOG_VERSION=v0.5.40`. Change the install dir with
`KEYHOG_INSTALL=/usr/local/bin`.

Three diagnostic modes ship with the same script:
```bash
sh install.sh --diagnose    # print host + binary state, change nothing
sh install.sh --repair      # re-download the right variant for this host
sh install.sh --uninstall   # remove the binary + installer-owned shell wiring
```

For an interactive install (variant prompts + post-install wizard for
PATH, shell completions, Claude Code / Cursor hook, git pre-commit
hook), download the script first instead of piping into sh:
```bash
curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh \
    -o keyhog-install.sh
sh keyhog-install.sh
```

Daemon mode (sub-100 ms pre-commit scans) is Unix only. Everything
else works identically on Windows.

## Keep keyhog healthy and up to date

Once installed, keyhog maintains itself - the install script is only
needed for the first install:
```bash
keyhog doctor                # health check: host probe + end-to-end scan self-test
keyhog backend --self-test --json # CI-readable GPU path health proof
keyhog update                # self-update to the latest release (verified download + atomic swap)
keyhog update --check        # is a newer release available? (exits 10 if yes, 0 if current)
keyhog update --variant cuda # update to the CUDA build instead of the portable one
keyhog repair                # reinstall a known-good binary if the self-test fails (--force to force)
keyhog uninstall             # remove the binary (dry run; pass --yes to actually delete)
```

`keyhog doctor` reuses the scanner's own hardware probe and runs a real
end-to-end self-test - it plants a synthetic secret and confirms the
binary detects it - so it is the authoritative "will keyhog work here?"
check (the installer runs it automatically after install). `update` and
`repair` download the release binary over HTTPS, verify its minisign
signature against keyhog's embedded public key, and atomically swap the
running binary in place; a tampered or unsigned-mismatched binary is
refused. On a healthy host `keyhog update` is the one-command upgrade
path.

`keyhog backend --self-test --json` is the machine-readable GPU health
gate for self-hosted runners. It exits `4` when the production GPU scan
path degrades at runtime and emits stable `ok`, `status`, `exit_code`,
`recommended_backend`, and per-probe fields for CI routing.

## Quickstart

```bash
keyhog scan .                                          # scan a directory
keyhog scan --git-staged                               # pre-commit: only staged blobs
keyhog scan --git-diff main                            # files changed since base ref
keyhog scan --git-history .                            # every commit, every branch
keyhog scan --docker-image registry/app:v1             # Docker image layers
keyhog scan --s3-bucket logs-prod --s3-prefix /        # S3 objects (--s3-endpoint for non-AWS)
keyhog scan --gcs-bucket logs-prod --gcs-prefix config/ # GCS objects (--gcs-endpoint for compatible APIs)
keyhog scan --azure-container-url "$AZURE_CONTAINER_URL" --azure-prefix config/
keyhog scan --github-org acme --github-token "$GH_PAT" # every repo in a GitHub org (PAT required)
keyhog scan --gitlab-group acme --gitlab-token "$GL_PAT" # every project in a GitLab group
keyhog scan --bitbucket-workspace acme --bitbucket-username "$BB_USER" --bitbucket-token "$BB_APP_PASSWORD"
keyhog scan-system --space 50G                         # walk every drive, every git history
```

Filter, format, gate:

```bash
keyhog scan . --severity high                  # info | low | medium | high | critical
keyhog scan . --min-confidence 0.5             # raise the ML floor
keyhog scan . --format sarif -o keyhog.sarif   # GitHub code scanning
keyhog scan . --verify                         # live-verify against vendor APIs
keyhog scan . --baseline .keyhog-baseline.json # only NEW findings vs snapshot
keyhog scan . --fast                           # pre-commit speed (skip ML + decode)
keyhog scan . --deep                           # max detection depth
keyhog scan . --incremental                    # BLAKE3 Merkle skip → 10–100× CI loop
```

Exit codes: `0` clean, `1` findings above the severity floor, `2` user error
(bad path, bad config, unsupported flag), `3` system error or detector-corpus
audit failure, `4` `backend --self-test` failed, `10` live credentials found
(requires `--verify`), `11` scanner panic (thread panicked mid-scan), `12` required GPU
unavailable, `13` requested source failed before producing scan data. Matches
`keyhog --help`.

## What it catches

902 service-specific detectors with checksum / companion validation:

- **Cloud providers** . AWS (access key + secret + STS verification),
  Azure (subscription key, storage account key, SAS), GCP (service account,
  API key), Cloudflare, Heroku, Vercel, Supabase.
- **Payment processors** . Stripe, Braintree, Razorpay, Paddle, Plaid,
  Square, PayPal . all with companion-required validation (a Braintree
  private key without its public counterpart never fires).
- **Source forges** . GitHub PATs (with CRC32 checksum), GitLab tokens,
  Bitbucket app passwords, npm tokens (with checksum), Gitea / Forgejo
  / Codeberg.
- **Auth / SSO** . Okta, Auth0, Clerk, JumpCloud, Kinde.
- **Comms** . Slack, Discord, Twilio, SendGrid, Postmark, Mailgun,
  Resend, Loops.
- **AI / ML** . OpenAI (sk-/sk-proj-), Anthropic, Google AI Studio,
  Cohere, Mistral, HuggingFace, Replicate.
- **Databases** . Postgres connection strings, MongoDB Atlas, Supabase
  service-role, PlanetScale, Neon, Turso, MySQL, Redis URLs.
- **Generic + entropy fallback** . `API_KEY=<high-entropy-blob>` catches
  credentials with no named detector, gated by per-context entropy
  thresholds + ML scoring.
- **Cryptographic material** . RSA / EC / SSH private keys, PGP private
  blocks, JWT signing secrets.

Each detector ships as a [TOML file](./detectors/) (data, not code):
service metadata, regex patterns, keywords, companion fields,
verification handler. Adding a new detector is 5–10 lines of TOML;
the [contributor guide](./CONTRIBUTING.md) walks through it.

Browse the full catalog at [`/site/detectors.html`](./site/detectors.html) -
loads all 902 with severity + service + keyword filter.

## Why higher recall, fewer false positives

- **Decode-through scanning.** Kubernetes `Secret` manifests, JWT payloads,
  base64-wrapped envs, helm values, docker-config `auth:` blobs . the
  structured preprocessor decodes them in place and feeds every
  downstream detector the plaintext, so detectors don't each need to
  re-implement decoding.
- **Multiline reassembly.** `"sk-proj-" + \` continuation in JavaScript,
  YAML multi-line strings, Makefile backslash-continuation, Helm /
  Jinja templated outputs . all reassembled before regex matching.
- **Companion-required validation.** AWS access key without its 40-char
  secret? Skipped. Twilio API key without its auth token? Skipped.
  Two-out-of-two signals are required for the high-noise detectors,
  cutting the canonical `git log -G ghp_` false-positive cluster.
- **Confidence scoring.** Every finding carries a `[0.0, 1.0]` score
  derived from Shannon entropy, surrounding context, companion match,
  checksum (GitHub CRC32, npm, Slack), and a small ML classifier
  (~30k params). Default threshold `0.40` (the canonical
  `ScanConfig::default()` floor; same as the `--min-confidence` default
  and the `[scan] min_confidence` example below) filters low-quality
  matches without hiding real secrets.
- **Bayesian per-detector calibration.** `keyhog calibrate --fp generic-api-key`
  feeds a Beta(α,β) posterior that damps detectors that fire wrongly in
  your codebase, sharpening over time without manual rule tuning.

## Performance

Measured head-to-head against BetterLeaks, Kingfisher, TruffleHog, and
Titus, scored identically by the reproducible harness in
[`benchmarks/`](benchmarks/): the SecretBench containment rule, with the
ground-truth manifest **excluded from every scanner's scan tree** so no tool
is ever shown the answer key. The tables below are generated by
`make -C benchmarks report` — **do not edit them by hand.**

### Detection leaderboard

<!-- BENCH:leaderboard:start -->
Corpus: **mirror** - 15000 fixtures, 3000 labeled positives. Every scanner scored identically (SecretBench overlap rule); the answer-key manifest is excluded from the scan tree.

| Rank | Scanner | F1 | Precision | Recall | Findings | Wall | Peak RSS |
|---|---|---|---|---|---|---|---|
| 1 | **KeyHog** | **0.9131** | 0.9945 | 0.8440 | 2550 | 1.61s | 1106 MB |
| 2 | TruffleHog | 0.5265 | 1.0000 | 0.3573 | 1072 | 1.45s | 322 MB |
| 3 | Kingfisher | 0.4720 | 0.3912 | 0.5947 | 5241 | 3.81s | 502 MB |
| 4 | Titus | 0.4127 | 0.3318 | 0.5457 | 5159 | 4.13s | 114 MB |
| 5 | Nosey Parker | 0.4078 | 0.3414 | 0.5063 | 4532 | 0.82s | 534 MB |
| 6 | BetterLeaks | 0.3585 | 0.2313 | 0.7967 | 10828 | 1.04s | 210 MB |
<!-- BENCH:leaderboard:end -->

### Speed & memory

<!-- BENCH:perf:start -->
| Scanner | Config | Corpus | Wall | Throughput | Peak RSS |
|---|---|---|---|---|---|
| Nosey Parker | `default-nocache-nodaemon-no-git-history` | mirror | 0.75s | 3.1 MB/s | 285 MB |
| BetterLeaks | `default-nocache-nodaemon-no-validate` | mirror | 0.77s | 3.0 MB/s | 192 MB |
| Nosey Parker | `default-nocache-nodaemon-no-git-history` | mirror | 0.82s | 2.8 MB/s | 534 MB |
| Nosey Parker | `default-nocache-nodaemon-no-git-history` | creddata | 0.92s | 1056.3 MB/s | 1743 MB |
| BetterLeaks | `default-nocache-nodaemon-no-validate` | mirror | 1.04s | 2.2 MB/s | 210 MB |
| TruffleHog | `default-nocache-nodaemon-no-verify` | mirror | 1.45s | 1.6 MB/s | 322 MB |
| KeyHog | `simd-nocache-nodaemon-full` | mirror | 1.61s | 1.4 MB/s | 1106 MB |
| TruffleHog | `default-nocache-nodaemon-no-verify` | mirror | 1.73s | 1.3 MB/s | 308 MB |
| KeyHog | `simd-nocache-nodaemon-full` | mirror | 2.12s | 1.1 MB/s | 1085 MB |
| Titus | `default-nocache-nodaemon-no-validate` | mirror | 2.53s | 0.9 MB/s | 117 MB |
| BetterLeaks | `default-nocache-nodaemon-no-validate` | creddata | 2.83s | 342.8 MB/s | 252 MB |
| BetterLeaks | `default-nocache-nodaemon-no-validate` | creddata | 3.07s | 316.5 MB/s | 261 MB |
| Titus | `default-nocache-nodaemon-no-validate` | creddata | 3.16s | 307.6 MB/s | 2024 MB |
| KeyHog | `simd-nocache-nodaemon-full` | creddata | 3.31s | 293.8 MB/s | 1887 MB |
| KeyHog | `cpu-nocache-nodaemon-full` | creddata | 3.45s | 281.7 MB/s | 1821 MB |
| KeyHog | `auto-nocache-nodaemon-full` | creddata | 3.52s | 275.9 MB/s | 1850 MB |
| KeyHog | `megascan-nocache-nodaemon-full` | creddata | 3.70s | 262.7 MB/s | 1952 MB |
| Kingfisher | `default-nocache-nodaemon-low-no-validate` | mirror | 3.81s | 0.6 MB/s | 502 MB |
| KeyHog | `simd-nocache-nodaemon-full` | creddata | 4.02s | 241.7 MB/s | 1962 MB |
| Titus | `default-nocache-nodaemon-no-validate` | mirror | 4.13s | 0.6 MB/s | 114 MB |
| Kingfisher | `default-nocache-nodaemon-low-no-validate` | mirror | 4.88s | 0.5 MB/s | 421 MB |
| KeyHog | `gpu-nocache-nodaemon-full` | creddata | 5.12s | 189.7 MB/s | 3562 MB |
| Kingfisher | `default-nocache-nodaemon-low-no-validate` | creddata | 7.36s | 131.9 MB/s | 728 MB |
| Kingfisher | `default-nocache-nodaemon-low-no-validate` | creddata | 8.13s | 119.4 MB/s | 657 MB |
| TruffleHog | `default-nocache-nodaemon-no-verify` | creddata | 19.98s | 48.6 MB/s | 644 MB |
<!-- BENCH:perf:end -->

### Per-category gaps (where a competitor still wins)

<!-- BENCH:gaps:start -->
| Category | KeyHog F1 | Best competitor | Gap | Competitor overall precision |
|---|---|---|---|---|
| `generic-high-entropy-string` | 0.440 | BetterLeaks 0.893 | +0.453 | 0.231 |
<!-- BENCH:gaps:end -->

Reproduce: `make -C benchmarks bench` runs every scanner on the 15k
SecretBench-mirror corpus and writes `benchmarks/results/<host>/`;
`make -C benchmarks report` regenerates the tables above and
`benchmarks/reports/`. See [`benchmarks/README.md`](benchmarks/README.md)
for the corpora (mirror, competitor home-turf, Samsung/CredData) and the
backend/cache/daemon/OS/GPU matrix.

## CI integration

### GitHub Actions

```yaml
- uses: santhsecurity/keyhog/.github/actions/keyhog@v0.5.40
  with:
    path: .
    severity: high       # info | low | medium | high | critical
    format: sarif        # SARIF auto-uploads to GitHub code scanning
    baseline: .keyhog-baseline.json   # block only NEW findings
```

Auto-downloads a prebuilt binary; falls back to `cargo build` when no
release asset matches the host triple. SARIF carries CWE-798 + OWASP
A07:2021 taxa on every finding.

### CI never needs a GPU

**keyhog runs pure CPU/SIMD in CI - no GPU, no drivers, no CUDA toolkit.**
keyhog auto-detects hosted CI runners (`CI=true` plus a dozen
provider-specific markers) and skips every GPU init path, routing all
work through the SIMD/CPU engine. There is nothing to configure: the
GPU is for interactive desktop scans on machines that have one, never a
requirement. Detection results are identical on CPU and GPU - the GPU
only changes throughput, never which secrets are found.

Self-hosted runner with a real GPU and want to use it? Set
`KEYHOG_NO_GPU=0` to opt back in.

Building keyhog from source in CI (rather than the prebuilt binary)?
Use the `portable` feature - every detection feature, no system-library
build deps (skips the Hyperscan/Ghidra build step):

```yaml
- run: cargo install keyhog --no-default-features --features portable
- run: keyhog scan . --format sarif --severity high > keyhog.sarif
```

Other CIs (GitLab, CircleCI, Drone, BuildKite, Jenkins), pre-commit
recipes, Husky / lefthook, and the full SARIF schema:
[`site/ci.html`](./site/ci.html) and [`docs/DROP_IN_USAGE.md`](docs/DROP_IN_USAGE.md).

### Pre-commit hook

```bash
keyhog hook install                    # writes .git/hooks/pre-commit
keyhog hook uninstall                  # removes the keyhog-generated hook
```

The installed hook calls `keyhog scan --fast --git-staged` on every
commit. If `keyhog daemon start` is running, the in-process scan reuses
the daemon's compiled scanner for sub-50 ms latency; otherwise the
hook pays the ~3 s compile cost on each commit.

Or via the `pre-commit` framework:

```yaml
repos:
  - repo: https://github.com/santhsecurity/keyhog
    rev: v0.5.40
    hooks:
      - id: keyhog
```

## Daemon mode (105× faster re-scan)

Every keyhog invocation pays a ~2 s cold start in the default desktop
build (Hyperscan compile + GPU adapter probe). The lean ci profile
above drops that to ~140 ms by skipping both. For pre-commit and
IDE save handlers where even 140 ms is too much, run keyhog as a
daemon: the cost is paid once per host, every subsequent scan is
**~7 ms**:

```bash
keyhog daemon start                    # Unix socket on $XDG_RUNTIME_DIR
keyhog scan --stdin --daemon < .env    # 7 ms instead of 740 ms
keyhog daemon status
keyhog daemon stop
```

Use it in pre-commit hooks, IDE save handlers, or any per-commit CI
loop. systemd / launchd unit examples in
[`site/daemon.html`](./site/daemon.html).

Watch-mode for IDEs:

```bash
keyhog watch ./src                     # inotify/FSEvents/RDCW; sub-100 ms per save
```

## System-wide credential triage

```bash
sudo keyhog scan-system --space 50G                  # default 50 GiB ceiling
sudo keyhog scan-system --space 1T --include-network # also scan NFS / SMB
sudo keyhog scan-system --space 10G --no-git-history # skip historical blobs
```

Enumerates every mounted drive (skipping pseudo-FS like `/proc`,
`/sys`, `tmpfs`, `nsfs`, `fuse.snapfuse`), auto-discovers every `.git`
(worktrees + bare repos + submodules), and runs the full scan +
git-history pipeline. Honors a hard `--space <bytes>` ceiling and
exits 1 on findings. Built for incident-response triage, M&A
inheritance audits, and quarterly developer-laptop sweeps.

## Lockdown mode (security-critical embeddings)

For deployments where keyhog runs **on the same machine that holds the
secrets** (e.g. paired with [EnvSeal](https://github.com/santhsecurity/envseal))
and there is no trusted boundary between the scanner and the
credentials it inspects:

```bash
keyhog scan . --lockdown
```

Enforces:

- `mlockall(MCL_CURRENT|MCL_FUTURE)` on Linux . credentials never page
  to swap.
- `PR_SET_DUMPABLE = 0` (always on, even outside lockdown) . disables
  core dumps, ptrace, `/proc/<pid>/mem` reads. macOS gets
  `PT_DENY_ATTACH`.
- `setrlimit(RLIMIT_CORE, 0)` on Linux . kernel refuses to write any
  core file regardless of the system `coredump_filter`, so anonymous
  pages can never reach disk via the dump path.
- Refuses to run if `~/.cache/keyhog/*` exists, refuses
  `--incremental` writes, refuses `--verify`, refuses
  `--show-secrets`, refuses `--fast` / `--no-decode` / `--no-entropy` /
  `--no-ml` / `--no-unicode-norm` / `--no-default-excludes` (each
  trades off detection completeness for speed; lockdown is for the
  highest-stakes runs where you want every gate engaged).

The always-on hardening (everything except mlock + cache refusal) is
applied to every keyhog invocation . even without `--lockdown` a
keyhog binary can't be coredumped or ptraced.

## Library API

```rust
use keyhog_core::{Chunk, ChunkMetadata, DetectorFile};
use keyhog_scanner::CompiledScanner;

// build.rs embeds every detectors/*.toml as a (name, toml-body) pair.
let detectors: Vec<_> = keyhog_core::embedded_detector_tomls()
    .iter()
    .filter_map(|(_name, body)| toml::from_str::<DetectorFile>(body).ok())
    .map(|file| file.detector)
    .collect();
let scanner = CompiledScanner::compile(detectors)?;

let findings = scanner.scan(&Chunk {
    data: "TOKEN=sk_live_EXAMPLE…".into(),
    metadata: ChunkMetadata::default(),
});
```

Mix shipped + custom detectors by concatenating before compile. The
scanner is `Send + Sync`; share one across rayon workers. Streaming
source helpers in `keyhog-sources` (file-system, git, stdin, Docker,
S3, GCS, Azure Blob, GitHub org, GitLab group, Bitbucket workspace). Live verification in `keyhog-verifier`.

Full API surface + stability policy: [`site/api.html`](./site/api.html).

## Configuration

Per-repo defaults via `.keyhog.toml`:

```toml
[scan]
severity = "high"
min_confidence = 0.40          # canonical default; raise toward 0.85 for fewer FPs
exclude = ["**/test/fixtures/**", "vendor/"]

[limits]
stdin_bytes = "10MB"
web_response_bytes = "10MB"
git_total_bytes = "256MB"
docker_tar_total_bytes = "8GB"

[detector.generic-api-key]
enabled = false                # noisy detector? turn it off (hot-* fast-path
                               # ids like `hot-aws_key` are disabled the same way)

[detector.twilio-api-key]
min_confidence = 0.6           # per-detector floor; overrides the global one

[lockdown]
require = true                 # refuse to run unless --lockdown is passed

[system]
autoroute_cache = "/home/alice/.cache/keyhog/autoroute.json"  # or "off"

[aws]
canary_accounts = []           # extra 12-digit canary issuer accounts
knockoff_accounts = []         # treated the same way: do not live-verify

[tuning]
fallback_hs = true             # scanner recall-route defaults; printed by config --effective
hs_prefilter_max_len = 4096
decode_focus = true
confirmed_suffix_gate = true
no_candidate_gate = true
gpu_moe_timeout_ms = 30000
```

Precedence (rightmost wins): compiled defaults → `.keyhog.toml`
(walked up from the scan path) → CLI flags. The canonical defaults live in
`ScanConfig::default()` (`crates/core/src/config.rs`). Full reference:
[`docs/src/reference/configuration.md`](./docs/src/reference/configuration.md).

Suppress specific findings (not whole detectors) with a `.keyhogignore`
file by hash, path glob, or detector id - see
[suppressions](./docs/src/suppressions.md).

Allowlist a known leak with a hash, path glob, or detector id . plus
optional `reason` / `expires` / `approved_by` governance metadata:

```
# .keyhogignore . gitignore-style shorthand
*.log
node_modules/
9d6060e21ef8d5daec9cfe4a44b1b1bc9792246bfad28210edaaa1782a8a676a

# Explicit form with governance
hash:9f86d081…    ; reason="rotated 2026-04-25" ; expires=2026-07-01 ; approved_by="security@acme"
detector:demo-token
path:**/fixtures/*.env
```

Entries past `expires` are silently dropped on load with a WARN.

## Architecture

> **Contributor map:** [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) is the
> one-page guide to the whole repo — every top-level directory, the crate
> layering, and the bytes→finding pipeline with each stage pointing at the
> module that owns it. Start there to navigate the code.

```
crates/
  core/       Detector loading, finding types, reporting (text/JSON/SARIF), allowlists
  scanner/    Hardware routing, Hyperscan, GPU, decode-through, entropy, ML, multiline
  sources/    File system, git (staged/diff/history), stdin, Docker, S3, GCS, Azure Blob, GitHub/GitLab/Bitbucket, web
  verifier/   Live credential verification (344 detectors carry an active `[detector.verify]` endpoint)
  cli/        CLI binary, daemon, watch, baselines, calibrate, hook installer
detectors/    902 TOML files (data, not code)
site/         Documentation site (17 pages, GitHub-Pages-ready)
benchmarks/   Reproducible eval harness: corpus generators, scanner adapters, scorer, gate, README report generator
tools/        Contract generators (gen_contracts.py, gen_companion_contracts.py)
```

Two-phase coalesced scan:

1. **Phase 1** . Hyperscan NFA on raw bytes, parallel across all files
   via rayon. 95 %+ of files have no hits and pay zero cost.
2. **Phase 2** . full extraction on hits only: regex capture groups,
   companion matching, checksum validation, entropy gating, ML
   confidence + Bayesian damping.

Result: a multi-GB monorepo scans in seconds. Determinism is part of
the contract . same input → same output, byte-exact, every time.

Full architecture writeup, hardware routing matrix, profiling tips:
[`site/architecture.html`](./site/architecture.html) and
[`site/performance.html`](./site/performance.html).

## Other useful subcommands

```bash
keyhog detectors --search aws --verbose      # list / inspect detectors
keyhog explain aws-access-key                # spec, regex, severity, rotation guide
keyhog diff before.json after.json           # NEW / RESOLVED / UNCHANGED for CI gates
keyhog calibrate --tp aws-access-key         # record a true positive
keyhog calibrate --fp generic-api-key        # record a false positive
keyhog calibrate --show                      # posterior-mean bar chart per detector
keyhog backend                               # detected hardware + routing matrix
keyhog completion zsh                        # shell completions (bash/zsh/fish/powershell/elvish)
```

## Contributing

- **New detector?** Drop a TOML in [`detectors/`](./detectors/), open a
  PR. The contributor guide ([`CONTRIBUTING.md`](./CONTRIBUTING.md))
  has the schema and a worked example.
- **Bug / missed secret / false positive?** File an issue with the
  redacted credential shape and detector id; each report becomes a
  permanent test fixture under
  [`tests/contracts/`](./crates/scanner/tests/contracts/).
- **Security issue in keyhog itself?** Don't open a public issue -
  email `security@santh.dev` (PGP key on the org page).

[Changelog](./CHANGELOG.md). [Open issues](https://github.com/santhsecurity/keyhog/issues).

## Credits

keyhog stands on prior secret-scanning work. Ideas borrowed from:

- [trufflehog](https://github.com/trufflesecurity/trufflehog) . detector breadth + verification semantics
- **betterleaks** . entropy/keyword fusion and false-positive suppression
- **titus** . scanning ergonomics and severity calibration

Thanks to these projects and their contributors.

## License

MIT. Use commercially, embed, fork, sell a hosted version. The
detector TOMLs are also MIT . adding one is a 5-line PR with zero
legal friction.

---

## Star history

If keyhog has saved you from leaking a credential, a star is the
cheapest way to tell the next person it exists.

<a href="https://star-history.com/#santhsecurity/keyhog&Date">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=santhsecurity/keyhog&type=Date&theme=dark" />
    <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=santhsecurity/keyhog&type=Date" />
    <img alt="Star history of santhsecurity/keyhog" src="https://api.star-history.com/svg?repos=santhsecurity/keyhog&type=Date" />
  </picture>
</a>
