# What KeyHog can do

This page is the map. Every capability below links to the chapter that
explains it in depth. If you are evaluating KeyHog, read this first: most of
what the tool offers is not visible from `keyhog scan .` alone.

## GPU detection

The VYRE CUDA and WGPU engines match region presence for the whole compiled
detector corpus in a single resident dispatch. They then feed the same
confirmation pipeline as the CPU backends. A GPU route changes execution, not
findings, and it is selected only when the host's calibration proves it fastest
for that workload.

An RTX 5090 diagnostic recorded 24.6 ms on VYRE CUDA and 69.6 ms on Hyperscan
with identical findings. That run did not attest a clean source tree, so it is
historical performance evidence rather than a release crossover claim. See
[Backends and routing](./backends.md) for the evidence contract.

## What KeyHog can scan

One binary reads eleven kinds of source. Every source flows through the same
detector pipeline, so a finding from an S3 object is adjudicated exactly like a
finding from a working-tree file.

| Source | How to point at it | Chapter |
|---|---|---|
| Working tree | `keyhog scan <path>...` (default) | [Your first scan](./first-scan.md) |
| stdin / single file | `--stdin`, IDE-save fast path | [Daemon and warm scans](./workflows/daemon.md) |
| Git history | `--git-history <repo>` | [Deep recovery](./guides/deep-recovery.md) |
| Git diff / staged | `--git-diff <range>`, `--git-staged` | [Pre-commit hook](./workflows/precommit.md) |
| GitHub org / repos | `--github-org`, `--github-collaboration` (issues, PRs, discussions, wiki, gists) | [GitHub collaboration scans](./workflows/github-collaboration.md) |
| GitLab group | `--gitlab-group` | [Mass scanning](./guides/mass-scanning.md) |
| Bitbucket workspace | `--bitbucket-workspace` | [Mass scanning](./guides/mass-scanning.md) |
| S3 / GCS / Azure Blob | `--s3-bucket`, `--gcs-bucket`, `--azure-container-url` | [Mass scanning](./guides/mass-scanning.md) |
| Docker image | `--docker-image <ref>` | [Mass scanning](./guides/mass-scanning.md) |
| HTTP responses and wire captures | `--url <url>...` | [HTTP and wire scanning](./http-wire.md) |
| ZIP / tar / TeX / APK archives | auto-detected inside any of the above | [Source archives](./source-archives.md) |

## How KeyHog decides what is real

Precision is the product. A finding survives several independent stages before
it reaches your terminal.

| Stage | What it does | Chapter |
|---|---|---|
| Detectors | 923 service and generic detectors, shipped as TOML data files under `detectors/` | [Detectors](./detectors.md) |
| Entropy and shape | vectorized entropy plus declarative charset/grouping shape checks | [How detection works](./detection.md) |
| On-device MoE | a small mixture-of-experts model scores ambiguous candidates locally, never off-device | [How detection works](./detection.md) |
| Context and suppression | example-credential, vendored-bundle, comment, and `${{ secrets.NAME }}` suppression by default | [Suppressions](./suppressions.md) |
| Verification | optional live check that a credential is active, including out-of-band callbacks | [Verification](./verification.md) |

## How KeyHog stays fast

| Capability | What it buys you | Chapter |
|---|---|---|
| Autoroute calibration | picks the fastest correct backend for your exact host, corpus, and data shape | [Autoroute calibration](./reference/autoroute-calibration.md) |
| GPU region presence | VYRE CUDA / WGPU dispatch for the whole corpus at once | [Backends and routing](./backends.md) |
| Hyperscan SIMD prefilter | vectorized literal and regex prefiltering on the CPU path | [Backends and routing](./backends.md) |
| Daemon and warm scans | a resident process serves IDE-save and single-file scans without cold start (Unix) | [Daemon and warm scans](./workflows/daemon.md) |
| Incremental scans | a content-addressed index rescans only what changed | [Mass scanning](./guides/mass-scanning.md) |

## What KeyHog emits

| Output | Use | Chapter |
|---|---|---|
| Eleven formats | `text`, `json`, `json-envelope`, `jsonl`, `jsonl-envelope`, `sarif`, `csv`, `github-annotations`, `gitlab-sast`, `html`, `junit` | [Output formats](./output-formats.md) |
| Baselines | accept known findings once; only new secrets fail future scans | [CI integration](./workflows/ci.md) |
| Exit codes | stable codes for clean, findings, and error so scripts branch reliably | [Exit codes](./reference/exit-codes.md) |

## How KeyHog protects the secrets it reads

A scanner holds credentials in memory by design, so KeyHog hardens the process
that does it.

| Property | What it means | Chapter |
|---|---|---|
| Local detection | no telemetry, no network for detection; offline service validators | [Hardening and data handling](./hardening.md) |
| Always-on hardening | core dumps and `ptrace` disabled on every run, zero cost | [Hardening and data handling](./hardening.md) |
| Lockdown mode | `mlockall`, no-swap, no-disk run for same-host deployments | [Hardening and data handling](./hardening.md) |
| Zeroized credentials | found secrets zeroed on drop; redacted in every report | [Hardening and data handling](./hardening.md) |
| Signed releases | checksum + minisign verification with rollback | [Install](./install.md) |

## Every subcommand

| Command | Purpose |
|---|---|
| `scan` | scan any source and report findings (`--verify` adds live credential checks) |
| `scan-system` | recursive whole-machine audit: every mounted drive, every git history, one `--space` ceiling ([guide](./guides/system-wide-triage.md)) |
| `watch` | continuously scan one or more directories as files change |
| `diff` | diff two baselines or artifacts: NEW / REMOVED / UNCHANGED |
| `explain` | show a detector's spec, regex, severity, and rotation guide |
| `detectors` | list and inspect the embedded detector corpus |
| `config` | print the resolved scan configuration without scanning |
| `hook` | install or remove the git pre-commit hook |
| `daemon` | start, stop, or query the warm-scan daemon (Unix) |
| `calibrate` | show or update per-detector Bayesian confidence calibration |
| `calibrate-autoroute` | prime autoroute across every policy preset and workload bucket |
| `backend` | inspect hardware, routing heuristics, and autoroute evidence |
| `doctor` | health-check the install: host, PATH, corpus, scan and GPU self-test |
| `update` | verified download and self-replace to the latest release, with rollback |
| `repair` | reinstall a known-good binary, then verify |
| `uninstall` | remove the binary (dry run unless `--yes`) |
| `completion` | emit shell completions (bash, zsh, fish, powershell, elvish) |

The full flag surface for every command is in the
[CLI reference](./reference/cli.md).
