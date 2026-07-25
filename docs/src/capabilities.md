# What KeyHog can do

Use this page to choose an execution mode, input source, and output contract.
Each table links to the chapter that owns the details.

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

## Choose an execution mode

Start with the narrowest mode that covers the input you need.

| Need | Command | Boundary |
|---|---|---|
| Scan files or directories once | `keyhog scan <path>...` | Runs in the CLI process. Use this for local work and CI. |
| Scan Git state | `keyhog scan --git-staged`, `--git-diff <range>`, or `--git-history <repo>` | Staged and diff modes inspect selected changes. History mode walks commits. |
| Scan one file repeatedly on Unix | `keyhog daemon start`, then `keyhog scan <file>` | Eligible single-file and stdin requests can use the warm daemon. Other scan options remain in-process. |
| Monitor local directories | `keyhog watch <path>...` | Runs a foreground watcher. It is separate from the daemon. |
| Audit a host | `keyhog scan-system` | Walks eligible local mounted filesystems and discovered Git histories. Network mounts require `--include-network`. |

See [Architecture](./architecture.md#execution-surfaces) for routing ownership
and [Exit codes](./reference/exit-codes.md) for the process outcome contract.

Daemon routing has three explicit states. An absent daemon flag uses
opportunistic `auto` behavior. Bare `--daemon` or `--daemon=on` requires a
compatible running daemon. `--daemon=off` guarantees in-process execution.
The daemon transport is Unix-only.

## Choose a detector corpus mode

`--detectors <DIR>` selects a custom detector directory. Choose how it
participates in the corpus:

| Mode | Command | Result |
|---|---|---|
| Replace | `--detectors ./reviewed --detectors-mode replace` | Uses only the custom directory. This is also the compatibility behavior when an explicit custom directory omits the mode. |
| Overlay | `--detectors ./extra --detectors-mode overlay` | Adds the custom directory to the embedded corpus. Duplicate detector IDs fail corpus loading. |

The selected corpus owns matching, validation, entropy, suppression, ML, and
declared decode-transform policy. Replace mode does not inherit detector-local
policy from the embedded corpus. See [Detectors](./detectors.md).

## What KeyHog can scan

The default and official release builds support the sources below. Reduced
source builds can omit feature-gated Git, web, cloud, container, and verifier
support. Every enabled source feeds the same compiled detector pipeline.

| Source | How to point at it | Chapter |
|---|---|---|
| Working tree | `keyhog scan <path>...` (default) | [Your first scan](./first-scan.md) |
| stdin / single file | `--stdin` or `keyhog scan path/to/file` | [Daemon and warm scans](./workflows/daemon.md) |
| Git history | `--git-history <repo>` | [Deep recovery](./guides/deep-recovery.md) |
| Git diff / staged | `--git-diff <range>`, `--git-staged` | [Pre-commit hook](./workflows/precommit.md) |
| GitHub org / repos | `--github-org`, `--github-collaboration` (issues, PRs, discussions, wiki, gists) | [GitHub collaboration scans](./workflows/github-collaboration.md) |
| GitLab group | `--gitlab-group` | [Mass scanning](./guides/mass-scanning.md) |
| Bitbucket workspace | `--bitbucket-workspace` | [Mass scanning](./guides/mass-scanning.md) |
| S3 / GCS / Azure Blob | `--s3-bucket`, `--gcs-bucket`, `--azure-container-url` | [Mass scanning](./guides/mass-scanning.md) |
| Docker image | `--docker-image <ref>` | [Mass scanning](./guides/mass-scanning.md) |
| Web URLs | `--url <url>...` | [HTTP and wire scanning](./http-wire.md) |
| HAR captures | `keyhog scan capture.har` | [HTTP and wire scanning](./http-wire.md) |
| Archives, compressed files, and supported containers | pass the containing path; formats are detected during filesystem and remote-source expansion | [Source archives](./source-archives.md) |

## How KeyHog decides what is real

Precision is the product. A finding survives several independent stages before
it reaches your terminal.

| Stage | What it does | Chapter |
|---|---|---|
| Detectors | The embedded detector catalog is compiled from TOML data under `detectors/`; query the running binary for its exact count | [Detectors](./detectors.md) |
| Entropy and shape | vectorized entropy plus declarative charset/grouping shape checks | [How detection works](./detection.md) |
| On-device MoE | a small mixture-of-experts model scores ambiguous candidates locally | [How detection works](./detection.md) |
| Context and suppression | example-credential, vendored-bundle, comment, and `${{ secrets.NAME }}` suppression by default | [Suppressions](./suppressions.md) |
| Verification | optional live checks for detectors with a verification plan; these checks send credential-derived requests to the service | [Verification](./verification.md) |

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
| Local default | local filesystem, Git, stdin, archive, decoding, and detector work do not send findings or telemetry | [Hardening and data handling](./hardening.md) |
| In-process scan hardening | Linux and macOS in-process scans attempt core-dump and debugger-attachment protections before reading input | [Hardening and data handling](./hardening.md) |
| Linux lockdown mode | `--lockdown` fails closed unless memory locking and dump protections apply, and it refuses network verification and plaintext output | [Hardening and data handling](./hardening.md) |
| Credential buffer zeroization | the report credential buffer is zeroized on drop; reports redact unless `--show-secrets` is explicit | [Hardening and data handling](./hardening.md) |
| Authenticated releases | the normal install, update, and repair paths verify release checksums and signatures before replacement | [Install](./install.md) |

## Every subcommand

| Command | Purpose |
|---|---|
| `scan` | scan any source and report findings (`--verify` adds live credential checks) |
| `scan-system` | audit eligible local mounted filesystems and discovered Git histories under one `--space` ceiling; `--include-network` opts into network mounts ([guide](./guides/system-wide-triage.md)) |
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
| `bloom-diagnostic` | measure the production Bloom rejection gate and prove enabled-versus-bypassed finding parity |
| `doctor` | health-check the install: host, PATH, corpus, scan and GPU self-test |
| `update` | verified download and self-replace to the latest release, with rollback |
| `repair` | reinstall a known-good binary, then verify |
| `uninstall` | remove the binary (dry run unless `--yes`) |
| `completion` | emit shell completions (bash, zsh, fish, powershell, elvish) |

The full flag surface for every command is in the
[CLI reference](./reference/cli.md).
