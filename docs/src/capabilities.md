# Choose a scanning workflow

Start with the source boundary you need. Then choose a detection policy and an
execution route. These are separate decisions: a backend changes how KeyHog
executes, while a preset changes what detection work it performs.

## Choose in 30 seconds

| Your boundary | Start here | Do not substitute |
|---|---|---|
| One checked-out repository in GitHub Actions | [GitHub Action](./workflows/github-action.md) | An organization inventory job |
| One checkout in GitLab, CircleCI, Jenkins, Buildkite, or a shell runner | [CI secret scanning](./workflows/ci.md) | Action-specific inputs or outputs |
| A Git provider organization, cloud bucket, or partitioned estate | [Mass scanning](./guides/mass-scanning.md) | One oversized repository gate |
| A local working tree | [Your first scan](./first-scan.md) | Git history unless you select it |
| Staged content or changed lines | [Pre-commit](./workflows/precommit.md) or `--git-diff` | A full checkout scan when the policy is diff-only |
| Repeated one-file or bounded-stdin requests on Unix | [Daemon and warm scans](./workflows/daemon.md) | Directories, Git, archives, remote sources, or verification |
| A local host and mounted filesystems | [System-wide triage](./guides/system-wide-triage.md) | Repository or cloud inventory ownership |

Then make three independent choices:

1. Select the source boundary. This determines which bytes are eligible.
2. Keep the default detection policy unless you accept a documented fast,
   deep, or precision tradeoff.
3. Use calibrated automatic routing for normal scans. Select an explicit
   backend only for diagnosis, measurement, or a required-accelerator gate.

If any source reports incomplete coverage, preserve that status with the
findings and report. A partial scan is not a clean scan.

## Choose the source boundary

| Task | Command or workflow | What it covers |
|---|---|---|
| Scan a working tree once | `keyhog scan .` | Files present below the selected path. It does not add Git history automatically. |
| Scan staged content | `keyhog scan --git-staged` or `keyhog hook install` | Exact blobs in the Git index. It does not scan unstaged working-tree bytes. |
| Gate a pull-request checkout | [GitHub Action](./workflows/github-action.md) or `keyhog scan .` | The checked-out tree. Add a committed baseline when existing findings should remain visible without blocking adoption. |
| Gate only pull-request changes | `keyhog scan --git-diff <base>` | Changed lines relative to the selected base. This is narrower than scanning the checkout. |
| Scan reachable commit additions | `keyhog scan --git-history .` | Added lines from reachable commit patches, bounded by `max_commits` and the ancestry present in the checkout. A credential on a branch this checkout never had, or one left behind by `git commit --amend`, is missed with no coverage gap. |
| Scan the repository object database | `keyhog scan --git-blobs .` | Deduplicated blobs from refs, reflogs, stashes, annotated tags, and unreachable or dangling objects still present in `.git`. This is broader than reachable commit history, but cannot recover objects already pruned from the clone. |
| Verify a release | `keyhog scan --git-history . --git-blobs . --verify` | Reachable additions and blobs, plus live checks for eligible detectors. Verification sends credential-derived requests to provider endpoints. |
| Scan a Git provider or cloud inventory | `--github-org`, `--gitlab-group`, `--bitbucket-workspace`, `--s3-bucket`, `--gcs-bucket`, or `--azure-container-url` | One provider inventory. Partition larger estates into independent jobs with separate reports and exit codes. |
| Scan GitHub collaboration content | `--github-collaboration` | Issues, pull requests, discussions, wikis, and gists selected by the collaboration workflow. |
| Audit a host | `keyhog scan-system` | Eligible local mounted filesystems and discovered Git histories under one space ceiling. |
| Reuse a warm scanner on Unix | Start `keyhog daemon start`, then scan one file or bounded stdin | Eligible single-file or stdin requests only. Directories, Git, remote, cloud, verification, baselines, presets, and most policy overrides remain in process. |
| Monitor local directories | `keyhog watch <path>...` | A foreground filesystem-event loop with an in-process scanner. |
| Inspect a native executable or firmware image | `keyhog scan --binary app.bin` | Printable strings and supported native object sections, on a build with the `binary` feature. A directory walk records binaries as skipped and does not reinterpret them as text; `--no-default-excludes` does not change that. A directory containing only skipped binaries exits `13` because zero source bytes reached the scanner. A mixed tree can still exit `0` with an advisory binary gap, so inspect `coverage_gap_summary`. |

Read [Your first scan](./first-scan.md) for a local repository,
[CI secret scanning](./workflows/ci.md) for direct CI jobs, and
[Mass repository and cloud scanning](./guides/mass-scanning.md) for inventory
partitioning and coverage.

## Choose a scan policy

| Policy | Command | Resolved behavior |
|---|---|---|
| Default | `keyhog scan .` | Decode depth 10, ML enabled, and entropy evidence for eligible structured candidates. Decoding is capped at `--decode-size-limit`, 512K by default, applied per chunk rather than per file. Generic source-file entropy discovery is off. The global confidence floor is 0.40 unless detector policy owns a different floor. |
| Fast preset | `keyhog scan . --fast` | Named regex and multiline matching remain. Decode, entropy discovery, and ML are off in the base preset. An explicit compatible option such as `--decode-depth 2` can refine it. |
| Deep preset | `keyhog scan . --deep` | Source-file entropy and comment scanning at full confidence, heuristic evidence beside entropy ML, decode depth 10, and prepared decode chunks up to 1 MiB. |
| Precision preset | `keyhog scan . --precision` | Entropy discovery and the relaxed keyword bridge are off, ML remains on for eligible candidates, decode depth is 1, and every confidence floor is at least 0.85. |
| Lockdown mode | `keyhog scan . --lockdown` | Linux-only fail-closed process protection. It is a security execution mode, not a detection preset. It requires sufficient locked-memory capacity and refuses incompatible completeness-reducing, network, daemon, cache, and plaintext-output requests. |

The three presets are mutually exclusive bases. Compatible explicit options
refine them; a precision confidence override may raise but never lower 0.85.
Lockdown refuses fast and other completeness-reducing switches, and always runs
in process. See [Configuration](./reference/configuration.md#presets) and
[Hardening](./hardening.md#lockdown-mode).

### The default decode cap can hide an encoded credential

Decide this one before you trust a clean result on a repository with large
files. A Base64-encoded credential in a chunk above `--decode-size-limit` is
never decoded, so it is never reported. The scan exits `0`:

```text
file size    keyhog scan <file>                       with --deep
400K         1 finding, exit 1, status success        1 finding, exit 1
510K         1 finding, exit 1, status success        1 finding, exit 1
520K         0 findings, exit 0, status partial       1 finding, exit 1
600K         0 findings, exit 0, status partial       1 finding, exit 1
```

The miss is reported, but only in the envelope. `coverage_gap_summary` carries
`scanner decode-through declined by --decode-size-limit`, and `scan_status`
becomes `partial`. The exit code stays `0`, so a CI gate that branches on the
exit code alone passes over a real credential. Gate on the gap reason, not the
exit code.

Position in the file governs this, not size. The cap applies per chunk, and a
file is read in 1 MiB windows, so only the short tail window of a large file
can fall under the 512K limit. An encoded credential in the interior of any
file above about 1 MiB is never decoded, at any file size:

```text
2000K file, payload at end of file       1 finding, exit 1
2000K file, payload in the middle        0 findings, exit 0
3000K file, payload at end of file       1 finding, exit 1
3000K file, payload in the middle        0 findings, exit 0
```

That is also why the size table above looks erratic: planting at the end of the
file tests the one position that can still succeed, and the tail window's size
rises and falls as the file grows. Do not infer a safe file size from a fixture
that passed, and do not build a regression fixture that plants at the end.

Either preset choice restores it. `--deep` raises the ceiling as part of its
policy, and `--decode-size-limit 4M` raises it without changing anything else:

```sh
keyhog scan . --decode-size-limit 4M
```

## Choose an execution route

Normal scans use `auto`. An explicit backend is a diagnostic or benchmark
contract, not a recommendation for routine routing.

| Route | Select it with | Use case and boundary |
|---|---|---|
| Calibrated automatic routing | Run `keyhog calibrate-autoroute`, then `keyhog scan .` | Chooses the fastest parity-checked eligible backend for the exact host, binary, detector policy, and workload class. A normal scan does not benchmark. |
| Portable CPU-only build | Install with `cargo install --locked keyhog` | This is the default on every host. It includes local, remote, container, and native binary sources without Hyperscan, GPU, or Ghidra build prerequisites. A scalar-only build has no routing choice and needs no autoroute cache. |
| Explicit pure-Rust CPU | `--backend cpu` | Diagnose the portable path or compare it in a benchmark. `--no-gpu` is not equivalent because Hyperscan may remain eligible. |
| Hyperscan or Vectorscan | Let calibrated `auto` select it, or diagnose with `--backend simd` | Accelerated CPU trigger matching followed by the shared extraction and policy pipeline. It requires a compatible build and runtime. |
| CUDA, native Metal, or WGPU | Let calibrated `auto` select an eligible peer | GPU region-presence matching followed by the same confirmation pipeline. GPU availability does not mean the GPU is fastest for every workload. |
| Required GPU | `--require-gpu`, `[system].gpu = "required"`, or diagnostic `--backend gpu-cuda|gpu-metal|gpu-wgpu` | Use on a self-hosted GPU lane whose contract must fail if the accelerator cannot initialize or dispatch. It never substitutes another backend. |
| Warm Unix daemon | Start `keyhog daemon start`; use `--daemon=on` when the server is required | Removes repeated scanner startup for eligible single-file or stdin requests. It does not accelerate directory, Git, archive, remote, cloud, or policy-changing scans. |

Use `keyhog --version --full` to inspect compiled capability, `keyhog backend
--self-test --json` to prove backend health, and `keyhog backend --autoroute
--json` to inspect the measured route. These commands answer different
questions: discovery, correctness, and comparative selection.

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

| Capability | What it buys you | Boundary | Chapter |
|---|---|---|---|
| Autoroute calibration | Picks the fastest correct backend for the exact host, binary, detector corpus, policy, and workload class. | Normal scans consume persisted evidence. They do not benchmark or guess on a cache miss. | [Autoroute calibration](./reference/autoroute-calibration.md) |
| Parallel scan workers | Uses the available CPU cores by default. `--threads <N>` caps scanner workers when a shared runner has a smaller CPU budget. | Concurrent KeyHog processes each own a worker pool. Divide the host budget across partitions instead of letting every process claim every core. | [CLI reference](./reference/cli.md) |
| Dedicated readers | Overlaps filesystem reads with scanning. The reader count derives from the scan worker pool by default. | Set `--reader-threads` only after profiling the target storage path. | [CLI reference](./reference/cli.md) |
| Incremental scans | Reuses trusted clean-file proofs so repeated scans of one tree skip unchanged files; an all-hit run starts no backend dispatch. | Keep one cache per repository or partition. Do not share it across unrelated or untrusted workspaces. | [Mass scanning](./guides/mass-scanning.md) |
| Partition concurrency | Runs independent repositories, provider targets, or buckets in parallel with independent retry boundaries. | Preserve one envelope and raw exit code per partition. | [Mass scanning](./guides/mass-scanning.md) |
| Verification limits | Controls live provider traffic separately with `--verify-concurrency`, `--verify-rate`, and `--verify-batch`. | Provider quotas, not scanner worker count, own this concurrency. | [Verification](./verification.md) |
| GPU region presence | Uses VYRE CUDA, native Metal, or WGPU dispatch for the whole corpus at once when measured routing evidence selects it. | GPU availability alone does not prove it is fastest for the workload. | [Backends and routing](./backends.md) |
| Hyperscan SIMD prefilter | Uses vectorized literal and regex prefiltering on the accelerated CPU path. | Let calibrated automatic routing compare it with every eligible peer. | [Backends and routing](./backends.md) |
| Daemon and warm scans | Serves IDE-save and single-file scans without cold start on Unix. | Directories, Git, archives, remote sources, verification, and policy changes are not daemon work. | [Daemon and warm scans](./workflows/daemon.md) |

The generated scaling matrix measures these controls instead of prescribing a
fixed thread count. Run `make -C benchmarks readme-scaling` on the target host.
The result binds the binary, detector corpus, exact workload bytes, effective
CPU limit, filesystem identity, page-cache policy, raw trials, and process exit
status.

## What KeyHog emits

| Output | Use | Chapter |
|---|---|---|
| Eleven formats | `text`, `json`, `json-envelope`, `jsonl`, `jsonl-envelope`, `sarif`, `csv`, `github-annotations`, `gitlab-sast`, `html`, `junit` | [Output formats](./output-formats.md) |
| Baselines | accept known findings once, then fail only on new secrets; entries match the detector and credential value, never the path | [Fail only on new secrets](./workflows/ci.md#fail-only-on-new-secrets) |
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
| `update` | maintain an older GitHub binary-asset install; crates.io installs update with `cargo install --locked --force keyhog` |
| `repair` | maintain an older GitHub binary-asset install; reinstall the current crates.io version with Cargo for new installs |
| `uninstall` | remove the binary (dry run unless `--yes`) |
| `completion` | emit shell completions (bash, zsh, fish, powershell, elvish) |

The full flag surface for every command is in the
[CLI reference](./reference/cli.md).
