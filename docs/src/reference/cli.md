# CLI reference

## `keyhog scan [PATH]...`

The main subcommand. Scans one or more `PATH` roots (default: current
directory) and emits findings. Pass several roots in a single run
(`keyhog scan src/ tests/ config/`) and each is walked as its own source;
a root nested inside another is folded into its covering parent (announced
on stderr) so no subtree is scanned twice. Exit code: `0` clean, `1` findings
present, `2` user error, `3` system error, `10` live credential, `11` scanner
panic, `12` required GPU unavailable, `13` requested source failed or coverage
incomplete.

### Input selection

| Flag                          | Effect                                         |
|-------------------------------|------------------------------------------------|
| `<PATH>...`                   | One or more positional roots. Each may be a file or directory; nested/duplicate roots are folded into their covering parent. `--git-staged` requires a single root. |
| `--stdin`                     | Read from stdin instead. Default 10 MiB cap; tune with `--limit-stdin-bytes`. |
| `--exclude-paths <GLOB>...`   | Skip files matching glob. Space-separated list, repeatable. |
| `--git-staged`                | Scan git-staged files only (pre-commit mode).  |
| `--git-history <PATH>`        | Walk commits added-line patches (default: HEAD only). |
| `--git-blobs <PATH>`          | Scan reachable repository blobs, deduplicated by blob ID. |
| `--git-diff <BASE_REF>`       | Scan only added lines since `BASE_REF`.        |
| `--git-diff-path <PATH>`      | Select the repository used by `--git-diff` instead of the current directory. |
| `--docker-image <IMAGE>`      | Scan a saved Docker image archive.             |
| `--github-org <ORG>`          | Clone and scan every repository in a GitHub organization. Requires `--github-token`. |
| `--gitlab-group <GROUP>`      | Clone and scan every project in a GitLab group, including subgroups. Requires `--gitlab-token`; use `--gitlab-endpoint` for self-managed GitLab. |
| `--bitbucket-workspace <WORKSPACE>` | Clone and scan every repository in a Bitbucket Cloud workspace. Requires `--bitbucket-username` and `--bitbucket-token` app password. |
| `--s3-bucket <BUCKET>`        | Scan an S3 bucket. Use `--s3-prefix` to narrow. |
| `--gcs-bucket <BUCKET>`       | Scan a Google Cloud Storage bucket. Use `--gcs-prefix` to narrow. |
| `--azure-container-url <URL>` | Scan an Azure Blob container URL. Include a SAS query string for private containers; use `--azure-prefix` to narrow. |
| `--url <URL>...`              | Fetch + scan one or more HTTPS URLs (JS/source-map/WASM/text). |

### Output

| Flag                          | Effect                                         |
|-------------------------------|------------------------------------------------|
| `--format <text\|json\|jsonl\|sarif\|csv\|github-annotations\|gitlab-sast\|html\|junit>` | Output format. Default `text`. The machine formats (`json`/`jsonl`/`sarif`/`csv`/`github-annotations`/`gitlab-sast`/`junit`) are findings-only: the banner/summary go to stderr (or are omitted), so stdout stays a clean parseable artifact. |
| `--output <FILE>`             | Write the report to `FILE` instead of stdout.  |
| `--stream`                    | Stream a one-line redacted preview per finding to stderr as they're found; the full formatted report still lands on stdout/`--output` after verification. |
| `--show-secrets`              | Show full credentials. Default redacts.        |
| `--min-confidence <FLOAT>`    | Only emit findings >= confidence. 0.0..=1.0.   |
| `--dogfood`                   | Surface suppression telemetry in output.       |

### Verification and HTTP transport

| Flag                          | Effect                                         |
|-------------------------------|------------------------------------------------|
| `--verify`                    | Call each detector's verify endpoint.          |
| `--timeout <SECONDS>`         | Set the per-request HTTP verification timeout (default `5`); requires `--verify`. This is not a scan deadline. |
| `--verify-concurrency <N>`    | Cap in-flight verification requests per service (default `5`, minimum `1`); requires `--verify`. This is concurrency, not requests per second. |
| `--proxy <URL>`               | Route every outbound KeyHog HTTP client—remote sources and verification—through an explicit proxy (`http://burp:8080`, `socks5://...`). `off` disables all proxying, including TOML configuration; ambient proxy variables are ignored. |
| `--insecure`                  | Skip TLS certificate verification for every outbound KeyHog HTTP client, including remote sources and verification. Use only in a controlled interception lab. |
| `--verify-rate <RPS>`         | Cap steady-state verification calls per service (default `5`); requires `--verify`. |
| `--verify-batch`              | Serialize verification per service; requires `--verify`. |
| `--verify-oob`                | Enable callback-based verification; requires `--verify`. |
| `--oob-server <HOST>`         | Select the Interactsh collector for OOB verification. |
| `--oob-timeout <SECS>`        | Bound the per-finding OOB callback wait. |

### Performance

| Flag                          | Effect                                         |
|-------------------------------|------------------------------------------------|
| `--fast`                      | Disable entropy discovery, ML scoring, and decode recursion (`max_decode_depth = 0`). Named regex detectors remain loaded; the speedup and recall change are workload-dependent. |
| `--daemon`                    | Force daemon route for eligible stdin/single-file scans. Unix only; fails if the request needs the in-process pipeline. |
| `--daemon=auto`               | On Unix, use a reachable compatible daemon when it can honor the exact request; with no socket, run in process, and report failures that occur after selecting the daemon before retrying in process. This is also the absent-flag policy, except that explicit `auto` is rejected on platforms with no daemon transport. |
| `--daemon=off`                | Force in-process scan even if daemon is up.    |
| `--profile`                   | Emit the scanner-owned hierarchical profile report to stderr at scan end. |
| `--perf-trace`                | Emit low-level scan/GPU phase timing traces to stderr. |

### Source Limits

Every limit below also has a `[limits]` key in `.keyhog.toml` with the same name
minus the `limit-` prefix and with dashes changed to underscores.

| Flag | Effect |
|------|--------|
| `--limit-stdin-bytes <SIZE>` | Maximum bytes read from `--stdin`. |
| `--limit-web-response-bytes <SIZE>` | Maximum bytes fetched for one `--url` response. |
| `--limit-s3-object-bytes <SIZE>` / `--limit-gcs-object-bytes <SIZE>` / `--limit-azure-blob-bytes <SIZE>` | Maximum bytes downloaded for one cloud object/blob. |
| `--limit-docker-tar-entry-bytes <SIZE>` / `--limit-docker-image-config-bytes <SIZE>` / `--limit-docker-tar-total-bytes <SIZE>` | Docker/OCI archive and manifest/config ceilings. |
| `--limit-git-line-bytes <SIZE>` / `--limit-git-total-bytes <SIZE>` / `--limit-git-blob-bytes <SIZE>` / `--limit-git-chunks <N>` | Git stdout-line, aggregate, per-blob, and chunk-count ceilings. |
| `--limit-binary-read-bytes <SIZE>` / `--limit-binary-decompiled-bytes <SIZE>` | Binary strings and Ghidra output ceilings. |

### Detector tuning

| Flag                          | Effect                                         |
|-------------------------------|------------------------------------------------|
| `--detectors <DIR>`           | Use the detector TOMLs in `DIR` instead of the embedded corpus. To run a curated subset, copy the detector TOMLs you want into a directory and point `--detectors` at it (there is no per-ID enable/disable flag). |
| `--no-suppress-test-fixtures` | Show findings on bundled example credentials.  |
| `--baseline <FILE>`           | Compare against a prior scan; show only new.   |
| `--create-baseline <FILE>`    | Write a new baseline from the current findings and exit. |
| `--update-baseline <FILE>`    | Merge current findings into an existing baseline. |
| `--hide-client-safe`          | Drop every `CLIENT-SAFE` finding (Sentry DSN, Stripe `pk_*`, Mapbox `pk.`, PostHog `phc_`, etc.) before reporting. Use this for bug-bounty / exfiltration-impact workflows where keys public by design are noise. |

### Scan controls

| Control                               | Effect                                                                |
|---------------------------------------|-----------------------------------------------------------------------|
| `keyhog scan --backend auto\|gpu\|simd\|cpu` | Use persisted automatic routing (`auto`) or explicitly force one diagnostic backend (`gpu`, `simd`, or `cpu`). Profiles and routing evidence use the descriptive labels `gpu-region-presence`, `simd-regex`, and `cpu-fallback`; retired MegaScan and implementation-name aliases are rejected. |
| `keyhog scan --gpu-batch-input-limit 512MB` | Override the VRAM-adaptive byte limit for one GPU region-presence batch (clamped to 128 MiB–1 GiB). |
| `keyhog scan --no-gpu`                | Short-circuit GPU init at hardware-probe time. The scanner runs as if no GPU adapter existed. |
| `keyhog scan --require-gpu`           | Fail closed with exit `12` when no usable GPU stack is available. |
| `keyhog scan --autoroute-calibrate`   | Installer/maintenance mode: benchmark parity-checked autoroute candidates and persist fastest-correct decisions. Normal scans do not use this mode. |
| `keyhog scan --autoroute-gpu`         | Low-level direct-calibration diagnostic: include eligible GPU candidates. `keyhog calibrate-autoroute` always includes every eligible backend. |
| `keyhog scan --no-autoroute-gpu`      | Low-level direct-calibration diagnostic: exclude GPU despite TOML. This is not used by canonical calibration. |
| `keyhog scan --per-chunk-timeout-ms <MS>` | Attach an `Instant` deadline to every chunk scan. Default unset = no operator deadline; `[scan].per_chunk_timeout_ms` provides the persistent default. |
| `keyhog scan --threads <N>`           | Pin the rayon worker count for this run. `.keyhog.toml` `[scan].threads` provides the persistent default. |
| `keyhog scan --calibration-cache <PATH>` | Apply one explicit per-detector Bayesian confidence cache. Missing or invalid files fail closed. |
| `keyhog scan --reader-threads <N>`    | Pin dedicated filesystem reader threads. `.keyhog.toml` `[scan].reader_threads` provides the persistent default. |
| `keyhog scan --fused-batch <N>`       | Pin fused filesystem pipeline batch size. `.keyhog.toml` `[scan].fused_batch` provides the persistent default. |
| `keyhog scan --fused-depth <N>`       | Pin fused filesystem pipeline channel depth. `.keyhog.toml` `[scan].fused_depth` provides the persistent default. |

Hyperscan database cache location is explicit scan configuration: use
`keyhog scan --cache-dir <DIR>` or `.keyhog.toml` `[system].cache_dir`.
Autoroute calibration evidence is also explicit scan configuration: use
`keyhog scan --autoroute-cache <PATH|off>` or `.keyhog.toml`
`[system].autoroute_cache`.
GPU MoE readback timeout is explicit scanner tuning:
`.keyhog.toml` `[tuning].gpu_moe_timeout_ms`. GPU region-presence parity/debug
recall-floor runs use `.keyhog.toml` `[tuning].gpu_recall_floor = true`.

Custom S3 and GCS endpoints never receive ambient cloud credentials unless the
operator explicitly passes `--allow-s3-credential-forward` or
`--allow-gcs-token-forward`. Private cloud endpoints additionally require
`--allow-private-cloud-endpoint` (or `[http].allow_private_endpoint = true`).

## `keyhog config --effective [SCAN FLAGS]`

Prints the resolved scan configuration and exits without scanning. This is the
operator-visible way to prove what the scanner would run after compiled
defaults, `.keyhog.toml`, and CLI overrides are merged.

`config --effective` accepts the same config-affecting flags as `scan`, including
`--config`, `--fast`, `--deep`, `--precision`, source limits, detector paths,
confidence floors, and the positional path shorthand.

```sh
keyhog config --effective
keyhog config --effective --config .keyhog.toml --precision .
keyhog config --effective --limit-stdin-bytes 32MB --no-ml
```

## `keyhog detectors`

Lists every detector in the embedded corpus.

```sh
keyhog detectors                  # human-readable, grouped by service
keyhog detectors --format json    # one JSON array of detector objects
keyhog detectors --format json | jq length
keyhog detectors --search aws     # id/name/service/keyword substring filter
keyhog detectors --search aws --verbose  # full matching specs
keyhog detectors --audit          # validate the loaded corpus; errors exit 3
keyhog detectors --fix --dry-run  # preview safe verifier-template rewrites
```

`--fix` only performs the mechanically safe single-brace to double-brace
verification-template rewrite; other audit findings require an explicit edit.
`--format` is mutually exclusive with `--audit` and `--fix`.

## `keyhog explain <DETECTOR_ID>`

Explain the loaded detector. Includes keywords, patterns, companion rules,
verification endpoint, and detector-owned entropy/BPE/length/suppression
policy.

```sh
keyhog explain stripe-secret-key
```

## `keyhog watch [PATH]...`

Foreground subcommand that watches one or more directories for file changes
and re-scans each changed file. Useful for IDE-side feedback. It does not
connect to or appear in `keyhog daemon status`; the independent `keyhog daemon`
is a Unix-socket service used only by eligible `keyhog scan --daemon` requests.
Pass several roots to monitor them with a single watcher; nested or
duplicate roots fold into their covering parent, mirroring `keyhog scan`.
Every root must be a directory.

```sh
keyhog watch src/                 # watch the source tree
keyhog watch src/ config/         # watch several roots in one process
keyhog watch                      # watch the current directory
```

## `keyhog hook <install|uninstall>`

Manages the git pre-commit hook. See
[Pre-commit hook](../workflows/precommit.md) for usage.

## `keyhog daemon <start|stop|status>` (Unix only)

The daemon holds a compiled scanner and initialized accelerator state for
eligible stdin and single-file scans. Directory, Git, remote, baseline,
verification, explicit backend/calibration, and incompatible policy requests
use the in-process pipeline in `auto` mode; `--daemon=on` fails if the exact
daemon route cannot be honored.

| Subcommand         | Effect                                              |
|--------------------|-----------------------------------------------------|
| `daemon start`     | Bind the Unix socket, accept connections.           |
| `daemon stop`      | Tell the running daemon to shut down.               |
| `daemon status`    | Print uptime, scans served, active scans, and detector count. |

`daemon start --request-timeout-secs <N>` sets how long one client connection
may sit without completing a request frame before the daemon closes it and
reclaims the connection slot. Default: `300`.

Default socket path: `$XDG_RUNTIME_DIR/keyhog.sock`, or
`~/.cache/keyhog/server.sock` if `XDG_RUNTIME_DIR` is unset.

On Windows: every `daemon` subcommand and explicit `scan --daemon=auto|on`
prints a Unix-only error and exits non-zero. No Windows daemon transport ships;
an absent daemon flag or explicit `--daemon=off` runs the in-process scanner.

See [Daemon and warm scans](../workflows/daemon.md) for the complete `auto` /
`on` / `off` contract, request eligibility, warm autoroute behavior, and socket
security semantics.

## `keyhog diff <FILE_A> <FILE_B>`

Compare two scan outputs (JSON or NDJSON). Useful for "did this PR
introduce a new finding?" gating in CI.

```sh
keyhog scan . --format json > baseline.json
git checkout pr-branch
keyhog scan . --format json > pr.json
keyhog diff baseline.json pr.json
```

## `keyhog calibrate`

Show or update the per-detector Bayesian (Beta-α/β) calibration
counters. Used to teach the scorer that detector X has produced N
true positives and M false positives in your environment. Scans use the
counters only when `--calibration-cache <PATH>` or
`[system].calibration_cache` explicitly points at the file.

```sh
keyhog calibrate --show                       # print current counters
keyhog calibrate --tp stripe-secret-key       # record one TP
keyhog calibrate --fp generic-api-key         # record one FP
```

Pass `--cache <PATH>` to point at a non-default counter file (the
default lives under the platform cache directory, normally
`$XDG_CACHE_HOME/keyhog/calibration.json`). Existing corrupted or
schema-incompatible cache files fail closed and are not overwritten.

## `keyhog calibrate-autoroute`

Runs the complete scan-policy and workload-bucket sweep, verifies backend
parity, and persists fastest-correct routing evidence for normal `auto` scans.
`--autoroute-cache <PATH>` selects the evidence file; `off` is rejected because
calibration must persist its result. `--quiet` suppresses per-probe progress but
still prints the final summary.

## `keyhog backend`

Prints hardware probe results and a diagnostic per-tier heuristic matrix:
which SIMD ISA was detected and whether Hyperscan, CUDA, or wgpu initialized.
The matrix is not the `scan --backend auto` decision; normal automatic scans
use persisted fastest-correct calibration. Use `keyhog backend --autoroute`
to inspect that evidence, and `--probe-bytes` only for heuristic what-if work.

```sh
keyhog backend
```

## `keyhog scan-system`

Recursive system-wide credential audit. Walks every mounted drive
(skipping pseudo-filesystems and, by default, network mounts),
discovers every `.git` repository on the way, and runs the same
scan + git-history pipeline that `keyhog scan --git-history` uses
on each. Honors a hard `--space <N>` ceiling on total bytes scanned
so it cannot accidentally exhaust a CI runner. Does NOT honor
`.gitignore` unless `--respect-gitignore` is passed (an attacker
stashing leaked keys would `.gitignore` them).

```sh
keyhog scan-system                                  # local mounts, git history on
keyhog scan-system --include-network                # also walk NFS/SMB/sshfs
keyhog scan-system --space 50G --no-git-history     # cap + skip history walks
keyhog scan-system --lockdown                       # forbids --include-network
```

## `keyhog completion <bash|zsh|fish|powershell|elvish>`

Emits a shell-completion script. Pipe into the shell's completion
location.

```sh
keyhog completion bash > /etc/bash_completion.d/keyhog
keyhog completion zsh > "${fpath[1]}/_keyhog"
keyhog completion fish > ~/.config/fish/completions/keyhog.fish
keyhog completion powershell >> $PROFILE
keyhog completion elvish > ~/.config/elvish/lib/keyhog.elv
```

## Install maintenance

| Command | Effect |
|---------|--------|
| `keyhog doctor` | Report host and PATH state, detector corpus health, and end-to-end scanner/GPU self-tests. |
| `keyhog update --check` | Check the newest complete stable release for this host; exits `10` when one is available. |
| `keyhog update [--version <TAG>]` | Atomically install the newest complete stable release or an exact published tag and roll back if verification fails. |
| `keyhog repair [--force] [--version <TAG>]` | Reinstall from the newest complete stable release or an exact published tag; without `--force`, a healthy install is left intact. |
| `keyhog uninstall [--yes]` | Show what would be removed; `--yes` performs the uninstall. |

Linux uses one GPU-capable artifact that probes CUDA and WGPU at runtime. These
commands therefore have no backend or artifact-variant selector.
Implicit resolution excludes drafts and prereleases and requires the binary,
checksum, signature, GPU-literal sidecar, sidecar checksum, and sidecar
signature. An explicit `--version` may select a published prerelease but never
a draft.

## Root options

These are root-command options. `--version` and `--full` are not scan flags;
they print identity information and exit. Each subcommand also has its own
`--help`.

| Flag             | Effect                                              |
|------------------|-----------------------------------------------------|
| `-V`, `--version` | Print version + build info, then exit.              |
| `--full`          | With `--version`, include the hardware probe.       |
| `-h`, `--help`    | Print root help.                                    |

Display controls are command-specific: `scan --no-color` disables report and
summary ANSI output, while `detectors --verbose` prints full matching detector
specifications.
