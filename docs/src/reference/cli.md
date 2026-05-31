# CLI reference

## `keyhog scan [PATH]`

The main subcommand. Scans `PATH` (default: current directory) and
emits findings. Exit code: `0` clean, `1` findings present, `2`
runtime error.

### Input selection

| Flag                          | Effect                                         |
|-------------------------------|------------------------------------------------|
| `<PATH>`                      | Positional path. File or directory.            |
| `--stdin`                     | Read from stdin instead. 10 MiB cap.           |
| `--exclude-paths <GLOB>...`   | Skip files matching glob. Space-separated list, repeatable. |
| `--git-staged`                | Scan git-staged files only (pre-commit mode).  |
| `--git-history <PATH>`        | Walk commits added-line patches (default: HEAD only). |
| `--git-diff <BASE_REF>`       | Scan only added lines since `BASE_REF`.        |
| `--docker-image <IMAGE>`      | Scan a saved Docker image archive.             |
| `--s3-bucket <BUCKET>`        | Scan an S3 bucket. Use `--s3-prefix` to narrow. |
| `--url <URL>...`              | Fetch + scan one or more HTTPS URLs (JS/source-map/WASM/text). |

### Output

| Flag                          | Effect                                         |
|-------------------------------|------------------------------------------------|
| `--format <text\|json\|jsonl\|sarif>` | Output format. Default `text`. The machine formats (`json`/`jsonl`/`sarif`) are findings-only: the banner/summary go to stderr (or are omitted), so stdout stays a clean parseable document. |
| `--output <FILE>`             | Write the report to `FILE` instead of stdout.  |
| `--stream`                    | Stream a one-line redacted preview per finding to stderr as they're found; the full formatted report still lands on stdout/`--output` after verification. |
| `--show-secrets`              | Show full credentials. Default redacts.        |
| `--min-confidence <FLOAT>`    | Only emit findings >= confidence. 0.0..=1.0.   |
| `--dogfood`                   | Surface suppression telemetry in output.       |

### Verification

| Flag                          | Effect                                         |
|-------------------------------|------------------------------------------------|
| `--verify`                    | Call each detector's verify endpoint.          |
| `--proxy <URL>`               | Route verifier traffic through a proxy (`http://burp:8080`, `socks5://...`). `off` disables all proxying (incl. env). |
| `--insecure`                  | Skip TLS cert verification on verifier traffic (don't use outside a lab). Env: `KEYHOG_INSECURE_TLS=1`. |

### Performance

| Flag                          | Effect                                         |
|-------------------------------|------------------------------------------------|
| `--fast`                      | Skip entropy + ML scorer. ~50% faster, ~20% fewer detectors. |
| `--daemon`                    | Force daemon route. Unix only.                 |
| `--no-daemon`                 | Force in-process scan even if daemon is up.    |
| `--timeout <SECONDS>`         | Hard per-scan deadline.                        |

### Detector tuning

| Flag                          | Effect                                         |
|-------------------------------|------------------------------------------------|
| `--detectors <DIR>`           | Use the detector TOMLs in `DIR` instead of the embedded corpus. To run a curated subset, copy the detector TOMLs you want into a directory and point `--detectors` at it (there is no per-ID enable/disable flag). Env: `KEYHOG_DETECTORS`. |
| `--no-suppress-test-fixtures` | Show findings on bundled example credentials.  |
| `--baseline <FILE>`           | Compare against a prior scan; show only new.   |
| `--hide-client-safe`          | Drop every `CLIENT-SAFE` finding (Sentry DSN, Stripe `pk_*`, Mapbox `pk.`, PostHog `phc_`, etc.) before reporting. Use this for bug-bounty / exfiltration-impact workflows where keys public by design are noise. |

### Environment variables

| Variable                              | Effect                                                                |
|---------------------------------------|-----------------------------------------------------------------------|
| `KEYHOG_BACKEND=gpu\|simd\|cpu\|auto`  | Force a scan backend instead of letting the auto-router choose.        |
| `KEYHOG_NO_GPU=1`                     | Short-circuit GPU init at hardware-probe time. The scanner runs as if no GPU adapter existed. Use this when Metal / CUDA init blocks on a given host (Apple Silicon Mac configurations have reproduced this) and you want predictable startup. |
| `KEYHOG_GPU_MOE_TIMEOUT_MS=<MS>`       | Bound one GPU MoE confidence readback. Default `30000`; timeout falls back to CPU MoE for that batch. |
| `KEYHOG_PER_CHUNK_TIMEOUT_MS=<MS>`    | Attach an `Instant` deadline to every chunk scan. Default unset = no timeout (original behaviour). Recommend `30000` for production scans where bounded latency matters more than scan completeness. |
| `KEYHOG_THREADS=<N>`                  | Pin the rayon worker count. Default = physical-core count.            |
| `KEYHOG_DETECTORS=<DIR>`              | Override the auto-discovered detector directory.                       |
| `KEYHOG_CACHE_DIR=<DIR>`              | Override the regex / database cache location (must sit under `$HOME` or `/tmp/keyhog-cache-<uid>` for safety).                 |

## `keyhog detectors`

Lists every detector in the embedded corpus.

```sh
keyhog detectors                  # human-readable, grouped by service
keyhog detectors --json           # one JSON object per detector
keyhog detectors --json | jq length
894
```

## `keyhog explain <DETECTOR_ID>`

Pretty-print a single detector's TOML. Includes keywords, patterns,
companion rules, and verification endpoint.

```sh
keyhog explain stripe-secret-key
```

## `keyhog watch [PATH]`

Daemon-mode subcommand that watches a directory for file changes and
re-scans on each one. Useful for IDE-side feedback. Unix only.

```sh
keyhog watch src/                 # watch the source tree
keyhog watch                      # watch the current directory
```

## `keyhog tui [PATH]`

Interactive ratatui dashboard. Streams findings in a severity-colored
list while a status panel reports files scanned, throughput, GPU
backend, and pattern count. `q` or `Esc` to quit; any keypress exits
once the scan completes.

```sh
keyhog tui .                          # live dashboard on CWD
keyhog tui demo --throttle-ms 200     # paced scan for demo recordings
keyhog tui --feed-depth 500 .         # keep more findings in the feed
keyhog tui --max-files 20 src/        # short fixed-duration loops
```

| Flag                   | Default | Effect                                           |
|------------------------|---------|--------------------------------------------------|
| `--max-files N`        | 0       | Stop after scanning N files. 0 = unlimited.      |
| `--feed-depth N`       | 200     | Rolling window of recent findings shown.         |
| `--throttle-ms MS`     | 0       | Sleep MS between files; demo / recording knob.   |

Exit code matches `keyhog scan`: 0 clean, 1 findings present.

## `keyhog hook <install|uninstall>`

Manages the git pre-commit hook. See
[Pre-commit hook](../workflows/precommit.md) for usage.

## `keyhog daemon <start|stop|status>` (Unix only)

The daemon holds the compiled scanner in memory so pre-commit /
IDE-save invocations skip the ~3 s cold start.

| Subcommand         | Effect                                              |
|--------------------|-----------------------------------------------------|
| `daemon start`     | Bind the Unix socket, accept connections.           |
| `daemon stop`      | Tell the running daemon to shut down.               |
| `daemon status`    | Print uptime, scans served, active scans.           |

Default socket path: `$XDG_RUNTIME_DIR/keyhog.sock`, or
`~/.cache/keyhog/server.sock` if `XDG_RUNTIME_DIR` is unset.

On Windows: every `daemon` subcommand prints "daemon mode is
unix-only" and exits non-zero. Daemon support via named pipes is
tracked but not yet implemented.

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
true positives and M false positives in your environment so its
confidence is adjusted on future scans.

```sh
keyhog calibrate --show                       # print current counters
keyhog calibrate --tp stripe-secret-key       # record one TP
keyhog calibrate --fp generic-api-key         # record one FP
keyhog calibrate --tp aws-access-key --show   # record + print
```

Pass `--cache <PATH>` to point at a non-default counter file (the
default lives under `$XDG_DATA_HOME/keyhog/`).

## `keyhog backend`

Prints hardware probe results: which SIMD ISA was detected, whether
Hyperscan / CUDA / wgpu backends initialized, the per-tier GPU
thresholds in effect.

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

## `keyhog completion <bash|zsh|fish|powershell>`

Emits a shell-completion script. Pipe into the shell's completion
location.

```sh
keyhog completion bash > /etc/bash_completion.d/keyhog
keyhog completion zsh > "${fpath[1]}/_keyhog"
keyhog completion fish > ~/.config/fish/completions/keyhog.fish
keyhog completion powershell >> $PROFILE
```

## Global flags

These work on any subcommand:

| Flag             | Effect                                              |
|------------------|-----------------------------------------------------|
| `--version`      | Print version + build info, exit.                   |
| `--help`         | Print help for the current subcommand.              |
| `--verbose`      | More log output to stderr.                          |
| `--no-color`     | Disable ANSI colors. Auto-detects TTY otherwise.    |
