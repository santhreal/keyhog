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
| `--exclude-paths <GLOB>`      | Skip files matching glob. Repeatable.          |
| `--include-extensions <EXT>`  | Only scan files with these extensions.         |
| `--staged`                    | Scan git-staged files only (pre-commit mode).  |
| `--git-history`               | Scan all commits, not just HEAD.               |

### Output

| Flag                          | Effect                                         |
|-------------------------------|------------------------------------------------|
| `--format <human\|json\|sarif\|ndjson>` | Output format. Default `human`.      |
| `--quiet`                     | Suppress banner + footer. Findings only.       |
| `--show-secrets`              | Show full credentials. Default redacts.        |
| `--min-confidence <FLOAT>`    | Only emit findings >= confidence. 0.0..=1.0.   |
| `--dogfood`                   | Surface suppression telemetry in output.       |

### Verification

| Flag                          | Effect                                         |
|-------------------------------|------------------------------------------------|
| `--verify`                    | Call each detector's verify endpoint.          |
| `--proxy <URL>`               | HTTPS proxy for verifier traffic.              |
| `--insecure-tls`              | Accept self-signed certs (don't use outside lab). |

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
| `--disable-detectors <ID,..>` | Drop findings from these detectors.            |
| `--enable-detectors <ID,..>`  | Only run these detectors. Implies disable-rest. |
| `--no-suppress-test-fixtures` | Show findings on bundled example credentials.  |
| `--baseline <FILE>`           | Compare against a prior scan; show only new.   |
| `--hide-client-safe`          | Drop every `CLIENT-SAFE` finding (Sentry DSN, Stripe `pk_*`, Mapbox `pk.`, PostHog `phc_`, etc.) before reporting. Use this for bug-bounty / exfiltration-impact workflows where keys public by design are noise. |

### Environment variables

| Variable                              | Effect                                                                |
|---------------------------------------|-----------------------------------------------------------------------|
| `KEYHOG_BACKEND=gpu\|simd\|cpu\|auto`  | Force a scan backend instead of letting the auto-router choose.        |
| `KEYHOG_NO_GPU=1`                     | Short-circuit GPU init at hardware-probe time. The scanner runs as if no GPU adapter existed. Use this when Metal / CUDA init blocks on a given host (Apple Silicon Mac configurations have reproduced this) and you want predictable startup. |
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
891
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

## `keyhog calibrate [PATH]`

Diagnostic tool that scans a directory at increasing detector counts
and reports throughput. Used to verify hardware acceleration is
active.

```sh
keyhog calibrate --show
```

## `keyhog backend`

Prints hardware probe results: which SIMD ISA was detected, whether
Hyperscan / CUDA / wgpu backends initialized, the per-tier GPU
thresholds in effect.

```sh
keyhog backend
```

## `keyhog scan-system`

Scans well-known system locations (`~/.aws/credentials`, `~/.ssh/`,
`~/.netrc`, `~/.npmrc`, `~/.docker/config.json`, etc.) for misplaced
credentials in shell history files, environment dumps, etc.
Intentionally narrow scope.

```sh
keyhog scan-system
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
