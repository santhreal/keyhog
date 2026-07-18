# CLI reference

The command names and long-flag inventory in this page are checked against
KeyHog's live Clap command model in CI. The descriptions and workflow guidance
below remain curated so they explain semantics, precedence, and failure modes
that generated `--help` output cannot express.

## `keyhog scan [PATH]...`

The main subcommand. Scans one or more `PATH` roots (default: current
directory) and emits findings. Pass several roots in a single run
(`keyhog scan src/ tests/ config/`) and each is walked as its own source;
a root nested inside another is folded into its covering parent (announced
on stderr) so no subtree is scanned twice. Exit code: `0` clean, `1` findings
present, `2` user error, `3` system error, `10` live credential, `11` scanner
panic, `12` selected or required GPU unavailable, `13` requested source failed
or coverage incomplete.

### Input selection

| Flag                          | Effect                                         |
|-------------------------------|------------------------------------------------|
| `<PATH>...`                   | One or more positional roots. Each may be a file or directory; nested/duplicate roots are folded into their covering parent. `--git-staged` accepts one directory inside one worktree and discovers its repository root. |
| `--path <PATH>`               | Explicit single-root spelling. Prefer positional roots when scanning several paths. |
| `--binary`                    | In builds with binary analysis, extract and scan strings from supported working-tree binary inputs in addition to ordinary text handling. Run it separately from `--git-staged`, whose commit-boundary input is exact index blobs. |
| `--stdin`                     | Read from stdin instead. Default 10 MiB cap; tune with `--limit-stdin-bytes`. |
| `--exclude-paths <GLOB>...`   | Skip files matching glob. Space-separated list, repeatable. |
| `--no-default-excludes`       | Disable the shipped lock-file, minified-file, build-output, and similar default exclusions. Explicit exclusions still apply. |
| `--git-staged`                | Scan exact git index blobs only (pre-commit mode), even when the working-tree copy differs. Honors path exclusions and `.keyhogignore`; accepts the worktree root or any directory beneath it. |
| `--git-history <PATH>`        | Walk commits added-line patches (default: HEAD only). |
| `--git-blobs <PATH>`          | Scan reachable repository blobs, deduplicated by blob ID. |
| `--git-diff <BASE_REF>`       | Scan only added lines since `BASE_REF`.        |
| `--git-diff-path <PATH>`      | Select the repository used by `--git-diff` instead of the current directory. |
| `--max-commits <N>`           | Bound the number of commits traversed by git-history scanning. |
| `--docker-image <IMAGE>`      | Scan a saved Docker image archive.             |
| `--github-org <ORG>`          | Clone and scan every repository in a GitHub organization. Requires `KEYHOG_GITHUB_TOKEN` (recommended) or `--github-token`. |
| `--github-collaboration <OWNER/REPO>` | Select a GitHub collaboration target. Requires one or more of `--github-issues`, `--github-pull-requests`, `--github-discussions`, `--github-wiki`, or `--github-gists`. |
| `--gitlab-group <GROUP>`      | Clone and scan every project in a GitLab group, including subgroups. Requires `KEYHOG_GITLAB_TOKEN` (recommended) or `--gitlab-token`; use `--gitlab-endpoint` for self-managed GitLab. |
| `--bitbucket-workspace <WORKSPACE>` | Clone and scan every repository in a Bitbucket Cloud workspace. Requires `KEYHOG_BITBUCKET_USERNAME` plus `KEYHOG_BITBUCKET_TOKEN` (recommended), or `--bitbucket-username` plus `--bitbucket-token`; `--bitbucket-endpoint` selects the API root. |
| `--s3-bucket <BUCKET>`        | Scan an S3 bucket. Use `--s3-prefix` to narrow and `--s3-endpoint` for an S3-compatible API. |
| `--gcs-bucket <BUCKET>`       | Scan a Google Cloud Storage bucket. Use `--gcs-prefix` to narrow and `--gcs-endpoint` for a compatible API. |
| `--azure-container-url <URL>` | Scan an Azure Blob container URL. Include a SAS query string for private containers; use `--azure-prefix` to narrow. |
| `--url <URL>...`              | Fetch + scan one or more HTTPS URLs (JS/source-map/WASM/text). |
| `--source <NAME>`             | Enable a named pluggable custom input source. Repeat as supported by the loaded source registry. |

### Output

| Flag                          | Effect                                         |
|-------------------------------|------------------------------------------------|
| `--format <text\|json\|json-envelope\|jsonl\|jsonl-envelope\|sarif\|csv\|github-annotations\|gitlab-sast\|html\|junit>` | Output format. Default `text`. Machine formats keep stdout parseable; the banner/summary go to stderr (or are omitted). `json` and `jsonl` retain legacy array/stream contracts; the `*-envelope` forms add versioned schema identity, and JUnit adds coverage properties when a scan is partial. |
| `--output <FILE>`             | Write the report to `FILE` instead of stdout.  |
| `--stream`                    | Stream a one-line redacted preview per finding to stderr as they're found; the full formatted report still lands on stdout/`--output` after verification. |
| `--show-secrets`              | Show full credentials. Default redacts.        |
| `--severity <LEVEL>`          | Minimum reported severity: `info`, `client-safe`, `low`, `medium`, `high`, or `critical`. |
| `--min-confidence <FLOAT>`    | Only emit findings >= confidence. 0.0..=1.0.   |
| `--progress`                  | Force the live progress display. Mutually exclusive with `--quiet`. |
| `--quiet`                     | Suppress banner, live ticker, and completion summary; coverage warnings and fatal errors remain visible. |
| `--no-color`                  | Disable report and summary ANSI styling regardless of terminal detection. |
| `--dogfood`                   | Surface suppression telemetry in output.       |

### Verification and HTTP transport

| Flag                          | Effect                                         |
|-------------------------------|------------------------------------------------|
| `--verify`                    | Call each detector's verify endpoint.          |
| `--timeout <SECONDS>`         | Set the per-request HTTP verification timeout (default `5`); requires `--verify`. This is not a scan deadline. |
| `--verify-concurrency <N>`    | Cap in-flight verification requests per service (default `5`, minimum `1`); requires `--verify`. This is concurrency, not requests per second. |
| `--proxy <URL>`               | Route every outbound KeyHog HTTP client (remote sources and verification) through an explicit proxy (`http://burp:8080`, `socks5://...`). `off` disables all proxying, including TOML configuration; ambient proxy variables are ignored. |
| `--insecure`                  | Skip TLS certificate verification for every outbound KeyHog HTTP client, including remote sources and verification. Use only in a controlled interception lab. |
| `--verify-rate <RPS>`         | Cap steady-state verification calls per service (default `5`); requires `--verify`. |
| `--verify-batch`              | Serialize verification per service; requires `--verify`. |
| `--allow-script-verify`       | Permit `script:` verification only for a detector corpus the operator trusts; activation is warned because verifier-supplied code executes locally. |
| `--verify-oob`                | Enable callback-based verification; requires `--verify`. |
| `--oob-server <HOST>`         | Select the Interactsh collector for OOB verification. |
| `--oob-timeout <SECS>`        | Bound the per-finding OOB callback wait. |

### Performance

| Flag                          | Effect                                         |
|-------------------------------|------------------------------------------------|
| `--fast`                      | Disable entropy discovery, ML scoring, and decode recursion (`max_decode_depth = 0`). Named regex detectors remain loaded; the speedup and recall change are workload-dependent. |
| `--deep`                      | Enable source-file entropy, heuristic plus ML recovery, comment recovery, a 1 MiB decode ceiling, and depth 10. |
| `--precision`                 | Seed a high-precision policy: decode depth 1, entropy discovery and the relaxed keyword bridge off, ML scoring retained, and a minimum confidence floor of `0.85`. Explicit floors may tighten but not lower it. |
| `--incremental`               | Skip files whose content hash matches the Merkle index, then update the index after a successful scan. |
| `--incremental-cache <PATH>`  | Override the Merkle index used by `--incremental`. |
| `--daemon`                    | Require the daemon for an eligible request. Bare form means `on`. See the [daemon contract](../workflows/daemon.md). |
| `--daemon=auto`               | Use an eligible compatible daemon when available, with the documented visible retry. This is the Unix default. |
| `--daemon=off`                | Force in-process scanning. |
| `--daemon-socket <PATH>`      | Select the same non-default socket supplied to `daemon start --socket`. |
| `--benchmark`                 | Run the built-in backend benchmark corpus and exit instead of scanning the requested source. |
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
| `--limit-cloud-max-objects <N>` | Maximum objects listed from one S3, GCS, or Azure container before coverage is reported incomplete. |
| `--limit-docker-tar-entry-bytes <SIZE>` / `--limit-docker-image-config-bytes <SIZE>` / `--limit-docker-tar-total-bytes <SIZE>` | Docker/OCI archive and manifest/config ceilings. |
| `--limit-git-line-bytes <SIZE>` / `--limit-git-total-bytes <SIZE>` / `--limit-git-blob-bytes <SIZE>` / `--limit-git-chunks <N>` | Git stdout-line, aggregate, per-blob, and chunk-count ceilings. |
| `--limit-binary-read-bytes <SIZE>` / `--limit-binary-decompiled-bytes <SIZE>` | Binary strings and Ghidra output ceilings. |
| `--limit-hosted-git-pages <N>` | Maximum hosted Git listing pages or GitHub collaboration API requests. |

### Detector tuning

| Flag                          | Effect                                         |
|-------------------------------|------------------------------------------------|
| `--detectors <DIR>`           | Use the detector TOMLs in `DIR` instead of the embedded corpus. To run a curated subset, copy the detector TOMLs you want into a directory and point `--detectors` at it (there is no per-ID enable/disable flag). |
| `--no-decode` / `--decode-depth <N>` / `--decode-size-limit <SIZE>` | Disable recursive decoding, set its maximum depth, or bound the input size admitted to decode-through scanning. |
| `--no-entropy`                | Disable generic entropy discovery. Named detector matching remains active. |
| `--entropy-source-files`      | Admit entropy discovery in source-code files as well as configuration/data files. |
| `--entropy-threshold <BITS>`  | Set the scan-wide Shannon bits-per-byte threshold where detector-owned policy does not provide the effective gate. |
| `--entropy-bpe-max-bytes-per-token <RATIO>` | Set the scan-wide BPE word-likeness ceiling; lower values suppress more word-like entropy candidates. |
| `--min-secret-len <N>`        | Set the minimum length for entropy-discovery candidates; named detectors retain their shape-specific lengths. |
| `--no-entropy-ml-scoring`     | Disable every entropy owner's compiled ML mode for this scan and use bare entropy scoring. It does not select or alter detector authority. |
| `--no-keyword-low-entropy`    | Disable the lower-floor `generic-keyword-secret` bridge so anchored generic candidates must satisfy the stricter `generic-secret` policy. |
| `--ml-threshold <FLOAT>`      | Raise the resolved global confidence floor. A detector-specific `min_confidence` remains that detector's effective floor. |
| `--ml-weight <FLOAT>`         | Override detector-local ML scoring weights for diagnostics or controlled benchmarks (`0.0..=1.0`). |
| `--no-ml`                    | Disable ML-based confidence scoring. |
| `--no-unicode-norm`          | Disable Unicode normalization; use only for parity diagnostics because it can reduce recall. |
| `--scan-comments`            | Treat credentials in source comments as first-class findings rather than applying the default comment-context confidence penalty. |
| `--no-suppress-test-fixtures` | Show findings on bundled example credentials.  |
| `--baseline <FILE>`           | Compare against a prior scan; show only new.   |
| `--create-baseline <FILE>`    | Write a new baseline from the current findings and exit. |
| `--update-baseline <FILE>`    | Merge current findings into an existing baseline. |
| `--hide-client-safe`          | Drop every `CLIENT-SAFE` finding (Sentry DSN, Stripe `pk_*`, Mapbox `pk.`, PostHog `phc_`, etc.) before reporting. Use this for bug-bounty / exfiltration-impact workflows where keys public by design are noise. |

### Scan controls

| Control                               | Effect                                                                |
|---------------------------------------|-----------------------------------------------------------------------|
| `keyhog scan --backend auto\|gpu-cuda\|gpu-cuda-region-presence\|gpu-wgpu\|gpu-wgpu-region-presence\|simd\|simd-regex\|cpu\|cpu-fallback` | Use persisted automatic routing (`auto`) or force one diagnostic backend. Descriptive labels are accepted spellings of the same peers shown in persisted evidence. Automatic GPU runtime faults visibly replay the stable batch and report recovered bytes; an explicit GPU override remains a hard contract and exits `12`. |
| `keyhog scan --gpu-batch-input-limit 512MB` | Override the VRAM-adaptive byte limit for one GPU region-presence batch (clamped to 128 MiB–1 GiB). |
| `keyhog scan --max-file-size <SIZE>` | Bound one filesystem input (default 100 MiB); larger files are named in the coverage summary. |
| `keyhog scan --regex-dfa-limit <SIZE>` | Bound each regex lazy-DFA cache (default 1 MiB); lowering the safety ceiling may force complex patterns onto the slower NFA path. |
| `keyhog scan --no-gpu`                | Short-circuit GPU init at hardware-probe time. The scanner runs as if no GPU adapter existed. |
| `keyhog scan --require-gpu`           | Fail closed with exit `12` when GPU is unavailable before scanning or a selected GPU dispatch fails at runtime. |
| `keyhog scan --autoroute-calibrate`   | Installer/maintenance mode: benchmark parity-checked autoroute candidates and persist fastest-correct decisions. Normal scans do not use this mode. |
| `keyhog scan --autoroute-gpu`         | Low-level direct-calibration diagnostic: include eligible GPU candidates. `keyhog calibrate-autoroute` always includes every eligible backend. |
| `keyhog scan --no-autoroute-gpu`      | Low-level direct-calibration diagnostic: exclude GPU despite TOML. This is not used by canonical calibration, and its incomplete evidence is isolated from normal auto-scan identity. |
| `keyhog scan --batch-pipeline` / `--no-batch-pipeline` | Explicitly select or reject the coalesced batch pipeline for this diagnostic/configuration identity. |
| `keyhog scan --per-chunk-timeout-ms <MS>` | Attach an `Instant` deadline to every chunk scan. Default unset = no operator deadline; `[scan].per_chunk_timeout_ms` provides the persistent default. |
| `keyhog scan --threads <N>`           | Pin the rayon worker count for this run. `.keyhog.toml` `[scan].threads` provides the persistent default. |
| `keyhog scan --calibration-cache <PATH>` | Apply one explicit per-detector Bayesian confidence cache. Missing or invalid files fail closed. |
| `keyhog scan --reader-threads <N>`    | Pin dedicated filesystem reader threads. `.keyhog.toml` `[scan].reader_threads` provides the persistent default. |
| `keyhog scan --fused-batch <N>`       | Pin fused filesystem pipeline batch size. `.keyhog.toml` `[scan].fused_batch` provides the persistent default. |
| `keyhog scan --fused-depth <N>`       | Pin fused filesystem pipeline channel depth. `.keyhog.toml` `[scan].fused_depth` provides the persistent default. |
| `keyhog scan --dedup <credential\|file\|none>` | Select report grouping scope. Default `credential`. |
| `keyhog scan --no-config`             | Run from compiled defaults only: skip walk-up `.keyhog.toml` discovery and reject an explicit `--config`. |
| `keyhog scan --lockdown`              | Fail closed unless all memory/core-dump/cache protections activate; also forces HTTPS-only verification and forbids disk cache writes. |

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

Prints the resolved scan and report policy and exits without scanning. This is
the operator-visible way to prove what KeyHog would run after compiled defaults,
`.keyhog.toml`, and CLI overrides are merged. The output includes report format,
severity floor, dedup scope, secret visibility, client-safe/test-fixture policy,
and lockdown alongside backend, detector, scanner, source-limit, verification,
and cache settings. It also prints `validate_decode`, the scanner's decoded-
payload safety policy, so the operator can see the exact recursive-decoding
contract covered by the autoroute identity.

`config --effective` accepts the same config-affecting flags as `scan`, including
`--config`, `--fast`, `--deep`, `--precision`, source limits, detector paths,
confidence floors, and the positional path shorthand.

```sh
keyhog config --effective
keyhog config --effective --config .keyhog.toml --precision .
keyhog config --effective --limit-stdin-bytes 32MB --no-ml
```

## `keyhog detectors`

Lists every detector in the effective corpus. With no `--detectors` flag,
KeyHog uses the first installed corpus found in the user data directories,
system data directories, or beside the executable. If none exists, it uses the
embedded corpus. An explicit path always replaces that search and fails closed
when missing or invalid.

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

| Argument | Type | Default | Purpose |
|----------|------|---------|---------|
| `[PATH]...` | directory path(s) | `.` | Watch one or more directory trees. Nested and duplicate roots fold into their covering parent. |
| `--detectors <PATH>` | directory path | installed or embedded corpus | Replace corpus discovery with an explicit detector TOML directory. An explicitly named missing or invalid directory is an error. |
| `--cache-dir <DIR>` | directory path | unset | Override the Hyperscan compiled-database cache directory. |
| `--backend <BACKEND>` | `auto`, `cpu` (`cpu-fallback`), `simd` (`simd-regex`), `gpu-cuda` (`gpu-cuda-region-presence`), or `gpu-wgpu` (`gpu-wgpu-region-presence`) | `auto` | Use persisted autoroute evidence or force one diagnostic backend. Missing, stale, invalid, or runtime-quarantined evidence triggers visible scalar recovery with complete byte coverage and a recalibration receipt. The aliases are accepted spellings of the same backend, not separate routing candidates. |
| `--quiet` | flag | off | Print findings while suppressing watcher startup and status lines. |

## `keyhog hook <install|uninstall>`

Manages the git pre-commit hook. See
[Pre-commit hook](../workflows/precommit.md) for usage.

## `keyhog daemon <start|stop|status>` (Unix only)

The optional foreground daemon holds a compiled scanner for repeated eligible
stdin and single-file scans.

| Subcommand         | Effect                                              |
|--------------------|-----------------------------------------------------|
| `daemon start`     | Bind the Unix socket and accept connections. Startup options include `--socket`, `--detectors`, `--cache-dir`, `--backend`, and `--request-timeout-secs`. |
| `daemon stop`      | Tell the running daemon to shut down.               |
| `daemon status`    | Print uptime, scans served, active scan attempts (running or queued behind serialized scanner execution), detector count, and backend policy. |

See [Daemon and warm scans](../workflows/daemon.md) for option semantics,
`auto` / `on` / `off` routing, eligibility, readiness, socket resolution,
identity, shutdown, timeout, coverage, and exits.

## `keyhog diff <FILE_A> <FILE_B>`

Compare two baseline files produced by `scan --create-baseline`. A credential
present only in the older baseline is `verification_unknown`, not resolved,
because disappearance from source does not prove provider revocation.

```sh
keyhog scan . --create-baseline baseline.json
git checkout pr-branch
keyhog scan . --create-baseline pr.json
keyhog diff baseline.json pr.json
```

Pass `--hide-unchanged` to omit the unchanged section from human output, or
`--json` for a stable CI-readable comparison. Baseline-only removed findings
return exit 1 because their verification state is unknown.

To verify credentials removed between two text artifacts, keep both versions
on disk only for the command lifetime and opt in to network verification:

```sh
keyhog diff old.env new.env --artifacts --verify-removed --json
```

The report emits only `removed_still_live`, `removed_inactive`, or
`verification_unknown`. It never emits the credential. A live or unknown
removal returns exit 1. Only provider-confirmed inactive removals can pass.

| Option | Artifact comparison behavior |
|--------|------------------------------|
| `--artifacts` | Scan both inputs as UTF-8 text with the deterministic CPU reference path. No baseline containing credential bytes is written. |
| `--detectors <DIR>` | Use an explicit detector TOML corpus. A missing explicit directory fails. |
| `--max-artifact-bytes <N>` | Bound each input read. The default is 64 MiB. Oversized or growing inputs fail. |
| `--verify-removed` | Send only before-only credentials to each detector's allowlisted provider endpoint through the existing verifier. A build without verifier support fails visibly. |
| `--verify-timeout <SECONDS>` | Set the per-credential timeout. The default is 5 seconds. Zero is rejected. |

Artifact-only options are rejected during baseline comparison. Binary inputs
must use `keyhog scan --binary`; artifact diff never decodes them implicitly.

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

Runs the local stdin/filesystem scan-policy and workload-bucket sweep, verifies
backend parity, and persists fastest-correct routing evidence for those normal
`auto` scans. Git, container, web, and other environment-backed source classes
remain in the installer's calibration sweep.
The command compiles one scanner per preset. It reuses immutable detector, GPU
literal, and GPU phase-two program artifacts, then resets workload-shaped
accelerator state before each representative. It composes the measured shared
literal and backend-shaped phase-two preparation costs into each matching
one-shot decision. Candidate measurement order rotates across workload bands to
limit fixed-order thermal bias. This avoids per-probe process startup without
turning cold GPU evidence into warm evidence.
`--autoroute-cache <PATH>` selects the evidence file; `off` is rejected because
calibration must persist its result. `--quiet` suppresses per-probe progress but
still prints the final summary.

## `keyhog backend`

Prints hardware probe results and a diagnostic per-tier heuristic matrix:
which SIMD ISA was detected and whether Hyperscan, CUDA, or wgpu initialized.
The matrix is not the `scan --backend auto` decision; normal automatic scans
use persisted fastest-correct calibration. Use `keyhog backend --autoroute`
to inspect that evidence, including distinct cold-aware one-shot and warm-daemon
routes, and `--probe-bytes` only for heuristic what-if work.

The human autoroute view is intentionally concise: it reports cache health,
coverage, selected GPU routes, and the recalibration command. Add `--verbose`
to expand every workload decision and parity receipt. `--json` remains the
complete stable representation for CI and tooling.

```sh
keyhog backend
```

`--probe-bytes <N>` and `--patterns <N>` are what-if inputs to the diagnostic
heuristic matrix only; neither changes the corpus nor predicts persisted
autoroute. On an eligible GPU host, `--self-test` reports three named probes: `moe_kernel` for GPU
confidence scoring, `vyre_literal_set` for VYRE's direct match-triple
diagnostic, and `gpu_region_presence` for the production scan route. The last
probe owns scan eligibility. A direct-mode limitation is reported as `known`
when classified and `warning` otherwise, but only a production-path or required
GPU capability failure makes the health report fail. When no eligible physical
GPU exists, the normal self-test emits one `gpu_adapter` probe with status
`skip` and exits `0`; `--require-gpu` changes that probe to `fail` and exits
`4`. `--no-gpu` explicitly requests the skip without initializing a GPU.
`--json` is available for self-test
and autoroute inspection output. A failed self-test emits the complete report
and exits `4`. An explicit or required GPU scan whose route fails exits `12`;
a normal automatic scan reports stable-input recovery when it can preserve full
coverage.

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

| Option | Type | Default | Purpose |
|--------|------|---------|---------|
| `--space <SIZE>` | positive byte size with `K`, `M`, `G`, or `T` suffix | `50G` | Stop before scanning a file that would exceed the cumulative byte ceiling. |
| `--include-network` | flag | off | Include NFS, SMB, sshfs, and other network mounts. Incompatible with `--lockdown`. |
| `--no-git-history` | flag | off | Skip repository discovery and historical Git object scanning. |
| `--respect-gitignore` | flag | off | Honor Git ignore rules. The default system audit scans ignored working-tree files. |
| `--output <PATH>` | file path | unset | Atomically write the redacted finding array as JSON. Without it, findings use the text diagnostic stream. |
| `--detectors <PATH>` | directory path | installed or embedded corpus | Replace corpus discovery with an explicit detector TOML directory. An explicitly named missing or invalid directory is an error. |
| `--cache-dir <DIR>` | directory path | unset | Override the Hyperscan compiled-database cache directory. |
| `--threads <N>` | positive integer | automatic | Set the scanner worker count. Automatic mode uses the resolved runtime default. |
| `--lockdown` | flag | off | Require stronger memory and process protections and refuse network mounts. |

`--threads` configures a process-global Rayon pool. Reusing the same width in
one process is supported when KeyHog created the pool. An externally initialized
pool is rejected even at the requested width because its stack size, naming,
and ownership cannot be attested. A different live width is also an
operator-visible error. Effective config and autoroute identity record the
actual KeyHog-owned width.

`scan-system` always runs its own in-process scanner, whether the daemon is
active or inactive. It uses persisted autoroute evidence and has no explicit
backend override. Missing, stale, or incomplete evidence warns and completes
through the scalar correctness oracle; the report is marked
`complete_after_recovery` rather than claiming a calibrated route.

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
summary ANSI output, while `detectors --verbose` prints matching-policy
summaries. Use `detectors --format json` for the complete detector schema.
