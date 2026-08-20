# CLI reference

The generated tables on this page are rebuilt from KeyHog's live `clap`
command tree in CI. They cover the root options, every visible top-level
command, nested subcommands, aliases, hidden flags, value arities, defaults,
and possible values. The surrounding workflow guidance remains curated so it
can explain semantics, precedence, and failure modes that `--help` cannot.

## `keyhog scan [PATH]...`

The main subcommand. Scans one or more `PATH` roots (default: current
directory) and emits findings. Pass several roots in a single run
(`keyhog scan src/ tests/ config/`) and each is walked as its own source;
a root nested inside another is folded into its covering parent (announced
on stderr) so no subtree is scanned twice. Exit code: `0` means no finding
blocks the active evidence policy, `1` means at least one finding blocks,
`2` user error, `3` system error, `10` live credential, `11` scanner panic,
`12` selected or required GPU unavailable, and `13` requested source failure
or incomplete coverage.

<!-- keyhog-generated: cli-reference command="scan" -->
| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `<PATH>` | `PATH...` |  | Path(s) to scan. Pass several to scan multiple roots in one run (`keyhog scan a/ b/ c/`); nested or duplicate roots fold into their covering parent. Positional shorthand for `--path` (single root only) |
| `--access-targets` |  |  | Report the resource each credential opens (its "door"). A finding says where a credential is. It does not say which database, bucket, tenant, or account that credential reaches, which is the first thing a responder needs in order to rank it. The address almost always sits next to the credential (in the same connection string, the same `.env`, the same variable block) and no detector can see it: a companion regex is bounded to a few lines and is written to capture the other half of the CREDENTIAL, not the resource. This pass runs after the scan, over the findings the report is about to publish, and attaches typed targets: `account`, `tenant`, `endpoint`, `database`, `resource`. Which providers are understood is Tier-B data (`crates/core/data/access-targets.toml`), not a hardcoded list. Redaction-safe by construction. Connection-string rules skip userinfo with a non-capturing group, any candidate whose digest matches a credential in the same report is dropped, and evidence carries only the rule id, line, column, span length, and line distance. No document text is ever emitted. Bounded: file context is indexed at most once per file, over at most 1 MiB of it, under a 256 MiB whole-pass ceiling. Findings the pass could not inspect (git history, container layers, stdin, unreadable paths) are reported as coverage gaps, so an empty target list never reads as "this credential opens nothing". Purely additive: findings are never added, dropped, reordered, or edited. `--format json-envelope` gains an `access_targets` object; every other format is untouched. Default off, so a report produced without this flag is byte-identical. |
| `--action-receipt` *(hidden)* | `PATH` |  | Write an internal composite-Action receipt bound to the completed report |
| `--allow-gcs-token-forward` |  |  | Forward the ambient GCS bearer token to a custom GCS endpoint you trust. Off by default; googleapis.com endpoints do not need this. This flag is intentionally explicit because it can send a bearer token to a third-party host |
| `--allow-private-cloud-endpoint` |  |  | Allow web, hosted-git, and cloud sources to reach an endpoint whose host, literal or DNS-resolved, is private, loopback, link-local, or cloud-metadata. OFF by default: the shared SSRF screen refuses every such endpoint. Enable ONLY for a trusted private-network deployment, such as an on-premises web application or self-hosted object store. This flag (or its `[http].allow_private_endpoint` TOML equivalent) is the ONLY way to relax the screen. No environment variable can silently turn KeyHog into an SSRF proxy for internal services |
| `--allow-s3-credential-forward` |  |  | Forward ambient AWS credentials to a custom S3 endpoint you trust. Off by default; AWS-owned endpoints do not need this. This flag is intentionally explicit because it can send AWS identity material to a third-party host |
| `--allow-script-verify` |  |  | Permit detector `script:` verification for trusted detector corpora. Off by default because scripts execute verifier-supplied code with credential-adjacent context. Prints an explicit warning when active |
| `--autoroute-cache` | `PATH\|off` |  | Override the persistent autoroute calibration cache file. Use an absolute path, or `off` to disable persistence. Config: `[system].autoroute_cache` in `.keyhog.toml`; this flag overrides it. |
| `--autoroute-calibrate` |  |  | Run this scan as an explicit autoroute calibration probe: benchmark parity-checked backend candidates and persist the fastest-correct decision for each workload bucket. Normal scans never benchmark on cache miss; they use persisted evidence or fail closed without scanning. An explicit `--backend` is diagnostic only |
| `--autoroute-gpu` |  |  | Allow autoroute calibration to include GPU candidates for eligible workload buckets. Normal scans still use persisted calibration only |
| `--azure-container-url` | `URL` |  | Scan an Azure Blob Storage container URL. Include a SAS query string for private containers |
| `--azure-prefix` | `PREFIX` |  | Optional Azure Blob prefix to limit the scan |
| `--backend` | `BACKEND` |  | Select persisted autoroute or explicitly force one diagnostic backend. Accepted values are listed below Possible values: `auto`, `gpu-cuda`, `gpu-cuda-region-presence`, `gpu-metal`, `gpu-metal-region-presence`, `gpu-wgpu`, `gpu-wgpu-region-presence`, `simd`, `simd-regex`, `cpu`, `cpu-fallback`. |
| `--baseline` | `PATH` |  | Suppress findings that match an existing baseline file |
| `--batch-pipeline` |  |  | Force the coalesced batch scan pipeline instead of the fused filesystem pipeline. This is an explicit calibration/diagnostic control, not an ambient environment switch. Config: `[system].batch_pipeline`; this flag overrides it |
| `--benchmark` |  |  | Run the built-in backend benchmark corpus and exit. This measures backend throughput over KeyHog's own corpus; it never scans an operator-supplied target and never writes a report. Passing a scan target (`PATH`, `--path`, `--stdin`) or a report destination (`--output`) alongside it used to exit 0 having silently ignored both, so an operator could read "benchmark winner: ..." as a completed scan of their tree. Those combinations now fail closed with the conflict named. |
| `--binary` |  |  | Scan binary files for hardcoded strings |
| `--bitbucket-endpoint` | `BITBUCKET_ENDPOINT` | `https://api.bitbucket.org/2.0` | Bitbucket Cloud API endpoint root |
| `--bitbucket-token` | `APP_PASSWORD` |  | Bitbucket app password for --bitbucket-workspace. Prefer KEYHOG_BITBUCKET_TOKEN so the token is not exposed in the process list |
| `--bitbucket-username` | `USERNAME` |  | Bitbucket username for --bitbucket-workspace. May be supplied through KEYHOG_BITBUCKET_USERNAME |
| `--bitbucket-workspace` | `WORKSPACE` |  | Scan all repositories in a Bitbucket Cloud workspace |
| `--cache-dir` | `DIR` |  | Override the Hyperscan compiled-database cache directory. This is explicit CLI/TOML configuration, not an environment variable: pass an absolute path under your home directory or the per-user keyhog temp cache root. Config: `[system].cache_dir` in `.keyhog.toml`; this flag overrides it. |
| `--calibration-cache` | `PATH` |  | Explicit per-detector Bayesian calibration cache for confidence scoring. Normal scans are hermetic and ignore any default `keyhog calibrate` cache unless this flag or `[system].calibration_cache` supplies a path. The file must already exist and parse cleanly; damaged or missing explicit caches fail before scanning so score changes are reproducible. |
| `--config` | `PATH` |  | Load configuration from a specific file path |
| `--correlate` |  |  | Report cross-file credential correlations alongside the findings. Joins one credential value seen at several file paths, across the detector boundary that per-detector dedup never crosses, and provider credentials whose halves are separate detectors split across files of one directory (an AWS access key in `main.tf`, its secret in `.env`). Which providers have halves is Tier-B data, not a hardcoded list, and an ambiguous directory reports nothing rather than a guess. Additive only: `--format json-envelope` gains a `correlations` array and `--format text` a summary block. Findings and every other format are unchanged, so a default scan is byte-identical without this flag. |
| `--create-baseline` | `PATH` |  | Create a new baseline file from current findings and exit |
| `--daemon` | `[auto\|on\|mass\|off]` |  | Daemon routing: `auto` (default, use a live daemon for eligible warm requests), `on` (require the warm stdin/single-file route), `mass` (stream bounded directory, Git, archive, binary, remote, or cloud source batches to a daemon started with `daemon start --mass`), or `off` (force in-process). Bare `--daemon` means `on`. Startup and request latency depend on the corpus, backend, cache state, host, and input. See `keyhog daemon start --help`. Socket: the daemon route connects to the shared default resolution (`$XDG_RUNTIME_DIR`, then the OS cache directory, then the OS temporary directory) unless `--daemon-socket <path>` points it at a daemon bound elsewhere (`daemon start --socket <path>`). Unix only: Windows rejects explicit `auto` and `on`; explicit `off` is accepted as a portable declaration of in-process execution. Optional value. Possible values: `auto`, `on`, `mass`, `off`. |
| `--daemon-socket` | `PATH` |  | Connect the daemon route to a daemon bound on a non-default socket. By default `scan --daemon` uses `$XDG_RUNTIME_DIR/keyhog.sock`, then the OS user-cache directory, then the OS temporary directory. Pass the same path a daemon was started on (`keyhog daemon start --socket <path>`) to reach a fixed-location daemon (e.g. a shared/system or systemd-managed instance). Combining it with `--daemon=off` is rejected as contradictory. |
| `--decode-depth` | `DEPTH` |  | Maximum depth for recursive decoding (1-10, default: 10) |
| `--decode-size-limit` | `SIZE` |  | Maximum prepared chunk size admitted to decode-through (default: 512KB) |
| `--dedup` | `DEDUP` | `credential` | Deduplication scope for findings Possible values: `credential`, `file`, `none`. |
| `--deep` |  |  | Deep recovery mode: scans entropy candidates in source files, removes comment confidence penalties, keeps heuristic evidence alongside ML for entropy candidates, sets decode depth 10, and admits one 1 MiB chunk into decode-through. Compatible explicit knobs override this BASE |
| `-d`, `--detectors` | `DETECTORS` | `detectors` | Detector TOML directory |
| `--detectors-mode` | `MODE` |  | How an explicitly selected custom corpus participates in the embedded corpus. Omitted preserves the established replace behavior Possible values: `replace`, `overlay`. |
| `--docker-image` | `IMAGE` |  | Scan a Docker image by unpacking `docker image save` |
| `--dogfood` |  |  | Emit a structured `--dogfood` JSON trace to stderr after the scan: every credential that was matched but suppressed, with the reason, both example/test/placeholder markers (`kind: example_suppressed`) AND shape/heuristic gates such as UUID-v4, bare-hex digest, base64 blob, dashed serial, or repetitive run (`kind: shape_suppressed`, `reason` names the gate), plus bounded static-recovery expressions rejected as malformed (`kind: static_recovery_rejected`). Detail events are bounded; exact aggregate rejection counts and `detail_events_dropped` remain visible after the bound is reached. Credentials are redacted (prefix and suffix shown, middle elided), and recovery rejections contain no source bytes. Useful when keyhog reports zero findings and you want to know whether a match was made and silenced, recovery rejected an expression, or the candidate never reached the engine |
| `--entropy-bpe-max-bytes-per-token` | `RATIO` |  | BPE "rare-not-random" suppression bound in bytes-per-token (default: 2.2). A surviving entropy/generic candidate whose cl100k_base bytes-per-token is above this is treated as word-like (dotted API paths, prose) and dropped. Lower = more aggressive suppression (higher precision, lower recall); a large value effectively disables the gate |
| `--entropy-source-files` |  |  | Enable entropy scanning in source code files |
| `--entropy-threshold` | `BITS` |  | Entropy threshold in bits per byte (default: 4.5) |
| `--evidence-policy` | `POLICY` |  | Finding evidence tiers that produce a non-zero CI exit. `default` blocks `likely` and `confirmed`; `paranoid` also blocks `review`. Findings remain visible under either policy Possible values: `default`, `paranoid`. |
| `--exclude-paths` | `PATH...` |  | Explicit paths or glob patterns to exclude from scanning |
| `--fast` |  |  | Fast mode: pattern matching only. No decode, no entropy, no ML scoring. Maximum speed. A preset is a BASE: it seeds defaults, then compatible explicit knobs override it (e.g. `--fast --decode-depth 2` re-enables shallow decode on top of the fast base). Entropy-only knobs conflict because fast mode disables entropy, so accepting them would create a no-op flag |
| `--format` | `FORMAT` | `text` | Output format. `json` is a bare findings array for pipelines; prefer `json-envelope` for scan status, coverage gaps, and backend recoveries in one document (KH-1435 / KH-1474) Possible values: `text`, `json`, `json-envelope`, `jsonl`, `jsonl-envelope`, `sarif`, `csv`, `github-annotations`, `gitlab-sast`, `html`, `junit`. |
| `--fused-batch` | `N` |  | Fused filesystem pipeline chunk batch size |
| `--fused-depth` | `N` |  | Fused filesystem pipeline channel depth |
| `--gcs-bucket` | `BUCKET` |  | Scan a Google Cloud Storage bucket via the JSON API |
| `--gcs-endpoint` | `URL` |  | Optional GCS endpoint override for compatible APIs or tests |
| `--gcs-prefix` | `PREFIX` |  | Optional GCS object prefix to limit the scan |
| `--git-blobs` | `GIT_BLOBS` |  | Scan repository blobs from refs, reflogs, stashes, and unreachable objects. Commit blobs are collected by parent-tree diff (added, changed, and deleted sides); every ref tip under refs/ plus HEAD, root commits, and unreadable parents fall back to a full tree walk |
| `--git-diff` | `BASE_REF` |  | Scan only changed lines between two git refs (e.g., --git-diff main) |
| `--git-diff-path` | `GIT_DIFF_PATH` |  | Path to git repository for --git-diff (defaults to current directory) |
| `--git-history` | `PATH` |  | Scan reachable commits using added lines from each commit patch |
| `--git-staged` |  |  | Scan exact staged index blobs, never substituted working-tree bytes |
| `--github-all` |  |  | Include every supported collaboration surface for --github-collaboration. This is the concise equivalent of passing all six --github-* surface flags |
| `--github-api-endpoint` | `URL` |  | GitHub-compatible API endpoint for --github-collaboration |
| `--github-collaboration` | `OWNER/REPO` |  | GitHub repository whose explicitly selected collaboration surfaces are scanned |
| `--github-discussions` |  |  | Include discussion text and comments from --github-collaboration |
| `--github-gists` |  |  | Include public gist revisions and comments for the repository owner |
| `--github-issues` |  |  | Include issue text and comments from --github-collaboration |
| `--github-org` | `ORG` |  | Scan all repositories in a GitHub organization |
| `--github-pull-requests` |  |  | Include pull request text, issue comments, and review comments |
| `--github-releases` |  |  | Include release notes, including drafts and prereleases, plus every release asset name and label, from --github-collaboration |
| `--github-token` | `PAT` |  | GitHub personal access token for --github-org or --github-collaboration. Prefer KEYHOG_GITHUB_TOKEN so the token is not exposed in the process list |
| `--github-wiki` |  |  | Include every readable wiki revision from --github-collaboration |
| `--github-wiki-url` | `URL` |  | Explicit clone URL for the wiki selected by --github-wiki |
| `--gitlab-endpoint` | `GITLAB_ENDPOINT` | `https://gitlab.com` | GitLab API endpoint root, for example https://gitlab.example.com |
| `--gitlab-group` | `GROUP` |  | Scan all projects in a GitLab group, including subgroups |
| `--gitlab-token` | `PAT` |  | GitLab personal access token for --gitlab-group. Prefer KEYHOG_GITLAB_TOKEN so the token is not exposed in the process list |
| `--gpu-batch-input-limit` | `SIZE` |  | GPU batch-input buffer byte budget, e.g. "256MB" or "1GB". Overrides the VRAM-adaptive default (128 MiB–1 GiB by detected VRAM); the value is clamped into that range. Larger buffers scan more bytes per GPU dispatch on big inputs at higher VRAM cost. Config: `gpu_batch_input_limit` in `.keyhog.toml`; this flag overrides it |
| `--hide-client-safe` |  |  | Drop every `client-safe` finding before reporting. Use this for bug-bounty / exfiltration-impact workflows where keys that are public by design (Sentry DSN, Stripe `pk_*`, Firebase web, Mapbox `pk.`, PostHog project, Google Maps browser, Mixpanel project, Algolia search, Datadog browser RUM) are noise: the vendor *expects* them to ship in client bundles and no attacker gains server-side access from finding one. Default off: client-safe findings still appear in scan output at the `CLIENT-SAFE` tier (below `LOW`) so a misconfigured "publishable" key wired into a server-only detector still surfaces. `--hide-client-safe` is the explicit opt-in to silence them. |
| `--incremental` |  |  | Incremental scan: skip files whose metadata and content match the spec-bound Merkle index. The index is updated after successful scanning. This works in process and with `--daemon=mass` for daemon-local filesystem roots. If acquisition yields only unchanged files, backend routing and scanner dispatch do not start. Pass `--incremental-cache <path>` to override the default location |
| `--incremental-cache` | `PATH` |  | Override the merkle-index cache file location |
| `--insecure` |  |  | Skip TLS certificate verification for every outbound HTTP request. Needed when scanning through Burp / mitmproxy / corporate-MITM CAs that present self-signed certificates. Off by default. This flag (or its TOML equivalent) is the ONLY way to disable verification: no environment variable can turn it off, so an ambient toggle can't silently expose secrets to a MITM |
| `--limit-azure-blob-bytes` | `SIZE` |  | Maximum bytes downloaded for one Azure blob |
| `--limit-binary-decompiled-bytes` | `SIZE` |  | Maximum Ghidra decompiled-output bytes accepted for parsing |
| `--limit-binary-read-bytes` | `SIZE` |  | Maximum bytes read for binary strings extraction |
| `--limit-cloud-max-objects` | `N` |  | Maximum objects listed from one S3/GCS/Azure container before truncating |
| `--limit-docker-image-config-bytes` | `SIZE` |  | Maximum bytes accepted for Docker/OCI image config and manifest JSON |
| `--limit-docker-tar-entry-bytes` | `SIZE` |  | Maximum bytes allowed for one Docker tar entry |
| `--limit-docker-tar-total-bytes` | `SIZE` |  | Maximum cumulative bytes unpacked for one Docker/OCI image, summed across the image tar and every layer tar |
| `--limit-gcs-object-bytes` | `SIZE` |  | Maximum bytes downloaded for one GCS object |
| `--limit-git-blob-bytes` | `SIZE` |  | Maximum bytes read from one git blob |
| `--limit-git-chunks` | `N` |  | Maximum chunk count emitted by a git blob-history scan |
| `--limit-git-line-bytes` | `SIZE` |  | Maximum bytes buffered for one line of git stdout |
| `--limit-git-total-bytes` | `SIZE` |  | Maximum aggregate bytes emitted by a git blob-history scan |
| `--limit-hosted-git-pages` | `N` |  | Maximum hosted-git listing pages or GitHub collaboration API requests |
| `--limit-s3-object-bytes` | `SIZE` |  | Maximum bytes downloaded for one S3 object |
| `--limit-stdin-bytes` | `SIZE` |  | Maximum bytes accepted from --stdin before failing closed |
| `--limit-web-response-bytes` | `SIZE` |  | Maximum HTTP response bytes scanned by --url |
| `--lockdown` |  |  | Lockdown mode: maximum security at the cost of throughput. Enables every protection in `keyhog_core::apply_protections(true)` (mlock, refuse-on-coredump-leak, refuse-on-disk-cache), forces HTTPS-only verifier, refuses to write any cache to disk, and hard-aborts if any protection fails to take. Use this when keyhog is running inside EnvSeal or otherwise in a security-critical embedding |
| `--matcher-cache` | `DIR\|off` |  | Override the MatcherArtifact cache directory. Persists the eager compiled matcher graph across process invocations. This is distinct from `--cache-dir`, which only stores Hyperscan `.db` shards. Use an absolute directory, or `off` to disable. Config: `[system].matcher_cache` in `.keyhog.toml`; this flag overrides it. |
| `--max-commits` | `MAX_COMMITS` |  | Max git commits to traverse |
| `--max-file-size` | `SIZE` |  | Maximum file size to scan. Files larger than this are listed in the end-of-scan "files skipped: exceeded --max-file-size" summary. Default is 100 MiB, the `FilesystemSource` ceiling. Files above the 1 MiB window size are read in overlapping ~1 MiB windows (so memory stays bounded regardless of file size), up to this cap |
| `--min-confidence` | `FLOAT` |  | Minimum confidence score (0.0 - 1.0) to report findings (default: 0.40) |
| `--min-secret-len` | `N` |  | Minimum credential length for entropy-discovery candidates (default: 16). Named detectors keep their own shape-specific length gates |
| `--ml-threshold` | `THRESHOLD` |  | Raise the global confidence floor (0.0 to 1.0). Takes effect as `max(min_confidence, ml_threshold)`, so it tightens but never loosens the floor set by `--min-confidence`. Despite the name, this raises the floor for ALL findings, not only ML-scored ones, and still applies when `--no-ml` disables ML scoring. A detector's explicit `min_confidence` in its TOML remains that detector's effective floor. Absence leaves the canonical floor untouched |
| `--ml-weight` | `WEIGHT` |  | Override every detector's ML scoring weight for diagnostics/benchmarks |
| `--no-autoroute-gpu` |  |  | Keep GPU candidates out of autoroute calibration even when TOML enables them |
| `--no-batch-pipeline` |  |  | Keep the fused filesystem pipeline even when `[system].batch_pipeline` is true |
| `--no-color` |  |  | Disable ANSI color in the report and the stderr summary, regardless of whether the output is a TTY (the `NO_COLOR` convention is also honored) |
| `--no-config` |  |  | Ignore any ambient `.keyhog.toml`: skip the walk-up discovery from the scan root and reject an explicit `--config`. The scan then runs on the compiled-in shipped defaults (the Tier-A `SHIPPED_*` floors/disables) and nothing else. This is the hermetic, reproducible config used by CI gates and the benchmark harness, so the measured behavior is the shipped default BY DESIGN and cannot silently drift when a stray `.keyhog.toml` appears on an ancestor path; the hermetic-config tests pin that contract |
| `--no-decode` |  |  | Skip decoding base64/hex encoded content |
| `--no-default-excludes` |  |  | Disable every default exclusion for this scan. Two separate defaults are turned off. The walker stops skipping lock files, minified and bundled assets, build outputs, and vendored trees, so their bytes are read. The scanner also stops dropping findings whose path is a minified or vendored bundle (`.min.js`, `.bundle.js`, `.min.css`, `node_modules/`, `site-packages/`, `wp-includes/`, and similar), so a credential a build pipeline inlined into `app.min.js` is reported instead of silently discarded. Expect more noise: random byte sequences in third-party bundles do collide with credential shapes. Without this flag, findings dropped by the second rule are counted and reported as a coverage gap, so you can see how many there were before deciding to rerun. |
| `--no-entropy` |  |  | Disable entropy-based detection |
| `--no-entropy-ml-scoring` |  |  | Score entropy-discovery candidates with the bare entropy heuristic instead of routing them through the MoE (the model is authoritative by default). The default ML path is a recall-safe precision win on the detector-owned model mode; this opt-out selects bare entropy-only scoring. It does not change detector policy and has no effect when `--no-entropy` or `--no-ml` is set |
| `--no-gpu` |  |  | Disable GPU probing and GPU backend acquisition for this scan |
| `--no-keyword-low-entropy` |  |  | Disable the lower-floor `generic-keyword-secret` bridge for anchored values (`PASSWORD=`, `*_PASS=`, `secret:`, `api_key=` ...). Anchored candidates must then satisfy the stricter `generic-secret` policy. No effect unless the generic keyword bridge would otherwise fire |
| `--no-ml` |  |  | Disable ML-based confidence scoring |
| `--no-suppress-test-fixtures` |  |  | Opt out of the bundled test-fixture suppression list. By default keyhog suppresses well-known public demo credentials (Stripe's docs example `sk_live_4eC39...`, GitHub's docs example `ghp_aBcD...`, the keyhog test fixtures, etc.) so the report stays focused on real leaks rather than tutorial copies. Pass this flag when you intentionally want those surfaced. Useful for differential benchmarking against gitleaks / trufflehog (which do NOT suppress these), or for auditing the suppression list itself |
| `--no-unicode-norm` |  |  | Disable Unicode normalization (not recommended) |
| `--no-verify` |  |  | Disable credential verification, overriding `verify = true` in `.keyhog.toml` |
| `--oob-server` | `HOST` | `oast.fun` | Interactsh server for OOB verification. Defaults to projectdiscovery's public collector at `oast.fun`. Use a self-hosted server for sensitive scans; the collector sees correlation IDs and the IPs of services that call back, never the credential itself. Only meaningful with `--verify-oob`; clap rejects the flag without it instead of silently ignoring it (the prior behavior gave false confidence that an override had been applied) |
| `--oob-timeout` | `SECS` | `30` | Per-finding OOB wait timeout in seconds. Detector specs may set their own `timeout_secs`; this value is the global default. The upper bound is max(this value, 120s), so a detector can always wait at least 120s for a delayed webhook even when this default is lower. Lower = faster scans, higher = catches services with delayed webhooks (e.g., queued mail delivery). Requires `--verify-oob` |
| `-o`, `--output` | `OUTPUT` |  | Write findings to file |
| `-p`, `--path` | `PATH` |  | Scan a directory or file |
| `--per-chunk-timeout-ms` | `MS` |  | Hard deadline per chunk scan in milliseconds. Default unset = no operator deadline; decode still has its internal bomb guard |
| `--perf-trace` |  |  | Raise `--profile` to its diagnostic level: add higher-overhead per-pattern, per-decoder, and backend timing traces on stderr |
| `--precision` |  |  | High-precision mode for mass scanning: minimise false positives at the cost of some recall. Disables entropy discovery and the relaxed keyword bridge, retains ML scoring for remaining candidates, raises the minimum confidence floor to 0.85, and uses decode depth 1. Explicit confidence flags may tighten but cannot lower that floor. Entropy-only knobs conflict because precision mode disables entropy |
| `--profile` |  |  | Emit low-overhead stage, resource, build, policy, source, and measured workload identity evidence to stderr at scan end |
| `--profile-out` | `PATH` |  | Write the complete causal scan profile as JSON to `PATH` at scan end. Implies `--profile`; the artifact is written atomically |
| `--progress` |  |  | Show progress bar |
| `--proxy` | `URL` |  | Route outbound HTTP through a proxy (`http://burp:8080`, `socks5://127.0.0.1:9050`, etc.). This flag (or its TOML equivalent) is the ONLY way to set a proxy: no environment variable is consulted, and ambient `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` is ignored, so a stray env proxy can never silently reroute secret-bearing traffic. When unset, no proxy is used. Pass `off` to make that explicit for air-gapped scans |
| `--quiet` |  |  | Suppress the interactive stderr chrome (banner, live progress ticker, and the "Scan complete" summary). Coverage FAIL/WARN lines and fatal errors are still printed so a quiet scan can never read as clean when it was not. Findings still go to stdout / `--output`. Mutually exclusive with `--progress` |
| `--reader-threads` | `N` |  | Dedicated filesystem reader threads. Default is one direct reader |
| `--regex-dfa-limit` | `SIZE` |  | Per-regex lazy-DFA cache CEILING, e.g. "256KB" or "1MB" (default 1 MiB). Bounds the worst-case per-thread DFA cache for pathological/state-heavy patterns; typical detectors stay well under it, so lowering this does NOT meaningfully cut peak memory (it's a safety ceiling, not a general memory lever). Lowering can force complex regexes to slower NFA simulation; raise it only for unusually large patterns. Config: `regex_dfa_limit` in `.keyhog.toml`; this flag overrides it |
| `--require-gpu` |  |  | Require a usable GPU stack before scanning and keep GPU execution as a hard contract; unavailable initialization or runtime dispatch exits 12 |
| `--s3-bucket` | `BUCKET` |  | Scan a public or path-style S3 bucket via ListObjectsV2 |
| `--s3-endpoint` | `URL` |  | Optional S3 endpoint for S3-compatible APIs |
| `--s3-prefix` | `PREFIX` |  | Optional S3 object prefix to limit the scan |
| `--scan-comments` |  |  | Treat credentials inside source-code comments (// … / # … / /* … */ / &lt;!-- … --&gt;) as first-class findings instead of applying the default comment-context confidence penalty. By default keyhog downgrades the confidence of credentials it sees inside a comment because the most common case is an engineer pasting an EXAMPLE token into a doc comment. The drawback is that genuine secrets pasted into a TODO ("rotate this key, Bob") or a debug-trace comment never surface. Pass `--scan-comments` for repos where comments are part of the threat surface: shared snippets directories, leak post-mortems, training corpora, and CTF-style audits. |
| `-s`, `--severity` | `SEVERITY` |  | Min severity to report: info, client-safe, low, medium, high, critical Possible values: `info`, `client-safe`, `low`, `medium`, `high`, `critical`. |
| `--show-secrets` |  |  | Show full credentials (default: redacted) |
| `--source` | `NAME[:PARAMS]` |  | Construct a compiled-in source by canonical name |
| `--stdin` |  |  | Scan stdin |
| `--stream` |  |  | Emit a redacted `[stream]` preview line on stderr for every REPORTED finding (`SEVERITY SERVICE/DETECTOR PATH:LINE redacted`), so a quick human- or CI-scrapeable summary lands on stderr while the full formatted report (text/json/sarif/jsonl) goes to stdout or `--output`. The preview stream is consistent with that report and the exit code: every streamed line corresponds to a finding that survived suppression, the confidence floor / `--min-confidence`, and baseline filtering, it never previews a match the report drops |
| `--threads` | `N` |  | Number of parallel scanning threads (default: number of CPU cores) |
| `--timeout` | `TIMEOUT` |  | Per-request HTTP verification timeout in seconds (default: 5). This does not impose a deadline on scanning; use `--per-chunk-timeout-ms` for the scanner's optional chunk deadline |
| `--update-baseline` | `PATH` |  | Update an existing baseline file with new findings |
| `--url` | `URL...` |  | Scan JavaScript, source maps, or WASM binaries at URLs for secrets |
| `--verify` |  |  | Verify discovered credentials via API calls |
| `--verify-batch` |  |  | Conservative verify mode: serialises live verifications per service (max-concurrent-per-service = 1) on top of the `--verify-rate` cap. Use for repos with lots of legitimate findings (test fixtures, vendored examples) where bursting a provider's auth endpoint would get the scan IP rate-limited or blocked. Implies `--verify` |
| `--verify-concurrency` | `N` |  | Maximum in-flight verification requests per service (default: 5) |
| `--verify-oob` |  |  | Enable out-of-band callback verification via an embedded interactsh client. For webhook- and callback-shaped credentials, OOB verification proves the credential is exfil-capable: we mint a per-finding subdomain on the configured collector, embed it in the verification probe, and confirm the service actually called back. Off by default. See docs/src/reference/oob-verification.md for the threat model and self-hosting guidance |
| `--verify-rate` | `RPS` | `5.0` | Steady-state cap for verification calls *per service*, in requests-per-second. Default 5.0. Drop this to be polite to upstream APIs when scanning a tree with hundreds of legitimate findings (test fixtures, examples); every finding produces a live verify call and most public APIs throttle aggressively. The limiter applies even with `--verify-batch` (which adds per-service serialisation on top) |
<!-- /keyhog-generated: cli-reference command="scan" -->

Hyperscan database cache location is explicit scan configuration: use
`keyhog scan --cache-dir <DIR>` or `.keyhog.toml` `[system].cache_dir`.
Autoroute calibration evidence is also explicit scan configuration: use
`keyhog scan --autoroute-cache <PATH|off>` or `.keyhog.toml`
`[system].autoroute_cache`.
GPU region-presence parity/debug recall-floor runs use `.keyhog.toml`
`[tuning].gpu_recall_floor = true`. Authenticated GPU routes score eligible
candidates through the separate quantized VYRE program; CPU-owned rows and the
shared policy tail remain on the CPU.

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

<!-- keyhog-generated: cli-reference command="config" -->
| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `<PATH>` | `PATH...` |  | Path(s) to scan. Pass several to scan multiple roots in one run (`keyhog scan a/ b/ c/`); nested or duplicate roots fold into their covering parent. Positional shorthand for `--path` (single root only) |
| `--access-targets` |  |  | Report the resource each credential opens (its "door"). A finding says where a credential is. It does not say which database, bucket, tenant, or account that credential reaches, which is the first thing a responder needs in order to rank it. The address almost always sits next to the credential (in the same connection string, the same `.env`, the same variable block) and no detector can see it: a companion regex is bounded to a few lines and is written to capture the other half of the CREDENTIAL, not the resource. This pass runs after the scan, over the findings the report is about to publish, and attaches typed targets: `account`, `tenant`, `endpoint`, `database`, `resource`. Which providers are understood is Tier-B data (`crates/core/data/access-targets.toml`), not a hardcoded list. Redaction-safe by construction. Connection-string rules skip userinfo with a non-capturing group, any candidate whose digest matches a credential in the same report is dropped, and evidence carries only the rule id, line, column, span length, and line distance. No document text is ever emitted. Bounded: file context is indexed at most once per file, over at most 1 MiB of it, under a 256 MiB whole-pass ceiling. Findings the pass could not inspect (git history, container layers, stdin, unreadable paths) are reported as coverage gaps, so an empty target list never reads as "this credential opens nothing". Purely additive: findings are never added, dropped, reordered, or edited. `--format json-envelope` gains an `access_targets` object; every other format is untouched. Default off, so a report produced without this flag is byte-identical. |
| `--action-receipt` *(hidden)* | `PATH` |  | Write an internal composite-Action receipt bound to the completed report |
| `--allow-gcs-token-forward` |  |  | Forward the ambient GCS bearer token to a custom GCS endpoint you trust. Off by default; googleapis.com endpoints do not need this. This flag is intentionally explicit because it can send a bearer token to a third-party host |
| `--allow-private-cloud-endpoint` |  |  | Allow web, hosted-git, and cloud sources to reach an endpoint whose host, literal or DNS-resolved, is private, loopback, link-local, or cloud-metadata. OFF by default: the shared SSRF screen refuses every such endpoint. Enable ONLY for a trusted private-network deployment, such as an on-premises web application or self-hosted object store. This flag (or its `[http].allow_private_endpoint` TOML equivalent) is the ONLY way to relax the screen. No environment variable can silently turn KeyHog into an SSRF proxy for internal services |
| `--allow-s3-credential-forward` |  |  | Forward ambient AWS credentials to a custom S3 endpoint you trust. Off by default; AWS-owned endpoints do not need this. This flag is intentionally explicit because it can send AWS identity material to a third-party host |
| `--allow-script-verify` |  |  | Permit detector `script:` verification for trusted detector corpora. Off by default because scripts execute verifier-supplied code with credential-adjacent context. Prints an explicit warning when active |
| `--autoroute-cache` | `PATH\|off` |  | Override the persistent autoroute calibration cache file. Use an absolute path, or `off` to disable persistence. Config: `[system].autoroute_cache` in `.keyhog.toml`; this flag overrides it. |
| `--autoroute-calibrate` |  |  | Run this scan as an explicit autoroute calibration probe: benchmark parity-checked backend candidates and persist the fastest-correct decision for each workload bucket. Normal scans never benchmark on cache miss; they use persisted evidence or fail closed without scanning. An explicit `--backend` is diagnostic only |
| `--autoroute-gpu` |  |  | Allow autoroute calibration to include GPU candidates for eligible workload buckets. Normal scans still use persisted calibration only |
| `--azure-container-url` | `URL` |  | Scan an Azure Blob Storage container URL. Include a SAS query string for private containers |
| `--azure-prefix` | `PREFIX` |  | Optional Azure Blob prefix to limit the scan |
| `--backend` | `BACKEND` |  | Select persisted autoroute or explicitly force one diagnostic backend. Accepted values are listed below Possible values: `auto`, `gpu-cuda`, `gpu-cuda-region-presence`, `gpu-metal`, `gpu-metal-region-presence`, `gpu-wgpu`, `gpu-wgpu-region-presence`, `simd`, `simd-regex`, `cpu`, `cpu-fallback`. |
| `--baseline` | `PATH` |  | Suppress findings that match an existing baseline file |
| `--batch-pipeline` |  |  | Force the coalesced batch scan pipeline instead of the fused filesystem pipeline. This is an explicit calibration/diagnostic control, not an ambient environment switch. Config: `[system].batch_pipeline`; this flag overrides it |
| `--benchmark` |  |  | Run the built-in backend benchmark corpus and exit. This measures backend throughput over KeyHog's own corpus; it never scans an operator-supplied target and never writes a report. Passing a scan target (`PATH`, `--path`, `--stdin`) or a report destination (`--output`) alongside it used to exit 0 having silently ignored both, so an operator could read "benchmark winner: ..." as a completed scan of their tree. Those combinations now fail closed with the conflict named. |
| `--binary` |  |  | Scan binary files for hardcoded strings |
| `--bitbucket-endpoint` | `BITBUCKET_ENDPOINT` | `https://api.bitbucket.org/2.0` | Bitbucket Cloud API endpoint root |
| `--bitbucket-token` | `APP_PASSWORD` |  | Bitbucket app password for --bitbucket-workspace. Prefer KEYHOG_BITBUCKET_TOKEN so the token is not exposed in the process list |
| `--bitbucket-username` | `USERNAME` |  | Bitbucket username for --bitbucket-workspace. May be supplied through KEYHOG_BITBUCKET_USERNAME |
| `--bitbucket-workspace` | `WORKSPACE` |  | Scan all repositories in a Bitbucket Cloud workspace |
| `--cache-dir` | `DIR` |  | Override the Hyperscan compiled-database cache directory. This is explicit CLI/TOML configuration, not an environment variable: pass an absolute path under your home directory or the per-user keyhog temp cache root. Config: `[system].cache_dir` in `.keyhog.toml`; this flag overrides it. |
| `--calibration-cache` | `PATH` |  | Explicit per-detector Bayesian calibration cache for confidence scoring. Normal scans are hermetic and ignore any default `keyhog calibrate` cache unless this flag or `[system].calibration_cache` supplies a path. The file must already exist and parse cleanly; damaged or missing explicit caches fail before scanning so score changes are reproducible. |
| `--config` | `PATH` |  | Load configuration from a specific file path |
| `--correlate` |  |  | Report cross-file credential correlations alongside the findings. Joins one credential value seen at several file paths, across the detector boundary that per-detector dedup never crosses, and provider credentials whose halves are separate detectors split across files of one directory (an AWS access key in `main.tf`, its secret in `.env`). Which providers have halves is Tier-B data, not a hardcoded list, and an ambiguous directory reports nothing rather than a guess. Additive only: `--format json-envelope` gains a `correlations` array and `--format text` a summary block. Findings and every other format are unchanged, so a default scan is byte-identical without this flag. |
| `--create-baseline` | `PATH` |  | Create a new baseline file from current findings and exit |
| `--daemon` | `[auto\|on\|mass\|off]` |  | Daemon routing: `auto` (default, use a live daemon for eligible warm requests), `on` (require the warm stdin/single-file route), `mass` (stream bounded directory, Git, archive, binary, remote, or cloud source batches to a daemon started with `daemon start --mass`), or `off` (force in-process). Bare `--daemon` means `on`. Startup and request latency depend on the corpus, backend, cache state, host, and input. See `keyhog daemon start --help`. Socket: the daemon route connects to the shared default resolution (`$XDG_RUNTIME_DIR`, then the OS cache directory, then the OS temporary directory) unless `--daemon-socket <path>` points it at a daemon bound elsewhere (`daemon start --socket <path>`). Unix only: Windows rejects explicit `auto` and `on`; explicit `off` is accepted as a portable declaration of in-process execution. Optional value. Possible values: `auto`, `on`, `mass`, `off`. |
| `--daemon-socket` | `PATH` |  | Connect the daemon route to a daemon bound on a non-default socket. By default `scan --daemon` uses `$XDG_RUNTIME_DIR/keyhog.sock`, then the OS user-cache directory, then the OS temporary directory. Pass the same path a daemon was started on (`keyhog daemon start --socket <path>`) to reach a fixed-location daemon (e.g. a shared/system or systemd-managed instance). Combining it with `--daemon=off` is rejected as contradictory. |
| `--decode-depth` | `DEPTH` |  | Maximum depth for recursive decoding (1-10, default: 10) |
| `--decode-size-limit` | `SIZE` |  | Maximum prepared chunk size admitted to decode-through (default: 512KB) |
| `--dedup` | `DEDUP` | `credential` | Deduplication scope for findings Possible values: `credential`, `file`, `none`. |
| `--deep` |  |  | Deep recovery mode: scans entropy candidates in source files, removes comment confidence penalties, keeps heuristic evidence alongside ML for entropy candidates, sets decode depth 10, and admits one 1 MiB chunk into decode-through. Compatible explicit knobs override this BASE |
| `-d`, `--detectors` | `DETECTORS` | `detectors` | Detector TOML directory |
| `--detectors-mode` | `MODE` |  | How an explicitly selected custom corpus participates in the embedded corpus. Omitted preserves the established replace behavior Possible values: `replace`, `overlay`. |
| `--docker-image` | `IMAGE` |  | Scan a Docker image by unpacking `docker image save` |
| `--dogfood` |  |  | Emit a structured `--dogfood` JSON trace to stderr after the scan: every credential that was matched but suppressed, with the reason, both example/test/placeholder markers (`kind: example_suppressed`) AND shape/heuristic gates such as UUID-v4, bare-hex digest, base64 blob, dashed serial, or repetitive run (`kind: shape_suppressed`, `reason` names the gate), plus bounded static-recovery expressions rejected as malformed (`kind: static_recovery_rejected`). Detail events are bounded; exact aggregate rejection counts and `detail_events_dropped` remain visible after the bound is reached. Credentials are redacted (prefix and suffix shown, middle elided), and recovery rejections contain no source bytes. Useful when keyhog reports zero findings and you want to know whether a match was made and silenced, recovery rejected an expression, or the candidate never reached the engine |
| `--effective` *(required)* |  |  | Print the resolved scan configuration and exit without scanning. Accepts the same config-affecting flags as `keyhog scan`, so operators can prove the compiled defaults, TOML config, and CLI overrides that would reach the scanner for the same scan invocation. |
| `--entropy-bpe-max-bytes-per-token` | `RATIO` |  | BPE "rare-not-random" suppression bound in bytes-per-token (default: 2.2). A surviving entropy/generic candidate whose cl100k_base bytes-per-token is above this is treated as word-like (dotted API paths, prose) and dropped. Lower = more aggressive suppression (higher precision, lower recall); a large value effectively disables the gate |
| `--entropy-source-files` |  |  | Enable entropy scanning in source code files |
| `--entropy-threshold` | `BITS` |  | Entropy threshold in bits per byte (default: 4.5) |
| `--evidence-policy` | `POLICY` |  | Finding evidence tiers that produce a non-zero CI exit. `default` blocks `likely` and `confirmed`; `paranoid` also blocks `review`. Findings remain visible under either policy Possible values: `default`, `paranoid`. |
| `--exclude-paths` | `PATH...` |  | Explicit paths or glob patterns to exclude from scanning |
| `--fast` |  |  | Fast mode: pattern matching only. No decode, no entropy, no ML scoring. Maximum speed. A preset is a BASE: it seeds defaults, then compatible explicit knobs override it (e.g. `--fast --decode-depth 2` re-enables shallow decode on top of the fast base). Entropy-only knobs conflict because fast mode disables entropy, so accepting them would create a no-op flag |
| `--format` | `FORMAT` | `text` | Output format. `json` is a bare findings array for pipelines; prefer `json-envelope` for scan status, coverage gaps, and backend recoveries in one document (KH-1435 / KH-1474) Possible values: `text`, `json`, `json-envelope`, `jsonl`, `jsonl-envelope`, `sarif`, `csv`, `github-annotations`, `gitlab-sast`, `html`, `junit`. |
| `--fused-batch` | `N` |  | Fused filesystem pipeline chunk batch size |
| `--fused-depth` | `N` |  | Fused filesystem pipeline channel depth |
| `--gcs-bucket` | `BUCKET` |  | Scan a Google Cloud Storage bucket via the JSON API |
| `--gcs-endpoint` | `URL` |  | Optional GCS endpoint override for compatible APIs or tests |
| `--gcs-prefix` | `PREFIX` |  | Optional GCS object prefix to limit the scan |
| `--git-blobs` | `GIT_BLOBS` |  | Scan repository blobs from refs, reflogs, stashes, and unreachable objects. Commit blobs are collected by parent-tree diff (added, changed, and deleted sides); every ref tip under refs/ plus HEAD, root commits, and unreadable parents fall back to a full tree walk |
| `--git-diff` | `BASE_REF` |  | Scan only changed lines between two git refs (e.g., --git-diff main) |
| `--git-diff-path` | `GIT_DIFF_PATH` |  | Path to git repository for --git-diff (defaults to current directory) |
| `--git-history` | `PATH` |  | Scan reachable commits using added lines from each commit patch |
| `--git-staged` |  |  | Scan exact staged index blobs, never substituted working-tree bytes |
| `--github-all` |  |  | Include every supported collaboration surface for --github-collaboration. This is the concise equivalent of passing all six --github-* surface flags |
| `--github-api-endpoint` | `URL` |  | GitHub-compatible API endpoint for --github-collaboration |
| `--github-collaboration` | `OWNER/REPO` |  | GitHub repository whose explicitly selected collaboration surfaces are scanned |
| `--github-discussions` |  |  | Include discussion text and comments from --github-collaboration |
| `--github-gists` |  |  | Include public gist revisions and comments for the repository owner |
| `--github-issues` |  |  | Include issue text and comments from --github-collaboration |
| `--github-org` | `ORG` |  | Scan all repositories in a GitHub organization |
| `--github-pull-requests` |  |  | Include pull request text, issue comments, and review comments |
| `--github-releases` |  |  | Include release notes, including drafts and prereleases, plus every release asset name and label, from --github-collaboration |
| `--github-token` | `PAT` |  | GitHub personal access token for --github-org or --github-collaboration. Prefer KEYHOG_GITHUB_TOKEN so the token is not exposed in the process list |
| `--github-wiki` |  |  | Include every readable wiki revision from --github-collaboration |
| `--github-wiki-url` | `URL` |  | Explicit clone URL for the wiki selected by --github-wiki |
| `--gitlab-endpoint` | `GITLAB_ENDPOINT` | `https://gitlab.com` | GitLab API endpoint root, for example https://gitlab.example.com |
| `--gitlab-group` | `GROUP` |  | Scan all projects in a GitLab group, including subgroups |
| `--gitlab-token` | `PAT` |  | GitLab personal access token for --gitlab-group. Prefer KEYHOG_GITLAB_TOKEN so the token is not exposed in the process list |
| `--gpu-batch-input-limit` | `SIZE` |  | GPU batch-input buffer byte budget, e.g. "256MB" or "1GB". Overrides the VRAM-adaptive default (128 MiB–1 GiB by detected VRAM); the value is clamped into that range. Larger buffers scan more bytes per GPU dispatch on big inputs at higher VRAM cost. Config: `gpu_batch_input_limit` in `.keyhog.toml`; this flag overrides it |
| `--hide-client-safe` |  |  | Drop every `client-safe` finding before reporting. Use this for bug-bounty / exfiltration-impact workflows where keys that are public by design (Sentry DSN, Stripe `pk_*`, Firebase web, Mapbox `pk.`, PostHog project, Google Maps browser, Mixpanel project, Algolia search, Datadog browser RUM) are noise: the vendor *expects* them to ship in client bundles and no attacker gains server-side access from finding one. Default off: client-safe findings still appear in scan output at the `CLIENT-SAFE` tier (below `LOW`) so a misconfigured "publishable" key wired into a server-only detector still surfaces. `--hide-client-safe` is the explicit opt-in to silence them. |
| `--incremental` |  |  | Incremental scan: skip files whose metadata and content match the spec-bound Merkle index. The index is updated after successful scanning. This works in process and with `--daemon=mass` for daemon-local filesystem roots. If acquisition yields only unchanged files, backend routing and scanner dispatch do not start. Pass `--incremental-cache <path>` to override the default location |
| `--incremental-cache` | `PATH` |  | Override the merkle-index cache file location |
| `--insecure` |  |  | Skip TLS certificate verification for every outbound HTTP request. Needed when scanning through Burp / mitmproxy / corporate-MITM CAs that present self-signed certificates. Off by default. This flag (or its TOML equivalent) is the ONLY way to disable verification: no environment variable can turn it off, so an ambient toggle can't silently expose secrets to a MITM |
| `--limit-azure-blob-bytes` | `SIZE` |  | Maximum bytes downloaded for one Azure blob |
| `--limit-binary-decompiled-bytes` | `SIZE` |  | Maximum Ghidra decompiled-output bytes accepted for parsing |
| `--limit-binary-read-bytes` | `SIZE` |  | Maximum bytes read for binary strings extraction |
| `--limit-cloud-max-objects` | `N` |  | Maximum objects listed from one S3/GCS/Azure container before truncating |
| `--limit-docker-image-config-bytes` | `SIZE` |  | Maximum bytes accepted for Docker/OCI image config and manifest JSON |
| `--limit-docker-tar-entry-bytes` | `SIZE` |  | Maximum bytes allowed for one Docker tar entry |
| `--limit-docker-tar-total-bytes` | `SIZE` |  | Maximum cumulative bytes unpacked for one Docker/OCI image, summed across the image tar and every layer tar |
| `--limit-gcs-object-bytes` | `SIZE` |  | Maximum bytes downloaded for one GCS object |
| `--limit-git-blob-bytes` | `SIZE` |  | Maximum bytes read from one git blob |
| `--limit-git-chunks` | `N` |  | Maximum chunk count emitted by a git blob-history scan |
| `--limit-git-line-bytes` | `SIZE` |  | Maximum bytes buffered for one line of git stdout |
| `--limit-git-total-bytes` | `SIZE` |  | Maximum aggregate bytes emitted by a git blob-history scan |
| `--limit-hosted-git-pages` | `N` |  | Maximum hosted-git listing pages or GitHub collaboration API requests |
| `--limit-s3-object-bytes` | `SIZE` |  | Maximum bytes downloaded for one S3 object |
| `--limit-stdin-bytes` | `SIZE` |  | Maximum bytes accepted from --stdin before failing closed |
| `--limit-web-response-bytes` | `SIZE` |  | Maximum HTTP response bytes scanned by --url |
| `--lockdown` |  |  | Lockdown mode: maximum security at the cost of throughput. Enables every protection in `keyhog_core::apply_protections(true)` (mlock, refuse-on-coredump-leak, refuse-on-disk-cache), forces HTTPS-only verifier, refuses to write any cache to disk, and hard-aborts if any protection fails to take. Use this when keyhog is running inside EnvSeal or otherwise in a security-critical embedding |
| `--matcher-cache` | `DIR\|off` |  | Override the MatcherArtifact cache directory. Persists the eager compiled matcher graph across process invocations. This is distinct from `--cache-dir`, which only stores Hyperscan `.db` shards. Use an absolute directory, or `off` to disable. Config: `[system].matcher_cache` in `.keyhog.toml`; this flag overrides it. |
| `--max-commits` | `MAX_COMMITS` |  | Max git commits to traverse |
| `--max-file-size` | `SIZE` |  | Maximum file size to scan. Files larger than this are listed in the end-of-scan "files skipped: exceeded --max-file-size" summary. Default is 100 MiB, the `FilesystemSource` ceiling. Files above the 1 MiB window size are read in overlapping ~1 MiB windows (so memory stays bounded regardless of file size), up to this cap |
| `--min-confidence` | `FLOAT` |  | Minimum confidence score (0.0 - 1.0) to report findings (default: 0.40) |
| `--min-secret-len` | `N` |  | Minimum credential length for entropy-discovery candidates (default: 16). Named detectors keep their own shape-specific length gates |
| `--ml-threshold` | `THRESHOLD` |  | Raise the global confidence floor (0.0 to 1.0). Takes effect as `max(min_confidence, ml_threshold)`, so it tightens but never loosens the floor set by `--min-confidence`. Despite the name, this raises the floor for ALL findings, not only ML-scored ones, and still applies when `--no-ml` disables ML scoring. A detector's explicit `min_confidence` in its TOML remains that detector's effective floor. Absence leaves the canonical floor untouched |
| `--ml-weight` | `WEIGHT` |  | Override every detector's ML scoring weight for diagnostics/benchmarks |
| `--no-autoroute-gpu` |  |  | Keep GPU candidates out of autoroute calibration even when TOML enables them |
| `--no-batch-pipeline` |  |  | Keep the fused filesystem pipeline even when `[system].batch_pipeline` is true |
| `--no-color` |  |  | Disable ANSI color in the report and the stderr summary, regardless of whether the output is a TTY (the `NO_COLOR` convention is also honored) |
| `--no-config` |  |  | Ignore any ambient `.keyhog.toml`: skip the walk-up discovery from the scan root and reject an explicit `--config`. The scan then runs on the compiled-in shipped defaults (the Tier-A `SHIPPED_*` floors/disables) and nothing else. This is the hermetic, reproducible config used by CI gates and the benchmark harness, so the measured behavior is the shipped default BY DESIGN and cannot silently drift when a stray `.keyhog.toml` appears on an ancestor path; the hermetic-config tests pin that contract |
| `--no-decode` |  |  | Skip decoding base64/hex encoded content |
| `--no-default-excludes` |  |  | Disable every default exclusion for this scan. Two separate defaults are turned off. The walker stops skipping lock files, minified and bundled assets, build outputs, and vendored trees, so their bytes are read. The scanner also stops dropping findings whose path is a minified or vendored bundle (`.min.js`, `.bundle.js`, `.min.css`, `node_modules/`, `site-packages/`, `wp-includes/`, and similar), so a credential a build pipeline inlined into `app.min.js` is reported instead of silently discarded. Expect more noise: random byte sequences in third-party bundles do collide with credential shapes. Without this flag, findings dropped by the second rule are counted and reported as a coverage gap, so you can see how many there were before deciding to rerun. |
| `--no-entropy` |  |  | Disable entropy-based detection |
| `--no-entropy-ml-scoring` |  |  | Score entropy-discovery candidates with the bare entropy heuristic instead of routing them through the MoE (the model is authoritative by default). The default ML path is a recall-safe precision win on the detector-owned model mode; this opt-out selects bare entropy-only scoring. It does not change detector policy and has no effect when `--no-entropy` or `--no-ml` is set |
| `--no-gpu` |  |  | Disable GPU probing and GPU backend acquisition for this scan |
| `--no-keyword-low-entropy` |  |  | Disable the lower-floor `generic-keyword-secret` bridge for anchored values (`PASSWORD=`, `*_PASS=`, `secret:`, `api_key=` ...). Anchored candidates must then satisfy the stricter `generic-secret` policy. No effect unless the generic keyword bridge would otherwise fire |
| `--no-ml` |  |  | Disable ML-based confidence scoring |
| `--no-suppress-test-fixtures` |  |  | Opt out of the bundled test-fixture suppression list. By default keyhog suppresses well-known public demo credentials (Stripe's docs example `sk_live_4eC39...`, GitHub's docs example `ghp_aBcD...`, the keyhog test fixtures, etc.) so the report stays focused on real leaks rather than tutorial copies. Pass this flag when you intentionally want those surfaced. Useful for differential benchmarking against gitleaks / trufflehog (which do NOT suppress these), or for auditing the suppression list itself |
| `--no-unicode-norm` |  |  | Disable Unicode normalization (not recommended) |
| `--no-verify` |  |  | Disable credential verification, overriding `verify = true` in `.keyhog.toml` |
| `--oob-server` | `HOST` | `oast.fun` | Interactsh server for OOB verification. Defaults to projectdiscovery's public collector at `oast.fun`. Use a self-hosted server for sensitive scans; the collector sees correlation IDs and the IPs of services that call back, never the credential itself. Only meaningful with `--verify-oob`; clap rejects the flag without it instead of silently ignoring it (the prior behavior gave false confidence that an override had been applied) |
| `--oob-timeout` | `SECS` | `30` | Per-finding OOB wait timeout in seconds. Detector specs may set their own `timeout_secs`; this value is the global default. The upper bound is max(this value, 120s), so a detector can always wait at least 120s for a delayed webhook even when this default is lower. Lower = faster scans, higher = catches services with delayed webhooks (e.g., queued mail delivery). Requires `--verify-oob` |
| `-o`, `--output` | `OUTPUT` |  | Write findings to file |
| `-p`, `--path` | `PATH` |  | Scan a directory or file |
| `--per-chunk-timeout-ms` | `MS` |  | Hard deadline per chunk scan in milliseconds. Default unset = no operator deadline; decode still has its internal bomb guard |
| `--perf-trace` |  |  | Raise `--profile` to its diagnostic level: add higher-overhead per-pattern, per-decoder, and backend timing traces on stderr |
| `--precision` |  |  | High-precision mode for mass scanning: minimise false positives at the cost of some recall. Disables entropy discovery and the relaxed keyword bridge, retains ML scoring for remaining candidates, raises the minimum confidence floor to 0.85, and uses decode depth 1. Explicit confidence flags may tighten but cannot lower that floor. Entropy-only knobs conflict because precision mode disables entropy |
| `--profile` |  |  | Emit low-overhead stage, resource, build, policy, source, and measured workload identity evidence to stderr at scan end |
| `--profile-out` | `PATH` |  | Write the complete causal scan profile as JSON to `PATH` at scan end. Implies `--profile`; the artifact is written atomically |
| `--progress` |  |  | Show progress bar |
| `--proxy` | `URL` |  | Route outbound HTTP through a proxy (`http://burp:8080`, `socks5://127.0.0.1:9050`, etc.). This flag (or its TOML equivalent) is the ONLY way to set a proxy: no environment variable is consulted, and ambient `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` is ignored, so a stray env proxy can never silently reroute secret-bearing traffic. When unset, no proxy is used. Pass `off` to make that explicit for air-gapped scans |
| `--quiet` |  |  | Suppress the interactive stderr chrome (banner, live progress ticker, and the "Scan complete" summary). Coverage FAIL/WARN lines and fatal errors are still printed so a quiet scan can never read as clean when it was not. Findings still go to stdout / `--output`. Mutually exclusive with `--progress` |
| `--reader-threads` | `N` |  | Dedicated filesystem reader threads. Default is one direct reader |
| `--regex-dfa-limit` | `SIZE` |  | Per-regex lazy-DFA cache CEILING, e.g. "256KB" or "1MB" (default 1 MiB). Bounds the worst-case per-thread DFA cache for pathological/state-heavy patterns; typical detectors stay well under it, so lowering this does NOT meaningfully cut peak memory (it's a safety ceiling, not a general memory lever). Lowering can force complex regexes to slower NFA simulation; raise it only for unusually large patterns. Config: `regex_dfa_limit` in `.keyhog.toml`; this flag overrides it |
| `--require-gpu` |  |  | Require a usable GPU stack before scanning and keep GPU execution as a hard contract; unavailable initialization or runtime dispatch exits 12 |
| `--s3-bucket` | `BUCKET` |  | Scan a public or path-style S3 bucket via ListObjectsV2 |
| `--s3-endpoint` | `URL` |  | Optional S3 endpoint for S3-compatible APIs |
| `--s3-prefix` | `PREFIX` |  | Optional S3 object prefix to limit the scan |
| `--scan-comments` |  |  | Treat credentials inside source-code comments (// … / # … / /* … */ / &lt;!-- … --&gt;) as first-class findings instead of applying the default comment-context confidence penalty. By default keyhog downgrades the confidence of credentials it sees inside a comment because the most common case is an engineer pasting an EXAMPLE token into a doc comment. The drawback is that genuine secrets pasted into a TODO ("rotate this key, Bob") or a debug-trace comment never surface. Pass `--scan-comments` for repos where comments are part of the threat surface: shared snippets directories, leak post-mortems, training corpora, and CTF-style audits. |
| `-s`, `--severity` | `SEVERITY` |  | Min severity to report: info, client-safe, low, medium, high, critical Possible values: `info`, `client-safe`, `low`, `medium`, `high`, `critical`. |
| `--show-secrets` |  |  | Show full credentials (default: redacted) |
| `--source` | `NAME[:PARAMS]` |  | Construct a compiled-in source by canonical name |
| `--stdin` |  |  | Scan stdin |
| `--stream` |  |  | Emit a redacted `[stream]` preview line on stderr for every REPORTED finding (`SEVERITY SERVICE/DETECTOR PATH:LINE redacted`), so a quick human- or CI-scrapeable summary lands on stderr while the full formatted report (text/json/sarif/jsonl) goes to stdout or `--output`. The preview stream is consistent with that report and the exit code: every streamed line corresponds to a finding that survived suppression, the confidence floor / `--min-confidence`, and baseline filtering, it never previews a match the report drops |
| `--threads` | `N` |  | Number of parallel scanning threads (default: number of CPU cores) |
| `--timeout` | `TIMEOUT` |  | Per-request HTTP verification timeout in seconds (default: 5). This does not impose a deadline on scanning; use `--per-chunk-timeout-ms` for the scanner's optional chunk deadline |
| `--update-baseline` | `PATH` |  | Update an existing baseline file with new findings |
| `--url` | `URL...` |  | Scan JavaScript, source maps, or WASM binaries at URLs for secrets |
| `--verify` |  |  | Verify discovered credentials via API calls |
| `--verify-batch` |  |  | Conservative verify mode: serialises live verifications per service (max-concurrent-per-service = 1) on top of the `--verify-rate` cap. Use for repos with lots of legitimate findings (test fixtures, vendored examples) where bursting a provider's auth endpoint would get the scan IP rate-limited or blocked. Implies `--verify` |
| `--verify-concurrency` | `N` |  | Maximum in-flight verification requests per service (default: 5) |
| `--verify-oob` |  |  | Enable out-of-band callback verification via an embedded interactsh client. For webhook- and callback-shaped credentials, OOB verification proves the credential is exfil-capable: we mint a per-finding subdomain on the configured collector, embed it in the verification probe, and confirm the service actually called back. Off by default. See docs/src/reference/oob-verification.md for the threat model and self-hosting guidance |
| `--verify-rate` | `RPS` | `5.0` | Steady-state cap for verification calls *per service*, in requests-per-second. Default 5.0. Drop this to be polite to upstream APIs when scanning a tree with hundreds of legitimate findings (test fixtures, examples); every finding produces a live verify call and most public APIs throttle aggressively. The limiter applies even with `--verify-batch` (which adds per-service serialisation on top) |
<!-- /keyhog-generated: cli-reference command="config" -->

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

<!-- keyhog-generated: cli-reference command="detectors" -->
| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--audit` |  |  | Audit detectors against the quality gate (`keyhog_core::validate_detector`). Prints every issue grouped by detector and exits non-zero (3) if any `Error`-severity issue was found. Warnings are reported but do not fail the run. Pairs with `--detectors <DIR>` for CI gating |
| `-d`, `--detectors` | `DETECTORS` | `detectors` | Detector TOML directory |
| `--dry-run` |  |  | Show the rewrites `--fix` *would* make without writing them. No-op unless `--fix` is also set |
| `--fix` |  |  | Apply safe automated fixes to the detector TOMLs in `--detectors`. Currently rewrites single-brace template references (`{name}`) to the double-brace form (`{{name}}`) within `[detector.verify*]` blocks: the one fix the interpolator's contract makes safe to perform mechanically. Other validator findings are left alone (they need human judgement). Use `--dry-run` to preview rewrites without touching the filesystem |
| `--format` | `FORMAT` |  | Output format for the detector listing. `text` (default) is the grouped, human-readable summary; `json` emits the structured detector array. This is the canonical flag, it matches `scan --format` so the two surfaces share one convention (CLI-01). Only `text`/`json` apply to a detector listing, so the format set is intentionally narrower than `scan`'s. Mutually exclusive with `--audit` / `--fix` (they emit their own structured formats) Possible values: `text`, `json`. |
| `--mechanisms` |  |  | Print the generated mechanism manifest: which recovery mechanisms each detector actually declares. KeyHog advertises regex matching, structural validation, entropy scoring, BPE token efficiency, decode recovery, companion confirmation, live verification, and detector-owned suppression, but nothing in the product will tell you which of those a given detector uses. This does, and it derives every answer from the loaded corpus: each mechanism is a predicate over detector TOML fields and the field that made it active is reported as its evidence, so there is no per-detector table in Rust to drift. A mechanism KeyHog cannot express yet is reported as unavailable with the reason rather than omitted, because a missing row cannot be told apart from "no detector uses this". Pairs with `--search` to scope the manifest, and with `--format json` for the machine-readable document. Does not scan. |
| `-s`, `--search` | `SEARCH` |  | Filter detectors by substring match (case-insensitive) against id, name, service, and keywords. Useful for finding detectors in the 926-strong corpus (e.g. `keyhog detectors --search aws`). |
| `-v`, `--verbose` |  |  | Print the matching-policy summary (regexes, keywords, companions, verification presence) instead of the grouped service summary. Pairs naturally with `--search`. Use `--format json` for the redaction-safe declared schema, including verification structure and test coverage |
<!-- /keyhog-generated: cli-reference command="detectors" -->

## `keyhog explain <DETECTOR_ID>`

Explain the loaded detector. Includes keywords, patterns, companion rules,
verification endpoint, and detector-owned entropy/BPE/length/suppression
policy. Use `--compiled-plan` to print resolved companion and cross-detector
evidence operations.

```sh
keyhog explain stripe-secret-key
```

<!-- keyhog-generated: cli-reference command="explain" -->
| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `<DETECTOR_ID>` *(required)* | `DETECTOR_ID` |  | Detector ID to explain (e.g. `aws-access-key`, `github-pat-fine-grained`). Use `keyhog detectors` to list available IDs |
| `--bloom-evidence` | `PATH` |  | Read a `bloom-evidence-v1` receipt produced by `keyhog bloom-diagnostic`. The receipt must match the selected detector corpus and prove exact enabled-versus-bypassed finding parity |
| `--compiled-plan` |  |  | Print the detector's compiled evidence plan, including resolved capture groups, direction, structural scope, and admission semantics |
| `-d`, `--detectors` | `DETECTORS` | `detectors` | Detector TOML directory. When omitted, KeyHog discovers an installed corpus or uses the embedded corpus. An explicitly named missing path is an error |
<!-- /keyhog-generated: cli-reference command="explain" -->

## `keyhog guard <add|remove|up|down|list|status|reconcile|rebuild>`

Manages perpetual repository and filesystem guard protection. Connects to
the daemon and sends guard control frames. When no daemon is available,
reports that clearly instead of silently doing nothing.
The command requires the Unix daemon transport and exits unsupported on Windows.

<!-- keyhog-generated: cli-reference command="guard" -->
| Subcommand | Aliases | Description |
|------------|---------|-------------|
| `add` |  | Register a repository or filesystem root for continuous guard protection. Waits for initial reconciliation to complete before returning. When guarding a Git repository in `repo` mode, also attempts to install the managed pre-commit hook (skipped if a foreign hook already exists, or if `--no-hook` is passed) |
| `down` |  | Stop the background guard daemon cleanly. Persisted root registrations and durable indexes remain on disk and resume on the next `guard up` |
| `help` |  | Print this message or the help of the given subcommand(s) |
| `list` |  | List all registered guard roots and their current states |
| `rebuild` |  | Delete and recreate the durable guard store for a root. Use after store corruption or when the persisted state is irrecoverably stale. The root is re-registered and a full reconciliation is triggered |
| `reconcile` |  | Force a full reconciliation of a guarded root after an intentional policy or filesystem change |
| `remove` |  | Stop protecting a root and remove its persisted non-secret state. Also removes any KeyHog-owned Git pre-commit hook unless `--keep-hook` is passed |
| `status` |  | Print the exact state and current policy identity of a guarded root |
| `up` |  | Start or ensure the background guard daemon is running and ready. When the daemon is already running, reports that it is active. Reconciles registered roots loaded from the durable store |

### `keyhog guard add`

| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `<ROOT>` *(required)* | `ROOT` |  | Root path to guard |
| `--mode` | `MODE` | `repo` | Guard mode: `repo` uses Git object IDs for exact staged-content identity; `filesystem` uses content hashes without immutable Git OIDs |
| `--no-hook` |  |  | Do not install or update the Git pre-commit hook during registration |
| `--socket` | `PATH` |  | Override the socket path |

### `keyhog guard down`

| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--socket` | `PATH` |  | Override the socket path |

### `keyhog guard help`

*No arguments.*

### `keyhog guard list`

| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--socket` | `PATH` |  | Override the socket path |

### `keyhog guard rebuild`

| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `<ROOT>` *(required)* | `ROOT` |  | Root path to rebuild |
| `--mode` | `MODE` | `repo` | Guard mode: `repo` or `filesystem`. Defaults to `repo` |
| `--socket` | `PATH` |  | Override the socket path |

### `keyhog guard reconcile`

| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `<ROOT>` *(required)* | `ROOT` |  | Root path to reconcile |
| `--socket` | `PATH` |  | Override the socket path |

### `keyhog guard remove`

| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `<ROOT>` *(required)* | `ROOT` |  | Root path to unguard |
| `--keep-hook` |  |  | Keep the Git pre-commit hook in place when unregistering |
| `--socket` | `PATH` |  | Override the socket path |

### `keyhog guard status`

| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `<ROOT>` *(required)* | `ROOT` |  | Root path to inspect |
| `--format` | `FORMAT` | `human` | Output format: `human` or `json` |
| `--socket` | `PATH` |  | Override the socket path |

### `keyhog guard up`

| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--backend` | `BACKEND` |  | Force a specific scan backend (default `auto` uses autoroute) |
| `--socket` | `PATH` |  | Override the socket path |

<!-- /keyhog-generated: cli-reference command="guard" -->

## `keyhog watch [PATH]...`

Foreground subcommand that watches one or more directories for file changes
and re-scans each changed file. Useful for IDE-side feedback. It does not
connect to or appear in `keyhog daemon status`; the independent `keyhog daemon`
is a Unix-socket service used only by eligible `keyhog scan --daemon` requests.
Pass several roots to monitor them with a single watcher; nested or
duplicate roots fold into their covering parent, mirroring `keyhog scan`.
Every root must be a directory. The scanner and selected backend stay warm:
automatic routing consumes the persisted warm-runtime decision for each exact
single-file workload, while `--backend` remains a diagnostic override.

```sh
keyhog watch src/                 # watch the source tree
keyhog watch src/ config/         # watch several roots in one process
keyhog watch                      # watch the current directory
```

<!-- keyhog-generated: cli-reference command="watch" -->
| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `<PATH>` | `PATH...` | `.` | Director(ies) to watch recursively. Pass several to monitor multiple roots in one foreground watcher (`keyhog watch src/ config/`); nested or duplicate roots fold into their covering parent, mirroring `keyhog scan`. Each root must be a directory. Defaults to the current directory |
| `--backend` | `BACKEND` |  | Select persisted autoroute or explicitly force one diagnostic backend. Accepted values are listed below. Without valid installer calibration, change scans fail closed without scanning Possible values: `auto`, `gpu-cuda`, `gpu-cuda-region-presence`, `gpu-metal`, `gpu-metal-region-presence`, `gpu-wgpu`, `gpu-wgpu-region-presence`, `simd`, `simd-regex`, `cpu`, `cpu-fallback`. |
| `--cache-dir` | `DIR` |  | Override the Hyperscan compiled-database cache directory |
| `-d`, `--detectors` | `DETECTORS` | `detectors` | Detector TOML directory. When omitted, KeyHog discovers an installed corpus or uses the embedded corpus. An explicitly named missing path is an error |
| `--max-consecutive-failures` | `N` | `8` | Exit after this many consecutive per-file scan engine failures so a wedged scanner cannot silently drop secrets under editor saves (KH-1334 / KH-1462). Default 8 |
| `--max-file-size` | `BYTES` |  | Maximum bytes per changed file (same default as `keyhog scan`, 100 MiB). Pass `0` to use the built-in default. Oversized editor saves are skipped with a loud error rather than OOM-ing the single-threaded watcher (KH-1461) |
| `--quiet` |  |  | Quiet mode: only print findings (suppress "watching X" status) |
<!-- /keyhog-generated: cli-reference command="watch" -->

## `keyhog hook <install|uninstall>`

Manages the git pre-commit hook. See
[Pre-commit hook](../workflows/precommit.md) for usage.

<!-- keyhog-generated: cli-reference command="hook" -->
| Subcommand | Aliases | Description |
|------------|---------|-------------|
| `help` |  | Print this message or the help of the given subcommand(s) |
| `install` |  | Install a git pre-commit hook in the current repository |
| `uninstall` |  | Remove the KeyHog pre-commit hook from the current repository |

### `keyhog hook help`

*No arguments.*

### `keyhog hook install`

| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--force` |  |  | Replace an existing non-KeyHog pre-commit hook |

### `keyhog hook uninstall`

*No arguments.*

<!-- /keyhog-generated: cli-reference command="hook" -->

## `keyhog daemon <start|stop|status>` (Unix only)

The optional foreground daemon holds a compiled scanner for repeated eligible
stdin and single-file scans.

<!-- keyhog-generated: cli-reference command="daemon" -->
| Subcommand | Aliases | Description |
|------------|---------|-------------|
| `help` |  | Print this message or the help of the given subcommand(s) |
| `start` |  | Start a daemon process that holds a compiled scanner and serves scan requests over a Unix socket. Blocks until `daemon stop` is invoked |
| `status` |  | Print uptime, scans served, active scans, detector count, and backend policy |
| `stop` |  | Stop the running daemon by sending it a `Shutdown` over the socket |

### `keyhog daemon help`

*No arguments.*

### `keyhog daemon start`

| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--backend` | `BACKEND` |  | Force a daemon scan backend instead of using persisted autoroute. The default `auto` mode requires persisted calibration. Missing or invalid evidence prevents readiness. Use an explicit backend only for diagnostics and hermetic daemon tests. Possible values: `auto`, `gpu-cuda`, `gpu-cuda-region-presence`, `gpu-metal`, `gpu-metal-region-presence`, `gpu-wgpu`, `gpu-wgpu-region-presence`, `simd`, `simd-regex`, `cpu`, `cpu-fallback`. |
| `--cache-dir` | `DIR` |  | Override the Hyperscan compiled-database cache directory |
| `--detectors` | `DETECTORS` | `detectors` | Detector directory (same default as `keyhog scan --detectors`) |
| `--mass` |  |  | Enable bounded directory, Git, archive, binary, remote, and cloud batches from `keyhog scan --daemon=mass`. Warm one-file requests remain available on the same socket |
| `--mass-gpu-primary` |  |  | Require each completed mass transaction to prove that GPU processed more than half of all non-empty payload bytes. The client validates the terminal receipt and fails instead of accepting CPU-majority work |
| `--request-timeout-secs` | `SECS` | `300` | Max seconds a client connection may sit without completing one request frame before the daemon closes it and reclaims the slot |
| `--socket` | `PATH` |  | Override the default socket path. KeyHog otherwise uses $XDG_RUNTIME_DIR/keyhog.sock, then the OS user-cache directory, then the OS temporary directory. A daemon started here is reachable by `daemon stop`/`status --socket` AND by scans via `keyhog scan --daemon --daemon-socket <same path>`. Pass the matching path so a fixed-location daemon (e.g. a systemd unit) actually serves scans, not just admin commands. |

### `keyhog daemon status`

| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--socket` | `PATH` |  | *No description.* |

### `keyhog daemon stop`

| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--socket` | `PATH` |  | *No description.* |

<!-- /keyhog-generated: cli-reference command="daemon" -->

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

Artifact-only options are rejected during baseline comparison. Binary inputs
must use `keyhog scan --binary`; artifact diff never decodes them implicitly.

<!-- keyhog-generated: cli-reference command="diff" -->
| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `<BEFORE>` *(required)* | `BEFORE` |  | Baseline file A, or the older artifact when --artifacts is set |
| `<AFTER>` *(required)* | `AFTER` |  | Baseline file B, or the newer artifact when --artifacts is set |
| `--artifacts` |  |  | Scan the two inputs as artifacts instead of loading baseline JSON |
| `--detectors` | `DETECTORS` |  | Detector TOML directory used by --artifacts (default: auto-discover) |
| `--hide-unchanged` |  |  | Suppress the `UNCHANGED` section (default: shown) |
| `--json` |  |  | Emit results as JSON instead of human-readable text. Useful for CI that wants to gate merges on regressions programmatically |
| `--max-artifact-bytes` | `MAX_ARTIFACT_BYTES` |  | Maximum bytes read from each artifact (default: 67108864) |
| `--verify-removed` |  |  | Verify credentials found only in the older artifact |
| `--verify-timeout` | `VERIFY_TIMEOUT` |  | Per-credential verification timeout in seconds (default: 5) |
<!-- /keyhog-generated: cli-reference command="diff" -->

## `keyhog triage`

Import a current versioned redacted finding envelope and write separate
runtime-suppression and pattern-training artifacts. Every record must carry the
scanner's exact public `evidence.provenance` object. Provenance binds the
16-hex active detector digest, nullable pattern index, candidate channel,
source role, and context class. The input accepts stable detector IDs and
BLAKE3 finding/context/scope identities only. It rejects unknown fields, stale
detector or pattern identities, free-form reasons, raw paths, raw context, and
credential values.

```sh
keyhog triage \
  --input findings.redacted.json \
  --suppressions suppressions.json \
  --pattern-feedback pattern-feedback.json
```

On Unix, the command creates new regular files with private permissions through
held no-follow parent-directory descriptors. Input reads and failed-output
cleanup use the same descriptor-relative boundary, so parent replacement cannot
redirect the operation. Input and output paths must be distinct and cannot use
symbolic links or parent components. Existing output files are not overwritten.
Windows builds fail before reading the envelope until equivalent held-handle,
reparse-point-safe I/O is available.

Scopes are `exact`, `path`, `repository`, and `pattern-feedback-only`. Path and
repository scopes carry BLAKE3 identities, not names or filesystem locations.
Only dismissed `exact`, `path`, and `repository` records produce immediate
runtime suppressions. Every validated record produces pattern feedback.
`pattern-feedback-only` can never produce runtime suppression.

<!-- keyhog-generated: cli-reference command="triage" -->
| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--input` *(required)* | `PATH` |  | Current versioned redacted finding envelope |
| `--pattern-feedback` *(required)* | `PATH` |  | New file for pattern-training feedback |
| `--suppressions` *(required)* | `PATH` |  | New file for immediate scoped runtime suppressions |
<!-- /keyhog-generated: cli-reference command="triage" -->

## `keyhog calibrate`

Show or update the per-detector Bayesian (Beta-α/β) calibration
counters. Used to teach the scorer that detector X has produced N
true positives and M false positives in your environment. Scans use the
counters only when `--calibration-cache <PATH>` or
`[system].calibration_cache` explicitly points at the file.

```sh
keyhog calibrate --show                       # print current counters
keyhog calibrate --tp aws-access-key          # record one TP
keyhog calibrate --fp generic-api-key         # record one FP
```

Pass `--cache <PATH>` to point at a non-default counter file (the
default lives under the platform cache directory, normally
`$XDG_CACHE_HOME/keyhog/calibration.json`). Existing corrupted or
schema-incompatible cache files fail closed and are not overwritten.

<!-- keyhog-generated: cli-reference command="calibrate" -->
| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--cache` | `PATH` |  | Override the calibration cache path. Defaults to $XDG_CACHE_HOME/keyhog/calibration.json |
| `--fp` | `DETECTOR_ID` |  | Mark these detector IDs as confirmed false positives (β += 1 each) |
| `--show` |  |  | Print every recorded counter and exit (no updates). Read-only: it cannot be combined with the `--tp`/`--fp` update flags (mixing "show me the state" with "mutate the state" is contradictory and silently ran the update before (clap now rejects it with exit 2)) |
| `--tp` | `DETECTOR_ID` |  | Mark these detector IDs as confirmed true positives (α += 1 each). Use `--tp` repeatedly: `--tp aws-access-key --tp github-pat-fine-grained` |
<!-- /keyhog-generated: cli-reference command="calibrate" -->

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
calibration must persist its result. `--policy <default|fast|deep|precision|all>`
selects the policy to refresh. It defaults to `all` for the complete install
sweep. `--quiet` suppresses per-probe progress but still prints the final
summary.
Statistically overlapping route timings are inconclusive: the command exits 2
and publishes no generation rather than selecting an unproved winner. Rerun
`keyhog calibrate-autoroute` on an idle host. An explicit `--backend` is only a
diagnostic override and does not replace autoroute evidence.


<!-- keyhog-generated: cli-reference command="calibrate-autoroute" -->
| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--autoroute-cache` | `PATH` |  | Override the persistent autoroute cache file every probe writes to. Must be a writable path. Calibration exists to PERSIST routing decisions, so `off` (which disables persistence) is rejected up front rather than failing every probe closed. Defaults to the same cache a normal scan reads, so a plain `keyhog calibrate-autoroute` primes exactly what later scans resolve against. |
| `--execution-packs` | `DIR` |  | Bind persisted route evidence to this authenticated execution-pack generation. Calibration binds to the authenticated generation in the platform cache directory on its own, so an ordinary install needs no flag. Name a directory only to bind against a generation that lives elsewhere; it fails closed when the directory does not authenticate. |
| `--measurement-receipts` *(hidden)* | `PATH` |  | Internal receipt sink used by the all-policy parent transaction |
| `--no-config` |  |  | Calibrate the compiled-in defaults instead of the repository config. Routing decisions are stored under the RESOLVED scan configuration, so calibration must resolve the same `.keyhog.toml` walk-up the scans that follow it resolve. Skipping the file writes every decision under a digest no scan in that repository requests, and the next `keyhog scan` fails closed with "none matching config digest". Pass this to prime a host baseline that is independent of whatever directory calibration ran in. Installers do exactly that, and an operator whose repository carries a `.keyhog.toml` reruns the bare command inside the repository. |
| `--policy` | `POLICY` | `all` | Select which scan policy to calibrate. `all` preserves the install-time sweep. Select one policy when you need to repair or refresh only the configuration you run. Possible values: `default`, `fast`, `deep`, `precision`, `all`. |
| `--quiet` |  |  | Suppress the per-probe progress lines; print only the final summary |
<!-- /keyhog-generated: cli-reference command="calibrate-autoroute" -->

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
autoroute. On an eligible GPU host, `--self-test` reports two VYRE-owned probes:
`vyre_literal_set` for the direct match-triple diagnostic and
`gpu_region_presence` for the production scan route. The production probe owns
scan eligibility. A direct-mode limitation is reported as `known` when
classified and `warning` otherwise, but only a production-path or required GPU
capability failure makes the health report fail.
When no eligible physical GPU exists, the normal self-test emits one `gpu_adapter` probe with status
`skip` and exits `0`; `--require-gpu` changes that probe to `fail` and exits
`4`. `--no-gpu` explicitly requests the skip without initializing a GPU.
The JSON report lists `healthy_gpu_backends` and sets `route_selection` to
`not_measured`. A health probe does not recommend a route. Use
`keyhog backend --autoroute` to inspect persisted measured evidence.
`--json` is available for self-test
and autoroute inspection output. A failed self-test emits the complete report
and exits `4`. An explicit or required GPU scan whose route fails exits `12`;
a normal automatic scan reports stable-input recovery when it can preserve full
coverage.

<!-- keyhog-generated: cli-reference command="backend" -->
| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--autoroute` |  |  | Inspect the persisted autoroute calibration cache: which resolved scan configs and workload buckets have a fastest-correct backend decision, the cold-aware one-shot and warm-daemon routes, confidence basis, and whether the cache is stale for this build. Read-only; pairs with `--json`. Use this to diagnose an "autoroute calibration required" routing error and identify the exact unproved workload bucket |
| `--autoroute-cache` | `PATH\|off` |  | Inspect this explicit autoroute cache file instead of the platform default. Use the same absolute path passed to `scan --autoroute-cache` or configured as `[system].autoroute_cache`; `off` inspects the disabled state |
| `--json` |  |  | Emit `backend --self-test` or `backend --autoroute` as stable JSON for CI health gates / scripted inspection |
| `--no-gpu` |  |  | Disable GPU probing for backend inspection/self-test |
| `--patterns` | `PATTERNS` |  | Compiled pattern count to use for the routing-simulation matrix. This is a what-if knob: it does not change the loaded corpus, only the pattern_count fed to the backend-routing thresholds so you can probe how a larger/smaller corpus would route. Omit it to use the live compiled embedded corpus |
| `--probe-bytes` | `PROBE_BYTES` |  | Probe the workload size in the diagnostic hardware heuristic matrix. This does not predict `scan --backend auto`, which uses persisted fastest-correct calibration evidence |
| `--require-gpu` |  |  | Fail closed when backend self-test cannot use a real GPU |
| `--self-test` |  |  | Run the GPU self-tests (MoE compute kernel + VYRE direct-match diagnostic + production region-presence dispatch). Prints PASS/FAIL with adapter info and exits with code 4 on failure so CI can gate a release on real GPU functionality. Reports SKIP and exits zero without a non-software adapter unless --require-gpu is set |
| `--verbose` |  |  | Include every workload decision and parity receipt in human-readable autoroute inspection. The default view is a concise health and route summary; `--json` remains the complete machine-readable representation |
<!-- /keyhog-generated: cli-reference command="backend" -->

## `keyhog bloom-diagnostic`

Measure the production Bloom gate on a benchmark-owned corpus fixture.
This command emits a `bloom-evidence-v1` receipt that proves enabled-versus-bypassed
finding parity for a given detector corpus; `keyhog explain --bloom-evidence` and
`keyhog doctor --bloom-evidence` consume that receipt.

<!-- keyhog-generated: cli-reference command="bloom-diagnostic" -->
| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--corpus-root` *(required)* | `PATH` |  | Root directory used to resolve fixture-relative corpus paths |
| `--fixture` *(required)* | `PATH` |  | JSON fixture naming the corpus and its exact negative input files |
<!-- /keyhog-generated: cli-reference command="bloom-diagnostic" -->

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

<!-- keyhog-generated: cli-reference command="scan-system" -->
| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--cache-dir` | `DIR` |  | Override the Hyperscan compiled-database cache directory |
| `--detectors` | `DETECTORS` | `detectors` | Detector directory (same as `keyhog scan --detectors`) |
| `--include-network` |  |  | Include network-mounted filesystems (NFS, SMB, sshfs). Off by default; these are typically slow and contain other people's secrets the user hasn't authorized scanning |
| `--lockdown` |  |  | Apply hardening protections (mlocked + coredump-blocked) and refuse the operations that weaken detection or expand attack surface. See `keyhog scan --lockdown` for the full list |
| `--no-git-history` |  |  | Skip auto-discovery of `.git` directories. By default scan-system finds every git repo on every walked drive and runs --git-history on each, including bare repos and submodules. Disable to save time when you only care about working-tree state |
| `--output` | `OUTPUT` |  | Output JSON path. Defaults to stderr (text format) if unset |
| `--respect-gitignore` |  |  | Honor `.gitignore` like `keyhog scan` does. Default OFF; system scans are paranoid because an attacker stashing a leaked key would `.gitignore` it. Set this to behave like a normal scan |
| `--space` | `SPACE` | `50G` | Hard ceiling on total bytes scanned. Walker tracks running total and stops when the next file would push past this. Examples: --space 50G --space 1T --space 500M Default 50 GiB; enough to cover most home directories without drowning the scan on a NAS-mount |
| `--threads` | `N` |  | Number of parallel scanning threads (default: number of CPU cores) |
<!-- /keyhog-generated: cli-reference command="scan-system" -->

`--threads` configures a process-global Rayon pool. Reusing the same width in
one process is supported when KeyHog created the pool. An externally initialized
pool is rejected even at the requested width because its stack size, naming,
and ownership cannot be attested. A different live width is also an
operator-visible error. Effective config and autoroute identity record the
actual KeyHog-owned width.

`scan-system` always runs its own in-process scanner, whether the daemon is
active or inactive. It uses persisted autoroute evidence and has no explicit
backend override. Missing, stale, or incomplete evidence selects no backend for
the affected batch; the report records partial coverage and names the required
calibration.

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

<!-- keyhog-generated: cli-reference command="completion" -->
| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `<SHELL>` *(required)* | `SHELL` |  | Shell to generate completions for Possible values: `bash`, `elvish`, `fish`, `powershell`, `zsh`. |
<!-- /keyhog-generated: cli-reference command="completion" -->

## Install maintenance

### `keyhog doctor`

<!-- keyhog-generated: cli-reference command="doctor" -->
| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--autoroute-cache` | `PATH\|off` |  | Inspect this explicit autoroute cache file instead of the platform default. Use the same absolute path passed to `scan --autoroute-cache` or configured as `[system].autoroute_cache`; `off` inspects the disabled state. Without it, doctor reports the platform-default cache, which is not the file a project-configured scan uses |
| `--bloom-evidence` | `PATH` |  | Read a `bloom-evidence-v1` receipt produced by `keyhog bloom-diagnostic`. The receipt must match this binary's detector corpus and prove exact enabled-versus-bypassed finding parity |
<!-- /keyhog-generated: cli-reference command="doctor" -->

### `keyhog uninstall`

<!-- keyhog-generated: cli-reference command="uninstall" -->
| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--yes` |  |  | Actually remove the binary. Without this, uninstall is a safe dry run that only reports what would be removed |
<!-- /keyhog-generated: cli-reference command="uninstall" -->

Linux uses one GPU-capable artifact that probes CUDA and WGPU at runtime, so
`uninstall` has no backend or artifact-variant selector.

There is no `keyhog update` or `keyhog repair`. KeyHog has no self-update
path: automatic releases publish crates.io packages only, and no workflow
builds, signs, or uploads release binaries. Update and repair the same way you
installed, with `cargo install --locked --force keyhog`. See
[Install](../install.md).

## Root options

These are root-command options. `--version` and `--full` are not scan flags;
they print identity information and exit. Each subcommand also has its own
`--help`.

<!-- keyhog-generated: cli-reference command="" -->
| Argument | Value | Default | Description |
|----------|-------|---------|-------------|
| `--full` |  |  | Include the hardware probe in version output. This initializes GPU/SIMD discovery, so it is explicit instead of controlled by ambient env |
| `-h`, `--help` |  |  | Print help |
| `-V`, `--version` |  |  | Print version, build information, and statistics |
<!-- /keyhog-generated: cli-reference command="" -->

Display controls are command-specific: `scan --no-color` disables report and
summary ANSI output, while `detectors --verbose` prints matching-policy
summaries. Use `detectors --format json` for the complete detector schema.
