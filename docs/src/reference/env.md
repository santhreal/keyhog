# Environment variables

KeyHog deliberately reads **almost no** environment variables, and **none** that
change how a scan behaves. Detection, routing, suppression, limits, output, and
every other knob come from exactly two places:

1. compiled defaults, overridden by
2. a single `.keyhog.toml` (see [Configuration](./configuration.md)),

with **CLI flags** as the per-invocation override on top. There is no
`KEYHOG_*` behavior knob and no environment override tier, so the same repo
scans identically on every machine, regardless of shell profile or CI
environment. A CI gate (`production_env_reads_stay_on_the_allowlist`) fails the
build if shipped code reads any environment variable outside the small allowlist
documented below.

The only environment variables KeyHog reads fall into three groups: the install
scripts, OS/terminal standards, and cloud-provider credentials used purely for
authentication.

## Install scripts (`install.sh` / `install.ps1`)

These are read by the installer, not by the scanner.

| Variable          | Default                                                  | Effect |
|-------------------|----------------------------------------------------------|--------|
| `KEYHOG_VERSION`  | (latest release)                                          | Pin the install to a specific release tag instead of latest. |
| `GITHUB_TOKEN`    | (unset)                                                  | Optional token for the fallback GitHub releases API lookup only; the default latest-asset redirect path does not use it. |

## OS / terminal standards

| Variable          | Default       | Effect |
|-------------------|---------------|--------|
| `NO_COLOR`        | (unset)       | Honored per [no-color.org](https://no-color.org): if set, all ANSI styling is disabled. |
| `TERM`, `COLORTERM` | (set by terminal) | Read only to detect terminal color capability for the human reporter. |
| `PATH`            | (OS)          | Used when locating trusted system binaries (KeyHog never trusts a bare `PATH` lookup for credential-handling tools; see the safe-binary resolver). |
| `XDG_RUNTIME_DIR` | (login session) | Preferred Unix daemon socket location: `$XDG_RUNTIME_DIR/keyhog.sock`. Without it, KeyHog uses the OS user cache directory (`~/.cache/keyhog/server.sock` on Linux or `~/Library/Caches/keyhog/server.sock` on macOS), then the OS temporary directory plus `keyhog/server.sock` when no cache directory is available. The exact path is overridable per process with `daemon start/stop/status --socket` and `scan --daemon-socket`; there is no `KEYHOG_*` socket environment variable. |
| `RUST_LOG`        | `keyhog=warn` | Tracing filter. `keyhog=debug` for verbose detector/suppression telemetry; `keyhog::routing=trace` for per-chunk backend selection. |
| `RUST_BACKTRACE`  | (unset)       | Standard Rust backtrace control on panic (`1` short, `full` full). |

## Cloud-provider credentials (authentication only)

Read only to authenticate to the matching cloud API for a remote-source scan.
They never alter detection, and they are never forwarded to a non-matching
custom endpoint without an explicit opt-in flag.

| Variable | Effect |
|----------|--------|
| `KEYHOG_GITHUB_TOKEN` | GitHub PAT read only when `--github-org` or `--github-collaboration` explicitly selects a GitHub scan. Preferred over putting `--github-token` in the process arguments. |
| `KEYHOG_GITLAB_TOKEN` | GitLab PAT read only when `--gitlab-group` explicitly selects a group scan. |
| `KEYHOG_BITBUCKET_USERNAME`, `KEYHOG_BITBUCKET_TOKEN` | Bitbucket Cloud identity read only when `--bitbucket-workspace` explicitly selects a workspace scan. |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`, `AWS_DEFAULT_REGION` | SigV4 signing for S3 `ListObjectsV2` / object GET against AWS-owned endpoints. |
| `GOOGLE_OAUTH_ACCESS_TOKEN`, `GCS_BEARER_TOKEN` | Bearer token for `--gcs-bucket` JSON-API listing/downloads (the Google token wins when both are set). |

Repository-collection scope is CLI-only. The dedicated credential variables
above authenticate only an explicitly selected `--github-org`,
`--github-collaboration`, `--gitlab-group`, or `--bitbucket-workspace` source.
They never register a source by themselves.
Token flags remain available for controlled diagnostics, but CI and shell
workflows should inject the dedicated variables through their secret store so
credentials do not appear in process arguments.

## Removed behavior environment controls

Every behavior/config KeyHog-owned environment variable was removed. Its setting
now lives in `.keyhog.toml` or a CLI flag, and retired variable names are
intentionally absent from this reference so they cannot be mistaken for live
controls. The common replacements are:

| Need | Now set via |
|------|-------------|
| Backend override | `--backend <auto\|gpu\|simd\|cpu>` |
| GPU routing requirement or disablement | `--require-gpu`, `--no-gpu`, or `[system].gpu = "required"` / `"off"` |
| Direct diagnostic calibration GPU control | `--autoroute-gpu`, `--no-autoroute-gpu`, or `[system].autoroute_gpu`; canonical `keyhog calibrate-autoroute` measures all eligible peers |
| Scanner concurrency and per-chunk limits | `--threads` plus `[scan].threads`, `reader_threads`, `per_chunk_timeout_ms`, `fused_batch`, and `fused_depth` |
| Detector directory | `--detectors` or top-level `detectors` |
| Cache and trusted binary roots | `[system].cache_dir`, `[system].autoroute_cache`, and `[system].trusted_bin_dirs` |
| Detection tuning | `[tuning]` |
| AWS canary and knockoff account lists | `[aws] canary_accounts` / `knockoff_accounts` |
| Verifier/source proxy and lab TLS override | `--proxy <URL>`, `[http] proxy`, `--insecure`, or `[http] insecure_tls` |
| Dogfood capture | `--dogfood` |

Autoroute calibration is explicit and persistent. The installer runs a visible
calibration phase, and `keyhog scan --autoroute-calibrate` is the scan-owned
calibration entry point for writing parity-checked fastest-correct decisions.
Normal scans never benchmark on cache miss; they require a valid persisted
decision or an explicit diagnostic `--backend` override.

See [Configuration](./configuration.md) for the full `.keyhog.toml` schema.

## Precedence

For any setting, the highest source present wins:

1. CLI flag (e.g. `--proxy http://a`)
2. `.keyhog.toml` (discovered at the scan root, or `--config <path>`)
3. compiled default

Environment variables are **not** in this list for behavior, by design.

## What KeyHog deliberately does NOT read

- Any `KEYHOG_*` knob that changes detection, routing, suppression, output, or
  configuration. Tuning is `.keyhog.toml`-only so a scan reproduces across
  machines without environment contamination.
- No proxy or TLS environment variable participates in verification or HTTP
  source routing: ambient `HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` are neutralized,
  and removed KeyHog-owned TLS/proxy controls such as `KEYHOG_INSECURE_TLS` are
  ignored. Use `--proxy`, `[http] proxy`, `--insecure`, or
  `[http] insecure_tls` explicitly.
- Unscoped forge tokens or source-selecting variables (`SLACK_TOKEN`,
  `S3_BUCKET`, etc.). Hosted Git credentials use only the dedicated variables
  listed above and only after the matching source flag is present.
- Anything named `KEYHOG_API_KEY` / `KEYHOG_TOKEN` / `KEYHOG_TELEMETRY_*`. There
  is no telemetry and no service to authenticate to; findings stay local.
