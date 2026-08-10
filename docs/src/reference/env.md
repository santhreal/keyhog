# Environment variables

KeyHog keeps scan policy out of the environment. Detection, suppression,
routing, limits, and output are resolved in this order:

1. a CLI flag;
2. `.keyhog.toml`, discovered from the scan root or selected with `--config`;
3. the compiled default.

Environment variables authenticate an explicitly selected remote source,
control standard terminal diagnostics, or help the operating system choose a
runtime directory. They do not select a source or change detector policy.

Backend selection has no environment override. Use `--backend auto`,
`--backend cpu` (`cpu-fallback`), `--backend simd` (`simd-regex`),
`--backend gpu-cuda` (`gpu-cuda-region-presence`), or `--backend gpu-wgpu`
(`gpu-wgpu-region-presence`).

For example, keep a GitHub token out of the process arguments:

```sh
KEYHOG_GITHUB_TOKEN="$GITHUB_TOKEN" \
  keyhog scan --github-org example-org
```

Setting `KEYHOG_GITHUB_TOKEN` without `--github-org` or
`--github-collaboration` does not add a GitHub source.

## Direct reads in the release binary

The production-source gate
`production_env_reads_stay_on_the_allowlist` restricts direct Rust environment
reads to the names and owners below.

### Terminal, diagnostics, and daemon paths

| Variable | Read by | Effect |
|---|---|---|
| `NO_COLOR` | CLI style layer | A present, non-empty value disables ANSI styling. An empty `NO_COLOR=` does not. |
| `RUST_LOG` | tracing subscriber | Selects diagnostic log filters. The built-in directive is `keyhog=warn`. This changes diagnostics, not findings. |
| `RUST_BACKTRACE` | Rust runtime | Enables panic backtraces according to the standard Rust runtime rules. |
| `PATH` | `keyhog doctor` | Checks whether the installed KeyHog directory is on `PATH` and whether another `keyhog` shadows it. Scan subprocesses use the trusted-binary resolver rather than a bare `PATH` lookup. |
| `XDG_RUNTIME_DIR` | Unix daemon socket resolver | Uses `$XDG_RUNTIME_DIR/keyhog.sock` when set. |

Without `XDG_RUNTIME_DIR`, the Unix daemon uses the platform cache directory
plus `keyhog/server.sock`. If no cache directory is available, it uses the
platform temporary directory plus `keyhog/server.sock`. Override this per
process with `daemon start/stop/status --socket` and `scan --daemon-socket`.

### Remote-source credentials

These variables are read only after the matching source flag has selected a
remote source. A CLI credential flag takes precedence over its hosted-source
environment variable.

| Variable | Selected source and behavior |
|---|---|
| `KEYHOG_GITHUB_TOKEN` | `--github-org` or `--github-collaboration`; GitHub personal access token. |
| `KEYHOG_GITLAB_TOKEN` | `--gitlab-group`; GitLab personal access token. |
| `KEYHOG_BITBUCKET_USERNAME` | `--bitbucket-workspace`; Bitbucket Cloud username. |
| `KEYHOG_BITBUCKET_TOKEN` | `--bitbucket-workspace`; Bitbucket app password or token. |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | `--s3-bucket`; both must be present for SigV4 authentication. If only one is present, the source fails instead of sending an unsigned request. |
| `AWS_SESSION_TOKEN` | `--s3-bucket`; optional temporary-credential token. |
| `AWS_REGION`, `AWS_DEFAULT_REGION` | `--s3-bucket`; signing region. `AWS_REGION` wins, then `AWS_DEFAULT_REGION`, then endpoint inference, then `us-east-1`. |
| `GOOGLE_OAUTH_ACCESS_TOKEN`, `GCS_BEARER_TOKEN` | `--gcs-bucket`; bearer token. `GOOGLE_OAUTH_ACCESS_TOKEN` wins when both are set. |

Ambient AWS credentials are not forwarded to a non-AWS S3 endpoint without the
explicit credential-forwarding flag. Proxy and TLS behavior also remain
explicit. `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` do not route KeyHog
verification or HTTP source requests. Use `--proxy`, `[http] proxy`,
`--insecure`, or `[http] insecure_tls`.
KeyHog deliberately does NOT read `KEYHOG_INSECURE_TLS`.
No proxy or TLS environment variable participates in routing or certificate
policy.

## Platform directory discovery

KeyHog also uses the `dirs` crate and the standard temporary-directory API.
These APIs can consult platform environment variables even though KeyHog does
not read those names directly.

| Platform input | What it can locate |
|---|---|
| `HOME` and the Unix `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, and `XDG_DATA_HOME` conventions | Default cache, configuration, detector-discovery, and daemon-fallback paths on Unix-like systems. |
| Windows known-folder APIs, commonly rooted by `LOCALAPPDATA`, `APPDATA`, and the user profile | Cache, data, and configuration paths on Windows. |
| The platform temporary-directory setting, such as `TMPDIR` on Unix or `TEMP`/`TMP` on Windows | Last-resort daemon socket parent and temporary work files. |

These paths can change where KeyHog reads or writes caches and optional user
configuration. They do not override a detector, source, or output setting.
Use explicit CLI or `.keyhog.toml` paths when an automation job must not depend
on the runner's home-directory conventions.

## Installer script environment

The installer scripts are separate programs from the KeyHog binary.

| Variable | Script | Effect |
|---|---|---|
| `KEYHOG_VERSION` | both | Selects an exact release tag instead of the latest release. The `--version` argument is the explicit alternative. |
| `GITHUB_TOKEN` | both | Authenticates GitHub API requests when present. |
| `NO_COLOR` | both | A non-empty value disables installer styling. |
| `HOME` | `install.sh` | Supplies the default install root `$HOME/.local/bin`. |
| `LOCALAPPDATA` | `install.ps1` | Supplies the default install directory and cache roots. | <!-- keyhog:ignore detector=entropy-token -->
| `USERPROFILE` | `install.ps1` | Locates PowerShell completion directories. | <!-- keyhog:ignore detector=entropy-token -->
| `PATH` | `install.ps1` | Checks whether the selected install directory is already reachable. |

## CI-only autoroute fixture variables

The `ci-lean` and test builds compile an authenticated timing-fixture seam for
autoroute integration tests. Official release builds do not compile this seam.

| Variable | Required value or effect |
|---|---|
| `KEYHOG_CI_AUTOROUTE_TIMING_FIXTURE` | `confidence-separated-v1` or `overlapping-v1`; replaces measured trial timings with the selected deterministic fixture during calibration. |
| `KEYHOG_CI_AUTOROUTE_FIXTURE_AUTH` | Must equal `bench-backend-parity-v1`; without this sentinel, fixture use fails. |

Do not set these variables in ordinary scans. They exist only to make the
real calibration path deterministic in CI.

## Replacing removed behavior variables

KeyHog-owned environment variables for scan behavior are ignored. Use the
supported interface instead:

| Need | Use |
|---|---|
| Backend override | `--backend <BACKEND>` with `auto`, `cpu`, `simd`, `gpu-cuda`, or `gpu-wgpu` |
| GPU requirement or disablement | `--require-gpu`, `--no-gpu`, or `[system].gpu` |
| Autoroute calibration | `keyhog calibrate-autoroute` or `scan --autoroute-calibrate` |
| Scanner concurrency and per-chunk limits | `--threads`, `[scan].threads`, `reader_threads`, `per_chunk_timeout_ms`, `fused_batch`, and `fused_depth` |
| Detector corpus | `--detectors`, `--detector-mode`, or the top-level `detectors` setting |
| Cache and trusted binary roots | `[system].cache_dir`, `[system].autoroute_cache`, and `[system].trusted_bin_dirs` |
| Detection tuning | `[tuning]` |
| AWS canary and knockoff account lists | `[aws] canary_accounts` and `knockoff_accounts` |
| Verifier and source proxy or lab TLS override | `--proxy`, `[http] proxy`, `--insecure`, or `[http] insecure_tls` |
| Dogfood capture | `--dogfood` |

Normal scans do not benchmark on an autoroute cache miss. Invalid or missing
normal-scan evidence leaves the affected batch unscanned and forces non-success
status. Run `keyhog calibrate-autoroute` to restore healthy automatic routing.
See [Configuration](./configuration.md) for the complete schema and
[Autoroute calibration](./autoroute-calibration.md) for the evidence contract.
