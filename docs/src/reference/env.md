# Environment variables

KeyHog reads a small set of environment variables. Each one is
documented here with default, effect, and a typical use case.

## Install / location

| Variable            | Default                                       | Effect                                |
|---------------------|-----------------------------------------------|---------------------------------------|
| `KEYHOG_INSTALL`    | `~/.local/bin` (sh) / `%LOCALAPPDATA%\keyhog\bin` (ps1) | Where install.sh / install.ps1 drops the binary. |
| `KEYHOG_VERSION`    | (latest release asset redirect)               | Pin install.sh / install.ps1 to a specific tag. Without a pin, install.sh first downloads through GitHub's non-API `/releases/latest/download/...` redirect, then walks `/releases?per_page=10` only when that asset is missing so a one-off zero-asset release still recovers. |
| `KEYHOG_VARIANT`    | `auto` (`cuda` on hosts with the full CUDA toolkit, `cpu` otherwise) | Force the `cuda` or `cpu` variant of the Linux build during install. `cpu` is the WGPU + SIMD default which already dispatches on any compatible adapter via Vulkan; `cuda` adds the native-CUDA backend on hosts with libcuda + the matching toolkit. |
| `GITHUB_TOKEN`      | (unset)                                       | Optional token used only for the fallback GitHub releases API lookup. The default latest-asset redirect path does not read it. |

## Backend selection

No backend-selection `KEYHOG_*` environment variable changes scan routing.
Autoroute calibration mode is explicit CLI behavior: installers run
`keyhog scan --autoroute-calibrate` during the visible calibration phase.
Normal scans never benchmark on cache miss; they require persisted
fastest-correct decisions or an explicit `--backend`.

Autoroute GPU candidate eligibility is explicit scan configuration: use
`keyhog scan --autoroute-gpu` for calibration runs, `--no-autoroute-gpu` to
override TOML, or `.keyhog.toml` `[system] autoroute_gpu = true`.

GPU probe policy is explicit scan configuration: use `keyhog scan --no-gpu`,
`keyhog scan --require-gpu`, or `.keyhog.toml` `[system] gpu = "off"` /
`"required"`.

## Threading + chunking

Filesystem reader threads and fused-pipeline batch shape are explicit scan
configuration: use `keyhog scan --reader-threads <N>`,
`--fused-batch <N>`, `--fused-depth <N>`, or the matching `.keyhog.toml`
`[scan]` keys. They are printed by `keyhog config --effective` and included in
autoroute scan identity.

Hyperscan compile sharding is also explicit scanner tuning:
`.keyhog.toml` `[tuning].hs_shard_target`.

Trusted external binary directories and the Hyperscan compiled-database cache
directory are configured through `.keyhog.toml` `[system]` or explicit CLI
flags, not environment variables.
AWS canary/knockoff issuer account extensions are configured through
`.keyhog.toml` `[aws]`.
Detection/recall route tuning is configured through `.keyhog.toml` `[tuning]`;
use `[tuning].gpu_recall_floor = true` for explicit GPU parity/debug runs.
Legacy `KEYHOG_*` tuning variables are ignored so scan recall is not changed
by ambient shell state.
Scanner profiling and low-level timing are explicit scan flags:
`keyhog scan --profile` and `keyhog scan --perf-trace`.
GPU MoE readback timeout is configured through `.keyhog.toml` `[tuning]`
`gpu_moe_timeout_ms`.
Per-chunk scan timeout is configured with `keyhog scan --per-chunk-timeout-ms
<MS>` or `.keyhog.toml` `[scan].per_chunk_timeout_ms`.

## Daemon (Unix only)

| Variable            | Default                                       | Effect                                |
|---------------------|-----------------------------------------------|---------------------------------------|
| `XDG_RUNTIME_DIR`   | (set by login session)                        | Daemon socket location: `$XDG_RUNTIME_DIR/keyhog.sock`. Fallback is `~/.cache/keyhog/server.sock`. |

Daemon request timeout is configured explicitly with
`keyhog daemon start --request-timeout-secs <N>`.

## Remote source auth

| Variable            | Default     | Effect                                                |
|---------------------|-------------|-------------------------------------------------------|
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`, `AWS_DEFAULT_REGION` | (unset) | Optional S3 ListObjectsV2 / object GET signing for AWS-owned endpoints. Custom `--s3-endpoint` hosts never receive ambient AWS credentials unless `--allow-s3-credential-forward` is passed. |
| `GOOGLE_OAUTH_ACCESS_TOKEN`, `GCS_BEARER_TOKEN` | (unset) | Optional bearer token for `--gcs-bucket` JSON API listing/object downloads. The Google token variable wins when both are set. Custom `--gcs-endpoint` hosts never receive the token unless `--allow-gcs-token-forward` is passed. |
| GitHub/GitLab/Bitbucket tokens | (CLI only) | Repository-collection scans require explicit `--github-token`, `--gitlab-token`, or `--bitbucket-token` flags. KeyHog does not read ambient forge tokens for these sources. |

## Logging

| Variable            | Default       | Effect                                              |
|---------------------|---------------|-----------------------------------------------------|
| `RUST_LOG`          | `keyhog=warn` | Tracing filter. `keyhog=debug` for verbose detector / suppression telemetry. `keyhog::routing=trace` to see per-chunk backend selection. |
| `RUST_BACKTRACE`    | (unset)       | Standard. `1` for short backtrace on panic; `full` for full. |

## Verification (extra)

| Variable                  | Default | Effect                                                |
|---------------------------|---------|-------------------------------------------------------|
| `KEYHOG_LIVE_VERIFY`      | (unset) | Internal: enables a special live-verify mode used by the end-to-end test harness. |
| `KEYHOG_LIVE_AWS_ACCESS_KEY_ID`, `KEYHOG_LIVE_AWS_SECRET_ACCESS_KEY`, `KEYHOG_LIVE_GITHUB_PAT` | (unset) | Test-only credentials the verifier integration tests probe against real upstream services. Never set these outside the maintainer test environment. |

## Testing / development

| Variable                       | Default | Effect                                                |
|--------------------------------|---------|-------------------------------------------------------|
| `KEYHOG_ADVERSARIAL_STRICT`    | (unset) | Tighten the adversarial-runner test gate. Used by CI's strict-runners job. |
| `KEYHOG_ADVERSARIAL_FULL_LOG`  | (unset) | Emit per-fixture log for every adversarial corpus row (slow; debugging only). |
| `KEYHOG_ENCODING_STRICT`       | (unset) | Strict mode for the encoding-evasion runner.          |
| `KEYHOG_PATH_SHAPE_STRICT`     | (unset) | Strict mode for the path-shape runner.                |
| `KEYHOG_ENTROPY_STRICT`        | (unset) | Strict mode for the entropy-bypass runner.            |
| `KEYHOG_UNICODE_STRICT`        | (unset) | Strict mode for the unicode-homoglyph runner.         |
| `KEYHOG_COMMENT_STRICT`        | (unset) | Strict mode for the comment-evasion runner.           |
| `KEYHOG_COMPOUND_STRICT`       | (unset) | Strict mode for the compound-bypass runner.           |
| `KEYHOG_LINE_LEN_STRICT`       | (unset) | Strict mode for the line-length runner.               |
| `KEYHOG_MULTI_STRICT`          | (unset) | Strict mode for the multi-pattern runner.             |
| `KEYHOG_NOISE_STRICT`          | (unset) | Strict mode for the noise-injection runner.           |
| `KEYHOG_CHUNK_IDS`             | (unset) | Restrict the scan to a comma-separated list of chunk IDs. Used by adversarial bisection. |

## What KeyHog deliberately does NOT read

- `KEYHOG_*` flags for changing detector behavior. Detector tuning is
  via `.keyhog.toml` only, so the same scan reproduces across
  developer machines without env-var contamination.
- Old cache-dir environment overrides. Configure the Hyperscan
  compiled-database cache with `keyhog scan --cache-dir <DIR>` or
  `.keyhog.toml` `[system].cache_dir`.
- Old autoroute-cache environment overrides in the keyhog binary. Configure the
  persisted autoroute calibration evidence file with
  `keyhog scan --autoroute-cache <PATH|off>` or `.keyhog.toml`
  `[system].autoroute_cache`.
- Old AWS canary extension environment overrides. Configure site-local canary
  and knockoff issuer account IDs with `.keyhog.toml` `[aws]`.
- Ambient remote-source targets such as `SLACK_TOKEN`, `S3_BUCKET`,
  `GCS_BUCKET`, or `AZURE_BLOB_CONTAINER_URL`. Use explicit source flags
  (`--source slack:TOKEN`, `--s3-bucket`, `--gcs-bucket`,
  `--azure-container-url`) so target selection is visible in the command
  and captured by config/audit logs.
- Ambient verifier/source HTTP policy variables such as `HTTPS_PROXY`,
  `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY`, `KEYHOG_PROXY`, and
  `KEYHOG_INSECURE_TLS`. Use explicit `keyhog scan --proxy <URL>` /
  `--proxy off` and `--insecure`, or the matching TOML fields. When no
  proxy is configured, KeyHog disables reqwest's ambient proxy detection
  so shell or CI environment cannot silently reroute secret-bearing
  verification traffic or disable TLS verification.
- Anything named `KEYHOG_API_KEY` / `KEYHOG_TOKEN`. The scanner never
  reports findings upstream; there's no service to authenticate to.
- `KEYHOG_TELEMETRY_*`. There is no telemetry. Findings stay local.

## Precedence

For scanner options that have both CLI and TOML forms, CLI wins over
`.keyhog.toml`, and the compiled default applies when neither is set.
The environment variables documented above are explicit install, credential,
host-integration, logging, or test/development exceptions; they are not a
general override tier.

For verifier/source HTTP policy specifically, the order is:

1. CLI flag (`--proxy <URL>`, `--proxy off`, `--insecure`)
2. `.keyhog.toml`
3. Compiled default (`no proxy`, strict TLS)

No proxy or TLS environment variable participates in that order.
