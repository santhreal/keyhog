# Environment variables

KeyHog reads a small set of environment variables. Each one is
documented here with default, effect, and a typical use case.

## Install / location

| Variable            | Default                                       | Effect                                |
|---------------------|-----------------------------------------------|---------------------------------------|
| `KEYHOG_INSTALL`    | `~/.local/bin` (sh) / `%LOCALAPPDATA%\keyhog\bin` (ps1) | Where install.sh / install.ps1 drops the binary. |
| `KEYHOG_VERSION`    | (latest release with assets)                  | Pin install.sh / install.ps1 to a specific tag. install.sh now walks back through `/releases?per_page=10` to find the most recent release with binaries attached, surviving a one-off release-workflow failure without forcing an explicit pin. |
| `KEYHOG_VARIANT`    | `auto` (`cuda` on hosts with the full CUDA toolkit, `cpu` otherwise) | Force the `cuda` or `cpu` variant of the Linux build during install. `cpu` is the WGPU + SIMD default which already dispatches on any compatible adapter via Vulkan; `cuda` adds the native-CUDA backend on hosts with libcuda + the matching toolkit. |

## Cache

| Variable            | Default                                       | Effect                                |
|---------------------|-----------------------------------------------|---------------------------------------|
| `KEYHOG_CACHE_DIR`  | `~/.cache/keyhog` (Linux) / `~/Library/Caches/keyhog` (macOS) | Where the Hyperscan compiled database is cached across runs. Must be a user-owned dir; cold start (~3 s) becomes warm start (~150 ms) when the cache hits. |

## Version output

| Variable                  | Default | Effect                                                |
|---------------------------|---------|-------------------------------------------------------|
| `KEYHOG_VERSION_FULL`     | (unset) | Set to `1` to make `keyhog --version` also print the full hardware probe (SIMD ISA, GPU adapter, CUDA / WGPU availability). Hidden by default because the probe initializes wgpu/Vulkan (~200 ms + a 134 MB MAP_SHARED segment), which makes `keyhog --version` 9× slower than `keyhog --help`. The same probe runs unconditionally for `keyhog backend`. |

## Backend selection

| Variable            | Default     | Effect                                                |
|---------------------|-------------|-------------------------------------------------------|
| `KEYHOG_BACKEND`    | `auto`      | One of `auto`, `cpu_fallback`, `simd_cpu`, `gpu`, `megascan`. Overrides hardware-probe selection. Mostly useful for benchmarking. |
| `KEYHOG_NO_GPU`     | (unset)     | If set to `1`, skip the GPU probe entirely. Useful for CI where the runner reports a software-rendered GPU and you'd rather force CPU. Mirrored by `CI=true`/`GITHUB_ACTIONS=true` auto-detection. |
| `KEYHOG_REQUIRE_GPU` | (unset)    | If set to `1`, refuse to run when no usable GPU adapter is detected. Useful for self-hosted runners where a regression on GPU initialization should fail loudly, not silently fall back to CPU. |
| `KEYHOG_GPU_KERNEL` | `auto`      | Override the GPU dispatch kernel pick. Mostly a development knob for benchmarking individual kernel implementations. |
| `KEYHOG_GPU_MOE_TIMEOUT_MS` | `30000` | Deadline for one GPU MoE confidence readback. On timeout KeyHog falls back to CPU MoE for that batch instead of parking a scan worker forever. |

## Threading + chunking

| Variable                     | Default            | Effect                                       |
|------------------------------|--------------------|----------------------------------------------|
| `KEYHOG_THREADS`             | physical-core count | Pin the rayon worker pool. Useful inside containers where `available_parallelism()` reports the wrong value. |
| `KEYHOG_PER_CHUNK_TIMEOUT_MS` | (unset)            | Hard deadline per chunk scan in milliseconds. Recommended `30000` for production scans where bounded latency matters more than scan completeness. |
| `KEYHOG_DETECTORS`           | (workspace default) | Override the auto-discovered detector directory path. |
| `KEYHOG_TRUSTED_BIN_DIR`     | (unset)            | Restrict which binary paths the daemon will execute when forking for sub-scans (defense-in-depth knob). |

## Daemon (Unix only)

| Variable            | Default                                       | Effect                                |
|---------------------|-----------------------------------------------|---------------------------------------|
| `XDG_RUNTIME_DIR`   | (set by login session)                        | Daemon socket location: `$XDG_RUNTIME_DIR/keyhog.sock`. Fallback is `~/.cache/keyhog/server.sock`. |
| `KEYHOG_DOGFOOD`    | (unset)                                       | Enable dogfood telemetry capture in the daemon. Equivalent to passing `--dogfood` on every connecting client. |

## Verification

| Variable            | Default     | Effect                                                |
|---------------------|-------------|-------------------------------------------------------|
| `HTTPS_PROXY`       | (unset)     | Standard env var. Routes verifier traffic through a proxy. `keyhog scan --proxy <URL>` overrides. |
| `KEYHOG_PROXY`      | `auto`      | `off` disables proxy resolution entirely (useful for air-gapped builds where `HTTPS_PROXY` is set but no proxy is reachable). Also disables DNS pinning when off, so don't set it to `off` casually. |
| `NO_PROXY`          | (unset)     | Standard env var. Hostnames to bypass the proxy on. |

## Logging

| Variable            | Default       | Effect                                              |
|---------------------|---------------|-----------------------------------------------------|
| `RUST_LOG`          | `keyhog=warn` | Tracing filter. `keyhog=debug` for verbose detector / suppression telemetry. `keyhog::routing=trace` to see per-chunk backend selection. |
| `RUST_BACKTRACE`    | (unset)       | Standard. `1` for short backtrace on panic; `full` for full. |

## Verification (extra)

| Variable                  | Default | Effect                                                |
|---------------------------|---------|-------------------------------------------------------|
| `KEYHOG_INSECURE_TLS`     | (unset) | If set, accept self-signed TLS certs on verifier traffic. Equivalent to `--insecure`. Use only in lab environments. |
| `KEYHOG_ALLOW_SCRIPT_VERIFY` | (unset) | Permit the `script:` verifier kind (which would otherwise be refused as a remote-execution risk). Opt-in for trusted detector corpora only. |
| `KEYHOG_AWS_CANARY_ACCOUNTS` | (unset) | Path to a TOML extension file with `[canary].accounts` / `[knockoff].accounts` 12-digit AWS account IDs. Unreadable, empty, malformed, or non-UTF-8 values fail closed before scans or AWS verification, because ignoring this file would remove operator-supplied canary protection. |
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
- Anything named `KEYHOG_API_KEY` / `KEYHOG_TOKEN`. The scanner never
  reports findings upstream; there's no service to authenticate to.
- `KEYHOG_TELEMETRY_*`. There is no telemetry. Findings stay local.

## Precedence

When two sources disagree:

1. CLI flag (`--proxy <URL>`)
2. `.keyhog.toml` in the repo root
3. Environment variable
4. Compiled default

So `keyhog scan --proxy http://a` beats `HTTPS_PROXY=http://b` beats
`KEYHOG_PROXY=off`. The lowest-precedence wins only when nothing
above it is set.
