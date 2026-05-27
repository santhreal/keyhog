# Environment variables

KeyHog reads a small set of environment variables. Each one is
documented here with default, effect, and a typical use case.

## Install / location

| Variable            | Default                                       | Effect                                |
|---------------------|-----------------------------------------------|---------------------------------------|
| `KEYHOG_INSTALL`    | `~/.local/bin` (sh) / `%LOCALAPPDATA%\keyhog\bin` (ps1) | Where install.sh / install.ps1 drops the binary. |
| `KEYHOG_VERSION`    | (latest release)                              | Pin install.sh / install.ps1 to a specific tag. |

## Cache

| Variable            | Default                                       | Effect                                |
|---------------------|-----------------------------------------------|---------------------------------------|
| `KEYHOG_CACHE_DIR`  | `~/.cache/keyhog` (Linux) / `~/Library/Caches/keyhog` (macOS) | Where the Hyperscan compiled database is cached across runs. Must be a user-owned dir; cold start (~3 s) becomes warm start (~150 ms) when the cache hits. |

## Backend selection

| Variable            | Default     | Effect                                                |
|---------------------|-------------|-------------------------------------------------------|
| `KEYHOG_BACKEND`    | `auto`      | One of `auto`, `cpu_fallback`, `simd_cpu`, `gpu`, `megascan`. Overrides hardware-probe selection. Mostly useful for benchmarking. |
| `KEYHOG_DISABLE_GPU` | (unset)    | If set to anything, skip the GPU probe entirely. Useful for CI where the runner reports a software-rendered GPU and you'd rather force CPU. |

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

## Testing / development

| Variable            | Default     | Effect                                                |
|---------------------|-------------|-------------------------------------------------------|
| `KEYHOG_ADVERSARIAL_STRICT` | (unset) | Tighten the adversarial-runner test gate. Used by CI's strict-runners job. |
| `KEYHOG_ENCODING_STRICT`    | (unset) | Same, for the encoding-evasion runner.                |
| `KEYHOG_PATH_SHAPE_STRICT`  | (unset) | Same, for the path-shape runner.                      |

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
