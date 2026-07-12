# Docker integration matrix

Drives the **real** `keyhog` binary inside clean per-libc container images,
under spoofed hardware / env / edge cases, and asserts exit code + stdout.
This is the cross-platform, cross-hardware dogfood layer: things a host-only
`cargo test` can't reach (musl vs glibc, no-GPU, single-thread, non-root,
missing system libs, piped/non-TTY output).

## Layout

| File | Role |
|------|------|
| `Dockerfile.glibc` | Debian builder + runtime; `--no-default-features --features ci-lean` (Hyperscan ON, GPU stack OFF). Exercises the Hyperscan-accelerated glibc runtime path: the C lib that links on glibc but not musl. (Full default features pull the wgpu/vyre/cuda graph, which exceeds the 45-min runner cap; GPU build validation lives in release-build + runners-nightly.) |
| `Dockerfile.musl`  | Alpine builder + runtime; `--no-default-features --features portable` against musl. Tests the macOS/Windows/static-Alpine feature set and musl-vs-glibc differences. |
| `corpus/`          | Small committed scan inputs baked into the image at `/data/corpus` (a neutral, non-`test/` path so `--precision`'s test-path penalty does not suppress the planted key; the matrix asserts the AWS key is found under *every* profile). |
| `scenarios.sh`     | The battery. One data-table row = one integration test; `(image × row)` is the matrix. |
| `run.sh`           | Builds the image(s) and runs `scenarios.sh` against each. CI + local entry point. |

## Run it

```sh
tests/docker/run.sh glibc   # debian/hyperscan image only
tests/docker/run.sh musl    # alpine/portable image only
tests/docker/run.sh all     # both (default)
```

CI runs `run.sh <variant>` per libc family in
`.github/workflows/integration-docker.yml`.

## Add a test

Append one row to `SCENARIOS` in `scenarios.sh`:

```
name | env | args | want_exit | grep_contains | grep_forbids
```

- `env`: space-separated `KEY=VAL` spoof vars (for supported env-only test toggles), or
  `-`. GPU policy is an explicit scan argument (`--no-gpu` /
  `--require-gpu`) or `.keyhog.toml` `[system].gpu`.
- `args`: arguments passed to `keyhog` in the container.
- `want_exit`: expected process exit code.
- `grep_contains` / `grep_forbids`: substrings that must / must not appear in
  stdout+stderr, or `-`.

The row runs against every image automatically, so a single line adds N tests.

## What it has already caught

- production `Dockerfile` missing `libssl-dev` (reqwest openssl-sys build fail);
- glibc skew (`rust:1.89-slim` is trixie/2.39, runtime bookworm/2.36 →
  `GLIBC_2.39 not found`);
- `tracing` emitting raw ANSI to non-TTY stderr;
- a broken `portable` build (ungated `build_simd_scanner` import) that was
  failing CI's macOS/Windows jobs.
