# Install

KeyHog releases are Rust packages on crates.io. Install the latest published
version with Cargo:

```sh
cargo install --locked keyhog
keyhog --version
keyhog doctor
```

`cargo install` builds KeyHog for your host and places the binary in Cargo's
binary directory. This is usually `$HOME/.cargo/bin` on Linux and macOS, or
`%USERPROFILE%\.cargo\bin` on Windows. Add that directory to `PATH` if your
shell cannot find `keyhog`.

## Platform support

`cargo install` is the current distribution path and builds KeyHog from source
for the host that runs it. Hosted release CI proves this matrix:

| OS | CI-proven architecture |
|---|---|
| Linux | x86_64 |
| macOS | x86_64, arm64 |
| Windows | x86_64 |

Other Rust host targets are not part of the hosted release contract. Cargo may
build them when KeyHog's dependencies support the target, but a successful local
build is the evidence for that host. In particular, Linux arm64 and Windows
arm64 do not have hosted release jobs.

### Installing a bundle you already hold

There is no binary download channel. No workflow builds, signs, or uploads
release binaries, and KeyHog has no self-update command.

`install.sh` and `install.ps1` install a binary you already have, with
`--from-file`. Use them for an air-gapped host or to place a locally built
binary on `PATH` with the same layout, permission, and PATH handling that a
packaged install would use. Neither script contacts the network. Both refuse
to install without `--from-file` and print the Cargo command instead.

Both scripts run `keyhog doctor`, publish an execution-pack generation,
calibrate autoroute, and then scan a throwaway two-file directory with no
backend override. That last scan is the install's pass criterion for routing: a
calibrated cache that cannot serve an ordinary scan fails the install and the
previous binary is restored.

Update with `cargo install --locked --force keyhog`. That is also the repair
path: it rebuilds and replaces the installed binary.

## Install Rust

KeyHog requires Rust 1.89 or newer. Install Rust with
[rustup](https://rustup.rs/) when `cargo --version` is unavailable. Then open a
new terminal and run the install command again.

The default build includes filesystem, Git, web, cloud, container, archive, and
native binary sources plus live verification. It uses the pure-Rust CPU scanner
and has no Hyperscan, GPU-driver, CUDA-toolkit, or Ghidra build prerequisite.
Binary string and object scanning works without Ghidra. If you install Ghidra
separately, KeyHog can also enrich supported binaries with decompiled content.

## Pin an exact version

Use an exact Cargo version requirement when a build or CI job must stay on one
release:

```sh
cargo install --locked --version '=0.5.85' keyhog
```

The leading equals sign prevents Cargo from selecting another compatible
version. KeyHog publishes canonical `X.Y.Z` versions. Do not include a leading
`v` in the Cargo version requirement.

To update to the latest release, run:

```sh
cargo install --locked --force keyhog
keyhog doctor
```
Every successful `main` CI run publishes the next patch version. KeyHog does
not publish binary release assets or installer bundles.

## Update or roll back

Stop a running daemon before replacing the executable:

```sh
keyhog daemon stop
cargo install --locked --force keyhog
keyhog doctor
```
Cargo builds the replacement before it changes the installed binary. A compile
or download failure leaves the previous executable in place.

To roll back, choose a version from the
[crates.io version list](https://crates.io/crates/keyhog/versions), replace
`MAJOR.MINOR.PATCH` below, and install that exact package:

```sh
cargo install --locked --force --version '=MAJOR.MINOR.PATCH' keyhog
keyhog doctor
```
The commands are identical in Bash, Zsh, and PowerShell. If PowerShell reports
that `keyhog.exe` is in use, stop the daemon and close other KeyHog processes,
then retry. If Cargo reports that `libhs` is missing, remove an unintended
`simd` feature or install the Hyperscan/Vectorscan development package. The
default install does not require `libhs`.

## Choose installation features

The profiles below serve different products. `ci` is the small user-facing CI
build; `ci-lean` is a broad maintainer test closure and is not the lightweight
edition.

| Intent | Feature selection | Included surface | Additional requirement |
|---|---|---|---|
| General installation | default (`portable`) | Every documented source provider, binary scanning, and live verification; pure-Rust CPU route | None |
| General installation with GPU peers | `portable,gpu` | `portable` plus CUDA, native Metal, and WGPU | Supported runtime driver |
| General installation with SIMD peer | `portable,simd` | `portable` plus Hyperscan/Vectorscan | Development package and `libhs.pc` visible to `pkg-config` |
| Small checkout-only CI scanner | `ci` | Filesystem, archives, stdin, and the full detection policy; no remote providers, verification, SIMD, or GPU | None |
| Hosted maintainer test closure | `ci-lean` | Broad network providers, verification, Hyperscan/SIMD, and scanner data features; no GPU dispatch | Hyperscan/Vectorscan development package |

Install the default portable build:

```sh
cargo install --locked keyhog
```

Enable CUDA, native Metal, and WGPU:

```sh
cargo install --locked keyhog --no-default-features --features portable,gpu
```

Enable Hyperscan or Vectorscan:

```sh
cargo install --locked keyhog --no-default-features --features portable,simd
```

Install the small checkout-only CI scanner:

```sh
cargo install --locked keyhog \
  --no-default-features \
  --features ci
```

Cargo does not execute the binary after installation. After installing a
multi-backend `portable,gpu` or `portable,simd` build, acquire and calibrate the
eligible peers explicitly:

```sh
keyhog backend --self-test
keyhog calibrate-autoroute
keyhog backend --autoroute
```

A scalar-only `portable` or `ci` build reports autoroute health as `direct`
because it has no backend choice to calibrate.

## Which build your workload needs

Source providers are compile-time features. A flag that its feature did not
build is not hidden or ignored: it is absent from the command line, so the
command exits `2` with `error: unexpected argument`. That is loud, and it is
the reason to pick the right build before you script against it.

| Workload | Flag | Feature | In `portable` (the default) | In `ci` |
|---|---|---|:---:|:---:|
| Working tree, single file | positional path | always built | yes | yes |
| Standard input | `--stdin` | always built | yes | yes |
| Archives and nested archives | positional path | always built | yes | yes |
| Watch changed files | `keyhog watch` | always built | yes | yes |
| Git history, blobs, diff, staged | `--git-history`, `--git-blobs`, `--git-diff`, `--git-staged` | `git` | yes | no |
| Container images | `--docker-image` | `docker` | yes | no |
| S3 buckets | `--s3-bucket` | `s3` | yes | no |
| GCS buckets | `--gcs-bucket` | `gcs` | yes | no |
| Azure Blob containers | `--azure-container-url` | `azure` | yes | no |
| GitHub orgs and collaboration surfaces | `--github-org`, `--github-collaboration` | `github` | yes | no |
| GitLab groups | `--gitlab-group` | `gitlab` | yes | no |
| Bitbucket workspaces | `--bitbucket-workspace` | `bitbucket` | yes | no |
| URLs, source maps, WASM | `--url` | `web` | yes | no |
| Native binaries and firmware | `--binary` | `binary` | yes | no |
| Live credential verification | `--verify` | `verify` | yes | no |

The `ci` build covers the filesystem and standard-input workloads and nothing
else. That is the point of it: a checked-out tree is what a CI job scans, and
dropping the rest removes the network and native dependencies. Add back only
what you need:

```sh
cargo install --locked keyhog --no-default-features --features ci,git
```

Check what your installed build has before you script against it:

```sh
keyhog scan --help
```

A workload whose flag is missing from that output is not available in your
build. Reinstall with its feature rather than working around the error.

## Build the checked-out source

From the repository root:

```sh
cargo install --locked --path crates/cli
```

Use this path when you are testing an unreleased checkout. A tagged GitHub
Action ref installs its exact crates.io version with the lean `ci` feature. A
branch or commit Action ref builds its checked-out source.

## Confirm the installation

Inspect the compiled capabilities and health before your first scan:

```sh
keyhog --version --full
keyhog scan --help
keyhog doctor
keyhog backend --self-test
keyhog backend --autoroute
keyhog scan .
```

`scan --help` is the authoritative list of source flags compiled into this
binary. `backend --self-test` executes available accelerator diagnostics and
reports a successful `SKIP` when no physical GPU is present. `backend
--autoroute` reports `direct` for a scalar-only build and `ready` for a valid
multi-backend calibration.

`keyhog doctor` exits `0` when the installed binary is healthy and `4` when a
health check fails. `keyhog scan .` exits `0` when no finding blocks the active
evidence policy and `1` when at least one finding blocks. Continue with
[Your first scan](./first-scan.md) to exercise a safe synthetic finding.
