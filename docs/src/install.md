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
cargo install --locked --version '=0.5.57' keyhog
```

The leading equals sign prevents Cargo from selecting another compatible
version. KeyHog publishes canonical `X.Y.Z` versions. Do not include a leading
`v` in the Cargo version requirement.

To update to the latest release, run:

```sh
cargo install --locked --force keyhog
```

Every successful `main` CI run publishes the next patch version. KeyHog does
not publish binary release assets or installer bundles.

## Update or roll back

Stop a running daemon before replacing the executable:

```sh
keyhog daemon stop
cargo install --locked --force keyhog
```

Cargo builds the replacement before it changes the installed binary. A compile
or download failure leaves the previous executable in place.

To roll back, choose a version from the
[crates.io version list](https://crates.io/crates/keyhog/versions), replace
`MAJOR.MINOR.PATCH` below, and install that exact package:

```sh
cargo install --locked --force --version '=MAJOR.MINOR.PATCH' keyhog
```

The commands are identical in Bash, Zsh, and PowerShell. If PowerShell reports
that `keyhog.exe` is in use, stop the daemon and close other KeyHog processes,
then retry. If Cargo reports that `libhs` is missing, remove an unintended
`simd` feature or install the Hyperscan/Vectorscan development package. The
default install does not require `libhs`.

## Choose installation features

The default install is the portable build. It keeps every source provider and
the full detection policy while avoiding native accelerator build
prerequisites:

```sh
cargo install --locked keyhog
```

Enable CUDA, native Metal, and WGPU while keeping Hyperscan optional:

```sh
cargo install --locked keyhog --no-default-features --features portable,gpu
```

The GPU drivers load supported accelerators at runtime. A host without an
eligible adapter keeps the pure-Rust CPU route. Run `keyhog backend --self-test`
to inspect exact acquisition state before calibration.

Enable Hyperscan or Vectorscan only after installing its development package and
making `libhs.pc` visible to `pkg-config`:

```sh
cargo install --locked keyhog --no-default-features --features portable,simd
```

For a smaller checkout-only CI scanner, use the `ci` feature:

```sh
cargo install --locked keyhog \
  --no-default-features \
  --features ci
```

The `ci` feature supports filesystem and standard-input scans. It omits remote
source providers, live verification, and accelerator backends.

## Build the checked-out source

From the repository root:

```sh
cargo install --locked --path crates/cli
```

Use this path when you are testing an unreleased checkout. A tagged GitHub
Action ref installs its exact crates.io version with the lean `ci` feature. A
branch or commit Action ref builds its checked-out source.

## Confirm the installation

Run a health check before your first scan:

```sh
keyhog --version
keyhog doctor
keyhog scan .
```

`keyhog doctor` exits `0` when the installed binary is healthy and `4` when a
health check fails. `keyhog scan .` exits `0` for a clean scan and `1` when it
reports findings. Continue with [Your first scan](./first-scan.md) to exercise a
safe synthetic finding.
