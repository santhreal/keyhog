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

A default build includes the scanner, repository and cloud sources, live
verification, Hyperscan where supported, and eligible GPU backends. Your host
may need a C compiler and the platform libraries required by those features.

## Pin an exact version

Use an exact Cargo version requirement when a build or CI job must stay on one
release:

```sh
cargo install --locked --version '=0.5.49' keyhog
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

## Install a portable build

Use the portable feature set when native accelerator dependencies are not
available:

```sh
cargo install --locked keyhog \
  --no-default-features \
  --features portable
```

On macOS, add native Metal and WGPU to the portable source surface:

```sh
cargo install --locked keyhog --no-default-features --features portable,gpu
```

The portable build keeps filesystem, Git, web, cloud, container, archive, and
verification sources. It uses the scalar CPU scanner. Run explicit CPU scans
or calibrate the available routes before using `backend = "auto"`.

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
Action ref installs its exact crates.io version instead. A branch or commit
Action ref builds its checked-out source with the portable feature set.

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
