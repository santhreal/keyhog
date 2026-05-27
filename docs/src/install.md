# Install

The quickest paths first. Pick one - they all give you the same `keyhog`
binary.

## One-liner - Linux / macOS

```sh
curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | sh
```

Drops a binary in `~/.local/bin/keyhog`. The script tells you to add
that to `$PATH` if it isn't already. No sudo, no system files touched.

To pin a specific version:

```sh
curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh \
  | KEYHOG_VERSION=v0.5.25 sh
```

To install somewhere else:

```sh
curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh \
  | KEYHOG_INSTALL=/usr/local/bin sh
```

## One-liner - Windows

PowerShell 5+ (ships with Windows 10/11):

```powershell
iwr https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.ps1 -useb | iex
```

Drops the binary in `%LOCALAPPDATA%\keyhog\bin\keyhog.exe`. Same
`KEYHOG_VERSION` / `KEYHOG_INSTALL` env-var overrides as the shell
script.

> **Heads up.** The Unix daemon mode is unavailable on Windows
> (Unix-domain-socket-specific). `keyhog scan`, `keyhog detectors`,
> `keyhog watch`, `keyhog hook`, etc. all work the same. The `daemon`
> subcommand and the `--daemon` flag emit an explicit "unix-only"
> error so nothing silently regresses.

## Direct binary download

If you don't trust pipe-to-shell - fair - grab the binary by hand from
the [releases page](https://github.com/santhsecurity/keyhog/releases/latest).

Asset names follow the platform you'd expect:

| Platform              | Asset name                  |
|-----------------------|-----------------------------|
| Linux x86_64          | `keyhog-linux-x86_64`       |
| macOS x86_64 (Intel)  | `keyhog-macos-x86_64`       |
| macOS aarch64 (Apple) | `keyhog-macos-aarch64`      |
| Windows x86_64        | `keyhog-windows-x86_64.exe` |

`chmod +x` the binary and put it somewhere on your `PATH`.

## Build from source

You'll want this if you're contributing or running a feature combination
the prebuilt binaries don't cover (e.g. CUDA GPU scan, Ghidra binary
extraction).

```sh
git clone https://github.com/santhsecurity/keyhog
cd keyhog
cargo build --release -p keyhog
./target/release/keyhog --version
```

The default feature set requires **Hyperscan / Vectorscan**:

- Debian / Ubuntu: `sudo apt install libhyperscan-dev pkg-config`
- macOS: not available via Homebrew. Build with `--no-default-features --features portable` to skip Hyperscan and use the pure-Rust path.
- Windows: build with `--no-default-features --features portable`.

The `portable` feature is what the official Windows + macOS release
binaries are built with - same scanner, no native dependency, ~5% slower
on big inputs.

## crates.io

Not yet. KeyHog vendors `vyre-libs` (the GPU literal-set scan crate) and
isn't published to crates.io until that dependency lands there. Track
the [crates.io publish issue](https://github.com/santhsecurity/keyhog/issues?q=is%3Aissue+crates.io)
for status.

## Verify the install

```sh
keyhog --version
keyhog detectors | head     # smoke-test the embedded detector corpus
keyhog scan README.md       # scan a single file; exit 0 = clean
```

If `keyhog --version` reports `0.5.25` (or whatever the latest release
is) and `keyhog detectors` lists hundreds of detectors, you're set.
Move on to [Your first scan](./first-scan.md).

## Uninstall

There's nothing global to remove - the install scripts only touch the
install dir. Delete `keyhog` (or `keyhog.exe`) from there and you're
done. Nothing in `~/.cache`, `~/.config`, the Windows registry, or the
launchd plist is touched.
