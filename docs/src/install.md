# Install

The quickest paths first. Pick one - they all give you the same
`keyhog` binary.

## One-liner: Linux / macOS

```sh
curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | sh
```

Drops a binary in `~/.local/bin/keyhog`. The installer detects your
CPU, GPU, and existing install before downloading, and tells you the
asset it picked and why.

On Linux x86_64, the default asset is the **WGPU + Hyperscan/SIMD**
build: it can dispatch the same vyre AC / RulePipeline on your GPU via
the vulkan backend, with a smaller binary and no `libcuda.so` runtime
dependency. The dedicated `keyhog-linux-x86_64-cuda` build is only
auto-selected on Linux when the host has the **full CUDA toolkit
installed** - `nvcc` on PATH, `$CUDA_HOME` set, or `/usr/local/cuda`
present. A driver-only NVIDIA host (libcuda.so loadable but no
toolkit) stays on the default Linux asset, since the native-CUDA
dispatch saves only single-digit percent on typical repo scans and the
binary footprint + runtime dependency are not worth it for the
non-CUDA-developer case. Pass `--variant=cuda` to force the CUDA build
anyway. macOS release assets are portable no-system-library builds:
they include the scanner data/source surface without Hyperscan, WGPU,
CUDA, or a native Metal asset in the current release.

## Interactive mode (recommended for first install)

`curl ... | sh` is fast but skips the wizard because stdin is a pipe.
For variant selection, shell completions, and optional hook setup:

```sh
curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh \
    -o keyhog-install.sh
sh keyhog-install.sh
```

The interactive installer shows you:

- The host it detected (OS, arch, GPU, libcuda state).
- The binary it would install (with the GPU note).
- Any existing keyhog install it found.
- Whether `~/.local/bin` is on your `PATH`.

Then it prompts (default in brackets):

- Add `~/.local/bin` to your shell `PATH`? `[Y/n]`
- Install shell completions for bash / zsh / fish? `[y/N]`
- Wire keyhog as a git pre-commit hook in this dir? `[y/N]`

Each prompt is opt-in. Nothing in your `.bashrc` / `.zshrc` / git
hooks dir is touched without an explicit "y". There is no shipped
Claude Code / Cursor agent-hook prompt or `keyhog hook install --agent
<name>` flag; the prompt was removed in v0.5.34.

## One-liner: Windows

PowerShell 5+ (ships with Windows 10/11):

```powershell
iwr https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.ps1 -useb | iex
```

Drops the binary in `%LOCALAPPDATA%\keyhog\bin\keyhog.exe`. Detects
your GPU for diagnostics; the Windows installer ships the portable
no-system-library build, with no Hyperscan, WGPU, or CUDA asset in the
current release.

For the interactive flow:

```powershell
iwr https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.ps1 `
    -OutFile keyhog-install.ps1
.\keyhog-install.ps1
```

> **Heads up.** The Unix daemon mode is unavailable on Windows (it
> relies on Unix-domain sockets). `keyhog scan`, `keyhog detectors`,
> `keyhog watch`, `keyhog hook`, etc. all work the same. The `daemon`
> subcommand and the `--daemon` flag emit an explicit "unix-only"
> error so nothing silently regresses.

## Variants and overrides

The installer auto-detects, but you can override:

| Env var / flag                          | Effect                                                        |
|-----------------------------------------|---------------------------------------------------------------|
| `--variant=cuda`                        | Force the CUDA-accelerated Linux build (requires libcuda.so). |
| `--variant=cpu`                         | Force the default non-CUDA release asset for this platform, skipping CUDA-asset auto-selection. |
| `KEYHOG_VERSION=v0.5.40` (or `--version=v0.5.40`) | Pin a specific release tag (default: GitHub's latest-asset redirect, with API fallback only when that asset is missing). |
| `--install-dir=...`                     | Install into a different directory.            |
| `GITHUB_TOKEN=...`                      | Optional auth for the fallback GitHub releases API lookup. The normal latest-asset path does not need it. |
| `--yes` / `-y`                          | Non-interactive: accept all defaults, no prompts.             |
| `--no-color`                            | Disable ANSI colors (e.g. for log capture).                   |

### Runtime GPU controls

| Control                  | Effect                                                                                                                                                                                                                                       |
|--------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `keyhog scan --no-gpu`   | Force the CPU + SIMD path; skip every GPU init (saves cold-start on hosts with no usable GPU).                                                                                                                                               |
| `keyhog scan --require-gpu` | Hard-fail (`exit 12`) when the GPU stack is unavailable. This is a diagnostic/CI assertion, separate from autoroute. Autoroute itself is not a fallback hierarchy: it selects the fastest measured-correct backend from all eligible candidates. |
| `.keyhog.toml [system] gpu = "off"` | Persist the CPU/SIMD-only policy for a repository. Use `"required"` for self-hosted GPU runners where a GPU regression must fail closed.                                                                                         |
| `keyhog scan --backend gpu\|simd\|cpu` | Force a specific live scan engine regardless of autoroute. Diagnostic and benchmark override only; it does not prove autoroute correctness.                                                                                                  |

Hosted CI runners normally have no useful GPU. Use `--no-gpu` or
`[system] gpu = "off"` there. On self-hosted GPU runners, use
`--require-gpu` or `[system] gpu = "required"` so a driver regression fails
closed instead of running as a CPU-only scan.

An explicit `--variant=cuda` request requires the `keyhog-linux-x86_64-cuda`
release asset and fails closed if that asset is missing. Falling back to the
default Linux asset is allowed only when the installer auto-selected CUDA from
host detection; in that case the installer made the accelerator choice and logs
the fallback before installing the default asset.

## Repair, diagnose, uninstall

```sh
sh keyhog-install.sh --diagnose    # print host + binary state, change nothing
sh keyhog-install.sh --repair      # re-download the right variant for this host
sh keyhog-install.sh --uninstall   # remove the binary + installer-owned shell wiring
```

`--diagnose` is the first thing to run if something looks off: it
reports CPU arch, OS, GPU + libcuda state, the currently-installed
binary (path + version), whether the install dir is on `PATH`, and
the asset the installer would download for the latest release tag.

`--repair` re-downloads the asset matching your current host even if
the existing binary still runs. Useful after a host upgrade adds a
new GPU, or on Linux after CUDA userland gets installed and the
non-CUDA asset should be swapped for the CUDA build.

`--uninstall` removes the binary, asks an installed `keyhog uninstall --yes`
to surface/clean persisted state first when that subcommand is available,
then removes only the shell artifacts the installer owns: its marked `PATH`
block and the known bash/zsh/fish completion files.

## Direct binary download

If you don't trust pipe-to-shell - fair - grab the binary by hand
from the [releases page](https://github.com/santhsecurity/keyhog/releases/latest).

| Platform              | Asset name                       |
|-----------------------|----------------------------------|
| Linux x86_64 (default)| `keyhog-linux-x86_64`            |
| Linux x86_64 + CUDA   | `keyhog-linux-x86_64-cuda`       |
| macOS x86_64 (Intel)  | `keyhog-macos-x86_64`            |
| macOS aarch64 (Apple) | `keyhog-macos-aarch64`           |
| Windows x86_64        | `keyhog-windows-x86_64.exe`      |

`chmod +x` the binary and put it somewhere on your `PATH`.

## Build from source

You'll want this if you're contributing or running a feature
combination the prebuilt binaries don't cover (e.g. Ghidra binary
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

For the CUDA backend, add the `cuda` feature on Linux:

```sh
cargo build --release -p keyhog --features cuda
```

This requires the CUDA toolkit at link time (NVCC + cudart + nvrtc)
and `libcuda.so` at runtime. The release workflow provisions CUDA
12.6 on the GitHub-hosted ubuntu runner for the
`keyhog-linux-x86_64-cuda` asset; for local source builds, install
the matching toolkit from
[developer.nvidia.com/cuda-toolkit](https://developer.nvidia.com/cuda-toolkit)
or your distro's `nvidia-cuda-toolkit` package.

The `portable` feature is what the official Windows + macOS release
binaries are built with: same scanner, no native dependency, ~5%
slower on big inputs.

## crates.io

KeyHog consumes the published Vyre runtime crates from crates.io through exact
workspace pins. The repository does not carry a `vendor/` source tree.

## Verify the install

```sh
keyhog --version
keyhog detectors | head     # smoke-test the embedded detector corpus
keyhog scan README.md       # scan a single file; exit 0 = clean
```

If `keyhog --version` reports a recent release and `keyhog detectors`
lists hundreds of detectors, you're set. Move on to
[Your first scan](./first-scan.md).

You can also run the installer in diagnostic mode at any time to
print a full status report:

```sh
sh keyhog-install.sh --diagnose
```
