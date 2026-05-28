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

The default is the **WGPU + SIMD** build everywhere: it already
dispatches the same vyre AC / RulePipeline on your GPU via the vulkan
backend, with a smaller binary and no `libcuda.so` runtime
dependency. The dedicated `keyhog-linux-x86_64-cuda` build is only
auto-selected on Linux when the host has the **full CUDA toolkit
installed** - `nvcc` on PATH, `$CUDA_HOME` set, or `/usr/local/cuda`
present. A driver-only NVIDIA host (libcuda.so loadable but no
toolkit) stays on the WGPU build, since the native-CUDA dispatch
saves only single-digit percent on typical repo scans and the
binary footprint + runtime dependency are not worth it for the
non-CUDA-developer case. Pass `--variant=cuda` (or set
`KEYHOG_VARIANT=cuda`) to force the CUDA build anyway. Apple
Silicon hosts get an explicit "Metal GPU acceleration coming soon"
note; until that lands, Apple Silicon runs SIMD on CPU plus WGPU
on the integrated GPU.

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
hooks dir is touched without an explicit "y". Claude Code / Cursor
agent-hook integration is on the roadmap but not yet shipped; the
prompt was removed in v0.5.34 once it became clear the underlying
`keyhog hook install --agent <name>` flag wasn't real yet.

## One-liner: Windows

PowerShell 5+ (ships with Windows 10/11):

```powershell
iwr https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.ps1 -useb | iex
```

Drops the binary in `%LOCALAPPDATA%\keyhog\bin\keyhog.exe`. Detects
your GPU (informational only: a dedicated CUDA-on-Windows variant is
on the roadmap but not yet shipped, so today every Windows host gets
the same WGPU + SIMD binary).

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
| `KEYHOG_VARIANT=cuda` (or `--variant=cuda`) | Force the CUDA-accelerated Linux build (requires libcuda.so). |
| `KEYHOG_VARIANT=cpu`  (or `--variant=cpu`)  | Force the default WGPU + SIMD build, skip GPU detection.      |
| `KEYHOG_VERSION=v0.5.30` (or `--version=v0.5.30`) | Pin a specific release tag.                            |
| `KEYHOG_INSTALL=/usr/local/bin` (or `--install-dir=...`) | Install into a different directory.            |
| `--yes` / `-y`                          | Non-interactive: accept all defaults, no prompts.             |
| `--no-color`                            | Disable ANSI colors (e.g. for log capture).                   |

### Runtime env vars (consumed by the `keyhog` binary itself)

| Env var                  | Effect                                                                                                                                                                                                                                       |
|--------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `KEYHOG_NO_GPU=1`        | Force the CPU + SIMD path; skip every GPU init (saves ~250 ms of cold-start on hosts with no usable GPU).                                                                                                                                    |
| `KEYHOG_NO_GPU=0`        | Force GPU init even when CI auto-detection would otherwise skip it. Useful on self-hosted GitHub / GitLab runners with a real GPU.                                                                                                            |
| `KEYHOG_REQUIRE_GPU=1`   | Hard-fail (`exit 2`) instead of silently degrading when the GPU stack is unavailable. Pairs with the no-silent-fallback contract.                                                                                                            |
| `KEYHOG_BACKEND=gpu\|mega-scan\|simd\|cpu` | Force a specific scan backend regardless of hardware probe. Mostly for benches; production code should let auto-select route.                                                                                                  |

**CI auto-detect.** When `CI=true` is set (or any of `GITHUB_ACTIONS`, `GITLAB_CI`, `CIRCLECI`, `TRAVIS`, `JENKINS_URL`, `TF_BUILD`, `BUILDKITE`, `DRONE`, `APPVEYOR`, `TEAMCITY_VERSION`, `CODEBUILD_BUILD_ID`, `BITBUCKET_BUILD_NUMBER`, `WERCKER`, `SEMAPHORE`), keyhog skips the GPU probe entirely and goes straight to the SIMD + CPU path. The savings: ~250 ms of cold-start per `keyhog` invocation, plus no confusing "GPU MoE init failed" warning when the runner's only GPU is `llvmpipe`. Override with `KEYHOG_NO_GPU=0` on self-hosted GPU runners.

When a CUDA variant asset isn't published for the resolved release
tag yet, the installer logs the fallback and downloads the default
WGPU + SIMD asset instead. You can rerun with `--variant=cuda` once
a tag with the CUDA variant lands.

## Repair, diagnose, uninstall

```sh
sh keyhog-install.sh --diagnose    # print host + binary state, change nothing
sh keyhog-install.sh --repair      # re-download the right variant for this host
sh keyhog-install.sh --uninstall   # remove the binary (leaves PATH entries alone)
```

`--diagnose` is the first thing to run if something looks off: it
reports CPU arch, OS, GPU + libcuda state, the currently-installed
binary (path + version), whether the install dir is on `PATH`, and
the asset the installer would download for the latest release tag.

`--repair` re-downloads the asset matching your current host even if
the existing binary still runs. Useful after a host upgrade adds a
new GPU, or after CUDA userland gets installed and the WGPU build
should be swapped for the CUDA build.

`--uninstall` only removes the binary itself. Shell `PATH` entries
and completion files added by the post-install wizard are left in
place: we don't know which lines in your `.bashrc` / `.zshrc` are
ours vs yours, and silently editing those files is exactly the kind
of installer behavior we don't want.

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

Not yet. KeyHog vendors `vyre-libs` (the GPU literal-set scan crate)
and isn't published to crates.io until that dependency lands there.
Track the
[crates.io publish issue](https://github.com/santhsecurity/keyhog/issues?q=is%3Aissue+crates.io)
for status.

## Verify the install

```sh
keyhog --version
keyhog detectors | head     # smoke-test the embedded detector corpus
keyhog scan README.md       # scan a single file; exit 0 = clean
```

If `keyhog --version` reports `0.5.30` (or whatever the latest
release is) and `keyhog detectors` lists hundreds of detectors,
you're set. Move on to [Your first scan](./first-scan.md).

You can also run the installer in diagnostic mode at any time to
print a full status report:

```sh
sh keyhog-install.sh --diagnose
```
