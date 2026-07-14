# Install

The quickest paths first. Each installs the canonical release artifact for
your supported host; platform feature differences are explicit below.

## Pinned verified install: Linux / macOS

```sh
TAG=v0.5.41
BASE="https://github.com/santhreal/keyhog/releases/download/$TAG"
KEYHOG_MINISIGN_PUBLIC_KEY='RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go'
curl -fSLO "$BASE/install.sh"
curl -fSLO "$BASE/install.sh.minisig"
curl -fSLO "$BASE/install.sh.sha256"
minisign -Vm install.sh -P "$KEYHOG_MINISIGN_PUBLIC_KEY"
sha256sum -c install.sh.sha256
KEYHOG_VERSION="$TAG" sh install.sh
```

Drops a binary in `~/.local/bin/keyhog`. The installer detects the platform and
existing install before downloading and tells you the chosen asset. Linux
x86_64 has one accelerator-capable binary: Hyperscan plus VYRE's CUDA and WGPU
drivers. CUDA/NVRTC use dynamic loading, so no build-time toolkit is required
and the same artifact runs on GPU and CPU-only hosts. Backend probing and
persisted autoroute evidence, not installer variants, decide execution. macOS and
Windows assets use the portable no-system-library build without Hyperscan or GPU
drivers.

This path authenticates the versioned installer before execution. Changing the
repository's `main` branch cannot change a pinned install. On macOS, replace the
checksum command with `shasum -a 256 -c install.sh.sha256`.

## Interactive mode (recommended for first install)

The verified command above keeps stdin attached to the terminal, so it can show
the wizard for shell completions and optional hook setup. To repeat the
interactive run after verification:

```sh
KEYHOG_VERSION="$TAG" sh install.sh
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

The displayed default is authoritative: PATH setup defaults to yes, while
completion and repository-hook setup default to no. `--yes` accepts those
defaults without prompting. There is no shipped Claude Code / Cursor agent-hook
prompt or `keyhog hook install --agent <name>` flag; installer variants are not
part of the current release contract.

## Pinned verified install: Windows

PowerShell 5+ (ships with Windows 10/11):

```powershell
$Tag = 'v0.5.41'
$Base = "https://github.com/santhreal/keyhog/releases/download/$Tag"
$PublicKey = 'RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go'
iwr "$Base/install.ps1" -OutFile keyhog-install.ps1
iwr "$Base/install.ps1.minisig" -OutFile keyhog-install.ps1.minisig
iwr "$Base/install.ps1.sha256" -OutFile keyhog-install.ps1.sha256
minisign -Vm keyhog-install.ps1 -x keyhog-install.ps1.minisig -P $PublicKey
$Expected = (Get-Content keyhog-install.ps1.sha256).Split()[0].ToLowerInvariant()
$Actual = (Get-FileHash keyhog-install.ps1 -Algorithm SHA256).Hash.ToLowerInvariant()
if ($Actual -ne $Expected) { throw 'installer checksum mismatch' }
& .\keyhog-install.ps1 -Version $Tag
```

Drops the binary in `%LOCALAPPDATA%\keyhog\bin\keyhog.exe`. Detects
your GPU for diagnostics; the Windows installer ships the portable
no-system-library build, with no Hyperscan, WGPU, or CUDA asset in the
current release.

For an unpinned development checkout of the installer:

```powershell
iwr https://raw.githubusercontent.com/santhreal/keyhog/main/install.ps1 `
    -OutFile keyhog-install.ps1
.\keyhog-install.ps1
```

> **Heads up.** The Unix daemon mode is unavailable on Windows (it
> relies on Unix-domain sockets). `keyhog scan`, `keyhog detectors`,
> `keyhog watch`, `keyhog hook`, etc. all work the same. The `daemon`
> subcommand and explicit `--daemon=auto|on` emit an explicit "unix-only"
> error so nothing silently regresses. `--daemon=off` remains a valid portable
> declaration of in-process scanning.

## Installer overrides

| Env var / flag                          | Effect                                                        |
|-----------------------------------------|---------------------------------------------------------------|
| `KEYHOG_VERSION=v0.5.41` (or `--version=v0.5.41`) | Pin a specific release tag. With no pin, the installer admits only the newest stable release with this host's complete signed bundle; it probes the latest redirect first, then checks recent releases when that proof is incomplete. |
| `--install-dir=...`                     | Install into a different directory.            |
| `GITHUB_TOKEN=...`                      | Optional auth for the fallback GitHub releases API lookup. The normal latest-asset path does not need it. |
| `--yes` / `-y`                          | Accept the displayed defaults without prompting: PATH setup yes, optional completion and repository hook no. |
| `--no-color`                            | Disable ANSI colors (e.g. for log capture).                   |
| `--from-file=/path/to/asset`            | Offline / air-gapped install from a pre-downloaded complete host bundle. The installer requires sibling `.sha256` files unless `--insecure` accepts missing checksum proof; verify the downloaded `.minisig` files manually as shown below before invoking the local path. |
| `--calibrate`                           | Re-run the installer's visible autoroute calibration sweep against the already-installed binary, without replacing that binary. |
| `--insecure`                            | Emergency-only: proceed when signature/checksum *proof is missing*. A present-but-wrong signature or checksum is always fatal, `--insecure` or not. |

The table uses Unix spellings. The PowerShell equivalents are `-Version`,
`-InstallDir`, `-Yes`, `-NoColor`, `-FromFile`, `-Calibrate`, and `-Insecure`;
environment variables keep the same names. PowerShell also exposes the matching
`-Diagnose`, `-Repair`, and `-Uninstall` modes.

### Download integrity

Every downloaded asset is verified before it replaces anything: a minisign
signature check against the pinned release public key, then a SHA-256
checksum, for both the binary and the GPU literal sidecar (which is also
hardened against path traversal and symlink escapes). Verification runs on the
freshly downloaded file in a temporary location, so a binary that fails either
check is deleted and never installed.

Verification fails closed by default. If the signature or checksum cannot be
obtained or does not verify, the install aborts rather than proceed with an
unverified binary. Passing `--insecure` (`-Insecure` on Windows) is the only way
to accept an unverified binary, and it is intended for emergency or local
diagnostics, not routine installs.

The binary swap itself is recoverable: the previous binary is backed up before
the new one is moved into place and restored automatically if the new binary
fails its post-install self-test, so a failed or interrupted install leaves a
working binary behind.

Release publication uses the same exact manifest: each platform binary, its
SHA-256 file, the GPU-literal sidecar and checksum, plus detached minisign
signatures for both payloads. The versioned POSIX and PowerShell installers,
their checksums, signatures, and GitHub provenance attestations are part of that
manifest too. Matrix builds stage those files as private CI artifacts. New
releases and published-release reruns remain private while the asset set is
mutated; only the exact signed manifest is made visible.

`keyhog update` and `keyhog repair` use strict semantic-version precedence.
Their implicit latest-release lookup ignores drafts and prereleases and skips
any release that lacks the complete signed binary and GPU-literal bundle for
the current host. Use `--version <TAG>` to request an exact published tag,
including a prerelease. Release metadata, payloads, and signatures have bounded
downloads and connection/request deadlines; an oversized or stalled response
fails without changing the installed binary.

The maintenance commands validate the signed sidecar's archive paths, entry
types, expansion limits, manifest version, binary-version binding, filenames,
and byte lengths before changing local state. Matcher files are installed under
the scanner-owned cache path while the candidate binary is health-checked. A
failed artifact install or candidate check restores both the previous binary
and every replaced matcher; concurrent maintenance uses a visible cache lock.

### Post-install calibration

The installer does not report success immediately after copying the binary. It
runs `keyhog doctor`, then visibly measures every candidate enabled for each
calibrated configuration: scalar CPU and Hyperscan/SIMD where present, plus
every eligible hardware GPU. It covers the workload classes and scan-policy
presets it can materialize on that host. The resulting
decisions are written to the same per-user autoroute cache normal scans read. If
a required calibration probe fails, the install fails rather than leave
`--backend auto` pretending to be usable. Source-specific probes that require
an unavailable external tool, such as Git or a running Docker daemon, are named
as unavailable; install the tool and rerun `install.sh --calibrate` or
`install.ps1 -Calibrate` before relying on that source class.

Calibration is identity-bound to the KeyHog binary/build, detector and routing
rules, resolved scan configuration, host/backend capabilities, source class,
and workload bucket. An absent, stale, malformed, or incomplete decision is
therefore not permission to choose a convenient backend. An automatic scan
fails closed with exit `2` and an actionable recalibration message. Inspect the
current state without changing it with:

```sh
keyhog backend --autoroute
keyhog backend --autoroute --json
```

Use `keyhog calibrate-autoroute` for KeyHog's self-contained filesystem/stdin
workload sweep. Use the installer `--calibrate` mode when you also want its
environment-backed Git, URL, and container probes. An explicit
`--backend cpu|simd|gpu` bypasses the autoroute decision table for that scan;
it is a diagnostic or benchmark override, not a repair for missing evidence.

### Runtime GPU controls

| Control                  | Effect                                                                                                                                                                                                                                       |
|--------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `keyhog scan --no-gpu`   | Disable GPU initialization for this resolved scan configuration. Automatic routing still requires persisted calibration for that configuration; use an explicit CPU/SIMD backend only for diagnostics. |
| `keyhog scan --require-gpu` | Hard-fail (`exit 12`) when GPU is unavailable before scanning or a selected GPU dispatch fails at runtime. This is a diagnostic/CI assertion, separate from autoroute. Autoroute itself is not a fallback hierarchy: it selects the fastest measured-correct backend from all eligible candidates. |
| `.keyhog.toml [system].gpu = "off"` | Persist the CPU/SIMD-only policy for a repository. Use `"required"` for self-hosted GPU runners where a GPU regression must fail closed.                                                                                         |
| `keyhog scan --backend gpu-cuda\|gpu-wgpu\|simd\|cpu` | Force a specific live scan engine regardless of autoroute. Diagnostic and benchmark override only; it does not prove autoroute correctness. A selected GPU driver that cannot complete dispatch exits `12` without substituting another driver or CPU/SIMD. |

The GitHub Action calibrates the actual runner and admits only usable physical
accelerators. On self-hosted GPU runners, `--require-gpu` or
`[system].gpu = "required"` turns accelerator availability into an explicit
fail-closed requirement; it does not choose GPU over a faster calibrated peer.

### Daemon policy after installation

Installation and calibration do not start a daemon. On Unix, manage the
optional foreground warm scanner explicitly:

```sh
keyhog daemon start
keyhog daemon status
keyhog daemon stop
```

An omitted scan flag means `--daemon=auto` on Unix. Bare `--daemon` means
`--daemon=on`; `--daemon=off` always runs in process. See
[Daemon and warm scans](workflows/daemon.md) for the canonical activation,
eligibility, retry, identity, shutdown, socket, coverage, and exit contract.

## Repair, diagnose, uninstall

```sh
sh keyhog-install.sh --diagnose    # print host + binary state, change nothing
sh keyhog-install.sh --repair      # re-download the right asset for this host
sh keyhog-install.sh --uninstall   # remove the binary + installer-owned shell wiring
```

`--diagnose` is the first thing to run if something looks off: it
reports CPU arch, OS, GPU + libcuda state, the currently-installed
binary (path + version), whether the install dir is on `PATH`, and
the asset the installer would download for the latest release tag.

`--repair` re-downloads the asset matching your current platform even if
the existing binary still runs. The unified Linux binary probes CUDA and WGPU
at runtime, so installing a GPU or CUDA userland does not require replacing it
with a different artifact.

`--uninstall` removes the binary, asks an installed `keyhog uninstall --yes`
to surface/clean persisted state first when that subcommand is available,
then removes only the shell artifacts the installer owns: its marked `PATH`
block and the known bash/zsh/fish completion files.

On Unix, the running binary can unlink itself. Windows does not allow a running
`.exe` to delete itself, so direct `keyhog uninstall --yes` exits `2` and prints
the exact executable path to remove after the process exits. The PowerShell
installer performs that outer-process cleanup for the normal uninstall flow.

## Direct binary download

If you do not trust pipe-to-shell, download and inspect the installer first, or
obtain the complete host bundle from the
[releases page](https://github.com/santhreal/keyhog/releases/latest).

| Platform              | Asset name                       |
|-----------------------|----------------------------------|
| Linux x86_64 (default)| `keyhog-linux-x86_64`            |
| macOS x86_64 (Intel)  | `keyhog-macos-x86_64`            |
| macOS aarch64 (Apple) | `keyhog-macos-aarch64`           |
| Windows x86_64        | `keyhog-windows-x86_64.exe`      |

For an asset named `<asset>`, the complete host bundle is:

- `<asset>`, `<asset>.sha256`, and `<asset>.minisig`;
- `<asset>.gpu-literals.tar.gz`, its `.sha256`, and its `.minisig`.

Verify both payload signatures with minisign and both SHA-256 files before
installing. The offline installer path then performs its own checksum checks,
safe sidecar extraction, atomic replacement, health check, and rollback:

```sh
ASSET=/absolute/path/to/keyhog-linux-x86_64
KEYHOG_MINISIGN_PUBLIC_KEY='RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go'
minisign -Vm "$ASSET" -P "$KEYHOG_MINISIGN_PUBLIC_KEY"
minisign -Vm "$ASSET.gpu-literals.tar.gz" -P "$KEYHOG_MINISIGN_PUBLIC_KEY"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$(dirname "$ASSET")" && sha256sum -c "$(basename "$ASSET").sha256")
  (cd "$(dirname "$ASSET")" && sha256sum -c "$(basename "$ASSET").gpu-literals.tar.gz.sha256")
else
  (cd "$(dirname "$ASSET")" && shasum -a 256 -c "$(basename "$ASSET").sha256")
  (cd "$(dirname "$ASSET")" && shasum -a 256 -c "$(basename "$ASSET").gpu-literals.tar.gz.sha256")
fi
sh keyhog-install.sh --from-file="$ASSET"
```

Release workflows also publish GitHub build-provenance attestations for both
payloads. With a GitHub CLI version that provides `gh attestation`, this online
check proves that GitHub-hosted `release.yml` attested the exact bytes for the
requested tag. It does not by itself prove the Cargo feature or profile policy.
It complements the detached minisign signatures, which remain the installer's
offline trust root:

```sh
TAG=v0.5.41
gh attestation verify "$ASSET" --repo santhreal/keyhog \
  --signer-workflow github.com/santhreal/keyhog/.github/workflows/release.yml \
  --source-ref "refs/tags/$TAG" --deny-self-hosted-runners
gh attestation verify "$ASSET.gpu-literals.tar.gz" --repo santhreal/keyhog \
  --signer-workflow github.com/santhreal/keyhog/.github/workflows/release.yml \
  --source-ref "refs/tags/$TAG" --deny-self-hosted-runners
```

On Windows, use
`./keyhog-install.ps1 -FromFile C:\absolute\path\to\keyhog-windows-x86_64.exe`.
Verify each payload's `.minisig` first and keep each `.sha256` sibling beside
its payload. Do not install only the binary and silently omit the release-bound
GPU literal sidecar.

## Build from source

You'll want this if you're contributing or running a feature
combination the prebuilt binaries don't cover (e.g. Ghidra binary
extraction).

```sh
git clone https://github.com/santhreal/keyhog
cd keyhog
cargo build --release -p keyhog
./target/release/keyhog --version
```

The default feature set requires **Hyperscan / Vectorscan**:

- Debian / Ubuntu: `sudo apt install libhyperscan-dev pkg-config`
- macOS: `brew install vectorscan pkg-config`, then use the default build for
  the Hyperscan path. Use `--no-default-features --features portable` only for
  the no-system-library build used by the official macOS asset.
- Windows: build with `--no-default-features --features portable`.

The default Linux build includes the dynamically loaded CUDA and WGPU backends:

```sh
cargo build --release -p keyhog
```

CUDA is attempted only when its runtime libraries and a compatible device are
present. On Linux, scanner construction acquires CUDA first and tries WGPU only
when CUDA acquisition fails. That acquisition failure is reported. It is not a
scan-time backend substitution. `keyhog backend --self-test --json` reports the
acquired runtime state, and autoroute calibration determines whether that GPU
route is eligible against the CPU candidates.

The `portable` feature is what the official Windows + macOS release
binaries are built with. It keeps the portable scanner data paths without
native Hyperscan, GPU, or Ghidra dependencies. Throughput varies by host and
workload; benchmark the intended scan class instead of applying a fixed ratio.

## crates.io

KeyHog consumes the published VYRE runtime crates from crates.io through exact
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
