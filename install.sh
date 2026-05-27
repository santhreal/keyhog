#!/usr/bin/env sh
#
# keyhog install script (Linux + macOS).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | sh
#
# Or with an explicit install location:
#   curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | KEYHOG_INSTALL=/usr/local/bin sh
#
# What it does:
#   - Detects OS, CPU arch, and (on Linux) whether an NVIDIA GPU plus
#     a loadable libcuda.so are present.
#   - Picks the fastest binary variant the host can actually run.
#   - Falls back gracefully if the optimal variant isn't published
#     for the resolved tag yet.
#   - Drops the binary in $KEYHOG_INSTALL (default ~/.local/bin) and
#     chmods it executable. No sudo, no daemons.
#
# Overrides:
#   KEYHOG_VERSION=v0.5.29   pin a specific release tag.
#   KEYHOG_VARIANT=cuda      force the CUDA build (Linux only).
#   KEYHOG_VARIANT=cpu       skip GPU detection, install the default
#                            (WGPU + SIMD) build.
#   KEYHOG_INSTALL=/path     change the install directory.

set -eu

REPO="santhsecurity/keyhog"
INSTALL_DIR="${KEYHOG_INSTALL:-$HOME/.local/bin}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# detect_linux_cuda: prints "yes" if both an NVIDIA GPU AND a loadable
# libcuda.so are present, "missing-lib" if a GPU is present but the
# CUDA userland is not installed, "no-gpu" otherwise.
detect_linux_cuda() {
    if ! command -v nvidia-smi >/dev/null 2>&1; then
        if [ -d /proc/driver/nvidia ]; then
            echo "missing-tools"
            return
        fi
        echo "no-gpu"
        return
    fi
    if ! nvidia-smi -L 2>/dev/null | grep -q "GPU "; then
        echo "no-gpu"
        return
    fi
    # libcuda.so is the userland driver shim that vyre-driver-cuda
    # dlopens at runtime. ldconfig is the cheapest cross-distro probe.
    if ldconfig -p 2>/dev/null | grep -q "libcuda\.so"; then
        echo "yes"
        return
    fi
    for p in /usr/lib/x86_64-linux-gnu/libcuda.so /usr/lib64/libcuda.so \
             /usr/local/cuda/lib64/libcuda.so /opt/cuda/lib64/libcuda.so; do
        if [ -e "$p" ]; then
            echo "yes"
            return
        fi
    done
    echo "missing-lib"
}

# Pick the asset. We resolve to a single canonical name; the
# tag-resolution + download step retries on the base asset if the
# preferred variant 404s.
ASSET=""
ASSET_FALLBACK=""
GPU_NOTE=""

case "$OS-$ARCH" in
  linux-x86_64|linux-amd64)
    if [ "${KEYHOG_VARIANT:-}" = "cpu" ]; then
        ASSET="keyhog-linux-x86_64"
        GPU_NOTE="KEYHOG_VARIANT=cpu, installing default build (WGPU + SIMD)."
    elif [ "${KEYHOG_VARIANT:-}" = "cuda" ]; then
        ASSET="keyhog-linux-x86_64-cuda"
        ASSET_FALLBACK="keyhog-linux-x86_64"
        GPU_NOTE="KEYHOG_VARIANT=cuda, installing CUDA-accelerated build."
    else
        case "$(detect_linux_cuda)" in
          yes)
            ASSET="keyhog-linux-x86_64-cuda"
            ASSET_FALLBACK="keyhog-linux-x86_64"
            gpu=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -n 1)
            GPU_NOTE="Detected NVIDIA GPU (${gpu:-unknown}) with libcuda.so. Installing CUDA build, which is significantly faster than the WGPU fallback on large scans."
            ;;
          missing-lib)
            ASSET="keyhog-linux-x86_64"
            GPU_NOTE="Detected NVIDIA GPU but libcuda.so is not loadable. Installing default WGPU build; for the faster CUDA path install the NVIDIA driver + CUDA userland, then rerun this script."
            ;;
          missing-tools)
            ASSET="keyhog-linux-x86_64"
            GPU_NOTE="NVIDIA driver appears present but nvidia-smi is missing. Installing default WGPU build; install nvidia-utils + libcuda1 to enable the CUDA path."
            ;;
          *)
            ASSET="keyhog-linux-x86_64"
            GPU_NOTE="No NVIDIA GPU detected. Installing default build (WGPU fallback for any compatible discrete adapter, SIMD on the CPU path)."
            ;;
        esac
    fi
    ;;
  darwin-arm64|darwin-aarch64)
    ASSET="keyhog-macos-aarch64"
    GPU_NOTE="Apple Silicon detected. Native Metal GPU acceleration is on the roadmap; the current build runs SIMD on CPU plus the WGPU GPU path (slower than a CUDA build on equivalent NVIDIA hardware for very large scans, but plenty fast for typical use)."
    ;;
  darwin-x86_64|darwin-amd64)
    ASSET="keyhog-macos-x86_64"
    GPU_NOTE="Intel Mac detected. The current build runs SIMD on CPU plus the WGPU GPU path on a compatible discrete adapter. Metal GPU acceleration is on the roadmap."
    ;;
  *)
    echo "ERROR: unsupported platform: $OS-$ARCH" >&2
    echo "Supported: linux-x86_64, darwin-x86_64 (Intel Mac), darwin-arm64 (Apple Silicon)." >&2
    echo "On Windows use install.ps1 instead." >&2
    exit 1
    ;;
esac

# Pick the tag. KEYHOG_VERSION=v0.5.29 pins a specific release;
# otherwise ask the GitHub API for the latest published tag. The API
# call is unauthenticated and rate-limited at 60/hour per IP, which
# is fine for one-shot installs.
if [ -n "${KEYHOG_VERSION:-}" ]; then
    TAG="$KEYHOG_VERSION"
else
    TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' \
        | head -n 1)
    if [ -z "$TAG" ]; then
        echo "ERROR: could not resolve latest release tag from GitHub API." >&2
        echo "Try setting KEYHOG_VERSION=v0.5.29 (or another known tag) explicitly." >&2
        exit 1
    fi
fi

echo "keyhog: $GPU_NOTE"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT INT TERM

# download_asset NAME: returns 0 on success, 1 on 404 / failure.
download_asset() {
    name="$1"
    url="https://github.com/$REPO/releases/download/$TAG/$name"
    printf 'keyhog: downloading %s\n' "$url"
    if curl -fsSL "$url" -o "$TMP"; then
        return 0
    fi
    return 1
}

if ! download_asset "$ASSET"; then
    if [ -n "$ASSET_FALLBACK" ] && [ "$ASSET_FALLBACK" != "$ASSET" ]; then
        echo "keyhog: $ASSET not published for $TAG yet, falling back to $ASSET_FALLBACK."
        if ! download_asset "$ASSET_FALLBACK"; then
            echo "ERROR: neither $ASSET nor $ASSET_FALLBACK could be downloaded for $TAG." >&2
            echo "Browse https://github.com/$REPO/releases to confirm the asset exists." >&2
            exit 1
        fi
    else
        echo "ERROR: download failed. Is the release published yet?" >&2
        echo "Browse https://github.com/$REPO/releases to confirm the asset exists." >&2
        exit 1
    fi
fi

mkdir -p "$INSTALL_DIR"
mv "$TMP" "$INSTALL_DIR/keyhog"
chmod +x "$INSTALL_DIR/keyhog"

printf 'keyhog: installed %s to %s/keyhog\n' "$TAG" "$INSTALL_DIR"
"$INSTALL_DIR/keyhog" --version

# Friendly PATH hint - don't pollute shell rc files, just tell the
# user what to add if their PATH doesn't already include the install
# dir.
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    echo
    echo "NOTE: $INSTALL_DIR is not in your PATH."
    echo "      Add it with: export PATH=\"$INSTALL_DIR:\$PATH\""
    ;;
esac
