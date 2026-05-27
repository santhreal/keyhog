#!/usr/bin/env sh
#
# keyhog install script — Linux + macOS.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | sh
#
# Or with explicit install location:
#   curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | KEYHOG_INSTALL=/usr/local/bin sh
#
# Detects OS + CPU arch, fetches the corresponding binary from the
# latest GitHub release, drops it in $KEYHOG_INSTALL (default:
# ~/.local/bin), and chmods it executable. No system-wide install,
# no sudo, no daemons started.

set -eu

REPO="santhsecurity/keyhog"
INSTALL_DIR="${KEYHOG_INSTALL:-$HOME/.local/bin}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$OS-$ARCH" in
  linux-x86_64)        ASSET="keyhog-linux-x86_64" ;;
  linux-amd64)         ASSET="keyhog-linux-x86_64" ;;
  darwin-x86_64)       ASSET="keyhog-macos-x86_64" ;;
  darwin-amd64)        ASSET="keyhog-macos-x86_64" ;;
  darwin-arm64)        ASSET="keyhog-macos-aarch64" ;;
  darwin-aarch64)      ASSET="keyhog-macos-aarch64" ;;
  *)
    echo "ERROR: unsupported platform: $OS-$ARCH" >&2
    echo "Supported: linux-x86_64, darwin-x86_64 (Intel Mac), darwin-arm64 (Apple Silicon)." >&2
    echo "On Windows, use install.ps1 instead." >&2
    exit 1
    ;;
esac

# Pick the tag. KEYHOG_VERSION=v0.5.25 sh install.sh pins a specific
# release; otherwise we ask the GitHub API for the latest published
# tag. The API call is unauthenticated and rate-limited at 60/hour
# per IP, which is fine for one-shot installs.
if [ -n "${KEYHOG_VERSION:-}" ]; then
    TAG="$KEYHOG_VERSION"
else
    TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' \
        | head -n 1)
    if [ -z "$TAG" ]; then
        echo "ERROR: could not resolve latest release tag from GitHub API." >&2
        echo "Try setting KEYHOG_VERSION=v0.5.25 (or another known tag) explicitly." >&2
        exit 1
    fi
fi

URL="https://github.com/$REPO/releases/download/$TAG/$ASSET"
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT INT TERM

printf 'keyhog: downloading %s\n' "$URL"
if ! curl -fsSL "$URL" -o "$TMP"; then
    echo "ERROR: download failed. Is the release published yet?" >&2
    echo "Browse https://github.com/$REPO/releases to confirm the asset exists." >&2
    exit 1
fi

mkdir -p "$INSTALL_DIR"
mv "$TMP" "$INSTALL_DIR/keyhog"
chmod +x "$INSTALL_DIR/keyhog"

printf 'keyhog: installed %s to %s/keyhog\n' "$TAG" "$INSTALL_DIR"
"$INSTALL_DIR/keyhog" --version

# Friendly PATH hint — don't pollute shell rc files, just tell the
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
