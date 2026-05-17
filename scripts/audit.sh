#!/usr/bin/env bash
# Wrapper around `cargo audit` that applies the four ignores we have
# accept-with-rationale write-ups for in `audit.toml` + `SECURITY.md`.
#
# `cargo audit` 0.22 doesn't auto-load `audit.toml` from the project
# root (it only honours `~/.cargo/audit.toml`), so the CI workflow and
# this helper need to keep the ignore list in sync.
#
# Usage: scripts/audit.sh [extra cargo-audit flags...]
set -euo pipefail
exec cargo audit \
    --ignore RUSTSEC-2023-0071 \
    --ignore RUSTSEC-2024-0436 \
    --ignore RUSTSEC-2026-0002 \
    --ignore RUSTSEC-2026-0097 \
    "$@"
