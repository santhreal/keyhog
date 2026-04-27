#!/usr/bin/env bash
# Architectural invariant guard for vyre.
#
# Vyre's design contract (see THESIS.md) requires core to own nothing but the
# graph structure and the trait contracts. The moment vyre-core, vyre-ir,
# vyre-primitives, or vyre-reference declares a real dependency on a backend
# crate or on vyre-conform, the substrate-neutral claim collapses: the
# "abstract" IR would require a specific backend to compile. This script
# enforces the contract at CI time and fails any PR that violates it.
#
# Dev-dependencies are allowed — tests that exercise cross-crate integration
# are still a legitimate part of the workspace. What is forbidden is a
# NON-dev dependency edge: anything that would force a downstream consumer
# of the core crates to pull a backend or the conformance harness.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Crates that MUST stay substrate-neutral. A violation in any of these is
# a rebuild regression, not a style nit.
PURE_CRATES=(
  "vyre-core"
  "vyre-ir"
  "vyre-primitives"
  "vyre-reference"
  "vyre-spec"
)

# Crates that the pure crates must never depend on (outside dev-dependencies).
FORBIDDEN_DEPS=(
  "vyre-wgpu"
  "vyre-conform"
  "vyre-conform-spec"
  "vyre-conform-generate"
  "vyre-conform-enforce"
  "vyre-conform-runner"
  "wgpu"
  "naga"
)

violations=0

for crate in "${PURE_CRATES[@]}"; do
  manifest="$REPO_ROOT/$crate/Cargo.toml"
  if [[ ! -f "$manifest" ]]; then
    # Crate may not exist yet in the rebuild; skip silently. When it lands,
    # this guard starts enforcing.
    continue
  fi

  # Extract the [dependencies] and [build-dependencies] sections only.
  # [dev-dependencies] are intentionally permitted.
  pure_deps="$(awk '
    /^\[dependencies\]/          { inside=1; next }
    /^\[build-dependencies\]/    { inside=1; next }
    /^\[dev-dependencies\]/      { inside=0; next }
    /^\[target\.[^]]+\.dev-dependencies\]/ { inside=0; next }
    /^\[target\.[^]]+\.dependencies\]/     { inside=1; next }
    /^\[target\.[^]]+\.build-dependencies\]/ { inside=1; next }
    /^\[/                        { inside=0; next }
    inside && NF > 0             { print }
  ' "$manifest")"

  for forbidden in "${FORBIDDEN_DEPS[@]}"; do
    if echo "$pure_deps" | grep -qE "^[[:space:]]*\"?${forbidden}\"?[[:space:]]*="; then
      echo "ARCH VIOLATION: $crate depends on $forbidden outside [dev-dependencies]." >&2
      echo "  Manifest: $manifest" >&2
      echo "  Pure crates must stay substrate-neutral per THESIS.md." >&2
      echo "  Fix: move the dependency under [dev-dependencies] or, if the" >&2
      echo "  usage is non-test, relocate the code to a downstream crate." >&2
      violations=$((violations + 1))
    fi
  done
done

# A second invariant: vyre-wgpu must not declare vyre-ir / vyre-primitives /
# vyre-reference by path. Repo-split readiness requires version declarations.
# This invariant activates once vyre-ir exists — before then it is a no-op.
if [[ -f "$REPO_ROOT/vyre-ir/Cargo.toml" ]]; then
  for backend in vyre-wgpu; do
    manifest="$REPO_ROOT/$backend/Cargo.toml"
    if [[ ! -f "$manifest" ]]; then
      continue
    fi
    if grep -qE '^[[:space:]]*vyre-ir[[:space:]]*=[[:space:]]*\{[^}]*path[[:space:]]*=' "$manifest"; then
      echo "ARCH VIOLATION: $backend declares vyre-ir with a path dependency." >&2
      echo "  Repo-split readiness requires a version dependency with" >&2
      echo "  workspace-level [patch.crates-io] overriding it locally." >&2
      echo "  Manifest: $manifest" >&2
      violations=$((violations + 1))
    fi
  done
fi

if [[ "$violations" -gt 0 ]]; then
  echo "" >&2
  echo "Architectural invariants failed: $violations violation(s)." >&2
  echo "See THESIS.md for the substrate-neutrality contract." >&2
  exit 1
fi

echo "Architectural invariants: all $(printf '%s\n' "${PURE_CRATES[@]}" | wc -l | tr -d ' ') pure crates clean."
