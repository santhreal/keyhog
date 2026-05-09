#!/usr/bin/env bash
# Vendor a clean snapshot of the latest stable vyre release into
# `vendor/vyre/`, scoped to just the vyre-* subdirs we depend on.
#
# Why scoped: the keyhog vendor tree carries hand-edited supporting
# files (workspace Cargo.toml, AGENTS.md, scripts/, etc.) that don't
# correspond to anything upstream. A naive `cp -a` would clobber
# them. This script only replaces directories whose name matches
# `vyre-*` and writes a VENDOR_INFO.txt so the next reviewer can
# tell exactly which upstream commit landed.
#
# Usage:
#   scripts/vendor-vyre.sh                # latest semver tag, default repo
#   scripts/vendor-vyre.sh --ref v0.6.0   # pin to an explicit ref
#   scripts/vendor-vyre.sh --ref HEAD     # current upstream tip
#   VYRE_REPO=/path/to/vyre scripts/vendor-vyre.sh
#
# Source location resolution: VYRE_REPO env var > --repo flag >
# autodiscover from common sibling layouts. No personal absolute
# paths are baked into this script.

set -euo pipefail

# Anchor to the keyhog repo root regardless of where the script is invoked from.
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
KEYHOG_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"
VENDOR_DIR="${KEYHOG_ROOT}/vendor/vyre"

# Walk a few well-known sibling layouts (standalone clone next to
# keyhog, or vyre as a subtree of a Santh-style monorepo). First
# match wins; the user can always override with VYRE_REPO=... or
# --repo <path>.
default_vyre_repo() {
    local candidates=(
        "$(dirname "${KEYHOG_ROOT}")/vyre"
        "$(dirname "${KEYHOG_ROOT}")/Santh/libs/performance/matching/vyre"
        "${HOME}/code/vyre"
        "${HOME}/src/vyre"
        "${HOME}/Santh/libs/performance/matching/vyre"
        "${HOME}/santh/libs/performance/matching/vyre"
    )
    for c in "${candidates[@]}"; do
        if [[ -d "${c}" ]] && git -C "${c}" rev-parse --show-toplevel >/dev/null 2>&1; then
            echo "${c}"
            return 0
        fi
    done
    return 1
}

VYRE_REPO="${VYRE_REPO:-}"
REF=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ref)
            REF="$2"
            shift 2
            ;;
        --repo)
            VYRE_REPO="$2"
            shift 2
            ;;
        -h|--help)
            sed -n '2,18p' "$0"
            exit 0
            ;;
        *)
            echo "unknown arg: $1" >&2
            exit 2
            ;;
    esac
done

if [[ -z "${VYRE_REPO}" ]]; then
    if ! VYRE_REPO=$(default_vyre_repo); then
        echo "error: vyre source repo not found in any default location." >&2
        echo "       export VYRE_REPO=/path/to/vyre  or  pass --repo <path>" >&2
        exit 2
    fi
fi

# vyre may live inside a larger monorepo rather than as its own
# standalone git repo, so resolve the toplevel and remember the
# subpath that gets it back.
if ! GIT_TOPLEVEL=$(git -C "${VYRE_REPO}" rev-parse --show-toplevel 2>/dev/null); then
    echo "error: VYRE_REPO is not inside a git repo: ${VYRE_REPO}" >&2
    echo "       set VYRE_REPO=/path/to/vyre or pass --repo <path>" >&2
    exit 2
fi
VYRE_SUBPATH=$(realpath --relative-to="${GIT_TOPLEVEL}" "${VYRE_REPO}")
if [[ "${VYRE_SUBPATH}" == "." ]]; then
    VYRE_SUBPATH=""
fi
PATH_PREFIX=""
if [[ -n "${VYRE_SUBPATH}" ]]; then
    PATH_PREFIX="${VYRE_SUBPATH}/"
fi
if [[ ! -d "${VENDOR_DIR}" ]]; then
    echo "error: vendor directory not found: ${VENDOR_DIR}" >&2
    echo "       run this script from within a keyhog checkout" >&2
    exit 2
fi

# Refresh tags non-destructively. `--prune-tags` would delete local-only
# tags upstream removed; we deliberately don't pass it because a CI
# user might keep an annotated test tag.
echo "→ fetching tags from ${GIT_TOPLEVEL}"
git -C "${GIT_TOPLEVEL}" fetch --tags --quiet 2>/dev/null || true

# Resolve target ref: explicit --ref wins, otherwise latest semver tag,
# otherwise upstream HEAD. When vyre lives inside a monorepo we look
# for tags shaped `v<semver>` OR `vyre-v<semver>` so a project-scoped
# tagging convention works either way.
if [[ -z "${REF}" ]]; then
    REF=$(git -C "${GIT_TOPLEVEL}" tag --list 'vyre-v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n 1)
    if [[ -z "${REF}" ]]; then
        REF=$(git -C "${GIT_TOPLEVEL}" tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | head -n 1)
    fi
fi
if [[ -z "${REF}" ]]; then
    REF="HEAD"
fi
echo "→ vendoring ref: ${REF}"

if ! SHA=$(git -C "${GIT_TOPLEVEL}" rev-parse --verify "${REF}^{commit}" 2>/dev/null); then
    echo "error: ref '${REF}' not resolvable in ${GIT_TOPLEVEL}" >&2
    exit 2
fi
SHORT_SHA=$(git -C "${GIT_TOPLEVEL}" rev-parse --short "${REF}^{commit}")
COMMIT_DATE=$(git -C "${GIT_TOPLEVEL}" show -s --format=%ci "${SHA}")
COMMIT_SUBJECT=$(git -C "${GIT_TOPLEVEL}" show -s --format=%s "${SHA}")

# Enumerate the vyre-* subdirs that exist at the chosen ref. Anything
# else under vendor/vyre/ (workspace Cargo.toml, READMEs, AGENTS.md,
# helper scripts, weir/, shared/, etc.) is preserved as-is.
mapfile -t SUBDIRS < <(
    git -C "${GIT_TOPLEVEL}" ls-tree -d --name-only "${SHA}" "${PATH_PREFIX}" \
        | sed "s|^${PATH_PREFIX}||" \
        | grep '^vyre-' \
        | sort
)
if [[ ${#SUBDIRS[@]} -eq 0 ]]; then
    echo "error: no vyre-* subdirs in ${REF}; aborting before we destroy anything" >&2
    exit 2
fi
echo "→ subdirs to refresh (${#SUBDIRS[@]}): ${SUBDIRS[*]}"

# Stage the new tree to a sibling directory FIRST so a partial extract
# can never leave the vendor tree half-populated. Atomic-rename per
# subdir at the end.
STAGE_DIR="$(mktemp -d "${VENDOR_DIR}.stage.XXXXXX")"
trap 'rm -rf "${STAGE_DIR}"' EXIT

echo "→ archiving from ${GIT_TOPLEVEL}@${SHORT_SHA} into stage"
# Compute how many path components to strip so the extracted tree
# lands as `${STAGE_DIR}/<sub>/...` regardless of how deep vyre sits
# inside the source repo.
STRIP=0
if [[ -n "${VYRE_SUBPATH}" ]]; then
    STRIP=$(awk -F'/' '{print NF}' <<< "${VYRE_SUBPATH}")
fi
for sub in "${SUBDIRS[@]}"; do
    git -C "${GIT_TOPLEVEL}" archive --format=tar "${SHA}" -- "${PATH_PREFIX}${sub}" \
        | tar -x -C "${STAGE_DIR}" --strip-components="${STRIP}"
done

# Replace each vyre-* subdir atomically. We do NOT remove the parent
# vendor/vyre directory and re-extract — that would clobber the
# adjacent files (Cargo.toml, weir/, shared/) that aren't tracked
# upstream and represent local-only build glue.
echo "→ swapping subdirs into ${VENDOR_DIR}"
for sub in "${SUBDIRS[@]}"; do
    if [[ -d "${STAGE_DIR}/${sub}" ]]; then
        OLD_BACKUP="${VENDOR_DIR}/${sub}.swap.$$"
        if [[ -d "${VENDOR_DIR}/${sub}" ]]; then
            mv "${VENDOR_DIR}/${sub}" "${OLD_BACKUP}"
        fi
        mv "${STAGE_DIR}/${sub}" "${VENDOR_DIR}/${sub}"
        rm -rf "${OLD_BACKUP}"
    fi
done

# Write a VENDOR_INFO.txt at the vendor root so the next person to
# touch this can `git blame` or grep their way back to the upstream
# commit without re-running the script. The "upstream" path is the
# user's local clone and may differ between developers; that's fine,
# the immutable identity is the commit SHA below it.
cat > "${VENDOR_DIR}/VENDOR_INFO.txt" <<EOF
upstream:    ${VYRE_REPO}
ref:         ${REF}
commit:      ${SHA}
short:       ${SHORT_SHA}
date:        ${COMMIT_DATE}
subject:     ${COMMIT_SUBJECT}
subdirs:     ${SUBDIRS[*]}
vendored_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
script:      scripts/vendor-vyre.sh

NOTE: only vyre-* subdirectories are managed by this script. Any
other file in this directory (workspace Cargo.toml, AGENTS.md,
weir/, shared/, etc.) is local to keyhog and survives re-vendoring.
EOF

echo
echo "✓ vendored vyre @ ${SHORT_SHA} (${REF})"
echo "  ${COMMIT_SUBJECT}"
echo "  ${COMMIT_DATE}"
echo "  manifest: ${VENDOR_DIR}/VENDOR_INFO.txt"
echo
echo "next steps:"
echo "  cargo build -p keyhog-scanner   # confirm the new vyre still compiles"
echo "  git add vendor/vyre && git diff --stat HEAD"
