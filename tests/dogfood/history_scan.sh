#!/usr/bin/env bash
# Git-history dogfood lane.
#
# CI fetches full history, and the repository dogfood lanes scan only the
# working tree. A credential committed and later deleted is invisible to both,
# so "the self-scan is clean" has never meant "no credential was ever
# committed". This lane scans the history scope explicitly.
#
# It also proves the scope actually works before trusting a clean result: it
# builds a scratch repository whose credential exists only in a parent commit
# and requires the scan to report it with the exact commit and path. A history
# scope that silently returned nothing would otherwise look identical to a
# clean history.
#
# usage: history_scan.sh <keyhog-binary> [manifest-dir] [max-commits]
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "usage: $0 <keyhog-binary> [manifest-dir] [max-commits]" >&2
  exit 2
fi

binary=$(realpath "$1")
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest_dir=${2:-${RUNNER_TEMP:-/tmp}/keyhog-dogfood-history}
max_commits=${3:-500}
mkdir -p "$manifest_dir"

report="$manifest_dir/history-report.json"
trace="$manifest_dir/history-report.trace.log"
manifest="$manifest_dir/history-coverage.json"

# --- Scope proof -------------------------------------------------------------
# A credential that exists ONLY in a parent commit must come back with its
# exact commit and path. The value carries real entropy on purpose: a
# low-entropy placeholder is suppressed as degenerate and the proof would pass
# for the wrong reason.
probe_repo="$manifest_dir/scope-probe"
probe_value='sk_live_pjQRKxbggvjggR8SgFDLxNmvVKn3f0PQIbCk'
rm -rf "$probe_repo"
mkdir -p "$probe_repo"
(
  cd "$probe_repo"
  git init -q .
  git config user.email dogfood@keyhog.invalid
  git config user.name "keyhog dogfood"
  echo "no credential here" >readme.txt
  git add -A && git commit -qm "base"
  printf 'STRIPE_SECRET_KEY=%s\n' "$probe_value" >deleted-later.env
  git add -A && git commit -qm "leak"
  git rm -q deleted-later.env
  git commit -qm "remove the leak from the working tree"
)

probe_worktree="$manifest_dir/scope-probe-worktree.json"
probe_history="$manifest_dir/scope-probe-history.json"
"$binary" scan "$probe_repo" --no-config --daemon=off \
  --format json --output "$probe_worktree" >/dev/null 2>&1 || true
"$binary" scan --git-history "$probe_repo" --no-config --daemon=off \
  --format json --output "$probe_history" >/dev/null 2>&1 || true

if [[ "$(jq 'length' "$probe_worktree")" -ne 0 ]]; then
  echo "history lane self-check broken: the probe leaks into the working tree" >&2
  exit 2
fi

probe_hit=$(jq -r '
  [.[] | select(.location.file_path == "deleted-later.env"
                and (.location.commit | type == "string")
                and (.location.commit | length) > 0)] | length' "$probe_history")
if [[ "$probe_hit" -eq 0 ]]; then
  echo "history scope FAILED its own proof: a credential present only in a parent" >&2
  echo "commit was not reported with an exact commit and path. A clean result from" >&2
  echo "this lane would mean nothing." >&2
  jq -r '.[] | "  \(.detector_id) \(.location.commit) \(.location.file_path)"' \
    "$probe_history" >&2
  exit 1
fi
rm -rf "$probe_repo"

# --- Repository history scan --------------------------------------------------
set +e
(cd "$repo_root" && "$binary" scan --git-history . \
  --max-commits "$max_commits" --no-config --daemon=off \
  --format json --output "$report" 2>"$trace")
status=$?
set -e

# Same rule as the strict lane: an incomplete history walk still recovered real
# credentials from the commits it did reach, and discarding them is the wrong
# trade. Report them, then fail with the reason coverage was incomplete.
if [[ $status -gt 1 ]]; then
  echo "repository history dogfood did not complete: exit=$status" >&2
  recovered=0
  if [[ -s "$report" ]] && jq -e 'type == "array"' "$report" >/dev/null 2>&1; then
    recovered=$(jq 'length' "$report")
  fi
  echo "$recovered credential(s) were recovered before the failure and are NOT discarded:" >&2
  if [[ "$recovered" -gt 0 ]]; then
    jq -r '.[] | "  \(.credential_hash)  \(.detector_id)  \(.location.commit)  \(.location.file_path):\(.location.line)"' \
      "$report" >&2
  fi
  echo "coverage gap: the remaining commits in the requested range were not walked. Reason:" >&2
  tail -n 40 "$trace" >&2
  exit "$status"
fi

findings=$(jq 'length' "$report")
jq -n \
  --arg lane history \
  --argjson commits "$max_commits" \
  --argjson findings "$findings" \
  --arg scope "git-history" \
  --slurpfile report "$report" \
  '{lane: $lane, scope: $scope, max_commits: $commits, findings: $findings,
    commits_with_findings: ($report[0] | map(.location.commit) | unique | length),
    paths: ($report[0] | map(.location.file_path) | unique)}' >"$manifest"

if [[ "$findings" -ne 0 ]]; then
  echo "history dogfood found $findings credential(s) in the last $max_commits commit(s):" >&2
  jq -r '.[] | "  \(.credential_hash)  \(.detector_id)  \(.location.commit)  \(.location.file_path):\(.location.line)"' \
    "$report" >&2
  echo "Each one is a credential that was committed at some point. Rotate it, then" >&2
  echo "register the value hash in .keyhogignore with reason= and approved_by=." >&2
  exit 1
fi

echo "history dogfood OK: scope proof passed, 0 credential(s) in the last $max_commits commit(s)"
echo "coverage manifest: $manifest"
