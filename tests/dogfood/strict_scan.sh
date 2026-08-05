#!/usr/bin/env bash
# Strict repository dogfood lane.
#
# The operator lane (`repository_scan.sh` + `.keyhogignore`) excludes five
# fixture-heavy trees by directory. A directory exclusion cannot tell an
# intentional fixture from a real leak, and it cannot tell a clean scan from a
# skipped one. This lane scans those trees under `keyhogignore.strict`, which
# suppresses only reviewed values, and then proves coverage by planting an
# unmarked credential in each protected tree and requiring the scan to report
# it.
#
# usage: strict_scan.sh <keyhog-binary> [manifest-dir]
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <keyhog-binary> [manifest-dir]" >&2
  exit 2
fi

binary=$(realpath "$1")
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest_dir=${2:-${RUNNER_TEMP:-/tmp}/keyhog-dogfood-strict}
mkdir -p "$manifest_dir"

policy="$repo_root/tests/dogfood/keyhogignore.strict"
config="$manifest_dir/strict.keyhog.toml"
report="$manifest_dir/strict-report.json"
trace="$manifest_dir/strict-report.trace.log"
manifest="$manifest_dir/strict-coverage.json"

# `require_reason` / `require_approved_by` make the scanner itself refuse an
# unlabeled suppression, so the governance is enforced by the product and not
# only by the auditor.
cat >"$config" <<EOF
[allowlist]
file = "$policy"
require_reason = true
require_approved_by = true
EOF

python3 "$repo_root/tests/dogfood/suppression_audit.py" \
  --policy "$policy" --root "$repo_root" \
  --manifest "$manifest" --allow-unused-hashes

# The five trees the operator lane hides wholesale. Each gets a planted,
# unmarked credential below.
protected_trees=(
  "detectors"
  "crates/scanner/examples"
  "benchmarks/baselines"
  "benchmarks/generators"
  ".github/workflows"
)

scan() {
  local out=$1
  shift
  set +e
  # `--no-suppress-test-fixtures` disables the CLI self-scan suppression in
  # crates/cli/src/orchestrator/postprocess.rs, which drops every finding inside
  # keyhog's own repo whose path carries a `detectors`, `tests`, `fixtures`, or
  # `benches` segment. Without it this lane cannot see the trees it exists to
  # scan, and a planted credential under detectors/ comes back clean.
  (cd "$repo_root" && "$binary" scan . \
    --config "$config" --daemon=off --backend cpu --no-suppress-test-fixtures \
    --format json --output "$out" "$@" 2>"$trace")
  local status=$?
  set -e
  return "$status"
}

# The probe files below are this lane's own instrument. An earlier run killed
# between planting and cleanup would leave one behind, and the first scan would
# then report it as an unreviewed credential in the repository. Sweep first.
probe_name=keyhog-strict-lane-probe.env
for tree in "${protected_trees[@]}"; do
  rm -f "$repo_root/$tree/$probe_name"
done

status=0
scan "$report" || status=$?

# A scan that failed partway still recovered real findings, and throwing them
# away makes the lane useless exactly when it matters. Report everything the
# run did produce, then fail with the reason it was incomplete. Completeness
# comes from persisting, never from discarding.
if [[ $status -gt 1 ]]; then
  echo "strict dogfood scan did not complete: exit=$status" >&2
  recovered=0
  if [[ -s "$report" ]] && jq -e 'type == "array"' "$report" >/dev/null 2>&1; then
    recovered=$(jq 'length' "$report")
  fi
  echo "$recovered finding(s) were recovered before the failure and are NOT discarded:" >&2
  if [[ "$recovered" -gt 0 ]]; then
    jq -r '.[] | "  \(.credential_hash)  \(.detector_id)  \(.location.file_path):\(.location.line)"' \
      "$report" >&2
  fi
  echo "coverage gap: the scan below this point did not run. Reason:" >&2
  tail -n 40 "$trace" >&2
  exit "$status"
fi

# The detector corpus is 900+ declared samples, far too many to review as a
# hash list, and a hand-maintained list of that size rots. It gets its own
# sample-aware gate backed by a generated inventory. Everything else must be
# zero.
jq --arg probe "$probe_name" \
  '[.[] | select((.location.file_path | endswith($probe)) | not)]' \
  "$report" >"$report.repo-only"
python3 "$repo_root/tests/dogfood/detector_fixture_check.py" \
  --report "$report.repo-only" --root "$repo_root"

outside=$(jq --arg root "$repo_root/" '
  [.[] | .location.file_path
   | if startswith($root) then ltrimstr($root) else . end
   | select(endswith($probe) | not)
   | select(startswith("detectors/") | not)] | length' --arg probe "$probe_name" "$report")
if [[ "$outside" -ne 0 ]]; then
  echo "strict dogfood found $outside unreviewed finding(s) outside detectors/:" >&2
  jq -r --arg root "$repo_root/" '
    .[] | (.location.file_path | if startswith($root) then ltrimstr($root) else . end) as $p
    | select(($p | endswith($probe)) | not)
    | select($p | startswith("detectors/") | not)
    | "  \(.credential_hash)  \(.detector_id)  \($p):\(.location.line)"' \
    --arg probe "$probe_name" "$report" >&2
  echo "Review each value. If it is an intentional fixture, add" >&2
  echo "  hash:<credential_hash>; reason=\"...\"; approved_by=\"...\"" >&2
  echo "to tests/dogfood/keyhogignore.strict. Never add a directory." >&2
  exit 1
fi

# Coverage proof. A policy that excluded a tree by accident would also report
# zero findings, so require a planted credential in every protected tree to
# come back. The value is a fabricated Stripe-shaped test key.
# One DISTINCT value per tree. A single shared value is collapsed by the
# default `--dedup credential`, so only the first tree the walker reaches would
# report it and the other four would look uncovered. Distinct values also make
# each tree an independent proof instead of one proof repeated.
declare -A planted_values=(
  ["detectors"]='sk_live_pjQRKxbggvjggR8SgFDLxNmvVKn3f0PQIbCk'
  ["crates/scanner/examples"]='sk_live_Xt7mQ2vKdN4wRhZ9bLcE6yFa1sGuP0Jo'
  ["benchmarks/baselines"]='sk_live_Bq5zHnT8xWvM3kCdRy7LpEg2AsJf4UiO'
  ["benchmarks/generators"]='sk_live_Vm9cKw4NpQz6TdXhRb1LyGa8FeJs3UoI'
  [".github/workflows"]='sk_live_Ld3RyPkV7nBcW5qMxZt2HgEa9JuFs6OiN'
)
planted_files=()
cleanup() {
  for f in "${planted_files[@]:-}"; do rm -f "$f"; done
}
trap cleanup EXIT

for tree in "${protected_trees[@]}"; do
  target="$repo_root/$tree/keyhog-strict-lane-probe.env"
  printf 'STRIPE_SECRET_KEY=%s\n' "${planted_values[$tree]}" >"$target"
  planted_files+=("$target")
done

planted_report="$manifest_dir/strict-planted.json"
scan "$planted_report" || true

missing=()
for tree in "${protected_trees[@]}"; do
  # Reports carry either a scan-root-relative or an absolute path depending on
  # how the root resolved, so normalize before comparing. An exact match against
  # one form silently fails for every tree when the run emits the other, which
  # would turn this proof into a proof of nothing.
  if ! jq -e --arg root "$repo_root/" --arg p "$tree/keyhog-strict-lane-probe.env" \
    'any(.[]; (.location.file_path | if startswith($root) then ltrimstr($root) else . end) == $p)' \
    "$planted_report" >/dev/null; then
    missing+=("$tree")
  fi
done

cleanup
planted_files=()

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "strict dogfood coverage FAILED: planted credential not reported in:" >&2
  printf '  %s\n' "${missing[@]}" >&2
  echo "The strict policy is excluding these trees, so a clean result there proves nothing." >&2
  exit 1
fi

jq --argjson trees "$(printf '%s\n' "${protected_trees[@]}" | jq -R . | jq -s .)" \
  '. + {lane: "strict", scanned_protected_trees: $trees, planted_probe_reported: $trees}' \
  "$manifest" >"$manifest.tmp"
mv "$manifest.tmp" "$manifest"

echo "strict dogfood OK: 0 unreviewed findings; planted probe reported in all ${#protected_trees[@]} protected trees"
echo "coverage manifest: $manifest"
