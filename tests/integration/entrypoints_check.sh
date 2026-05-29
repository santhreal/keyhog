#!/usr/bin/env bash
#
# Integration entry-point gate (buildless, deterministic).
#
# The two ways an enterprise wires keyhog into a pipeline are the pre-commit
# framework hook (`.pre-commit-hooks.yaml`) and the GitHub Action
# (`.github/actions/keyhog/action.yml`). Both invoke the keyhog CLI; a silent
# drift here (a renamed flag, a dropped `pass_filenames`) breaks every
# consumer's pipeline with no test catching it. This gate locks the load-
# bearing properties without needing to build keyhog.

set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
fail=0
note() { printf '  %s\n' "$*"; }

# Flags confirmed NOT to exist in the keyhog CLI - same denylist class as the
# docs gate. Either entry point referencing one is a broken pipeline.
DENY='--disable-detectors|--enable-detectors|--detector |--insecure-tls|--source-type|--image |--s3 |--token |--exclude '

PCH="$ROOT/.pre-commit-hooks.yaml"
if [ -f "$PCH" ]; then
  # pass_filenames: false is REQUIRED. The framework otherwise appends staged
  # filenames as positional args; `keyhog scan` takes one [PATH], so a second
  # filename aborts with clap exit 2 - failing EVERY commit in every consumer
  # repo. This single line is the difference between "works" and "bricked".
  if grep -qE '^\s*pass_filenames:\s*false' "$PCH"; then
    note "OK   .pre-commit-hooks.yaml: pass_filenames: false (filenames not appended)"
  else
    echo "FAIL .pre-commit-hooks.yaml MUST set 'pass_filenames: false' or every consumer commit fails (clap exit 2 on the appended filename)."
    fail=1
  fi
  # entry must invoke `keyhog scan` with a self-discovering source (no per-file
  # positional), and no denylisted flag.
  entry=$(grep -E '^\s*entry:' "$PCH" | head -1)
  case "$entry" in
    *"keyhog scan"*) note "OK   .pre-commit-hooks.yaml: entry invokes 'keyhog scan'" ;;
    *) echo "FAIL .pre-commit-hooks.yaml entry must invoke 'keyhog scan'; got: $entry"; fail=1 ;;
  esac
  if printf '%s' "$entry" | grep -qE -- "$DENY"; then
    echo "FAIL .pre-commit-hooks.yaml entry uses a nonexistent flag: $entry"; fail=1
  fi
else
  echo "FAIL .pre-commit-hooks.yaml missing - consumers cannot wire keyhog via pre-commit."
  fail=1
fi

ACT="$ROOT/.github/actions/keyhog/action.yml"
if [ -f "$ACT" ]; then
  # Denylisted (nonexistent) flags must not appear anywhere in the Action -
  # whole-file scan so it stays robust to how the invocation is assembled
  # (inline `keyhog scan ...` or an `args=(scan ...)` array).
  if grep -qE -- "$DENY" "$ACT"; then
    echo "FAIL action.yml uses a nonexistent keyhog flag:"
    grep -nE -- "$DENY" "$ACT" | sed 's/^/    /'
    fail=1
  else
    note "OK   action.yml: no denylisted keyhog flags"
  fi
  # The Action must actually invoke the keyhog CLI: inline `keyhog scan` or the
  # args-array form `keyhog "${args[@]}"`.
  if grep -qE 'keyhog (scan|"\$\{args\[@\]\}")' "$ACT"; then
    note "OK   action.yml: invokes the keyhog scan CLI"
  else
    echo "FAIL action.yml does not invoke 'keyhog scan' (inline or args-array)."
    fail=1
  fi
  # SARIF upload should be guarded so a fork PR (no security-events:write) does
  # not hard-fail the whole workflow.
  if grep -q "continue-on-error: true" "$ACT" && grep -q "upload-sarif" "$ACT"; then
    note "OK   action.yml: SARIF upload is fork-PR safe (continue-on-error)"
  else
    echo "WARN action.yml: SARIF upload step should be continue-on-error for fork PRs."
  fi
else
  echo "FAIL .github/actions/keyhog/action.yml missing - the documented Action does not exist."
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "integration entry-point gate: PASS"
else
  echo "integration entry-point gate: FAIL"
fi
exit "$fail"
