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
SCAN="$ROOT/.github/actions/keyhog/run-scan.sh"
if [ -f "$ACT" ] && [ -f "$SCAN" ]; then
  # Denylisted (nonexistent) flags must not appear anywhere in the Action -
  # whole-file scan so it stays robust to how the invocation is assembled
  # (inline `keyhog scan ...` or an `args=(scan ...)` array).
  if grep -qE -- "$DENY" "$ACT" "$SCAN"; then
    echo "FAIL GitHub Action entrypoint uses a nonexistent keyhog flag:"
    grep -nE -- "$DENY" "$ACT" "$SCAN" | sed 's/^/    /'
    fail=1
  else
    note "OK   GitHub Action entrypoint: no denylisted keyhog flags"
  fi
  # The Action must actually invoke the tested local scan script, and that
  # script must build a scan argv and execute `keyhog "${args[@]}"`.
  if grep -q "run-scan.sh" "$ACT" \
     && grep -q "args=(scan" "$SCAN" \
     && grep -q 'keyhog "${args\[@\]}"' "$SCAN"; then
    note "OK   GitHub Action entrypoint: invokes the tested keyhog scan CLI"
  else
    echo "FAIL GitHub Action entrypoint does not route through run-scan.sh to 'keyhog scan'."
    fail=1
  fi
  # SARIF upload should be advisory only for fork PRs (no
  # security-events:write), while trusted CI must fail closed if the user asked
  # for Code Scanning upload.
  if grep -q "continue-on-error: \${{ github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name != github.repository }}" "$ACT" \
     && grep -q "upload-sarif" "$ACT"; then
    note "OK   action.yml: SARIF upload is trusted-fail-closed and fork-PR advisory"
  else
    echo "FAIL action.yml: SARIF upload must fail closed on trusted runs and be advisory only for fork PRs."
    fail=1
  fi
  # Findings counting is a CI security boundary. Missing jq / malformed JSON
  # must not become findings=0 after the scanner already returned exit 1/10.
  if grep -q "count_from_report()" "$SCAN" \
     && grep -q "Could not parse.*keyhog exited" "$SCAN" \
     && grep -q "but did not write" "$SCAN" \
     && ! grep -q "jq .*|| echo 0" "$SCAN"; then
    note "OK   GitHub Action entrypoint: report counting fails closed when parser/report fails"
  else
    echo "FAIL GitHub Action entrypoint findings counting must fail closed; do not convert parser/missing-report failures to findings=0."
    fail=1
  fi
  if grep -q "GITHUB_STEP_SUMMARY" "$SCAN" && grep -q "### KeyHog scan" "$SCAN"; then
    note "OK   GitHub Action entrypoint: writes a GitHub Step Summary"
  else
    echo "FAIL GitHub Action entrypoint must write a concise GITHUB_STEP_SUMMARY for CI triage."
    fail=1
  fi
else
  echo "FAIL .github/actions/keyhog/action.yml or run-scan.sh missing - the documented Action does not exist."
  fail=1
fi

BENCH="$ROOT/scripts/run_benchmark.sh"
if [ -f "$BENCH" ]; then
  if grep -qE 'grep -c|2>/dev/null|\|\| echo 0|cargo build|target/release/keyhog|tests/recall|KEYHOG_BIN=' "$BENCH"; then
    echo "FAIL scripts/run_benchmark.sh must delegate to the canonical benchmark harness; no grep scoring, stderr suppression, hardcoded target binary, or legacy tests/recall corpus."
    grep -nE 'grep -c|2>/dev/null|\|\| echo 0|cargo build|target/release/keyhog|tests/recall|KEYHOG_BIN=' "$BENCH" | sed 's/^/    /'
    fail=1
  elif grep -q 'leaderboard' "$BENCH" \
     && grep -q 'gate' "$BENCH" \
     && grep -q 'REQUIRE_COMPETITORS' "$BENCH"; then
    note "OK   benchmark entrypoint: delegates to canonical leaderboard + gate"
  else
    echo "FAIL scripts/run_benchmark.sh must route through benchmarks/Makefile leaderboard and gate with required competitors."
    fail=1
  fi
else
  echo "FAIL scripts/run_benchmark.sh missing - compatibility benchmark entrypoint must route to the canonical harness."
  fail=1
fi

PRE="$ROOT/scripts/prerelease.sh"
if [ -f "$PRE" ]; then
  if grep -qE 'SKIP bench gate|KEYHOG_BIN:-|target/release/keyhog|scan --no-daemon .*2>/dev/null .*grep|scan --no-daemon .*grep' "$PRE"; then
    echo "FAIL scripts/prerelease.sh must not skip the bench gate open or prove installed detection with grep/suppressed stderr."
    grep -nE 'SKIP bench gate|KEYHOG_BIN:-|target/release/keyhog|scan --no-daemon .*2>/dev/null .*grep|scan --no-daemon .*grep' "$PRE" | sed 's/^/    /'
    fail=1
  elif grep -q 'make -C benchmarks mirror' "$PRE" \
     && grep -q 'python3 -m bench gate' "$PRE" \
     && grep -q 'installed_detection_smoke' "$PRE"; then
    note "OK   prerelease entrypoint: bench gate fails closed and install smoke parses JSON"
  else
    echo "FAIL scripts/prerelease.sh must require the mirror bench gate and JSON-parse the installed scan report."
    fail=1
  fi
else
  echo "FAIL scripts/prerelease.sh missing - release gate cannot be audited."
  fail=1
fi

DOG="$ROOT/scripts/dogfood-all-os.sh"
if [ -f "$DOG" ]; then
  if grep -qE 'tests/install/install_from_local_build\.sh|scan "\\$t/leak\.env" --format json 2>/dev/null|grep -q aws-access-key|>/dev/null 2>&1; check "clean tree|>/dev/null 2>&1; check "git-history|scan --stdin >/dev/null 2>&1' "$DOG"; then
    echo "FAIL scripts/dogfood-all-os.sh must use OS-specific install proofs and JSON/log-backed scan checks."
    grep -nE 'tests/install/install_from_local_build\.sh|scan "\\$t/leak\.env" --format json 2>/dev/null|grep -q aws-access-key|>/dev/null 2>&1; check "clean tree|>/dev/null 2>&1; check "git-history|scan --stdin >/dev/null 2>&1' "$DOG" | sed 's/^/    /'
    fail=1
  elif grep -q 'expect_aws_json' "$DOG" \
     && grep -q 'tests/install/linux/install_from_local_build.sh' "$DOG" \
     && grep -q 'tests/install/macos/install_from_local_build.sh' "$DOG"; then
    note "OK   cross-OS dogfood entrypoint: parses JSON and uses OS install proofs"
  else
    echo "FAIL scripts/dogfood-all-os.sh must parse planted-secret JSON and call Linux/macOS install proof wrappers."
    fail=1
  fi
else
  echo "FAIL scripts/dogfood-all-os.sh missing - cross-OS dogfood cannot be audited."
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "integration entry-point gate: PASS"
else
  echo "integration entry-point gate: FAIL"
fi
exit "$fail"
