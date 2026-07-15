# Exit codes

KeyHog uses exit codes to signal scan and maintenance outcomes. The numeric
contract is stable across versions; consumers (CI gates, pre-commit hooks, IDE
plugins, and health checks) can rely on it.

| Exit | Meaning                                                            |
|------|--------------------------------------------------------------------|
| `0`  | Command succeeded; for a scan, zero reported findings and no clean-blocking coverage/cache failure. |
| `1`  | Findings present, none confirmed live (unverified, skipped, or verified-inactive: dead/revoked). |
| `2`  | User/operator error: bad input/config, missing or invalid scan state, an unavailable required daemon, or missing/stale/incomplete autoroute evidence. Also operator-correctable I/O such as not-found, permission-denied, connection-refused, invalid-input, or invalid-data. |
| `3`  | System error: a lower-level operating-system I/O failure, incremental-cache failure, or explicitly selected non-GPU backend that cannot execute. |
| `4`  | Health/self-test failure: `keyhog doctor` unhealthy, `keyhog repair` could not restore a working binary, `keyhog backend` self-test failed, or multi-backend `keyhog backend --autoroute` reports `calibration_required`, `disabled`, `stale`, or `invalid`. |
| `10` | **LIVE credentials confirmed** (a `--verify` scan where the vendor API accepted a found secret) - the highest-severity gate. Also returned by `keyhog update --check` when a newer release exists. |
| `11` | Scanner thread panicked. The finding count is NOT trustworthy - investigate, don't ship. Distinct from `2`/`3` so CI can tell a code bug from a config error. |
| `12` | Selected/required GPU unavailable: `--require-gpu`, an explicit GPU backend, or persisted autoroute selected GPU but the stack or dispatch could not honor it. CPU/SIMD is not substituted. |
| `13` | A requested source failed before producing scan data, or a zero-finding scan had incomplete input coverage, so KeyHog refuses to report clean. |
| `130`| Interrupted (SIGINT / Ctrl-C).                                     |

## `0` (clean)

Use case: a CI step like `keyhog scan .` exits 0 when the working tree
is clean. The job stays green.

With `--verify`, the exit code escalates when a credential is confirmed
live: a found secret the vendor API accepts exits `10`, while a finding
that is unverified, skipped, or verified inactive (`dead` or `revoked`)
exits `1`. So gating ONLY on live credentials needs no JSON parsing -
branch on the exit code:

```sh
keyhog scan . --verify
case $? in
  0)  echo "clean" ;;
  10) echo "LIVE credentials present - block + page" ; exit 1 ;;
  1)  echo "findings, none confirmed live" ;;
esac
```

## `1` (findings present)

The most common non-zero. CI fails, pre-commit hook blocks the commit,
PR check turns red. Findings get printed to stdout in whatever format
`--format` selected.

Exit `1` means findings exist but none were confirmed live. That covers
findings that were not verified, findings whose verification was skipped,
and findings verified inactive (`dead` or `revoked`). A scan that confirms
a live credential exits `10` instead (see below), so "findings, none live"
vs "some live" is just `1` vs `10`, no JSON parsing required.

## `2` (user error)

Things that exit `2`:

- Unknown CLI flag.
- On Windows, direct `keyhog uninstall --yes`: the running `.exe` cannot delete
  itself, so the command prints the path to remove after it exits. The
  PowerShell installer handles this outer-process cleanup normally.
- `.keyhog.toml` parse error.
- Detector corpus load failure. KeyHog rejects the whole corpus before reading
  scan input. It does not scan with a partial detector set.
- `--baseline <FILE>` where FILE doesn't exist or isn't valid JSON.
- Missing, stale, invalid, or incomplete autoroute calibration for an
  automatic backend decision. Inspect it with `keyhog backend --autoroute`,
  then rerun `keyhog calibrate-autoroute`, `install.sh --calibrate`, or
  `install.ps1 -Calibrate`. An explicit `--backend` bypasses the table for that
  diagnostic scan; it does not make the autoroute state valid.
- Daemon availability, eligibility, trust, or protocol errors. See
  [Daemon and warm scans](../workflows/daemon.md) for routing-specific exits,
  automatic retry, stale status, coverage, and Windows behavior.
- Invalid daemon startup configuration, including an unknown `--backend`
  value. Required or selected GPU failures are `12`, not `2`.
- Network error during `--verify` is NOT a `2`; it's a `verification-error`
  marker per finding and the scan exits `1` if any unverified-live
  findings exist.

Stderr carries the error message. Stdout may have partial output
depending on where the error happened.

## `3` (system error)

A failure below the operator-input boundary: a low-level I/O error that is not
one of the operator-correctable kinds mapped to `2`, an incremental-cache
failure, a fatal daemon listener or connection-handler spawn failure, or an
explicitly selected SIMD/Hyperscan path that becomes unavailable. A selected
or required GPU failure is `12`, not `3`. A
missing/garbage `--baseline` is `2`; a requested source that produced no scan
data (for example `--git-history` on a non-repo) is `13`; and a detector TOML
load failure is `2`. Distinct codes let automation choose whether to correct
configuration, repair a runner, or rescan uncovered input. Stderr carries the
cause.

## `4` (health / self-test failure)

Returned by the maintenance subcommands, not by `scan`: `keyhog doctor`
when the install fails its end-to-end self-test, `keyhog repair` when it
could not restore a working binary, `keyhog backend` when its self-test fails,
and multi-backend `keyhog backend --autoroute` when its persisted routing state
is missing, disabled, stale, or invalid. A health monitor can treat `4` as
"binary present but not trustworthy." Use `keyhog backend --self-test --json`
or `keyhog backend --autoroute --json` when CI needs stable fields instead of
stderr scraping.

## `10` (live credentials, or update available)

The highest-severity scan outcome: a `--verify` scan where the vendor
API **accepted** a found secret - it is real and exfil-capable right now.
Gate hard on this:

```sh
keyhog scan . --verify || rc=$?
[ "${rc:-0}" = "10" ] && { echo "::error::live credential confirmed"; exit 1; }
```

`keyhog update --check` reuses `10` to mean "a newer release exists"
(exit `0` = already current), so a self-update cron can branch on it.

## `11` (scanner panic)

A panic inside a scanner thread (regex compile bug, OOM in a windowed
chunk, etc.). The scan was incomplete; the count of findings emitted
is NOT trustworthy. CI should treat this as "investigate" rather
than "ship anyway because exit 11 != 1".

The reason this is `11` rather than `2`:

- A panic is a code bug worth surfacing distinctly.
- Some CIs (older Jenkins, certain shell wrappers) collapse `2` with
  "command not found" or other ambient errors. `11` is unambiguous.
- Additional scan failure categories can be added without renumbering existing
  codes.

## `12` (selected or required GPU unavailable)

Returned when the operator explicitly required GPU execution (`--require-gpu`
or `[system].gpu = "required"`), explicitly selected the GPU backend, or a
persisted autoroute decision selected GPU, but the host cannot provide or keep
a usable GPU dispatch path. This can happen before scanning or during a runtime
dispatch. CPU/SIMD is not substituted. The distinct code lets CI identify a GPU
runner/driver regression without scraping stderr.

For `keyhog daemon start`, exit `12` covers required GPU preflight, GPU scanner
compilation, an unavailable or incompatible initialized backend, and a warmup
that degrades before readiness. A GPU dispatch failure after the ready line also
terminates the daemon with `12`. Run `keyhog backend --self-test`; repair the
GPU driver/runtime or select `--backend simd` or `--backend cpu` explicitly.

## `13` (requested source failed or coverage incomplete)

Returned when a source the operator explicitly requested produced no scan data,
or when the scan completed with zero findings but input coverage was incomplete:
for example `--git-history` on a non-git directory, a bad git ref, a remote
source that could not be read, an unreadable file, an oversized file skipped by
`--max-file-size`, a truncated archive, or a decode/source expansion cap. This
is distinct from clean `0` and generic user-error `2`; the scan did not prove
the target clean because requested bytes were not scanned. If findings were
reported from the covered portion, the findings outcome (`1`, or `10` when a
credential was confirmed live) takes precedence while the coverage warning
still remains visible on stderr.

## Composing in shell

```sh
set -e
keyhog scan .                # exit 1 stops the shell here
```

Or to handle the non-zero explicitly:

```sh
keyhog scan . --verify || rc=$?
case "$rc" in
  0|"")  echo "clean" ;;
  1)     echo "findings (none live) -> opening PR comment" ;;
  10)    echo "LIVE credentials -> block + page on-call" ;;
  2)     echo "user error (bad flag/config) -> failing build" ;;
  3)     echo "system error -> retry / investigate" ;;
  4)     echo "health/self-test failure -> repair installation" ;;
  11)    echo "scanner panic -> paging on-call" ;;
  12)    echo "selected/required GPU unavailable -> repair runner or recalibrate" ;;
  13)    echo "source failed or coverage incomplete -> fix source/ref/token or rescan uncovered input" ;;
  130)   echo "interrupted" ;;
  *)     echo "unknown exit $rc" ;;
esac
```

## What you can't do

- No `--exit-zero` flag. KeyHog deliberately does not provide a way
  to lie to CI about findings. If you need to override (e.g. "this
  finding is accepted, ship anyway"), suppress it by hash in
  `.keyhogignore` instead. The exit code then reflects truth: there
  are no UN-suppressed findings, so it's `0`.
