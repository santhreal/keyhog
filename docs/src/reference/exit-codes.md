# Exit codes

The table below is the KeyHog 0.5.86 process contract. The canonical numeric
definitions live in `crates/cli/src/exit_codes.rs` and are rendered in
`keyhog --help` and `keyhog scan --help`.

| Exit | Meaning |
|---|---|
| `0` | Success. No finding blocks the active evidence policy, no incremental-cache failure occurred, and source coverage is complete. Under the default policy, review-tier findings can remain visible. |
| `1` | At least one finding blocks the active evidence policy, but none were confirmed live. |
| `2` | User or operator error, including invalid arguments or configuration and operator-correctable I/O. |
| `3` | System or local environment failure, including other low-level I/O, a fatal daemon service failure, or an explicitly selected SIMD backend failure. |
| `4` | A maintenance health or self-test command reported an unhealthy state. |
| `10` | A scan confirmed a live credential. |
| `11` | A scanner thread panicked. Scan state is not trustworthy. |
| `12` | An explicitly selected or required GPU path could not execute. |
| `13` | A requested source failed or input coverage was incomplete and no finding outcome took precedence. |
| `130` | SIGINT or Ctrl-C interrupted the process. |

## Capture the code safely

Do not run a non-zero scan as a bare command under `set -e` if you intend to
inspect the result. Put it on the left side of `||`:

```sh
rc=0
keyhog scan . --verify || rc=$?

case "$rc" in
  0)   echo "no policy-blocking findings" ;;
  1)   echo "findings block the active evidence policy" ;;
  10)  echo "live credential confirmed"; exit 1 ;;
  2)   echo "fix arguments, configuration, or operator input"; exit 1 ;;
  3)   echo "repair or retry this runner"; exit 1 ;;
  4)   echo "maintenance health check failed"; exit 1 ;;
  11)  echo "scanner panic; discard this scan result"; exit 1 ;;
  12)  echo "required GPU path unavailable"; exit 1 ;;
  13)  echo "source or coverage incomplete; do not report clean"; exit 1 ;;
  130) echo "interrupted"; exit 130 ;;
  *)   echo "unknown KeyHog exit: $rc"; exit 1 ;;
esac
```

## Completed scan precedence

For a completed normal scan, `resolve_scan_exit` applies this order:

1. scanner panic, `11`;
2. at least one live credential, `10`;
3. at least one finding that blocks the active evidence policy, `1`;
4. incremental-cache or autoroute-cache persist failure, `3`;
5. incomplete source coverage, `13`;
6. policy success, `0`.

This means a blocking finding from the covered portion remains `1` or `10`
even when coverage is incomplete. The coverage warning remains visible.
Automation must not infer complete coverage from a finding code.

Autoroute calibration is a separate scan mode, but it does not hide the scan's
own result. `keyhog scan . --autoroute-calibrate` still exits `1` when a finding
blocks the active evidence policy, and `0` only when no finding blocks and the
calibration succeeded. Calibration publishes only evidence that passed its
checks, and an inconclusive or failed calibration returns an error instead.
This matters because the documented first-run command is a calibrating scan: a
real policy-blocking leak cannot read as a successful warm-up.

## `0`: policy success

A normal scan returns `0` only when it can make a successful claim under the
active evidence policy. The default policy keeps `review` findings visible
without blocking; `--evidence-policy paranoid` makes them block. A source or
expansion gap prevents a zero-blocking-finding scan from returning `0`.

Maintenance subcommands also use `0` for their successful state. For example,
`doctor` returns `0` when the installation is healthy.

## `1`: findings block the active policy

The default evidence policy blocks `likely` and `confirmed`. Paranoid policy
also blocks `review`. Verification states other than `live` do not override the
scanner evidence verdict, so skipped, dead, revoked, and verification-error
findings can still return `1` when their tier blocks. A live finding returns
`10`.

## `2`: user or operator error

Examples include:

- an unknown flag or invalid flag combination;
- invalid `.keyhog.toml`;
- a detector corpus that fails to load or validate;
- a missing or invalid baseline;
- a required daemon that is unavailable, ineligible, or fails its trust or
  protocol checks. This is `--daemon=on`, where you asked for the warm route as
  a hard contract. `--daemon=auto`, the default, never exits `2` because of a
  daemon problem: any daemon failure falls back to an in-process scan and the
  scan's own exit code is returned;
- a failed or inconclusive autoroute calibration operation;
- missing, stale, invalid, incomplete, or quarantined autoroute evidence on a
  normal automatic scan;
- I/O classified as not found, permission denied, connection refused, invalid
  input, invalid data, or already exists.

A normal automatic scan needs a valid autoroute decision for the exact workload
class, detector corpus, config, binary, and host. Without one there is no
measured-correct backend to select, so the scan fails closed: nothing is
scanned, stdout carries no findings document, and stderr names the state and the
repair. An empty findings document reads as a clean tree, so an unroutable scan
writes none. KeyHog never benchmarks at scan time and never substitutes scalar
execution for a missing decision. Inspect the state and repair it with:

```sh
keyhog backend --autoroute --json
keyhog calibrate-autoroute
```

`backend --autoroute` reports the same unhealthy state as `4`, its maintenance
health code.

An explicit `--backend` request is different. It bypasses automatic selection
for that diagnostic run and keeps its own fail-closed execution contract.

## `3`: system or local environment failure

This code covers a low-level I/O error not classified as operator-correctable,
an incremental-cache failure, an autoroute decision-cache persist failure
(the scan reported no findings but could not save its routing decision), a fatal
daemon listener or connection-handler spawn failure, or an explicitly selected
SIMD/Hyperscan path that cannot execute. A selected or required GPU failure is
`12`.

## `4`: maintenance health failure

`scan` does not return `4`. Maintenance commands use it for unhealthy states:

- `doctor` could not establish a healthy installation;
- `backend --self-test` failed;
- `backend --autoroute` found `quarantined`, `calibration_required`,
  `disabled`, `stale`, or `invalid` routing state.

Use the structured diagnostic surfaces when automation needs details:

```sh
keyhog backend --self-test --json
keyhog backend --autoroute --json
```

## `10`: live credential

For `scan --verify`, at least one credential was accepted by its verification
service. This takes precedence over other findings and incomplete coverage.

## `11`: scanner panic

A scanner thread panicked. Partial findings and counts are not trustworthy.
The CLI flushes its diagnostic streams and exits immediately with `11` so a
later accelerator teardown cannot replace this code.

## `12`: selected or required GPU unavailable

This applies when `--require-gpu`, `[system].gpu = "required"`, an explicit GPU
backend, or a GPU calibration candidate cannot execute. The same code covers a
daemon GPU route that fails before readiness. KeyHog does not substitute CPU or
SIMD for these explicit contracts.

An automatically selected accelerated backend that faults at runtime is
different. When exact recovery is possible, KeyHog retains completed work,
replays only unprocessed stable input through a measured-correct peer, records
the recovery, and follows normal completed-scan exit semantics. If recovery
cannot cover the input, the scan is incomplete rather than clean.

## `13`: source failed or coverage incomplete

This code protects the clean claim. Examples include:

- Git history requested for a non-repository or an invalid ref;
- a requested remote source that produced no scan data;
- an unreadable file;
- a file skipped by `--max-file-size`;
- a truncated archive;
- a source or decode expansion limit that left requested input uncovered.

If no finding outcome takes precedence, the scan returns `13`. Fix the source,
credentials, ref, permissions, or limit and scan the uncovered input again.

The report is always written, including when every source failed to read. That
report carries `scan covered nothing` plus the reason each source failed, so a
CI job never has to pre-seed a placeholder file to have something to publish.

A report that cannot be written is a different failure and says so. It exits
`2`, because the output path is operator-correctable, and names the path and
the I/O error:

```text
error: the scan completed but its report could not be written to /srv/out/keyhog.json: atomically writing report /srv/out/keyhog.json: Permission denied (os error 13)
```

Read that as "fix the output path", not "the scan could not cover your input".
The two used to share a signature; they no longer do.

### Not every coverage gap reaches the exit code

Each gap reason carries one of two severities, and the severity decides whether
it can produce `13`:

| Severity | What it means | Exit with no findings |
| --- | --- | --- |
| Advisory | The bytes were examined. A file was deliberately skipped, or a derived layer such as decode-through was not expanded. | `0` |
| Failing | The bytes were not covered, or their line identity is untrustworthy. | `13` |

Advisory reasons include `default exclusion policy (...)`,
`binary (extension or content sniff)`,
`matches dropped by the vendored/minified path policy`,
`exceeded a configured size cap`, and
`scanner decode-through declined by --decode-size-limit`. Failing reasons
include `unreadable (permission denied or I/O error)`,
`source emitted error rows`, `Git object unreadable or wrong object kind`,
`archive or container extraction truncated`, and `scan covered nothing`. The
full split lives in `severity()` in `crates/cli/src/reporting.rs`.

One scan can carry both classes, and then the failing one decides. A file over
`--max-file-size` is advisory on its own, but the source that could not read it
also emits `source emitted error rows`, which is failing, so that scan exits
`13`. Read the reasons rather than counting the rows.

The advisory rows are the ones to plan for. A tree whose only credentials sit
in `vendor/`, inside a compiled binary, inside a minified bundle, or inside an
encoded value too large to decode reports `partial`, exits `0`, and prints
`No secrets detected in the scanned files.` on stdout, with the warning on
stderr only. A gate that reads the exit code alone treats that as clean. Rerun
with `--no-default-excludes` when those trees hold code you wrote. See
[tell a real clean from a skipped input](./coverage-truth.md).

## `130`: interrupted

SIGINT is a process boundary, not a clean partial result. On Unix, the signal
handler writes an interruption diagnostic and exits immediately with `130`.
On other supported platforms, the Ctrl-C task uses the same code.

## Findings cannot be forced to zero

KeyHog has no `--exit-zero` flag. Accept a known finding through a reviewed
suppression instead. The next scan then computes its exit from the remaining
unsuppressed findings and coverage state. Choose by scope:

- Findings that predate adoption: record them once in a committed baseline. See
  [Fail only on new secrets](../workflows/ci.md#fail-only-on-new-secrets).
- One reviewed value, path, or detector: use `.keyhogignore` or
  `.keyhogignore.toml`. See [Suppressions](../suppressions.md).

Exit `13` cannot be suppressed. Coverage is a property of the input, not of the
findings, so fix the source, permission, ref, or limit instead.

## Guard subcommand exit codes

`keyhog guard` subcommands use the same numeric exit codes with guard-specific
state mapping:

| Guard state | Exit code | Condition |
|---|---|---|
| `current` | `0` | The root is proven clean. |
| `blocked` | `1` | Unsuppressed findings were detected. |
| `dirty`, `stopped`, `indexing`, `degraded`, `stale-policy` | `13` | The root is not proven clean or coverage is incomplete. |

`guard rebuild` uses the same mapping after re-adding the root. A rebuild that
completes with `current` returns `0`; a rebuild that leaves the root `stopped`
or `indexing` returns `13`.
