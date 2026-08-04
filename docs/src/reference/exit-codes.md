# Exit codes

The table below is the KeyHog 0.5.65 process contract. The canonical numeric
definitions live in `crates/cli/src/exit_codes.rs` and are rendered in
`keyhog --help` and `keyhog scan --help`.

| Exit | Meaning |
|---|---|
| `0` | Success. For a normal scan, there are no reportable findings, no incremental-cache failure, and no incomplete source coverage. |
| `1` | Findings are present, but none were confirmed live. |
| `2` | User or operator error, including invalid arguments or configuration and operator-correctable I/O. |
| `3` | System or local environment failure, including other low-level I/O, a fatal daemon service failure, or an explicitly selected SIMD backend failure. |
| `4` | A maintenance health or self-test command reported an unhealthy state. |
| `10` | A scan confirmed a live credential, or `update --check` found a newer release. |
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
  0)   echo "clean" ;;
  1)   echo "findings present; none confirmed live" ;;
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
3. at least one reportable finding, `1`;
4. incremental-cache failure, `3`;
5. incomplete source coverage, `13`;
6. clean success, `0`.

This means a finding from the covered portion remains `1` or `10` even when
coverage is incomplete. The coverage warning remains visible. Automation must
not infer complete coverage from a finding code.

Autoroute calibration is a separate scan mode. A successful calibration run
returns `0` and publishes only evidence that passed its calibration checks.
An inconclusive or failed calibration returns an error instead.

## `0`: success

A normal scan returns `0` only when it can make a clean claim under the active
policy. A source or expansion gap prevents a zero-finding scan from returning
`0`.

Maintenance subcommands also use `0` for their successful state. For example,
`update --check` returns `0` when the installed version is current.

## `1`: findings, none confirmed live

Exit `1` covers findings that are unverified, skipped, or verified inactive
(`dead` or `revoked`). A verification network error remains a per-finding
`verification-error`; it does not become exit `2`. If findings remain and none
is confirmed live, the scan returns `1`.

## `2`: user or operator error

Examples include:

- an unknown flag or invalid flag combination;
- invalid `.keyhog.toml`;
- a detector corpus that fails to load or validate;
- a missing or invalid baseline;
- a required daemon that is unavailable, ineligible, or fails its trust or
  protocol checks;
- a failed or inconclusive autoroute calibration operation;
- I/O classified as not found, permission denied, connection refused, invalid
  input, invalid data, or already exists.

Missing, stale, invalid, incomplete, or quarantined autoroute evidence during a
normal automatic scan is not an exit `2`. The scan warns and uses scalar
correctness recovery for the affected work. Its final exit follows completed
scan precedence. Inspect the unhealthy evidence with:

```sh
keyhog backend --autoroute --json
keyhog calibrate-autoroute
```

An explicit backend request is different. It bypasses automatic selection for
that diagnostic run and keeps its own fail-closed execution contract.

## `3`: system or local environment failure

This code covers a low-level I/O error not classified as operator-correctable,
an incremental-cache failure, a fatal daemon listener or connection-handler
spawn failure, or an explicitly selected SIMD/Hyperscan path that cannot
execute. A selected or required GPU failure is `12`.

## `4`: maintenance health failure

`scan` does not return `4`. Maintenance commands use it for unhealthy states:

- `doctor` could not establish a healthy installation;
- `repair` could not restore a working binary;
- `backend --self-test` failed;
- `backend --autoroute` found `quarantined`, `calibration_required`,
  `disabled`, `stale`, or `invalid` routing state.

Use the structured diagnostic surfaces when automation needs details:

```sh
keyhog backend --self-test --json
keyhog backend --autoroute --json
```

## `10`: live credential or update available

For `scan --verify`, at least one credential was accepted by its verification
service. This takes precedence over other findings and incomplete coverage.

`update --check` reuses `10` to mean that a newer release is available. The
subcommand context distinguishes this maintenance result from a scan result.

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

## `130`: interrupted

SIGINT is a process boundary, not a clean partial result. On Unix, the signal
handler writes an interruption diagnostic and exits immediately with `130`.
On other supported platforms, the Ctrl-C task uses the same code.

## Findings cannot be forced to zero

KeyHog has no `--exit-zero` flag. To accept a known finding, suppress it through
the reviewed `.keyhogignore` workflow. The next scan then computes its exit from
the remaining unsuppressed findings and coverage state.
