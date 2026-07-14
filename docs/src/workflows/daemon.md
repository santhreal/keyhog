# Daemon and warm scans

The Unix daemon keeps one compiled scanner and its backend state warm for
repeated small scans. It serves eligible standard-policy `stdin` and
single-file requests. Repository, multi-source, and policy-changing scans use
the full in-process orchestrator.

The daemon is opt-in infrastructure. KeyHog never starts it implicitly, and a
running daemon never captures an ineligible scan silently.

```sh
# Terminal or service-manager process. This command stays in the foreground.
keyhog daemon start

# The omitted scan flag means --daemon=auto on Unix.
keyhog scan --stdin < changed-file.txt
keyhog scan path/to/one-file.txt

keyhog daemon status
keyhog daemon stop
```

`keyhog watch` is separate. It is a foreground filesystem watcher with its own
compiled scanner. It does not use the daemon socket and does not appear in
`daemon status`.

## Lifecycle and readiness

`daemon start` prints a compilation message first. The service can accept
requests only after this line appears:

```text
keyhog daemon ready on <socket> (<count> detectors, wire=<version>)
```

The ready line follows detector loading, scanner compilation, backend
validation and warmup, socket binding, and socket permission checks. Startup
fails instead of announcing readiness when any required step fails. An
autorouted daemon requires valid persisted warm-route evidence. A forced
`--backend gpu|simd|cpu` is a diagnostic startup choice and must be usable as
requested. Backend selection never falls through silently. See
[Autoroute calibration](../reference/autoroute-calibration.md).

`daemon status` connects to an existing service. It reports uptime, completed
scan attempts, active scans, detector count, backend policy, and identity
staleness. `scans served` includes attempts that returned a daemon error, so it
is an activity counter rather than a success counter. Status never starts a
daemon.

`daemon stop` sends a shutdown request and succeeds after receiving the
acknowledgement. The server then stops accepting connections and removes the
socket. The current implementation does not wait for other active scan handlers
to finish. Check that `daemon status` reports `0 active` before stopping when
in-flight requests must complete. An abrupt process exit can leave a socket
entry. The next start removes it only after the stale-socket trust checks pass.

## Socket selection and trust

All daemon commands use the same default socket resolver:

1. `$XDG_RUNTIME_DIR/keyhog.sock` when `XDG_RUNTIME_DIR` is set.
2. The OS user-cache directory plus `keyhog/server.sock`.
3. The OS temporary directory plus `keyhog/server.sock`.

The usual cache paths are `~/.cache/keyhog/server.sock` on Linux and
`~/Library/Caches/keyhog/server.sock` on macOS. For a fixed location, pass the
same path at both ends:

```sh
keyhog daemon start --socket /private/path/keyhog.sock
keyhog scan --daemon=on --daemon-socket /private/path/keyhog.sock one-file.txt
keyhog daemon status --socket /private/path/keyhog.sock
keyhog daemon stop --socket /private/path/keyhog.sock
```

The socket carries unredacted matches between same-user processes. The server
requires an owned, non-symlinked socket path, tightens a created parent to mode
`0700`, and requires the socket itself to be mode `0600`. Both client and server
verify the connected peer UID. A stale entry is removed only when it is an
owned `0600` Unix socket in a trusted directory and no listener accepts a
connection. KeyHog refuses ordinary files, symlinks, foreign owners, loose
permissions, and a live socket rather than replacing them.
An untrusted stale entry is not removed automatically. Correct or remove it
after verifying the path and owner, then start the daemon again.

Windows ships no daemon transport. An absent daemon flag or
`--daemon=off` runs in process. Explicit `--daemon=auto`, `--daemon=on`, and all
`daemon` subcommands fail with the Unix-only error.

## Routing contract

On Unix, omitting `--daemon` is equivalent to `--daemon=auto`. Bare
`--daemon` is equivalent to `--daemon=on`.

| Policy | Eligible and compatible daemon | No usable daemon | Incompatible request |
|---|---|---|---|
| `--daemon=auto` or omitted | Use the daemon. A connection, handshake, request, or daemon execution error is printed, then the request is retried in process. | Run in process. A stale socket that exists is attempted, so its failure is printed before the retry. | Run in process without sending a daemon request. |
| `--daemon=on` or bare `--daemon` | Require the daemon result. | Exit with the specific availability, trust, identity, or protocol error. | Exit with the specific unsupported requirement. |
| `--daemon=off` | Do not connect. | Run in process. | Run in process. |

`--daemon-socket` cannot be combined with `--daemon=off`.

The automatic retry boundary is a fully decoded and validated `ScanResults`
response. Failures before that boundary, including incompatible required wire
fields, retry in process under `auto`. Allowlist loading, finalization, output
creation, serialization, and report writes occur after that boundary. Those
client-side failures return directly and never rescan. This prevents duplicate
or mixed output after a partial write.

An automatic in-process retry uses the normal one-shot autoroute contract. It
does not pin CPU to make the retry succeed. Missing or stale one-shot evidence
therefore remains a visible calibration error.

## Request eligibility

The daemon accepts exactly one primary input:

- `--stdin`, subject to the configured stdin byte limit
- one path whose metadata identifies it as a regular file

Eligible requests may still use client-owned reporting and finalization such as
output formats, output files, deduplication, bundled test-fixture suppression,
local default allowlists, inline suppression, and `--dogfood`. Dogfood detail is
request-scoped and bounded; exact aggregate counters are carried separately.

The in-process orchestrator is required for any of these request classes:

- directories, multiple roots, Git modes, remote, cloud, container, binary,
  dynamic, or mixed sources
- baseline filtering, live verification, or Merkle/incremental source state
- `--fast`, `--deep`, `--precision`, benchmark mode, or changes to decode,
  entropy, ML, Unicode normalization, comment scanning, scanner limits, source
  limits, detector vocabulary, or detector corpus
- per-request backend, GPU, batch-pipeline, autoroute, cache, or calibration
  controls
- path-exclusion changes
- lockdown, secret display, client-safe hiding, confidence or severity floors,
  custom AWS canaries, detector confidence policy, allowlist governance, or a
  malformed effective configuration

In `auto`, these requests stay in process. In `on`, they fail before scanning.
Daemon availability therefore cannot weaken a requested policy or change the
selected detector and engine configuration.

## Identity, wire data, and coverage

Every connection begins with a versioned handshake. Scan clients require all
of these values to match the current client:

- wire version
- KeyHog package version
- Git build hash
- canonical detector-rules digest

The detector digest is compared with the client's embedded detector corpus.
The handshake also carries the daemon-owned backend policy. It must be
`autoroute` or a canonical forced backend label. A scan client rejects an
unknown label. `daemon status` and `daemon stop` tolerate package, build, and
detector identity staleness so an operator can inspect and terminate an old
service. They still require a compatible wire protocol. Stale status prints the
exact mismatch and exits successfully because the health request succeeded.

Current scan results require matches, example-suppression count, dogfood
detail, exact static-recovery rejection aggregates, dropped-detail count, and
source coverage gaps. Missing fields are malformed protocol data. The client
never invents zero values for absent coverage or telemetry.

Coverage gaps include oversized or binary input, unreadable data or Git
objects, archive truncation, unresolved binary section names, source
truncation, structured-source parse failures, unavailable archive duplicate
scans, and Git LFS pointers. The client prints a warning whenever any count is
nonzero. Current exit behavior is:

| Daemon scan outcome | Exit |
|---|---:|
| No findings and complete coverage | `0` |
| One or more findings | `1` |
| No findings and one or more coverage gaps | `13` |
| SIGINT / Ctrl-C | `130` |

A scan with both findings and coverage gaps exits `1` and prints the incomplete
coverage warning. It is not reported as clean.

## Administrative and routing errors

Daemon availability, eligibility, trust, handshake, and ordinary
operator-correctable path errors normally exit `2`. This includes forced
`--daemon=on` without a usable service, `status` or `stop` without a service,
an incompatible forced request, and invalid startup configuration. Low-level
operating-system I/O failures outside the operator-input classes exit `3`.
Daemon GPU validation, initialization, and warmup errors currently exit `2`.
If an `auto` request fails inside the daemon, KeyHog reports the error and
retries in process; the retry then owns its normal exit semantics, including
`12` if its selected or required GPU cannot run.

A fatal listener accept or connection-handler spawn error prints a failure,
stops the service, and currently lets `daemon start` return `0` after socket
cleanup. Treat that logged failure as an unhealthy service even though the
process status is zero.

`daemon status` against an identity-stale but wire-compatible service exits `0`
and prints a warning. `daemon stop` can stop that service. A wire-incompatible
service cannot be inspected or stopped through the current protocol. Stop it
with the matching KeyHog binary or the service manager that owns it.

`daemon start --request-timeout-secs <N>` limits how long a connected client
may take to deliver one complete request frame. The default is `300` seconds.
On timeout, the daemon closes that connection and reclaims its concurrency
slot. This is a request-read deadline, not a scan execution deadline.
