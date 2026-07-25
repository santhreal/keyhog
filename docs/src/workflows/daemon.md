# Daemon and warm scans

The Unix daemon keeps one compiled scanner and its backend state warm. It is
useful for repeated standard-policy scans of `stdin` or one regular file.
Directory, repository, remote, watch, and system-wide scans require the
in-process orchestrator. Automatic routing keeps them in process. Required
daemon mode rejects them instead of falling back.

Starting the daemon is an explicit operational step. KeyHog never starts one
for you. Run the server in one terminal or under a service manager:

```sh
# Terminal 1. This stays in the foreground until stop or a fatal service error.
keyhog daemon start
```

Wait for the ready line before sending required requests. Use a second
terminal for scans and administration:

```sh
# Terminal 2. Omitted --daemon means --daemon=auto on Unix.
keyhog scan --stdin < changed-file.txt
keyhog scan path/to/one-file.txt

# Require daemon execution. This fails rather than changing execution mode.
keyhog scan --daemon=on path/to/one-file.txt

# Guarantee in-process execution even while the daemon is ready.
keyhog scan --daemon=off path/to/one-file.txt

keyhog daemon status
keyhog daemon stop
```

`keyhog watch` is separate. It is a foreground filesystem watcher with its own
compiled scanner. It does not use the daemon socket and does not appear in
`daemon status`.

The `watch` and `scan-system` subcommands do not accept `--daemon`. Each
compiles and owns an in-process scanner. A running daemon neither serves nor
accelerates those commands.

## Lifecycle and readiness

`daemon start` prints a compilation message first. The service can accept
requests only after this line appears:

```text
keyhog daemon ready on <socket> (<count> detectors, wire=<version>)
```

The ready line follows detector loading, scanner compilation, backend
validation and warmup, socket binding, and socket permission checks. Startup
fails instead of announcing readiness when any required step fails. With a
valid decision table, an autorouted daemon warms only peers selected by at
least one persisted warm-daemon route. An acquired but unused peer cannot block
readiness, while every selected peer must initialize and warm successfully.
With missing, stale, or invalid autoroute state, the daemon becomes ready with
only scalar correctness recovery initialized. Each affected request reports
`autoroute-invalid`, recovered ranges and bytes, and recalibration guidance;
neither daemon health nor scan output calls that recovery autoroute. A forced
`--backend gpu-cuda|gpu-wgpu|simd|cpu` is a diagnostic startup choice and must
be usable as requested. See
[Autoroute calibration](../reference/autoroute-calibration.md).

GPU startup failures retain their stage and exit `12`. This covers required
GPU preflight, scanner compilation, an unavailable or incompatible backend,
and degradation during the readiness warmup. The diagnostic tells the operator
to run `keyhog backend --self-test`, repair the driver/runtime, or start with
`--backend simd` or `--backend cpu`. An invalid backend value or unrelated
daemon configuration error remains exit `2`.

After readiness, an automatically routed accelerated-backend fault does not kill
the service or drop the request. The daemon warns and replays that request's
stable text or file input through the fastest remaining measured-correct peer.
GPU recovery replays only exact unprocessed ranges. The daemon records recovered
ranges and bytes, quarantines that workload route, and keeps unrelated requests alive. Later
requests for the quarantined workload warn and complete through scalar
correctness recovery with recalibration guidance. Runtime route health is
persisted separately from timing evidence, so restarting the daemon cannot
erase quarantine; successful
recalibration clears only the repaired workload identity. A forced GPU daemon
remains an explicit contract and returns a request error instead of substituting
another backend.

`daemon status` connects to an existing service. It reports uptime, completed
scan attempts, active scans, detector count, backend policy, and identity
staleness. `scans served` includes attempts that returned a daemon error, so it
is an activity counter rather than a success counter. Status never starts a
daemon. `active scans` counts accepted scan attempts until their blocking task
finishes, including attempts queued behind the scanner's fragment-state lock.
Backend health reports the number of recovered requests and the last failed and
recovery backend with recovered byte count. `autoroute-invalid -> cpu-fallback`
means the request completed exactly, but the daemon has no usable proof-backed
route for that workload. Before the first affected request, status prints
`backend policy: autoroute invalid` and the scalar-recovery repair command, so a
ready socket cannot disguise invalid startup evidence as calibrated autoroute.
After a restart with persisted runtime quarantine, status instead prints
`backend policy: autoroute degraded`; healthy workload routes remain usable and
affected routes report scalar recovery until recalibration clears them.
The daemon can frame multiple client connections concurrently, but production
scanner execution is serialized so fragment state cannot cross requests.

`daemon stop` sends a shutdown request and succeeds after receiving the
acknowledgement. The server then stops accepting connections and removes the
socket. The current implementation does not wait for other active scan handlers
to finish. Check that `daemon status` reports `0 active` before stopping when
in-flight requests must complete. An abrupt process exit can leave a socket
entry. The next start removes it only after the stale-socket trust checks pass.

Use the service manager as the process owner when it started the daemon. Before
restarting, run `daemon status` against the same socket and wait for
the status line to show `0 active` when requests must finish. Then use
`daemon stop`, or stop the
service-manager unit. Start the replacement process and wait for its ready line.
Do not delete a live socket to restart the service. Removing the path does not
stop the listener and can leave an unreachable daemon running.

## Socket selection and trust

The server, scan client, status command, and stop command use the same default
socket resolver:

1. `$XDG_RUNTIME_DIR/keyhog.sock` when `XDG_RUNTIME_DIR` is set.
2. The OS user-cache directory plus `keyhog/server.sock`.
3. The OS temporary directory plus `keyhog/server.sock`.

The usual cache paths are `~/.cache/keyhog/server.sock` on Linux and
`~/Library/Caches/keyhog/server.sock` on macOS. There is no KeyHog socket
environment variable. For a fixed location, pass the same path at both ends:

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

`--daemon=on` and bare `--daemon` require the daemon route. If the daemon is unavailable or cannot
honor the request's source or policy, that is an error and the scan exits with
the specific diagnostic; no in-process retry is attempted. Use
`--daemon=auto` when an opportunistic daemon attempt with an in-process retry
is the intended behavior: use a reachable daemon only when it can honor the request.

`--daemon-socket` cannot be combined with `--daemon=off`.

The socket state and daemon state are separate signals. Use this matrix when
diagnosing an automatic route:

| Observed state | `--daemon=auto` / omitted | `--daemon=on` | `daemon status` / `daemon stop` |
|---|---|---|---|
| No socket entry | Run in process with no daemon diagnostic. | Fail with daemon-unavailable exit `2`. | Fail with service-unavailable exit `2`. |
| Trusted stale `0600` socket | Attempt once, report the connection failure, then retry in process. Automatic scans never unlink it. | Fail with the specific stale/availability error. | Inspect or stop only after a trusted handshake; stale cleanup belongs to the next trusted `daemon start`. |
| Live compatible daemon | Send the eligible request and use its validated result. | Send the eligible request and require its result. | Report live identity and counters, or acknowledge stop. |
| Live but wire-incompatible daemon | Report the mismatch, then retry an eligible request in process. | Fail before scanning with the exact wire mismatch. | Report the mismatch; the current protocol does not inspect or stop it. |
| Untrusted entry or peer | Report the trust failure, then retry an eligible request in process. | Fail before scanning with the exact trust error. | Refuse to unlink or operate on the entry. |

Some compatibility failures can be known only after connecting. This includes
a detector identity or wire mismatch. Under `auto`, KeyHog reports that failure
and retries the same eligible input in process. Under `on`, it returns the
failure without rescanning. A request that is known to be unsupported from its
source or policy does not connect in either mode.

The automatic retry boundary is a fully decoded and validated `ScanResults`
response. Failures before that boundary, including incompatible required wire
fields, retry in process under `auto`. Allowlist loading, finalization, output
creation, serialization, and report writes occur after that boundary. Those
client-side failures return directly and never rescan. This prevents duplicate
or mixed output after a partial write.

`stdin` is single-consumer, so the client acquires it into one bounded replay
buffer before sending `ScanText`. If an automatic daemon request fails before
the validated result boundary, the in-process retry scans that same buffer as
the `stdin` source. It does not read the pipe again, and it preserves the
configured byte limit, source metadata, and lossy UTF-8 decoding. A successful
daemon response releases the buffer with the rest of the request.

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

The daemon can use an explicit replacement corpus. Start it and scan with the
same reviewed directory:

```sh
keyhog daemon start --detectors ./reviewed-detectors
keyhog scan --daemon=on \
  --detectors ./reviewed-detectors \
  --detectors-mode=replace \
  one-file.txt
```

The daemon startup flag always selects a complete replacement corpus. It does
not compose that directory over the embedded corpus. The scan-side
`--detectors-mode=replace` spelling is optional, but makes the contract visible.
The client derives the expected rules identity from its selected directory.
The warm route is accepted only when the daemon compiled the exact same rules.
The report records the replacement count, digest, source, and mode.

`--detectors-mode=overlay` is not daemon-compatible. The daemon cannot rebuild
its warm scanner for a per-request overlay. With `--daemon=auto`, an overlay
scan stays in process without opening the socket. With `--daemon=on`, it fails
before scanning. Use `--daemon=off` to make the supported execution mode
explicit:

```sh
keyhog scan --daemon=off \
  --detectors ./site-detectors \
  --detectors-mode=overlay \
  source-tree/
```

If the client and daemon select different replacement corpora, the handshake
fails. `auto` prints the identity error and retries in process. `on` prints the
identity error and exits. It never substitutes the daemon's corpus.

The in-process orchestrator is required for any of these request classes:

- directories, multiple roots, Git modes, remote, cloud, container, binary,
  dynamic, or mixed sources
- baseline filtering, live verification, or Merkle/incremental source state
- `--fast`, `--deep`, `--precision`, benchmark mode, or changes to decode,
  entropy, ML, Unicode normalization, comment scanning, scanner limits, source
  limits, detector vocabulary, or detector overlay composition
- a replacement corpus whose rules identity does not exactly match the warm
  daemon; this mismatch is detected during the handshake
- per-request backend, GPU, batch-pipeline, autoroute, cache, or calibration
  controls
- path-exclusion changes
- lockdown, secret display, client-safe hiding, confidence or severity floors,
  custom AWS canaries, detector disable or confidence policy, allowlist
  governance, or a malformed effective configuration

In `auto`, requests rejected by source or policy stay in process. A replacement
identity mismatch is the exception described above because it is learned from
the handshake, after which `auto` reports it and retries in process. In `on`,
every unsupported or incompatible request fails without an in-process scan.
Daemon availability therefore cannot weaken a requested policy or change the
selected detector and engine configuration.

These distinctions are useful when checking an unsupported combination:

```sh
# Supported in process. Auto also keeps this directory request in process.
keyhog scan --daemon=off source-tree/

# Unsupported as a required daemon request. This exits before scanning.
keyhog scan --daemon=on source-tree/

# Unsupported as a required daemon request because overlays are per scan.
keyhog scan --daemon=on \
  --detectors ./site-detectors --detectors-mode=overlay one-file.txt
```

## Identity, wire data, and coverage

Every connection begins with a versioned handshake. Scan clients require all
of these values to match the current client:

- wire version
- KeyHog package version
- Git build hash
- canonical detector-rules digest

For the default corpus, the detector digest is compared with the client's
embedded rules. For an explicit replacement corpus, the client derives the
expected digest from its own selected directory and accepts only an exact match.
Overlay composition is not daemon-eligible. The handshake also carries the
daemon-owned backend policy. It must be `autoroute` or a canonical forced backend
label. A scan client rejects an unknown label. `daemon status` and `daemon stop`
tolerate package, build, and detector identity staleness so you can inspect and
terminate an old service. They still require a compatible wire protocol.
Stale status prints the exact mismatch and exits successfully because the health
request succeeded.

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
Daemon GPU validation, initialization, and warmup failures exit `12`. A forced
GPU dispatch failure after readiness returns a request error. An autorouted
dispatch fault completes against the same stable request through the visible
recovery contract when full coverage is possible.
If an `auto` request fails inside the daemon, KeyHog reports the error and
retries in process; the retry then owns its normal exit semantics, including
automatic backend recovery or `12` when GPU was explicitly required.

A fatal listener accept or connection-handler spawn error prints a failure,
stops the service, removes the daemon socket, and makes `daemon start` exit `3`.
The typed service failure remains distinct from requested `daemon stop`, which
cleans up the same socket and leaves `daemon start` at exit `0`.

`daemon status` against an identity-stale but wire-compatible service exits `0`
and prints a warning. `daemon stop` can stop that service. A wire-incompatible
service cannot be inspected or stopped through the current protocol. Stop it
with the matching KeyHog binary or the service manager that owns it.

`daemon start --request-timeout-secs <N>` limits how long a connected client
may take to deliver one complete request frame. The default is `300` seconds.
On timeout, the daemon closes that connection and reclaims its concurrency
slot. This is a request-read deadline, not a scan execution deadline.

After a request is sent, the client applies a response deadline by request
kind. `Hello`, `Health`, and `Shutdown` use 5 seconds. `ScanText` uses 60
seconds. `ScanPath` uses 300 seconds. A timeout fails with restart guidance.
Automatic scan routing may then use its documented in-process recovery path,
while `--daemon=on`, `daemon status`, and `daemon stop` return an error.
