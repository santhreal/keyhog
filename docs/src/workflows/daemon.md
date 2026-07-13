# Daemon and warm scans

The Unix daemon keeps one compiled scanner alive for repeated small scans. It
is useful for editor saves, hooks, and other workflows where compiling the
detector corpus costs more than scanning one file. It is not a second scanner
implementation and it does not replace the full scan orchestrator.

`keyhog watch` is separate: it is a foreground filesystem-event loop with its
own compiled scanner, not a daemon client or daemon-managed process. Starting a
watcher does not create the Unix socket, and `daemon status` does not report it.
Use `watch` for continuous directory monitoring; use `scan --daemon` for an
eligible stdin or single-file request sent to the separately started service.

## Start, inspect, and stop

```sh
keyhog daemon start
keyhog daemon status
keyhog daemon stop
```

The default socket is `$XDG_RUNTIME_DIR/keyhog.sock` when
`XDG_RUNTIME_DIR` is set. Otherwise KeyHog uses the OS user cache directory:
`~/.cache/keyhog/server.sock` on Linux or
`~/Library/Caches/keyhog/server.sock` on macOS. If the OS cache directory is
unavailable (for example, a container without `HOME`), the fallback is the OS
temporary directory plus `keyhog/server.sock`. Use matching
`daemon start --socket <PATH>` and `scan --daemon-socket <PATH>` options for
another location. The transport is a user-only Unix-domain socket. Windows has
no daemon transport: it rejects daemon
commands and explicit `--daemon=auto|on`, while an absent flag or
`--daemon=off` uses the in-process scanner. On Unix, an absent flag has the
documented `auto` behavior and can use a compatible daemon at the selected
socket.

The service owns its startup configuration. `daemon start --detectors <DIR>`
selects its detector corpus, `--cache-dir <DIR>` selects its compiled Hyperscan
cache, and `--backend auto|gpu|simd|cpu` selects persisted autoroute or an
explicit diagnostic backend for requests the service can accept. Client scan
flags never rewrite those daemon-owned choices; the handshake rejects a corpus
or build identity mismatch instead of silently mixing them.

The daemon initializes scanner regex state and runs a bounded real GPU warmup
before announcing readiness. If an eligible physical GPU cannot complete that
probe, daemon startup fails loudly instead of substituting CPU/SIMD. Autoroute
therefore treats it as a persistent warm runtime: GPU decisions use calibrated
warm trials. An in-process one-shot scan uses the same calibration record but
includes the
measured first-dispatch GPU cost. This distinction prevents a warm daemon result
from making a cold CLI scan choose GPU incorrectly.

An explicit daemon backend is validated before the readiness line. For example,
`daemon start --backend gpu` is rejected when this build/host has no eligible
physical GPU, and `--backend simd` is rejected without a live Hyperscan
prefilter; neither request is silently relabeled. Pre-readiness argument,
configuration, or capability rejection exits `2`. Operator-correctable socket
path failures also exit `2`, including a missing socket, permission denial,
invalid path/data, connection refusal, or an already-bound socket. Other
low-level operating-system I/O failures exit `3`, and a selected GPU dispatch
that fails during the real warmup exits `12`. An explicit CPU or SIMD daemon does not warm or require the GPU;
the GPU warmup is mandatory only for daemon autoroute or an explicit GPU
daemon.

## What `--daemon` means

`keyhog scan` has one tri-state daemon policy:

| Value | Behavior |
|---|---|
| `--daemon=auto` | Default. Use a reachable daemon only when it can honor the request. A connection/runtime failure is reported, then the scan runs in process. |
| `--daemon=on` or bare `--daemon` | Require the daemon route. Missing daemon, unsupported request, or IPC failure is an error; KeyHog does not silently substitute an in-process scan. |
| `--daemon=off` | Always use the in-process orchestrator. |

## Requests the daemon can serve

The fast path accepts exactly one input: `--stdin` or one regular file. The
client still applies the shared finding finalization needed by eligible scans,
including inline suppression, allowlist/rule suppression, match resolution, and
deduplication.

The in-process orchestrator is required for directories, multiple inputs, Git
modes, remote/cloud/container/binary sources, baselines, Merkle skip state, live
verification, explicit backend/GPU controls, calibration mode, and policy that
the daemon cannot enforce exactly. Examples of incompatible policy include
lockdown requirements, secret display, explicit confidence or severity floors,
and custom detector/AWS-canary configuration.

In `auto` mode an incompatible request simply stays in process. In `on` mode it
fails with the specific unsupported requirement. This is intentional: daemon
availability must never change findings or weaken policy silently.

Every scan connection performs a versioned handshake that binds the daemon to
the client's package version, Git build identity, and canonical embedded
detector-rules digest. This rejects a daemon left alive across an upgrade and a
same-version daemon started with a different `--detectors` corpus. `daemon
status` and `daemon stop` intentionally tolerate an identity mismatch so the
operator can inspect and terminate it; `status` prints the exact mismatch and
the strict scan route refuses it. In `--daemon=auto` that refusal is visible on
stderr before the identical request runs in process. In `--daemon=on` it is an
error. Wire-v3 scan results require suppression telemetry, dogfood telemetry,
and source-coverage fields on every frame; missing fields are a malformed frame,
not permission to synthesize zeroes that could hide incomplete scanning.

## Autoroute semantics

The daemon does not inherit a client process's backend override. It loads the
persisted fastest-correct decision table for its compiled detector/config/host
identity and resolves each real workload bucket itself. Missing, stale, or
incomplete evidence is an error, just as it is for a one-shot automatic scan.

Calibration stores one real GPU cold dispatch followed by warm trials. A
one-shot scan compares CPU/Hyperscan against the conservative cold-aware GPU
interval. A ready daemon compares against the warm GPU interval because its
accelerator state was initialized before requests were accepted. Scalar CPU,
Hyperscan/SIMD, and GPU remain peer candidates; daemon mode is not permission to
prefer GPU.

## Timeouts and status

`daemon start --request-timeout-secs <N>` bounds the time a client may take to
finish a request frame (default `300`). `daemon status` reports uptime, scans
served, active scans, detector count, and any build/corpus identity mismatch. A
stale socket is removed only after ownership and directory trust checks pass.
