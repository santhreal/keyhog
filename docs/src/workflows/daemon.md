# Daemon and warm scans

The Unix daemon keeps one compiled scanner alive for repeated small scans. It
is useful for editor saves, hooks, and other workflows where compiling the
detector corpus costs more than scanning one file. It is not a second scanner
implementation and it does not replace the full scan orchestrator.

## Start, inspect, and stop

```sh
keyhog daemon start
keyhog daemon status
keyhog daemon stop
```

The default socket is `$XDG_RUNTIME_DIR/keyhog.sock`, falling back to
`~/.cache/keyhog/server.sock`. Use matching `daemon start --socket <PATH>` and
`scan --daemon-socket <PATH>` options for another location. The transport is a
user-only Unix-domain socket; Windows has no daemon transport and rejects daemon
commands and `--daemon=on` explicitly.

The daemon initializes scanner regex state and runs a bounded real GPU warmup
before announcing readiness. If an eligible physical GPU degrades during that
probe, daemon startup fails loudly. Autoroute therefore treats it as a persistent warm
runtime: GPU decisions use calibrated warm trials. An in-process one-shot scan
uses the same calibration record but includes the measured first-dispatch GPU
cost. This distinction prevents a warm daemon result from making a cold CLI scan
choose GPU incorrectly.

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
served, active scans, and detector count. A stale socket is removed only after ownership
and directory trust checks pass.
