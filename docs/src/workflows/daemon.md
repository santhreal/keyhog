# Daemon and warm scans

The Unix daemon keeps one compiled scanner alive for repeated small scans. It
is useful for editor saves, hooks, and other workflows where compiling the
detector corpus costs more than scanning one file. It is not a second scanner
implementation and it does not replace the full scan orchestrator.

Use it for repeated eligible `stdin` or single-file requests. Use the
in-process orchestrator for repository-wide and multi-source work:

```sh
# Repeated small scans: start once, then allow the default daemon=auto policy.
keyhog daemon start
keyhog scan --stdin < changed-file.txt

# Large trees and multi-source scans always use the full in-process path.
keyhog scan --daemon=off /large/repository
```

A running daemon is passive until an eligible client connects. KeyHog never
starts it implicitly. Conversely, a running daemon does not capture every scan:
directories, multiple inputs, and policy the protocol cannot represent remain
in process.

`keyhog watch` is separate: it is a foreground filesystem-event loop with its
own compiled scanner, not a daemon client or daemon-managed process. Starting a
watcher does not create the Unix socket, and `daemon status` does not report it.
Use `watch` for continuous directory monitoring; use `scan --daemon` for an
eligible stdin or single-file request sent to the separately started service.

## Start, confirm readiness, and stop

```sh
keyhog daemon start
keyhog daemon status
keyhog daemon stop
```

`daemon start` first prints that compilation is in progress, then prints a
separate readiness line after scanner initialization, backend validation, and
socket binding complete. Only the readiness line means the daemon can accept
requests. `daemon status` checks the existing process; it does not start one.

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

An autorouted daemon initializes scanner regex state and runs a bounded real GPU
warmup before announcing readiness when a physical GPU is eligible. If that GPU
cannot complete the probe, startup fails loudly instead of substituting
CPU/SIMD. Autoroute therefore treats a ready daemon as a persistent warm
runtime: GPU decisions use calibrated warm trials. An in-process scan uses the
same calibration record but includes the measured first-dispatch GPU cost.
These are separate derived decisions, not one generic "GPU time."

An explicit daemon backend is validated before the readiness line. For example,
`daemon start --backend gpu` is rejected when this build/host has no eligible
physical GPU, and `--backend simd` is rejected without a live Hyperscan
prefilter; neither request is silently relabeled. Pre-readiness argument,
configuration, or capability rejection exits `2`. Operator-correctable socket
path failures also exit `2`, including a missing socket, permission denial,
invalid path/data, connection refusal, or an already-bound socket. Other
low-level operating-system I/O failures exit `3`, and a selected GPU dispatch
that fails during the real warmup exits `12`. An explicit CPU or SIMD daemon
does not warm or require the GPU; the GPU warmup is mandatory only for daemon
autoroute or an explicit GPU daemon.

## What `--daemon` means

`keyhog scan` has one tri-state daemon policy. On Unix, omitting the flag is the
same as `--daemon=auto`:

| Policy | Compatible daemon active | Daemon inactive, stale, or request incompatible |
|---|---|---|
| `--daemon=auto` (default on Unix) | Send an eligible request to the daemon. If IPC or daemon execution fails, report it and retry the same eligible workflow in process. | Stay or retry in process after reporting a connection/identity failure; an incompatible request is kept in process without sending it. |
| `--daemon=on` or bare `--daemon` | Require the daemon response. | Fail with the specific availability, identity, or eligibility error. No in-process substitution occurs. |
| `--daemon=off` | Do not connect; run in process. | Run in process. |

An automatic in-process retry is still an automatic scan: it uses the one-shot
autoroute decision for its real workload. If that decision is missing or stale,
the retry fails closed with `autoroute calibration required`; it does not pin a
CPU backend to make the retry succeed.

## Small requests the daemon can serve

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

## Repository and mass scans

Directory trees, multiple inputs, Git history, remote sources, and other
high-volume workflows use the in-process orchestrator whether or not the daemon
is active. That path can overlap source reads with fused scanner batches and can
represent the complete source, verification, baseline, and reporting policy.

Autoroute decisions are looked up for the concrete batches produced by that
workflow. A calibration entry covers one exact workload key, whose numeric
dimensions are logarithmic ranges measured using a representative input; it is
not proof for every byte length inside the range. If any required key is absent,
KeyHog reports the missing key and fails closed instead of borrowing a
neighbouring range or silently selecting CPU. Run `keyhog calibrate-autoroute`
for the core file/tree ladder or the installer calibration for source-specific
fixtures. See [Autoroute calibration](../reference/autoroute-calibration.md).

Every scan connection performs a versioned handshake that checks the daemon's
wire version, package version, Git hash, and detector-rules digest against the
client. This rejects a daemon left alive across an upgrade and a same-version
daemon started with a different `--detectors` corpus. `daemon
status` and `daemon stop` intentionally tolerate an identity mismatch so the
operator can inspect and terminate it; `status` prints the exact mismatch and
the strict scan route refuses it. In `--daemon=auto` that refusal is visible on
stderr before the identical request runs in process. In `--daemon=on` it is an
error. Scan-result frames require suppression telemetry, dogfood telemetry, and
source-coverage fields; missing fields are malformed protocol data, not
permission to synthesize zeroes that could hide incomplete scanning.

## Autoroute semantics

The daemon does not inherit a client process's backend override. It loads the
persisted fastest-correct decision table for its compiled detector/config/host
identity and resolves each real workload bucket itself. Missing, stale, or
incomplete evidence is an error, just as it is for a one-shot automatic scan.

Calibration records warm CPU/Hyperscan trials and one real GPU first dispatch
followed by warm GPU trials. An in-process lookup compares the CPU/Hyperscan
medians with the conservative cold-aware GPU representative. A ready daemon
compares against the warm GPU median because accelerator state was initialized
before requests were accepted. Scalar CPU, Hyperscan/SIMD, and the acquired GPU
runtime remain peer execution classes; daemon mode is not permission to prefer
GPU. GPU driver implementations are not independent autoroute candidates: the
scanner exposes the single GPU runtime it acquired as the GPU class.

`keyhog backend --autoroute` renders separate `one-shot` and `daemon` rows for
every calibrated workload. Its JSON form names the persisted cold-aware route
as `backend` and the warm route as `daemon_backend`, with separate confidence,
basis, and margin fields for each. Neither runtime silently executes a different
backend after selection: unavailable SIMD fails, and unavailable or failed GPU
execution fails with the GPU error status.

## Timeouts and status

`daemon start --request-timeout-secs <N>` bounds the time a client may take to
finish a request frame (default `300`). `daemon status` reports uptime, scans
served, active scans, detector count, and any build/corpus identity mismatch. A
stale socket is removed only after ownership and directory trust checks pass.

The status counter labeled `scans served` currently counts completed scan
attempts, including attempts that returned a daemon error. Use it as activity
telemetry, not as a success counter.
