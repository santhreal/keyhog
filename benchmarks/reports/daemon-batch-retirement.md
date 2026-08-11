# Daemon filesystem batch retirement

Daemon-local filesystem acquisition now starts retirement with one `mass_filesystem_drain` request. The daemon emits each bounded result batch and the terminal completion response without waiting for another client request between responses.

## Result

| Metric | Legacy | Pipelined | Change |
|---|---:|---:|---:|
| Bounded result batches | 32 | 32 | unchanged |
| Filesystem retirement requests | 33 | 1 | 33x fewer |
| Files and chunks accounted | 32,768 | 32,768 | exact parity |
| Findings | 0 | 0 | exact parity |
| Scan status | success | success | exact parity |

The legacy client sent one `mass_filesystem_next` request for every result batch and one more for the terminal completion receipt. The pipelined client sends one `mass_filesystem_drain` request. Responses remain separately bounded, ordered, and subject to the existing socket write timeout and backpressure.

## Method

The production mass-daemon client and CPU daemon scanned 32,768 one-byte files on tmpfs. The source emitted 32 batches at the 1,024-chunk ceiling. `strace 6.8` captured `write`, `writev`, `sendto`, and `sendmsg`; the request operation names were counted from framed Unix-socket `writev` calls.

Both binaries exited 0 with `scan_status=success`, 32,768 source chunks, 32,768 source bytes, no coverage gap, and the same empty ordered finding digest. The receipt binds both executable hashes, source revisions, workload hash, and syscall trace hashes.

This evidence measures the eliminated control-plane round trips. It makes no wall-time claim because filesystem discovery and scanning dominate this metadata-heavy workload.

Receipt: [`daemon-batch-retirement.json`](daemon-batch-retirement.json)
