# Warm incremental scanner-dispatch bypass

Commit `96e6a5cbf26d180b6162a063d542f7c0e68d7312` defers backend-router and scanner-worker setup until source acquisition emits a changed chunk.

## Result

| Production path | Cold dispatch setups | Warm all-unchanged setups | Change |
|---|---:|---:|---:|
| Fused filesystem pipeline | 1 | 0 | eliminated |
| Coalesced `--batch-pipeline` | 1 | 0 | eliminated |

The production-path regression drives both pipelines over the same clean file and trusted Merkle index. The cold scan starts dispatch once. The warm scan closes acquisition with zero dispatch setups. Reintroducing eager coalesced setup made the regression fail with `left: 1`, `right: 0`.

A committed release binary then ran 20 warm trials per pipeline against 2,000 clean files and an external Merkle cache. All 40 trials exited `0`, reported zero findings, emitted no zero-byte coverage failure, and did not load an autoroute decision. Ordered finding parity is SHA-256 `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945` for the canonical empty finding array.

The exact host, workload, executable, mutation, and gate receipt is in [`incremental-startup.json`](incremental-startup.json).

## Scope

This result claims complete elimination of scanner-dispatch setup for an all-unchanged workload. It does not claim an end-to-end wall-time speedup. Process startup and scanner materialization still dominate this small metadata-only workload; changing those costs belongs to matcher-artifact startup work rather than this dispatch boundary.
