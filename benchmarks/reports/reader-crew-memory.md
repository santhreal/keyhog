# Default reader crew memory

The default filesystem path now uses one reader that emits directly into the bounded scanner channel. Explicit widths above one retain ordered reassembly and deterministic output.

## Result

| Metric | Legacy default | One direct reader | Change |
|---|---:|---:|---:|
| Reader threads | 4 | 1 | 75% fewer |
| Ordered-reassembly threads | 1 | 0 | eliminated |
| Source-side worker threads | 5 | 1 | 80% fewer |
| Maximum RSS | 186,408 KiB | 67,204 KiB | 119,204 KiB lower (63.95%) |
| Elapsed time | 3,570.768 ms | 3,569.016 ms | no material change |
| Accounted bytes | 536,870,912 | 536,870,912 | exact parity |
| Accounted chunks | 592 | 592 | exact parity |

The maximum-RSS ratio is 2.774x. The scanner and required single reader remain resident, so this source-layer change cannot produce a 10x reduction in whole-process RSS.

## Method

Immutable release binaries scanned sixteen 32 MiB files from tmpfs through the production in-process CPU route. `/usr/bin/time -v` recorded process memory and CPU time. Both runs exited 0 with `scan_status=success`, zero findings, and exact source-byte and chunk accounting.

The regression suite compares every emitted source type, path, base offset, body byte, error, and output position between reader widths one and four. Its fixture includes a multi-window file, so direct output cannot silently reorder file parts. The existing part, byte, and chunk flush ceilings remain unchanged.

Receipt: [`reader-crew-memory.json`](reader-crew-memory.json)
