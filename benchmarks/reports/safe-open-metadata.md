# Safe-open metadata reuse

Safe-open now returns the descriptor metadata captured while validating that an opened path is a regular file. Filesystem whole-file and windowed mmap admission, compressed-input reads, binary analysis, Ghidra output parsing, and Docker capped reads reuse that snapshot instead of querying the descriptor again. A windowed read that abandons mmap refreshes descriptor metadata before its later buffered fallback so a file cannot grow past the hard cap between those phases.

## Result

| Metric | Baseline | Candidate | Change |
|---|---:|---:|---:|
| `statx` calls | 13,084 | 10,084 | 3,000 fewer (22.93%) |
| Redundant post-validation metadata queries | 3,000 | 0 | 100% eliminated |
| `openat` calls | 4,011 | 4,011 | unchanged |
| `flock` calls | 6,002 | 6,002 | unchanged |
| Source chunks and bytes | 3,002 / 307,200,560 | 3,002 / 307,200,560 | exact parity |
| Findings | 1 | 1 | exact ordered parity |
| Coverage gaps | 0 | 0 | exact parity |

The unchanged open and advisory-lock counts confirm that the optimization does not bypass the no-follow opener or torn-write lock. Safe-open validation still performs one descriptor metadata query per regular file and refuses non-regular inputs before reading. The measured workload does not enter the exceptional windowed buffered-fallback path, whose later descriptor refresh remains required for its TOCTOU cap.

## Method

`strace 6.8 -f -c` measured immutable release binaries running the production filesystem scan with an explicit CPU backend, JSON-envelope output, and a 200 MiB file cap. The tmpfs workload contains 3,000 100 KiB input files, 307,200,000 input bytes, and input SHA-256 `138221eb1b8a0dd9cd2bab532669cf35162e525d6762b1d42b533cf7a6fcd301`. The workload manifests add two scanned chunks.

Both scans exited 1 because the canonical workload contains one expected finding. Both reported `scan_status=success`, the same detector and configuration digests, identical source accounting, no coverage gaps, and ordered-findings SHA-256 `6e0b7686455400cf6beb328293d301dff5598c0660c0281d7b700d72781b7b01`.

One descriptor metadata query remains necessary for safe-open regular-file validation. Discovery metadata and unrelated `statx` calls also remain, so total `statx` cannot improve by 10x. The affected redundant query is eliminated completely.

Receipt: [`safe-open-metadata.json`](safe-open-metadata.json)
