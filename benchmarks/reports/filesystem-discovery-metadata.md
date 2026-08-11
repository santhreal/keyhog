# Filesystem discovery metadata retirement

Ordinary unbounded filesystem scans now classify archive symlinks during the configured metadata walk. The separate full-tree archive-symlink audit remains only for byte-budgeted discovery, where path-sorted charging is part of the boundary contract.

## Result

| Metric | Legacy | Fused | Change |
|---|---:|---:|---:|
| Archive-symlink audit walks | 1 | 0 | 100% eliminated |
| Required configured metadata walks | 1 | 1 | unchanged |
| `getdents64` calls | 71 | 37 | 34 fewer (47.89%) |
| Files and chunks accounted | 32,768 | 32,768 | exact parity |
| Findings | 0 | 0 | exact parity |

The `statx` count remained 99,356 in both runs. This change retires directory re-enumeration; required file metadata and no-follow reader checks remain.

## Method

The production in-process CPU route scanned 32,768 one-byte files on tmpfs. `strace 6.8` summarized `statx`, `newfstatat`, `getdents64`, and `readlink` for each immutable release binary. Both runs exited 0 with `scan_status=success`, identical source-byte and chunk accounting, and the same ordered finding digest.

Archive-symlink regressions cover ordinary and byte-budgeted discovery, dangling targets, target-derived archive classification, descriptor-relative long-path replacement, exact refusal ordering, and one refusal per expandable symlink.

One configured discovery walk is required, so removing one redundant audit cannot produce a 10x reduction in total traversal syscalls. The redundant walk itself is eliminated completely.

Receipt: [`filesystem-discovery-metadata.json`](filesystem-discovery-metadata.json)
