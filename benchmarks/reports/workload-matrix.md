# Workload regime matrix

- binary: `/tmp/kh-ref-bin/keyhog`
- version: KeyHog v0.5.68
- sha256: `e4f4fcc96c748e1485112438840f70f97eca151ed62b979085b9a59d610433fb`
- binary mtime: 2026-08-04T21:46:28, 49721328 bytes
- corpus root: `/media/mukund-thiru/SanthData/keyhog-wm` (scale 1.0)
- host: 32 cores, load average 52.0, 65.9, 95.7
- reps per regime: 5 (reported value is the median)
- controls: a canary-only file yields 1 canary finding; the same file with the credential shape broken yields 0. Every zero below is measured against a proven-visible baseline.
- generated: 2026-08-04T23:08:29

Absolute wall times on a loaded machine are not comparable across sessions. Read the ratios between regimes and the CPU percent, not the seconds.

| regime | wall s | CPU % | peak RSS | bytes scanned | findings | canary found/planted | exit | status | verdict |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `many_small` | 4.57 | 663 | 643 MiB | 293.0 MiB | 1 | 1/1 | 1 | success | OK |
| `one_large` | 4.79 | 497 | 1109 MiB | 342.8 MiB | 1 | 1/1 | 1 | success | OK |
| `encoded_midfile` | 1.54 | 192 | 532 MiB | 4.6 MiB | 1 | 1/2 | 1 | success | LOUD MISS |
| `over_max_size` | 1.75 | 165 | 504 MiB | 84 B | 1 | 1/2 | 1 | partial | LOUD MISS |
| `one_long_line` | 2.07 | 234 | 575 MiB | 57.1 MiB | 1 | 1/1 | 1 | success | OK |
| `deep_nest` | 49.79 | 90 | 500 MiB | 32 B | 0 | 0/1 | 13 | partial | LOUD MISS |
| `flat_many` | 8.53 | 208 | 583 MiB | 10.3 MiB | 1 | 1/1 | 1 | success | OK |
| `binary_reject` | 0.78 | 282 | 473 MiB | 40 B | 0 | 0/1 | 0 | partial | QUIET CLEAN |
| `symlink_cycle` | 0.74 | 303 | 508 MiB | 103 B | 1 | 1/1 | 1 | success | OK |
| `no_extension` | 0.97 | 254 | 509 MiB | 437 B | 1 | 1/1 | 1 | success | OK |
| `encoding_mixed` | 0.98 | 245 | 629 MiB | 794 B | 7 | 7/8 | 1 | success | LOUD MISS |
| `sparse` | 0.94 | 295 | 658 MiB | 166 B | 0 | 0/2 | 0 | partial | QUIET CLEAN |
| `size_changing` | 1.08 | 355 | 607 MiB | - | 0 | 0/2 | 0 | - | PANIC |
| `empty_dir` | 0.44 | 432 | 466 MiB | - | 0 | 0/0 | 0 | success | OK |
| `unreadable_dir` | 0.51 | 373 | 473 MiB | 16 B | 0 | 0/0 | 13 | partial | PARTIAL |
| `all_sources_fail` | 0.44 | 439 | 465 MiB | - | 0 | 0/1 | 13 | - | NO REPORT |

## What the scan admitted per regime

| regime | coverage gaps | canary suppressed by |
| --- | --- | --- |
| `many_small` | none | - |
| `one_large` | none | - |
| `encoded_midfile` | none | - |
| `over_max_size` | source emitted error rows (requested input was not fully scanned) x1; exceeded --max-file-size x1 | entropy_below_floor |
| `one_long_line` | none | - |
| `deep_nest` | source emitted error rows (requested input was not fully scanned) x2; unreadable (permission denied or I/O error) x2 | - |
| `flat_many` | none | - |
| `binary_reject` | binary (extension or content sniff) x2000 | - |
| `symlink_cycle` | none | - |
| `no_extension` | none | - |
| `encoding_mixed` | none | native_binary_strings |
| `sparse` | binary (extension or content sniff) x1 | native_binary_strings |
| `size_changing` | none | entropy_below_floor |
| `empty_dir` | none | - |
| `unreadable_dir` | source emitted error rows (requested input was not fully scanned) x3; unreadable (permission denied or I/O error) x3 | - |
| `all_sources_fail` | none | - |

## Broken regimes, worst first

- `size_changing`: **PANIC**. killed by SIGBUS in at least one repetition, so the whole scan's report was lost.
- `all_sources_fail`: **NO REPORT**. the machine-readable envelope requested with `-o` was not written, so a pipeline reading it gets nothing to act on. the scan did exit 13, so a shell sees the failure even though no artifact describes it.
- `binary_reject`: **QUIET CLEAN**. found 0 of 1 planted canary copies. exit 0 despite an admitted coverage gap, so a CI gate on the exit code passes over the missed credential.
- `sparse`: **QUIET CLEAN**. found 0 of 2 planted canary copies. a `--dogfood` probe of this corpus reports a canary-shaped credential suppressed by `native_binary_strings`. That proves a suppression gate is active on this input; it does not by itself prove the MISSING copy went that way rather than never being read. Compare bytes scanned. exit 0 despite an admitted coverage gap, so a CI gate on the exit code passes over the missed credential.
- `encoded_midfile`: **LOUD MISS**. found 1 of 2 planted canary copies. the scan refused to report success (exit 1).
- `over_max_size`: **LOUD MISS**. found 1 of 2 planted canary copies. a `--dogfood` probe of this corpus reports a canary-shaped credential suppressed by `entropy_below_floor`. That proves a suppression gate is active on this input; it does not by itself prove the MISSING copy went that way rather than never being read. Compare bytes scanned. the scan refused to report success (exit 1).
- `deep_nest`: **LOUD MISS**. found 0 of 1 planted canary copies. the scan refused to report success (exit 13).
- `encoding_mixed`: **LOUD MISS**. found 7 of 8 planted canary copies. a `--dogfood` probe of this corpus reports a canary-shaped credential suppressed by `native_binary_strings`. That proves a suppression gate is active on this input; it does not by itself prove the MISSING copy went that way rather than never being read. Compare bytes scanned. the scan refused to report success (exit 1).
- `unreadable_dir`: **PARTIAL**. every canary copy was found, but part of the input was not scanned.
