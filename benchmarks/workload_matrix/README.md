# Workload regime matrix

Every other benchmark in this repository scans many small source files. That is
one workload. This harness measures the others.

A scan is not one thing. The same 300 MiB behaves differently as 300 files, as
one file, and as one line. A tree of 4096 nested directories, a directory with
200k entries in it, a tree where almost every file is rejected as binary, a tree
full of symlink cycles, a file being truncated while you read it: each of those
is a distinct regime with its own failure mode, and a scanner that handles one
well can be broken on the next.

## What it measures

For every regime: wall seconds, CPU percent, peak RSS, bytes scanned, total
findings, canary findings, exit code, `scan_status`, and the coverage gaps the
scan admitted to.

The canary column is the one that matters. Every regime plants the same Stripe
secret key (`canary.py`) a known number of times, recorded as `canary_copies` in
the regime's stamp, and the matrix reports `found/planted`. A shortfall is never
ambiguous:

- `8/8` — the scan reached every copy. The row is real.
- `1/8` — the scan reported a credential it can see and missed seven it can also
  see. This is the case a plain "did we find anything" check cannot detect, and
  it is how the mixed-encoding hole hid.

The scan runs with `--dedup file` for exactly this reason. The default
`--dedup credential` collapses the same credential across files into ONE finding,
which would make `1/8` and `8/8` produce identical output. That is the only
deliberate difference from a default scan besides the two entries in
`REGIME_ARGS`.

A shortfall splits further, and the verdicts are ordered by how bad it is:

| verdict | meaning |
| --- | --- |
| `SILENT CLEAN` | a copy was missed, exit 0, and `coverage_gap_summary` is empty. Nothing tells the operator anything was missed. The worst outcome this product can produce. |
| `PANIC` | the scanner died. No report, and every other finding in that scan is lost with it. |
| `NO REPORT` | the scan failed loudly but wrote no machine-readable artifact, so a pipeline reading `-o` gets a missing file. Loud to a shell, silent to everything else. |
| `HANG` | the scan did not finish inside the harness timeout. |
| `BROKEN` | exit 0 and no usable envelope, or a canary count that contradicts the regime's own accounting. |
| `QUIET CLEAN` | a copy was missed and a coverage gap WAS recorded, but the exit code is still 0. A CI gate on `$?` passes over a real credential. |
| `LOUD MISS` | a copy was missed and the scan refused to report success. Working as intended: a gap you can act on. |
| `PARTIAL` | every copy was found, but part of the input was not scanned. |
| `OK` | every copy found, no gaps. |

A verdict is taken from the WORST repetition, not the last. A crash in run 3 that
run 5 does not repeat is still a crash.

When a regime is short a copy, the harness runs one extra `--dogfood` probe to
separate "never read those bytes" from "read them and a suppression gate hid
them". The two have different fixes and the raw numbers cannot tell them apart.

## Running it

```
# Build the corpora once. About 2 GiB at scale 1.0.
python3 benchmarks/workload_matrix/generate.py --root /var/tmp/keyhog-wm

# Measure. Writes a markdown matrix and the raw results.
python3 benchmarks/workload_matrix/run.py \
    --root /var/tmp/keyhog-wm \
    --binary target/release-fast/keyhog \
    --out benchmarks/reports/workload-matrix.md \
    --json-out benchmarks/reports/workload-matrix.json
```

`run.py` exits nonzero on any verdict that a pipeline cannot act on
(`SILENT CLEAN`, `PANIC`, `NO REPORT`, `BROKEN`, `HANG`), so it can gate CI
directly. `QUIET CLEAN`, `LOUD MISS` and `PARTIAL` do not fail the run: they are
admitted, visible gaps.

Useful flags:

- `--only one_long_line deep_nest` — one or more regimes instead of all of them.
- `--scale 0.05` (generate) — a small corpus for a quick smoke build. Every
  regime keeps its shape, only its size shrinks. A regime directory is stamped
  with the scale it was built at, so a rebuild at a different scale is detected.
- `--reps N` (run, default 5) — repetitions. The reported value is the median.
- `--extra --deep` — extra keyhog arguments applied to every regime.
- `--clean` (generate) — remove the corpus root, including the chmod-000
  directory the `unreadable_dir` regime creates.

Stdlib Python only. It does not need `benchmarks/requirements.txt`.

## Reading the numbers

Report the binary, the commit, and the machine load with every number. The
harness records the binary's sha256, size and mtime in the matrix header for
exactly this reason: shared build directories get overwritten, and a comparison
that unknowingly spans two builds is worse than no comparison.

Absolute wall times are not comparable across sessions. Read the ratio between
regimes and the CPU percent. CPU percent is the most useful single number here:
a regime that pins 700% of a 32-core box is using the pool, and a regime stuck
near 90% is running one thread no matter what `--threads` says.

## The regimes

| regime | shape | what it is asking |
| --- | --- | --- |
| `many_small` | 3000 files x 100 KiB | The existing baseline. The control for every other row. |
| `one_large` | 1 file x 300 MiB | The same bytes as one file. Scanned with `--max-file-size 512M`, because the 100 MiB default would make this a cap measurement. |
| `over_max_size` | 1 file just past 100 MiB | Scanned with DEFAULT arguments. What an operator hits by accident with a log or a heap dump. |
| `one_long_line` | 1 file, 50 MiB, ONE line | A minified bundle or a single-line JSON blob. Any line-oriented buffer meets its worst case. Named `single-line.json`, deliberately not `*.min.js`, so the row measures long-line handling and not the minified-path exclusion. |
| `deep_nest` | 4096 nested directories | Depth, not breadth. Built with relative `mkdir` at each level so the walker's own limits bind rather than `PATH_MAX` on the path we pass in. |
| `flat_many` | 200k files in ONE directory | `readdir` batching, not tree walking. |
| `binary_reject` | 2000 x 128 KiB ELF-shaped files | The cost of REJECTION, and whether a credential inside a rejected file is reported as unscanned or vanishes. The canary is inside a genuinely binary file. |
| `symlink_cycle` | self cycle, mutual cycle, dangling, absolute, escaping, plus a 64-link fan at one target | Loop termination and dedup. |
| `no_extension` | `Dockerfile`, `credentials`, `id_rsa`, `blob`, ... | Type inference with no extension to infer from. The canary is in a file named `blob`. |
| `encoding_mixed` | 8 files, 8 encodings, all carrying the canary | UTF-8, BOM, UTF-16LE/BE, latin-1, Shift-JIS, invalid UTF-8, and one file that changes encoding mid-file. |
| `sparse` | 3 files, 64 MiB apparent, 4 KiB allocated | A scanner that budgets by `st_size` for a file it will never actually read. Canary at offset 0, at the end, and absent. |
| `size_changing` | files appended to and truncated WHILE the scan runs | The regime nobody tests. `run.py` starts the mutator; the corpus is rebuilt before every repetition, or the growing file crosses the size cap and the row silently turns into a cap measurement. |
| `empty_dir` | nothing | The control that proves zero findings is not always a bug. The only regime with no canary. |
| `unreadable_dir` | a chmod-000 directory holding the canary, plus a chmod-000 file | The scan must say so and must not report clean. |
| `encoded_midfile` | a Base64 payload in the interior of a 4 MiB file, plus the same payload in a 64 KiB file | Decode-through is capped per CHUNK at 512 KiB while the reader windows at 1 MiB, so a full-size window can never be decode-expanded and the interior of any file over 1 MiB is unreachable. The small file is the control: it MUST be found, otherwise a zero on this row would just mean the encoded canary is undetectable. |
| `all_sources_fail` | one oversize file and nothing else | `over_max_size` with the sibling removed, so EVERY source row errors. A scan that cannot honor its whole input must say so, but it must not discard what it already found, and it must still write the report it was asked for. |

## Adding a regime

Write a `build_<name>(dir, scale) -> dict` in `generate.py`, hide
`canary_bytes()` in it exactly once, and add it to `BUILDERS`. The returned dict
is recorded in the regime's stamp and shows up in the results JSON, so put the
facts that explain the row in it (file counts, byte counts, the depth actually
reached).

If the regime only makes sense with a non-default flag, add it to `REGIME_ARGS`
in `run.py` with a comment saying why. Keep that list short: the matrix measures
the default scan, and every entry there is a documented exception.

If the regime destroys its own corpus by measuring it, add it to `RESEED`.

If the regime is EXPECTED to miss a copy, give it a second copy that must be
found, in the same corpus, as `encoded_midfile` does. A row whose zero cannot be
distinguished from "the harness cannot see this credential at all" is not
evidence. The run-wide preflight covers the whole harness; a per-regime control
covers the specific mechanism that regime is about.
