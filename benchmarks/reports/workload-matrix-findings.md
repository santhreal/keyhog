# Workload regimes: what is broken

Companion to `workload-matrix.md`, which holds the generated numbers. Harness and
regime definitions are `benchmarks/workload_matrix/`.

Binary for every number here: `/tmp/kh-ref-bin/keyhog`, KeyHog v0.5.68, commit
`044cfdc4259766900033a42d12b8266183a1d60f`, ci-lean release-fast, sha256
`e4f4fcc96c748e1485112438840f70f97eca151ed62b979085b9a59d610433fb`. Machine: 32
cores, load average 52 to 190 across the session, roughly 25 other agents active.
Absolute wall times are not comparable across sessions; read ratios and CPU
percent.

Every zero below is measured against a control: a canary-only file scans to
exactly one finding and the same file with the credential shape broken scans to
zero, asserted at the start of every run before any regime is measured.

## The premise checks out, quantified

The report that started this was a single 300 MiB file against the same bytes as
many files. Both regimes scan 300 MiB with the identical detector corpus:

| | `many_small` (3000 x 100 KiB) | `one_large` (1 x 300 MiB) | ratio |
| --- | --- | --- | --- |
| wall, median of 5 | 4.57 s | 4.79 s | 1.05x |
| CPU percent | 663 | 497 | 0.75x |
| peak RSS | 643 MiB | 1109 MiB | 1.72x |

The memory and parallelism halves reproduce and are worse than reported: 72
percent more peak RSS, not 33, and three quarters of the parallelism. The wall
gap is inside the noise on a machine at load 52; do not quote the 1.05x.

Note `one_large` needs `--max-file-size 512M` to be measured at all. At the
100 MiB default the same file is refused outright, which is its own row.

## Broken, worst first

### 1. SIGBUS kills the scan when a file is truncated under it. FIXED.

`size_changing` writes to one file and truncates another while the scan runs.
The scanner mapped files and read through the mapping, and there is no race-free
way to do that: `ftruncate` from any other process invalidates the page-cache
pages past the new EOF and the next touch raises `SIGBUS`. No handler, no report,
no findings for anything else in that scan.

Measured, 8 trials per size while a second thread truncated and refilled:

| file size | reference `e4f4fcc9` | patched `50138ccf` |
| --- | --- | --- |
| 128 KiB | 0/8 died by signal 7 | 0/8 |
| 800 KiB | **4/8 died by signal 7** | **0/8** |
| 32 MiB | 3/6 died by signal 7 | not fixed, see below |

Not an exotic input. `scan-system` walks live filesystems where logs rotate, so
one rotating file could destroy a whole-system scan.

Fixed in `crates/sources/src/filesystem/read/raw.rs`: `read_file_mmap` is now
`read_file_whole_capped` and reads the already-open descriptor into an owned
buffer. Same `open_file_safe` (same `O_NOFOLLOW`, same `LOCK_SH`), same post-open
re-stat, same 2 GiB hard cap. A shrink becomes a short read and growth becomes
extra bytes scanned; neither can fault. This is designed out rather than retried,
and it costs nothing: `read_file_buffered`'s own comment already recorded that
the mmap path could never move its backing store into the decoded `String` and so
always paid a full copy the buffered path avoids.

Proof the regression test catches it: at pristine HEAD, with only the new test
added, `cargo test -p keyhog-sources --test all_tests` dies with
`signal: 7, SIGBUS: access to undefined memory`. With the fix it passes. Test is
`crates/sources/tests/adversarial/whole_file_read_survives_concurrent_truncation.rs`;
the source-structure gate in `regression_oom_unbounded_read_caps.rs` is updated to
pin the new contract (no `MmapOptions` in that module) instead of the old one.

**Still open, owned:** `crates/sources/src/filesystem/read/window.rs:232` maps
large files the same way and is the 32 MiB row. Handed to LargeFileRegime with
the repro; they confirmed it, confirmed their in-flight patch neither causes nor
widens it, and took the conversion to a read-based window path as a follow-up
rather than bundling it, because their byte-identical-findings evidence was all
measured through the mmap path. `read/bytes.rs:151` maps compressed input and is
the same class, unmeasured.

### 2. A NUL byte anywhere in a text file hides every credential in it.

`encoding_mixed` plants the canary in eight encodings. Seven are found. The one
that is not is `mixed.env`: a 100-byte file whose plain-ASCII
`STRIPE_SECRET_KEY=sk_live_...` line is visible in a hexdump, preceded by one
UTF-16LE segment. Twelve embedded NUL bytes flip the whole file onto the
printable-strings path, and every named detector without a
`[detector.credential_shape]` is then dropped as `native_binary_strings`.
**Four detectors declare one.**

That count is derived, not remembered: parsing every `detectors/*.toml` except
`corpus.toml` with `tomllib` and testing for `[detector.credential_shape]` gives
4 of 925 (`anthropic-api-key`, `aws-access-key`, `notion-api-key`,
`notion-oauth-secret`), with a control confirming the same parser finds
`detector.id` in all 925. An earlier draft said "4 of 924", which was wrong twice:
it counted `corpus.toml` as a detector, and the corpus has since grown by one. The
numerator, which is the part the defect turns on, was right both times.

Scanned alone, that file is a complete silent clean: exit 0, `scan_status`
`success`, `coverage_gap_summary` empty, zero findings, and nothing at all on
stderr under `--quiet`. `--dogfood` shows `kind=example_suppressed`
`reason=native_binary_strings`.

`sparse` is the same gate with a different trigger: a `.log` file holding one
Stripe key at offset 0 and a 64 MiB hole. Same silent clean.

Not fixed by me. `crates/scanner/src/suppression/api.rs:449` is owned by
BinaryRecovery, who found the same root cause from the archive side; both repros
are handed over. The two triggers matter because neither file is a binary by
extension or by format, so a fix scoped to "real binaries" would miss them.

Also worth naming: this hole is masked by any sibling finding. In the directory
scan the row reads `7/8` and exit 1, because seven other files reported. Only the
per-file canary accounting makes it visible at all; a "did we find anything"
check cannot see it.

### 3. A loud failure writes no machine-readable report.

`all_sources_fail` is one 108 MiB file and nothing else, with the canary at byte
0, inside the 100 MiB cap. Result: exit 13, the message "a requested scan source
failed to read and produced no data", and **`--format json-envelope -o PATH`
writes no file at all**. Add one small sibling and it becomes exit 1 with the
sibling's finding and `scan_status` partial, so the discard is triggered by
"every source row errored", not by the cap.

Loud to a shell, silent to every pipeline. Handed to ScanCompleteness, who took
it as their headline case; the regime exists so the row stays red until they land.

### 4. Skips exit 0. A CI gate on `$?` passes over the missed credential.

`binary_reject` (2000 ELF-shaped files, canary in one of them) and `sparse` both
end at exit 0 with `scan_status` partial and a populated `coverage_gap_summary`.
The human summary warns; the exit code says success. This is a documented design
split (skips are advisory, errors are FAIL-class) and I am not calling it a
defect, but the matrix records it because it is the difference between an
operator who reads stderr and a CI job that does not.

### 5. The `--max-file-size` cap refuses the whole file, not the part it allows.

`over_max_size` is one 108 MiB file plus a small sibling, both carrying the
canary. Result 1 of 2: the sibling's copy is found and the over-cap file's copy,
at byte 0, is never read. 84 bytes scanned. The cap is a whole-file refusal
rather than a bounded prefix scan, and the remedy the message offers ("re-scan
with a larger cap") means reading all 108 MiB.

### 6. Encoded payloads are unreachable in the interior of any file over 1 MiB.

`encoded_midfile` is new and is the durable fixture several agents asked for and
nobody had. Decode-through is capped per CHUNK at 512 KiB while the reader
windows at 1 MiB, so a full-size window can never be decode-expanded.

Measured, same payload behind one Base64 layer, default preset, varying size AND
position, which nobody else varied together:

| bytes | payload at head | mid-file | at EOF |
| --- | --- | --- | --- |
| 1,500,103 | miss | miss | miss |
| 2,048,101 | miss | miss | **found** |
| 4,194,421 | miss | miss | miss |

Every arm recovers under `--decode-size-limit 4M`, which is the two-sided
control. Head and interior miss at every size; only the tail is ever reachable
and only when the remainder happens to fall under the cap. So a sweep that varies
file size with the payload at EOF is measuring the one position that can succeed.
The regime therefore plants mid-file, where the outcome does not depend on
arithmetic, plus the same payload in a 64 KiB file that MUST be found, so a zero
on this row cannot be confused with "the encoded canary is undetectable".

Not mine to fix (KH-532, DeepRecoveryRows for recall, CliTestingBacklog for
visibility, who has since landed a counter that turns this from silent to
surfaced).

### 7. Extensionless containers are never opened.

Not a regime row, measured directly because the brief named it. The same
`tar.gz` bytes: named `noext.tar.gz`, exit 1 with the member's credential found;
named `payload`, exit 0 with zero findings and a `binary` coverage gap. The
inference is extension-only at the CONTAINER level; an extensionless MEMBER
inside a recognised archive is found. SourcesBacklog has a fix in the tree.

### 8. Deep nesting fails loud, and slowly.

`deep_nest` at 4096 levels: exit 13, two FAIL rows, canary at the deepest level
unreachable. Correct behavior. The cost is the problem: 49.8 s median at 90
percent CPU, single-threaded, for 4096 directories holding two files, with 4 KiB
path strings in every warning. Walker territory, handed to ParallelWalk.

## Regimes that are fine

`many_small`, `one_long_line` (50 MiB on one line, 2.07 s, no gaps),
`flat_many` (200k entries in one directory, canary found), `symlink_cycle`
(self cycle, mutual cycle, dangling, absolute, escaping, 64-link fan: terminates,
no duplicates, canary found), `no_extension` (plain walker infers content, canary
in a file named `blob` found), `empty_dir` (the control: zero findings is
correct), `unreadable_dir` (exit 13, three FAIL rows, refuses to report clean).

## What I could not fix

- `read/window.rs` and `read/bytes.rs` still map files. Same crash class as the
  one I fixed. Named owner (LargeFileRegime) for the first, unowned for the
  second.
- `suppression/api.rs:449`. Owned by BinaryRecovery; my two triggers are handed
  over with repros.
- The missing envelope on a total source failure. Owned by ScanCompleteness.
- Decode-through reachability. KH-532, owned.
- Deep-nesting walk cost, and the whole-file `--max-file-size` refusal. Handed
  to ParallelWalk and BoundaryMatrix respectively; both fail loud today, so they
  are slow-and-wrong rather than silent.

One thing the harness cannot currently tell you: whether a suppression event a
`--dogfood` probe reports belongs to the copy that went missing. On
`over_max_size` the probe names `entropy_below_floor`, but 84 bytes were scanned,
so the missing copy was never read at all. The note in each row says so rather
than implying the attribution.

## Re-measured after peer fixes landed

ScanCompleteness landed the always-write-the-report change and asked for a
re-run. Binary `/tmp/sc-target/release-fast/keyhog`, sha256
`0d4ea5bc3ad7c8e4cd6f475ab6ce00650199b80a2f3aee2a7abe2c9370bc5079`, median of 3,
load average about 50. That is a build of the whole working tree, so it carries
several agents' changes including my own `raw.rs` fix; it isolates nobody's
change on its own, and the rows below say which effect belongs to which.

| regime | reference `e4f4fcc9` | working tree `0d4ea5bc` |
| --- | --- | --- |
| `all_sources_fail` | NO REPORT: exit 13, `-o` file NOT written | LOUD MISS: exit 13, envelope written and parseable, `scan_status` partial, three gap rows including `scan covered nothing` and `exceeded a configured size cap` |
| `over_max_size` | LOUD MISS, 1/2, envelope written | unchanged: LOUD MISS, 1/2, exit 1, partial |
| `size_changing` | **PANIC**, SIGBUS, no envelope, 0/2 | **OK**: exit 1, envelope written, **2/2 canary copies**, no gaps, across 3 reps |

Two things worth separating.

The `all_sources_fail` change is ScanCompleteness's and it does what they said:
the loud failure now produces a machine-readable document instead of only stderr
prose. The canary at byte 0 of the over-cap file is still not reported, which is
a policy refusal rather than a miss.

The `size_changing` change is the `raw.rs` fix reaching a peer's independent
build. Three reps, no signal, envelope written every time, and both canary copies
found. That is the crash class gone in someone else's binary rather than only in
my test.

Peak RSS across these three regimes also fell from 465-607 MiB to 130-268 MiB.
That is other agents' memory work (LargeFileRegime, MemoryFootprint), not mine,
and it is recorded here only so the numbers are not read as a property of the
fixes above.

`read/window.rs` still maps files, so the 32 MiB arm of the SIGBUS class is
unchanged. ScanCompleteness's retry policy (`keyhog_core::retry`, 3 attempts,
5 ms doubling to 40 ms, `SizeChangedUnderRead` and `VanishedUnderWalk` as named
causes) exists but is not wired into the filesystem read path, so `size_changing`
passes above because the fault was designed out, not because anything retried.

## Reading the RSS and CPU columns

A fixed floor sits under every row and it is not a property of any regime.
WorkloadDominance measured it independently: a directory holding ONE 6-byte file
costs 2.45 CPU-seconds and 473 MiB on the pristine reference, and it scales with
the detector corpus (5 detectors 34 MiB, 100 detectors 79 MiB, 923 detectors
473 MiB). That is detector compilation, paid per invocation.

So in this matrix:

- The 466 to 680 MiB peak RSS on the small regimes is that floor, not the input.
  Only `one_large` (1109 MiB) and `many_small` (643 MiB) carry meaningful
  regime-attributable memory above it.
- The low CPU percent on the small regimes is the same floor: a scan whose total
  work is under three CPU-seconds spends most of it in a compile step that does
  not parallelise the way the scan pool does. Do not read `binary_reject` at 282
  percent as a statement about the rejection path.
- The after-fix run's 130 to 268 MiB is that floor coming down, from other
  agents' work, not from anything measured here.

The regime-to-regime ratios and the canary columns are unaffected, because every
row pays the same floor. It is the absolute numbers that need the caveat.

## One repair note, for whoever reads the diff

`crates/sources/tests/adversarial/whole_file_read_survives_concurrent_truncation.rs`
was caught by an automated `use`-list sweep that another agent ran across
`crates/sources` (disclosed by ArchitectureBacklog: the regex character class
matched newlines, so it collapsed function bodies onto one comma-joined line and
deduplicated repeated tokens). My file lost the newlines inside the read loop but
no tokens. Repaired and re-verified rather than assumed: 2 declared, 2 passed,
both named, `running 0 tests` absent, on the tree at 2026-08-05T06:2x.

Their point is the one worth keeping: a file that still compiles after a sweep is
not evidence it is unharmed. In their case the same pass silently turned
`v4(255, 255, 255, 255)` into `v4(255, 255, 255)` in test assertions, which
compiles fine and asserts something else.

A crude delimiter-balance check I wrote over my own five files reports `()` off by
one in `regression_oom_unbounded_read_caps.rs`. That is a false positive: the
imbalance is a parenthesis inside a message string literal, and the file compiles
and its test passes. Recorded because it is the day's lesson in miniature: the
compiler's exit code is the answer, and a hand-rolled counter over source text is
not.

## Attribution

Several findings in this report were found by other people and measured by me.
Verifying, reproducing and diagnosing a peer's finding all leave it sitting in
your own report looking like yours, and no path or file filter can tell the
difference, so it has to be stated.

Found here, not previously reported by anyone:

- The SIGBUS on concurrent truncation, including the diagnosis, the fix in
  `read/raw.rs`, and the identification of `read/window.rs` and `read/bytes.rs`
  as the remaining sites.
- The two triggers for the `native_binary_strings` silent clean that are not
  binaries by extension or by format: a text file carrying a NUL byte from a
  UTF-16 segment, and a sparse file. The GATE itself
  (`suppression/api.rs:449`, four detectors declaring `credential_shape`) was
  found independently and near-simultaneously by BinaryRecovery from the archive
  side, so the gate is jointly found and the two triggers are mine.
- The total-source-failure discard: exit 13 with no envelope written at all, and
  the observation that adding one readable sibling changes it to exit 1 with the
  sibling's finding, so the trigger is "every source row errored".

Measured and quantified here, found elsewhere:

- Extensionless containers. The brief already carried separate evidence for
  extension-only inference in archives, and SourcesBacklog had a fix in flight. My
  contribution is the measurement that pins it at the CONTAINER level rather than
  the member level: the same `tar.gz` bytes are opened under a recognised name and
  refused under none, while an extensionless member INSIDE a recognised archive is
  found.
- The decode-through cliff. Found by DeepRecoveryRows. BoundaryMatrix named the
  knob, LargeFileRegime derived the closed-form last-window rule and established
  that POSITION governs rather than file size, DetectionBacklog computed the
  unreachable bytes and the corpus blind spot, CliTestingBacklog landed the
  visibility counter, BoundaryAudit landed the ordering guard. Mine is narrower:
  the head position, which nobody had tested and which misses at every size, and
  packaging the whole thing as a regime with an in-corpus positive control so it
  is a standing CI row rather than a one-off sweep.
- The per-invocation detector-compilation floor that dominates every peak-RSS
  number in the matrix. Measured four independent ways by WorkloadDominance,
  MemoryFootprint, ProfilerExpansion and Phase2HotPath. I only apply it as a
  caveat on how to read my own columns.

Two design decisions in the harness came from peers and read as mine because the
code is mine. Stating them, since implementing someone else's idea leaves it in
your own transcript looking like yours:

- The `all_sources_fail` regime exists because ScanCompleteness asked for it by
  name, specified its pass condition (exit 13 AND the output file must exist AND
  parse AND carry a gap naming the size cap), and pointed out that the existing
  verdicts had no bucket for a loud failure with no artifact. The `NO REPORT`
  verdict is their observation; I built the regime and the classifier arm.
- `encoded_midfile` plants mid-file rather than at EOF because LargeFileRegime and
  BoundaryMatrix both told fixture-builders to, before I wrote it: an EOF plant
  tests the one position that can succeed and passes or fails on where the tail
  lands. The in-corpus positive control follows BinaryRelease's rule that a
  fixture should assert its own probe fires in the same run.

## Correction to the commit status stated earlier

I said, repeatedly, "nothing committed". That is wrong for two of my files and I
did not check it until the end.

`crates/sources/src/filesystem/read/raw.rs` and
`crates/sources/src/filesystem/read/mod.rs` are in commit `847aa9d89e`, "land the
symbols the content-format extractor already depends on". I did not make that
commit. A peer landed it to unbreak `HEAD`, which was failing because an earlier
commit took `extract.rs` (carrying the call-site hunk released to me) without the
two files that define the symbol. Verified rather than inferred: `git show
HEAD:.../raw.rs` contains `read_file_whole_capped` and no `MmapOptions`, with
`open_file_safe` as a control confirming the read is of the real file.

So the accurate statement is: the SIGBUS fix's two source files are committed, by
someone else, for a reason unrelated to my work being finished. Everything else of
mine is in the working tree, unstaged: the four harness files and three report
files (untracked), the new adversarial test (untracked), and edits to
`extract.rs`, `tests/adversarial/mod.rs`, `regression_oom_unbounded_read_caps.rs`
and the two `filesystem_read` test files (all shared, so no volume claimed).

How I nearly missed it, since it is the same shape as everything else in this
tree today: my first footprint check filtered `git status --porcelain` by
directory and skipped any entry ending in `/`. Git collapses untracked
directories into a single entry, so `benchmarks/workload_matrix/` was reported
once and dropped, and four files I had certainly written read as absent. The
same run showed `raw.rs` as not-dirty, which I was briefly ready to read as
"my checker is broken" rather than "the file is committed". Both readings were
available and only one was true. `-uall` plus `git log` on the specific path
settled it, and neither is a search.

## The empty-coverage-gap claims are controlled

Every silent-clean claim above is of the form "`coverage_gap_summary` was empty",
and an empty field cannot be told apart from a field that never populates. The
control is inside the same run rather than bolted on: five regimes in this matrix
produce a POPULATED `coverage_gap_summary` from the same binary, the same
`--format json-envelope`, and the same invocation shape (`over_max_size`,
`deep_nest`, `binary_reject`, `sparse`, `unreadable_dir`, with one to three gap
rows each). So the field demonstrably populates, and the empty ones are a fact
about those scans rather than a property of the format.

The same applies to the canary column: rows reporting `1/1`, `7/8` and `2/2` sit
beside rows reporting `0/1` and `0/2`, so the detector demonstrably fires, and the
run-wide preflight proves it before any regime is measured.
