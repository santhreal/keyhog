# Competitive workload comparison

KeyHog measured against gitleaks, trufflehog and noseyparker on twelve
workloads, same inputs, same machine, same hour.

Read the headline first, because it is not comfortable. **KeyHog is slower than
the best available peer on every one of the twelve workloads.** The margin runs
from 1.5x to 27.7x. Most of that gap has a single cause, and it is not the
scanning engine.

## How to read these numbers

The primary metric is CPU seconds, user plus system. The machine was running
about 28 other agents throughout, with load average between 35 and 411, so wall
time is unreliable and CPU seconds is not. The same keyhog run measured 17.3
CPU-s at load 117 and 18.3 CPU-s at load 411, a 6% spread across a 3.5x load
swing, so treat CPU seconds as the signal and wall time as context.

Every row is the median of 5 runs after one discarded warmup. Runs are
interleaved, so all four scanners see comparable load inside a round rather than
one scanner getting a quiet minute and the next getting a storm. Load average is
sampled immediately before every individual run and the range is reported.

Binary under test: `/tmp/kh-ref-bin/keyhog`, sha256
`e4f4fcc96c748e1485112438840f70f97eca151ed62b979085b9a59d610433fb`, KeyHog
v0.5.68, commit 044cfdc4259766900033a42d12b8266183a1d60f, ci-lean release-fast,
detector set 923. Peers: gitleaks 8.30.0, trufflehog 3.95.5, noseyparker 0.24.0.

Every corpus carries the same planted AWS key pair. The canary column is the
control: a scanner that reports zero on a corpus containing the canary has
either missed it or never ran. 50 of the 53 measured cells found the canary, and
all three that did not are explained below.

## The table

CPU seconds, median of 5. Lower is better. "Best peer" is the fastest peer that
actually found the planted credential.

| Workload | keyhog | gitleaks | trufflehog | noseyparker | Best peer | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| Many small files (2,000 x 64 KiB, 128 MiB) | **20.71** | 34.6 | 10.65 | 1.27 | noseyparker | LOSS 16.3x to noseyparker |
| One very large file (96 MiB, one file) | **16.15** | 14.64 | 6.94 | 1.02 | noseyparker | LOSS 15.8x to noseyparker |
| One very long single line (32 MiB, 1 line) | **3.84** | 3.95 | 2.99 | 0.66 | noseyparker | LOSS 5.8x to noseyparker |
| Deep directory tree (depth 500, 11 files) | **3.49** | 0.52 | 2.29 | 0.63 | gitleaks | LOSS 6.7x to gitleaks |
| Very wide flat directory (100,000 files, one dir) | **16.92** | 22.95 | 22.72 | 2.55 | noseyparker | LOSS 6.6x to noseyparker |
| Binary-heavy, name-rejectable (6,021 files, 192 MiB) | **2.92** | 0.94 | 24.39 | 1.37 | gitleaks | LOSS 3.1x to gitleaks |
| Binary-heavy, name tells nothing (6,021 files, 192 MiB) | **4.49** | 1.38 | 38.53 | 1.43 | gitleaks | LOSS 3.3x to gitleaks |
| Vendor-heavy (80,000 node_modules + 201 src) | **3.93** | 0.76 | 18.08 | 2.21 | gitleaks | LOSS 5.2x to gitleaks |
| Archives and nested archives (tar.gz, zip, tgz-in-tgz) | **4.11** | 0.33 | 2.74 | 0.49 | trufflehog | LOSS 1.5x to trufflehog |
| Container layers (25-layer image, 96 MiB unpacked) | **43.28** | 163.56 | 13.74 | 1.56 | noseyparker | LOSS 27.7x to noseyparker |
| Git history (400 commits, secret added then removed) | **7.8** | 12.09 | 5.48 | 0.72 | noseyparker | LOSS 10.8x to noseyparker |
| Repeat scan, caching should dominate (128 MiB) | **20.59** | 35.34 | 9.43 | 0.97 | noseyparker | LOSS 21.2x to noseyparker |

## Where the time goes

Scan a directory holding one 6-byte file and keyhog spends 2.45 CPU seconds and
473 MiB before it looks at your data. gitleaks spends 0.40 and trufflehog 1.85 on
the same input.

That floor is detector compilation, and it scales with the corpus:

| Detectors compiled | CPU-s | peak RSS |
| --- | --- | --- |
| 5 | 0.03 | 34 MiB |
| 100 | 0.27 | 79 MiB |
| 923 (embedded default) | 2.25 | 473 MiB |

Read that table as a corpus sweep, not as a per-detector price. The cost tracks
pattern SHAPE, not detector count. DetectionBacklog attributed a corpus change
that added 2 detectors and 12 patterns: the two new detectors, which use plain
anchored patterns, cost 0 MiB, and the entire +20 MiB came from 12 bounded-window
patterns of the form `(?is)...{0,256}...`, at roughly 1.7 MiB of DFA each. A
hundred anchored detectors would be cheaper than a dozen windowed ones.

Subtract the floor and the picture changes completely:

| Workload | keyhog CPU-s | minus the 2.45 s floor | share that is startup |
| --- | --- | --- | --- |
| Many small files (2,000 x 64 KiB, 128 MiB) | 20.71 | 18.26 | 12% |
| One very large file (96 MiB, one file) | 16.15 | 13.70 | 15% |
| One very long single line (32 MiB, 1 line) | 3.84 | 1.39 | 64% |
| Deep directory tree (depth 500, 11 files) | 3.49 | 1.04 | 70% |
| Very wide flat directory (100,000 files, one dir) | 16.92 | 14.47 | 14% |
| Binary-heavy, name-rejectable (6,021 files, 192 MiB) | 2.92 | 0.47 | 84% |
| Binary-heavy, name tells nothing (6,021 files, 192 MiB) | 4.49 | 2.04 | 55% |
| Vendor-heavy (80,000 node_modules + 201 src) | 3.93 | 1.48 | 62% |
| Archives and nested archives (tar.gz, zip, tgz-in-tgz) | 4.11 | 1.66 | 60% |
| Container layers (25-layer image, 96 MiB unpacked) | 43.28 | 40.83 | 6% |
| Git history (400 commits, secret added then removed) | 7.8 | 5.35 | 31% |
| Repeat scan, caching should dominate (128 MiB) | 20.59 | 18.14 | 12% |

Two things follow. On the four workloads dominated by startup, keyhog is losing
before it reads a byte. And on `binary_reject` the floor-adjusted ratio is 0.5x,
which means keyhog's marginal cost of rejecting 6,021 files by extension is
**half** what gitleaks spends. The rejection path is not the problem people
assumed it was. The floor in front of it is.

### Four measurements of the same floor

This number was arrived at independently four ways on the same commit, which is
why it is worth acting on.

| Source | Method | Result |
| --- | --- | --- |
| this report | `/usr/bin/time` on a 6-byte file | 2.45 CPU-s, 473 MiB |
| MemoryFootprint | `/usr/bin/time`, corpus swept by `--detectors-mode replace` | 483 MB at 923 detectors |
| ProfilerExpansion | `--profile`, reported from inside the process | `engine_init_resident_bytes` 481-485 MiB |
| Phase2HotPath | retired instructions at `--threads 1` | 18.95 Ginstr on a 12-byte file, 47% of a full mirror scan |

Two of those measurements change what you should do about it.

**The memory half is already fixed.** MemoryFootprint stopped retaining compiled
patterns after validation. At 923 detectors the floor goes 482.7 MB to 68.0 MB,
a per-detector slope of 0.489 down to 0.041 MB. The CPU half does not move,
deliberately: every pattern is still eagerly compiled so a malformed or oversized
regex fails loudly before a scan starts. Re-measure the RSS column in this report
against a working-tree build before quoting it.

**A compiled-scanner cache recovers about 58% of the CPU floor, not all of it.**
Phase2HotPath decomposed the 32.73 Ginstr fixed cost: roughly 19 Ginstr is eager
construction and serialisable, and roughly 13.8 Ginstr is `LazyRegex`, compiled
per pattern on first use. The lazy half is absent from the 6-byte-file probe by
design, and it is not in the constructed scanner to be serialised. Capturing it
too would mean holding every compiled detector regex resident, which is exactly
the memory MemoryFootprint just stopped spending. So this is a memory against
latency trade, not a free win, and whoever scopes it should size both halves.

One consequence for the wall-time column below: the regex crate's lazy DFA cache
is per regex per thread, so on 32 workers a hot pattern's DFA is built up to 32
times. Serialised construction does not parallelise, so the floor's share of wall
time grows with core count while its share of CPU seconds stays flat.

## Wall time, memory and load

| Workload | keyhog wall s | fastest peer wall s | keyhog peak RSS MiB | load average during the row |
| --- | --- | --- | --- | --- |
| Many small files (2,000 x 64 KiB, 128 MiB) | 7.32 | 1.65 (noseyparker) | 616.5 | 130.5-171.1 |
| One very large file (96 MiB, one file) | 3.12 | 1.03 (noseyparker) | 711.7 | 46.4-76.0 |
| One very long single line (32 MiB, 1 line) | 0.92 | 0.66 (noseyparker) | 535 | 37.2-45.2 |
| Deep directory tree (depth 500, 11 files) | 2.24 | 0.52 (gitleaks) | 531.5 | 97.4-117.1 |
| Very wide flat directory (100,000 files, one dir) | 8.05 | 1.64 (noseyparker) | 564.5 | 120.6-179.2 |
| Binary-heavy, name-rejectable (6,021 files, 192 MiB) | 2.37 | 0.89 (gitleaks) | 531.6 | 137.9-148.1 |
| Binary-heavy, name tells nothing (6,021 files, 192 MiB) | 3.01 | 1.28 (noseyparker) | 558.9 | 131.3-146.2 |
| Vendor-heavy (80,000 node_modules + 201 src) | 3.91 | 1.12 (gitleaks) | 540 | 131.5-142.2 |
| Archives and nested archives (tar.gz, zip, tgz-in-tgz) | 1.1 | 0.3 (gitleaks) | 562.6 | 52.4-57.7 |
| Container layers (25-layer image, 96 MiB unpacked) | 6 | 1.38 (noseyparker) | 698 | 45.1-85.5 |
| Git history (400 commits, secret added then removed) | 2.95 | 1.02 (noseyparker) | 566.5 | 69.9-92.7 |
| Repeat scan, caching should dominate (128 MiB) | 1.95 | 0.49 (noseyparker) | 613.8 | 50.2-60.2 |

KeyHog parallelises hard, so its wall time is far better than its CPU time. On
one 96 MiB file it burns 16.15 CPU-s but finishes in 3.12 s wall by spreading
across cores. That is a real advantage on an idle machine and a real liability
on a busy CI runner sharing cores with other jobs.

## Where the comparison is not apples to apples

Say this plainly rather than claiming a clean sweep.

**KeyHog detects more.** It runs 923 detectors and reports the AWS access key and
the secret key as two findings. noseyparker reports one. Any row where keyhog
shows `f=2` and a peer shows `f=1` is comparing different amounts of work.

**gitleaks and noseyparker do not open archives at all.** On the archive regime
they report zero findings in 0.33 and 0.49 CPU-s. That is not a win over keyhog,
it is a scanner declining to do the work. The only honest comparator there is
trufflehog, and keyhog loses to it 1.5x while finding the same credential inside
a `.tar.gz` nested in a `.tar.gz`.

**gitleaks is unusable on container images.** On the 25-layer image it emits
**1,462,479 findings** in 163.56 CPU-s by pattern-matching raw compressed tar
bytes. It technically contains the canary. It is not a result an operator can
use. The correctness-matched comparator is trufflehog at 13.74 CPU-s, so the real
container verdict is a 3.1x loss, not the 27.7x the table shows against
noseyparker.

**noseyparker silently misses a large file.** On a 128 MiB file holding a
plaintext AWS key it exits 0 with zero findings and no warning. keyhog refuses
the same file: exit 13, no envelope, and an explicit statement that it will not
report clean. keyhog is correct and noseyparker is dangerous. But note that
trufflehog scans that file in 4.01 s and finds the key, so keyhog is also the
only one of the four that will not scan a 128 MiB file at all by default.

## The three cells that did not find the canary

`archives / gitleaks` and `archives / noseyparker` are genuine capability gaps.
Neither tool descends into archives.

`one_long_line / keyhog` was **my measurement error, not a keyhog defect**, and
it is worth recording how it was caught. The corpus file was named
`bundle.min.js`. That name hits the post-match minified suppression, which at
pristine HEAD `--no-default-excludes` does not defeat. keyhog reported 0 while
all three peers reported 1, which looked exactly like a silent clean. A positive
control, the same secret on a single short line in a file with the same name,
also returned 0, which proved the probe was blind rather than keyhog broken.
Renamed to `bundle.js`, keyhog finds the credential and the row is reported as
`one_long_line_fixed`. Without the control this report would have filed a
fabricated silent clean.

## Repeat scans

This is the regime where caching should decide it, and the floor caps the win.

| Arm | CPU-s |
| --- | --- |
| keyhog, plain repeat | 20.59 |
| keyhog, `--incremental` warm | 2.45 |
| gitleaks, full rescan | 35.34 |
| trufflehog, full rescan | 9.43 |
| noseyparker, full rescan | 0.97 |

`--incremental` works well and cuts an unchanged repeat 8.4x, from 20.59 to
2.45. It also beats gitleaks 14x, which is the closest thing to a win in this
whole report.

Then notice what 2.45 is. It is the detector-compilation floor exactly. A
re-scan where nothing changed and every file hits the merkle cache costs the
same as compiling the detectors and doing nothing at all. **No improvement to
the incremental cache can take a one-shot repeat scan below 2.45 CPU seconds**,
because the scanner is rebuilt from scratch on every invocation. noseyparker
does a complete cold scan of the same 128 MiB in 0.97.

That bound is per invocation, and one route already goes under it. Measured by
DaemonBehavior on the repo's `docs/` tree, medians of 5 at load 32-36: an
in-process repeat costs 2.86 CPU-s and 688 MB, while a `--daemon=mass` repeat
costs the client 0.26 CPU-s and 40 MB for identical findings. That is 8x below
the floor, because the daemon does not rebuild the scanner per request.

Four things stop that being a general answer. The daemon still pays the floor
once at start, so a single scan is a net loss and it only pays from the second
invocation. `--daemon=mass` refuses per-scan policy overrides, so `--threads N`
over that route is exit 2. The daemon runs one scan at a time under a
process-wide lock, measured at 0.95x for 8 concurrent scans, so it removes the
per-invocation floor and not the serialisation ceiling. And it holds 542 MB
resident for its whole life with no idle shutdown, which relocates the floor
rather than deleting it.

Two more before you deploy this on the binary measured here. On pristine HEAD the
daemon dies from SIGPIPE when a client abandons a connection mid-reply, because
it inherits `SIGPIPE=SIG_DFL` from the filter behaviour that makes
`keyhog scan | head` exit cleanly. Three hello-and-close connections kill it, and
since execution is serialised every other client's warm scanner dies with it. So
pre-fix, the shared process you are adopting to amortise the floor is one that
any client ends with a Ctrl-C or a timeout. Treat the daemon SIGPIPE fix as a
prerequisite. Separately, the daemon compiles from raw detectors and shipped
defaults and ignores its own `.keyhog.toml`, and the handshake cannot detect the
difference because both ends hash the default config digest, so a warm daemon may
not be running your configuration.

So the daemon covers repeat and CI-runner workloads. What is still missing is a
persisted compiled corpus, so that a cold one-shot invocation gets it too. That
is the case the daemon cannot help and the one noseyparker wins at 0.97.

The Hyperscan compiled-database cache does not help. `--cache-dir` writes its
`.db` artifact and the floor does not move: 2.57 CPU-s without it, 2.58 with it.
It caches the Hyperscan database build, not the detector-spec regex compilation
that costs the 2.25.

## Backends make no difference

`--backend simd`, `--backend simd-regex` and `--backend cpu` cost the same on
this hardware, and produce byte-identical output.

| Backend | 128 MiB many-small CPU-s | 96 MiB one-file CPU-s |
| --- | --- | --- |
| cpu | 21.32 | 16.11 |
| simd | 22.13 | 17.10 |
| simd-regex | n/a | 16.40 |

Findings are identical across all three, sha256 `4b1efe07a12ad879` on the same
corpus, so the autoroute recovery path costs correctness nothing. It also buys
throughput nothing here. Hyperscan 5.4.2 is linked into this binary and a build
without it errors loudly on `--backend simd`, so the backend is engaged rather
than silently falling back.

Note that a stock `cargo install keyhog` gets `default = ["portable"]`, which
does not include `simd` at all.

## What to fix, in order

1. **Cache the compiled scanner.** The 2.45 CPU seconds per invocation is the
   single largest competitive gap and the whole story on five of the twelve
   workloads. It is also a hard floor under `--incremental`, so the caching work
   cannot pay off without it. Scope both halves before starting: about 58% of the
   fixed cost is eager construction and serialisable, and the remaining `LazyRegex`
   half is compiled per pattern on first use, so capturing it means holding every
   compiled detector regex resident. Wire `CacheId::MatcherArtifact` on day one so
   the hit rate shows up in `--profile-out` and the payoff is a two-run diff.
   The memory half of the floor is already addressed and is not part of this.
2. **Container layer unpacking.** 43.28 CPU-s against trufflehog's 13.74 on the
   same image, with both finding the same two credentials.
3. **Content sniffing for unclassifiable names.** Rejecting 6,000 files whose
   extension is on the skip list costs 0.47 CPU-s. Rejecting 6,000 files whose
   name says nothing costs 2.04. Both reject the same bytes.
4. **Directory pruning.** The walker deliberately disables codewalk's
   `exclude_dirs` so every skipped file reaches `process_entry` and gets counted.
   80,000 `node_modules` files cost 1.48 CPU-s to enumerate and discard. Note the
   constraint before changing it: the `Excluded` count is an observable WARN
   coverage gap, so pruning changes reported output.

## Reproducing

    python3 /tmp/kh-compete-work/matrix.py            # the twelve regimes
    python3 /tmp/kh-compete-work/supplement.py        # corrected long-line, repeat scan

Corpora are generated under `/tmp/kh-compete-corpora`. Raw per-row JSON with
every median, min, max and load sample is in
`/tmp/kh-compete-work/results.jsonl` and `results-supplement.jsonl`.
