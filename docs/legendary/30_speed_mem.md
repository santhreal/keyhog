# 30 — Speed + memory, every layer

The fastest correct secret scanner in existence. Every change measured before
and after; the bottleneck named at each layer (prior: the CPU pipeline is the
throughput ceiling, not the GPU). Seed finding: 1.5 GB peak RSS scanning keyhog's
own tree — too high. Hardest-first: the end-to-end CredData/large-repo wall-clock
crown is a RESEARCH lane and leads.

Numbers: KH-L-0250 … KH-L-0379.

## Flagship: win the wall-clock crown (RESEARCH)

- KH-L-0250 [AV1,SCALE][SCANNER][RESEARCH] Beat every peer on end-to-end wall-clock on a large real tree (linux kernel, chromium subset) AND CredData — measured, repeatable, in the bench gate. Proof: a peer wall-clock leaderboard, keyhog #1.
- KH-L-0251 [AV1,L7][SCANNER][RESEARCH] Profile the full CPU pipeline (`KEYHOG_PROFILE=1`) on a large tree; attribute every % and attack the top-3 line items. Proof: a phase-attribution before/after table per push.
- KH-L-0252 [L7,AV1][SCANNER][L] phase-2 confirmed-extraction cost: the regex confirm pass is the dominant non-prefilter cost — vectorize / batch / cache it. Proof: a measured confirm-pass speedup, recall flat.
- KH-L-0253 [AV1][SCANNER][L] `fb:prefilter` was ~55% of scan (homoglyph variants) — now skipped on ASCII; attack the remaining prefilter cost on non-ASCII + decoded sub-chunks. Proof: non-ASCII prefilter bench win.

## Memory

- KH-L-0254 [L7,AV15][SCANNER][L] 1.5 GB peak RSS on keyhog's own tree — root-cause (chunk buffering, decode fan-out clones, interner growth) and bound it. Proof: a memory-ceiling bench; RSS down with recall flat.
- KH-L-0255 [L7][DECODE][M] Decode pipeline clones every decoded chunk (`decoded.clone()` into queue + results) — reduce copies (Arc/borrow) under the cap. Proof: allocation-count bench on a decode-dense file.
- KH-L-0256 [L7,AV15][SCANNER][M] Bound per-file memory on huge files via the windowing path (`scan_chunk_or_window`, >1 MiB); prove a multi-GB file scans in bounded RSS. Proof: a large-file streaming test with an RSS ceiling.
- KH-L-0257 [VR1,AV15][SOURCES][M] Decompression-bomb + giant-file inputs (zip/gzip/tar) scan under a memory + time cap, loud on hitting it. Proof: a bomb corpus, bounded RSS, recorded cap-hit.
- KH-L-0258 [L7][CORE][M] The `StaticInterner` is bounded / doesn't grow unboundedly on adversarial high-cardinality input. Proof: an interner-growth test under adversarial keys.

## Concurrency + scale

- KH-L-0259 [L7,AV15][SCANNER][L] The rayon parallel scan is contention-free (no lock on the hot path); profile lock waits at high core count (32 logical here). Proof: a scaling curve to 32 threads, near-linear.
- KH-L-0260 [VR9,AV15][SCANNER][M] Concurrent determinism: the finding set is identical regardless of thread interleaving (the `RawMatch::Ord` total order guarantees it — gate it under thread-shuffle). Proof: a thread-shuffle determinism test.
- KH-L-0261 [AV1,SCALE][SOURCES][L] Scale: scan a 1M-file tree without unbounded memory or O(n²) directory walking. Proof: a synthetic 1M-file scale test, bounded resources.
- KH-L-0262 [L7][SOURCES][M] Git-history scan is incremental + bounded (doesn't re-read every blob); benchmark on a large-history repo. Proof: a git-history scale bench.
- KH-L-0263 [AV1][DAEMON][M] Daemon re-scan is the claimed 105× faster (README) — verify + gate the speedup; merkle-index incremental correctness. Proof: a daemon-rescan bench asserting the ratio.

## Micro + SIMD

- KH-L-0264 [L7,AV1][ENTROPY][M] Entropy is AVX-512 / AVX2 / scalar with runtime dispatch; each path is correct (differential) and the SIMD path is measured-faster. Proof: entropy SIMD differential + bench.
- KH-L-0265 [L7][SCANNER][M] `simd.rs` (728 L) prefilter union (AC + Hyperscan) is necessary (the recall-load-bearing union) AND fast; bench the union cost. Proof: a SIMD-trigger bench + the union recall gate.
- KH-L-0266 [AV1,L7][CORE][M] SHA-256 credential hashing (per match) uses a fast impl; not a per-match bottleneck on match-dense files. Proof: a hashing micro-bench in the hot-path profile.
- KH-L-0267 [L7][SCANNER][M] The `bigram_bloom` / `prefix_trie` / `alphabet_filter` fast-reject gates are measured net-positive (reject cost < confirm cost saved). Proof: a per-gate cost/benefit bench.

## Perf gates + no-regression

- KH-L-0268 [AV1,SCALE][BENCH][M] Criterion baselines for every hot path; the perf gate fails a PR on >X% regression. Proof: a wired criterion-baseline CI gate.
- KH-L-0269 [L7,AV6][SCANNER][S] No fixed sleeps / busy-waits anywhere on the scan or TUI path (the TUI idle fix is the model). Proof: a `no_fixed_sleep` grep gate with documented exceptions.
- KH-L-0270 [AV1][CLI][M] Cold-start latency budget enforced (portable < 150 ms incl. detector load); gated. Proof: a startup-latency e2e gate.
- KH-L-0271 [L7,AV15][SCANNER][M] No avoidable O(n²): audit every nested loop on text (multiline preprocessor, context inference, dedup) for quadratic blowup on adversarial input. Proof: a worst-case-input bench per suspect.

(Breadth: each `engine/` hot file gets a criterion bench + a profile-attribution
item; enumerated as benches land. Seeded with the load-bearing lanes above.)
