# 20 — Detection truth: recall + precision on REAL corpora

The flagship correctness lane. keyhog sits ~5th/6 on real CredData (F1 ~0.15,
recall-bound) despite ~0.92 on the synthetic mirror — the single most important
gap to close, and genuinely multi-month. Per hardest-first, the CredData lane
leads. Every item proves a real value (file·line·rule·credential), never `!is_empty`.

Numbers: KH-L-0100 … KH-L-0249.

## Flagship: close the real-world (CredData) recall gap (RESEARCH)

- KH-L-0100 [SCALE,AV2,VR1][ML][RESEARCH] Build the standing CredData harness: every change benches CredData (not just mirror) with per-category recall/precision/F1 and a peer leaderboard. Proof: `bench gate` emits CredData F1 + rank each run.
- KH-L-0101 [AV2,AV5][DETECTORS][RESEARCH] Per-category failure analysis on CredData: which credential classes keyhog misses vs the leaders (gitleaks/trufflehog/detect-secrets/...). Proof: a categorized miss-ledger with counts.
- KH-L-0102 [SCR,AV3][ML][RESEARCH] The keyword-bridge reaches only ~10% of positives — design the bigger surfacing mechanism (context windows, assignment-shape, proximity) that lifts recall without flooding FPs. Proof: +recall with bounded FP delta on held-out CredData.
- KH-L-0103 [AV2,ML][ML][RESEARCH] Retrain the MoE on the real distribution (harvest→blend→retrain, file-grouped split) until real held-out recall ≥ target; never overfit the mirror. Proof: held-out recall curve in the ledger.
- KH-L-0104 [L10,ML][ML][L] The entropy→MoE routing is env-gated OFF (`KEYHOG_ENTROPY_ML_AUTHORITATIVE`) pending a better model — get the model good enough to turn it ON by default without recall regression. Proof: default-on with mirror+CredData both ≥ baseline.
- KH-L-0105 [AV2][ENTROPY][L] Low-entropy real secrets (the `generic_keyword_low_entropy` floor) — widen coverage without re-admitting placeholder noise. Proof: CredData low-entropy recall up, mirror precision flat.
- KH-L-0106 [DEDUP,AV7][ML][M] One model-versioning scheme; the ML model digest in `doctor` matches the embedded weights + training manifest. Proof: `ml_model_provenance` gate.
- KH-L-0107 [VR8,SCR][ML][M] No overclaim: confidence scores calibrated against real outcome frequencies (calibration curve), not hand-tuned. Proof: a reliability-diagram test within tolerance.
- KH-L-0108 [AV2][DETECTORS][L] Mine the 50 highest-value detectors missing from the 901 set (modern SaaS/cloud tokens) from peer rule-sets + provider docs. Proof: +N detectors each with positive/negative/checksum tests.
- KH-L-0109 [L9,AV4][DETECTORS][L] Every detector that emits `generic-*` on CredData is examined for a precise typed detector that would raise precision. Proof: typed-detector conversions with before/after FP counts.

## Self-scan + suppression truth

- KH-L-0110 [L10,AV13][SUPPRESS][M] `keyhog scan .` returns `[]` on its own tree — prove this is correct test-fixture suppression, not masking. Audit every suppression that fired. Proof: `scan . --no-suppress-test-fixtures` shows the fixtures + a documented diff.
- KH-L-0111 [L10][SUPPRESS][L] Every suppression rule is loud + auditable: a `--explain-suppressions` mode lists what was suppressed and why (never a silent drop). Proof: e2e test of the explain output.
- KH-L-0112 [SCR,L6][SUPPRESS][M] Test-fixture suppression must not suppress a REAL secret that happens to sit in a tests/ dir — prove the heuristic's precision. Proof: a planted-real-secret-in-tests fixture still fires.
- KH-L-0113 [AV15][SUPPRESS][M] Suppression-bypass audit: can an attacker-controlled `.keyhogignore`/path shape silence detection (e.g. via traversal or glob)? Proof: a suppression-evasion test corpus, all fail-closed.
- KH-L-0114 [DEDUP][CORE][M] One dedup pipeline: `dedup_matches`→`dedup_cross_detector` is the only path; TUI + scan + daemon all use it (already aligned — gate it). Proof: a cross-surface dedup-parity test.
- KH-L-0115 [L6][CORE][M] Dedup identity (detector,credential,offset) is correct under every scope (None/Credential/File) — proptest the invariants. Proof: `dedup_invariants_proptest` extended to 10k.

## Decoder recall (the decode-through pipeline)

- KH-L-0116 [AV3,L10][DECODE][L] Every one of the 14 decoders has a recall test: a secret wrapped in that encoding is recovered. Proof: per-decoder positive fixture firing through `scan`.
- KH-L-0117 [L10,AV15][DECODE][L] The decode fan-out caps (`MAX_DECODED_CHUNKS_PER_ROOT`, total-bytes, wall-budget) drop chunks LOUDLY — a capped scan records what it skipped. Proof: a cap-hit emits a recorded, operator-visible note.
- KH-L-0118 [AV2,SCR][DECODE][L] Nested/compound encodings (base64-of-gzip-of-base64, URL-of-JSON) recovered to the configured depth; differential vs a brute oracle. Proof: a compound-encoding corpus runner.
- KH-L-0119 [L6][DECODE][M] Caesar/rotate/reverse decoders gated on real preconditions (alphabetic-run) so they add recall without 25× FP fan-out. Proof: before/after FP + recall on the decode corpus.
- KH-L-0120 [VR1,AV15][DECODE][RESEARCH] Fuzz the decode recursion (structure-aware) for decompression bombs / OOM / infinite-fan-out to a PoC or a disk-documented kill. Proof: a fuzz harness + corpus, no OOM under cap.
- KH-L-0121 [L10][DECODE][M] Decoder errors never silently swallow a chunk (the `.ok()`/`Err(_)=>` audit) — each is loud or fails closed. Proof: `no_silent_decode_drop` gate.

## Multiline / structural / context

- KH-L-0122 [AV3][MULTILINE][L] Multi-line secrets (PEM keys, JSON blobs, concatenated assignments) recovered; the fragment cache is deterministic (see `regression_fragment_cache_determinism`). Proof: PEM + multiline JSON fixtures fire.
- KH-L-0123 [L7,AV1][MULTILINE][M] The multiline preprocessor (606 L) is O(text), not O(text²) on concatenation-dense files. Proof: a criterion bench on a worst-case concat file.
- KH-L-0124 [AV3][CONTEXT][L] Context inference (645 L) — assignment/proximity/key-name signals raise precision; each signal has a positive+negative test. Proof: per-signal contract tests.
- KH-L-0125 [SCR,L6][CONTEXT][M] Documentation/comment context lowers confidence correctly without dropping real secrets in comments. Proof: secret-in-comment still fires above floor.
- KH-L-0126 [AV3][STRUCTURED][L] Structured parsers (json/yaml/toml/env/xml) attribute secrets to the right key path; each parser has a recall+attribution test. Proof: per-format key-path assertions.

## Checksums / typed validation

- KH-L-0127 [L6,AV12][CHECKSUM][M] Every checksummed detector (github/gitlab/stripe/slack/npm/aws/...) validates the checksum; a fabricated-but-shaped token is rejected. Proof: per-checksum positive(valid)+negative(invalid) pair.
- KH-L-0128 [L10][CHECKSUM][M] The hot-pattern fast path replicates checksum + suppression policy (the known bypass class) — gate that fast-path == slow-path per match. Proof: `hot_path_policy_parity` test.
- KH-L-0129 [AV6,CFG][CHECKSUM][M] Checksum algorithms are Tier-B data where possible (CRC/luhn/base62 params), not hardcoded per detector. Proof: a checksum-spec data file + loader.

## Differential + corpus truth

- KH-L-0130 [AV2,TC][BENCH][L] Differential harness against ≥4 peers (gitleaks, trufflehog, detect-secrets, ggshield) on the SAME corpora; report per-tool TP/FP/FN. Proof: a `differential-bench` matrix in CI.
- KH-L-0131 [AV2][BENCH][M] The mirror corpus is union/deduped/canonical (one bench system — already `benchmarks/bench`); gate that retired systems stay retired. Proof: `bench_single_system` gate.
- KH-L-0132 [TC,AV12][DETECTORS][L] CVE-replay corpus: known leaked-credential CVEs reproduced as detection fixtures. Proof: `cve_corpus_runner` extended with N real CVEs.
- KH-L-0133 [AV2,SCALE][BENCH][RESEARCH] Stand up additional real corpora beyond CredData (e.g. public leak datasets, sampled GitHub) for recall breadth. Proof: ≥2 new real corpora wired into the gate.
- KH-L-0134 [VR9][BENCH][M] Harness-artifact guard: a finding caused by the bench's own fixtures is flagged, not counted. Proof: a self-check that bench fixtures don't leak into corpus positives.

## Precision (false-positive war)

- KH-L-0135 [AV2,SCR][SUPPRESS][L] Reduce FPs on the base64/protobuf shape class (precision ~0.80 is a deliberate recall tradeoff) — close it with context/ML, not blunt shape gates that drop real CredData secrets. Proof: precision up with recall flat on both corpora.
- KH-L-0136 [AV13][SUPPRESS][M] Dogfood FP audit: scan ~/.config, /etc samples, large OSS repos; every FP becomes a negative fixture. Proof: `FP_AUDIT_REPORT` regenerated + each Category → tests.
- KH-L-0137 [L9][CONFIDENCE][M] The confidence floor + penalties (degenerate-repeat, placeholder) are data-driven + tested at boundaries. Proof: boundary tests at each threshold.
- KH-L-0138 [AV3][SUPPRESS][M] Allowlist/`.keyhogignore.toml` governance: hash/path/rule suppression each has positive+negative+adversarial tests. Proof: rule-engine contract suite.

(Detection backlog continues — every detector × {positive, negative, adversarial,
checksum, cross-file, CVE-replay} is an item; enumerated per-detector in
`95_testing_coherence.md`. Target ≥120 items in this file as per-detector and
per-category analysis lands; seeded above with the load-bearing lanes.)
