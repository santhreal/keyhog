# 95 — Testing Contract + coherence, per surface (the generative breadth)

The Testing Contract in CLAUDE.md is per-rule and per-surface. keyhog has 901
detectors, 14 decoders, ~20 sources, 17 subcommands, 4 output formats, 4 backends.
The bulk of the 1000+ items is this matrix — enumerated generatively (a materializer
expands it into the concrete backlog `99_BACKLOG.tsv`) so every single thing is
covered, not just a sample. Each generated item is a real, named, value-asserting
test, never `!is_empty`.

Numbers: KH-L-1060 … KH-L-1199 (the generators); the materialized rows are
KH-G-* in `99_BACKLOG.tsv`.

## The generators (each expands to N concrete items)

- KH-L-1060 [TC,AV12][DETECTORS][RESEARCH] **Per-detector contract** (×901): every detector gets {positive-truth, negative-twin, adversarial/evasion, checksum(valid+invalid where applicable), cross-file, CVE-replay where relevant}. Generator: `detectors/*.toml` × test-types → ~5–6k rows; prioritized by detector value. Proof: `all_detectors_self_validate` extended to assert each test-type exists per detector.
- KH-L-1061 [TC,AV12][DECODE][L] **Per-decoder contract** (×14): {recall(secret-through-encoding), negative, nested/compound, bomb-safe, differential-vs-oracle}. Proof: a decoder-contract runner.
- KH-L-1062 [TC,AV12][SOURCES][L] **Per-source contract** (×20): {positive, negative, error/exit-code, scale, adversarial, SSRF-where-remote}. Proof: a source-contract runner.
- KH-L-1063 [TC,AV12][CLI][L] **Per-subcommand contract** (×17): {defaults, representative flag combos, every output format, every error path + exit code, --help-matches-behavior}. Proof: a subcommand-contract runner.
- KH-L-1064 [TC,AV12][CLI][M] **Per-output-format contract** (×4: text/json/jsonl/sarif): schema-valid, field-coherent across formats, redaction-correct, GitHub-SARIF-compliant. Proof: a format-schema suite.
- KH-L-1065 [TC,AV12][GPU][L] **Per-backend parity** (×4: cpu/simd/gpu/megakernel): identical RawMatch sets on {empty, edge, chunk-boundary, large, decode-dense} corpora. Proof: the backend-parity matrix on a GPU runner.
- KH-L-1066 [TC,AV12][CLI][M] **Per-TUI-state** : {launching, scanning, done-idle, resize, scroll, quit, error} each driven via PTY. Proof: a TUI-state runner.
- KH-L-1067 [TC][CORE][M] **Per-config-knob** (Tier-A): every flag/env/toml round-trips compiled→toml→CLI with CLI winning. Proof: a config-roundtrip runner over the knob registry.
- KH-L-1068 [TC,VR-proptest][CORE][L] **Proptest 10k+** per invariant: dedup, ordering, segment-attribution, offset-mapping, redaction, decode-roundtrip. Proof: each proptest at ≥10k cases.
- KH-L-1069 [TC,AV2][BENCH][L] **Differential vs peers** per corpus (mirror, CredData, +new): TP/FP/FN per tool. Proof: the differential-bench matrix.
- KH-L-1070 [TC,AV1][BENCH][M] **Criterion** per hot path + a regression gate. Proof: the criterion baseline set.
- KH-L-1071 [TC,AV13][INSTALL][L] **Cross-OS e2e** per {install, doctor, scan, sarif, tui, hook, uninstall} × {linux-x64, linux-arm64, macos-arm64, windows}. Proof: the dogfood-all-os matrix extended.

## Coherence gates (docs/help/code/tests agree at every commit)

- KH-L-1072 [AV10][DOCS][M] README claim-extraction: every quantitative/behavioral claim (63 claims, "105× daemon", "what it catches", perf numbers) has a verifying test; a gate fails on an unverified claim. Proof: a `readme_claims` runner covering all 63.
- KH-L-1073 [AV10][CLI][M] `--help` ↔ args ↔ completions ↔ README ↔ man — one source, generated, gated for drift. Proof: a `help_coherence` gate.
- KH-L-1074 [AV10][CORE][M] JSON/JSONL/SARIF field names ↔ docs ↔ code one source of truth. Proof: the schema-coherence gate (cross-link KH-L-0842).
- KH-L-1075 [AV10][DETECTORS][M] Detector ids in docs/reports resolve to a canonical `detectors/<id>.toml` (the FP_AUDIT gate, generalized to all docs). Proof: `doc_detector_ids_resolve` over every doc.
- KH-L-1076 [AV10][CLI][S] CHANGELOG top entry matches the built version + the headline features have tests. Proof: cross-link KH-L-0031.

## The materializer

- KH-L-1077 [SCALE,AV12][CI][M] `scripts/materialize-backlog.sh` reads `detectors/*.toml`, the subcommand/decoder/source/format/backend registries, and the generators above, and emits `docs/legendary/99_BACKLOG.tsv` (one row per concrete test item: `KH-G-NNNNN<TAB>vector<TAB>subsystem<TAB>target<TAB>test-type<TAB>status`). This is how the plan reaches and exceeds 1000+ concrete items mechanically — every detector, decoder, source, subcommand, format, backend × its contract test-types. Proof: the script + a committed `99_BACKLOG.tsv` with ≥1000 rows; CI checks each `done` row maps to a real passing test.
- KH-L-1078 [SCALE][CI][M] A `backlog-burndown` report: `% of KH-G rows with a passing test`, printed by `legendary-status.sh`, trending to 100%. Proof: the burndown in the ledger.
- KH-L-1079 [AV14][CI][S] The materializer re-runs on every detector/source/subcommand addition so the backlog never goes stale (a new detector auto-adds its contract rows). Proof: a `backlog_current` gate.

The materialized `99_BACKLOG.tsv` + the ~260 hand-authored lane items (files
10–90) together far exceed 1000 concrete, grounded, executable items. Execution
order: the RESEARCH/XL flagship lanes (files 10/20/30/40/90) first, then the
generated breadth burns down per-surface, hardest detectors/sources first.
