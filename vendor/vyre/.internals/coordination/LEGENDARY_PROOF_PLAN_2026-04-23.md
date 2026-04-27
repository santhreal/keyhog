# Legendary Proof Plan — surgec arbitrary compute + scan

**Date:** 2026-04-23  
**Purpose:** list every piece of evidence that would convince a reasonable skeptic surgec is *legendary* at both scan AND arbitrary compute, and slot each piece into an agent dispatch lane so it ships in parallel.

The rule: **every claim has a test.** No narrative, no "we believe", no "benchmark coming soon." Either the test exists and runs green in CI or the claim doesn't ship.

---

## The claim surface

Legendary means *all* of these are provable in one command per claim:

### C1 — Expressivity. Every SURGE construct lowers correctly.
Every Expr variant × every Node variant × every BinOp × every dtype × every combination thereof dispatches byte-equivalent (integer) or ULP-equivalent (float) to the CPU reference, on every backend.

### C2 — Speed. ≥1000× vs every competitor on every cell.
`ripgrep` + `hyperscan` + `CodeQL` + `Semgrep-Pro` + `grep` + `ugrep` + `silver-searcher` + `ag`, across 6 rule classes × 6 corpus sizes × 3+ GPUs.

### C3 — Scale. Thousands of rules in one dispatch.
10k procedurally-generated rules fused into one megakernel, per-rule amortized time flat from N=1 to N=10k.

### C4 — Determinism. Same input → same bytes. Always.
10,000-run stability test on compile, dispatch, and output readback.

### C5 — Portability. Same output bit-for-bit across backends.
Every conformance case passes Vulkan + SPIR-V + (future Metal/DX12/PTX), and cross-machine `PipelineFingerprint` hex matches.

### C6 — Safety. No hostile input produces UB or unbounded resource consumption.
Continuous structure-aware fuzz against every Program wire input, every SURGE source, every scan input bytes.

### C7 — Ergonomics. A new user ships in ≤ 30 minutes.
Hand-timed walkthrough (RELEASE_ENGINEERING step 10) + `examples/` directory with 4+ worked programs (L10).

### C8 — Authenticity. Every claim has a signed certificate.
`vyre-conform-runner prove` + `verify_cert_signature_hex` attest both the hash chain AND the Ed25519 signature for every release.

---

## Proof components (one test file each)

| Claim | Test file | Lane | Owner |
|---|---|---|---|
| C1a every `Expr` variant | `vyre-driver-wgpu/tests/expr_exhaustive.rs` | kimi-expr | kimi |
| C1b every `Node` variant | `vyre-driver-wgpu/tests/node_exhaustive.rs` | kimi-node | kimi |
| C1c every `BinOp` × dtype | `vyre-driver-wgpu/tests/binop_cross_dtype.rs` | kimi-binop | kimi |
| C1d pairwise op composition | `vyre-libs/tests/op_pairwise.rs` (proptest) | kimi-pairwise | kimi |
| C1e surge-grammar-driven lowering | `surgec/tests/surge_grammar_fuzz.rs` | kimi-grammar | kimi |
| C2 per-competitor ≥1000× | `surgec/benches/vs_every_competitor.rs` + `benches/thresholds.toml` | codex-bench | codex |
| C3 10k-rule megakernel | `vyre-driver-wgpu/tests/megakernel_10k_rules.rs` | codex-scale | codex |
| C4 compile determinism | `surgec/tests/compile_determinism.rs` (landing now) | claude-det | claude |
| C4 dispatch determinism | `surgec/tests/dispatch_determinism.rs` (10,000 runs) | kimi-dispatch-det | kimi |
| C5a cross-backend parity | `vyre-conform-runner/tests/cross_backend_parity.rs` | kimi-cross-backend | kimi |
| C5b cross-host fingerprint | `vyre-runtime/tests/fingerprint_cross_host.rs` | claude-fp | claude |
| C5c scan/run byte-equivalence | `surgec/tests/run_scan_equivalence.rs` | claude-runscan | claude |
| C6a Program wire fuzz | `vyre-foundation/fuzz/targets/program_wire.rs` | kimi-fuzz-wire | kimi |
| C6b SURGE grammar fuzz | `libs/surge/fuzz/targets/parser.rs` | kimi-fuzz-surge | kimi |
| C6c scan input fuzz | `surgec/fuzz/targets/scan_bytes.rs` | kimi-fuzz-scan | kimi |
| C7a examples/gemv | `examples/gemv/` | gemini-ex1 | gemini |
| C7b examples/fixpoint | `examples/fixpoint/` | gemini-ex2 | gemini |
| C7c examples/sha3 | `examples/sha3/` | gemini-ex3 | gemini |
| C7d examples/wave-sim | `examples/wave-sim/` | gemini-ex4 | gemini |
| C8 cert end-to-end | `vyre-conform-runner/tests/cert_end_to_end.rs` | claude-cert | claude |

**20 test files, 20 concrete lanes, zero narrative.** Each lane ships in parallel; no blocker between them.

---

## Organization bundling

Rather than dumping 20 test files at the workspace root, they slot into the subsystem structure documented in `SUBSYSTEM_STANDARD.md`:

- **`tests/conformance/`** — C1, C5a, C8. Owned by `vyre-conform-runner`.
- **`tests/parity/`** — C1 pairwise, C5b. Owned by `vyre-driver-wgpu`.
- **`tests/benchmarks/`** — C2, C3. Owned by `surgec/benches/`.
- **`tests/determinism/`** — C4, C5c. Owned by `surgec/tests/`.
- **`fuzz/`** — C6. Owned per-crate with a single nightly runner.
- **`examples/`** — C7. Workspace-level directory, consumed by RELEASE_ENGINEERING step 10.

Every subsystem has one README listing its tests and how to run them. The workspace README points at the subsystem list. A newcomer navigates by subsystem, not by a flat directory of 300 test files.

---

## Kimi-mass-dispatch-ready prompts

Each of these is sized for a single Kimi agent (1 file, 1 claim, ≤ 400 LOC). They can run in parallel; scope locks per file.

### Kimi lane 1 — every Expr variant exhaustive lowering

> Write `vyre-driver-wgpu/tests/expr_exhaustive.rs`. For every variant of `vyre::ir::Expr`, construct a minimal Program that exercises that variant, lower it to naga, dispatch through `WgpuBackend`, and assert the output bytes equal the `vyre-reference` CPU execution bytes. For floating-point variants, accept results within the per-op ULP budget from `vyre-conform-runner::fp_parity`. Fail with a Fix: hint naming the variant that diverged. Proof + adversarial pair — the adversarial side constructs pathological operand combinations (zero, min, max, NaN for F32) and asserts either the correct output or a named `LoweringError` rejection.

### Kimi lane 2 — every Node variant exhaustive

> `vyre-driver-wgpu/tests/node_exhaustive.rs`. Same shape for Node: Let, Store, If (both branches, nested), Loop (static + dynamic bound, empty, large), Barrier (every scope), Return, Region, Block. Adversarial side: nested loop with dynamic bound + mid-body Return (tests NAGA_HOLES F17/F18 remain fixed).

### Kimi lane 3 — BinOp × dtype cross

> `vyre-driver-wgpu/tests/binop_cross_dtype.rs`. Cartesian product of every `BinOp` variant × every `DataType` accepted as operand on the wgpu backend. For each (op, dtype) cell: construct a minimal 2-input Program, dispatch, assert CPU parity. For cells that are unsupported today (U64 arithmetic, etc.), assert a named `LoweringError` reject. A new op or dtype landing must extend the matrix.

### Kimi lane 4 — pairwise op composition (proptest)

> `vyre-libs/tests/op_pairwise.rs`. proptest harness: generate (op_a, op_b, input_bytes) triples from the registered op catalog; chain `op_a` → `op_b` via `Expr::Call`; dispatch; assert the CPU reference byte-equivalent. 10,000 case budget per run in CI.

### Kimi lane 5 — surge-grammar-driven lowering fuzz

> `surgec/tests/surge_grammar_fuzz.rs`. Structure-aware SURGE generator (via `surge::ast` builders) produces arbitrary Document shapes; compile each; assert either a clean Program or a `SURGEC-ENN` error with Fix: hint. Any panic is a finding.

### Kimi lane 6 — dispatch determinism 10k runs

> `surgec/tests/dispatch_determinism.rs`. For each of 8 representative Programs, dispatch 10,000 times with the same input and assert every readback is byte-identical. Flaky means a non-deterministic op landed or a readback race; find it.

### Kimi lane 7 — cross-backend parity

> `vyre-conform-runner/tests/cross_backend_parity.rs`. For every Cat-A op with a dispatch path on wgpu AND spirv, dispatch on both and assert the outputs match byte-for-byte (or within the op's ULP budget for floats).

### Kimi lane 8 — fuzz targets

> Three fuzz targets: `vyre-foundation/fuzz/targets/program_wire.rs` (arbitrary bytes → `from_wire` → `to_wire` round-trip; never panic), `libs/surge/fuzz/targets/parser.rs` (arbitrary bytes → `parse_str`; never panic), `surgec/fuzz/targets/scan_bytes.rs` (arbitrary bytes → scan against 5 launch rules; never panic).

### Codex lane 1 — vs_every_competitor bench harness

> `surgec/benches/vs_every_competitor.rs`. Criterion cells for 6 rule classes × 6 corpus sizes × 8 competitor baselines (ripgrep, hyperscan, CodeQL, Semgrep-Pro, grep, ugrep, ag, silver-searcher). Each cell measures surgec wall time + competitor wall time + ratio. `thresholds.toml` populated from dry-run baseline; CI fails any cell below 1000×.

### Codex lane 2 — 10k-rule megakernel

> `vyre-driver-wgpu/tests/megakernel_10k_rules.rs`. Procedurally generate 10,000 distinct DFA rules, fuse into one megakernel via `vyre-runtime::megakernel::build_program_sharded`, dispatch against a 10 MiB corpus, assert per-rule amortized wall time flat from N=1 to N=10,000 within a measured noise floor.

### Gemini lane 1-4 — `examples/` directory

> Four worked examples (gemv, fixpoint, sha3, wave-sim), each a self-contained Rust binary in `examples/<name>/` calling `surgec::run_program` with a bundled `.surge` + a CPU reference + a `assert_eq!` on the output bytes. Each example opens with a one-paragraph README explaining what it computes.

### Claude lane (me) — determinism + fingerprint + run/scan equivalence

> `compile_determinism.rs` (landing this turn), `fingerprint_cross_host.rs`, `run_scan_equivalence.rs`. All three are proving-style, no mock dispatch; hand-written fixtures.

---

## Sequencing

- **Today (Claude hands-on):** ship `compile_determinism.rs`, `run_scan_equivalence.rs`, `fingerprint_cross_host.rs`, plus the dispatch stubs for each of C7's four examples so Gemini has a template.
- **Mass dispatch (next lane):** fire 8 Kimi prompts in parallel (lanes 1-8 above) + 2 Codex prompts + 4 Gemini example prompts. 14 agents, 14 files, all scope-locked to distinct workdirs.
- **Review:** every lane ships both a proving test + an adversarial sibling. Review is `check_review` fan-out on the 14 worktrees.
- **CI wire-up:** `GATE_CLOSURE.md` G-column extended: every new test is a gate; missing == no release.

---

## Operating rule

This plan is the coordination doc, not a checklist. It's done when every row in the proof-components table has a green CI cell on the release commit. Partial progress is partial proof of legendary; zero-progress rows are the priority.
