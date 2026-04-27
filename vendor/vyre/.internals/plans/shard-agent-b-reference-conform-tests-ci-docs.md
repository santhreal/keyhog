# SHARD AGENT-B — Reference + Conform + Tests + CI + Docs + Cleanliness

You own 11 tasks from `.internals/planning/LEGENDARY.md`. Work for hours.
Direct commits to `main`. Each commit references the task id
(`vyre §9: ...`).

Read `.internals/planning/LEGENDARY.md` once before starting. Read
`docs/THESIS.md` and `docs/ARCHITECTURE.md` for the invariants.

## Global invariants (non-negotiable)

1. **Zero runtime cost on the dispatch hot path.** Applies to you too —
   when you write tests, the code under test must honor this. Tests themselves
   may be slow (SQLite-level coverage), but production paths must not.
2. **No stubs (LAW 1).** Every test you add must assert something meaningful.
   No `let _ = result;`. Tests that pass by doing nothing are worse than no
   tests — they give false confidence.
3. **Don't delete, implement (feedback_dont_delete_implement).** If you
   encounter broken imports or "dead" code in your owned directories, rewire
   to the current API. Deletion is only correct when the subsystem is gone
   from the product. Two incidents on 2026-04-12 (core agent deleted 1400
   LOC of engine/decode; I deleted 584 LOC of conform bytecode_eq) both had
   to be reverted and re-implemented. Don't repeat them.
4. **Tests are designed to FAIL first.** Write what SHOULD be true based on
   the API contract. A failing test is a finding in the engine, not a bug in
   the test. Never soften an assertion to make it pass — report the engine
   failure so Claude or Agent-A can fix it.
5. **Commits must compile.** `cargo check --workspace --all-features` must
   pass (or the error count must be monotonically decreasing). You may NEVER
   raise the error count.

## Owned files — you may edit these

**Reference interpreter (full ownership):**
- `vyre-reference/**`
- `vyre-core/src/ops/*/reference/**` — MOVE these into `vyre-reference/src/`
  (see #7 §9). After you move them, they're gone from `vyre-core/src/ops/`.
- `vyre-core/src/ops/*/cpu_ref.rs` — same, move.
- `vyre-core/src/ops/*/reference.rs` — same, move.

**Conformance (full ownership):**
- `conform/vyre-conform-spec/**`
- `conform/vyre-conform-generate/**`
- `conform/vyre-conform-enforce/**`
- `conform/vyre-conform-runner/**`

**Examples:**
- `examples/hello_vyre/**` (minor edits OK)
- `examples/three_substrate_parity/**` (grow to full primitive corpus)
- `examples/external_ir_extension/**` (NEW — create as part of §21 / #11)

**Adversarial + fuzz tests:**
- `vyre-core/fuzz/**` (cargo-fuzz targets)
- `vyre-core/tests/adversarial_*.rs` (new adversarial tests — see §25 / #23)
- Any `*/tests/` dir in crates you own (conform, reference)

**CI workflows (you own almost all of them):**
- `.github/workflows/ci.yml`
- `.github/workflows/conform.yml`
- `.github/workflows/semver-checks.yml`
- `.github/workflows/public-api.yml`
- `.github/workflows/fuzz.yml`
- `.github/workflows/loom.yml`
- `.github/workflows/miri.yml`
- `.github/workflows/deny.yml`
- `.github/workflows/udeps.yml`
- `.github/workflows/dependency-audit.yml`
- `.github/workflows/architectural-invariants.yml` (grow with Claude — you
  orchestrate; Claude adds new gates)

**Build system (delete build-scan, minimize build.rs):**
- `vyre-build-scan/**` (DELETE entirely per §17)
- `xtask/**` (grow subcommands: check-all, bench-regen, conform-run, publish-dry)
- Every `build.rs` except those inside Agent-A's owned crates
- `rust-toolchain.toml`
- `.cargo/config.toml`

**Expect/unwrap ratchets + docs (scripts + counters):**
- `scripts/baselines/**` (create — counter files for ratchets)
- `scripts/gen_*.sh` (NEW — generators for docs/catalogs)
- `scripts/check_no_raw_unwrap.sh` (NEW)

**Docs consolidation + coverage matrix:**
- `README.md` (workspace root — rewrite to 5-section strict shape, see §23)
- `CHANGELOG.md` (edit freely; Claude adds release-gate entries)
- `CITATION.cff` `CODE_OF_CONDUCT.md` `CODEOWNERS` `SECURITY.md`
- Every per-crate `README.md` (they should all be ≤30-line pointers to the
  workspace README — rewrite them)
- `docs/catalogs/**` (NEW — coverage matrix, op catalog, public-api snapshots,
  all generated)
- `docs/parity/**` (NEW — parity reports)
- `.internals/` hygiene — audits/, planning/, release/, catalogs/, archive/

**Cleanliness targets:**
- `target/` .gitignore checks
- `vyre-sigstore/` (already gone — confirm `ls vyre-sigstore` returns no
  such file; nothing for you to do here)
- `vyre-primitives/` — KEEP (1745 LOC of live canonical primitive
  NodeKind contract, heavily imported by `vyre-reference`). Do NOT rename,
  do NOT delete. The overlap with the `vyre-ops-primitive` façade is
  naming-only — vyre-primitives is the contract; ops-facades/vyre-ops-primitive
  is a future-split placeholder that today is just `pub use vyre::ops::primitive::*;`.

## Forbidden files — never touch

- `vyre-core/src/dialect/**` (Claude + Agent-A share; you touch nothing here
  except for READING op definitions when writing conform tests. Specifically
  you may never edit a `dialect/*/wgsl.rs` or `*/naga.rs` — that's Agent-A.
  You may never edit `dialect/registry.rs`, `op_def.rs`, etc. — that's Claude.)
- `vyre-core/src/ir/**` (Claude — all IR)
- `vyre-core/src/ops/**` except the files explicitly listed in your
  "Reference interpreter" ownership section above. `ops/metadata.rs`,
  `cpu_op.rs`, `cpu_references.rs`, `fixtures.rs`, `rule.rs` are Claude's.
  Every `ops/*/reference/` and `ops/*/cpu_ref.rs` and `ops/*/reference.rs`
  is yours to MOVE (not edit in place) into `vyre-reference/src/`.
- `vyre-spec/**` (Claude)
- `vyre-macros/**` (Claude)
- `vyre-core/src/optimizer/**` (Agent-A — optimizer passes)
- `vyre-core/src/lower/**` (Agent-A — lowerings)
- `vyre-core/src/diagnostics.rs`, `error.rs` (Claude)
- `vyre-wgpu/**` (Agent-A)
- `backends/photonic/**`, `backends/spirv/**` (Agent-A)
- `benches/**` (Agent-A — EXCEPT you may add `benches/adversarial_*.rs` if an
  adversarial test happens to be a bench; prefer putting it in the fuzz
  target instead)
- `scripts/check_no_*.sh`, `check_architectural_invariants.sh`,
  `check_trait_freeze.sh`, `check_registry_consistency.sh`,
  `check_capability_negotiation.sh`, `check_unsafe_justifications.sh`,
  `check_expect_has_fix.sh`, `check_no_parse_str.sh` (Claude owns the Law
  gates; you may add your own new `check_*.sh` scripts for ratchets, but
  don't edit the existing Law-A/B/C/D/H gates)
- `docs/ARCHITECTURE.md`, `THESIS.md`, `VISION.md`, `semver-policy.md`,
  `wire-format.md`, `wire-format-v2.md`, `inventory-contract.md`,
  `frozen-traits/**`, `error-codes.md`, `composition-algebra.md`,
  `memory-model.md`, `targets.md` (Claude owns every doc named in
  ARCHITECTURE.md as canonical; you own `docs/catalogs/**`, `docs/parity/**`,
  `docs/benchmarks.md` if you create it, every per-crate README)
- Workspace `Cargo.toml` and `vyre-core/Cargo.toml` (Claude). You may edit
  the `Cargo.toml` of every crate you own.

## Known issues at plan start (fold into existing tasks)

These are concrete, verified bugs. Each maps to one of your tasks below.
When you land the task, the issue must be GONE — not documented, not
deferred. No evasion (LAW 9).

- **Circular dev-dep vyre-core ↔ vyre-reference** → fold into #7 §9. After
  the reference interpreter move, `vyre-reference` depends on `vyre` for
  IR types only. `vyre` depends on `vyre-reference` only as a dev-dep in
  test harnesses — and only after every other path is audited. A runtime
  dep either direction is disallowed. Break the cycle; if a test in
  `vyre-core` currently needs reference eval, route it through the
  `VyreBackend` trait (the reference backend registers via inventory,
  discoverable from `vyre`).

## Your 11 tasks

### #7 — §9 Reference interpreter inversion — BIG MOVE

**Where:** move `vyre-core/src/ops/*/reference/` + `ops/*/cpu_ref.rs` +
`ops/*/reference.rs` into `vyre-reference/src/`. Current offenders:
- `vyre-core/src/ops/hash/reference/` (2,040 LOC)
- `vyre-core/src/ops/compression/*/cpu_ref.rs`
- `vyre-core/src/ops/crypto/*/reference.rs`
- `vyre-core/src/ops/string_matching/*/reference.rs`

After the move, `vyre-core` has zero `*/reference/` directories.
`vyre-reference` depends on `vyre` for IR types only. Nothing in `vyre`
depends on `vyre-reference` except conform and tests.

**Rewrite the interpreter as iterative:** `vyre-reference/src/eval_expr.rs`
is recursive with `Box<Expr>`. Rewrite as an iterative stack machine with a
value stack and an op stack. Matches the GPU model. (Massive speedup; deep
IR no longer blows the native stack.)

**Delete the workgroup scheduler:** `vyre-reference/src/workgroup.rs`
simulates workgroups with a complex scheduler. `vyre-reference/src/sequential.rs`
(already landed) is the right model. Delete the old scheduler; every
conform path uses sequential.

**Unify entry point:** expose `vyre_reference::evaluate_program(program, inputs)
-> Outputs` as the **only** public entry. No workgroup internals leak.

**Register as backend:** impl `VyreBackend for Reference` so
`registered_backends()` sees it alongside wgpu / spirv / photonic. Mock-backend
tests in `vyre-core` depend on this registration, not on `vyre-reference`
internals.

**Success:** `cargo test -p vyre-reference` green, conform tests green,
`cargo test -p vyre --tests mock_backend` green (the tests read reference
via the backend trait). Iterative eval 10× faster than recursive on deep IR
(bench `benches/reference_iteration.rs`).

### #8 — §10 + §35 Real conform prover + composition algebra — BIGGEST

**Where:** `conform/vyre-conform-runner/**`, `conform/vyre-conform-enforce/**`,
`conform/vyre-conform-spec/**`, `conform/vyre-conform-generate/**`.

**What:**
- `vyre-conform-runner` gains the core loop: for each op in
  `DialectRegistry::global().iter()` × each backend in
  `registered_backends()`, instantiate `LawProver`, run every declared
  `AlgebraicLaw` against the op's `WitnessSet::enumerate`, emit a
  `Certificate` to `.internals/certs/<backend>/<op_id>.json`.
- `LawProver::verify_*` takes a raw `Fn(u32,u32)->u32` today. Add
  `verify_*_via_backend(op: &OpDef, backend: &dyn VyreBackend, witnesses:
  &[u32]) -> LawVerdict` that packages the program, dispatches, and
  compares.
- **Composition prover (NOVEL).** Implement the real law algebra in
  `conform/vyre-conform-spec/src/composition.rs`:
  - `Commutative ⊗ Commutative = Commutative` iff compose is binary-symmetric
  - `Associative + Associative` requires bracketing-independence test
  - `Identity(e_a) ⊗ Identity(e_b) = Identity(composition_of_identity(e_a, e_b))`
  - `Bounded{a,b} ⊗ Bounded{c,d} = Bounded{compose_bound(...)}`
  - `Monotonic ⊗ Monotonic = Monotonic`
  - `Involution ⊗ Involution = Identity`
  - `Distributive` interacts with itself under specific operator algebra
  - Negative: `Commutative ⊗ NonCommutative = {}` (empty set)

  Each rule is documented in source with a reference. Write
  `docs/composition-algebra.md` with proof sketches citing Mac Lane / Baez.
- **Signed certs:** `vyre-conform-runner` generates fresh ed25519 keypair
  per run (local) or reads `VYRE_CONFORM_SIGNING_KEY` from env (release).
  `Certificate` JSON has `signature` over canonical bytes (sorted keys, no
  whitespace). `--verify` subcommand checks a cert against a pubkey.
- `Certificate.program_blake3` and `Certificate.witness_set_blake3` become
  real blake3 of `Program::to_wire()` and
  `WitnessSet::fingerprint_canonical()`. Delete every `"TBD"` string.
- `Certificate.timestamp` — ISO 8601 UTC via `chrono`. Deterministic via
  `--freeze-time` env var.
- Determinism enforcer uses `seeded_nonzero_bytes` already. Grow witness
  coverage: full `U32Witness` set. "Zero triggers no races" was the original
  bug — never use zero as the sole witness.
- Bound combinatorial explosion: witness × op × backend ≤ 10M per CI run;
  shard across CI matrix when above.
- **Proptest integration:** `vyre-conform-generate` ships real proptest
  strategies per `DataType`. Shrinking finds minimal witnesses. If
  `verify_commutative` returns `CommutativeFails { a, b, .. }`, the shrinker
  reduces both to the smallest failing pair.
- **CI:** `.github/workflows/conform.yml` runs `vyre-conform run --backend
  wgpu` on every PR. Cert diff vs `main`-baseline rejects any cert-surface
  change without a CHANGELOG entry.

**Success:** every op in the registry × every backend produces a signed cert;
cert JSON is byte-identical across runs (determinism). CI conform.yml green.

### #11 — §21 External extension demo

**Where:** `examples/external_ir_extension/` (NEW). Crate NOT in the workspace
— depends on vyre via `path="../.."` for local dev (or a path-specifier that
won't break after workspace restructure).

**What:** register:
- A custom `ExprNode` implementing `tensor.gather` (hypothetical op)
- A custom `ExtensionDataType` (`Tensor { rank: 3 }`)
- A custom `RuleConditionExt` (`FileSizeGt`)
- A custom `Backend` (CPU-only mock that runs the extension op)

Integration test:
- Builds a Program using the extension Expr
- Round-trips through VIR0 wire
- Passes through CSE + DCE (proves visitor-based passes ride)
- Validates cleanly
- Dispatches on the mock backend
- Produces correct output
- **Zero edits** to `vyre-core`, `vyre-wgpu`, `vyre-reference` required

**Success:** `cargo test -p external_ir_extension` green in CI. ≤200 LOC
(the cap is the contract — LEGENDARY §21.4). Shows the extension surface
works end-to-end.

**Self-contained execution:** write the example against the IR surface as
specified in `LEGENDARY.md §1`. If `DataType::Opaque` / `Expr::Opaque` /
`ExtensionDataType` trait / `ExprExtensionNode` trait are not yet in the
tree, define the trait shapes you need in your example crate and use them.
Claude's §1 lands the same shapes in vyre-core; when both meet, rename your
local trait to `vyre::dialect::ExtensionDataType` in one search-replace and
delete your local definition. Keep moving — never wait.

### #12 — §22 Three-substrate parity

**Where:** `examples/three_substrate_parity/`. Scaffold exists today
(xor-1M). Grow to full primitive corpus.

**What:** one program per primitive, dispatched on wgpu + spirv +
reference (every non-stub backend), assert byte-identical output. Failing
byte-difference produces a message naming the specific differing bytes.

**CI:** runs nightly, publishes `docs/parity/<commit>.md`.

**Success:** every primitive in the stdlib dialect produces byte-identical
output across all three substrates. The parity table lives in
`docs/parity/latest.md`.

### #21 — §15 Expect/unwrap/docs ratchets to zero

**Where:** `scripts/check_expect_has_fix.sh` (Claude owns, but the baseline
counter file is yours to update), `scripts/check_no_raw_unwrap.sh` (NEW —
yours), `scripts/baselines/*.txt` (NEW — ratchet files).

**What:**
- `check_expect_has_fix.sh` baseline is currently 111 (per LEGENDARY §15.1).
  Your job: migrate call sites until the baseline drops. You don't touch the
  script; you touch the source files to add `Fix: ...` prose to every
  `expect(...)` string.
- Similar for `unwrap()` — 287 sites. Add `scripts/check_no_raw_unwrap.sh`
  with a baseline starting at 287. Ratchet down.
- `#![deny(missing_docs)]` is on core. Sweep every `pub` item — each gets
  real rustdoc (invariant + example + why). A one-line `///` is not enough.
  Absent the three pieces, prefer `#[allow(missing_docs)]` with a visible
  TODO over a one-line lie.
- Clippy: `cargo clippy --workspace --all-targets -- -D warnings` must be
  green in your owned crates. Every `#[allow(clippy::...)]` needs a comment
  naming why the lint is wrong here.
- `cargo doc --workspace --no-deps --all-features -D broken_intra_doc_links`
  in CI.

**Success:** `scripts/check_expect_has_fix.sh` and
`scripts/check_no_raw_unwrap.sh` both exit 0 with a baseline approaching 0.
`cargo doc` clean.

### #23 — §25 Adversarial tests + fuzz + proptest

**Where:** `vyre-core/fuzz/**` (cargo-fuzz targets), `vyre-core/tests/adversarial_*.rs`.

**What:**
- Fuzz targets (cargo-fuzz):
  - `wire_round_trip` — fuzz bytes → Program → bytes; assert identity or
    typed error.
  - `validate_no_panic` — fuzz Program → validate_program; assert result or
    typed error; never panic.
  - `optimizer_fixpoint` — fuzz Program → optimize; assert fixpoint reaches
    fixed state within the cap.
  - `parser_no_panic` — fuzz arbitrary bytes through every public `from_*`.
- Property tests for every AlgebraicLaw (via proptest): 1000 witnesses per
  run, shrinking on failure. Output captured to
  `.internals/audits/proptest-log-<date>.md`.
- Adversarial tests designed to FAIL:
  - Nested IR hitting the depth limit (`V018` triggers)
  - Cyclic buffer refs
  - Size-class overflow in BufferPool
  - Race between two dispatchers on the same pipeline
  - Corrupted wire bytes (every byte of a valid program flipped)

Each adversarial test lives next to the module it probes, named
`adversarial_*` to signal intent.

**Success:** `cargo fuzz run wire_round_trip -- -max_total_time=60` doesn't
panic. `cargo test adversarial_` green (these tests are INTENDED to exercise
failure paths, not trigger them — they assert that the engine produces a
typed error, never crashes).

### #26 — §19 Full CI gate set

**Where:** every `.github/workflows/*.yml`. Coordinate with Claude on
`architectural-invariants.yml` (Claude writes new gates; you own the
workflow file that runs them).

**What:** deliver every workflow in LEGENDARY §19 list. See that section for
the complete set. Summary:
- `ci.yml`: cargo test, clippy, doc, fmt
- `architectural-invariants.yml`: every `scripts/check_*.sh`
- `conform.yml`: conform run + cert diff
- `semver-checks.yml`, `public-api.yml`
- `fuzz.yml` (nightly), `loom.yml`, `miri.yml`
- `deny.yml`, `udeps.yml`, `dependency-audit.yml`
- `bench-regression.yml` (coordinate with Agent-A)

**Success:** every workflow green on a fresh clone + `main` push.

### #27 — §17 Build system (delete build-scan, minimize build.rs)

**Where:** `vyre-build-scan/**` (delete), `vyre-core/build.rs`,
`xtask/**`, `rust-toolchain.toml`, `.cargo/config.toml`.

**What:**
- `vyre-core/build.rs` runs `vyre_build_scan::scan_core()` via the
  `vyre-build-scan` crate. That crate parses the source tree with `syn` on
  every `cargo build`. **Delete it.**
- Replace with minimal walkdir-based discovery that emits
  `cargo:rerun-if-changed=src/` and nothing else. Registrations land at link
  time via inventory (§4 contract — Claude writes the doc; you trust it).
- `conform/*/build.rs` if any — same treatment.
- `rust-toolchain.toml` move to 1.87 (or current stable) when deps support.
- `.cargo/config.toml`: `[target.'cfg(all())']` link args (mold for Linux,
  lld for Windows). Builds 2–5× faster in CI.
- `xtask` subcommands: `check-all`, `bench-regen`, `conform-run`,
  `publish-dry`.

**Success:** `cargo build` cold takes ≥20% less time. `vyre-build-scan` gone
from the workspace.

### #28 — §18 Cleanliness sweep

**Where:** many — see LEGENDARY §18.

**What:**
- `vyre-sigstore/` orphan crate: delete or fold into conform-runner. Decide.
  (Coordinate with Claude via commit message if you fold — Claude updates
  ARCHITECTURE.md.)
- `vyre-build-scan/` already deleted in #27.
- `vyre-primitives/` — if it overlaps `vyre-ops-primitive`, rename to
  `vyre-cpu-primitives` for clarity. Coordinate with Claude (workspace
  Cargo.toml is Claude's).
- Dead features: `wgpu_subgroups = []`, `test-helpers = []` in
  `vyre-core/Cargo.toml` — **don't edit that Cargo.toml**, just flag via
  commit message `vyre §18-REQUEST: dead features in vyre-core/Cargo.toml:
  wgpu_subgroups, test-helpers`.
- `vyre-core/src/ops.rs` + `vyre-core/src/ops/` directory coexist — merge
  to `ops/mod.rs` (coordinate with Claude / Codex — Codex may already have
  touched this during §3).
- Documentation consolidation (also §23 / #29 — overlap fine).
- `.internals/` structure: `audits/`, `planning/`, `release/`, `catalogs/`,
  `archive/`. Move anything >60 days that isn't pinned to `archive/`.
- `scripts/` naming: every script starts with `check_`, `run_`, or `gen_`.
  Delete non-matching.
- `target/` hygiene — every `.gitignore` covers `target/` at any depth.
- `Cargo.lock` committed; `Cargo.lock.old` gitignored.

**Success:** workspace is pristine. `git status --porcelain` after `cargo
build` shows no target-related files.

### #29 — §23 Documentation consolidation

**Where:** every README, `docs/` tree, `docs/catalogs/**`, `docs/parity/**`.

**What:**
- `README.md` (root) strict 5-section shape: one-paragraph claim,
  three-example quickstart, crate map, link to THESIS/VISION/ARCHITECTURE,
  license. ≤100 lines ideal.
- `docs/` stays canonical — Claude owns those. You own `docs/catalogs/**`
  (generated from code; never hand-edited) and `docs/parity/**`.
- No `CHANGELOG.md` inside sub-crates. Each per-crate CHANGELOG becomes a
  pointer line to the workspace CHANGELOG.
- Per-crate README ≤30 lines and is a pointer to the workspace README.
- `docs/catalogs/` generated by `scripts/gen_*.sh`. CI re-runs the
  generators and fails if output drifts.
- Rustdoc cross-links: every op page links to its KAT vectors
  (`rules/kat/<path>.toml`), its cert (`rules/op/<id>.toml`), and its
  declaring dialect module.

**Success:** `cargo doc --workspace --no-deps --all-features` produces clean
docs with working intra-doc links. No duplicate per-crate changelogs.

### #30 — §27 + §38 Coverage matrix + consistency contracts

**Where:** `scripts/gen_coverage_matrix.sh` (NEW),
`docs/catalogs/coverage-matrix.md` (generated),
`scripts/check_coverage_matrix_complete.sh` (NEW),
`scripts/check_registry_consistency.sh` (EXISTS — Claude owns; you may
extend with commit-message request).

**What:**
- Coverage matrix: for each op in the registry — category, wgpu supported,
  spirv supported, reference supported, photonic supported, laws verified,
  cert present, parity-bench run. Generated from code, checked in under
  `docs/catalogs/coverage-matrix.md`.
- `scripts/check_coverage_matrix_complete.sh`: fails if any op has an
  unjustified hole (no cert, unregistered backend, missing laws).
- Consistency: (op_id, category) pairs unique across registry. KAT paths
  `rules/kat/<dialect>/<op>.toml`. Cert paths `rules/op/<id>.toml`. Every
  registered dialect has at least one op. Op-id catalog append-only.

**Success:** `docs/catalogs/coverage-matrix.md` regenerates from code, CI
gate `check_coverage_matrix_complete.sh` green. Publishing is blocked if any
column is empty without explicit justification.

## Merge protocol

- Commit to `main` directly. Each commit touches only owned files.
- Commit message prefix: `vyre §<N>: <one-line summary>`.
- Before committing: `cargo check --workspace --all-features` must pass (or
  error count strictly decreasing). Never raise the count.
- If you need Claude's files modified: commit a `vyre §<N>-REQUEST: <what
  you need>` placeholder. Don't edit Claude's files.
- If Agent-A's files have bugs that block your tests: commit a `vyre
  §<N>-BLOCKED-ON-AGENT-A: <what's wrong>` and take another task.

## What "done" looks like for your shard

- All 11 tasks committed.
- `cargo test --workspace --all-features --all-targets` green OR
  monotonically closer to green.
- Every CI workflow on `.github/workflows/*.yml` green.
- `cargo fuzz run wire_round_trip -- -max_total_time=60` clean.
- Coverage matrix regenerates from code and is byte-stable across runs.
- Every CHANGELOG entry you touched is clean, no duplicates.
- No stubs in any file you touched.

Go.
