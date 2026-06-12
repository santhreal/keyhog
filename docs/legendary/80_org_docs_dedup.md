# 80 — Organization, docs hygiene, dedup, legibility

The code core is well-mapped; the root is cluttered. The bar: a newcomer
navigates any subsystem in < 5 min from a module map; one canonical primitive per
job; zero stray/untracked/contradictory docs; every public symbol used by a
non-test path or removed. Grounded in the audit done this session.

Numbers: KH-L-0830 … KH-L-0919.

## Doc hygiene (the stray-docs problem)

- KH-L-0830 [AV10,L10][DOCS][M] `FP_AUDIT_REPORT.md` is UNTRACKED but a committed test (`cli/tests/gap/doc_detector_ids_resolve_in_registry.rs`) panics on its absence + `suppression/api.rs` cites it — commit it (it's meant to be tracked) or sever the references. Proof: clean-clone CI green; the doc tracked or the refs gone.
- KH-L-0831 [AV10][DOCS][S] `PANIC_SURFACE_AUDIT_REPORT.md` (untracked, referenced nowhere) — fold its findings into KH-L-0037 then remove. Proof: panic-surface items tracked here; file gone.
- KH-L-0832 [AV10,DEDUP][DOCS][M] Move session/program docs (`ROUNDS.md`, `WAVE10_AGENT_PUSH.md`, `TESTING_PROGRAM.md`, `KEYHOG_LINUX_QUALITY_PROGRAM.md`) into `docs/internal/` so root shows only user-facing docs. Proof: root `.md` list = README/CHANGELOG/CONTRIBUTING/SECURITY/CODE_OF_CONDUCT/PUBLISHING/LICENSE/AGENTS/CLAUDE only.
- KH-L-0833 [L2,AV10][DOCS][S] `TODO.md` (stale, 2026-05-26) — migrate live items into this plan, delete the file (Law 2: no floating TODO). Proof: TODO.md gone, items in `docs/legendary/`.
- KH-L-0834 [AV10,DEDUP][DOCS][M] `backlog/` + gitignored `coordination/` trees — consolidate into `docs/legendary/` (this plan) + the findings registry; one backlog, not three. Proof: a single backlog source; `findings_registry_integrity` green.
- KH-L-0835 [AV10,L10][CI][M] A `docs_no_stray_root` gate: new root `.md` outside the allowed set fails CI; new untracked `.md` referenced by code fails CI. Proof: the gate + green tree.
- KH-L-0836 [AV10][DOCS][M] Every `docs/*.md` is current + referenced (DROP_IN_USAGE, OOB, vyre-usage, GPU_DETECTION_REWRITE, keyhogignore-toml, INTEGRATION_PR_TEMPLATE); stale ones updated or removed. Proof: a `docs_referenced` link-check.

## Module maps + legibility

- KH-L-0837 [AV8][SCANNER][M] Every crate root + every multi-file module dir has a `//!` map like `engine/mod.rs` (the gold standard) — checksum/, decode/, suppression/, multiline/, structured/, sources/, verifier/, cli/. Proof: a `module_has_map` gate (each `mod.rs`/`lib.rs` has a `# ` doc map).
- KH-L-0838 [AV8,L5][CLI][M] `cli/src/orchestrator/dispatch.rs` (745 L) + `orchestrator_config.rs` (623 L) split by responsibility with a map. Proof: ≤500 L + a dispatch map.
- KH-L-0839 [AV8][SCANNER][M] The `CompiledScanner` god-object split (44 impl files) is documented in the map AND a gate keeps the map in sync with the files. Proof: a `engine_map_matches_files` gate.
- KH-L-0840 [AV5,L11][SCANNER][M] Dead/half-wired code sweep: every `pub`/`pub(crate)` symbol is used by a non-test path or made private/removed (`cargo +nightly udeps` + dead-code audit). Proof: a `no_dead_pub` baseline at zero.
- KH-L-0841 [DEDUP,AV7][SCANNER][L] One primitive per job: audit for duplicate helpers (search before any new helper). Known-OK: `warm_runtime_regexes` (per-module by design), trait methods. Find the real dups. Proof: a dedup catalog + each real dup unified into a shared crate.
- KH-L-0842 [DEDUP][CORE][M] One schema per concept: `RawMatch`/`DedupedMatch`/`RedactedFinding`/SARIF/JSON share one source-of-truth for field names. Proof: a schema-coherence test (field names match across formats).
- KH-L-0843 [DEDUP][CORE][M] One parser per format: json/yaml/toml/env parsing isn't reimplemented across structured/ + rule_filter + config. Proof: a single-parser audit.
- KH-L-0844 [DEDUP,AV6][CORE][M] One constant source: thresholds/caps/limits live in one place (Tier-A/Tier-B), not scattered `const`s. Proof: a constants-inventory + consolidation.

## Architecture (one-way, swappable)

- KH-L-0845 [AV8,L5][SCANNER][L] Every subsystem swappable through one boundary (Source trait, Decoder trait, backend enum, Reporter trait) — audit each for leaks. Proof: a per-boundary conformance test.
- KH-L-0846 [AV8,L1][CORE][M] Public API is minimal + stable (1/5/10-year): `cargo public-api` baseline, every addition reviewed. Proof: a public-api gate with a reviewed baseline.
- KH-L-0847 [L4][SCANNER][M] No work-arounds: every "doesn't fit the architecture" is fixed by extending the architecture (audit recent patches for shims). Proof: a shim-audit with each resolved.
- KH-L-0848 [AV10][CLI][M] `--help` for every subcommand + flag matches behavior + the README + completions. Proof: a `help_matches_behavior` e2e per subcommand.
- KH-L-0849 [AV10][CORE][M] Exit codes are documented + consistent + tested (0 clean, N found, error codes). Proof: an exit-code contract table + e2e.
- KH-L-0850 [AV14][ALL][M] Introspection: after each batch, the recurring gap is fixed at the shared cause (e.g. the stale-gate class → a meta-gate). Proof: a per-batch introspection note in the ledger.

(Breadth: each module map, each dedup target, each dead-pub removal is an item;
enumerated as the legibility sweep runs. ~90 items.)
