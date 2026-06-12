# 10 — Foundation: vyre 0.6.2, landing, build/CI spine

Everything else rides on these. The vyre release is the single biggest blocker
(the engine refactor can't push until it lands), so per the hardest-first rule it
runs **first**, in parallel with detection/speed lanes that don't touch the pin.

Numbers: KH-L-0001 … KH-L-0099.

## Flagship: unblock + ship vyre 0.6.2 (RESEARCH)

- KH-L-0001 [SCR,L4,AV5][VYRE][RESEARCH] Root-cause why the vyre release tooling hardcodes `0.6.1` and blocks a `0.6.2` cut — read the publish scripts end-to-end, name the exact hardcode sites. Proof: a written failure-map in `99_LEDGER.md` + a failing dry-run log.
- KH-L-0002 [L4,AV6,CFG][VYRE][L] Make a 0.6.2 cut a single operation by driving vyre's OWN release machinery (`xtask version-matrix` / `release-train` / `package-readiness`), NOT by hand-editing 28 manifests. CORRECTION (KH-L-0001 deep-read): version is deliberately literal-per-crate because the workspace is multi-product (weir/vyrec at 0.1.0); `check_crate_metadata_normalized.sh` intentionally omits `version` from the inherit set, so `version.workspace = true` is WRONG here. The block is the 0.6.1-pinned evidence baseline (release-evidence.toml, package_verify_passed, conformance/signed certs, the 10 release-note tokens), not a missing tool. Fix: a vyre `xtask bump-vyre 0.6.2` (or extend `version-matrix`/`release-train`) that bumps the 28 vyre-0.6.1 crates + `[workspace.dependencies]` + `release-train.toml` tokens/tags in lockstep from one source, leaving weir/vyrec untouched, then regenerates evidence. Proof: `xtask version-matrix` reports zero version blockers at 0.6.2; vyre builds+tests green.
- KH-L-0003 [L1,AV2][VYRE][RESEARCH] Audit the unreleased vyre surface keyhog depends on (`build_regex_dfa_unanchored`, `scan_presence_by_region`, megakernel-batch) — confirm each is API-stable enough to publish (1/5/10-year test). Proof: per-symbol stability note.
- KH-L-0004 [L6,TC][VYRE][L] Prove vyre source builds + full test suite green on this box AND santhserver before any publish. Proof: two green `cargo test` logs (x86_64, + CUDA where present).
- KH-L-0005 [L8][VYRE][M] Probe + prove the vyre CUDA driver builds and the AC kernel self-test passes on every GPU host (5090, santhserver). Proof: doctor `backend=cuda` PASS on each.
- KH-L-0006 [SCR,L1][VYRE][XL] Execute `cargo publish` of vyre 0.6.2 (all subcrates in dependency order) — USER-AUTHORIZED gate, never run unprompted; here the standing mandate authorizes it once 0001–0005 are green. Proof: crates.io shows 0.6.2.
- KH-L-0007 [L3,AV9][VYRE][M] Pin keyhog to `vyre =0.6.2` from crates.io; remove the path override from the workspace `Cargo.toml`. Proof: clean `cargo build` with no `path =`; `vyre_usage_doc_matches_workspace_pin` green.
- KH-L-0008 [L10,AV10][VYRE][S] Delete the now-stale `vendor/vyre` snapshot or re-vendor it at exactly 0.6.2 so vendor == published. Proof: `vendor/README.md` MC-11 contract holds; a gate asserts vendor digest == crates.io.
- KH-L-0009 [AV10][DOCS][S] Update `docs/vyre-usage.md` + the workspace pin comment to 0.6.2 and the published symbol list. Proof: `vyre_usage_doc_matches_workspace_pin` green.
- KH-L-0010 [SCALE,L4][CI][L] Land the engine refactor (78046450 lineage) on `origin/main` once the pin is published — the `[DO NOT PUSH]` flag clears. Proof: `git push`; CI green on origin.

## Build matrix + feature soundness

- KH-L-0011 [CRATE,AV9][CLI][M] Prove every feature combo compiles: `default`, `ci`, `ci-lean`, `portable`, `--no-default-features`, each single feature on/off. Proof: a `scripts/feature-matrix.sh` CI job, green.
- KH-L-0012 [L11,AV11][SCANNER][M] Every `#[cfg(feature=...)]` gate has a no-feature build that still compiles warning-clean (Law 11 utilization). Proof: `cargo build --no-default-features` warning-free per crate.
- KH-L-0013 [L10][SCANNER][L] Audit every `#[cfg(feature)]` fallback for silent degradation (e.g. simd→cpu, gpu→cpu): each must be loud + recorded. Proof: a `deny_silent_*` test per fallback edge.
- KH-L-0014 [AV1,L7][CLI][M] Cold-start time budget per feature profile (portable < 150 ms, default with GPU probe < target); measured + gated. Proof: criterion + a doctor-startup bench in CI.
- KH-L-0015 [CRATE][SCANNER][M] Prove each tool subcrate is usable as a library (`cargo add keyhog-scanner` etc.) with a doc-tested minimal example. Proof: a `tests/lib_consumer` crate that depends on each.
- KH-L-0016 [L5,AV8][CLI][L] Verify one-way layering by gate: domain crates (core/scanner) must not import cli/transport/ui. Proof: an `arch_layering` gate that greps the dep graph.
- KH-L-0017 [AV9][CI][M] Pin the exact rust toolchain + MSRV (1.89) and prove the MSRV build in CI, not just stable. Proof: an MSRV CI job green.
- KH-L-0018 [L7,AV1][CI][M] Replace `release-fast` ad-hoc profile usage with a documented profile table; ensure release binaries are LTO+strip optimal. Proof: a profile doc + size/speed comparison.
- KH-L-0019 [AV6,CFG][CORE][M] Every compiled-in default (concurrency, timeout, depth, rate, severity) flows compiled→`keyhog.toml`→CLI with CLI winning; no orphan defaults. Proof: a Tier-A round-trip test per knob.
- KH-L-0020 [AV6,CFG][DETECTORS][M] Every hardcoded list in src is either generated from Tier-B data or moved to `rules/`; a gate bans new hardcoded lists. Proof: a `no_hardcoded_lists` gate with the curated exceptions enumerated.

## CI gate system health

- KH-L-0021 [AV10,L9][CI][L] Inventory every gate file (145 `*_no_inline_tests` + the gap/ + unit/gates/ trees) and prove each runs in CI (named in a workflow or in an aggregator). Proof: a `gate_coverage` meta-test: every `tests/**/gates/*.rs` is reachable.
- KH-L-0022 [AV9][CI][M] Fix `findings_registry_integrity`: registry `test` paths in gitignored `coordination/` fail on clean clone. Decide: track the coordination findings or rewrite the gate to ignore gitignored paths loudly. Proof: gate green on clean checkout.
- KH-L-0023 [L10,AV9][CI][M] Make the standalone-test-file problem systemic: any `crates/*/tests/*.rs` not named in a workflow OR an aggregator fails a meta-gate (so new tests can't be silently un-run). Proof: the meta-gate + the current orphans wired in.
- KH-L-0024 [AV12,TC][CI][M] The big aggregators (`all_tests`) must run under BOTH `ci-lean` and `gpu` in CI on a GPU runner, not just ci-lean. Proof: a GPU CI lane (self-hosted 5090 runner) green.
- KH-L-0025 [L8][CI][L] Stand up a self-hosted GPU CI runner (5090/santhserver) so GPU gates (`gpu_ac_*`, `engine_scan_gpu_*`, megakernel parity) actually execute in CI, not just locally. Proof: GPU job green in Actions.
- KH-L-0026 [AV14][CI][M] A flaky-test detector: run the suite N× nightly, quarantine + file any test whose result varies. Proof: a nightly job + zero quarantined after fixes.
- KH-L-0027 [AV10][CI][S] CI caches are correct (LFS for contract fixtures, vectorscan install) — prove a from-scratch runner is green. Proof: a no-cache CI run green.
- KH-L-0028 [L9,AV9][CI][M] Ban `#[ignore]` drift: every ignored test carries a reason + a tracking item here; a gate lists them. Proof: `ignored_tests_have_owners` gate.
- KH-L-0029 [AV1][BENCH][L] The benchmark `gate` (bench-nightly + differential) runs on every PR touching the engine and fails on regression > threshold. Proof: a perf-gate CI job wired to criterion baselines.
- KH-L-0030 [SCALE][CI][M] A `scripts/legendary-status.sh` that prints plan progress (items landed / total, axes moved in last 10 commits). Proof: the script + its output in the ledger.

## Repo + release hygiene

- KH-L-0031 [AV10][DOCS][S] `CHANGELOG.md` (2393 L) is generated or curated against real commits; a gate checks the top entry matches the version. Proof: `changelog_matches_version` gate.
- KH-L-0032 [SCR,L1][CLI][M] `scripts/prerelease.sh` gates the full release contract (tests + bench + cross-OS dogfood + doc coherence) before a version bump. Proof: a dry-run that blocks on any red.
- KH-L-0033 [AV9][CLI][M] `keyhog --version` / `doctor` report commit + detector-set digest + ML-model version (already do) — gate that these match the build. Proof: a `version_provenance` e2e test.
- KH-L-0034 [L3][CLI][M] Publish keyhog to crates.io as installable CLI + the subcrates; prove `cargo install keyhog` works from a clean machine. Proof: a clean-VM install dogfood (cross-OS lane).
- KH-L-0035 [AV10][DOCS][S] One canonical `PUBLISHING.md` flow; delete divergent release notes. Proof: a single referenced release doc.
- KH-L-0036 [L2][SCANNER][M] Zero `TODO`/`FIXME`/`todo!()`/`unimplemented!()`/placeholder in shipped src (Law 2) — a gate enumerates current ones and drives them to zero. Proof: `no_stubs_in_src` gate at zero.
- KH-L-0037 [L2][SCANNER][L] Drive the panic surface to zero in non-test prod paths: audit every `.unwrap()`/`.expect()`/`panic!` on the scan hot path (see `PANIC_SURFACE_AUDIT_REPORT.md`). Proof: `no_unwrap_in_hot_path` gate, expanded beyond the GPU files.
- KH-L-0038 [ENG][CORE][M] Every error type carries context + a fix suggestion (Engineering Standards). Proof: an error-message lint/gate sampling each `Error` variant's Display.
- KH-L-0039 [ENG,L10][VERIFIER][M] Secrets never logged anywhere (tracing, errors, debug) — `RawMatch` Debug already redacts; extend the gate to every log site. Proof: `no_secret_in_logs` gate over all `tracing::`/`eprintln!`.
- KH-L-0040 [AV8][CORE][M] One re-export point per crate; minimal public surface — audit `pub use` (scanner has 35) for items that should be `pub(crate)`. Proof: `cargo public-api` baseline + a shrink.
