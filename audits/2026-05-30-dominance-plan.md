# Keyhog Dominance Audit

Date: 2026-05-30
Repo: `/media/mukund-thiru/SanthData/Santh/software/keyhog`
GPU probe: `NVIDIA GeForce RTX 5090, 32607 MiB, driver 570.211.01`
Status: active plan

## Execution Log

- 2026-05-30: Effective-config oracle wired into the real scan path; config files and explicit flags now resolve to the same operator-visible policy before scanning.
- 2026-05-30: Aggregate CLI fixture drift repaired for the inline `[u8; 32]` credential-hash contract.
- 2026-05-30: Git source audit found and fixed three production contract issues: default `--git-diff HEAD` now scans uncommitted worktree changes, `--git-staged --exclude-paths` cannot bypass excludes through the staged include list, and clean staged-mode tests now stage a real clean file instead of relying on whole-tree fallback.
- 2026-05-30: Dogfood example-suppression telemetry now deduplicates repeated detector/path/credential/reason events, and the pipeline batch-flush regression now proves exact static detector recall without arithmetic overflow from unrelated detector emissions.
- 2026-05-30: CLI source hygiene gate repaired by moving args, hook, and scan-system inline contracts into registered aggregate tests; scan-system redaction checks now assert the real raw hash bytes instead of stale fake hash strings.
- 2026-05-30: Structured named-detector recall audit found the generic UUID suppressor still firing under strong service anchors; the UUID gate is now bypassed only for strongly anchored detectors and remains active for generic/entropy UUID captures.
- 2026-05-30: Hot-pattern fast-path location mapping now uses the preprocessor's original-line map, preventing structured `.env` synthetic lines from surfacing as past-EOF additional locations.
- 2026-05-30: Scanner crate gate found stale `DetectorSpec::min_confidence` fixtures, an AVX-512 entropy parity gap on tiny/null-containing inputs, and residual weak-anchor misclassification for reviewed service-specific 32/40-hex API-key detectors; each is now wired into tests and detector data.
- 2026-05-30: CI Action contract suite now parses every committed GitHub workflow plus the composite Action manifest, and asserts the manifest remains a composite action with executable steps instead of relying only on text grep.
- 2026-05-30: CI workflow contracts now prove every committed workflow has a name, trigger, jobs mapping, runner/reusable-workflow target, and executable step definitions so valid-but-dead workflow YAML cannot silently ship.
- 2026-05-30: Committed mirror benchmark report tables refreshed from current `benchmarks/results`; report-check proves README injection is byte-stable, and the current gap table now names private-key recall as the largest competitor delta.
- 2026-05-30: Private-key benchmark gap traced to scorer normalization, not scanner recall: KeyHog emitted duplicate PEM appearances as `additional_locations`, while the adapter scored only the primary location. The adapter now expands those aliases, mirror private-key F1 is 1.000, and overall mirror F1 is 0.9108.
- 2026-05-30: Generic-high-entropy gap audit found BetterLeaks' category win comes with broad false-positive cost outside that category (overall precision 0.231). Gap reporting now includes competitor overall precision so category deltas cannot hide precision regressions.
- 2026-05-30: Composite Action artifact uploads now include the GitHub job id and scan duration in the artifact name, preventing the default `keyhog-report` name from colliding in common matrix CI layouts.
- 2026-05-30: SSH/TLS PEM private-key detector now captures full BEGIN/END blocks with paired algorithm boundaries, and the homoglyph alternation compiler preserves branch-local suffixes instead of creating header-only fallback regexes. Regression coverage proves header-only PEM markers stay silent and two distinct EC keys remain two credential-dedup findings.
- 2026-05-30: GPU backend self-test was run on the RTX 5090 host without `KEYHOG_NO_GPU`: MoE passed, `vyre_literal_set` reported the known subgroup lowering limitation, and `vyre_ac_kernel` failed on degenerate match triples before degrading to SIMD/CPU. Superseded 2026-05-31 by the bound-atomic AC builder: the same RTX 5090 JSON self-test now reports `vyre_ac_kernel=pass`.

## Dominance Contract

Keyhog dominates Betterleaks, Titus, Nosey Parker, and Kingfisher only when every gate in this file passes against pinned competitor builds and current Keyhog source. Dominance is measured, not claimed.

Required end state:

- Keyhog is first on aggregate F1, recall, precision, runtime, peak RSS, and operator time-to-triage across the shared benchmark matrix.
- Keyhog has no source, artifact, validation, revocation, report, or extension surface where any named competitor has a working public feature and Keyhog has none.
- Keyhog output is more actionable: each finding includes rule, credential identity, file/line/offset, provenance, confidence, validation result, blast radius where authorized, revocation command where supported, and stable fingerprint.
- Keyhog remains coherent: README, docs, `--help`, config, JSON, SARIF, HTML, tests, and benchmark artifacts agree at the same commit.
- The proof is committed as reproducible harness output, not notes.

## Evidence Checked

Competitor source clones in `/tmp/keyhog-competitors`:

- Betterleaks `93d973a`: CEL filters and validation, token-efficiency filter, GitHub API resource scanning, S3-compatible scanning, archive decoding, JSON/SARIF/CSV/JUnit/template reports.
- Titus `180f2b4`: CLI, Go library, Burp extension, Chrome extension, Vectorscan/Hyperscan, 497 counted YAML rule IDs, datastore, binary/document/container extraction, validation, 0-100 scoring.
- Nosey Parker `2e6e7f3`: Rust datastore workflow, Vectorscan, provenance model, Git/GitHub enumeration, 198 counted YAML rule IDs, rule example checks, JSON/JSONL/SARIF reporting.
- Kingfisher `c627cc5`: Rust scanner crates, 961 counted YAML rule IDs in source, README badge says 954 rules, broad platform sources, validation, revocation, access map, report viewer/importer, parser/context verification, library crates.

Keyhog source evidence:

- 894 detector TOMLs.
- 2917 Rust files under `crates`, including tests; 36,178 Rust LOC in production crates from the current checked command output.
- Latest visible SecretBench mirror result: `tools/secretbench/results/keyhog-v32-2026-05-29.json`, F1 0.8896, precision 0.9716, recall 0.8203, TP 2461, FP 72, FN 539.
- Existing benchmark adapters cover Keyhog, TruffleHog, Gitleaks, and Betterleaks in `tools/secretbench/scoring/score.py`; leaderboard evidence does not yet prove Titus, Nosey Parker, or Kingfisher dominance.
- Source adapters currently expose filesystem, stdin, git, git diff, git history, GitHub org, Slack, S3, Docker, binary, web, HAR, and compressed/archive handling under `crates/sources/src`.
- Current dirty tree is large. Treat it as shared work and do not revert unrelated changes.

## Competitor Map

### Betterleaks

What it does well:

- CEL is the real product differentiator. Global `prefilter` runs before regex over resource attributes; global/rule `filter` runs after regex over attributes plus finding data; `validate` can issue async HTTP and return structured status/metadata.
- Token-efficiency filtering uses BPE tokenization to reject natural-language false positives better than raw entropy.
- GitHub scanning covers repos, forks, PRs, PR comments, issue comments, actions, action artifacts, discussions, releases, release assets, and gists.
- S3 scanning is S3-compatible, not just AWS-specific.
- Config can translate older allowlist/entropy/token-efficiency fields into CEL.

What Keyhog must beat:

- CEL-level expressiveness without unbounded network or unsafe execution.
- Pre-regex source-aware filtering and post-regex finding-aware filtering.
- Betterleaks source breadth on GitHub resources and S3-compatible object stores.

### Titus

What it does well:

- Same engine powers CLI, Go library, Burp, Chrome, and WASM.
- Binary extraction explicitly includes Office, PDFs, Jupyter notebooks, SQLite, email, RTF, zip, tar, tar.gz, jar, war, ear, APK, IPA, CRX, XPI, and 7z.
- Docker/OCI image scanning does not require Docker daemon.
- Findings get numeric 0-100 score, severity, base score, modifiers, static accessibility context, and optional live scope scoring.
- Burp extension launches `titus serve` over NDJSON and gives a real appsec workflow, not only files.

What Keyhog must beat:

- Extension workflow coverage.
- Binary/document extraction breadth.
- Library and daemon embedding ergonomics.
- Risk scoring and scope scoring.

### Nosey Parker

What it does well:

- Datastore and provenance are first-class. Inputs become blobs; blobs have provenance; findings group matches and appearances.
- Dedup by shared secret reduces review load by 10x to 1000x in the public claim.
- Vectorscan byte matching and scratch reuse are simple and fast.
- Rules are checked against examples and negative examples by a dedicated command.

What Keyhog must beat:

- Provenance fidelity across files, git history, cloud APIs, archives, and synthetic decoded chunks.
- Review grouping and deterministic dedup.
- Rules with mandatory examples, negative examples, and regression replay.

### Kingfisher

What it does well:

- Broadest source list: files, local git, GitHub, GitLab, Azure Repos, Bitbucket, Gitea, Hugging Face, Jira, Confluence, Slack, Teams, Postman, Docker, AWS S3, and GCS.
- 954 to 961 public rule count depending on README vs source count.
- Validation, direct revocation, and access-map/blast-radius are central.
- Viewer imports Kingfisher, Gitleaks, and TruffleHog reports, dedups, enriches, and visualizes blast radius.
- Parser/context verification, SQLite scanning, Python bytecode scanning, compressed files, library crates, and deployment docs are all present.

What Keyhog must beat:

- Source coverage and integrations.
- Access map provider coverage.
- Viewer/importer and triage UX.
- Rule count and rule quality.
- Parser-based context verification.

## Current Keyhog Position

Strengths:

- Detector corpus is already close to Kingfisher scale at 894 TOMLs.
- Scanner has serious high-performance architecture: Hyperscan/SIMD, GPU routing, megascan/rule pipeline, AC gates, fallback paths, multiline reconstruction, decode-through scanning, BLAKE3 Merkle skip, daemon/watch/system scan.
- Security posture is stronger than most peers in several places: SSRF gates, DNS pinning, redirect revalidation, proxy coherency, OOB validation, hardening, coredump/ptrace controls, redaction discipline, archive bomb guards, symlink/path traversal tests.
- Test surface is large and adversarial by default.
- README already claims strong benchmark performance near Betterleaks on SecretBench mirror.

Gaps:

- Benchmark proof is incomplete for Titus, Nosey Parker, and Kingfisher.
- Source coverage trails Kingfisher on enterprise platforms.
- Binary/document extraction trails Titus.
- Validation metadata is less actionable than Titus/Kingfisher scoring/access-map/revocation.
- Report viewer/importer is behind Kingfisher.
- Config and benchmark coherence are fragile enough to be called out in local backlog.
- Bloat is visible: large modules, repeated gates, public/internal leakage, and many tests that look generated rather than proving deep contracts.

## Vector Plan

### 1. SPEED

Competitor best:

- Nosey Parker is still the clean speed model: byte matching with Vectorscan, datastore dedup, and GB/s public claim.
- Titus uses Hyperscan/Vectorscan when available and pure-Go fallback for portability.
- Kingfisher uses multithreaded Hyperscan plus context gating.
- Betterleaks relies on RE2, AC keyword filtering, and parallel source traversal.

Keyhog current:

- Strongest raw speed asset is GPU plus SIMD, but proof is fragmented.
- `hw_probe/select.rs` routes GPU only when thresholds clear; local hardware has RTX 5090.
- `scan.rs` has coalesced phase 1, trigger bitmaps, fallback gating, high-entropy run admission, boundary scan, and no-hit optimizations.
- `filesystem.rs` streams walk plus reads through bounded channels and parallel workers.

Gaps:

- No pinned competitor runtime/RSS matrix for all four named peers.
- GPU path can silently vanish unless tests require it on known GPU hosts.
- Speed claims do not cover GitHub API resources, object stores, archives, binary/document extractors, viewer import, validation, and access maps.

Plan:

- Add `tools/secretbench/scoring` adapters for Titus, Nosey Parker, and Kingfisher; keep Betterleaks adapter current.
- Add perf suites for six workloads: tiny file fanout, large monorepo, git history, archives/binary/docs, cloud/API stream, and validation/access-map.
- Record process startup, warm daemon, CPU/SIMD, GPU, peak RSS, bytes/sec, findings/sec, and operator-visible first finding latency.
- Add `KEYHOG_REQUIRE_GPU=1` and known-host GPU allowlist for RTX 5090/4090/santhserver.
- Make reports include selected backend and bytes per backend.
- Keep the Vyre track pinned to measured gains: the workspace is already on current crates.io `vyre` 0.6.1, so performance innovation means upstreamable batch dispatch, multi-buffer residency, literal/regex kernel fusion, and zero-copy result compaction work against `vendor/vyre`/crates.io parity gates.

Dominance gate:

- Keyhog is fastest on at least five of six workloads and no worse than 10 percent behind on the sixth.
- Keyhog peak RSS is lower than or equal to the best competitor for equivalent source coverage, or the extra memory buys strictly more extracted inputs.
- GPU-required tests fail when a known GPU host routes CPU.

### 2. RESEARCH

Competitor best:

- Betterleaks: CEL and token-efficiency research applied to FP reduction.
- Titus: Vectorscan engine shared across CLI/library/extensions plus risk scoring.
- Nosey Parker: provenance and dedup model from engagements.
- Kingfisher: parser/context verification, access maps, revocation, viewer import.

Keyhog current:

- Changelog and backlog show active benchmark-driven work, but peer research is not an automated loop.
- README mentions TruffleHog and Gitleaks more deeply than Titus/Nosey Parker/Kingfisher.

Gaps:

- No repeatable competitor source/issues scrape that turns peer features into tests.
- No "peer capability manifest" in the repo.

Plan:

- Add `tools/competitors/manifest.toml` with pinned repos, commits, release binaries, commands, supported sources, extractors, validators, reports, and known unsafe behaviors.
- Add a source scanner that reads competitor rule/source trees and emits a diffable capability table.
- Add tests that fail when a competitor has a feature Keyhog lacks, unless Keyhog has a measured reason not to ship it.
- Build rule ingestion experiments from Betterleaks/Titus/Nosey/Kingfisher rule corpora into a normalized intermediate schema.

Dominance gate:

- Every public competitor feature in the manifest maps to `implemented`, `rejected-with-proof`, or `superseded-by-keyhog`.
- `rejected-with-proof` requires a failing competitor safety/quality case plus a Keyhog alternative.

### 3. CAPABILITY

Competitor best:

- Kingfisher source breadth.
- Titus binary/document and extension workflow.
- Betterleaks GitHub resource depth and CEL validation.
- Nosey Parker datastore/provenance.

Keyhog current:

- Filesystem, git modes, Docker, S3, GitHub org, Slack, web JS/source maps/WASM, HAR, binary strings/Ghidra/sections, system scan.

Gaps:

- Missing or incomplete: GitLab, Azure Repos, Bitbucket, Gitea, Hugging Face, Jira, Confluence, Teams, Postman, GCS, Azure Blob, R2-first docs, CI artifacts/logs, package registries, browser extension, Burp extension, Office/PDF/Jupyter/SQLite/email/RTF/7z/XPI.

Plan:

- Create one source contract: `Source -> Artifact -> Provenance -> Chunk`, with auth, pagination, retries, rate limits, redaction, and SSRF policy shared.
- Implement missing source adapters in this order by dependency reuse:
  1. Git platforms: GitLab, Bitbucket, Azure Repos, Gitea, Hugging Face.
  2. Object stores: GCS, Azure Blob, R2 profile on S3-compatible path.
  3. Work systems: Jira, Confluence, Slack full search/files, Teams, Postman.
  4. CI systems: GitHub Actions logs/artifacts, GitLab CI, Buildkite, Jenkins.
  5. Appsec feeds: Burp NDJSON, browser extension feed, HAR bundles.
- Implement extractor matrix in `keyhog-sources` with per-format bomb/traversal tests: Office, PDF, Jupyter, SQLite, email/RTF, 7z, xpi, crx, ipa, apk, war, ear, pyc/pyo.

Dominance gate:

- Keyhog supports every named Kingfisher source plus Titus binary/document formats plus Betterleaks GitHub resource types.
- Each adapter has e2e test, auth-redaction test, pagination test, retry/rate-limit test, and adversarial abuse test.

### 4. INNOVATION

Competitor best:

- Kingfisher access-map/viewer is the current product advantage.
- Betterleaks CEL is the current rule-authoring advantage.
- Titus extension coverage is the current appsec workflow advantage.

Keyhog opportunity:

- Keyhog can combine GPU scanning, OOB verification, local hardening, real system scan, and source-wide provenance into one advantage none of the four has together.

Plan:

- Ship a "credential graph" core: every finding becomes an edge from secret identity to source artifact, validation evidence, permissions, owners, commits, channels, buckets, repos, and revocation action.
- Make `keyhog triage` a local viewer/importer that reads Keyhog, Gitleaks, TruffleHog, Betterleaks, Titus, Nosey Parker, and Kingfisher outputs.
- Add OOB-aware impact: webhook/callback credentials get callback proof in the graph.
- Add "blast-radius dry run" policy: enumerate permissions only when authorized flags and provider credentials are present; report skipped provider safely otherwise.
- Add one-command migration: `keyhog import-config --from gitleaks|betterleaks|titus|nosey|kingfisher`.

Dominance gate:

- A security engineer can scan, validate, view, prioritize, revoke, and export a ticket from Keyhog without switching tools.
- Imported competitor findings are deduped and enriched by Keyhog validation/access-map when Keyhog can verify them.

### 5. INSUFFICIENCY

Competitor best:

- Nosey Parker's rule examples and datastore force behavior to be inspectable.
- Titus/Kingfisher list capability surfaces loudly and wire them into commands.

Keyhog current:

- Large backlog already flags half-wired config, dead fields, benchmark drift, suppressions, and module bloat.
- `README.md` claims many capabilities that need byte-level contract tests.

Gaps:

- Generated adversarial suites are broad but can hide thin assertions.
- Some tests are gates for file size or no unwrap rather than behavior.
- Plan/audit scratch can bleed into product repo if not controlled.

Plan:

- Add `tools/audit/find_insufficient.py` scanning for dead CLI flags, config fields with no read path, public symbols not used in non-test code, detectors without contracts, docs claims without tests, and benchmark claims without artifacts.
- Convert each README claim into `tests/docs/claims/*.toml` with command, expected exit, expected output bytes/schema, and source path.
- Replace pure shape tests with proving tests that assert detector id, credential, file, line, confidence, verification, exit code, and output bytes.

Dominance gate:

- Zero shipped claims lack a proving test.
- Zero detector TOMLs lack positive, negative, and adversarial fixtures.
- Zero public config/CLI fields are unused by non-test paths.

### 6. GENERALIZATION

Competitor best:

- Betterleaks turns old allowlist and token-efficiency concepts into CEL programs.
- Kingfisher uses YAML rules with validation/revocation/access-map fields.
- Titus uses YAML rules plus separate validators/scorers.

Keyhog current:

- Detector TOMLs are broad and data-driven, but some known prefixes, keywords, suppression signals, and source/extractor behaviors are still code-heavy.

Gaps:

- Rule-time contextual logic is weaker than Betterleaks CEL.
- Provider scoring/revocation/access-map data is not uniformly modeled in detectors.

Plan:

- Define `keyhog_rule_v2.toml`: pattern, keywords, examples, negative examples, context filters, token-efficiency, checksum validation, live validation, revocation, access-map provider, confidence priors, client-safe/public-by-design tags.
- Add a safe expression evaluator with no shell, bounded CPU, bounded memory, no ambient network, explicit functions only, and static linting.
- Move keyword lists, client-safe lists, public demo suppressions, provider endpoints, and revocation docs into Tier B data files.
- Build importers from Betterleaks TOML/CEL, Titus YAML, Nosey Parker YAML, and Kingfisher YAML into v2 with loss report.

Dominance gate:

- 100 percent of detectors load through one schema.
- 95 percent or more of competitor rules import automatically; remaining loss is named and tested.
- No hardcoded provider lists remain outside generated Tier B data or tiny bootstrap constants.

### 7. DEDUPLICATION

Competitor best:

- Nosey Parker's shared-secret grouping is the benchmark for reducing review burden.
- Titus cross-rule dedup prefers richer/validator-bearing rules.
- Kingfisher viewer dedups imported reports by secret identity/fingerprint.

Keyhog current:

- `keyhog_core::dedup_matches`, `DedupScope`, cross-detector dedup, `additional_locations`, and baseline support exist.

Gaps:

- Dedup identity is not yet a cross-tool, cross-source credential graph primitive.
- Decoded/synthetic chunks, archives, git commits, and cloud records need deterministic provenance-preserving grouping.

Plan:

- Create one credential identity primitive: normalized secret bytes, detector family, provider identity, checksum hints, public-key pairing, and redacted display.
- Make dedup choose the highest-evidence finding: live verified, richer companion captures, provider-specific detector, higher confidence, better provenance.
- Add import dedup for Gitleaks, TruffleHog, Betterleaks, Titus, Nosey Parker, and Kingfisher.
- Store every secondary location and provenance edge, never drop evidence.

Dominance gate:

- Same corpus scanned through filesystem, git history, archive, and imported reports yields the same credential groups.
- Keyhog emits fewer review rows than each competitor while retaining all unique secrets and all provenance.

### 8. ARCHITECTURE

Competitor best:

- Titus has an embeddable core used by CLI/Burp/Chrome/WASM.
- Kingfisher has separate core/rules/scanner crates.
- Nosey Parker separates enumerator, rules, datastore, matcher.

Keyhog current:

- Crates exist (`core`, `scanner`, `sources`, `verifier`, `cli`), but internal modules leak and several files exceed 500 LOC.
- `CompiledScanner` still mixes engine state, GPU state, indexes, config, and fallback plumbing.

Gaps:

- No single boundary for extraction vs chunking vs scanning vs scoring vs verification vs reporting.
- Public API is not minimal enough for stable bindings.

Plan:

- Define seven stable boundaries:
  1. `keyhog-source`: source adapters and artifact streams.
  2. `keyhog-extract`: archives, binary/docs, compression, strings, structured formats.
  3. `keyhog-normalize`: decode, unicode, multiline, language context.
  4. `keyhog-detect`: compiled rule engine and candidate generation.
  5. `keyhog-score`: confidence, suppression, dedup, client-safe, calibration.
  6. `keyhog-impact`: verification, OOB, revocation, access-map.
  7. `keyhog-report`: JSON/SARIF/CSV/JUnit/HTML/viewer imports.
- Keep CLI as orchestration only.
- Add stable Rust facade, C ABI, Go binding, Python binding, and NDJSON daemon API.
- Split every production file over 500 LOC by ownership.

Dominance gate:

- Extension, CLI, daemon, library, and benchmark all call the same facade.
- No domain crate imports CLI/UI.
- Public symbols are documented and used by non-test paths or hidden.

### 9. WIRING

Competitor best:

- Betterleaks compiles CEL into executable filters/validators.
- Titus routes rules to scanner, validator, scorer, extensions, and reports.
- Kingfisher routes validate/revoke/access-map into CLI and viewer.

Keyhog current:

- Many important wiring fixes have happened recently: proxy to verifier/OOB, resolved config, `--print-effective-config`, embedded detectors, GitHub/S3/web flags, backend override.

Gaps:

- Backlog says config was drifting across core/scanner/CLI/benchmark.
- Source adapters and extraction flags must surface in report provenance and e2e tests.

Plan:

- Every flag/config/env var gets a contract test that proves it changes operator-visible behavior.
- Add `effective_config` and `source_manifest` blocks to JSON/SARIF/HTML and benchmark artifacts.
- Add a wiring matrix generated from clap args, config structs, env vars, and docs.
- Fail CI when a documented option lacks a non-test read path or report trace.

Dominance gate:

- For every user-visible option: default test, override test, config-file test, env test where applicable, conflict test, docs claim test.
- Benchmark result includes exact effective config and source/extractor manifest.

### 10. COHERENCE

Competitor best:

- Nosey Parker docs and generated manpages align with commands.
- Kingfisher docs are broad and map features to commands.
- Titus README makes interface promises that are wired into code.

Keyhog current:

- README is polished but contains claims that must be byte-checked.
- Changelog is dense and useful, but source-of-truth risk is high.

Gaps:

- README table currently compares against Betterleaks/Titus in a way the checked leaderboard artifacts do not fully reproduce.
- Docs/help/bench config can drift.

Plan:

- Generate detector count, source list, output format list, feature flags, and benchmark table from current code/artifacts.
- Move hand-authored competitive claims behind generated snippets or checked fixtures.
- Add `keyhog doctor --self-test --json` as the canonical health proof used by install docs.
- Add docs snapshots for every subcommand and output format.

Dominance gate:

- No README/docs benchmark number exists without a matching JSON artifact hash.
- `--help` snapshots, docs examples, and actual exit codes match.
- Detector count badge is generated from embedded detector corpus.

### 11. UTILIZATION

Competitor best:

- Titus uses same engine across multiple interfaces.
- Kingfisher's validation/access-map data reaches reports/viewer.

Keyhog current:

- Multiple public/testing hooks and computed states exist; some may be one-path-only.
- `CsrU32` is now adopted for the scanner hot index maps; continue checking for other half-wired computed state.

Gaps:

- Dead public API and partially adopted optimizations create bloat.
- Some tests validate existence rather than production use.

Plan:

- Add `cargo public-api` or local rustdoc JSON scan for public symbol inventory.
- Add `rg`/AST-based utilization audit for public functions, config fields, constants, and computed metadata.
- Require a non-test path for every public symbol except documented semver API and `testing`.
- Complete or delete partial optimizations.

Dominance gate:

- Utilization audit is clean.
- Every report field is either populated by at least one e2e path or removed from schema with migration.
- No "computed then unused" state exists on scanner hot path.

### 12. TESTING

Competitor best:

- Nosey Parker rules check examples/negative examples.
- Titus has extensive unit and integration tests around matcher, vectorscan, validators, scoring, extension pieces.
- Kingfisher has fuzz/testdata and broad feature docs.

Keyhog current:

- Very large adversarial suite and gates exist.
- Real-binary tests already protect `run_keyhog` and `run_trufflehog`; they need all named competitors.

Gaps:

- Generated breadth does not equal proving depth.
- Differential tests do not cover Titus/Nosey/Kingfisher.
- Source adapter/extractor pairs are not yet complete.

Plan:

- Add per-detector contract fixtures: positive, negative twin, adversarial/evasion, boundary, generated property cases, CVE/public replay where relevant.
- Add module-pair tests: source to extractor, extractor to chunk, chunk to scanner, scanner to suppression, suppression to confidence, confidence to reporter, scanner to verifier.
- Add differential matrix against Betterleaks/Titus/Nosey Parker/Kingfisher for detector families and source/extractor surfaces.
- Add property tests at 10k cases for confidence monotonicity, redaction non-leakage, dedup determinism, decode boundedness, path traversal, zip bombs, and SSRF.
- Add criterion perf gates for hot paths and source/extractor throughput.

Dominance gate:

- Failing detector contract is a finding, not an ignored fixture.
- Every competitor disagreement is classified and tracked until Keyhog wins or has a documented safety reason.
- Test report names coverage by behavior, not only file count.

### 13. DOGFOODING

Competitor best:

- Nosey Parker/Titus are engagement-shaped tools.
- Kingfisher viewer is designed for triage across real reports.

Keyhog current:

- `scan-system`, `doctor`, `watch`, `daemon`, `tui`, and SecretBench already make Keyhog dogfoodable.

Gaps:

- Dogfood findings are not yet a required loop with filed findings, fixes, and reruns across all sources.
- System scan output lacks the triage graph and viewer workflow needed for very large findings sets.

Plan:

- Run Keyhog on:
  - Keyhog repo, full git history, and generated artifacts.
  - Santh mounted tree with capped scan-system.
  - Competitor repos and their fixtures.
  - Local browser/HAR/appsec captures.
  - Container images and object-store test buckets.
- For every run, store findings/disagreements in a local dogfood ledger with source hash, config hash, scanner hash, and fix link.
- Add `keyhog dogfood replay` to rerun closed findings and verify they stay fixed.

Dominance gate:

- Every new capability is dogfooded on a real workflow before docs claim it.
- Regressions in dogfood replay fail CI or a named local gate.

### 14. INTROSPECTION

Competitor best:

- Betterleaks' CEL model exposes decisions through expressions.
- Kingfisher viewer exposes triage and access-map reasoning.

Keyhog current:

- `--dogfood`, `--print-effective-config`, telemetry hooks, backend selection, and suppression traces exist in parts.

Gaps:

- Operators need to know why a secret was found, suppressed, downgraded, grouped, validated, skipped, or routed CPU/GPU.
- Recurring gaps are not automatically rolled up into shared fixes.

Plan:

- Add `--explain-finding <fingerprint>` and `--trace-candidate` to show rule path, decode path, context, score components, suppression decisions, dedup winner, verifier path, and report output.
- Add `keyhog audit summarize` that clusters recent failures into shared causes: source gap, extractor gap, rule gap, scorer gap, verifier gap, reporter gap, docs gap.
- Emit structured decision traces in debug JSON with secrets redacted.

Dominance gate:

- Every false positive/false negative can be traced to one responsible subsystem.
- Batch audits produce shared root-cause fixes, not per-case patches.

### 15. AUDIT HUNTS

Competitor best:

- Keyhog already appears stronger than peers on SSRF/proxy hardening, but this must stay proven as surfaces expand.
- Titus browser extension weakens CSP/CORS during authorized testing; Keyhog must avoid making unsafe defaults look normal.

Keyhog current:

- Existing code covers many high-risk classes: redirect SSRF, DNS rebinding, userinfo redaction, proxy propagation, archive bombs, symlink archive paths, OOB consistency, reserved companion names, hardening, redaction, path traversal tests.

Gaps:

- New source adapters, extensions, extractors, validators, revokers, and viewer imports introduce the same bug classes again.

Plan:

- Add shared adversarial harness for:
  - OOM and decompression bombs.
  - Panics/unwraps on corrupt files.
  - TOCTOU, symlink races, traversal, zip slip, archive name encodings.
  - Arg injection, shell quoting, leading dash paths.
  - DNS rebinding, SSRF, proxy bypass, redirect-to-internal, metadata IPs.
  - CRLF/control injection, terminal escape injection, HTML/report XSS.
  - Weak crypto/RNG, constant-time gaps, credential redaction leaks.
  - Concurrent races, bounded queues, cancellation, timeouts.
  - Algorithmic DoS in regex, parsers, tokenizers, expressions, decoders.
  - Compatibility regressions on Linux, Windows, macOS, musl.
  - UX/perf failures: unreadable output, huge report hangs, viewer import blowups.
- Run the harness against Keyhog and competitor tools where possible to identify exploitable product gaps.

Dominance gate:

- Every new parser/source/verifier/revoker/viewer importer has adversarial tests for its relevant hunt classes.
- No security hardening regression is accepted to preserve speed or compatibility.

## Implementation Tracks

### Track A: Benchmark Proof

Files:

- `tools/secretbench/scoring/score.py`
- `tools/secretbench/scoring/leaderboard.py`
- `tools/secretbench/scoring/test_attribution.py`
- `tools/secretbench/results/`

Steps:

1. Add runner adapters for Titus, Nosey Parker, and Kingfisher.
2. Normalize schemas into one internal finding shape: scanner, detector/rule id, secret, file, line, offset, commit, verification, confidence, severity, metadata.
3. Pin install/build commands and binary digests.
4. Produce aggregate and per-category leaderboard for all named tools.
5. Emit disagreement reports: Keyhog-only TP, Keyhog-only FP, competitor-only TP, competitor-only FP, all-miss, all-hit.

Gate:

- Keyhog leads all named competitors by the dominance contract metrics.

### Track B: Source and Extractor Superset

Files:

- `crates/sources/src/`
- `crates/sources/tests/`
- `crates/cli/src/args/scan.rs`
- `crates/cli/src/subcommands/scan_system.rs`

Steps:

1. Freeze `Source -> Artifact -> Provenance -> Chunk` contract.
2. Add platform sources to match Kingfisher.
3. Add GitHub resource coverage to match Betterleaks.
4. Add binary/document/archive coverage to beat Titus.
5. Thread every source through CLI, config, JSON/SARIF/HTML provenance, and e2e tests.

Gate:

- Competitor capability manifest shows Keyhog source/extractor superset.

### Track C: Rule and Filter Superset

Files:

- `detectors/`
- `crates/core/src/spec*`
- `crates/scanner/tests/contracts/`
- `crates/scanner/tests/adversarial/`

Steps:

1. Define rule v2 schema.
2. Add token-efficiency signal.
3. Add safe expression filters and validators.
4. Import Betterleaks, Titus, Nosey Parker, and Kingfisher rules into staging.
5. Deduplicate and harden imported rules through mandatory examples and negative examples.

Gate:

- Keyhog has more active, tested, non-duplicate rules than Kingfisher and higher per-family recall than every competitor.

### Track D: Impact, Revocation, and Triage

Files:

- `crates/verifier/src/`
- `crates/core/src/report/`
- new `crates/impact/` or equivalent approved boundary
- new viewer/importer under product-owned path

Steps:

1. Extend verification result into evidence records.
2. Add provider access-map modules by highest-risk families first: AWS, GCP, Azure, GitHub, GitLab, Slack, Stripe, Jira, Bitbucket, Docker, Hugging Face, Postman.
3. Add revocation commands with dry-run, explicit confirmation, and audit log.
4. Add local triage viewer/importer for Keyhog and competitor outputs.
5. Export ticket-ready JSON and HTML.

Gate:

- Keyhog viewer/importer plus access-map/revocation beats Kingfisher's viewer and Titus scoring on actionability.

### Track E: Coherence and Bloat Removal

Files:

- `crates/*/src/`
- `README.md`
- `docs/`
- `tests/docs/`
- `.keyhog.toml.example`

Steps:

1. Resolve one canonical detection config and one report of effective config.
2. Generate docs snippets and benchmark tables from artifacts.
3. Split files over 500 LOC by responsibility.
4. Hide or remove unused public surfaces.
5. Add utilization and docs-claim gates.

Gate:

- No bloat-driven incoherence remains in the audited surfaces: every exposed knob, symbol, module, doc claim, and report field is wired and tested.

## Non-Negotiable Acceptance Matrix

| Area | Dominance proof |
| --- | --- |
| Accuracy | Keyhog F1 >= best named competitor + 0.05, recall >= best competitor, precision >= 0.97 |
| Speed | Keyhog fastest on 5 of 6 workload families, GPU-required tests pass on GPU hosts |
| Rules | Active tested rule count exceeds Kingfisher source count and imports peers with loss report |
| Sources | Keyhog supports all Kingfisher sources plus Betterleaks GitHub resources |
| Extractors | Keyhog supports all Titus document/binary/container formats plus adversarial tests |
| Validation | Keyhog validates at least every provider supported by Titus/Kingfisher/Betterleaks |
| Revocation | Keyhog supports direct revocation or exact dashboard/runbook command for every revocable high-risk provider |
| Access map | Keyhog maps blast radius for top cloud/SaaS credential families and viewer renders it |
| Triage | Keyhog imports/dedups/enriches reports from all named competitors plus Gitleaks/TruffleHog |
| Architecture | CLI, daemon, extensions, bindings, benchmark, and tests share one facade |
| Coherence | Generated docs/help/benchmark/config artifacts agree at one commit |
| Safety | Audit-hunt harness passes for every new source/extractor/verifier/revoker/viewer importer |

## First Patch Set

1. Extend `tools/secretbench/scoring` for Titus, Nosey Parker, and Kingfisher.
2. Add competitor manifest with pinned clones, commits, commands, features, and output schemas.
3. Add `KEYHOG_REQUIRE_GPU=1` route gate and backend trace in benchmark output.
4. Add rule v2 design skeleton plus import-loss report command for all four peer rule formats.
5. Add source capability manifest generated from Keyhog and competitor source lists.
6. Add docs-claim gate for README benchmark and source coverage claims.

This first patch set is the shortest path to stop guessing. It turns the dominance claim into a failing test suite and a measured competitor matrix, then the source/extractor/rule/impact work can land against concrete red rows until all gates are green.

## Executed Patch Set: Filesystem Hot Path

Date: 2026-05-30

Vector coverage:

- SPEED: removed a per-file Rayon yield from `process_entry`; the reader pool no longer pays scheduler overhead on every walked file.
- SPEED: compressed files now emit 8 MiB chunks through the source callback instead of collecting every decompressed chunk into a `Vec`.
- SPEED: archive entry path formatting is hoisted per archive, and binary archive decode no longer clones entry bytes before `String::from_utf8`.
- INSUFFICIENCY: `.zip` archive capability is now pinned as active behavior; the old test claimed zip was skipped.
- COHERENCE: stale source gates now track the split `filesystem/read/{bytes,mod,raw,window}.rs` layout.
- AUDIT HUNTS: symlink archive open, compressed input cap, mmap TOCTOU cap, and Unix `O_NOFOLLOW` gates now assert the current implementation locations.

Changed code/tests:

- `crates/sources/src/filesystem.rs`
- `crates/sources/tests/adversarial/nested_archive.rs`
- `crates/sources/tests/gap/archive_symlink_guard_in_source.rs`
- `crates/sources/tests/gap/compressed_input_uses_size_cap.rs`
- `crates/sources/tests/gap/mmap_toctou_sanity_cap_in_read.rs`
- `crates/sources/tests/gap/unix_open_no_follow_in_read.rs`

Verified gates:

- `cargo fmt -p keyhog-sources`
- `cargo check -p keyhog-sources`
- `cargo test -p keyhog-sources --all-features --lib filesystem::read`
- `cargo test -p keyhog-sources --all-features --test all_tests archive_symlink_guard_in_source -- --nocapture`
- `cargo test -p keyhog-sources --all-features --test all_tests compressed_input_uses_size_cap -- --nocapture`
- `cargo test -p keyhog-sources --all-features --test all_tests mmap_toctou_sanity_cap_in_read -- --nocapture`
- `cargo test -p keyhog-sources --all-features --test all_tests unix_open_no_follow_in_read -- --nocapture`
- `cargo test -p keyhog-sources --all-features --test all_tests zip_archive_inner_text_is_scanned_in_default_filesystem_walk -- --nocapture`
- `cargo test -p keyhog-sources --all-features --test all_tests gzip_member_secret_is_decompressed_to_chunk -- --nocapture`
- `cargo test -p keyhog-sources --all-features --test all_tests jar_binary_entry_extracts_printable_strings -- --nocapture`
- `cargo test -p keyhog-sources --all-features --test all_tests max_file_size_skips_oversize_plain_file -- --nocapture`
- `git diff --check`

Red gate captured:

- `cargo test -p keyhog-sources` fails because `crates/sources/tests/s3_ambient_credential_forward.rs` imports `keyhog_sources::s3` without enabling the `s3` feature.
- `cargo test -p keyhog-sources --all-features` reaches real tests, then fails on existing textual gates outside this patch batch and enters long HTTP property tests; the run was terminated after the failing set was captured and the process consumed about six CPU minutes with no new output.

## Executed Patch Set: Source Test Coherence

Date: 2026-05-30

Vector coverage:

- COHERENCE: source-crate no-inline-test gates now pass under default and all-features builds for every registered source gate.
- TESTING: moved filesystem path normalization, binary literal/section extraction, GitHub repo/clone validation, HTTP user-agent, and web SSRF/redaction/DNS-pin contracts into registered external tests.
- UTILIZATION: added a hidden `keyhog_sources::testing` facade so external tests can exercise internal contracts without leaving test modules embedded in production files.
- AUDIT HUNTS: fixed the oversize-file skip-counter assertion so parallel tests cannot turn another legitimate oversize skip into a false failure.

Changed code/tests:

- `crates/sources/src/lib.rs`
- `crates/sources/src/binary/{literals,mod,sections}.rs`
- `crates/sources/src/filesystem.rs`
- `crates/sources/src/github_org.rs`
- `crates/sources/src/http.rs`
- `crates/sources/src/web.rs`
- `crates/sources/tests/unit/internal_contracts.rs`
- `crates/sources/tests/unit/file_gate.rs`
- `crates/sources/tests/adversarial/max_file_size_skips_oversize_plain_file.rs`

Verified gates:

- `cargo fmt -p keyhog-sources`
- `cargo test -p keyhog-sources --test all_tests no_inline_tests -- --nocapture`
- `cargo test -p keyhog-sources --test all_tests no_unwrap_expect -- --nocapture`
- `cargo test -p keyhog-sources --test all_tests internal_contracts -- --nocapture`
- `cargo test -p keyhog-sources --all-features --test all_tests internal_contracts -- --nocapture`
- `cargo test -p keyhog-sources --all-features --test all_tests no_inline_tests -- --nocapture`
- `cargo test -p keyhog-sources --all-features --test all_tests no_unwrap_expect -- --nocapture`
- `cargo test -p keyhog-sources --test all_tests -- --skip property::http_fuzz --nocapture`
- `cargo test -p keyhog-sources --all-features --test all_tests -- --skip property::http_fuzz --nocapture`
- `cargo test -p keyhog-sources --lib`
- `git diff --check`

Remaining source-coherence findings surfaced by the green all-tests runs:

- None in the `keyhog-sources` aggregate gates after the filesystem split and property-gate fixes.

## Executed Patch Set: GitHub Org Split

Date: 2026-05-30

Vector coverage:

- ARCHITECTURE: split git-error redaction out of `github_org.rs` into `github_org/sanitize.rs`.
- COHERENCE: `github_org.rs` is now 488 lines and no longer emits the 500-line modularity warning in the source gates.

Verified gates:

- `cargo fmt -p keyhog-sources`
- `cargo test -p keyhog-sources --all-features --test all_tests github -- --nocapture`

## Executed Patch Set: Web SSRF Split

Date: 2026-05-30

Vector coverage:

- ARCHITECTURE: split URL redaction, host/IP denial, redirect revalidation, DNS screening, and pinned-client construction out of `web.rs` into `web/ssrf.rs`.
- COHERENCE: `web.rs` is now 411 lines and no longer emits the 500-line modularity warning in the source gates.
- AUDIT HUNTS: SSRF/DNS-rebinding contracts stay covered through the moved external web tests.

Verified gates:

- `cargo fmt -p keyhog-sources`
- `cargo test -p keyhog-sources --test all_tests web -- --nocapture`

## Executed Patch Set: Filesystem Source Split

Date: 2026-05-30

Vector coverage:

- ARCHITECTURE: split filesystem per-entry extraction into `filesystem/extract.rs` and walker/default-skip policy into `filesystem/filter.rs`.
- DEDUPLICATION: moved the read gate and walker extension checks to the same `SKIP_EXTENSIONS` source in `filesystem/filter.rs`.
- COHERENCE: `filesystem.rs` is now 324 lines, `filesystem/extract.rs` is 380 lines, and `filesystem/filter.rs` is 234 lines; the filesystem file-size/no-inline/no-unwrap gates now cover all three files.
- TESTING: registered the zip archive skip-list regression in `gap::mod`, so aggregate source tests now prove `.zip` reaches archive extraction instead of the extension denylist.

Verified gates:

- `cargo fmt -p keyhog-sources`
- `cargo test -p keyhog-sources --test all_tests filesystem -- --nocapture`
- `cargo test -p keyhog-sources --test all_tests gap:: -- --nocapture`
- `cargo test -p keyhog-sources --all-features --test all_tests filesystem -- --nocapture`
- `cargo test -p keyhog-sources --all-features --test all_tests gap:: -- --nocapture`
- `cargo test -p keyhog-sources --test all_tests -- --skip property::http_fuzz --nocapture`
- `cargo test -p keyhog-sources --all-features --test all_tests -- --skip property::http_fuzz --nocapture`
- `git diff --check`

## Executed Patch Set: Source Property Gates

Date: 2026-05-30

Vector coverage:

- TESTING: fixed HTTP property-test env isolation by locking and restoring `KEYHOG_PROXY` plus `KEYHOG_INSECURE_TLS` for every case that reads or writes HTTP env.
- TESTING: kept 10k-case HTTP policy properties and moved real reqwest builder/client properties to a bounded 256-case smoke profile.
- COHERENCE: removed the aggregate-gate `property::http_fuzz` skip; default and all-features `keyhog-sources` aggregate tests now run all registered source properties.
- COHERENCE: configured direct proptest regression files for HTTP and filesystem fuzz tests, removing the repeated SourceParallel persistence warning from aggregate source runs.

Verified gates:

- `cargo test -p keyhog-sources --all-features --test all_tests property::http_fuzz -- --nocapture`
- `cargo test -p keyhog-sources --test all_tests property:: -- --nocapture`
- `cargo test -p keyhog-sources --test all_tests -- --nocapture`
- `cargo test -p keyhog-sources --all-features --test all_tests -- --nocapture`
- `git diff --check`

## Executed Patch Set: Vyre Performance Innovation Lane

Date: 2026-05-30

Vector coverage:

- RESEARCH: verified the current published Vyre release through crates.io before changing the roadmap; the workspace pin is already at the latest `vyre = 0.6.1`.
- SPEED: clarified that the dominance path is fused GPU work, not detector breadth: require backend traces, keep sharded `GpuLiteralSet` as the floor, then fuse decode, literal matching, boundary extraction, entropy, and confidence prefeatures after parity.
- COHERENCE: updated `docs/vyre-usage.md` to stop claiming vendored `0.6.0`, path-dependency publish blockers, stale megakernel paths, or human-time shipping cadence.
- TESTING: added a scanner gap test that compares the root workspace Vyre pin to `docs/vyre-usage.md` and fails on stale "not on crates.io" / vendored `0.6.0` claims.
- COMPATIBILITY: fixed stale scanner `RawMatch` fixtures to use the production `[u8; 32]` credential-hash contract instead of string hashes.

Verified gates:

- `cargo search vyre --limit 10`
- `cargo fmt -p keyhog-scanner`
- `cargo test -p keyhog-scanner --test all_tests vyre_usage -- --nocapture`
- `cargo test -p keyhog-scanner --test all_tests resolution -- --nocapture`
- `cargo test -p keyhog-scanner --test all_tests record_window_match -- --nocapture`

## Executed Patch Set: Structured Parser Split

Date: 2026-05-30

Vector coverage:

- ARCHITECTURE: split `structured/parsers.rs` into `env`, `yaml`, `json`, `hcl`, and shared line-attribution modules with one re-export point.
- INSUFFICIENCY: moved the remaining inline parser contracts into `crates/scanner/tests/unit/inline_migrated/parsers_inline.rs` and enabled the standalone structured parser test module.
- COHERENCE: extended parser no-inline, no-unwrap, non-empty, and line-cap gates across the whole parser module tree instead of only the old monolith.
- TESTING: preserved parser contracts for env comments/quotes, HCL defaults/tfvars/block headers, k8s duplicate base64 line attribution, docker-compose recursion, tfstate recursion, and Jupyter array source attribution.

Verified gates:

- `cargo fmt -p keyhog-scanner`
- `cargo test -p keyhog-scanner --test all_tests structured_parsers -- --nocapture`
- `cargo test -p keyhog-scanner --test all_tests parsers_inline -- --nocapture`

## Executed Patch Set: Filesystem Reader Deadlock Fix

Date: 2026-05-30

Vector coverage:

- SPEED: fixed the large-tree scan hang by moving filesystem reader `par_bridge` work off the global Rayon pool used by scanner `par_iter`.
- ARCHITECTURE: kept source reading and scanner execution as separate scheduling domains; bounded-channel backpressure remains, but it can no longer starve the scanner workers that drain the channel.
- DOGFOODING: reran the real Linux kernel corpus scan with SIMD forced; the release binary completed in 93.52s wall, peak RSS 2.2GB, 22 findings, exit 1 for findings.
- INTROSPECTION: recorded the remaining scale bottlenecks in `backlog/performance.md`: GPU wait bounding, reader throughput, GPU phase2 cheap-reject parity, and runtime sizing.

Verified gates:

- `cargo test -p keyhog-sources --test all_tests filesystem -- --nocapture`
- `cargo test -p keyhog-sources --test all_tests gap:: -- --nocapture`
- `timeout 180s env KEYHOG_NO_GPU=1 /mnt/FlareTraining/santh-archive/cargo-target/release/keyhog scan --backend simd --no-daemon --format json --output /tmp/keyhog-kernel-scan.json /mnt/FlareTraining/santh-corpus/repos/linux`

## Executed Patch Set: GPU Phase2 Empty-Hit Fast Path

Date: 2026-05-30

Vector coverage:

- SPEED: GPU phase2 now skips `prepare_chunk`, `scan_prepared_with_pattern_hits`, and `post_process_matches` for empty-hit chunks that do not need fallback scanning.
- COHERENCE: the GPU no-hit admission policy now mirrors SIMD coalesced routing: multiline split-secret indicators, assignment keywords, known secret prefixes, or long entropy runs still route through fallback scanning.
- TESTING: added a scanner gap gate that proves the empty-hit check happens before `prepare_chunk` and keeps the keyword/entropy admission policy wired.
- AUDIT HUNTS: captured the forced-GPU red gate separately; at this checkpoint `KEYHOG_REQUIRE_GPU=1 cargo test -p keyhog-scanner --test gpu_parity gpu_and_simd_produce_identical_findings_on_same_corpus -- --nocapture` failed because runtime GPU dispatch degraded before parity assertions. Superseded 2026-05-31: the bound-atomic AC builder and strict-GPU guard fix make the RTX 5090 self-test and required-GPU parity pass.

Verified gates:

- `cargo fmt -p keyhog-scanner`
- `cargo test -p keyhog-scanner --test all_tests gpu_phase2_empty_hit_fast_path -- --nocapture`
- `/mnt/FlareTraining/santh-archive/cargo-target/debug/keyhog backend --self-test`

Red gate captured:

- `KEYHOG_REQUIRE_GPU=1 cargo test -p keyhog-scanner --test gpu_parity gpu_and_simd_produce_identical_findings_on_same_corpus -- --nocapture`

## Executed Patch Set: Composite Action CI Contract Harness

Date: 2026-05-31

Vector coverage:

- CI UX: moved the composite Action scan/count/summary path out of inline YAML into `.github/actions/keyhog/run-scan.sh`, so the production CI behavior is locally executable and covered by the CLI aggregate test target.
- COHERENCE: corrected the Action baseline producer docs to `keyhog scan --create-baseline`, documented the raw `exit-code` output, and kept Action metadata/README/summary fields aligned.
- WIRING: the Action now passes path, severity, format, verify, baseline, and output through env into one argv builder that preserves paths with spaces and exposes both finding count and raw scanner exit.
- AUDIT HUNTS: invalid `format`, `severity`, and `verify` fail before invoking `keyhog`; malformed clean reports and findings exits without reports fail closed; malformed findings reports are still treated as at least one finding; markdown summary cells escape pipes, backticks, and newlines.
- TESTING: added nine simulated-Action e2e contracts covering SARIF count, text count, malformed reports, missing reports, input validation, verify/baseline argv wiring, output propagation, and summary sanitization, plus a real-binary Action harness that scans a planted AWS key and parses the produced SARIF.
- SPEED / INNOVATION: kept Vyre work on the measured lane already captured in this audit: the workspace is pinned to crates.io `vyre` 0.6.1, so the next performance gain is fused GPU work and backend trace gates, not detector breadth or speculative dependency churn.

Verified gates:

- `bash -n .github/actions/keyhog/run-scan.sh`
- `cargo test -p keyhog --test all_tests action_ci_contract -- --nocapture`

## Executed Patch Set: Action Fail-Step Execution Contracts

Date: 2026-05-31

Vector coverage:

- CI UX: the composite Action's final fail shell block is now executed directly in the local contract suite, not only inspected as YAML text.
- COHERENCE: live verified credentials preserve `keyhog` exit 10 and ordinary finding failures preserve exit 1 with the operator-visible count/severity message.
- AUDIT HUNTS: malformed `exit-code` output is tested as workflow-command injection input and must fail closed without reflecting the untrusted value.

Verified gates:

- `bash -n .github/actions/keyhog/run-scan.sh`
- `cargo test -p keyhog --test all_tests action_ci_contract -- --nocapture`

## Executed Patch Set: Action Live-Credential Hard Fail

Date: 2026-05-31

Vector coverage:

- CI UX: `fail-on-findings: "false"` now means ordinary findings are advisory; verified-live credentials from `verify: "true"` still fail the composite Action after report/SARIF/artifact steps have a chance to run.
- COHERENCE: the Action README, input description, raw exit-code output, and fail step all preserve `keyhog` exit-10 semantics for live credentials.
- AUDIT HUNTS: the fail step validates the raw exit-code output through env before branching, so malformed output cannot be interpolated into shell or GitHub workflow commands.
- TESTING: added an Action manifest contract proving exit 10 bypasses advisory findings policy.

Verified gates:

- `bash -n .github/actions/keyhog/run-scan.sh`
- `cargo test -p keyhog --test all_tests action_ci_contract -- --nocapture`

## Executed Patch Set: GPU AC Cheap-Filter Whole-Chunk Confirmation

Date: 2026-05-31

Vector coverage:

- SPEED: keeps the AC cheap-filter bounded to one regex `is_match` per candidate pid while avoiding repeated window probes for the same pid.
- CAPABILITY: aligns GPU root confirmation with SIMD trigger semantics by evaluating detector regexes over the whole prepared chunk before precise extraction, preventing narrow-window misses for wider-context detector regexes; GPU phase-1 also ASCII-folds literals and coalesced haystacks so lowercase detector anchors match uppercase source occurrences the way Hyperscan's caseless path does.
- COHERENCE: the implementation now matches the existing code comments that described whole-chunk, position-independent confirmation.
- TESTING: the StackBlitz GPU recall narrow-window test ran but skipped its corpus-dependent assertion because the local bench corpus file is absent; added and ran a real-binary GPU/SIMD parity integration gate for far-offset and caseless literal-prefix regressions. Current full GPU self-test status is recorded in the required-GPU gate entry below.
- AUDIT HUNTS: the known forced-GPU synthetic parity gate still hard-fails before assertions with runtime GPU dispatch degradation, so the red gate remains recorded.

Verified gates:

- `/mnt/FlareTraining/santh-archive/cargo-target/debug/keyhog backend --self-test`
- `KEYHOG_REQUIRE_GPU=1 cargo test -p keyhog-scanner --test gpu_ac_recall_bug_56 gpu_ac_kernel_finds_stackblitz_token_in_narrow_window -- --nocapture`
- `cargo test -p keyhog --test gpu_simd_parity -- --nocapture`

Red gate captured:

- `KEYHOG_REQUIRE_GPU=1 cargo test -p keyhog-scanner --test gpu_parity gpu_and_simd_produce_identical_findings_on_same_corpus -- --nocapture`

## Executed Patch Set: Forced-GPU Hard-Fail Without Panic

Date: 2026-05-31

Vector coverage:

- AUDIT HUNTS: replaced the production `panic!` in the forced-GPU unavailable path with explicit stderr and exit code 2, matching the rest of the GPU hard-fail contract.
- COHERENCE: the doc comment now says the path exits instead of panicking.
- UX: `KEYHOG_BACKEND=gpu` on an unusable GPU stack reports `keyhog: ...` without a Rust panic backtrace.

Verified gates:

- `cargo test -p keyhog-scanner --test all_tests gpu_forced -- --nocapture`
- `cargo test -p keyhog --test gpu_simd_parity -- --nocapture`

## Executed Patch Set: CodeSandbox Enum False-Positive Kill

Date: 2026-05-31

Vector coverage:

- PRECISION: changed CodeSandbox token bodies from `[A-Za-z0-9_-]{20,}` to base62 `[A-Za-z0-9]{20,}`, preserving shipped positives while rejecting SCREAMING_SNAKE enum identifiers such as `CSB_MACHINE_STALLED_BY_CSB_MEMORY`.
- RESEARCH: checked current public CodeSandbox SDK/API-token references; public docs expose the token as `CSB_API_KEY` / API token but do not publish a character-level token grammar, so the detector contract follows the shipped positive corpus and the observed false-positive class.
- COHERENCE: added the negative to the detector contract so CPU/SIMD/GPU parity improvements cannot reintroduce the Linux-header false positive as a "valid" match.

Verified gates:

- `cargo test -p keyhog-scanner --test all_tests adv77_codesandbox_api_token_normal_must_fire -- --nocapture`
- `cargo test -p keyhog --test gpu_simd_parity -- --nocapture`
- Real CLI negative scan of `PERF_ENGG_CSB_MACHINE_STALLED_BY_CSB_MEMORY = 0x000000bd` produced `[]` with exit 0.

Red gate captured:

- `cargo test -p keyhog-scanner --test contracts_runner every_contract_passes_positives_negatives_evasions -- --nocapture` is red across many pre-existing detector contracts, so it is not a clean CodeSandbox-only proof gate.

## Executed Patch Set: EPA Contract Length Coherence

Date: 2026-05-31

Vector coverage:

- TESTING: corrected EPA contract positives/evasions from a 52-character value to a 40-character value matching the detector's documented `32-40` character API-key contract.
- COHERENCE: the fixture reason now matches the actual byte length being tested, so future contract failures point at detector behavior instead of stale generated fixture data.

Verified gates:

- `cargo test -p keyhog-scanner --test all_tests epa_api_key -- --nocapture`

## Executed Patch Set: GitHub Action CI Fail-Closed UX

Date: 2026-05-31

Vector coverage:

- COHERENCE: the composite Action no longer treats report parser failures as zero findings.
- CI UX: Action users now get a GitHub Step Summary with path, severity floor, format, report, finding count, exit code, and baseline.
- AUDIT HUNTS: if `keyhog` exits 1 or 10 but no report exists, the Action exits as a scanner failure instead of letting a subsequent `findings=0` path pass.
- TESTING: the entry-point integration gate now asserts fail-closed report counting and Step Summary wiring.

Verified gates:

- `bash tests/integration/entrypoints_check.sh`
- `python3 - <<'PY' ... yaml.safe_load(...) ... PY` for `.github/actions/keyhog/action.yml`, `.github/workflows/ci.yml`, and `.github/workflows/keyhog.yml`
- Extracted `.github/actions/keyhog/action.yml` `Run scan` block through `yaml.safe_load`, substituted GitHub expressions, and ran `bash -n`

## Executed Patch Set: Effective Config CI Oracle

Date: 2026-05-31

Vector coverage:

- COHERENCE: `KEYHOG_PRINT_EFFECTIVE_CONFIG=1` now reaches the real scan path and exits before source validation, giving CI a stable dump of the policy that would run.
- WIRING: scan construction now uses `resolve_scan_config` once, carries disabled detectors and lockdown requirements through the same resolved object, and stores the effective engine/post-process policy on `ScanOrchestrator`.
- INSUFFICIENCY: post-processing no longer re-derives confidence from raw args or bypasses the floor under `--no-ml`; it reads the resolved scanner floor.
- TESTING: added an e2e contract for source-free oracle output and config-file-vs-CLI byte identity.

Verified gates:

- `cargo build -p keyhog --bin keyhog`
- `KEYHOG_PRINT_EFFECTIVE_CONFIG=1 /mnt/FlareTraining/santh-archive/cargo-target/debug/keyhog scan --no-daemon`
- `KEYHOG_PRINT_EFFECTIVE_CONFIG=1 ... scan --config <tmp/.keyhog.toml>` byte-compared with equivalent explicit flags

Red gate captured:

- `cargo test -p keyhog --test all_tests scan_effective_config -- --nocapture` is blocked by unrelated aggregate-test compile errors in `crates/cli/tests/unit/{cli_misc,file_gate,baseline,daemon_wire}.rs` and missing `keyhog::benchmark::startup_summary`.

## Executed Patch Set: CLI Aggregate Test Compile Repair

Date: 2026-05-31

Vector coverage:

- CI UX: restored the `keyhog --test all_tests` compile path so filtered production CI gates can run instead of dying before test execution.
- COHERENCE: updated stale fixtures from string credential hashes to the shipped `[u8; 32]` contract and baseline hex serialization boundary.
- UTILIZATION: removed tests for the deleted duplicate `startup_summary` helper and pointed the benchmark surface checks at the retained `format_gpu_summary` API.
- TESTING: reran the effective-config aggregate filter plus the repaired baseline, inline suppression, daemon wire, benchmark, and orchestrator fixture tests.

Verified gates:

- `cargo test -p keyhog --test all_tests scan_effective_config -- --nocapture`
- `cargo test -p keyhog --test all_tests baseline_ -- --nocapture`
- `cargo test -p keyhog --test all_tests inline_suppression -- --nocapture`
- `cargo test -p keyhog --test all_tests daemon_scan_text_roundtrip_carries_matches -- --nocapture`
- `cargo test -p keyhog --test all_tests benchmark_happy -- --nocapture`
- `cargo test -p keyhog --test all_tests orchestrator_happy -- --nocapture`

## Executed Patch Set: Scanner Adversarial Recall/Precision Batch

Date: 2026-05-31

Vector coverage:

- SPEED: preserved hot-pattern substring validation on the fast path while adding a single next-byte boundary check for overlong known-prefix candidates.
- CAPABILITY: restored Discord bot-token standalone and cross-chunk recall for base64 snowflake prefixes above the old 10-59 route.
- TESTING: drove fixes from isolated adversarial failures, then widened to the first massive adversarial module.
- AUDIT HUNTS: fixed Unicode evasion gaps for C0 controls, combining marks, bidi isolates, line/paragraph separators, unusual Unicode spaces, and soft-hyphen separator impersonation.
- COHERENCE: kept detector quality gates green after splitting Discord prefix alternation under the 64-branch cap.

Verified gates:

- `cargo test -p keyhog-scanner --test all_detectors_self_validate -- --nocapture`
- `cargo test -p keyhog-scanner --test all_tests adversarial::massive_adversarial_suite::adv_discord_bot_token_normal_must_fire -- --nocapture`
- `cargo test -p keyhog-scanner --test all_tests adversarial::chunk_boundary::chunk_boundary_discord_bot_split_reassembled -- --nocapture`
- `cargo test -p keyhog-scanner --test all_tests adversarial::massive_adversarial_suite::adv_aws_access_key_too_long_must_silent -- --nocapture`
- `cargo test -p keyhog-scanner --test all_tests adversarial::massive_adversarial_suite_10::adv10_arbitrum_wrong_prefix_must_silent -- --nocapture`
- `cargo test -p keyhog-scanner --test all_tests adversarial::massive_adversarial_suite::adv_slack_bot_token_evade_soft_hyphen_dash_must_fire -- --nocapture`

Red gate captured:

- `cargo test -p keyhog-scanner --test all_tests adversarial::massive_adversarial_suite:: -- --nocapture` now passes 53/57. Remaining disagreements are bare Heroku UUID positives, Cyrillic `о` being correctly normalized to `o` and routed as `gho_`, and a Stripe chunk-boundary "near miss" whose length still satisfies the shipped Stripe detector.

## Executed Patch Set: GitHub Action CI Policy Hardening

Date: 2026-05-31

Vector coverage:

- WIRING: the composite Action now passes `fail-on-findings` and `upload-sarif` into the tested scan script, so typoed policy booleans fail before scanner invocation instead of silently weakening CI behavior.
- AUDIT HUNTS: GitHub workflow command messages now escape percent, CR, and LF in untrusted values, blocking newline command injection through action inputs and report paths.
- TESTING: the action contract covers malformed live-verification reports, policy boolean validation, workflow-command escaping, and manifest-to-script policy wiring.
- COHERENCE: CI summary output now records the resolved fail/upload policy alongside path, severity, format, report, findings, and scanner exit code.

Verified gates:

- `cargo test -p keyhog --test all_tests action_ -- --nocapture`

## Executed Patch Set: Composite Action Shell Interpolation Hardening

Date: 2026-05-31

Vector coverage:

- AUDIT HUNTS: user-controlled Action inputs are no longer interpolated directly into composite-action bash blocks; they enter through environment variables where shell syntax cannot be injected into the script body.
- WIRING: resolved `version`, `format`, report name, fail output, and download inputs now use explicit env names at the step boundary.
- COHERENCE: the version resolver validates release/ref characters before writing the single-line `version` output to `GITHUB_OUTPUT`.
- TESTING: manifest-level CI contracts reject `${{ inputs.* }}` and `${{ steps.* }}` inside `run:` blocks and lock the validated version output writer.

Verified gates:

- `cargo test -p keyhog --test all_tests action_ -- --nocapture`

## Executed Patch Set: Composite Action Rejection Message Hardening

Date: 2026-05-31

Vector coverage:

- AUDIT HUNTS: invalid `version` and invalid findings-output values are no longer reflected into GitHub workflow command bodies, closing the rejected-input newline injection path.
- COHERENCE: usage errors still explain the bad field without echoing attacker-controlled bytes.
- TESTING: action manifest contracts now reject reintroducing reflected invalid version or findings values.

Verified gates:

- `cargo test -p keyhog --test all_tests action_ -- --nocapture`

## Executed Patch Set: Release Workflow Tag Injection Hardening

Date: 2026-05-31

Vector coverage:

- AUDIT HUNTS: manual `workflow_dispatch` release tags are no longer interpolated directly into bash; every release job reads the tag from env, validates the `v` plus digit prefix, rejects shell metacharacters/control bytes, and writes `GITHUB_OUTPUT` with `printf`.
- WIRING: build, signing, container publish, and floating-major-tag jobs now share the same release-tag validation contract before checkout, release upload, signing, Docker tags, or git tag movement.
- COHERENCE: follow-up release shell steps receive the validated tag through `KEYHOG_RELEASE_TAG`, keeping release behavior aligned with the composite Action shell-input contract.
- TESTING: the action/CI contract now checks `release.yml` for raw `${{ inputs.tag }}` inside literal shell blocks and locks the validated output writer.

Verified gates:

- `cargo test -p keyhog --test all_tests action_ -- --nocapture`

## Executed Patch Set: Composite Action Release-Asset Verification

Date: 2026-05-31

Vector coverage:

- AUDIT HUNTS: the composite Action no longer executes a downloaded release binary unless the matching `.sha256` asset downloads and verifies; missing checksums fall back to a source build instead of silently trusting the binary.
- WIRING: the Linux prebuilt path now installs the Hyperscan/Vectorscan runtime before running the release asset, aligning the public Action path with the repo's previously separate dogfood workflow.
- DOGFOODING: `.github/workflows/keyhog.yml` now invokes `./.github/actions/keyhog` directly with strict-marker gating preserved, so the production Action path is exercised by KeyHog's own push/PR scanner.
- TESTING: action contracts now lock checksum verification, Linux runtime installation, local Action dogfooding, and env-based handling of Action outputs in the strict-marker shell step.

Verified gates:

- `cargo test -p keyhog --test all_tests action_ -- --nocapture`

## Executed Patch Set: Composite Action JSONL Fail-Closed Parsing

Date: 2026-05-31

Vector coverage:

- AUDIT HUNTS: JSONL report parsing no longer trusts raw line counts; blank lines are ignored and malformed clean JSONL now trips the same fail-closed report-parse path as SARIF/JSON.
- COHERENCE: `format=jsonl` now has the same report-integrity contract as `format=json` and `format=sarif` in the composite Action.
- TESTING: action contracts cover valid JSONL with blank lines and malformed clean JSONL.

Verified gates:

- `cargo test -p keyhog --test all_tests action_ -- --nocapture`

## Executed Patch Set: Degraded Batch Boundary Recall

Date: 2026-05-31

Vector coverage:

- CAPABILITY: GPU batch dispatch that degrades to CPU now still runs cross-chunk boundary reassembly, so credentials split across adjacent windows keep the same recall as normal CPU/SIMD batch paths.
- WIRING: the SIMD coalesced fallback used when the Hyperscan prefilter is unavailable also runs boundary reassembly after parallel per-chunk scanning.
- TESTING: scanner gap contracts reject removing boundary reassembly from either degraded batch branch.

Verified gates:

- `cargo test -p keyhog-scanner --test all_tests degraded_batch_paths_preserve_boundaries -- --nocapture`

## Executed Patch Set: GPU No-Hit Fallback Admission

Date: 2026-05-31

Vector coverage:

- CAPABILITY: GPU phase 2 no longer drops large chunks solely because literal/AC phase 1 found no hits; it now admits chunks whose production fallback active set is non-empty, preserving prefixless detector recall.
- COHERENCE: the GPU no-hit gate consults the same sparse fallback activation primitive used by CPU/SIMD fallback scanning instead of maintaining a separate keyword/size approximation.
- TESTING: scanner gap contracts lock the GPU no-hit admission path to the shared active-fallback probe.
- INNOVATION: correctness-first GPU routing creates the safe floor needed for fused literal/fallback GPU work without accepting fail-open acceleration.

Verified gates:

- `cargo test -p keyhog-scanner --test all_tests gpu_no_hit_fallback_admission -- --nocapture`

## Executed Patch Set: Azure Container Registry Hex-Constant Suppression

Date: 2026-05-31

Vector coverage:

- INSUFFICIENCY: the Azure Container Registry username pattern still treated C access-control register constants such as `ACR_USER 0x00000000` as credentials.
- COHERENCE: the detector now rejects `0x...` hex constants in the username capture while retaining the existing JWT and username contract positives.
- DOGFOODING: the targeted Linux kernel subset comparison identified this as a SIMD false positive rather than a GPU recall miss after the GPU fallback-admission fix.
- TESTING: the Azure Container Registry detector contract includes the exact `ACR_USER 0x00000000` negative shape.

Verified gates:

- `cargo test -p keyhog-scanner --test all_detectors_self_validate -- --nocapture`

## Executed Patch Set: GPU AC Recall Parity and Decode Attribution

Date: 2026-05-31

Vector coverage:

- SPEED: GPU phase 2 still uses the GPU hit list as the accelerator, but admitted chunks now union the canonical CPU AC trigger roots before extraction so the GPU path fails closed when the literal-set trigger set drifts.
- CAPABILITY: forced GPU scans of the targeted Linux subset now preserve the same five detector findings and source locations as forced SIMD after corrupt GPU AC triples degrade to the CPU/SIMD literal path.
- INSUFFICIENCY: GPU AC batches with impossible `end <= start` triples now degrade before chunk attribution instead of feeding corrupt ranges into phase 2.
- COHERENCE: decoded-source aliases no longer displace original file locations during dedup when both represent the same nearby credential.
- TESTING: wired the existing Caesar decode unit cases into the unified scanner harness and added guards for Kconfig/syscall-table paths, GPU AC degenerate triples, GPU phase-2 CPU-root union, and core decoded-alias dedup.
- DOGFOODING: reran the exact `/tmp/keyhog-gpu-divergence-subset` forced SIMD/GPU comparison and confirmed byte-identical sorted JSON output.

Verified gates:

- `cargo test -p keyhog-scanner --test all_tests a3_decode -- --nocapture`
- `cargo test -p keyhog-scanner --test all_tests gpu_ac_degenerate_triples_degrade -- --nocapture`
- `cargo test -p keyhog-scanner --test all_tests gpu_phase2_unions_cpu_ac_roots -- --nocapture`
- `cargo test -p keyhog-scanner --test all_tests gpu_no_hit_fallback_admission -- --nocapture`
- `cargo test -p keyhog-core --lib`
- `cargo test -p keyhog-core --test dedup_decoder_alias -- --nocapture`
- `cargo build --profile release-fast -p keyhog`
- `KEYHOG_NO_GPU=1 keyhog scan --backend simd --no-daemon --format json --output /tmp/keyhog-subset-simd.json /tmp/keyhog-gpu-divergence-subset`
- `KEYHOG_NO_GPU=0 keyhog scan --backend gpu --no-daemon --format json --output /tmp/keyhog-subset-gpu.json /tmp/keyhog-gpu-divergence-subset`
- `diff -u /tmp/keyhog-subset-simd.sorted.json /tmp/keyhog-subset-gpu.sorted.json`

## Executed Patch Set: Core Harness Hash Contract Closure

Date: 2026-05-31

Vector coverage:

- COHERENCE: the core unified harness now constructs `RawMatch` and `VerifiedFinding` with the production `[u8; 32]` credential-hash type instead of stale string hashes.
- WIRING: CSV, HTML, and JUnit reporter tests now live in the `tests/unit` harness rather than inline under `src/report/*`.
- TESTING: `keyhog-core --test all_tests` now runs 291 tests green after the hash-contract and reporter-test migration.

Verified gates:

- `cargo test -p keyhog-core --test all_tests -- --nocapture`

## Executed Patch Set: Sparse Fallback Activation

Date: 2026-05-31

Vector coverage:

- SPEED: the fallback scanner no longer scans a dense always-active bool table across every fallback detector for each admitted chunk; always-active seeds are precomputed as sparse indices.
- DEDUPLICATION: the active fallback path is now sparse end to end: precomputed always-active indices plus keyword-hit indices feed the same stamped dedup primitive.
- COHERENCE: the perf contract is locked with a gap test that rejects reintroducing a dense `Vec<bool>` always-active table on the hot path.
- INNOVATION: this is the KeyHog-side half of the Vyre/performance track: remove CPU fallback waste before pushing larger regex/literal fusion into the shared engine.

Verified gates:

- `cargo test -p keyhog-scanner --test all_tests fallback_always_active_sparse -- --nocapture`

## Executed Patch Set: CSR Hot Index Maps

Date: 2026-05-31

Vector coverage:

- SPEED: `prefix_propagation`, same-prefix siblings, fallback keyword routing, and SIMD Hyperscan dedup maps now use compact CSR storage instead of per-row heap allocations.
- UTILIZATION: the previously half-wired `CsrU32` hot-path optimization is now adopted by scanner state rather than sitting as dead internal code.
- ARCHITECTURE: scanner index-map storage is now one primitive with one row lookup contract, while external compiler builders can keep returning ordinary `Vec<Vec<usize>>`.
- TESTING: added a gap gate that locks the hot maps to `CsrU32` and rejects nested `Vec<Vec<usize>>` regression.

Verified gates:

- `cargo test -p keyhog-scanner --test all_tests csr_hot_maps_adopted -- --nocapture`

## Executed Patch Set: Fragment Cache Dead Hash Wrapper

Date: 2026-05-31

Vector coverage:

- UTILIZATION: removed the unused production `shard_index(&str)` wrapper; production fragment-cache routing now exposes only the allocation-free `(prefix, scope)` shard path.
- SPEED: the hot record path remains allocation-free for shard selection, and the equivalence test still proves the slice-pair hash matches the joined-key byte order.
- COHERENCE: the scanner warning for `shard_index` is gone instead of being hidden.

Verified gates:

- `cargo test -p keyhog-scanner shard_index_of_matches_joined_key_hash -- --nocapture`

## Executed Patch Set: GPU MoE Sigmoid Parity

Date: 2026-05-31

Vector coverage:

- CAPABILITY: GPU MoE confidence now uses the same rational sigmoid as CPU/SIMD scoring, so near-floor confidence decisions match the benchmarked path.
- COHERENCE: the shader comment, CPU scorer formula, tests, and changelog now agree that the rational activation is the shipped contract.
- TESTING: added external scanner unit tests that prove the true logistic diverges beyond the near-floor band and reject reintroducing the logistic shader formula.
- INNOVATION: this removes one reason benchmark scoring had to pin `KEYHOG_NO_GPU=1`, moving the GPU acceleration path closer to tuned-equals-shipped behavior.
- DOGFOODING: SecretBench scoring still defaults to deterministic CPU/SIMD, but now honors a caller-provided `KEYHOG_NO_GPU=0` so the canonical scorer can run the shipped GPU/auto path during parity checks.

Verified gates:

- `cargo test -p keyhog-scanner --test all_tests gpu_shader -- --nocapture`
- `python3 tools/secretbench/scoring/test_attribution.py`
- `python3 -m py_compile tools/secretbench/scoring/score.py`

## Executed Patch Set: GPU MoE Readback Deadline

Date: 2026-05-31

Vector coverage:

- SPEED: removed an unbounded GPU readback wait from the MoE confidence path so one stalled callback cannot pin a scan worker forever.
- UTILIZATION: `KEYHOG_GPU_MOE_TIMEOUT_MS` gives operators a bounded runtime knob while keeping the default desktop path GPU-accelerated.
- AUDIT HUNTS: replaced `device.poll(PollType::Wait)` and `receiver.recv()` with a deadline-bound `PollType::Poll` loop, nonblocking channel checks, and CPU MoE fallback on timeout, disconnect, poll error, or map error.
- COHERENCE: documented the new env var in the env reference, CLI reference, install docs, performance backlog, and changelog.

Verified gates:

- `cargo test -p keyhog-scanner --test all_tests gpu_moe_readback_uses_bounded_polling -- --nocapture`

## Executed Patch Set: Source-Level Large-File Parallelism

Date: 2026-05-31

Vector coverage:

- SPEED: lowered filesystem source windows from 64 MiB to 1 MiB so multi-MiB files become independent chunks before scanner batching and can occupy many rayon workers.
- COHERENCE: raised source overlap from 4 KiB to 128 KiB to match the scanner's own long-secret boundary contract.
- TESTING: added a default-path source integration gate proving a 1.2 MB text file emits multiple `filesystem/windowed` chunks with the expected base offsets.
- INTROSPECTION: this implements the L1 parallelism lever from PERF-08 while preserving the measured L2 literal/regex pass as a separate root cause in the performance backlog.

Verified gates:

- `cargo test -p keyhog-sources --test all_tests default_windowing_splits_multimegabyte_source_files -- --nocapture`
- `cargo test -p keyhog-sources --test all_tests windowed_path -- --nocapture`

## Executed Patch Set: Commented Config Assignment Recall

Date: 2026-05-31

Vector coverage:

- CAPABILITY: commented-out config assignments now retain assignment context, covering `# KEY=value`, `// token = value`, C block comments, and HTML comments around config lines.
- TESTING: added a context unit gate for commented assignment inference across shell, C/JS, block, and HTML comment syntaxes.
- INTROSPECTION: the full per-detector contract runner dropped from the broad commented-assignment evasion cluster to 26 remaining detector-specific failures.
- COHERENCE: bare prose comments still infer `Comment`; the change only lifts comment lines with assignment or mapping syntax after the comment marker.

Verified gates:

- `cargo test -p keyhog-scanner --test all_tests commented_assignment_context -- --nocapture`

Red gate captured:

- `cargo test -p keyhog-scanner --test contracts_runner every_contract_passes_positives_negatives_evasions -- --nocapture` remains red with 26 detector-specific failures after this shared-context fix.

## Executed Patch Set: Google OAuth Anchored Confidence

Date: 2026-05-31

Vector coverage:

- CAPABILITY: Google OAuth client IDs with the `.apps.googleusercontent.com` anchor no longer fall below the global confidence floor solely because their base62-ish body has low entropy.
- GENERALIZATION: the detector-local floor is justified by unique literal anchors rather than broadening global confidence policy.
- COHERENCE: documented the detector-specific floor rationale beside the detector patterns and in the changelog.

Verified gates:

- `cargo test -p keyhog-scanner --test all_detectors_self_validate -- --nocapture`

## Executed Patch Set: AWS Secret Anchored Confidence

Date: 2026-05-31

Vector coverage:

- CAPABILITY: anchored AWS secret-access-key assignments no longer fall below the global confidence floor solely because a valid 40-character body has moderate entropy.
- GENERALIZATION: this uses the detector-local reviewed floor path for strongly anchored service tokens instead of relaxing generic base64/hash suppression.
- COHERENCE: documented the mandatory anchor rationale in the detector and changelog.

Verified gates:

- `cargo test -p keyhog-scanner --test all_detectors_self_validate -- --nocapture`

## Executed Patch Set: Contract Runner Closure

Date: 2026-05-31

Vector coverage:

- CAPABILITY: restored every per-detector positive/evasion contract that was still failing after the shared commented-assignment fix.
- INSUFFICIENCY: fixed required-companion enforcement data for Avalara, Anthropic legacy lower-bound leakage, missing AWS session capture groups, Zendesk subdomain email/token shape, Alertmanager `USERNAME` alternation ordering, Azure OpenAI endpoint matching across lines, and short-prefix Pirsch routing.
- COHERENCE: corrected generated evasions that had stripped the service anchor down to a generic `secret` key, and replaced repeated synthetic positive bodies that were shaped like placeholders instead of plausible credentials.
- TESTING: the full per-detector contract runner is now green, and detector loading/quality validation stays green across all 894 TOML detectors.
- INTROSPECTION: SecretBench scoring now pins `KEYHOG_NO_GPU=1` so detector-floor experiments compare deterministic CPU/SIMD results instead of GPU MoE near-floor variance.

Verified gates:

- `cargo test -p keyhog-scanner --test all_detectors_self_validate -- --nocapture`
- `cargo test -p keyhog-scanner --test contracts_runner every_contract_passes_positives_negatives_evasions -- --nocapture`

## Executed Patch Set: Current-Thread CLI Runtime

Date: 2026-05-31

Vector coverage:

- SPEED: removed the default multi-thread Tokio runtime from plain CLI startup so filesystem scans do not carry an idle async worker pool beside the Rayon scanner/readers.
- ARCHITECTURE: scan parallelism remains owned by Rayon; async commands still run on Tokio without allocating one worker per core by default.
- TESTING: added a CLI gap gate that locks `#[tokio::main(flavor = "current_thread")]` into `main.rs`.

Verified gates:

- `cargo test -p keyhog --test all_tests main_uses_current_thread_tokio_runtime -- --nocapture`

## Executed Patch Set: Deterministic Floor Override Campaign

Date: 2026-05-31

Vector coverage:

- CAPABILITY: kept the deterministic SecretBench floor-override batch for strongly vendor-anchored detectors after `KEYHOG_NO_GPU=1` scoring removed GPU MoE near-floor variance from the measurement.
- RESEARCH: reconciled `score.py` and clean-negative FP analysis; the broad batch adds recall on label-positive fixtures while clean-negative false positives stay flat.
- COHERENCE: `backlog/detection.md`, detector TOML floors, and changelog now agree on the kept floor-override set.

Verified gates:

- `cargo test -p keyhog-scanner --test all_detectors_self_validate -- --nocapture`

## Executed Patch Set: Filesystem Reader Pool Sizing

Date: 2026-05-31

Vector coverage:

- SPEED: the filesystem producer still uses a dedicated reader pool to avoid reader/scanner deadlock, but the pool is now half the scanner pool with a 16-thread cap instead of a second full-size CPU pool.
- UTILIZATION: large-tree scans on 32-core hosts run 16 reader workers plus scanner workers instead of 32 reader workers competing with the scan pool.
- TESTING: added a source unit contract for the two-thread floor, half-pool sizing, and 16-thread cap.

Verified gates:

- `cargo test -p keyhog-sources --test all_tests filesystem_reader_pool_is_smaller_than_scan_pool_on_large_hosts -- --nocapture`

## Executed Patch Set: Vyre Roadmap Wording Cleanup

Date: 2026-05-31

Vector coverage:

- COHERENCE: removed stale handoff/session wording and human-time estimates from `docs/vyre-usage.md`; remaining Vyre work is described as concrete technical wires and parity gates.
- ARCHITECTURE: scanner comments now describe lazy regex/ML behavior without implying handoff or postponed ownership.

Verified gates:

- `cargo test -p keyhog-scanner --test all_tests vyre_usage -- --nocapture`

## Executed Measurement: AMD Include SIMD/CPU Remeasure

Date: 2026-05-31

Vector coverage:

- SPEED: remeasured the 467 MB Linux `drivers/gpu/drm/amd/include` workload after the windowing, current-thread runtime, and reader-pool sizing fixes.
- COHERENCE: updated `backlog/performance.md` so PERF-08 no longer relies on stale 5.56-6.86 s amd/include timings.
- TESTING: forced SIMD and forced CPU fallback emitted zero findings and byte-identical sorted JSON on the workload.

Verified commands:

- `/usr/bin/time -v env KEYHOG_NO_GPU=1 KEYHOG_BACKEND=simd keyhog scan --no-daemon --format json --output /tmp/keyhog-amd-include-simd.json /mnt/FlareTraining/santh-corpus/repos/linux/drivers/gpu/drm/amd/include`
- `/usr/bin/time -v env KEYHOG_NO_GPU=1 KEYHOG_BACKEND=cpu keyhog scan --no-daemon --format json --output /tmp/keyhog-amd-include-cpu.json /mnt/FlareTraining/santh-corpus/repos/linux/drivers/gpu/drm/amd/include`
- `diff -u /tmp/keyhog-amd-include-simd.sorted.json /tmp/keyhog-amd-include-cpu.sorted.json`

## Executed Measurement: Required-GPU Parity Gate Status

Date: 2026-05-31

Vector coverage:

- TESTING: reran the hard required-GPU parity gate after the AC recall and decode-attribution fixes.
- COHERENCE: recorded that the red gate is a runtime GPU dispatch degradation before assertions, not a SIMD/GPU finding-set mismatch.
- RESEARCH: the committed GPU route still fails before parity assertions, so the blocker remains in Vyre dispatch soundness.

Observed gates:

- `KEYHOG_REQUIRE_GPU=1 cargo test -p keyhog-scanner --test gpu_parity gpu_and_simd_produce_identical_findings_on_same_corpus -- --nocapture` exited 2 with `literals=true, backend=true, matcher=true` at this checkpoint; superseded 2026-05-31 by the strict-GPU guard fix.
- `cargo test -p keyhog-scanner --test gpu_parity gpu_and_simd_produce_identical_findings_on_same_corpus -- --nocapture` passed only by emitting the runtime GPU-degrade warning and falling back to SIMD/CPU at this checkpoint; superseded 2026-05-31 by required-GPU parity passing on the live RTX 5090.

## Executed Patch Set: Composite Action Missing-Report Gate

Date: 2026-05-31

Vector coverage:

- WIRING: the tested scan wrapper now treats every missing requested report as a CI failure, including `keyhog` exit 0, instead of publishing `findings=0` and relying on a subsequent artifact warning.
- SPEED: the wrapper emits `duration-ms` and records duration in the GitHub Step Summary so production CI runs can track scan cost without log scraping.
- TESTING: added e2e action contracts for clean-exit/missing-report failure and the duration output path.
- COHERENCE: updated the buildless integration entrypoint gate so it validates the composite manifest plus `run-scan.sh` instead of looking for moved scanner logic only in YAML.

Verified gates:

- `cargo test -p keyhog --test all_tests action_ci_contract -- --nocapture`
- `tests/integration/entrypoints_check.sh`
- `bash -n .github/actions/keyhog/run-scan.sh tests/integration/entrypoints_check.sh`

## Executed Patch Set: GPU Degrade Reason Propagation

Date: 2026-05-31

Vector coverage:

- INTROSPECTION: verified crates.io still publishes `vyre` 0.6.1 as the latest release, so the performance lane remains fixing dispatch soundness/fusion against the current API rather than bumping a dependency.
- COHERENCE: `KEYHOG_REQUIRE_GPU=1` hard-fail output and `backend --self-test` now preserve the concrete degrade reason when the AC path sees degenerate Vyre match triples.
- AUDIT HUNTS: the red RTX 5090 self-test still identifies the same Vyre CUDA AC corruption class, but the operator-facing warning no longer collapses it into a generic dispatch failure.

Observed commands:

- `cargo search vyre --limit 10`
- `RUST_LOG=keyhog::routing=debug timeout 90s /mnt/FlareTraining/santh-archive/cargo-target/debug/keyhog backend --self-test`

Verified gates:

- `cargo build -p keyhog`
- `cargo test -p keyhog-scanner --test all_tests gpu_ac_degenerate_triples_degrade -- --nocapture`

## Executed Patch Set: Fallback Active-Set Admission Short-Circuit

Date: 2026-05-31

Vector coverage:

- SPEED: GPU no-hit chunk admission now returns immediately when always-active fallback detectors or a missing fallback keyword prefilter make the active fallback set unconditional.
- DEDUPLICATION: the fast path stays inside the shared `has_active_fallback_patterns_for_chunk` primitive used by GPU phase 2, rather than adding a second approximation to the GPU path.
- TESTING: extended the sparse always-active fallback gate to lock in the unconditional-admission short-circuit.

Verified gates:

- `cargo test -p keyhog-scanner --test all_tests fallback_always_active_seed_is_sparse_not_dense_bool_scan -- --nocapture`

## Executed Patch Set: CI Guide Composite Action Alignment

Date: 2026-05-31

Vector coverage:

- COHERENCE: `docs/src/workflows/ci.md` now leads GitHub Actions users to the hardened composite Action instead of an older install-and-upload snippet that bypassed the tested wrapper.
- UX: the guide describes the report artifact, Code Scanning upload, job summary, raw exit code, finding count, duration, and baseline adoption path in the same terms as the Action README.

Verified gates:

- `rg -n "santhsecurity/keyhog/.github/actions/keyhog|duration|baseline" docs/src/workflows/ci.md`

## Executed Patch Set: Benchmark Contract Package

Date: 2026-05-31

Vector coverage:

- COHERENCE: replaced an incomplete benchmark package surface with tested schema, host, scoring, and corpus adapter commands; the Makefile no longer advertises missing runner/report modules.
- RESEARCH: the benchmark contract preserves SecretBench overlap scoring and adds corpus adapters for mirror, competitor homefield, CredData, and kernel performance measurements.
- TESTING: added Python package tests for `RunResult` round trips, zero-denominator metrics, base64/escape overlap, TP/FP/FN/ignore attribution, corpus loading, corpus resolution, and hardware JSON capture.

Verified gates:

- `cd benchmarks && python3 -m py_compile bench/*.py bench/corpora/*.py && python3 -m pytest -q bench/tests`
- `cd benchmarks && python3 -m bench host >/tmp/keyhog-bench-host.json && python3 -m bench corpus kernel >/tmp/keyhog-bench-kernel.json && python3 -m json.tool /tmp/keyhog-bench-host.json >/dev/null && python3 -m json.tool /tmp/keyhog-bench-kernel.json >/dev/null`

## Executed Patch Set: Benchmark Scanner Adapter Package

Date: 2026-05-31

Vector coverage:

- RESEARCH: added first-class benchmark adapters for Betterleaks, Kingfisher, Nosey Parker, Titus, and TruffleHog so dominance checks can run the installed competitor binaries through the same measured `Scanner` contract as Keyhog.
- WIRING: each adapter maps its real CLI, validation-off mode, JSON/JSONL report shape, datastore path, and unredacted output path into normalized `{file,line,value,detector}` findings plus wall/RSS/exit-code stats.
- COHERENCE: removed the duplicate `bench/scanners.py` module and kept one `bench.scanners` package, so Python import behavior cannot silently select the wrong adapter surface.
- TESTING: normalizer contracts now cover Keyhog, Betterleaks, Kingfisher JSONL, Nosey Parker report JSON, and Titus SQLite datastores; resolver tests lock the requested competitor names into measured scanner classes, and corpus tests prove the mirror scanner root excludes `manifest.jsonl`.
- AUDIT HUNTS: generated benchmark corpora are ignored because the mirror generator emits secret-shaped fixtures into `benchmarks/corpora/`, while source code and adapter contracts remain tracked.
- SPEED: corpus byte/file accounting now uses the same manifest-free `scan_root` that scanners receive, so throughput cannot be padded by answer-key bytes.

Verified gates:

- `cd benchmarks && python3 -m py_compile bench/*.py bench/corpora/*.py bench/scanners/*.py && python3 -m pytest -q bench/tests`
- Real-binary smoke through `resolve_scanner` over GitHub/AWS/Slack fixtures: Keyhog, Betterleaks, Nosey Parker, Titus, Kingfisher, and TruffleHog all invoked; Keyhog/Nosey/Titus flagged the GitHub sample, Betterleaks flagged the Slack sample, and Kingfisher/TruffleHog completed cleanly on the synthetic fixture set.

## Executed Patch Set: Benchmark RunResult Runner

Date: 2026-05-31

Vector coverage:

- WIRING: `python -m bench run <scanner> <corpus>` now binds scanner adapters, corpus adapters, scoring, host capture, throughput calculation, and JSON output into one artifact-producing path.
- COHERENCE: `make run` exposes the same entrypoint with `SCANNER`, `CORPUS`, and `OUTPUT` variables, and `RunResult` now serializes scanner `exit_code` plus `timed_out` instead of dropping measured process state.
- TESTING: runner tests cover scoring, throughput, JSON output round-trip, and mirror root mapping.
- DOGFOODING: ran the CLI runner on a tiny manifest-free mirror fixture with the real Keyhog binary and validated the JSON artifact.

Verified gates:

- `cd benchmarks && python3 -m py_compile bench/*.py bench/corpora/*.py bench/scanners/*.py && python3 -m pytest -q bench/tests`
- `cd benchmarks && python3 -m bench run keyhog mirror --corpus-root <tmp-fixture> --output /tmp/keyhog-bench-run.json && python3 -m json.tool /tmp/keyhog-bench-run.json >/dev/null`

## Executed Patch Set: Benchmark Measurement Portability

Date: 2026-05-31

Vector coverage:

- AUDIT HUNTS: benchmark subprocess measurement now verifies actual GNU `time` support before adding `-v -o`, preventing BSD/macOS `/usr/bin/time` from breaking every scanner row.
- SPEED: Linux keeps GNU peak-RSS capture when available; other hosts still produce wall time and best-effort RSS through `resource.getrusage`.
- TESTING: added a fallback-path unit test that forces GNU time unavailable and proves `run_measured` still captures stdout, exit code, wall time, and RSS.

Verified gates:

- `cd benchmarks && python3 -m py_compile bench/*.py bench/corpora/*.py bench/scanners/*.py && python3 -m pytest -q bench/tests`

## Executed Patch Set: GPU AC Degenerate Circuit Breaker

Date: 2026-05-31

Vector coverage:

- SPEED: after the first impossible Vyre AC readback, subsequent GPU AC batches in the process skip the known-corrupt dispatch and go straight to the SIMD/CPU recall-preserving path.
- AUDIT HUNTS: the circuit breaker keeps the existing fail-closed `end <= start` guard and makes the corruption sticky for process lifetime instead of rediscovering it batch by batch.
- TESTING: extended the scanner gap contract to require both the degenerate-triple guard and the process-level skip path.

Verified gates:

- `cargo test -p keyhog-scanner --test all_tests gpu_ac_degenerate_triples_degrade -- --nocapture`

## Executed Patch Set: Mirror Corpus Neutral Scan Root

Date: 2026-05-31

Vector coverage:

- COHERENCE: the mirror benchmark home is now `manifest.jsonl` beside a neutral `corpus/` scan tree, aligning docs, loader, generator, and tests around the same answer-key-free layout.
- RESEARCH: local dogfood showed path names like `fixtures/` suppress Keyhog confidence even under `--no-suppress-test-fixtures`, so the benchmark scan root now avoids scanner-specific test-context penalties.
- TESTING: added corpus tests for neutral scan roots, manifest exclusion, and migration of existing generated manifests out of the scan tree.
- INSUFFICIENCY: kept the established 15k-fixture mirror default (3k positives / 12k negatives) aligned with the generated README/report evidence.

Verified gates:

- `cd benchmarks && python3 -m py_compile bench/*.py bench/corpora/*.py bench/scanners/*.py && python3 -m pytest -q bench/tests`

## Executed Patch Set: Benchmark Exit-Code Contracts

Date: 2026-05-31

Vector coverage:

- WIRING: benchmark scanner adapters now expose accepted exit codes, and the runner marks unexpected scanner exits as `RunResult.error` instead of treating them as clean empty-result rows.
- COHERENCE: Keyhog's findings exits (`1`, `10`) are accepted as completed scans, while Betterleaks and other competitor adapters keep the default clean-exit-only contract unless explicitly widened.
- TESTING: added unit coverage for scanner exit contracts and reran the benchmark package gate.

Verified gates:

- `cd benchmarks && python3 -m py_compile bench/*.py bench/corpora/*.py bench/scanners/*.py && python3 -m pytest -q bench/tests`

## Executed Patch Set: Homefield Corpus Neutral Scan Root

Date: 2026-05-31

Vector coverage:

- COHERENCE: competitor homefield corpora now follow the same `manifest.jsonl` beside neutral `corpus/` scan-tree contract as mirror.
- TESTING: added a homefield corpus test proving scanners see only the neutral scan tree and not the answer key.

Verified gates:

- `cd benchmarks && python3 -m py_compile bench/*.py bench/corpora/*.py bench/scanners/*.py && python3 -m pytest -q bench/tests`

## Executed Patch Set: Benchmark Leaderboard Matrix

Date: 2026-05-31

Vector coverage:

- WIRING: added `python -m bench leaderboard` and `make leaderboard` so the benchmark harness can emit one `RunResult` JSON artifact per scanner/config row instead of only one manual run at a time.
- RESEARCH: the default matrix includes Keyhog, Betterleaks, Kingfisher, Nosey Parker, TruffleHog, and Titus.
- COHERENCE: leaderboard rows reuse the same corpus resolver, manifest-free scan root, scorer, output writer, and scanner exit-code contracts as `bench run`.
- TESTING: added leaderboard tests for default competitor coverage and unexpected-exit artifact errors, then dogfooded the CLI on an empty kernel corpus rooted at a temporary directory.

Verified gates:

- `cd benchmarks && python3 -m py_compile bench/*.py bench/corpora/*.py bench/scanners/*.py && python3 -m pytest -q bench/tests`
- `cd benchmarks && python3 -m bench leaderboard --corpus kernel --scanners keyhog --corpus-root <empty-tmp> --out <tmp-out>`

## Executed Patch Set: Benchmark Report Injection

Date: 2026-05-31

Vector coverage:

- COHERENCE: benchmark results now render to committed markdown rollups and inject the README performance tables between stable `BENCH:*` markers.
- WIRING: `make bench`, `make report`, and `make report-check` connect matrix execution, report rendering, and README freshness checks; raw host-specific `RunResult` JSON stays ignored while committed reports remain human-reviewable.
- RESEARCH: regenerated the mirror leaderboard across Keyhog, Betterleaks, Kingfisher, Nosey Parker, TruffleHog, and Titus on the neutral 15k-fixture corpus.
- TESTING: added report rendering/injection tests and ran the report freshness gate.

Verified gates:

- `cd benchmarks && python3 -m py_compile bench/*.py bench/corpora/*.py bench/scanners/*.py && python3 -m pytest -q bench/tests`
- `cd benchmarks && python3 -m bench leaderboard --corpus mirror --out results`
- `cd benchmarks && make report-check`

## Executed Patch Set: Benchmark Head Binary Resolution

Date: 2026-05-31

Vector coverage:

- COHERENCE: benchmark docs no longer handwrite transient mirror scores; the generated README/report path is the single visible source for current leaderboard numbers.
- WIRING: the Keyhog benchmark adapter now prefers the freshly built release binary from `CARGO_TARGET_DIR`, cargo config, or the repo target dir while preserving explicit constructor and `KEYHOG_BIN` overrides.
- DOGFOODING: this closes the stale-PATH benchmark failure mode where a leaderboard run could silently score an older installed `keyhog` instead of the source under review.
- TESTING: added adapter contracts for fresh release lookup, override precedence, and cargo config target-dir discovery.

Verified gates:

- `cd benchmarks && python3 -m py_compile bench/*.py bench/corpora/*.py bench/scanners/*.py && python3 -m pytest -q bench/tests`

## Executed Patch Set: Action Report Shape Validation

Date: 2026-05-31

Vector coverage:

- AUDIT HUNTS: the composite Action no longer lets jq count top-level JSON object keys as findings or flatten SARIF runs whose `results` field is not an array.
- COHERENCE: jq and Python report-counting paths now enforce the same JSON array and SARIF `runs[]/results[]` shape contracts.
- WIRING: malformed clean reports still take the fail-closed exit-3 path, while findings/live scanner exits keep the existing nonzero-finding parse-failure behavior.
- TESTING: added e2e contracts for object-shaped JSON reports and SARIF runs with non-array results.

Verified gates:

- `bash -n .github/actions/keyhog/run-scan.sh`
- `cargo test -p keyhog --test all_tests action_ci_contract -- --nocapture`

## Executed Patch Set: Benchmark Gap Analyzer Wiring

Date: 2026-05-31

Vector coverage:

- INSUFFICIENCY: promoted the FP/FN example miner from an untracked helper into the benchmark package interface instead of leaving count-only reports without a detector-tuning path.
- WIRING: added `python -m bench analyze` and `make analyze`, including scanner binary and corpus root arguments, so leaderboard gaps can be replayed through the same adapters and overlap attribution.
- COHERENCE: the benchmark Makefile no longer exports a desktop-specific `KEYHOG_BIN` by default; unset runs reach the adapter's host-local fresh-binary resolver.
- TESTING: added analyzer contracts for false-negative grouping, false-positive grouping, ignored records, unknown files, and package CLI dispatch.

Verified gates:

- `cd benchmarks && python3 -m py_compile bench/*.py bench/corpora/*.py bench/scanners/*.py && python3 -m pytest -q bench/tests`
- `cd benchmarks && make help`
- `cd benchmarks && python3 -m bench analyze --help`

## Executed Patch Set: GPU-Inclusive Database URL Confidence

Date: 2026-05-31

Vector coverage:

- UTILIZATION: the mirror gap analyzer exposed `database-connection-string` misses where named Redis/MySQL/PostgreSQL detectors emitted findings only below the default confidence floor.
- AUDIT HUNTS: verified the path through the real GPU backend on the RTX 5090; Vyre AC currently emits degenerate triples and degrades to SIMD/CPU, so GPU evidence is recorded instead of replaced by `KEYHOG_NO_GPU=1` runs.
- COHERENCE: the confidence model no longer treats `example.org` in the host of a named credential-bearing URL as proof that the password-bearing URL is a placeholder.
- WIRING: Redis, MySQL, and PostgreSQL connection-string detectors now ship reviewed `0.20` detector floors so the CLI post-process gate reports the named URL findings without lowering the global floor.
- WIRING: the PostgreSQL detector now uses explicit `postgresql|postgres` alternation and `pg-url`/`PG_URL` context keywords so the plain `postgres://` branch self-activates and clears the detector floor when structured decoding surfaces only a k8s Secret key plus URL.
- GPU/SIMD PHASE 2: cheap-filter confirmation and coalesced no-hit trigger collection now run against preprocessed text when structured decoding changes the chunk, so decoded structured credentials can activate detector roots even when the original file only contains base64.
- COHERENCE: match resolution now treats `generic-*` as fallback priority instead of service-specific priority, so a high-confidence decoded password fragment cannot hide the named database-URL finding on the same source line.
- TESTING: added positive and negative unit contracts: named credential URLs survive documentation-like hosts, while placeholder words inside URL userinfo still crush confidence.

Verified gates:

- `cargo fmt -p keyhog-scanner -- --check`
- `cargo test -p keyhog-scanner --test all_tests confidence_penalties -- --nocapture`
- `cargo test -p keyhog-scanner --test all_tests resolution -- --nocapture`
- `cargo test -p keyhog-scanner --test all_tests postgresql_connection_string -- --nocapture`
- `cargo test -p keyhog-scanner --test all_tests k8s_secret_decoded_postgres_url_self_activates_without_database_url_keyword -- --nocapture`
- `cargo test -p keyhog-scanner --test contracts_runner every_contract_passes_positives_negatives_evasions -- --nocapture`
- `cargo build --release -p keyhog --bin keyhog`
- `/mnt/FlareTraining/santh-archive/cargo-target/release/keyhog scan --backend gpu --no-daemon --format json --show-secrets --no-suppress-test-fixtures benchmarks/corpora/mirror/corpus/8b/mirror-pos-0000139.py` reported `redis-connection-string` after GPU AC degraded on degenerate Vyre triples.
- `/mnt/FlareTraining/santh-archive/cargo-target/release/keyhog scan --backend auto --no-daemon --format json --show-secrets --no-suppress-test-fixtures benchmarks/corpora/mirror/corpus/8b/mirror-pos-0000139.py` reported `redis-connection-string`.
- `/mnt/FlareTraining/santh-archive/cargo-target/release/keyhog scan --backend gpu --no-daemon --format json --show-secrets --no-suppress-test-fixtures benchmarks/corpora/mirror/corpus/a7/mirror-pos-0000167.yaml` reported `mysql-connection-string` after GPU AC degraded on degenerate Vyre triples.
- `/mnt/FlareTraining/santh-archive/cargo-target/release/keyhog scan --backend gpu --no-daemon --format json --show-secrets --no-suppress-test-fixtures benchmarks/corpora/mirror/corpus/4c/mirror-pos-0000332.yaml` reported `postgresql-connection-string` after GPU AC degraded on degenerate Vyre triples.
- `/mnt/FlareTraining/santh-archive/cargo-target/release/keyhog scan --backend auto --no-daemon --format json --show-secrets --no-suppress-test-fixtures benchmarks/corpora/mirror/corpus/4c/mirror-pos-0000332.yaml` reported `postgresql-connection-string`.
- `/mnt/FlareTraining/santh-archive/cargo-target/release/keyhog backend --self-test` confirmed RTX 5090 MoE PASS, literal-set KNOWN, and Vyre AC FAIL on degenerate triples at this checkpoint; superseded 2026-05-31 by `backend --self-test --json` reporting `vyre_ac_kernel=pass`.

## Executed Patch Set: Action JSONL Object Validation

Date: 2026-05-31

Vector coverage:

- CI UX: composite Action JSONL parsing now requires every nonblank JSONL value to be an object, matching the real reporter contract and preventing opaque strings/nulls from becoming fake findings counts.
- AUDIT HUNTS: clean malformed JSONL fails closed with exit 3, while malformed JSONL after a findings exit stays on the findings path instead of becoming zero findings.
- COHERENCE: jq and Python fallback parsers now enforce the same JSONL object shape.
- TESTING: added e2e Action contracts for clean and findings-exit non-object JSONL reports.

Verified gates:

- `bash -n .github/actions/keyhog/run-scan.sh`
- `cargo test -p keyhog --test all_tests action_ci_contract -- --nocapture`

## Executed Patch Set: AC GPU Degrade Reason Completion

Date: 2026-05-31

Vector coverage:

- SPEED / UTILIZATION: reran the real RTX 5090 `backend --self-test`; at this checkpoint MoE still passed, AC still degraded because Vyre emitted degenerate triples, and a probe of CUDA subgroup coalescing still failed neutral lowering on `_vyre_match_leader`. Superseded 2026-05-31 by the KeyHog bound-atomic AC builder for the non-subgroup path.
- CI UX: AC GPU runtime failures now carry the concrete backend cause into the same operator-visible degrade and `KEYHOG_REQUIRE_GPU=1` hard-fail path, instead of relying on tracing output that many CI jobs do not show.
- AUDIT HUNTS: batched dispatch errors, per-shard dispatch errors, missing/truncated output buffers, and match-cap overflow all fail closed with specific reasons before CPU/SIMD recall-preserving fallback.
- TESTING: extended the scanner gap contract so future AC GPU failure branches cannot return a generic degrade warning.

Verified gates:

- `RUST_LOG=keyhog::routing=debug timeout 120s cargo run -p keyhog -- backend --self-test` confirmed the live RTX 5090 path still reported MoE PASS, literal-set KNOWN, and AC FAIL on degenerate triples with the concrete reason in stderr at this checkpoint; superseded 2026-05-31 by JSON self-test `vyre_ac_kernel=pass`.
- `cargo test -p keyhog-scanner --test all_tests gpu_ac_degenerate_triples_degrade -- --nocapture`

## Executed Patch Set: CI Advisory-Mode Documentation Coherence

Date: 2026-05-31

Vector coverage:

- COHERENCE: the mdBook CI workflow, drop-in usage guide, and integration PR template now state the same advisory-mode contract as the composite Action metadata and README.
- CI UX: rollout docs distinguish ordinary advisory findings from verified-live credentials, which still fail after report/SARIF/artifact upload with exit code `10`.

Verified gates:

- `rg -n 'fail-on-findings|verified-live|exit code' docs/src/workflows/ci.md docs/DROP_IN_USAGE.md docs/INTEGRATION_PR_TEMPLATE.md`

## Executed Patch Set: Exit-Code Documentation Coherence

Date: 2026-05-31

Vector coverage:

- COHERENCE: first-scan, detector-authoring, and drop-in usage docs no longer describe verified-live credentials as ordinary exit `1` findings.
- CI UX: docs now tell CI consumers to block on both exit `1` and exit `10`, while keeping runtime/configuration failures distinct.

Verified gates:

- `! rg -n 'unverified or verified-live|bad config, panic|CI gates should look for|only depends on whether ANY finding exists' docs/src docs/DROP_IN_USAGE.md`

## Executed Patch Set: Real Text Action Count Dogfood

Date: 2026-05-31

Vector coverage:

- CI UX: the composite Action contract now runs the real `keyhog` binary through `format: text`, not only SARIF, and proves the wrapper reports the finding count through `GITHUB_OUTPUT`.
- WIRING: the text report counter is pinned to the actual TextReporter `Secret:` field emitted by KeyHog, closing the gap where the production text path was only covered by a stubbed report.

Verified gates:

- `cargo test -p keyhog --test all_tests action_ci_contract -- --nocapture`

## Executed Patch Set: Backend Self-Test JSON Gate

Date: 2026-05-31

Vector coverage:

- CI UX: `keyhog backend --self-test --json` now emits stable `ok`, `status`, `exit_code`, `recommended_backend`, and per-probe records so production CI can consume GPU health without scraping ANSI text.
- SPEED / UTILIZATION: the RTX 5090 path is still exercised as a real GPU path, not a no-GPU skip; at this checkpoint MoE passed while the production Vyre AC kernel remained a red exit-4 gate on degenerate match triples. Superseded 2026-05-31 by the bound-atomic AC builder.
- COHERENCE: README, mdBook CI guidance, exit-code docs, changelog, and tests now describe the same JSON self-test contract.
- TESTING: added renderer and real-binary no-GPU skip contracts, then reran the actual GPU self-test JSON command on the live RTX 5090 host.

Verified gates:

- `cargo test -p keyhog --test all_tests backend_self_test_json -- --nocapture`
- `cargo test -p keyhog --test all_tests r5t_backend_help_documents_json_flag -- --nocapture`
- `timeout 120s cargo run -p keyhog -- backend --self-test --json` confirmed live RTX 5090 `moe_kernel=pass`, `vyre_literal_set=known`, and `vyre_ac_kernel=fail` with exit `4` at this checkpoint; superseded 2026-05-31 by `status=pass`, `recommended_backend=gpu`, and `vyre_ac_kernel=pass`.

## Executed Patch Set: GPU AC Bound Atomic Slot

Date: 2026-05-31

Vector coverage:

- SPEED / UTILIZATION: the production GPU AC path now runs to completion on the live RTX 5090 instead of degrading to SIMD/CPU after a corrupt Vyre readback.
- AUDIT HUNTS: the match-output corruption root cause was isolated to the AC append builder cloning `atomic_add`; KeyHog's bound-slot builder emits one atomic increment and writes pattern/start/end through that same slot.
- WIRING: `KEYHOG_REQUIRE_GPU=1` no longer kills an already healthy GPU stack during preflight, while concrete runtime degrade reasons still hard-fail the process.
- COHERENCE: literal-set diagnostic degradations now carry the same concrete reason style as AC degradations, and the backlog no longer describes the RTX 5090 AC self-test as red.
- TESTING: the scanner gap gate locks the bound-slot builder, the backend self-test JSON proves the actual GPU path, and the required-GPU parity gate now reaches and passes its assertions.

Verified gates:

- `cargo test -p keyhog-scanner --test all_tests gpu_ac_degenerate_triples_degrade -- --nocapture`
- `timeout 120s cargo run -p keyhog -- backend --self-test --json` confirmed live RTX 5090 `status=pass`, `recommended_backend=gpu`, and `vyre_ac_kernel=pass`.
- `KEYHOG_REQUIRE_GPU=1 cargo test -p keyhog-scanner --test gpu_parity gpu_and_simd_produce_identical_findings_on_same_corpus -- --nocapture`

## Executed Patch Set: Trusted SARIF Upload Fail-Closed

Date: 2026-05-31

Vector coverage:

- CI UX: trusted GitHub Actions runs with `upload-sarif: 'true'` now fail closed when Code Scanning upload fails, so a green CI job cannot silently lack annotations; the report artifact still uploads under `always()` when the report exists.
- AUDIT HUNTS: fork pull requests keep the existing advisory upload behavior because their restricted token commonly lacks `security-events: write`; the workflow artifact remains available for review in both fork and trusted-failure cases.
- COHERENCE: Action README, CI guide, changelog, and composite Action YAML now describe the same trusted-vs-fork upload policy.
- TESTING: added composite Action manifest contracts that reject unconditional `continue-on-error: true` on the SARIF upload step and require artifact upload to run under `always()`.

Verified gates:

- `cargo test -p keyhog --test all_tests composite_action_sarif_upload_fails_closed_on_trusted_runs -- --nocapture`
- `cargo test -p keyhog --test all_tests action_ci_contract -- --nocapture`
- `tests/integration/entrypoints_check.sh`
- `bash -n .github/actions/keyhog/run-scan.sh tests/integration/entrypoints_check.sh`

## Executed Patch Set: Test-Fixture Opt-Out Confidence Coherence

Date: 2026-05-31

Vector coverage:

- WIRING: `--no-suppress-test-fixtures` now reaches `ScannerConfig::penalize_test_paths`, so the same operator flag disables fixture value suppressions, test/example path confidence penalties, and test/docs hard suppression.
- CAPABILITY: recall audits and competitor differentials can now surface real low-confidence credentials committed under `tests/fixtures` instead of silently dropping them by path context.
- COHERENCE: scanner helper tests, CLI config tests, real-binary e2e, changelog, and audit plan now describe the same flag contract.
- TESTING: added a real-binary `--no-daemon` e2e that proves a `tests/fixtures` finding is absent by default and present with `--no-suppress-test-fixtures`.

Verified gates:

- `cargo test -p keyhog-scanner --test all_tests confidence_path_penalty -- --nocapture`
- `cargo test -p keyhog --test all_tests build_scanner_config_no_suppress_disables_test_path_penalty -- --nocapture`
- `cargo test -p keyhog --test e2e_binary no_suppress_test_fixtures_surfaces_test_path_findings -- --nocapture`
