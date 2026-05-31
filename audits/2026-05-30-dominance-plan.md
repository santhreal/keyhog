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
- `CsrU32` exists as a hot-path optimization but must be verified as fully adopted or removed.

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
- AUDIT HUNTS: captured the remaining forced-GPU red gate separately; `KEYHOG_REQUIRE_GPU=1 cargo test -p keyhog-scanner --test gpu_parity gpu_and_simd_produce_identical_findings_on_same_corpus -- --nocapture` fails because runtime GPU dispatch degrades before parity assertions, while `keyhog backend --self-test` passes on the RTX 5090.

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

## Executed Patch Set: GPU AC Cheap-Filter Whole-Chunk Confirmation

Date: 2026-05-31

Vector coverage:

- SPEED: keeps the AC cheap-filter bounded to one regex `is_match` per candidate pid while avoiding repeated window probes for the same pid.
- CAPABILITY: aligns GPU root confirmation with SIMD trigger semantics by evaluating detector regexes over the whole prepared chunk before precise extraction, preventing narrow-window misses for wider-context detector regexes.
- COHERENCE: the implementation now matches the existing code comments that described whole-chunk, position-independent confirmation.
- TESTING: GPU self-test passed on the RTX 5090; the StackBlitz GPU recall narrow-window test ran but skipped its corpus-dependent assertion because the local bench corpus file is absent; added and ran a real-binary GPU/SIMD parity integration gate for far-offset and caseless literal-prefix regressions.
- AUDIT HUNTS: the known forced-GPU synthetic parity gate still hard-fails before assertions with runtime GPU dispatch degradation, so the red gate remains recorded.

Verified gates:

- `/mnt/FlareTraining/santh-archive/cargo-target/debug/keyhog backend --self-test`
- `KEYHOG_REQUIRE_GPU=1 cargo test -p keyhog-scanner --test gpu_ac_recall_bug_56 gpu_ac_kernel_finds_stackblitz_token_in_narrow_window -- --nocapture`
- `cargo test -p keyhog --test gpu_simd_parity -- --nocapture`

Red gate captured:

- `KEYHOG_REQUIRE_GPU=1 cargo test -p keyhog-scanner --test gpu_parity gpu_and_simd_produce_identical_findings_on_same_corpus -- --nocapture`

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
