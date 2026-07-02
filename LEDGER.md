# keyhog work ledger

Live record of concrete work. Every backlog item was found by READING CODE
(gemini/agent hunts + direct reads), not auto-generated. Completed items carry a
commit hash. Updated continuously; workflows run in the background so no turn
sits idle waiting on a build.

## DONE (committed)
- **e8e6eca4b** — unify 13 duplicated primitives into single owners (30 files, +754/-105):
  - same-name divergence BUGS fixed: `LOW_ENTROPY_THRESHOLD` (confidence 2.0) renamed
    `LOW_ENTROPY_PENALTY_FLOOR` (vs entropy detection floor 3.0); `is_windows_absolute`
    split into `core::winpath::{has_windows_drive_prefix, is_windows_absolute}` (broad
    security vs strict URI — they disagreed on `C:rel`).
  - dedups: `ends_with_ignore_ascii_case`→core::ascii_ci; `SHA256_HEX_LEN`→core::git_lfs;
    `arc_from_cow` hoisted; `HIGH_ENTROPY_BASE64_CUTOFF`, `MAX_INNER_LOOP_ITERS`,
    `FIRST_SOURCE_LINE_NUMBER`, `FRAMES`+`BAR_WIDTH` → module consts; `with_max_commits`,
    `hex_value` (new extract::hexnib), cloud `with_max_objects/with_prefix`,
    `is_base64_candidate_byte` → single owners.
  - ~50 new pass/fail tests lock the single-owner contracts. Builds green.
- **verified-correct (no change needed):** GPU-selected-but-unusable fallback is loud +
  fail-closed (`compiled_api.rs` require_gpu_unmet / warn_gpu_auto_degrade), not silent.
- **infra:** gemini-spawn MCP `gemini_result` made strictly non-blocking (can't wait);
  `CLAUDE.md` gained the ONE PLACE elegance law (every value/behavior has one owner).

## IN PROGRESS (background)
- **Wave 2 find-and-fix** (12 agents, one per disjoint code dir): read every .rs under
  their area, unify dups / hoist consts / rename same-name divergences / kill silent
  overrides / add tests, and report everything found. On completion: batch-build (bg),
  commit, log findings here, launch Wave 3.

## BACKLOG (found by reading code — to drain in waves)
### Duplication / elegance
- `as_any` boilerplate copied across ~17 sources modules → trait default method or macro.
- MoE arch consts: Rust `ml_weights.rs` vs WGSL `gpu_shader.rs` string → codegen one owner
  (drift = GPU/CPU scoring divergence).
- multiline offset free-fns (`source_offset_from_mapping`, `source_line_at`) byte-identical
  across the `multiline` cfg split → one always-compiled submodule (both-config build).
### Tier-B migration (hardcoded lists → data files; ~40 lists, needs loader/codegen infra first)
- detection: KNOWN_PREFIXES, CREDENTIAL_COMPACT_KEYWORDS, STRONG_HEX_KEY_COMPACT_EXACT,
  ENCODED_TEXT_SECRET_ANCHORS, BLOCKCHAIN_ADDR_KEYWORDS.
- suppression: PUBLIC_WORDS, ALGORITHMS, HTML_EVENTS, PERCENT_ENCODED_NEEDLES,
  PROSE_CONNECTORS, SOURCE_TYPE_TERMS, SOURCE_RECEIVERS, CREDENTIAL_WORDS,
  REGEX_SIGIL_SUFFIXES, FILENAME_SUFFIXES, EXTENSIONS, VENDORED_JS_PREFIXES, NEEDLES.
- extensions/filenames: PROGRAM_SOURCE_CODE_EXTENSIONS, CAESAR_TEXT_NOISE_EXTENSIONS,
  SOURCE_CODE_FILENAMES, CONFIG_EXTENSIONS_AFTER_STEM, PREFIX_MATCH_NAMES,
  EXACT_OR_CONFIG_EXT_NAMES.
- ml_features markers: CI/INFRA/BINARY/SOURCE/CONFIG/COMMENT, TEST_FILE_CONTEXT_FRAGMENTS,
  SOURCE_EXTENSIONS.
- misc: CORS_HEADERS, COMMENT_MARKERS, FAKE_SEQUENCES, EXAMPLE_PATH_COMPONENTS,
  FIXTURE_COMPONENTS, hash LABELS, FRAGMENT_SUFFIXES, JUPYTER_TEXT_OUTPUT_MIME_TYPES.
### Autoroute
- `workload_key` buckets on declared file size not the actual scanned slice → windowed
  large-file cache-miss/fail-closed. Verify against windowed path + fix.
- `clamp_below_calibrated_floor` hardcodes CpuFallback vs the floor bucket's measured
  backend — needs a scalar-vs-Hyperscan micro-bench at sub-floor sizes to resolve.
### Dead code (from compiler warnings — Law 11)
- `detector_ids.rs` GENERIC_PASSWORD, GENERIC_DATABASE_URL unused.
- `placeholder_words.rs` parse_placeholder_words unused.
- `cli/style.rs` print_diagnostic_finding unused.
### Docs
- README + every subcommand `--help` + JSON/SARIF fields + exit-code table + module docs
  reconciled against real behavior (one source of truth).

## Wave 2 (find-and-fix, commit pending — 27 fixed)

- [magic-number] crates/scanner/src/multiline/structural.rs:83 — Inline `>= 16` inline-array fragment cutoff (its own comment even referenced the bare literal) hoisted to named const MIN_INLINE_ARRAY_FRAGMENT_LEN=16 next to MIN_STRUCTURAL_FRAGME
- [magic-number] crates/scanner/src/multiline/structural.rs:118 — Inline `< 10` max cluster line-gap hoisted to named const MAX_CLUSTER_LINE_GAP=10; value unchanged.
- [silent-override] crates/cli/src/orchestrator.rs:285 — load_allowlist() did `Allowlist::load(&ignore_path).unwrap_or_else(|_| Allowlist::empty())` — when a .keyhogignore FILE EXISTS but fails to parse, it silently discarded the error a
- [hardcoded-list] crates/cli/src/orchestrator.rs:212 — Credential suppression used inline string literals ("parameter", "sk_live_4eC39HqLyjWDarjtT1zdp7dc", "EXAMPLE", "PLACEHOLDER") pasted directly into the filter predicate. Hoisted ea
- [hardcoded-list] crates/cli/src/orchestrator.rs:221 — Self-scan/test path suppression used inline literals ("/keyhog", "/tests/", "/fixtures/") in the filter predicate. Hoisted to named consts SUPPRESSED_PATH_SELF_SCAN_SUFFIX / _TESTS
- [magic-number] crates/scanner/src/context/placeholder.rs:114 — The 90% sequential-run threshold `* 9 / 10` was pasted inline at three sites (hex adjacent-step, pair-column, pair-value checks). Hoisted to one owner: `SEQUENTIAL_STEP_RATIO_NUMER
- [magic-number] crates/scanner/src/context/false_positive.rs:240 — Bare `44` (go.sum `h1:` base64 SHA-256 digest length) appeared twice inline in `has_strict_go_sum_checksum_shape` (slice bound + trailing-byte check). Hoisted to `GO_SUM_H1_BASE64_
- [magic-number] crates/scanner/src/context/false_positive.rs:395 — Bare `3` (git-LFS pointer lookaround window) duplicated in the `nearby_lines_contain` and `following_lines_contain` calls of `is_git_lfs_pointer_context_with_lines`. Hoisted to `GI
- [dead-code] crates/scanner/src/context/placeholder.rs:32 — `is_known_example_credential` bound `let body = credential.as_bytes();` a second time immediately after the identical `let bytes = credential.as_bytes();` at line 24, then used `bo
- [dup-fn] crates/sources/src/cloud/mod.rs:460 — Content-Type media-type extraction (split_once(';').map_or(...).trim()) pasted 3x: is_binary_content_type + is_unknown_binary_content_type in cloud/mod.rs and web_response_kind_fro
- [magic-number] crates/sources/src/github_org.rs:136 — GitHub page size 100 was inline in two coupled places: per_page=100 query string and the count < 100 last-page terminator. Divergence silently breaks pagination (drops repos or ext
- [dup-fn] crates/scanner/src/engine/phase2/hs_mark_timing.rs:72 — Byte-identical private `fn pct(part: u64, whole: u64) -> f64` (the `100*part/whole` percentage helper with the divide-by-zero guard) was defined in BOTH phase2/hs_mark_timing.rs (w
- [magic-number] crates/sources/src/filesystem/extract.rs:164 — The printable-strings minimum length literal `8` was pasted at 4 call sites (extract.rs `chunk_from_extracted_entry`, the Bytes and Mmap arms of `process_entry`, and pdf.rs `emit_n
- [magic-number] crates/sources/src/filesystem/extract/rar.rs:820 — The `64 * 1024` entry-buffer capacity hint was inline at two RAR sinks (`RarEntrySink::new` line ~820 and `SolidRarEntrySink::new` line ~874). Hoisted to `const RAR_ENTRY_BUFFER_CA
- [magic-number] crates/scanner/src/entropy/plausibility.rs:150 — Inline entropy floor `3.5` in passes_secret_strength_checks (the symbolic-credential relaxation floor) had no named owner while every sibling threshold in the entropy area (MIXED_A
- [magic-number] crates/scanner/src/entropy/plausibility.rs:231 — Inline entropy floor `4.8` in is_isolated_leading_slash_base64_secret (strictest, anchor-free base64 floor) had no named owner. Hoisted to pub(crate) const LEADING_SLASH_BASE64_ENT
- [magic-number] crates/scanner/src/entropy/plausibility.rs:258 — Inline entropy floor `2.5` in passes_secret_shape_checks (second-half tail-entropy floor) had no named owner. Hoisted to pub(crate) const SECOND_HALF_ENTROPY_FLOOR = 2.5 and re-poi
- [dup-const] crates/core/src/rule_filter.rs:240 — The multi-line '[[suppress]] entry has no conditions' rejection string was pasted byte-identically at two sites (the empty-conditions guard and the defensive `let Some(first) = ite
- [magic-number] crates/core/src/aws.rs:83 — The access-key-ID prefix length was an inline literal `4` in `&key_id.as_bytes()[4..]`, decoupled from AWS_KEY_ID_PREFIXES (['AKIA','ASIA'], both 4 chars) and from AWS_KEY_ID_LEN=2
- [dup-fn] crates/scanner/src/suppression/decision.rs:328 — The `{...}`/`<...>`/`${...}` template-placeholder shape check was reimplemented twice in decision.rs (inline in suppression_stage_inner ~line 328 and again in fn decoded_looks_like
- [dup-const] crates/scanner/src/suppression/doc_markers.rs:78 — The RFC-2606 reserved-domain carve-out `upper.contains("EXAMPLE.COM") || upper.contains("EXAMPLE.ORG")` was pasted at two sites in check_markers (the contains_EXAMPLE_token gate ~l
- [dead-code] crates/scanner/src/ml_scorer/ml_features.rs:21 — A 4-line mixture-of-experts doc comment ('Number of mixture-of-experts specialists ... grid search over {4,6,8,12}') was misattached to `const MAX_NORMALIZED_TEXT_LENGTH: f32 = 200
- [magic-number] crates/scanner/src/structured/mod.rs:19 — The synthetic-line key/value separator was a magic literal duplicated across 6 sites: the integer `2` (== len of ": ") in four capacity/offset expressions (build_preprocessed_text,
- [magic-number] crates/cli/src/subcommands/watch.rs:246 — The FNV-1a 64-bit offset basis (0xcbf2_9ce4_8422_2325) and prime (0x0000_0100_0000_01b3) were pasted inline across 6 sites in two functions (content_hash + findings_fingerprint). H
- [magic-number] scanner/src/confidence/penalties.rs:197 — Post-ML penalty multipliers were pasted inline eight times: 0.05 (placeholder word ×1), 0.1 (low-diversity ×2 + degenerate-shape ×2), and 0.02 (data-envelope ×3). The three 0.02 ar
- [magic-number] scanner/src/confidence/prefixes.rs:154 — known_prefix_confidence_floor returned a bare `Some(0.8)` while the doc comments reference 'the 0.8 floor' 5+ times and sibling floors are named consts (policy::NAMED_DETECTOR_ANCH
- [other] scanner/src/decode/pipeline.rs:67 — Stale comment claimed a chunk 'could run all 14 decoders' but the default registry (registry.rs default_decoders + its own comment 'There are 13 default decoders today') holds exac

## Backlog: Wave 2 reported (code-found, 47 items)

- [ ] [same-name-divergence] crates/scanner/src/multiline/structural.rs:382 — join_inline_array_strings hand-rolls quote-state scanning but OMITS backslash-escape handling, unlike the 4 sibling literal scanners (extract_quoted_content string_extract.rs:244, extract_quoted_strin
- [ ] [dup-fn] crates/scanner/src/multiline/config.rs:19 — VAR_REF_CONCAT_RE (config.rs:19) and CONCAT_RE (structural.rs:12) compile the SAME regex pattern — identical except CONCAT_RE wraps the RHS in a capture group, which does not change what is_match acce
- [ ] [same-name-divergence] crates/scanner/src/multiline/config.rs:136 — PreprocessedText::passthrough diverges by feature flag: the multiline variant (config.rs:136) builds a per-line mapping table, while the non-multiline twin (types.rs:189) builds a SINGLE line-1 mappin
- [ ] [dup-fn] crates/scanner/src/multiline/preprocessor.rs:168 — identity_line_mappings (preprocessor.rs:168) and PreprocessedText::passthrough (config.rs:136) reimplement the same per-line identity offset→line mapping two different ways (per-entry `(end+1).min(ori
- [ ] [hardcoded-list] crates/scanner/src/multiline/string_extract.rs:110 — Multiple hardcoded domain lists that per project policy should be Tier-B data: is_bare_ambiguous_fragment_owner (string_extract.rs:110 key/token/secret/...), normalized_assignment_name_is_public_metad
- [ ] [hardcoded-list] crates/cli/src/orchestrator.rs:25 — The credential + path suppression sets (now the SUPPRESSED_CREDENTIAL_* / SUPPRESSED_PATH_* consts) are still compiled-in hardcoded lists. Per the Tier-B mandate (hardcoded suppression lists banned) t
- [ ] [magic-number] crates/cli/src/orchestrator.rs:71 — Low-memory downscaling uses three bare magic numbers with no named owner: `mem_mb < 4096` (RAM threshold in MB, line 71), `.min(500)` (max_matches_per_chunk cap, line 73), `.min(256 * 1024)` (max_deco
- [ ] [dead-code] crates/cli/src/orchestrator.rs:23 — const EXIT_LIVE_CREDENTIALS: u8 = 10 is defined but never referenced by any non-test code. run() unconditionally returns ExitCode::SUCCESS even on the verify path where live credentials are confirmed,
- [ ] [same-name-divergence] crates/scanner/src/context/inference.rs:302 — Two code paths recognize a Rust/Java test attribute with divergent rule sets. The inline block in `is_in_test_function` (lines ~302-306) matches only exact `#[test]`, `#[cfg(test)]`, `#[tokio::test` p
- [ ] [hardcoded-list] crates/scanner/src/context/inference.rs:207 — Comment-marker enumeration diverges across three functions: `is_comment_line` (inference.rs:207-218) lists `//`,`#`,`--`(not `---`),`/*`,`<!--`,`<#`,`* `,`*/`,`rem `,`REM `; `strip_comment_prefix` (in
- [ ] [hardcoded-list] crates/scanner/src/context/inference.rs:56 — Multiple hardcoded domain lists that CLAUDE.md's Tier-B rule says belong in data files, not source: `is_encrypted_marker_line` (encrypted-block markers $ANSIBLE_VAULT/ENC[/sops:/sealed-secrets/PGP/AGE
- [ ] [hardcoded-list] crates/sources/src/cloud/mod.rs:434 — is_probably_text_object_key hardcodes BINARY_OBJECT_EXTS = [zip,gz,tgz,tar,7z,rar,pdf,bz2,xz,zst,lz4,sz] inline; a Tier-B extension-recognition list (task #167) that also overlaps filesystem::is_defau
- [ ] [magic-number] crates/sources/src/gcs.rs:230 — Per-provider listing page sizes are single-use inline literals with no named owner: gcs.rs maxResults=1000, cloud/azure_blob.rs maxresults=5000, bitbucket_workspace.rs pagelen=100. Unlike the GitHub c
- [ ] [dup-fn] crates/sources/src/gcs.rs:113 — fn as_any(&self) -> &dyn Any { self } is copy-pasted verbatim across ~7 Source impls in this area (s3, gcs, web, azure_blob, github_org, bitbucket_workspace, git). Catalog item #163. It is a trait met
- [ ] [same-name-divergence] crates/scanner/src/engine/scan_filters.rs:370 — The recall-critical secret prefixes have TWO hardcoded sources of truth: production reads them from Tier-B `rules/multiline_secret_prefixes.toml` via `crate::secret_prefixes::multiline_secret_prefixes
- [ ] [hardcoded-list] crates/scanner/src/engine/phase2_generic/keywords.rs:220 — Two detection-critical hardcoded keyword lists baked into code instead of Tier-B data: `STRONG_HEX_KEY_COMPACT_EXACT` (line 220: secret/apikey/privatekey/encryptionkey/signingkey/accesskey/clientsecre
- [ ] [hardcoded-list] crates/scanner/src/engine/phase2_entropy/gates.rs:232 — `BLOCKCHAIN_ADDR_KEYWORDS` (line 232: _ADDR=/_ADDRESS=/_WALLET=/_PUBKEY=/_CONTRACT=/_PEER_ID= etc.) is a hardcoded suppression keyword list driving the BlockchainOrNetworkAddress entropy-shape verdict
- [ ] [hardcoded-list] crates/sources/src/filesystem/extract/archive.rs:32 — `is_openpack_archive_ext` hardcodes the whole ZIP-container extension set (`zip/apk/ipa/crx/jar/whl/war/ear/aar/nupkg/snupkg/egg/xpi/vsix/docx/xlsx/pptx/odt/ods/odp`) inline as `OPENPACK_EXTS`. This i
- [ ] [hardcoded-list] crates/sources/src/filesystem/extract.rs:358 — `process_entry` hardcodes a minified/bundled skip list inline (`.min.`, `.bundle.`, `.chunk.js`, `.min.js`, `.bundle.js`) as a second exclusion pass, duplicating the *purpose* of the Tier-B `default_e
- [ ] [dup-const] crates/sources/src/filesystem/extract/pdf.rs:19 — `PDF_UNCAPPED_DECODE_BUDGET` (pdf.rs, usize, 1 GiB) and `UNCAPPED_ARCHIVE_BUDGET` (extract.rs:27, u64, 1 GiB) are two independently-named constants with the same value and the same role ('the uncapped
- [ ] [other] crates/scanner/src/entropy/mod.rs:375 — entropy/mod.rs carries an inline `#[cfg(test)] mod tests` block but is NOT in the INLINE_TEST_ALLOWLIST of crates/scanner/tests/gap/no_inline_tests_in_src.rs, so that gate flags it as a disallowed off
- [ ] [dup-fn] crates/scanner/src/entropy/fast.rs:261 — distinct_byte_count (u64 4-word bitset, #[cfg(test)]-only) is a fourth distinct-byte-counting implementation that its own doc does not acknowledge; mod.rs::unique_byte_count (bool[256], pub(crate), pr
- [ ] [hardcoded-list] crates/scanner/src/entropy/scanner.rs:517 — Two hardcoded key-material keyword lists — keyword_is_crypto_key_material (13 entries) and keyword_is_key_material (14 entries) — plus keywords.rs::CREDENTIAL_COMPACT_KEYWORDS (27 entries) heavily ove
- [ ] [dup-const] crates/core/src/calibration.rs:43 — STALE_CALIBRATION_TMP_CUTOFF_SECS = 60*60 (calibration.rs) and STALE_TMP_CUTOFF_SECS = 60*60 (merkle_index/tmp_hygiene.rs) are the same value with identical 'stale interrupted-save tmp file age cutoff
- [ ] [hardcoded-list] crates/core/src/config.rs:250 — secret_filenames() returns a ~50-entry hardcoded Vec<String> of credential-bearing filenames, and ScanConfig::default() hardcodes known_prefixes/secret_keywords/test_keywords/placeholder_keywords. Per
- [ ] [hardcoded-list] crates/core/src/dedup.rs:297 — is_decoder_location() hardcodes DECODER_SUFFIXES = ['/base64','/hex','/url','/json','/z85','/reverse','/caesar'] as a local const inside the fn. This list must stay in lockstep with the scanner's deco
- [ ] [same-name-divergence] crates/core/src/report/style.rs:90 — Two functions named `severity_label` diverge: report/style.rs `severity_label(severity: Severity, color: bool) -> String` (colored display label) vs rule_filter.rs:298 `severity_label(rank: usize) -> 
- [ ] [magic-number] crates/core/src/allowlist.rs:678 — The SHA-256 hex length 64 is an inline literal in invalid_bare_entry (bytes.len()==64) and in merkle_spec_hash.rs hex_to_array (bytes.len()!=64), while git_lfs::SHA256_HEX_LEN is the crate's declared 
- [ ] [magic-number] crates/scanner/src/suppression/decision.rs:112 — The entropy cutoff 4.8 (with the len>=40 floor) is pasted inline in decision.rs suppression_stage_inner (the suppresses_repetitive_run and high_entropy_base64_candidate exprs, ~lines 112 and 116) and 
- [ ] [same-name-divergence] crates/scanner/src/suppression/shape/mod.rs:522 — Two inline credential-keyword lists that answer the same question ('does this identifier contain a secret word') diverge. shape/mod.rs looks_like_ts_non_null_identifier (~line 522) uses [token, secret
- [ ] [hardcoded-list] crates/scanner/src/suppression/shape/public.rs:90 — Numerous hardcoded domain/word/extension lists live inline across the suppression shape layer that per CLAUDE.md should be Tier-B data files: PUBLIC_WORDS/ALGORITHMS/HTML_EVENTS/EXTENSIONS (public.rs)
- [ ] [other] crates/scanner/src/suppression/shape/public.rs:303 — looks_like_public_artifact_reference_with_randomness allocates `let lower = value.to_ascii_lowercase();` and then runs many .contains/.matches over it, in a per-candidate suppression predicate. This c
- [ ] [dup-fn] crates/scanner/src/suppression/api.rs:202 — suppress_named_detector_finding_stage repeats the pair `crate::adjudicate::record_example_suppression("pipeline", path, credential, reason); return shape_stage(reason);` ~16 times (lines ~202-405), al
- [ ] [dead-code] crates/scanner/src/ml_scorer/ml_weights.rs:176 — Eight `pub(crate)` weight-accessor fns (gate_weight, gate_bias, expert_fc1_weight, expert_fc1_bias, expert_fc2_weight, expert_fc2_bias, expert_fc3_weight, expert_fc3_bias) have zero callers outside th
- [ ] [dup-const] crates/scanner/src/structured/parsers/yaml.rs:244 — MAX_YAML_TRAVERSAL_DEPTH = 256 (yaml.rs:244) and MAX_TFSTATE_DEPTH = 256 (json.rs:32) are the same-value adversarial-recursion depth cap for structured parsers, declared independently in two sibling p
- [ ] [dup-fn] crates/scanner/src/structured/parsers/json.rs:503 — `scalar_value_text` (json.rs:503) and `yaml_scalar_value_text` (yaml.rs:300) are byte-identical in logic (String -> Some(clone), Number/Bool -> Some(to_string), else None) but operate on serde_json::V
- [ ] [same-name-divergence] crates/scanner/src/ml_scorer/ml_features.rs:112 — infer_file_type marker matching is inconsistent on case: BINARY_MARKERS, CI_MARKERS, INFRA_MARKERS, SOURCE_EXTENSIONS and CONFIG_MARKERS are all matched ASCII-case-insensitively (contains_any_ascii_ca
- [ ] [hardcoded-list] crates/scanner/src/ml_scorer/ml_features.rs:64 — Eight hardcoded domain lists live inline: COMMENT_PREFIXES, BINARY_MARKERS, CI_MARKERS, INFRA_MARKERS, SOURCE_MARKERS, SOURCE_EXTENSIONS, CONFIG_MARKERS (l.64-124) and TEST_FILE_CONTEXT_FRAGMENTS (l.1
- [ ] [hardcoded-list] crates/scanner/src/structured/parsers/json.rs:376 — JUPYTER_TEXT_OUTPUT_MIME_TYPES is a hardcoded 7-entry MIME allowlist (text/plain, text/html, ... image/svg+xml) governing which Jupyter output surfaces are scanned. Per Tier-B doctrine a recognition l
- [ ] [dup-fn] crates/cli/src/subcommands/backend.rs:172 — The SIMD-label chain (has_avx512=>"AVX-512" / avx2=>"AVX2" / neon=>"NEON" / else "scalar") is triplicated verbatim: backend.rs:172, subcommands/doctor.rs:49, and scanner/src/hw_probe/banner.rs:27. Two
- [ ] [dup-fn] crates/cli/src/subcommands/backend.rs:712 — backend.rs::fmt_bytes reimplements byte formatting that crate::format::format_bytes already owns, and diverges from it: fmt_bytes emits integer units ("8 MiB") while format_bytes emits 2-decimal ("8.0
- [ ] [hardcoded-list] crates/cli/src/subcommands/explain.rs:49 — canonical_for_hot_id's HOT_IDS table is a hand-maintained mapping index-aligned with the scanner's HOT_PATTERN_DETECTOR_IDS (a separate crate). Adding a hot-pattern detector in the scanner without edi
- [ ] [hardcoded-list] crates/cli/src/subcommands/calibrate_autoroute.rs:34 — SCAN_POLICY_PRESETS = ["--fast","--deep","--precision"] is a hardcoded duplicate of the preset flags defined in args/scan.rs; the comment concedes it must be kept in sync by hand (guarded only by an e
- [ ] [dup-fn] crates/cli/src/subcommands/explain.rs:293 — Local strip_prefix_ignore_ascii_case overlaps keyhog_core::starts_with_ignore_ascii_case (already used elsewhere in this crate). Not identical (core returns bool, this returns the Option<&str> remaind
- [ ] [same-name-divergence] scanner/src/decode/caesar.rs:167 — Two in-area code paths reimplement 'scheme://user:pass@host credential-URL' detection differently: decode/caesar.rs::line_has_credential_url splits userinfo on the FIRST '@' (userinfo.find('@')), whil
- [ ] [magic-number] scanner/src/confidence/penalties.rs:180 — Detection-tuning THRESHOLDS in apply_post_ml_penalties remain inline and unnamed: char_diversity < 0.1 (named branch) vs < 0.3 (generic branch), and max_repeat_run > 0.8 (named) vs > 0.5 (generic). Le
- [ ] [magic-number] scanner/src/decode/pipeline/extractor.rs:168 — Scattered per-decoder minimum-length floors are inline literals with no shared owner: extractor flush_b64 uses `b64_block.len() >= 16`, HexDecoder uses min_length 16, Base64Decoder uses floor 12, Z85 
