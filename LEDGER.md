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
