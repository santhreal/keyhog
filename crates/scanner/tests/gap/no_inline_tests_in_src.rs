//! KH-GAP-004: Inline `#[cfg(test)]` modules in `src/` violate the
//! Santh folder contract - all micro gates live under `tests/unit/`.
//!
//! ALLOWLIST: a SMALL, explicit set of crate-private modules whose tests are
//! white-box - they assert on private fields / call `pub(crate)` items whose
//! types are deliberately NOT part of the crate's public API. Migrating those
//! tests to an external `tests/` file would force exposing the internals as
//! `pub` purely to satisfy this lint, a worse trade (Law 1 / minimal public
//! surface) than keeping the white-box tests co-located with the code they pin.
//! Every entry is reviewed and must STAY a real offender: a stale entry (file
//! removed, or its tests since migrated) fails this gate loudly, so the
//! exception can never silently outlive the reason it was granted.

use std::path::{Path, PathBuf};

#[path = "inline_gate.rs"]
mod inline_gate;

/// Crate-private modules permitted to keep co-located `#[cfg(test)]` white-box
/// tests. Paths are relative to `src/`. Keep this list SHORT and justified.
const INLINE_TEST_ALLOWLIST: &[&str] = &[
    // Region batch construction and bounded-validation helpers are crate-private
    // implementation details of the GPU trigger path. The co-located tests keep
    // those helpers private instead of widening the scanner API for white-box
    // source assertions.
    "engine/gpu_region_dispatch.rs",
    // GPU regex-DFA admission tests exercise private catalog packing, replay,
    // region attribution, and shader-program selection helpers. Keeping those
    // tests co-located preserves the crate boundary instead of making GPU
    // admission internals pub(crate) solely for test placement.
    "engine/phase2_gpu_dfa.rs",
    // The root module has test-only imports used by crate-internal unit builds.
    // These are not behavioral inline tests; moving them to `tests/` would not
    // remove source-owned test logic, only break crate-local compilation seams.
    "lib.rs",
    // Hardware-probe tests need the crate-private backend override hook and
    // live under a `testing` facade, not as hidden production behavior.
    "hw_probe/mod.rs",
    // `telemetry.rs` keeps a `#[cfg(test)] #[doc(hidden)] pub mod testing` facade
    // (`reset`/`decode_truncation_count`) for integration tests that assert visible
    // counters — plus test-only thread-local coverage-gap helpers. Its actual test
    // MODULE was migrated to `tests/unit/telemetry_serial.rs`; this facade module
    // legitimately remains in-crate (exposing it as production API would leak the
    // mutable global telemetry internals), so the general gate allowlists the file.
    "telemetry.rs",
    // `testing.rs` is the intentionally doc-hidden scanner test facade used by
    // external integration targets. Its `#[cfg(test)]` sections are facade
    // wiring, not source-local behavioral test suites.
    "testing.rs",
    // The Hyperscan scratch pool keeps private thread-local scratch state. The
    // remaining co-located test reads that private TLS count to prove scanner
    // drop evicts retained scratches; external tests cover oversubscription
    // through the narrow `testing` facade instead of keeping that larger
    // concurrency regression in production source.
    "simd/backend/scan.rs",
    // The GPU MoE wgpu dispatch is a crate-private accelerator path. Its
    // regressions drive the private `dispatch_moe_batch` and
    // `gpu_moe_parity_probe_features` directly: a per-dispatch GPU/CPU parity
    // guard and the concurrent params-buffer race reproducer (the
    // shared-batch_size clobber that aborted autoroute calibration). Both need
    // the real device dispatch, so co-locating keeps `dispatch_moe_batch` and the
    // probe builder private instead of exporting the GPU internals as `pub`
    // solely for external test placement.
    "gpu/backend.rs",
    // The repeat-run precision heuristics (`is_degenerate_repeat`,
    // `longest_repeat_run_len`, `max_repeat_run`) and the `DEGENERATE_RUN_LEN`
    // threshold are private/`pub(crate)` to the confidence layer. The co-located
    // tests pin the exact 9-vs-10 degenerate-run boundary and the byte-based
    // run/ratio semantics that deny the confidence floor to placeholders; the
    // items are deliberately not public, so external placement would force them
    // `pub` solely for the test.
    "confidence/penalties.rs",
    // The credential-context keyword loader parses its Tier-B TOML through the
    // crate-private `parse_credential_context_keywords` and exposes only a
    // `pub(crate)` accessor over a `LazyLock`. The co-located tests pin a
    // byte-identical parity against the legacy in-code array plus the fail-closed
    // validator behaviour; the parser and the embedded TOML are deliberately not
    // public, so external placement would force them `pub` solely for the test.
    "credential_context_keywords.rs",
    // The detector-catalog helper `bundled_detector_ids` is a `#[cfg(test)]`
    // `pub(crate)` corpus loader — deliberately not part of the crate's public API,
    // so an external `tests/` target cannot reach it. Its co-located tests pin the
    // memoized bundled catalog directly, instead of widening the surface to `pub`.
    // (The former `validate_rule_detector_ids` rule-file id validator was removed
    // by the DET-0 migration — no rule file carries a detector-id list anymore.)
    "detector_catalog.rs",
    // `CredentialShapeRule` keeps its length/prefix/body fields PRIVATE; the
    // co-located tests construct fixtures through the `#[cfg(test)] pub(crate)`
    // `exact_length_for_test` / `prefix_body_range_for_test` builders that set
    // those private fields directly. Those builders are irreducibly co-located -
    // they exist only to populate the private shape - so migrating the tests out
    // would force the fields (or the builders) `pub` purely for test placement.
    "credential_shapes.rs",
    // The detector-classification tests drive the crate-private
    // `parse_classification_rules` parser against the private
    // `DETECTOR_CLASSIFICATION_TOML` bundle (duplicate-id, unknown-id and
    // duplicate-prefix rejection). The parser fn and the embedded TOML are both
    // deliberately not part of the crate's public API, so external placement
    // would force exposing them `pub` solely for the test.
    "detector_classification.rs",
    // The placeholder/doc-marker tests drive the crate-private `parse_vocab`
    // parser, the private `validate_markers` helper, and the private
    // `PlaceholderVocab` fields against the bundled `placeholder_words.toml`
    // (uppercase-on-load, `_`/`-` separators, dup/empty/uppercase rejection, and
    // the parity proof that the Tier-B `[doc_markers]` lists reproduce the old
    // `INSTRUCTIONAL_FRAGMENTS` / `DOC_MARKER_SUBSTRINGS` consts exactly). The
    // parser, vocab type, and marker validator are all crate-internal — the same
    // white-box justification as other private Tier-B parsers.
    "placeholder_words.rs",
    // The assignment-keyword tests drive the crate-private `derive_assignment_keywords`
    // builder and the private `ASSIGNMENT_KEYWORDS` static (separator expansion, case
    // fold, the phase2-generic `kind` filter, cross-detector dedup, and the recall-
    // parity proof that the vocab DERIVED from the generic detector specs is a superset
    // of the 46 recall-critical prefilter triggers — plus the one-home check that no
    // second vocab source exists). Builder and static are crate-internal — same
    // white-box justification as `placeholder_words.rs`.
    "assignment_keywords.rs",
    // The scan-filter tests pin the two recall-critical no-hit prefilters
    // (`has_secret_keyword_fast`, `has_generic_assignment_keyword`) that decide
    // which no-phase-1-trigger chunks still reach phase-2 reassembly — a silent
    // drop from either list is a direct false-negative. Both fns are `pub(super)`
    // and cfg-gated behind `any(simd, gpu)`, so the behavioral lock (every curated
    // vendor prefix, the deliberately-excluded short prefixes, and the
    // case-sensitivity CONTRAST between the two gates) is white-box and stays
    // co-located rather than widening the engine's internal surface.
    "engine/scan_filters.rs",
    // The multiline secret-prefix tests drive the crate-private
    // `parse_multiline_secret_prefixes` parser and the private
    // `MULTILINE_SECRET_PREFIXES` static against the bundled
    // `multiline_secret_prefixes.toml` (case-PRESERVING validation, dup/empty
    // rejection, the deliberately-excluded short prefixes, a case-sensitive
    // AC-build proof, and byte-for-byte parity with the old inline
    // `AhoCorasick::new` array in scan_filters.rs). Parser and static are
    // crate-internal — same white-box justification as `assignment_keywords.rs`.
    "secret_prefixes.rs",
    // The Tier-B list tests drive the crate-private `parse_token_list` primitive and
    // its `ListPolicy` directly across both policies (lowercase-required vs
    // case-preserving), pinning the shared charset/dup/empty/order contract that the
    // assignment-keyword and secret-prefix loaders delegate to. The primitive and
    // policy type are crate-internal — same white-box justification as
    // `assignment_keywords.rs`.
    "tier_b_list.rs",
    // The path-filter tests pin the `pub(crate)` path classifiers
    // (`path_is_ci_workflow_file`, `path_is_i18n_file`,
    // `looks_like_raw_base64_file_path`, `looks_like_entropy_raw_base64_file_path`)
    // with direct cross-platform boundary assertions. `tests/unit/` exercises only
    // the truly-`pub` API (see `tests/unit/shape_canonical.rs`), so migrating these
    // would force the crate-internal classifiers `pub` or weaken them to indirect
    // tests - both worse than co-locating the white-box assertions.
    "suppression/path_filter.rs",
    // The canonical-shape tests pin the `pub(crate)` suppression predicates
    // (`is_structured_dotted_token`, `looks_like_dashed_serial_key`,
    // `looks_like_aws_iam_arn`, `looks_like_random_byte_base64_blob`) whose exact
    // boundary behaviour is recall-load-bearing. They are crate-internal, not the
    // public API `tests/unit/` can reach, so the direct boundary assertions stay
    // co-located instead of widening the surface or weakening to indirect tests.
    "suppression/shape/canonical.rs",
    // Sibling `suppression/shape/*` predicate modules with the SAME white-box
    // justification as `canonical.rs`: each pins one `pub(crate)` shape predicate
    // whose exact single-pass boundary is recall-load-bearing —
    // `looks_like_url_or_path_segment` (path), `looks_like_english_prose` (prose),
    // `looks_like_public_artifact_reference_with_randomness` (public). They are
    // crate-internal (not reachable from `tests/unit/`), so co-locating the
    // boundary assertions is the same correct trade the shape family already made
    // for `canonical.rs` rather than widening the suppression surface to `pub`.
    "suppression/shape/path.rs",
    "suppression/shape/prose.rs",
    "suppression/shape/public.rs",
    // `suppression/shape/source.rs` pins the `pub(crate)`
    // `looks_like_dotted_source_identifier` predicate and, critically, the
    // `CREDENTIAL_KEYWORD_NEEDLES` unification intent (a camel-cased dotted
    // candidate carrying a canonical `passwd` segment IS a source identifier) —
    // the same crate-internal shape-boundary justification as `canonical.rs`.
    "suppression/shape/source.rs",
    // `suppression/shape/mod.rs` co-locates `#[cfg(test)] pub(crate)` test seams
    // (`public_noncredential_shape`) that construct the private `PublicShapeScope`
    // dispatcher over private randomness state. Migrating would force the scope
    // type and the dispatcher `pub` purely for placement — the white-box seam
    // belongs with the shape family it fronts.
    "suppression/shape/mod.rs",
    // The windowed-support tests pin the `pub(crate)` `absolute_offset`
    // overflow-to-`None` and `absolute_line` saturation arithmetic that composes
    // base+local coordinates for windowed reassembly. The helpers live behind a
    // private `mod windowed_support`; the exact overflow/saturation boundary is a
    // crate-internal invariant, co-located rather than widening the engine API.
    "engine/windowed_support.rs",
    // The isolated-entropy floor test is a DEDUP PARITY proof: it pins that the
    // private `isolated_bare_entropy_threshold` reproduces the isolated site's
    // exact per-band resolution (default→MIXED, ≤high→MIXED, non-finite→MIXED,
    // >high→verbatim) after unifying onto the shared override owner. Parity
    // proofs over a crate-private helper justify co-location.
    "entropy/isolated.rs",
    // `entropy/bpe.rs` co-locates white-box tests for the `pub(crate)`
    // `bytes_per_token` / `is_word_like_low_bpe` BPE gate: they assert the exact
    // tiktoken bytes-per-token of the crate-private FP/secret taxonomies and the
    // strictly-`>`-than-the-owner-const suppression boundary — crate-internal
    // predicates unreachable from `tests/` (no public surface), same white-box
    // justification as `entropy/isolated.rs`.
    "entropy/bpe.rs",
    // NOTE: `entropy/plausibility.rs` was removed here — its inline `#[cfg(test)]`
    // tests were migrated to `tests/unit/entropy.rs` (they now exercise the
    // per-detector entropy-floor resolution through the PUBLIC
    // `keyhog_core::detector_spec_by_id`, so no white-box access is needed). The
    // gate's anti-staleness check (a stale allowlist entry is a hard failure)
    // enforces that this list only names files that STILL hold inline tests.
    // The weak-anchor API tests pin the private `has_broad_identifier_capture`
    // and `is_full_alpha_identifier_class` regex-shape predicates that decide
    // whether a detector's capture is too broad to trust — the exact min-length
    // ≤1 / lazy-quantifier / lookbehind boundary is recall-load-bearing and
    // crate-internal, co-located like the other suppression shape predicates.
    "suppression/api.rs",
    // `AnchoredRegex` white-box tests assert the private anchor's `start()`/`end()`
    // span semantics AND the FAIL-CLOSED compile-failure panics (no-context /
    // left-context). The panic contract can only be pinned from inside the module
    // that owns the compile path; the type's internals are not public API.
    "anchored_regex.rs",
    // `context/placeholder.rs` co-locates white-box tests for the MODULE-PRIVATE
    // placeholder predicates `is_empty_input_hash` (empty-input digest recognition
    // of every hash length) and `is_hex_sequential_placeholder` (monotonic hex
    // runs), plus the `pub(crate)` `is_monotonic_sequence_placeholder`. The private
    // predicates have no public surface, so their exact near-miss boundaries — the
    // recall-load-bearing part — can only be pinned in-module.
    "context/placeholder.rs",
    // `detector_ids.rs` pins that every corpus-backed `pub(crate)` id const names a
    // real embedded detector and that synthetic ids stay ABSENT from the TOML
    // corpus — the same crate-private catalog-integrity white-box as
    // `detector_catalog.rs`, driving `bundled_detector_ids` directly.
    "detector_ids.rs",
    // `engine/mod.rs` co-locates compile-time `Send`/`Sync` assertions over the
    // private `CompiledScanner` plus the private `MAX_INNER_LOOP_ITERS` /
    // deadline-cadence hot-loop invariants. Compile-time trait asserts are
    // irreducibly source-local; the consts are crate-internal engine details.
    "engine/mod.rs",
    // `engine/phase2/mark_stats.rs` exposes a `pub(crate)` telemetry facade
    // (`record_mark_*`, `phase2_mark_stats_reset`) over thread-local mark-gate
    // counters. Same justification as `telemetry.rs`: keeping the reset/read seam
    // in-module avoids making the mutable counter internals public API.
    "engine/phase2/mark_stats.rs",
    // `engine/phase2_generic/keywords.rs` pins the private encoded-text-secret
    // anchoring (`is_strong_keyword_anchored_encoded_text_secret`,
    // `collect_generic_keyword_lines_from_positions`) — crate-internal phase-2
    // reassembly heuristics whose boundary behaviour is recall-load-bearing.
    "engine/phase2_generic/keywords.rs",
    // `engine/rule_pipeline.rs` pins the private megascan sizing floor/cap consts
    // (`MEGASCAN_INPUT_LEN_UNKNOWN`/`_HIGH`, 128 MiB / 1 GiB) and the
    // `clamp_megascan_input_len` override clamp — crate-internal pre-compile
    // budget invariants, not public API.
    "engine/rule_pipeline.rs",
    // `engine/scan_postprocess/fragments.rs` pins the private reassembly floors
    // (`REASSEMBLY_MIN_ENTROPY` = 3.0, `REASSEMBLY_MIN_VALUE_LEN` = 16) and proves
    // the no-hit reassembly path reuses the SINGLE `reassembly_probe_data` owner
    // (a ONE-PLACE guard). Crate-internal, co-located with the owner.
    "engine/scan_postprocess/fragments.rs",
    // `engine/phase2_prefilter.rs` pins the private `hs_prefilter_engages` engine
    // gate: Hyperscan on ASCII at any size, RegexSet only on large non-ASCII. The
    // exact ASCII/size decision boundary is recall-load-bearing and the predicate
    // is module-private (no public surface), so it can only be pinned in-module.
    "engine/phase2_prefilter.rs",
    // `entropy/mod.rs` pins `operator_entropy_override` (strictly-above-high-floor
    // engagement) and the private `plausibility::*` entropy-floor consts. The
    // floors are crate-internal recall thresholds, not public API.
    "entropy/mod.rs",
    // `generic_keyword_owner.rs` is the canonical owner of `leading_assignment_key`
    // extraction; its tests pin the exact delimiter-run boundary (`=`/`:`/`~`/`.`)
    // that every generic-keyword path delegates to. Co-located with the ONE-PLACE
    // owner it defines, over crate-internal extraction internals.
    "generic_keyword_owner.rs",
    // `scanner_config.rs` pins how the `*_effective()` resolvers fall back to the
    // COMPILED defaults (`FALLBACK_*_DEFAULT`) when a knob is unset — a
    // crate-internal Tier-A default-wiring contract asserted against private
    // compiled-default consts, not the public config surface.
    "scanner_config.rs",
];

/// True iff `path` ends with an allowlisted `src/`-relative path (component-wise,
/// so it is exact and cross-platform - never a loose substring match).
fn is_allowlisted(path: &Path) -> bool {
    INLINE_TEST_ALLOWLIST
        .iter()
        .any(|rel| path.ends_with(Path::new(rel)))
}

fn scan_rust_sources(dir: &Path, offenders: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir({}) failed: {e}", dir.display()));
    for entry in entries {
        let entry =
            entry.unwrap_or_else(|e| panic!("read_dir({}) entry failed: {e}", dir.display()));
        let path = entry.path();
        if path.is_dir() {
            scan_rust_sources(&path, offenders);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()));
        let has_inline_test = inline_gate::contains_inline_test_module_or_function(&content);
        if has_inline_test {
            offenders.push(path);
        }
    }
}

#[test]
fn no_inline_tests_in_src() {
    let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    scan_rust_sources(&src_dir, &mut offenders);
    offenders.sort();

    let rel = |p: &Path| {
        p.strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(p)
            .display()
            .to_string()
    };

    // Disallowed offenders: every inline-test src file that is NOT allowlisted.
    let disallowed: Vec<String> = offenders
        .iter()
        .filter(|p| !is_allowlisted(p))
        .map(|p| rel(p))
        .collect();
    assert!(
        disallowed.is_empty(),
        "{} scanner/src files still contain #[cfg(test)] - migrate to tests/unit/:\n  - {}",
        disallowed.len(),
        disallowed.join("\n  - ")
    );

    // Stale-allowlist guard: each allowlist entry must still correspond to a real
    // inline-test offender. If a file was removed or its tests migrated, the entry
    // is dead and must be deleted - otherwise it would silently exempt a future
    // file at the same path (Law 9: no evasion; the exception must earn its place
    // every run).
    for entry in INLINE_TEST_ALLOWLIST {
        assert!(
            offenders.iter().any(|p| p.ends_with(Path::new(entry))),
            "stale INLINE_TEST_ALLOWLIST entry `{entry}`: it no longer contains an inline \
             #[cfg(test)] (file moved or tests migrated) - remove it from the allowlist",
        );
    }
}
