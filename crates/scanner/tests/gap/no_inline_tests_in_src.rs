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
    // Hardware-probe tests need the crate-private backend override hook and
    // live under a `testing` facade, not as hidden production behavior.
    "hw_probe/mod.rs",
    // `telemetry.rs` keeps a `#[cfg(test)] #[doc(hidden)] pub mod testing` facade
    // (`reset`/`decode_truncation_count`) for integration tests that assert visible
    // counters, plus test-only thread-local coverage-gap helpers. Its actual test
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
    // The detector-catalog helper `bundled_detector_ids` is a `#[cfg(test)]`
    // `pub(crate)` corpus loader, deliberately not part of the crate's public API,
    // so an external `tests/` target cannot reach it. Its co-located tests pin the
    // memoized bundled catalog directly, instead of widening the surface to `pub`.
    // (The former `validate_rule_detector_ids` rule-file id validator was removed
    // by the DET-0 migration, no rule file carries a detector-id list anymore.)
    "detector_catalog.rs",
    // `engine/backend_prepared.rs` co-locates white-box tests for the `pub(crate)`
    // `PreparedChunk::code_lines` (KH-1226): they construct a `PreparedChunk` over
    // its `pub(crate)` fields (`chunk`, `preprocessed`, `line_offsets`) via the
    // `pub(crate) ScannerPreprocessedText::passthrough` constructor and assert that
    // `code_lines` slices `preprocessed.text` (the buffer `line_offsets` was
    // computed on) even when preprocessing rewrote the bytes. `PreparedChunk`, its
    // fields, and `code_lines` are crate-internal, so external placement would
    // force them `pub` solely for the test - the same white-box trade as the
    // other `engine/*` entries.
    "engine/backend_prepared.rs",
    // Sibling `suppression/shape/*` predicate modules with the SAME white-box
    // justification as `canonical.rs`: each pins one `pub(crate)` shape predicate
    // whose exact single-pass boundary is recall-load-bearing
    // `looks_like_url_or_path_segment` (path), `looks_like_english_prose` (prose),
    // `looks_like_public_artifact_reference_with_randomness` (public). They are
    // crate-internal (not reachable from `tests/unit/`), so co-locating the
    // boundary assertions is the same correct trade the shape family already made
    // for `canonical.rs` rather than widening the suppression surface to `pub`.
    "suppression/shape/path.rs",
    "suppression/shape/prose.rs",
    "suppression/shape/public.rs",
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
    // NOTE: `entropy/plausibility.rs` was removed here, its inline `#[cfg(test)]`
    // tests were migrated to `tests/unit/entropy.rs` (they now exercise the
    // per-detector entropy-floor resolution through the PUBLIC
    // `keyhog_core::detector_spec_by_id`, so no white-box access is needed). The
    // gate's anti-staleness check (a stale allowlist entry is a hard failure)
    // enforces that this list only names files that STILL hold inline tests.
    // The suppression API tests exercise its crate-private typed contexts and
    // stage results directly.
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
    // predicates have no public surface, so their exact near-miss boundaries, the
    // recall-load-bearing part (can only be pinned in-module).
    "context/placeholder.rs",
    // `detector_ids.rs` pins that every corpus-backed `pub(crate)` id const names a
    // real embedded detector and that synthetic ids stay ABSENT from the TOML
    // corpus, the same crate-private catalog-integrity white-box as
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
    // `collect_generic_keyword_lines_from_positions`), crate-internal phase-2
    // reassembly heuristics whose boundary behaviour is recall-load-bearing.
    "engine/phase2_generic/keywords.rs",
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
    // `scanner_config.rs` pins how the `*_effective()` resolvers fall back to the
    // COMPILED defaults (`FALLBACK_*_DEFAULT`) when a knob is unset, a
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
