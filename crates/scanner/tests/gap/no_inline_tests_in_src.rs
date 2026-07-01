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
    // Telemetry exposes a test-only reset/read facade for integration tests that
    // assert visible counters. Keeping the facade in-module avoids making the
    // mutable global telemetry internals public production API.
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
    // The entropy-floor tests drive the crate-private `parse_entropy_floors`
    // parser and the private `EntropyFloorTable::family_floor` lookup against the
    // private `ENTROPY_FLOORS_TOML` bundle (bucket ordering, catch-all placement,
    // and the parity proof that the Tier-B table reproduces the old hardcoded
    // floors exactly). The parser, table type, and embedded TOML are all
    // crate-internal, so external placement would force them `pub` solely for the
    // test — the same white-box justification as `detector_classification.rs`.
    "entropy_floors.rs",
    // The placeholder/doc-marker tests drive the crate-private `parse_vocab`
    // parser, the private `validate_markers` helper, and the private
    // `PlaceholderVocab` fields against the bundled `placeholder_words.toml`
    // (uppercase-on-load, `_`/`-` separators, dup/empty/uppercase rejection, and
    // the parity proof that the Tier-B `[doc_markers]` lists reproduce the old
    // `INSTRUCTIONAL_FRAGMENTS` / `DOC_MARKER_SUBSTRINGS` consts exactly). The
    // parser, vocab type, and marker validator are all crate-internal — the same
    // white-box justification as `entropy_floors.rs`.
    "placeholder_words.rs",
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
