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
    // The detector-catalog helper `bundled_detector_ids` is a `#[cfg(test)]`
    // `pub(crate)` corpus loader, deliberately not part of the crate's public API,
    // so an external `tests/` target cannot reach it. Its co-located tests pin the
    // memoized bundled catalog directly, instead of widening the surface to `pub`.
    // (The former `validate_rule_detector_ids` rule-file id validator was removed
    // by the DET-0 migration, no rule file carries a detector-id list anymore.)
    "detector_catalog.rs",
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
    // `engine/phase2/mark_stats.rs` exposes a `pub(crate)` telemetry facade
    // (`record_mark_*`, `take_mark_stats`) over the profile runtime's typed
    // counters. Same justification as `telemetry.rs`: keeping the record/read
    // seam in-module avoids making the counter plumbing public API.
    "engine/phase2/mark_stats.rs",
    // `engine/scan_postprocess/fragments.rs` pins the private reassembly floors
    // (`REASSEMBLY_MIN_ENTROPY` = 3.0, `REASSEMBLY_MIN_VALUE_LEN` = 16) and proves
    // the no-hit reassembly path reuses the SINGLE `reassembly_probe_data` owner
    // (a ONE-PLACE guard). Crate-internal, co-located with the owner.
    "engine/scan_postprocess/fragments.rs",
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
