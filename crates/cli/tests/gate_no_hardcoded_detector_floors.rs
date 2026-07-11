//! GATE: no hardcoded per-detector confidence floor may reappear in code.
//!
//! The user's core complaint is detection knobs scattered across the codebase.
//! A per-detector confidence floor MUST live in that detector's own
//! `detectors/<id>.toml` (`min_confidence`), never in a hardcoded Rust map.
//! This gate fails if either retired Rust override list reappears, pointing the
//! change back to the detector TOML so the one-owner invariant cannot rot.
//!
//! Source is embedded at compile time via `include_str!`, so the check is
//! CWD-independent (no raw-test-binary working-directory pitfalls) and needs no
//! runtime access to the private `const`.

const POLICY_SRC: &str = include_str!("../src/config/policy.rs");

#[test]
fn shipped_detector_floor_override_list_does_not_exist() {
    assert!(
        !POLICY_SRC.contains("SHIPPED_DETECTOR_FLOORS"),
        "a per-detector confidence floor belongs in detectors/<id>.toml, not a Rust list"
    );
}

#[test]
fn shipped_detector_disable_override_list_does_not_exist() {
    assert!(
        !POLICY_SRC.contains("SHIPPED_DISABLED_DETECTORS"),
        "shipped detector availability belongs in detector data, not a Rust disable list"
    );
}

/// The entropy-floor table's source of truth. Embedded at compile time so the
/// check needs no runtime access and no CWD.
const ENTROPY_FLOORS_SRC: &str = include_str!("../../scanner/src/entropy_floors.rs");

#[test]
fn entropy_floor_table_is_built_from_specs_not_a_resurrected_floor_file() {
    // The floors moved into each detector's own TOML (`entropy_floor` buckets);
    // the runtime table is derived from the embedded corpus specs. Guard against
    // a second source of truth reappearing: no `include_str!` of an
    // `entropy-floors` data file, and the spec-derived builder must still be used.
    let resurrected_file = ENTROPY_FLOORS_SRC
        .lines()
        .any(|l| l.contains("include_str!") && l.contains("entropy-floors"));
    assert!(
        !resurrected_file,
        "entropy_floors.rs must NOT `include_str!` a separate `entropy-floors` file — the \
         floors live in each detector's own `detectors/<id>.toml` (`entropy_floor`). A second \
         floor source is exactly the scattered-settings regression this gate prevents."
    );
    assert!(
        ENTROPY_FLOORS_SRC.contains("from_specs"),
        "entropy_floors.rs must build the floor table from the embedded detector specs \
         (`from_specs`); if that builder is gone, the single-source-of-truth is broken."
    );
}
