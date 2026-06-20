//! Gate `engine::phase2_compiled`: phase-2 profile route labels must describe
//! the live compiled route, not a looser parser-only prefix shape.

#[test]
fn engine_phase2_profile_route_truth() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/phase2_compiled.rs");
    let src = std::fs::read_to_string(path).expect("phase2_compiled source readable");
    assert!(
        src.contains("idx.is_eligible(*i)")
            && src.contains("[LOCAL]=live shared-anchor localized")
            && src.contains("[PREFIX]=prefix-shaped but whole-window in this scanner"),
        "phase2 profile must label live shared-anchor eligibility separately from prefix shape"
    );
    assert!(
        !src.contains("if anchored { \"ANCHOR\" }"),
        "phase2 profile must not report parser-only prefix shape as live ANCHOR route"
    );
}
