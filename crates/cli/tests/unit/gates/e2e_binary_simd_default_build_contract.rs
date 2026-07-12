#[test]
fn e2e_binary_simd_progress_probe_is_default_build_safe() {
    let source = include_str!("../../e2e_binary.rs");
    let helper_body = source
        .split("fn forced_simd_progress_banner()")
        .nth(1)
        .expect("forced_simd_progress_banner helper must exist")
        .split("fn parse_banner_counts(")
        .next()
        .expect("forced_simd_progress_banner helper boundary must exist");

    assert!(
        helper_body.contains("\"--backend\"") && helper_body.contains("\"simd\""),
        "e2e_binary progress-banner probe must keep explicit SIMD backend evidence"
    );
    assert!(
        helper_body.contains("--cache-dir"),
        "the default-build SIMD probe must exercise the Hyperscan cache surface; the CLI default enables its own simd cfg"
    );

    let test_body = source
        .split("fn docs_scan_banners_match_live_binary_banner_contract()")
        .nth(1)
        .expect("docs banner binary contract test must exist");
    assert!(
        test_body.contains("forced_simd_progress_banner()"),
        "the default-build e2e banner contract must continue to exercise the forced SIMD progress probe"
    );
}
