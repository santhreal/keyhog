/// The default-build banner E2E must use the backend every published build contains.
#[test]
fn e2e_progress_probe_uses_always_compiled_portable_backend() {
    let source = include_str!("../../e2e_binary.rs");
    let helper_body = source
        .split("fn portable_progress_banner()")
        .nth(1)
        .expect("portable_progress_banner helper must exist")
        .split("fn parse_banner_counts(")
        .next()
        .expect("portable_progress_banner helper boundary must exist");

    assert!(
        helper_body.contains("\"--backend\"")
            && helper_body.contains("FUNCTIONAL_E2E_BACKEND")
            && helper_body.contains("\"--no-config\""),
        "the default-build banner probe must isolate config and select the portable test backend"
    );
    assert!(
        !helper_body.contains("--cache-dir") && !helper_body.contains("\"simd\""),
        "the portable default-build probe must not require optional Hyperscan surfaces"
    );

    let test_body = source
        .split("fn docs_scan_banners_match_live_binary_banner_contract()")
        .nth(1)
        .expect("docs banner binary contract test must exist");
    assert!(
        test_body.contains("portable_progress_banner()"),
        "the banner contract must continue to execute the portable progress probe"
    );
}
