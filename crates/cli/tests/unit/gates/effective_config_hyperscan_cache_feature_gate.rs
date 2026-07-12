#[test]
fn effective_config_hyperscan_cache_success_test_is_simd_gated() {
    let source = include_str!("../../e2e/scan_effective_config.rs");
    let before_test = source
        .split("fn config_effective_prints_hyperscan_cache_dir_and_cli_overrides_toml(")
        .next()
        .expect("hyperscan cache effective-config test must exist");
    let attrs = before_test
        .rsplit_once("#[test]")
        .map(|(_, attrs)| attrs)
        .expect("hyperscan cache effective-config test must be a Rust test");

    assert!(
        attrs.contains("#[cfg(feature = \"simd\")]"),
        "the effective-config test that expects --cache-dir success must be \
         gated on feature=simd so portable and accelerator-free builds remain \
         valid; the default build enables this feature"
    );
}
