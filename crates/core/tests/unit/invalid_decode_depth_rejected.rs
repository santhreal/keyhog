//! Migrated from `src/config.rs` - decode depth above cap is rejected.

use keyhog_core::ScanConfig;

#[test]
fn invalid_decode_depth_rejected() {
    let config = ScanConfig {
        max_decode_depth: keyhog_core::testing::CoreTestApi::max_decode_depth_limit(
            &keyhog_core::testing::TestApi,
        ) + 1,
        ..Default::default()
    };
    let err = keyhog_core::testing::CoreTestApi::scan_config_validate(
        &keyhog_core::testing::TestApi,
        &config,
    )
    .expect_err("depth above limit must fail");
    assert!(
        err.to_string().contains("max_decode_depth"),
        "expected depth error, got: {err}"
    );
}
