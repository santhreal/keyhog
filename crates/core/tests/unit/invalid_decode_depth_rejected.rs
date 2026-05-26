//! Migrated from `src/config.rs` — decode depth above cap is rejected.

use keyhog_core::{ScanConfig, MAX_DECODE_DEPTH_LIMIT};

#[test]
fn invalid_decode_depth_rejected() {
    let config = ScanConfig {
        max_decode_depth: MAX_DECODE_DEPTH_LIMIT + 1,
        ..Default::default()
    };
    let err = config.validate().expect_err("depth above limit must fail");
    assert!(
        err.to_string().contains("max_decode_depth"),
        "expected depth error, got: {err}"
    );
}
