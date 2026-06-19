use keyhog::exit_codes::{
    EXIT_LIVE_CREDENTIALS, EXIT_REQUIRE_GPU_UNMET, EXIT_SCANNER_PANIC, EXIT_SOURCE_FAILED,
};

#[test]
fn scan_exit_constants_match_product_contract() {
    assert_eq!(EXIT_LIVE_CREDENTIALS, 10);
    assert_eq!(EXIT_SCANNER_PANIC, 11);
    assert_eq!(EXIT_REQUIRE_GPU_UNMET, 12);
    assert_eq!(EXIT_SOURCE_FAILED, 13);
}
