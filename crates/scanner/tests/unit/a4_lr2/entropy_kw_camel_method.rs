#[test]
fn entropy_kw_camel_method() {
    let val = "convertSearchHitToVersionedApiKeyDoc";
    assert!(keyhog_scanner::testing::looks_like_program_identifier(val));
}
