#[test]
fn entropy_kw_pascal_java_class() {
    let val = "BulkUpdateApiKeyResponse";
    assert!(keyhog_scanner::testing::looks_like_program_identifier(val));
}
