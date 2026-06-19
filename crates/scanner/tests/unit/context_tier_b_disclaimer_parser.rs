use keyhog_scanner::testing::context::parse_disclaimer_phrases_for_test;

#[test]
fn disclaimer_phrase_tier_b_parser_rejects_invalid_vocabularies() {
    let empty = parse_disclaimer_phrases_for_test("schema_version = 1\nphrases = []\n")
        .expect_err("empty disclaimer phrase list must fail closed");
    assert!(
        empty.contains("at least one entry"),
        "unexpected empty-list error: {empty}"
    );

    let unsupported_schema =
        parse_disclaimer_phrases_for_test("schema_version = 2\nphrases = [\"not a real\"]\n")
            .expect_err("unsupported disclaimer phrase schema must fail closed");
    assert!(
        unsupported_schema.contains("schema_version"),
        "unexpected schema error: {unsupported_schema}"
    );

    let uppercase =
        parse_disclaimer_phrases_for_test("schema_version = 1\nphrases = [\"Not a real\"]\n")
            .expect_err("uppercase disclaimer phrase must fail closed");
    assert!(
        uppercase.contains("lowercase ASCII"),
        "unexpected uppercase error: {uppercase}"
    );

    let duplicate = parse_disclaimer_phrases_for_test(
        "schema_version = 1\nphrases = [\"not a real\", \"not a real\"]\n",
    )
    .expect_err("duplicate disclaimer phrase must fail closed");
    assert!(
        duplicate.contains("duplicate disclaimer phrase"),
        "unexpected duplicate error: {duplicate}"
    );
}
