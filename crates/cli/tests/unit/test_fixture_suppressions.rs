use keyhog::testing::{CliTestApi as _, API};

#[test]
fn bundled_loads_and_parses() {
    let s = API.bundled_test_fixture_suppressions();
    assert!(
        API.test_fixture_exact_count(&s) >= 5,
        "expected at least 5 exact entries; got {}",
        API.test_fixture_exact_count(&s),
    );
}

#[test]
fn bundled_parser_rejects_invalid_suppression_files() {
    let malformed = API
        .test_fixture_suppressions_from_toml("schema_version =")
        .expect_err("malformed test-fixture suppression TOML must fail closed");
    assert!(
        malformed.contains("invalid test-fixtures.toml"),
        "unexpected malformed error: {malformed}"
    );

    let unsupported_schema = API
        .test_fixture_suppressions_from_toml("schema_version = 2\n")
        .expect_err("unsupported test-fixture schema must fail closed");
    assert!(
        unsupported_schema.contains("schema_version"),
        "unexpected schema error: {unsupported_schema}"
    );

    let empty = API
        .test_fixture_suppressions_from_toml("schema_version = 1\n")
        .expect_err("empty test-fixture suppression file must fail closed");
    assert!(
        empty.contains("at least one entry"),
        "unexpected empty error: {empty}"
    );

    let duplicate_exact = API
        .test_fixture_suppressions_from_toml(
            "schema_version = 1\n\
         [[exact]]\ncredential = \"API_KEY_EXAMPLE\"\n\
         [[exact]]\ncredential = \"API_KEY_EXAMPLE\"\n",
        )
        .expect_err("duplicate exact suppression must fail closed");
    assert!(
        duplicate_exact.contains("duplicate exact suppression credential"),
        "unexpected duplicate exact error: {duplicate_exact}"
    );

    let blank_substring = API
        .test_fixture_suppressions_from_toml(
            "schema_version = 1\n\
         [[substring]]\nneedle = \"  \"\n",
        )
        .expect_err("blank substring suppression must fail closed");
    assert!(
        blank_substring.contains("substring suppression needles"),
        "unexpected blank substring error: {blank_substring}"
    );
}

#[test]
fn bundled_suppresses_known_demo_keys() {
    let s = API.bundled_test_fixture_suppressions();
    assert!(API.test_fixture_suppresses(&s, concat!("sk_li", "ve_4eC39HqLyjWDarjtT1zdp7dc")));
    assert!(
        API.test_fixture_suppresses(&s, concat!("gh", "p_aBcD1234EFgh5678ijklMNop9012qrSTuvWX"))
    );
    assert!(API.test_fixture_suppresses(&s, concat!("xox", "b-123456789012-1234567890123")));
    assert!(API.test_fixture_suppresses(&s, "API_KEY_EXAMPLE"));
    assert!(API.test_fixture_suppresses(&s, "PLACEHOLDER_token"));
}

#[test]
fn bundled_does_not_suppress_real_aws_key() {
    let s = API.bundled_test_fixture_suppressions();
    assert!(!API.test_fixture_suppresses(&s, concat!("AK", "IAQYLPMN5HFIQR7XYA")));
    assert!(!API.test_fixture_suppresses(&s, "just some text"));
    assert!(!API.test_fixture_suppresses(&s, ""));
}

#[test]
fn empty_never_suppresses() {
    let s = API.empty_test_fixture_suppressions();
    assert!(!API.test_fixture_suppresses(&s, concat!("sk_li", "ve_4eC39HqLyjWDarjtT1zdp7dc")));
    assert!(!API.test_fixture_suppresses(&s, "API_KEY_EXAMPLE"));
    assert_eq!(API.test_fixture_exact_count(&s), 0);
}
