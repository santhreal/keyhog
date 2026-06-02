#[test]
fn sanitize_oob_value_uppercase_folding() {
    // Uppercase ASCII must be folded to lowercase. DNS is case-insensitive,
    // and the sanitized value must use a canonical form.
    let input = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let result = keyhog_verifier::testing::sanitize_oob_value(input);

    // All uppercase must be folded to lowercase
    assert_eq!(result, "abcdefghijklmnopqrstuvwxyz");

    // No uppercase characters remain
    assert!(!result.chars().any(|c| c.is_ascii_uppercase()));
}
