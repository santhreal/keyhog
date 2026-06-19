use keyhog_scanner::testing::normalize_chunk_data;

#[test]
fn zero_width_char_stripped_from_credential_body() {
    let input = "sk\u{200b}proj";
    let normalized = normalize_chunk_data(input);
    assert_eq!(normalized.as_ref(), "skproj");
}
