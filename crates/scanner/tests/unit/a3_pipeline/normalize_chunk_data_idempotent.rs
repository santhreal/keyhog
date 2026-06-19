use keyhog_scanner::testing::normalize_chunk_data;

#[test]
fn clean_ascii_text_unchanged_by_normalize() {
    let input = "sk-proj-abc123";
    let normalized = normalize_chunk_data(input);
    assert_eq!(normalized.as_ref(), input);
}
