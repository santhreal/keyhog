use keyhog_scanner::testing::normalize_chunk_data;
use std::borrow::Cow;

#[test]
fn clean_non_ascii_text_is_borrowed_without_rebuild() {
    let input = "caf\u{00e9}=plain";
    let normalized = normalize_chunk_data(input);
    match normalized {
        Cow::Borrowed(value) => assert_eq!(value.as_ptr(), input.as_ptr()),
        Cow::Owned(value) => panic!("clean non-ASCII text allocated: {value:?}"),
    }
}
