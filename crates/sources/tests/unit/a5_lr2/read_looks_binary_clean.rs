use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn read_looks_binary_clean() {
    assert!(!TestApi.looks_binary("hello world\n".repeat(100).as_bytes()));
}
