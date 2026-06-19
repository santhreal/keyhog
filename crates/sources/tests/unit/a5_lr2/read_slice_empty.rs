use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn read_slice_empty() {
    assert!(TestApi.slice_into_windows(&[], 64, 8).is_empty());
}
