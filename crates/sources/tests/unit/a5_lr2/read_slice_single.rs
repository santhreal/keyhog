use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn read_slice_single() {
    let ws = TestApi.slice_into_windows(b"abc", 64, 8); assert_eq!(ws.len(), 1);
}
