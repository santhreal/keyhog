use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn read_slice_two_windows() {
    let b: Vec<u8> = (0..65u8).collect(); let ws = TestApi.slice_into_windows(&b, 64, 8); assert_eq!(ws.len(), 2);
}
