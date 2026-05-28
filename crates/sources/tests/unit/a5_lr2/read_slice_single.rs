#[test]
fn read_slice_single() {
    let ws = keyhog_sources::testing::slice_into_windows(b"abc", 64, 8); assert_eq!(ws.len(), 1);
}
