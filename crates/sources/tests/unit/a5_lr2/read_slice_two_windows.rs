#[test]
fn read_slice_two_windows() {
    let b: Vec<u8> = (0..65u8).collect(); let ws = keyhog_sources::testing::slice_into_windows(&b, 64, 8); assert_eq!(ws.len(), 2);
}
