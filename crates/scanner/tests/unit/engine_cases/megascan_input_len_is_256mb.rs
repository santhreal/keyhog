use keyhog_scanner::engine::MEGASCAN_INPUT_LEN;
#[test]
fn megascan_input_len_is_256mb() {
    assert_eq!(MEGASCAN_INPUT_LEN, 256 * 1024 * 1024);
}
