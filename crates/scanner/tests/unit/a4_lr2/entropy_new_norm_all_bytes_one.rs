#[test]
fn entropy_new_norm_all_bytes_one() {
    let b: Vec<u8> = (0u8..=255).collect();
    let e = keyhog_scanner::entropy::normalized_entropy(&b);
    assert!(e <= 1.0, "got {e}");
}
