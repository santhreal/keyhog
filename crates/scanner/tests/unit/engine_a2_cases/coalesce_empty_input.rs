use keyhog_scanner::engine::coalesce_chunks;
#[test]
fn coalesce_empty_input() {
    let (e, b) = coalesce_chunks(&[]);
    assert!(e.is_empty() && b.is_empty());
}
