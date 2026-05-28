#[test]
fn sources_cap_oracle_17() {
    let cap = keyhog_sources::testing::max_buffered_read_bytes();
    assert!(cap >= 64 * 1024, "cap must be at least 64KiB, got {cap}");
    assert!(cap <= 2 * 1024 * 1024 * 1024u64, "cap must not exceed 2GiB sanity bound");
}
