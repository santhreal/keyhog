use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn sources_cap_oracle_05() {
    let cap = TestApi.max_buffered_read_bytes();
    assert!(cap >= 64 * 1024, "cap must be at least 64KiB, got {cap}");
    assert!(cap <= 2 * 1024 * 1024 * 1024u64, "cap must not exceed 2GiB sanity bound");
}
