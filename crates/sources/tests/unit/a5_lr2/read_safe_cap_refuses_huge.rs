use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn read_safe_cap_refuses_huge() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("big");
    std::fs::write(&p, vec![0u8; 8192]).unwrap();
    let r = TestApi.read_file_safe_capped(&p, 1024);
    let err = r.expect_err("over-cap buffered read must fail loud");
    let message = err.to_string();
    assert!(
        message.contains("filesystem buffered read exceeded stat-time 1024 byte cap"),
        "over-cap buffered read must explain the stat-time cap, got {message}"
    );
}
