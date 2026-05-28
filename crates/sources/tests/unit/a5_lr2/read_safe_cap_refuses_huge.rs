#[test]
fn read_safe_cap_refuses_huge() {
    let dir=tempfile::tempdir().unwrap(); let p=dir.path().join("big"); std::fs::write(&p, vec![0u8; 8192]).unwrap(); let r=keyhog_sources::testing::read_file_safe_capped(&p, 1024); assert!(r.is_err() || r.unwrap().len() <= 1024);
}
