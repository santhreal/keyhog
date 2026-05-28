#[test]
fn read_compressed_empty() {
    let dir=tempfile::tempdir().unwrap(); let p=dir.path().join("e"); std::fs::write(&p,b"").unwrap(); let fb=keyhog_sources::testing::read_file_for_compressed_input(&p,1024).expect("ok"); assert!(fb.as_slice().is_empty());
}
