use keyhog_scanner::testing::gpu_matcher_cache_dir_from_base;

#[test]
fn gpu_matcher_cache_dir_missing_base_is_loud_error() {
    let error = gpu_matcher_cache_dir_from_base(None).expect_err("missing cache base must error");

    assert_eq!(error, "no user cache directory is available");
}

#[test]
fn gpu_matcher_cache_dir_create_failure_is_loud_error() {
    let root = tempfile::tempdir().expect("tempdir");
    let file_parent = root.path().join("not-a-directory");
    std::fs::write(&file_parent, b"x").expect("seed file parent");

    let error = gpu_matcher_cache_dir_from_base(Some(file_parent.clone()))
        .expect_err("file parent cannot host cache directory");

    assert!(
        error.contains("failed to create GPU matcher cache dir"),
        "cache mkdir failure must name the operation: {error}"
    );
    assert!(
        error.contains(&file_parent.display().to_string()),
        "cache mkdir failure must name the bad path: {error}"
    );
}
