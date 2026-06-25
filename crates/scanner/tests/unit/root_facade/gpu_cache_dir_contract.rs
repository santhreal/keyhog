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

#[test]
fn gpu_lazy_cache_failure_compiles_uncached_instead_of_disabling_matcher() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/gpu_lazy.rs"
    ))
    .expect("gpu lazy source");
    let helpers = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/gpu_lazy_helpers.rs"
    ))
    .expect("gpu lazy helper source");

    assert!(
        !src.contains("gpu_matcher_cache_dir()?"),
        "cache-dir failure must not return None from gpu_matcher()"
    );
    assert!(
        helpers.contains("GPU matcher disk cache unavailable")
            && helpers.contains("GpuLiteralSet::compile(&literal_refs)"),
        "cache-dir failure must compile the GPU literal set without disk cache"
    );
    assert!(
        helpers.contains("fn report_gpu_matcher_cache_unavailable")
            && helpers.contains("GPU_MATCHER_CACHE_UNAVAILABLE_WARNED")
            && helpers.contains("eprintln!("),
        "cache-dir failure must be visible on normal stderr, not only tracing"
    );
}
