//! GPU parity tests must not silently skip when KEYHOG_REQUIRE_GPU=1.

#[test]
fn gpu_parity_sources_do_not_use_bare_skip_return() {
    let tests_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for name in [
        "gpu_parity.rs",
        "megakernel_parity.rs",
        "decode_backend_matrix.rs",
    ] {
        let path = tests_dir.join(name);
        if !path.exists() {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read test source");
        assert!(
            !src.contains("eprintln!(\"SKIP:"),
            "{name} must not SKIP-as-pass - use KEYHOG_REQUIRE_GPU gate or hard fail"
        );
    }
}
