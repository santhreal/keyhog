//! GPU parity tests must not silently skip when GPU runtime policy is required.

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
            "{name} must not SKIP-as-pass - use the require-GPU policy gate or hard fail"
        );
    }
}

#[test]
fn gpu_ac_recall_test_does_not_pin_personal_corpus_path() {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/gpu_ac_recall_bug_56.rs");
    let src = std::fs::read_to_string(&path).expect("read gpu AC recall test source");
    assert!(
        !src.contains("/media/mukund-thiru/SanthData/keyhog-bench-corpora"),
        "gpu AC recall regression must not depend on one developer's corpus path"
    );
    assert!(
        src.contains("KEYHOG_GPU_AC_RECALL_CORPUS"),
        "gpu AC recall regression must advertise the explicit corpus env override"
    );
    assert!(
        src.contains("benchmarks/corpora/gpu_ac_recall"),
        "gpu AC recall regression must have a repo-relative corpus fallback"
    );
}
