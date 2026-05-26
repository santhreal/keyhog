//! LR2-A8 harness integration: a3_pipeline unit slice preserved

#[test]
fn a3_pipeline_has_at_least_sixteen_tests() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/unit/a3_pipeline");
    let n = std::fs::read_dir(dir)
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .path()
                .extension()
                .map(|x| x == "rs")
                .unwrap_or(false)
        })
        .count();
    assert!(n >= 16, "expected >=16 a3_pipeline unit tests, got {n}");
}
