//! LR2-A8 harness integration: a3_multiline unit slice preserved

#[test]
fn a3_multiline_has_at_least_thirteen_tests() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/unit/a3_multiline");
    let n = std::fs::read_dir(dir).unwrap().filter(|e| {
        e.as_ref().unwrap().path().extension().map(|x| x == "rs").unwrap_or(false)
    }).count();
    assert!(n >= 13, "expected >=13 a3_multiline unit tests, got {n}");
}
