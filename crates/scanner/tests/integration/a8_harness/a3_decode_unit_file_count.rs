//! LR2-A8 harness integration: a3_decode unit slice preserved

#[test]
fn a3_decode_has_at_least_twenty_five_tests() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/unit/a3_decode");
    let n = std::fs::read_dir(dir).unwrap().filter(|e| {
        e.as_ref().unwrap().path().extension().map(|x| x == "rs").unwrap_or(false)
    }).count();
    assert!(n >= 25, "expected >=25 a3_decode unit tests, got {n}");
}
