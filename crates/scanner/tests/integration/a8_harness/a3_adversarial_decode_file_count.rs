//! LR2-A8 harness integration: a3 adversarial decode preserved

#[test]
fn a3_adversarial_decode_has_five_tests() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial/a3_decode");
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
    assert_eq!(n, 5, "expected five a3_decode adversarial tests, got {n}");
}
