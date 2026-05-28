//! KH-GAP-161: R5 adversarial rs file total floor.

use std::path::PathBuf;

fn count_rs(root: &PathBuf) -> usize {
    let mut n = 0;
    for entry in std::fs::read_dir(root).expect("read_dir") {
        let entry = entry.expect("entry");
        let path = entry.path();
        if path.is_dir() {
            n += count_rs(&path);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            n += 1;
        }
    }
    n
}

#[test]
fn r5_adversarial_expansion_total_floor_155() {
    let adv = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial");
    let count = count_rs(&adv);
    assert!(count >= 155, "KH-GAP-161: adversarial rs floor 155, got {count}");
}
