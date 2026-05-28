//! KH-GAP-143: Handwritten top50 near-miss twins must reach floor 50.

use std::path::PathBuf;

fn count_top50_near_miss(adv: &PathBuf) -> usize {
    std::fs::read_dir(adv)
        .expect("adversarial dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.starts_with("top50_") && name.contains("_near_miss") && name.ends_with(".rs")
        })
        .count()
}

#[test]
fn r5_near_miss_handwritten_twin_floor_50() {
    let adv = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial");
    let count = count_top50_near_miss(&adv);
    assert!(count >= 50, "KH-GAP-143: floor 50, got {count}");
}
