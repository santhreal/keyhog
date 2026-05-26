//! KH-GAP-014: pipeline god-file split — total pipeline module LOC under LR2 phase-1 budget.

use std::path::{Path, PathBuf};

fn dir_line_count(dir: &Path) -> usize {
    let mut total = 0usize;
    for entry in
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir({}) failed: {e}", dir.display()))
    {
        let path = entry.unwrap().path();
        if path.is_dir() {
            total += dir_line_count(&path);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            total += std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()))
                .lines()
                .count();
        }
    }
    total
}

#[test]
fn pipeline_module_loc_below_lr2_phase1_budget() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let pipeline_dir = manifest.join("src/pipeline");
    let total = dir_line_count(&pipeline_dir);
    const BUDGET: usize = 1400;
    assert!(
        total <= BUDGET,
        "src/pipeline/ is {total} LOC — exceeds LR2-A3 phase-1 budget {BUDGET}; \
         further splits deferred to LR3"
    );
}
