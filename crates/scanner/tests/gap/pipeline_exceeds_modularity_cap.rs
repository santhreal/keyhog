//! KH-GAP-014 (LR2-A3): monolithic `pipeline.rs` replaced by `src/pipeline/` modules.
//! Phase-1 cap: no single pipeline submodule file exceeds 800 LOC.

use std::path::{Path, PathBuf};

fn count_lines(path: &Path) -> usize {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()))
        .lines()
        .count()
}

fn scan_pipeline_dir(dir: &Path, offenders: &mut Vec<(PathBuf, usize)>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir({}) failed: {e}", dir.display())) {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            scan_pipeline_dir(&path, offenders);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let lines = count_lines(&path);
        const PHASE1_CAP: usize = 800;
        if lines > PHASE1_CAP {
            offenders.push((path, lines));
        }
    }
}

#[test]
fn pipeline_split_no_monolith_and_submodules_under_cap() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let monolith = manifest.join("src/pipeline.rs");
    assert!(
        !monolith.exists(),
        "monolithic src/pipeline.rs must be removed after LR2-A3 split"
    );

    let pipeline_dir = manifest.join("src/pipeline");
    assert!(pipeline_dir.is_dir(), "src/pipeline/ directory must exist");

    for required in ["context_window.rs", "scan_loop.rs", "postprocess"] {
        let path = pipeline_dir.join(required);
        assert!(path.exists(), "missing pipeline submodule {required}");
    }

    let mut offenders = Vec::new();
    scan_pipeline_dir(&pipeline_dir, &mut offenders);
    assert!(
        offenders.is_empty(),
        "pipeline submodule files exceed 800 LOC phase-1 cap:\n  - {}",
        offenders
            .iter()
            .map(|(p, n)| format!("{} ({n} lines)", p.display()))
            .collect::<Vec<_>>()
            .join("\n  - ")
    );
}
