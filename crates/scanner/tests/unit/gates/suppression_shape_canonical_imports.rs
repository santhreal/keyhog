//! Gate: shape and path suppression predicates use their owner modules.

use std::path::{Path, PathBuf};

fn scanner_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{} not readable: {e}", path.display()))
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{} not readable: {e}", dir.display()))
    {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn uncommented_code(src: &str) -> String {
    src.lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                None
            } else {
                Some(line)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn shape_predicates_do_not_route_through_pipeline_or_suppression_root() {
    let mut files = Vec::new();
    collect_rs_files(&scanner_src(), &mut files);
    let mut offenders = Vec::new();

    for path in files {
        let rel = path
            .strip_prefix(scanner_src())
            .expect("scanner src path")
            .to_string_lossy()
            .replace('\\', "/");
        if rel.starts_with("suppression/") || rel == "pipeline/mod.rs" {
            continue;
        }
        let code = uncommented_code(&read(&path));
        for forbidden in [
            "crate::pipeline::looks_like_",
            "crate::pipeline::contains_uuid_v4_substring",
        ] {
            if code.contains(forbidden) {
                offenders.push(format!("{rel} contains {forbidden}"));
            }
        }
        if code.contains("crate::suppression::looks_like_")
            || code.contains("crate::suppression::contains_uuid_v4_substring")
        {
            offenders.push(format!(
                "{rel} imports shape predicates through suppression root"
            ));
        }
    }

    let pipeline = read(&scanner_src().join("pipeline/mod.rs"));
    for forbidden in ["looks_like_", "contains_uuid_v4_substring"] {
        if pipeline.contains(forbidden) {
            offenders.push(format!("pipeline/mod.rs still re-exports {forbidden}"));
        }
    }

    assert!(
        offenders.is_empty(),
        "shape/path suppression predicates must use suppression::shape or suppression::path_filter: {offenders:#?}"
    );
}
