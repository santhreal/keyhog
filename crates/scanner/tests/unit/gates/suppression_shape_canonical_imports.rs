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

#[test]
fn legacy_shape_gate_module_homes_do_not_return() {
    let src = scanner_src();
    let legacy_root = src.join("suppression/shape.rs");
    let legacy_gates = src.join("suppression/shape_gates.rs");
    assert!(
        !legacy_root.exists(),
        "{} must stay moved to suppression/shape/mod.rs",
        legacy_root.display()
    );
    assert!(
        !legacy_gates.exists(),
        "{} must stay moved under suppression/shape/",
        legacy_gates.display()
    );

    let shape_mod = src.join("suppression/shape/mod.rs");
    let canonical = src.join("suppression/shape/canonical.rs");
    assert!(shape_mod.exists(), "{} is missing", shape_mod.display());
    assert!(canonical.exists(), "{} is missing", canonical.display());

    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);
    let mut offenders = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(&src)
            .expect("scanner src path")
            .to_string_lossy()
            .replace('\\', "/");
        let code = uncommented_code(&read(&path));
        for forbidden in [
            "mod shape_gates",
            "shape_gates::",
            "suppression::shape_gates",
        ] {
            if code.contains(forbidden) {
                offenders.push(format!("{rel} contains {forbidden}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "legacy shape-gate owner returned:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn entropy_keywords_does_not_own_shape_predicates() {
    let src = scanner_src();
    let entropy_keywords = read(&src.join("entropy/keywords.rs"));
    let mut offenders = Vec::new();

    for forbidden in [
        "fn looks_like_english_prose",
        "fn entropy_value_looks_like_prose",
        "fn looks_like_program_identifier",
        "fn looks_like_dotted_source_identifier",
        "fn is_dash_segmented_alnum_decoy",
    ] {
        if entropy_keywords.contains(forbidden) {
            offenders.push(format!("entropy/keywords.rs defines {forbidden}"));
        }
    }

    let shape_mod = read(&src.join("suppression/shape/mod.rs"));
    for required in [
        "looks_like_english_prose",
        "looks_like_program_identifier",
        "looks_like_dotted_source_identifier",
        "is_dash_segmented_alnum_decoy",
    ] {
        if !shape_mod.contains(required) {
            offenders.push(format!(
                "suppression/shape/mod.rs does not re-export {required}"
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "shape predicates leaked back into entropy keywords:\n{}",
        offenders.join("\n")
    );
}
