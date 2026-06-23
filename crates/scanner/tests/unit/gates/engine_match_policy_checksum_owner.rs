//! Gate: engine checksum confidence policy has one owner.

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
fn engine_emitters_do_not_call_checksum_policy_primitives_directly() {
    let src = scanner_src();
    let owner = src.join("confidence/policy.rs");
    let owner_code = uncommented_code(&read(&owner));
    let checksum_code = uncommented_code(&read(&src.join("checksum/mod.rs")));
    for required in [
        "fn checksum_policy_for(",
        "fn apply_checksum_confidence(",
        "fn apply_checksum_decision_confidence(",
        "ChecksumConfidenceDecision::for_credential",
        "decision.result()",
        "CHECKSUM_VALID_FLOOR",
    ] {
        assert!(
            owner_code.contains(required),
            "confidence::policy must own checksum confidence handoff token {required:?}"
        );
    }
    assert!(
        checksum_code.contains("fn result(self) -> ChecksumResult")
            && checksum_code.contains(
                "crate::confidence::policy::apply_checksum_confidence(confidence, credential)"
            )
            && !checksum_code.contains(".max(CHECKSUM_VALID_FLOOR)")
            && !checksum_code.contains("fn adjusted_confidence("),
        "checksum must expose checksum facts and delegate confidence adjustment to confidence::policy"
    );

    assert!(
        !src.join("engine/scoring.rs").exists(),
        "engine::scoring facade must stay deleted"
    );

    let process = uncommented_code(&read(&src.join("engine/process.rs")));
    assert!(
        process.contains("crate::confidence::policy::checksum_policy_for("),
        "engine process must ask confidence::policy directly for checksum confidence policy"
    );

    let mut files = Vec::new();
    collect_rs_files(&src.join("engine"), &mut files);
    let mut offenders = Vec::new();
    for path in files {
        let code = uncommented_code(&read(&path));
        for forbidden in [
            "checksum::checksum_adjusted_confidence",
            "checksum::validate_checksum",
            "checksum::CHECKSUM_VALID_FLOOR",
            "ChecksumConfidenceDecision::for_credential",
            ".adjusted_confidence(",
        ] {
            if code.contains(forbidden) {
                offenders.push(format!("{} contains {forbidden}", path.display()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "engine emission paths must route checksum confidence through confidence::policy without owning primitives: {offenders:#?}"
    );
}
