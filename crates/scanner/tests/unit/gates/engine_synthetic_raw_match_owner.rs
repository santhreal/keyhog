//! Gate: synthetic engine matches use one RawMatch construction owner.

use std::path::{Path, PathBuf};

fn scanner_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{} not readable: {e}", path.display()))
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
fn synthetic_engine_matches_route_through_shared_builder() {
    let src = scanner_src();
    let postprocess = uncommented_code(&read(&src.join("pipeline/postprocess/mod.rs")));
    assert!(
        postprocess.contains("fn build_synthetic_raw_match(")
            && postprocess.contains("companions: HashMap::new()")
            && postprocess.contains("credential_hash: crate::sha256_hash(credential)")
            && postprocess.contains("credential: scan_state.intern_credential(credential)"),
        "pipeline::postprocess must own synthetic RawMatch construction"
    );

    for path in ["engine/phase2_entropy.rs", "engine/phase2_generic.rs"] {
        let code = uncommented_code(&read(&src.join(path)));
        assert!(
            code.contains("build_synthetic_raw_match("),
            "{path} must call the shared synthetic RawMatch builder"
        );
        for forbidden in [
            "RawMatch {",
            "MatchLocation {",
            "credential_hash: crate::sha256_hash",
            "credential: scan_state.intern_credential",
        ] {
            assert!(
                !code.contains(forbidden),
                "{path} must not own synthetic RawMatch construction token {forbidden:?}"
            );
        }
    }

    let hot_patterns = uncommented_code(&read(&src.join("engine/hot_patterns.rs")));
    assert!(
        hot_patterns.contains("self.process_match(")
            && !hot_patterns.contains("build_synthetic_raw_match(")
            && !hot_patterns.contains("push_match_lazy("),
        "hot-pattern findings must route through canonical process_match, not synthetic RawMatch construction"
    );
}
