//! Gate: production engine callers use the typed known-example suppression context.

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
fn engine_uses_typed_known_example_suppression_context() {
    let api = read(&scanner_src().join("suppression/api.rs"));
    assert!(
        api.contains("struct KnownExampleSuppressionCtx")
            && api.contains("fn suppress_known_example_credential_stage("),
        "suppression::api must expose the typed stage-returning known-example suppression entry point"
    );
    for forbidden in [
        "fn suppress_known_example_credential(",
        "fn should_suppress_known_example_credential(",
        "fn should_suppress_known_example_credential_with_source(",
        "fn should_suppress_known_example_credential_with_source_and_entropy(",
    ] {
        assert!(
            !api.contains(forbidden),
            "suppression::api must not expose known-example rigor wrapper `{forbidden}`"
        );
    }

    let suppression_mod = read(&scanner_src().join("suppression/mod.rs"));
    assert!(
        !suppression_mod.contains("should_suppress_known_example_credential"),
        "suppression::mod must not re-export known-example rigor wrappers"
    );

    let mut files = Vec::new();
    collect_rs_files(&scanner_src().join("engine"), &mut files);
    let mut offenders = Vec::new();
    for path in files {
        let code = uncommented_code(&read(&path));
        for forbidden in [
            "should_suppress_known_example_credential(",
            "should_suppress_known_example_credential_with_source(",
            "should_suppress_known_example_credential_with_source_and_entropy(",
        ] {
            if code.contains(forbidden) {
                offenders.push(format!("{} contains {forbidden}", path.display()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "production engine callers must use KnownExampleSuppressionCtx, not public rigor-tier wrappers: {offenders:#?}"
    );
}
