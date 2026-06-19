use std::path::{Path, PathBuf};

fn rust_sources_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| {
        panic!(
            "safe-bin production fallback gate: read_dir({}) failed: {e}",
            dir.display()
        )
    }) {
        let path = entry
            .unwrap_or_else(|e| {
                panic!(
                    "safe-bin production fallback gate: reading {} entry failed: {e}",
                    dir.display()
                )
            })
            .path();
        if path.is_dir() {
            rust_sources_under(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn keyhog_production_code_does_not_call_path_fallback_resolver() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut offenders = Vec::new();

    for crate_name in ["cli", "scanner", "sources", "verifier"] {
        let mut files = Vec::new();
        rust_sources_under(
            &repo.join("crates").join(crate_name).join("src"),
            &mut files,
        );
        for file in files {
            let source = std::fs::read_to_string(&file).unwrap_or_else(|e| {
                panic!(
                    "safe-bin production fallback gate: reading {} failed: {e}",
                    file.display()
                )
            });
            if source.contains("resolve_or_fallback(") {
                offenders.push(
                    file.strip_prefix(&repo)
                        .unwrap_or(&file)
                        .display()
                        .to_string(),
                );
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "production crates must use resolve_safe_bin and fail closed instead of PATH fallback: {}",
        offenders.join(", ")
    );
}
