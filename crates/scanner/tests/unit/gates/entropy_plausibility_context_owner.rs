//! Gate: entropy plausibility has one typed-context production entry point.

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

#[test]
fn entropy_plausibility_uses_typed_context_entry_points() {
    let src = scanner_src();
    let owner = read(&src.join("entropy/keywords.rs"));
    assert!(
        owner.contains("pub(crate) struct PlausibilityContext"),
        "entropy::keywords must own the typed plausibility context"
    );
    assert!(
        owner.contains("pub(crate) fn is_candidate_plausible(")
            && owner.contains("context: PlausibilityContext"),
        "is_candidate_plausible must take PlausibilityContext"
    );
    assert!(
        owner.contains("pub(crate) fn is_secret_plausible(")
            && owner.contains("context: PlausibilityContext"),
        "is_secret_plausible must take PlausibilityContext"
    );
    assert!(
        owner.contains("pub(crate) fn passes_secret_strength_checks(")
            && owner.contains("context: PlausibilityContext"),
        "passes_secret_strength_checks must take PlausibilityContext"
    );

    for forbidden in [
        "fn is_candidate_plausible_with_context",
        "fn is_secret_plausible_with_context",
        "fn is_candidate_plausible_with_lift",
        "fn is_secret_plausible_with_lift",
        "fn passes_strict_secret_checks",
    ] {
        assert!(
            !owner.contains(forbidden),
            "entropy::keywords must not reintroduce overload `{forbidden}`"
        );
    }

    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);
    let mut offenders = Vec::new();
    for path in files {
        let rel = path.strip_prefix(&src).unwrap_or(&path);
        let code = read(&path);
        for forbidden in [
            "is_candidate_plausible_with_context",
            "is_secret_plausible_with_context",
            "is_candidate_plausible_with_lift",
            "is_secret_plausible_with_lift",
            "passes_strict_secret_checks",
        ] {
            if code.contains(forbidden) {
                offenders.push(format!("{} contains {forbidden}", rel.display()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "entropy plausibility overloads returned:\n{}",
        offenders.join("\n")
    );
}
