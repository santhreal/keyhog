//! Gate: shape predicates use the per-candidate token-randomness context.

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
            (!trimmed.starts_with("//")).then_some(line)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn shape_predicates_do_not_call_random_token_discriminator_directly() {
    let src = scanner_src();
    let mut files = Vec::new();
    collect_rs_files(&src.join("suppression/shape"), &mut files);

    let mut offenders = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(&src)
            .expect("scanner src path")
            .to_string_lossy()
            .replace('\\', "/");
        let code = uncommented_code(&read(&path));
        if code.contains("token_randomness::is_random_token(") {
            offenders.push(rel);
        }
    }

    assert!(
        offenders.is_empty(),
        "shape predicates must use TokenRandomness evidence supplied by the caller:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn production_adjudication_paths_thread_candidate_randomness_once() {
    let src = scanner_src();
    let contracts = [
        (
            "suppression/api.rs",
            [
                "TokenRandomness::for_candidate(credential)",
                "public_noncredential_shape_with_randomness(",
                "keep_identifier_gate_with_randomness(",
                "keep_word_separated_gate_with_randomness(",
            ]
            .as_slice(),
        ),
        (
            "engine/phase2_generic_shape.rs",
            [
                "TokenRandomness::for_candidate(value)",
                "public_noncredential_shape_with_randomness(",
                "looks_like_source_code_expression_with_randomness(",
                "looks_like_source_symbol_identifier_with_randomness(",
                "keep_identifier_gate_with_randomness(",
                "keep_word_separated_gate_with_randomness(",
            ]
            .as_slice(),
        ),
        (
            "engine/phase2_entropy/gates.rs",
            [
                "TokenRandomness::for_candidate(&entropy_match.value)",
                "public_noncredential_shape_with_randomness(",
                "looks_like_source_type_identifier_with_randomness(",
                "looks_like_source_code_expression_with_randomness(",
                "looks_like_source_symbol_identifier_with_randomness(",
            ]
            .as_slice(),
        ),
    ];

    let mut missing = Vec::new();
    for (rel, required) in contracts {
        let code = uncommented_code(&read(&src.join(rel)));
        for needle in required {
            if !code.contains(needle) {
                missing.push(format!("{rel} missing {needle}"));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "candidate randomness context contract is incomplete:\n{}",
        missing.join("\n")
    );
}
