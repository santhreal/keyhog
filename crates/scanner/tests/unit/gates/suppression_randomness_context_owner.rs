//! Gate: shape predicates use the per-candidate token-randomness context.

use super::support::*;

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
