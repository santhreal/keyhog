//! Gate `engine::phase2_entropy`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn engine_phase2_entropy_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/phase2_entropy.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "engine::phase2_entropy: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "engine::phase2_entropy: todo!/unimplemented! forbidden in non-test source"
    );
    assert_eq!(
        prod.matches("preprocessed.text.lines().collect()").count(),
        1,
        "engine::phase2_entropy must split preprocessed text once and share the line slice"
    );
    for required in [
        "is_entropy_appropriate_with_content_lines(",
        "has_isolated_bare_secret_candidate_with_lines(",
        "has_lower_dash_app_password_candidate_with_lines(",
        "find_entropy_secrets_with_canonical_lift_and_lines(",
    ] {
        assert!(
            prod.contains(required),
            "engine::phase2_entropy must route through shared-line entry point {required}"
        );
    }
}
