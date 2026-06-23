//! Gate JWT hot path shape parsing: no validate-then-resplit and no audience clone vector.

#[test]
fn jwt_analyze_reuses_validated_segments() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/jwt.rs");
    let src = std::fs::read_to_string(path).expect("jwt source readable");
    let prod = src
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        prod.contains("fn jwt_segments(s: &str) -> Option<(&str, &str, &str)>"),
        "JWT shape validation should expose validated segment slices"
    );
    assert!(
        prod.contains("let (header_b64, payload_b64, _signature_b64) = jwt_segments(s)?;"),
        "analyze must reuse the validated segment slices"
    );
    let analyze_body = prod
        .split("pub(crate) fn analyze(s: &str) -> Option<JwtAnalysis>")
        .nth(1)
        .and_then(|rest| rest.split("fn json_i64").next())
        .expect("analyze body present");
    assert!(
        !analyze_body.contains("if !looks_like_jwt(s)")
            && !analyze_body.contains("let mut parts = s.split('.')"),
        "analyze must not validate with looks_like_jwt and then split again"
    );
}

#[test]
fn jwt_audience_and_exp_extraction_avoid_clone_collect_shape() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/jwt.rs");
    let src = std::fs::read_to_string(path).expect("jwt source readable");
    let prod = src
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        prod.contains("fn join_audience_strings"),
        "JWT audience array joining needs one no-clone helper"
    );
    assert!(
        !prod.contains("let joined: Vec<String>") && !prod.contains("joined.join(\",\")"),
        "JWT audience extraction must not clone every audience into a temporary Vec<String>"
    );
    assert!(
        prod.contains("fn json_i64(value: serde_json::Value) -> Option<i64>"),
        "JWT exp extraction should be a named numeric helper, not an inline nested match"
    );
}
