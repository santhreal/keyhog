//! Gate verifier control-flow cleanup from the execution plan.

#[test]
fn verifier_control_flow_uses_single_expression_helpers() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let verify_mod =
        std::fs::read_to_string(root.join("src/verify/mod.rs")).expect("verify/mod readable");
    let credential = std::fs::read_to_string(root.join("src/verify/credential.rs"))
        .expect("verify/credential readable");
    let response = std::fs::read_to_string(root.join("src/verify/response.rs"))
        .expect("verify/response readable");

    assert!(
        verify_mod.contains("detector.as_ref().and_then(|det| det.verify.as_ref())")
            && !verify_mod.contains("match &detector {\n        Some(det) => match &det.verify"),
        "verify task should select detector verify specs without nested option matches"
    );
    assert!(
        credential.contains("last_attempt.unwrap_or_else(||")
            && credential.contains("success.map_or(status == 200,")
            && credential.contains("observed.to_string()")
            && !credential.contains("if observed { \"true\" } else { \"false\" }.to_string()"),
        "credential verifier should keep retry/success/OOB boolean flow expression-level"
    );
    assert!(
        response.contains(".map_or(!val.is_null(), |expected|")
            && response.contains("map.iter().any(|(key, val)|")
            && response.contains("n.as_f64().map_or(true, |f| f != 0.0)")
            && !response.contains("n.as_f64().map(|f| f != 0.0).unwrap_or(true)"),
        "response verifier should use map_or/any without hand-rolled early-return loops"
    );
}
