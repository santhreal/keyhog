/// WHY: verifier-plan ownership is the first live-verification boundary. A
/// missing graph must fail before candidate buffers, HTTP/OOB clients, caches,
/// or process-wide verifier policy are materialized.
#[test]
fn missing_verifier_plans_fail_closed_before_runtime_construction() {
    let error = super::require_verifier_plans(None)
        .expect_err("verification without retained plans must fail closed");
    assert_eq!(
        error.to_string(),
        "verification was requested without retained detector plans; rerun the scan"
    );
}
