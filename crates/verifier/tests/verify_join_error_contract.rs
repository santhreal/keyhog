#[test]
fn verify_all_preserves_join_error_groups_as_error_findings() {
    let verify = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/verify/mod.rs"))
        .expect("read verifier implementation");
    let verify_all = verify
        .split("pub async fn verify_all(")
        .nth(1)
        .and_then(|tail| tail.split("pub async fn enable_oob(").next())
        .expect("verify_all body extractable");

    for required in [
        "join_next_with_id()",
        "let mut task_groups = HashMap::new();",
        "spawn_tracked_verify_task(",
        "let task_id = join_error.id();",
        "task_groups.remove(&task_id)",
        "VerificationResult::Error(format!",
    ] {
        assert!(
            verify_all.contains(required),
            "verify_all must preserve verifier task join failures through `{required}`"
        );
    }
}
