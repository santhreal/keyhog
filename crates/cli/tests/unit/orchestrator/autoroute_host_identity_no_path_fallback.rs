#[test]
fn autoroute_host_identity_probe_does_not_fall_back_to_path() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch/backend/host.rs"
    ))
    .expect("autoroute host identity source readable");
    assert!(
        !src.contains("resolve_or_fallback"),
        "autoroute host identity must not execute PATH binaries when trusted resolution misses"
    );
    assert!(
        src.contains(r#"resolve_safe_bin("sysctl")"#)
            && src.contains(r#"resolve_safe_bin("powershell")"#)
            && src.contains(r#"resolve_safe_bin("wmic")"#),
        "autoroute host identity must use trusted absolute binary resolution for platform probes"
    );
}
