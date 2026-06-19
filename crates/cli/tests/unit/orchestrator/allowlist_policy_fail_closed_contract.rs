#[test]
fn allowlist_policy_load_errors_fail_closed() {
    let allowlist = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/allowlist.rs"
    ))
    .expect("orchestrator allowlist source readable");
    let scan = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/scan.rs"
    ))
    .expect("scan subcommand source readable");

    assert!(
        allowlist.contains("fn load_allowlist")
            && allowlist.contains("Result<keyhog_core::Allowlist>")
            && allowlist.contains("refusing to scan with silently ignored policy")
            && !allowlist.contains("Allowlist::load(&ignore_path)\n            .unwrap_or_else"),
        ".keyhogignore load errors must not become an empty allowlist"
    );
    assert!(
        allowlist.contains("fn load_rule_suppressor")
            && allowlist.contains("Result<keyhog_core::RuleSuppressor>")
            && allowlist.contains("silently ignored suppression rules")
            && !allowlist.contains("failed to load .keyhogignore.toml; ignoring rules"),
        ".keyhogignore.toml load errors must not become an empty suppressor"
    );
    assert!(
        scan.contains("fn load_daemon_allowlist")
            && scan.contains("Result<keyhog_core::Allowlist>")
            && scan.contains("fn load_daemon_rule_suppressor")
            && scan.contains("Result<RuleSuppressor>")
            && scan.contains("daemon route: failed to load")
            && !scan.contains("unwrap_or_else(|_| keyhog_core::Allowlist::empty())"),
        "daemon scan route must share the same fail-closed policy loading contract"
    );
}
