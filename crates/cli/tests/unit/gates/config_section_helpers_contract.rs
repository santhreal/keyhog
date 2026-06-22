#[test]
fn config_file_merge_uses_section_helpers() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config.rs"))
        .expect("config source readable");
    let apply = src
        .split("fn apply_config_file_impl(")
        .nth(1)
        .expect("apply_config_file_impl must exist");

    for helper in [
        "fn apply_system_section(",
        "fn apply_aws_section(",
        "fn apply_allowlist_section(",
        "fn apply_tuning_section(",
        "fn apply_scan_section(",
    ] {
        assert!(
            src.contains(helper),
            "config.rs must keep {helper} as a focused config section owner"
        );
    }

    for call in [
        "apply_system_section(",
        "apply_aws_section(",
        "apply_allowlist_section(",
        "apply_tuning_section(",
        "apply_scan_section(",
    ] {
        assert!(
            apply.contains(call),
            "apply_config_file_impl must delegate section handling through {call}"
        );
    }

    for forbidden in [
        "let mut collect_trusted_bin_dirs",
        "parse_canary_account_ids(",
        "\"- [allowlist].file: path must not be empty\"",
        "scanner_tuning.phase2_hs",
        "parse_gpu_runtime_policy(",
        "\"[scan].severity\"",
        "\"[scan].format\"",
        "\"[scan].dedup\"",
        "\"- [scan].min_secret_len = 0",
    ] {
        assert!(
            !apply.contains(forbidden),
            "apply_config_file_impl must not re-own section implementation detail `{forbidden}`"
        );
    }
}
