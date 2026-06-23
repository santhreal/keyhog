#[test]
fn config_file_merge_uses_section_helpers() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config.rs"))
        .expect("config source readable");
    let sections = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/config/sections.rs"
    ))
    .expect("config sections source readable");
    let scan = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config/scan.rs"))
        .expect("config scan source readable");
    let policy =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/config/policy.rs"))
            .expect("config policy source readable");
    let apply = src
        .split("fn apply_config_file_impl(")
        .nth(1)
        .expect("apply_config_file_impl must exist");

    for helper in [
        "fn apply_system_section(",
        "fn apply_aws_section(",
        "fn apply_allowlist_section(",
        "fn apply_tuning_section(",
    ] {
        assert!(
            sections.contains(helper),
            "config/sections.rs must keep {helper} as a focused config section owner"
        );
    }

    for helper in [
        "fn apply_scan_section(",
        "fn apply_top_level_scan_fields(",
        "fn parse_config_byte_size(",
        "fn parse_config_decode_depth(",
        "fn keyword_list_is_nonempty(",
    ] {
        assert!(
            scan.contains(helper),
            "config/scan.rs must keep {helper} as a focused scan config owner"
        );
    }

    for helper in [
        "fn resolve_policy_outcome(",
        "fn shipped_config_outcome(",
        "fn config_file_error(",
        "struct ConfigOutcome",
        "const SHIPPED_DETECTOR_FLOORS",
        "const SHIPPED_DISABLED_DETECTORS",
    ] {
        assert!(
            policy.contains(helper),
            "config/policy.rs must keep {helper} as the config policy outcome owner"
        );
    }

    for call in [
        "apply_system_section(",
        "apply_aws_section(",
        "apply_allowlist_section(",
        "apply_tuning_section(",
        "apply_top_level_scan_fields(",
        "apply_scan_section(",
        "resolve_policy_outcome(",
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
        "\"format\"",
        "\"severity\"",
        "\"dedup\"",
        "\"decode_size_limit\"",
        "apply_limits_section(",
        "known_prefixes",
        "secret_keywords",
        "placeholder_keywords",
        "config.lockdown",
        "config.detector",
        "let require_lockdown",
        "let baseline = shipped_config_outcome()",
        "section.enabled",
        "section.min_confidence",
    ] {
        assert!(
            !apply.contains(forbidden),
            "apply_config_file_impl must not re-own section implementation detail `{forbidden}`"
        );
    }

    for forbidden in [
        "const SHIPPED_DETECTOR_FLOORS",
        "const SHIPPED_DISABLED_DETECTORS",
        "struct ConfigOutcome",
        "fn resolve_policy_outcome(",
        "section.enabled",
        "section.min_confidence",
    ] {
        assert!(
            !src.contains(forbidden),
            "config.rs must not re-own policy implementation detail `{forbidden}`"
        );
    }
}
