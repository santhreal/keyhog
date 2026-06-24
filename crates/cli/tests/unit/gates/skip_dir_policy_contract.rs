#[test]
fn watch_and_scan_system_share_tier_b_skip_dir_policy() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let policy = std::fs::read_to_string(root.join("src/skip_dirs.rs"))
        .expect("skip dir policy source readable");
    let data = std::fs::read_to_string(root.join("data/path_skip_dirs.toml"))
        .expect("skip dir policy data readable");
    let watch =
        std::fs::read_to_string(root.join("src/subcommands/watch.rs")).expect("watch readable");
    let scan_system = std::fs::read_to_string(root.join("src/subcommands/scan_system.rs"))
        .expect("scan-system readable");

    assert!(
        policy.contains("include_str!(\"../data/path_skip_dirs.toml\")")
            && policy.contains("struct SkipDirPolicy")
            && policy.contains("keyhog_sources::default_exclude_dir_components()")
            && policy.contains("GIT_DISCOVERY_KEEP_COMPONENTS")
            && policy.contains("path_skip_dirs.toml")
            && policy.contains("keyhog/path_skip_dirs.toml")
            && policy.contains("is_watch_component")
            && policy.contains("is_git_discovery_component"),
        "src/skip_dirs.rs must compose CLI skip policy with source-owned default-exclude dirs"
    );
    assert!(
        data.contains("[skip_dirs]")
            && data.contains("base =")
            && data.contains("watch_extra =")
            && data.contains("git_discovery_extra =")
            && !data.contains("\"node_modules\"")
            && !data.contains("\"target\"")
            && !data.contains("\".cache\"")
            && !data.contains("\".git\"")
            && data.contains("\"System Volume Information\""),
        "data/path_skip_dirs.toml must carry only CLI-specific base and per-consumer skip-dir lists"
    );

    assert!(
        watch.contains("SkipDirPolicy::load()")
            && watch.contains("is_watch_component")
            && !watch.contains("const SKIP_NAMES"),
        "watch must consume shared skip-dir policy instead of owning a local skip list"
    );
    assert!(
        scan_system.contains("SkipDirPolicy::load()")
            && scan_system.contains("is_git_discovery_component")
            && !scan_system.contains("\"node_modules\"")
            && !scan_system.contains("\"System Volume Information\""),
        "scan-system git discovery must consume shared skip-dir policy instead of owning a local skip list"
    );
}
