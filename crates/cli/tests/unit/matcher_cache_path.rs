#[path = "../../src/matcher_cache_path.rs"]
mod matcher_cache_path;

use matcher_cache_path::resolve_matcher_cache_path_with_default;

#[test]
fn matcher_cache_path_config_overrides_and_disable() {
    let default_root = std::path::PathBuf::from("/tmp/keyhog-cache-root");
    let default = resolve_matcher_cache_path_with_default(None, Some(default_root.clone()))
        .expect("default matcher cache");
    assert_eq!(
        default,
        Some(default_root.join("keyhog").join("matcher-artifacts"))
    );

    for off in ["off", "OFF", "0", ""] {
        assert_eq!(
            resolve_matcher_cache_path_with_default(Some(off), None).expect("disable"),
            None
        );
    }

    assert_eq!(
        resolve_matcher_cache_path_with_default(
            Some("/home/alice/.cache/keyhog/matcher-artifacts"),
            None
        )
        .expect("explicit"),
        Some(std::path::PathBuf::from(
            "/home/alice/.cache/keyhog/matcher-artifacts"
        ))
    );
}

#[test]
fn matcher_cache_path_rejects_relative_paths() {
    let relative = resolve_matcher_cache_path_with_default(Some("relative/matcher"), None)
        .expect_err("relative path");
    assert!(
        relative.contains("absolute") && relative.contains("--matcher-cache"),
        "relative rejection must name the flag; got {relative}"
    );
}
