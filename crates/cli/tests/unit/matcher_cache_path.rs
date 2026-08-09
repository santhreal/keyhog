#[path = "../../src/matcher_cache_path.rs"]
mod matcher_cache_path;

use matcher_cache_path::resolve_matcher_cache_path_with_default;

#[test]
fn matcher_cache_path_config_overrides_and_disable() {
    let home = dirs::home_dir().expect("home");
    let default = resolve_matcher_cache_path_with_default(None, Some(home.clone()))
        .expect("default matcher cache");
    assert_eq!(
        default,
        Some(home.join("keyhog").join("matcher-artifacts"))
    );

    // Unusable automatic defaults soft-fail to disabled.
    assert_eq!(
        resolve_matcher_cache_path_with_default(
            None,
            Some(std::path::PathBuf::from("/var/cache/shared"))
        )
        .expect("unusable default"),
        None
    );

    for off in ["off", "OFF", "0", ""] {
        assert_eq!(
            resolve_matcher_cache_path_with_default(Some(off), None).expect("disable"),
            None
        );
    }

    let explicit = home.join(".cache/keyhog/matcher-artifacts");
    assert_eq!(
        resolve_matcher_cache_path_with_default(Some(explicit.to_str().unwrap()), None)
            .expect("explicit"),
        Some(explicit)
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
