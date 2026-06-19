//! Autoroute cache path resolution contracts live outside production source.

use std::path::PathBuf;

#[allow(dead_code)]
#[path = "../../src/autoroute_cache_path.rs"]
mod autoroute_cache_path;

use autoroute_cache_path::resolve_autoroute_cache_path_with_default;

#[test]
fn autoroute_cache_path_config_overrides_and_disable() {
    let default_root = PathBuf::from("/tmp/keyhog-cache-root");
    let default = resolve_autoroute_cache_path_with_default(None, Some(default_root))
        .expect("default cache root resolves")
        .expect("default path is enabled");
    assert!(
        default.ends_with("keyhog/autoroute.json"),
        "default cache path must live at keyhog/autoroute.json, got {}",
        default.display()
    );

    for off in ["off", "OFF", "Off", "0", "", "   "] {
        assert!(
            resolve_autoroute_cache_path_with_default(Some(off), None)
                .expect("disable sentinel resolves")
                .is_none(),
            "{off:?} must disable the autoroute cache"
        );
    }

    assert_eq!(
        resolve_autoroute_cache_path_with_default(
            Some("  /tmp/keyhog_autoroute_override.json  "),
            None,
        )
        .expect("absolute override resolves"),
        Some(PathBuf::from("/tmp/keyhog_autoroute_override.json"))
    );
    assert_eq!(
        resolve_autoroute_cache_path_with_default(Some("/var/cache/keyhog/ar.json"), None)
            .expect("absolute override resolves"),
        Some(PathBuf::from("/var/cache/keyhog/ar.json"))
    );
}

#[test]
fn autoroute_cache_path_rejects_unavailable_or_ambiguous_paths() {
    let missing_default = resolve_autoroute_cache_path_with_default(None, None)
        .expect_err("missing default cache dir must be explicit");
    assert!(
        missing_default.contains("platform cache directory")
            && missing_default.contains("--autoroute-cache"),
        "missing default cache dir must explain the explicit override; got {missing_default}"
    );

    let relative = resolve_autoroute_cache_path_with_default(Some("relative/autoroute.json"), None)
        .expect_err("relative autoroute cache path must be rejected");
    assert!(
        relative.contains("absolute file path"),
        "relative cache path must fail closed with a fix; got {relative}"
    );
}
