#[allow(dead_code)]
#[path = "../../src/matcher_cache_path.rs"]
mod matcher_cache_path;

use matcher_cache_path::resolve_matcher_cache_path_with_default;

#[test]
fn matcher_cache_path_config_overrides_and_disable() {
    let actual_home = dirs::home_dir().expect("home");
    let cache_home = tempfile::Builder::new()
        .prefix(".keyhog-matcher-cache-test-")
        .tempdir_in(actual_home)
        .expect("secure cache home");
    let home = cache_home.path().to_path_buf();
    let default = resolve_matcher_cache_path_with_default(None, Some(home.clone()))
        .expect("default matcher cache");
    assert_eq!(default.path(), Some(home.join("keyhog-matcher-artifacts")));

    // Unusable automatic defaults soft-fail to disabled with UnusableLocation.
    let unusable = resolve_matcher_cache_path_with_default(
        None,
        Some(std::path::PathBuf::from("/var/cache/shared")),
    )
    .expect("unusable default");
    assert_eq!(unusable.path(), None);
    assert_eq!(
        unusable.disable_reason(),
        Some(keyhog_scanner::MatcherArtifactCacheDisableReason::UnusableLocation)
    );

    for off in ["off", "OFF", "0", ""] {
        let disabled = resolve_matcher_cache_path_with_default(Some(off), None).expect("disable");
        assert_eq!(disabled.path(), None);
        assert_eq!(
            disabled.disable_reason(),
            Some(keyhog_scanner::MatcherArtifactCacheDisableReason::ConfiguredOff)
        );
    }

    let explicit = home.join(".cache/keyhog/matcher-artifacts");
    assert_eq!(
        resolve_matcher_cache_path_with_default(Some(explicit.to_str().unwrap()), None)
            .expect("explicit")
            .path(),
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

/// WHY: an explicit matcher cache path that fails validation must include the repair command in the error.
///
/// What it does not catch: validation on platforms without POSIX permissions.
#[test]
#[cfg(unix)]
fn matcher_cache_path_explicit_group_writable_error_includes_repair_command() {
    use std::os::unix::fs::PermissionsExt;

    let actual_home = dirs::home_dir().expect("home");
    let cache_home = tempfile::Builder::new()
        .prefix(".keyhog-matcher-cache-loose-")
        .tempdir_in(actual_home)
        .expect("secure cache home");
    let explicit = cache_home.path().join("loose-matcher-cache");
    std::fs::create_dir(&explicit).expect("create dir");
    std::fs::set_permissions(&explicit, std::fs::Permissions::from_mode(0o775))
        .expect("set loose mode");

    let err = resolve_matcher_cache_path_with_default(Some(explicit.to_str().unwrap()), None)
        .expect_err("explicit loose path must fail");
    assert!(
        err.contains("chmod 700"),
        "explicit validation error must include repair command `chmod 700`, got: {err}"
    );
}
