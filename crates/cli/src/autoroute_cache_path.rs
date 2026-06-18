use std::path::PathBuf;

/// Resolve the persistent autoroute cache file from explicit CLI/TOML config.
///
/// Resolution order:
///   1. explicit `--autoroute-cache <PATH|off>` / `[system].autoroute_cache`
///   2. `dirs::cache_dir()/keyhog/autoroute.json`
pub(crate) fn resolve_autoroute_cache_path(raw: Option<&str>) -> Result<Option<PathBuf>, String> {
    resolve_autoroute_cache_path_with_default(raw, dirs::cache_dir())
}

fn resolve_autoroute_cache_path_with_default(
    raw: Option<&str>,
    default_cache_dir: Option<PathBuf>,
) -> Result<Option<PathBuf>, String> {
    if let Some(raw) = raw {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("off") || trimmed == "0" {
            return Ok(None);
        }
        let path = PathBuf::from(trimmed);
        if !path.is_absolute() {
            return Err(format!(
                "autoroute cache path must be an absolute file path, got `{trimmed}`. \
                 Configure with --autoroute-cache <PATH|off> or [system].autoroute_cache"
            ));
        }
        return Ok(Some(path));
    }

    let Some(default_cache_dir) = default_cache_dir else {
        return Err(
            "could not determine a platform cache directory for autoroute; configure \
             --autoroute-cache <PATH|off> or [system].autoroute_cache"
                .to_string(),
        );
    };
    Ok(Some(
        default_cache_dir.join("keyhog").join("autoroute.json"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let relative =
            resolve_autoroute_cache_path_with_default(Some("relative/autoroute.json"), None)
                .expect_err("relative autoroute cache path must be rejected");
        assert!(
            relative.contains("absolute file path"),
            "relative cache path must fail closed with a fix; got {relative}"
        );
    }
}
