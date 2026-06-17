use std::ffi::OsString;
use std::path::PathBuf;

const AUTOROUTE_CACHE_ENV: &str = "KEYHOG_AUTOROUTE_CACHE";

/// Path to the persistent autoroute cache.
///
/// Resolution order:
///   1. `KEYHOG_AUTOROUTE_CACHE` env var (absolute path; `0`, `off`, or empty disables).
///   2. `dirs::cache_dir()/keyhog/autoroute.json`.
pub(super) fn autoroute_cache_path() -> Result<Option<PathBuf>, String> {
    resolve_autoroute_cache_path(std::env::var_os(AUTOROUTE_CACHE_ENV), dirs::cache_dir())
}

fn resolve_autoroute_cache_path(
    raw: Option<OsString>,
    default_cache_dir: Option<PathBuf>,
) -> Result<Option<PathBuf>, String> {
    let raw = match raw {
        Some(raw) => Some(raw.into_string().map_err(|_| {
            format!(
                "{AUTOROUTE_CACHE_ENV} is not valid Unicode; unset it, set it to `off`, \
                 or set it to an absolute cache file path"
            )
        })?),
        None => None,
    };
    resolve_autoroute_cache_path_str(raw.as_deref(), default_cache_dir)
}

fn resolve_autoroute_cache_path_str(
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
                "{AUTOROUTE_CACHE_ENV} must be an absolute cache file path, got `{trimmed}`"
            ));
        }
        return Ok(Some(path));
    }

    let Some(default_cache_dir) = default_cache_dir else {
        return Err(format!(
            "could not determine a platform cache directory for autoroute; set \
             {AUTOROUTE_CACHE_ENV} to an absolute cache file path or `off`"
        ));
    };
    Ok(Some(
        default_cache_dir.join("keyhog").join("autoroute.json"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autoroute_cache_path_env_overrides_and_disable() {
        let default_root = PathBuf::from("/tmp/keyhog-cache-root");
        let default = resolve_autoroute_cache_path_str(None, Some(default_root))
            .expect("default cache root resolves")
            .expect("default path is enabled");
        assert!(
            default.ends_with("keyhog/autoroute.json"),
            "default cache path must live at keyhog/autoroute.json, got {}",
            default.display()
        );

        for off in ["off", "OFF", "Off", "0", "", "   "] {
            assert!(
                resolve_autoroute_cache_path_str(Some(off), None)
                    .expect("disable sentinel resolves")
                    .is_none(),
                "{off:?} must disable the autoroute cache"
            );
        }

        assert_eq!(
            resolve_autoroute_cache_path_str(
                Some("  /tmp/keyhog_autoroute_override.json  "),
                None,
            )
            .expect("absolute override resolves"),
            Some(PathBuf::from("/tmp/keyhog_autoroute_override.json"))
        );
        assert_eq!(
            resolve_autoroute_cache_path_str(Some("/var/cache/keyhog/ar.json"), None)
                .expect("absolute override resolves"),
            Some(PathBuf::from("/var/cache/keyhog/ar.json"))
        );
    }

    #[test]
    fn autoroute_cache_path_rejects_unavailable_or_ambiguous_paths() {
        let missing_default = resolve_autoroute_cache_path_str(None, None)
            .expect_err("missing default cache dir must be explicit");
        assert!(
            missing_default.contains("platform cache directory")
                && missing_default.contains(AUTOROUTE_CACHE_ENV),
            "missing default cache dir must explain the env override; got {missing_default}"
        );

        let relative = resolve_autoroute_cache_path_str(Some("relative/autoroute.json"), None)
            .expect_err("relative autoroute cache path must be rejected");
        assert!(
            relative.contains("absolute cache file path"),
            "relative cache path must fail closed with a fix; got {relative}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn autoroute_cache_path_rejects_non_unicode_env_without_defaulting() {
        use std::os::unix::ffi::OsStringExt;

        let invalid = OsString::from_vec(vec![0xFF, b'a']);
        let error = resolve_autoroute_cache_path(Some(invalid), Some(PathBuf::from("/tmp")))
            .expect_err("invalid Unicode env value must fail closed");
        assert!(
            error.contains("not valid Unicode") && !error.contains("default"),
            "invalid env must not silently default; got {error}"
        );
    }
}
