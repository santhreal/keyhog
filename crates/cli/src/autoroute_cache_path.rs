use std::path::PathBuf;

/// Resolve the persistent autoroute cache file from explicit CLI/TOML config.
///
/// Resolution order:
///   1. explicit `--autoroute-cache <PATH|off>` / `[system].autoroute_cache`
///   2. `dirs::cache_dir()/keyhog/autoroute.json`
pub(crate) fn resolve_autoroute_cache_path(raw: Option<&str>) -> Result<Option<PathBuf>, String> {
    resolve_autoroute_cache_path_with_default(raw, dirs::cache_dir())
}

pub(crate) fn resolve_autoroute_cache_path_with_default(
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
