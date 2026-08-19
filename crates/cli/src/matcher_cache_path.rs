use std::path::PathBuf;

/// Resolve the MatcherArtifact cache directory from explicit CLI/TOML config.
///
/// Resolution order:
///   1. explicit `--matcher-cache <DIR|off>` / `[system].matcher_cache`
///   2. `dirs::cache_dir()/keyhog-matcher-artifacts`
///
/// `off` / `0` / empty disables persistence. `--lockdown` also disables the
/// cache at the orchestrator layer (unsigned local detector/matcher graphs are
/// incompatible with lockdown's past-findings audit).
///
/// Default-on mirrors Hyperscan's persistent shard cache, which likewise
/// resolves under `dirs::cache_dir()/keyhog` when `--cache-dir` is unset
/// (`simd::backend::resolve_cache_dir`). An explicit path that fails validation
/// is a hard error. The automatic default automatically tightens loose permissions
/// (e.g. 0775 to 0700) and soft-fails to `None` (cache disabled) when the platform
/// cache root is missing or outside the allowlist.
pub(crate) fn resolve_matcher_cache_path(raw: Option<&str>) -> Result<Option<PathBuf>, String> {
    resolve_matcher_cache_path_with_default(raw, dirs::cache_dir())
}

pub(crate) fn resolve_matcher_cache_path_with_default(
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
                "matcher-artifact cache path must be an absolute directory, got `{trimmed}`. \
                 Configure with --matcher-cache <DIR|off> or [system].matcher_cache"
            ));
        }
        keyhog_scanner::validate_matcher_artifact_cache_dir(&path)?;
        return Ok(Some(path));
    }

    match keyhog_scanner::default_matcher_artifact_cache_dir_from_base(default_cache_dir) {
        Ok(path) => {
            match keyhog_scanner::validate_and_tighten_matcher_artifact_cache_dir(&path, true) {
                Ok(()) => Ok(Some(path)),
                Err(error) => {
                    tracing::debug!(
                        error = %error,
                        path = %path.display(),
                        "matcher-artifact cache soft-fail: default cache location is unusable"
                    );
                    Ok(None)
                }
            }
        }
        Err(error) => {
            tracing::debug!(
                error = %error,
                "matcher-artifact cache soft-fail: no default cache location"
            );
            eprintln!(
                "warning: matcher-artifact cache unusable: {error}; configure with --matcher-cache <DIR>"
            );
            Ok(None)
        }
    }
}
