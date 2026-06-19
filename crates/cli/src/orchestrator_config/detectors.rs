use anyhow::{Context, Result};
use keyhog_core::{load_detectors, validate_detector, DetectorSpec, QualityIssue};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

const DETECTOR_CACHE_VERSION: u32 = 3;

#[derive(Serialize, Deserialize)]
struct DetectorCacheFile {
    version: u32,
    source_fingerprint: String,
    detectors: Vec<DetectorSpec>,
}

pub(crate) fn auto_discover_detectors(path: &Path) -> Result<PathBuf> {
    if path != Path::new("detectors") {
        return Ok(path.to_path_buf());
    }

    if path == Path::new("detectors") && !path.exists() {
        let mut default_dirs: Vec<Option<PathBuf>> = vec![
            dirs::home_dir().map(|h| h.join(".keyhog/detectors")),
            dirs::data_dir().map(|d| d.join("keyhog/detectors")),
            dirs::data_local_dir().map(|d| d.join("keyhog/detectors")),
        ];
        if cfg!(unix) {
            default_dirs.push(Some(PathBuf::from("/usr/share/keyhog/detectors")));
            default_dirs.push(Some(PathBuf::from("/usr/local/share/keyhog/detectors")));
        }
        default_dirs.push(
            std::env::current_exe()
                .ok() // LAW10: optional env/cwd probe; absent => None (intended config/probe), recall-irrelevant
                .and_then(|p| p.parent().map(|p| p.join("detectors"))),
        );
        for dir in default_dirs.into_iter().flatten() {
            if dir.exists() && dir.is_dir() {
                tracing::info!(detectors_dir = %dir.display(), "auto-detected detectors directory");
                return Ok(dir);
            }
        }
    }
    Ok(path.to_path_buf())
}

pub(crate) fn load_detectors_with_cache(path: &Path) -> Result<Vec<DetectorSpec>> {
    validate_detector_path_for_scan(path)?;
    if path.exists() && path.is_dir() {
        // The parse cache lives in the user's XDG cache dir, NOT inside the
        // detectors directory. A system install puts detectors under a
        // root-owned, read-only tree (e.g. /opt/keyhog/detectors,
        // /usr/share/keyhog/detectors); writing `.keyhog-cache.json` there
        // failed with `Permission denied` on EVERY run, spamming two WARN
        // lines and silently re-parsing each time. Keying the cache by the
        // source dir keeps distinct detector directories from colliding;
        // The CLI parse cache fingerprints the source TOML filenames and
        // contents, so removed/renamed/edited detectors cannot leave stale
        // detectors live just because no remaining file is newer than cache.
        let cache_path = detector_cache_path(path);
        if let Some(cache_path) = &cache_path {
            let loaded = load_detectors_from_dir_with_cache(path, cache_path)
                .context("loading detectors from directory with parse cache")?;
            require_non_empty_detectors(&loaded, path)?;
            return Ok(loaded);
        }
        let loaded = load_detectors(path)?;
        require_non_empty_detectors(&loaded, path)?;
        return Ok(loaded);
    }
    load_detectors_embedded_or_fail(path)
}

fn load_detectors_from_dir_with_cache(
    source_dir: &Path,
    cache_path: &Path,
) -> Result<Vec<DetectorSpec>> {
    if let Some(cached) = load_detector_cache(cache_path, source_dir) {
        return Ok(cached);
    }

    let loaded = load_detectors(source_dir).map_err(anyhow::Error::from)?;
    if loaded.is_empty() {
        return Ok(loaded);
    }
    let source_fingerprint = match detector_source_fingerprint(source_dir) {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            tracing::warn!(
                source_dir = %source_dir.display(),
                %error,
                "detector source changed after load; parse cache not written"
            );
            return Ok(loaded);
        }
    };
    if let Err(error) = save_detector_cache(&loaded, cache_path, source_fingerprint) {
        tracing::debug!(
            cache_path = %cache_path.display(),
            %error,
            "detector parse cache not written; re-parsing TOML on the next run"
        );
    }
    Ok(loaded)
}

fn save_detector_cache(
    detectors: &[DetectorSpec],
    cache_path: &Path,
    source_fingerprint: String,
) -> std::io::Result<()> {
    for detector in detectors {
        let issues = validate_detector(detector);
        if issues
            .iter()
            .any(|issue| matches!(issue, QualityIssue::Error(_)))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "refusing to cache invalid detector '{}'. Fix: repair the detector before writing the cache",
                    detector.id
                ),
            ));
        }
    }

    let json = serde_json::to_vec(&DetectorCacheFile {
        version: DETECTOR_CACHE_VERSION,
        source_fingerprint,
        detectors: detectors.to_vec(),
    })?;
    crate::atomic_file::write_bytes(cache_path, &json)
}

fn load_detector_cache(cache_path: &Path, source_dir: &Path) -> Option<Vec<DetectorSpec>> {
    let source_fingerprint = match detector_source_fingerprint(source_dir) {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            tracing::warn!(
                source_dir = %source_dir.display(),
                %error,
                "cannot fingerprint detector source directory; ignoring detector cache and re-parsing TOML"
            );
            return None;
        }
    };

    let data = match std::fs::read(cache_path) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            tracing::warn!(
                "failed to read detector cache {}: {}",
                cache_path.display(),
                error
            );
            return None;
        }
    };
    let cache: DetectorCacheFile = match serde_json::from_slice(&data) {
        Ok(cache) => cache,
        Err(error) => {
            tracing::warn!(
                "failed to parse detector cache {}: {}",
                cache_path.display(),
                error
            );
            return None;
        }
    };
    if cache.version != DETECTOR_CACHE_VERSION {
        return None;
    }
    if cache.source_fingerprint != source_fingerprint {
        return None;
    }

    let mut validated = Vec::with_capacity(cache.detectors.len());
    for spec in cache.detectors {
        let issues = validate_detector(&spec);
        if issues
            .iter()
            .any(|issue| matches!(issue, QualityIssue::Error(_)))
        {
            tracing::warn!(
                "cached detector '{}' failed quality gate; discarding the entire cache",
                spec.id
            );
            return None;
        }
        validated.push(spec);
    }

    if validated.is_empty() {
        tracing::warn!("detector cache is empty after validation, re-parsing detector TOML");
        return None;
    }

    Some(validated)
}

fn detector_source_fingerprint(source_dir: &Path) -> std::io::Result<String> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(source_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.extension().is_some_and(|ext| ext == "toml") {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let bytes = std::fs::read(&path)?;
        entries.push((name, *blake3::hash(&bytes).as_bytes()));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = blake3::Hasher::new();
    for (name, hash) in entries {
        hasher.update(name.as_bytes());
        hasher.update(b"\0");
        hasher.update(&hash);
        hasher.update(b"\n");
    }
    Ok(keyhog_core::hex_encode(hasher.finalize().as_bytes()))
}

/// Path to the detector parse cache in the user's XDG cache dir, keyed by the
/// source directory so multiple `--detectors` trees don't collide. Returns
/// `None` when no cache dir is resolvable (cache simply disabled). The
/// `.json` is created on first successful parse and revalidated against the
/// source TOMLs' mtimes by the CLI parse-cache loader.
fn detector_cache_path(source_dir: &Path) -> Option<std::path::PathBuf> {
    use std::hash::{Hash, Hasher};
    let canonical = std::fs::canonicalize(source_dir).unwrap_or_else(|_| source_dir.to_path_buf()); // LAW10: canonicalize failure => original path (best-effort normalization); recall-safe
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    canonical.hash(&mut hasher);
    // Version-scope the key: the embedded/default corpus shape can change
    // across keyhog versions, so a stale cache from an old binary is never
    // reused by a new one.
    env!("CARGO_PKG_VERSION").hash(&mut hasher);
    let key = hasher.finish();
    Some(
        dirs::cache_dir()?
            .join("keyhog")
            .join(format!("detectors-{key:016x}.json")),
    )
}

/// Load detectors without writing or reading the on-disk
/// `.keyhog-cache.json`. Used by `--lockdown` to avoid touching disk.
/// Falls through to the embedded TOML corpus when no detectors dir
/// exists, matching `load_detectors_with_cache`'s behaviour.
pub(crate) fn load_detectors_no_cache(path: &Path) -> Result<Vec<DetectorSpec>> {
    validate_detector_path_for_scan(path)?;
    if path.exists() && path.is_dir() {
        let loaded = load_detectors(path).map_err(anyhow::Error::from)?;
        require_non_empty_detectors(&loaded, path)?;
        return Ok(loaded);
    }
    load_detectors_embedded_or_fail(path)
}

/// Hard-fail when detector loading produces zero specs. The
/// `load_detectors` path returns `Ok(Vec::new())` for an empty
/// directory, a directory full of malformed TOMLs that all get
/// quality-gate rejected, or a typo'd `--detectors` path that
/// happens to be a directory. Without this gate the scan runs
/// against zero patterns, finds nothing, and exits SUCCESS - the
/// user (or their CI) reads "no findings" and assumes the code
/// is clean. That's the definition of a silent-data-loss bug.
///
/// `pub(crate)` so subcommands (`watch`, `scan-system`, `explain`)
/// share the gate. They all have their own `load_detectors`
/// helpers that historically bypassed this check.
pub(crate) fn require_non_empty_detectors(
    detectors: &[DetectorSpec],
    detectors_path: &Path,
) -> Result<()> {
    if detectors.is_empty() {
        anyhow::bail!(
            "loaded zero detectors from {}. \
             Fix: verify the directory contains valid `*.toml` detector \
             specs (run `keyhog detectors --detectors {}` to see \
             which TOMLs were rejected, if any). Refusing to scan with \
             no detectors loaded - that would silently report `no \
             findings` regardless of what's in the source.",
            detectors_path.display(),
            detectors_path.display(),
        );
    }
    Ok(())
}

/// Load detectors from a directory, falling back to the embedded TOML
/// corpus when the directory is empty / non-existent / all-rejected.
///
/// `pub(crate)` so the per-subcommand modules (`watch`, `explain`,
/// `scan_system`, `detectors`) can each call this one helper instead of
/// shipping divergent copies. Pre-2026-05-24 each subcommand had its
/// own load+fallback wrapper and the copies had drifted on error
/// messages and on the fallback-to-embedded branch - kimi-dedup rows #4-6.
// `pub` (was pub(crate)) so the relocated explain test loads the embedded
// corpus through the same path production uses (no_inline_tests_in_src gate).
pub(crate) fn load_detectors_or_embedded(path: &Path) -> Result<Vec<DetectorSpec>> {
    validate_detector_path_for_scan(path)?;
    if path.exists() && path.is_dir() {
        let loaded = load_detectors(path).context("loading detectors from directory")?;
        require_non_empty_detectors(&loaded, path)?;
        return Ok(loaded);
    }
    load_detectors_embedded_or_fail(path)
}

pub(crate) fn detector_compile_failed(
    command: &str,
    detectors_path: &Path,
    error: impl fmt::Display,
) -> anyhow::Error {
    anyhow::anyhow!(
        "{command}: scanner compile failed while compiling detectors from '{}': {error}. \
         Fix: run `keyhog detectors --audit --detectors {}` and repair detector errors, \
         or omit --detectors to use the embedded corpus.",
        detectors_path.display(),
        detectors_path.display(),
    )
}

fn validate_detector_path_for_scan(path: &Path) -> Result<()> {
    if path.exists() && !path.is_dir() {
        anyhow::bail!(
            "detectors path '{}' is not a directory. \
             Fix: pass a directory containing detector TOML files, or omit \
             --detectors to use the embedded corpus.",
            path.display()
        );
    }
    if !path.exists() && path != Path::new("detectors") {
        anyhow::bail!(
            "detectors directory '{}' does not exist. \
             Fix: pass an existing detector directory, or omit --detectors to \
             use the embedded corpus.",
            path.display()
        );
    }
    Ok(())
}

fn load_detectors_embedded_or_fail(path: &Path) -> Result<Vec<DetectorSpec>> {
    // The embedded set being empty is the one runtime-actionable case (the binary
    // was built without baking in any detectors): tell the operator how to point
    // at an on-disk corpus instead. Everything past here delegates to the single
    // shared fail-closed loader in keyhog_core so every scan entry point parses
    // the compiled-in corpus byte-for-byte the same way.
    if keyhog_core::embedded_detector_count() == 0 {
        anyhow::bail!(
            "detectors directory '{}' not found and no embedded detectors available. \
             Fix: specify --detectors <path> or install a binary with embedded detectors",
            path.display()
        );
    }
    tracing::info!(
        embedded_count = keyhog_core::embedded_detector_count(),
        "using embedded detectors (no external detectors directory found)"
    );
    // Fails closed (returns `Err`) if ANY embedded detector TOML is malformed -
    // a corrupt compiled-in corpus is a hard error, never a silently-dropped
    // recall hole (Law 10).
    Ok(keyhog_core::load_embedded_detectors_or_fail()?)
}

#[doc(hidden)]
pub(crate) mod testing {
    use anyhow::Result;
    use keyhog_core::DetectorSpec;
    use std::path::Path;

    pub(crate) fn load_detectors_from_dir_with_cache(
        source_dir: &Path,
        cache_path: &Path,
    ) -> Result<Vec<DetectorSpec>> {
        super::load_detectors_from_dir_with_cache(source_dir, cache_path)
    }
}
