//! On-disk cache helpers for compiled GPU literal-set matchers.
//! Cache blobs live at `~/.cache/keyhog/programs/` and are keyed here.

#[derive(Debug)]
pub(crate) enum GpuMatcherCacheDirError {
    MissingUserCacheDir,
    Create {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for GpuMatcherCacheDirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingUserCacheDir => write!(f, "no user cache directory is available"),
            Self::Create { path, source } => {
                write!(
                    f,
                    "failed to create GPU matcher cache dir {}: {source}",
                    path.display()
                )
            }
        }
    }
}

/// Local cache-format version mixed into every GPU matcher cache key. Bump
/// this when KeyHog's literal-row derivation changes in a way that must
/// invalidate on-disk matchers. It does NOT track VYRE's wire version: a
/// VYRE wire-format change is caught on load by `GpuLiteralSet::from_bytes`
/// (through `cached_load_or_compile`), which rejects and recompiles a blob
/// whose envelope no longer matches, so a stale matcher is never loaded
/// silently. Cache blobs live at `$XDG_CACHE_HOME/keyhog/programs/`
/// (typically `~/.cache/keyhog/programs/`).
const GPU_MATCHER_CACHE_VERSION: u32 = 1;

pub(crate) fn gpu_matcher_cache_dir() -> Result<std::path::PathBuf, GpuMatcherCacheDirError> {
    gpu_matcher_cache_dir_from_base(dirs::cache_dir())
}

pub(crate) fn gpu_matcher_cache_dir_from_base(
    base: Option<std::path::PathBuf>,
) -> Result<std::path::PathBuf, GpuMatcherCacheDirError> {
    let dir = base
        .ok_or(GpuMatcherCacheDirError::MissingUserCacheDir)?
        .join("keyhog")
        .join("programs");
    // `create_dir_all` is idempotent (Ok when the dir already exists), so an
    // explicit `exists()` pre-check would only add a redundant stat and a
    // TOCTOU window.
    std::fs::create_dir_all(&dir).map_err(|source| GpuMatcherCacheDirError::Create {
        path: dir.clone(),
        source,
    })?;
    Ok(dir)
}

/// Canonical `"{prefix}-{hash}"` cache key for a GPU literal matcher. This is
/// the single owner of the prefixed-key derivation shared by the runtime lazy
/// compiler and the offline artifact compiler.
pub(crate) fn gpu_matcher_cache_key_with_prefix(cache_prefix: &str, literals: &[&[u8]]) -> String {
    format!("{cache_prefix}-{}", gpu_matcher_cache_key(literals))
}

pub(crate) fn gpu_matcher_cache_key(literals: &[&[u8]]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(GPU_MATCHER_CACHE_VERSION.to_le_bytes());
    h.update((literals.len() as u32).to_le_bytes());
    for lit in literals {
        h.update((lit.len() as u32).to_le_bytes());
        h.update(lit);
    }
    let digest: [u8; 32] = h.finalize().into();
    keyhog_core::hex_encode(&digest)
}
