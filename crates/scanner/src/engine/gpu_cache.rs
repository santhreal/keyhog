//! On-disk cache helpers for compiled GPU matchers (the megakernel catalog
//! cache lives at `~/.cache/keyhog/programs/` and is keyed via these helpers).

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

/// On-disk cache for `GpuLiteralSet`. The compiled matcher is keyed by a
/// SHA-256 of the literal set + the vyre wire version (which is bumped
/// whenever the IR layout changes), so bumping vyre to a new minor
/// version automatically invalidates the cache instead of silently
/// loading a stale matcher. Lives at `$XDG_CACHE_HOME/keyhog/programs/`
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
    if !dir.exists() {
        std::fs::create_dir_all(&dir).map_err(|source| GpuMatcherCacheDirError::Create {
            path: dir.clone(),
            source,
        })?;
    }
    Ok(dir)
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
