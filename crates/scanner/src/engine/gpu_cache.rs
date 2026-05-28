//! GPU matcher on-disk cache helpers and constant-pack types.

/// Cached per-process GPU input constants - pre-packed LE byte streams
/// for the four pattern-shape inputs the GpuLiteralSet kernel reads on
/// every dispatch. Filled on first scan, borrowed thereafter.
pub struct GpuConstPacks {
    pub pattern_offsets: Vec<u8>,
    pub pattern_lengths: Vec<u8>,
    pub pattern_bytes: Vec<u8>,
    pub pattern_count: Vec<u8>,
}

/// Cached per-process AC-kernel input constants - pre-packed LE byte
/// streams for the four DFA-shape inputs the AC bounded-ranges kernel
/// reads on every dispatch. Separate from `GpuConstPacks` because the
/// AC kernel binds different fields (`dfa.transitions`,
/// `dfa.output_offsets`, `dfa.output_records`, `pattern_lengths`).
pub struct AcConstPacks {
    pub transitions: Vec<u8>,
    pub output_offsets: Vec<u8>,
    pub output_records: Vec<u8>,
    pub pattern_lengths: Vec<u8>,
}

/// On-disk cache for `GpuLiteralSet`. The compiled matcher is keyed by a
/// SHA-256 of the literal set + the vyre wire version (which is bumped
/// whenever the IR layout changes), so bumping vyre to a new minor
/// version automatically invalidates the cache instead of silently
/// loading a stale matcher. Lives at `$XDG_CACHE_HOME/keyhog/programs/`
/// (typically `~/.cache/keyhog/programs/`).
const GPU_MATCHER_CACHE_VERSION: u32 = 1;

pub(crate) fn gpu_matcher_cache_dir() -> Option<std::path::PathBuf> {
    let dir = dirs::cache_dir()?.join("keyhog").join("programs");
    if !dir.exists() && std::fs::create_dir_all(&dir).is_err() {
        return None;
    }
    Some(dir)
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
    let digest = h.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{:02x}", byte);
    }
    hex
}
