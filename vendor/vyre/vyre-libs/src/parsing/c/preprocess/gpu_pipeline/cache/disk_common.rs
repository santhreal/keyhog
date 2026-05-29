use std::path::PathBuf;

use super::classified_memory::{ClassifiedCacheKey, PREPROCESS_CACHE_SEMANTIC_VERSION};

// ---------------------------------------------------------------
// Disk-backed persistence for classified_cache (T030 first half).
//
// Default location is `${XDG_CACHE_HOME:-$HOME/.cache}/vyre/parsed-ast/`. Each entry is a
// length-prefixed binary file named by the (path, source_len, source_
// hash) cache key  -  a cache miss in process memory consults disk
// before paying for the GPU lex+classify dispatches; a successful
// disk hit also warms the in-memory cache so subsequent hits in the
// same process pay no I/O.
// ---------------------------------------------------------------

/// Magic header so a stale or unrelated file in the cache directory
/// can be rejected immediately rather than mis-decoded.
pub(crate) const CLASSIFIED_DISK_MAGIC: &[u8; 8] = b"VYRECTS1";

pub(crate) static DISK_CACHE_TMP_COUNTER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub(crate) fn parsed_ast_cache_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .unwrap_or_else(|| {
            panic!("vyre C GPU preprocessor disk cache has no XDG_CACHE_HOME or HOME. Fix: configure a writable cache root; silent cache disable is a production performance regression.")
        });
    let dir = base.join("vyre").join("parsed-ast");
    std::fs::create_dir_all(&dir).unwrap_or_else(|error| {
        panic!(
            "vyre C GPU preprocessor disk cache could not create {}: {error}. Fix: configure a writable cache directory.",
            dir.display()
        )
    });
    dir
}

pub(crate) fn disk_cache_tmp_path(path: &std::path::Path, extension: &str) -> PathBuf {
    let seq = DISK_CACHE_TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    path.with_extension(format!("{extension}.{}.{}.tmp", std::process::id(), seq))
}

pub(crate) fn remove_disk_cache_file(path: &std::path::Path, context: &str) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            panic!(
                "vyre C GPU preprocessor disk cache could not remove stale {context} entry {}: {error}. Fix: repair cache directory permissions or delete the cache root.",
                path.display()
            )
        }
    }
}

pub(crate) fn publish_disk_cache_file(
    tmp: &std::path::Path,
    path: &std::path::Path,
    context: &str,
) {
    if let Err(rename_error) = std::fs::rename(tmp, path) {
        match std::fs::remove_file(tmp) {
            Ok(()) => {}
            Err(cleanup_error) if cleanup_error.kind() == std::io::ErrorKind::NotFound => {}
            Err(cleanup_error) => {
                panic!(
                    "vyre C GPU preprocessor disk cache could not publish {context} entry {} from {}: {rename_error}; cleanup also failed: {cleanup_error}. Fix: repair cache directory permissions.",
                    path.display(),
                    tmp.display()
                )
            }
        }
        panic!(
            "vyre C GPU preprocessor disk cache could not publish {context} entry {} from {}: {rename_error}. Fix: repair cache directory permissions.",
            path.display(),
            tmp.display()
        );
    }
}

pub(crate) fn source_hash128(source: &[u8]) -> [u8; 16] {
    let digest = blake3::hash(source);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest.as_bytes()[..16]);
    out
}

pub(crate) fn cache_key_stem(
    path_bytes: &[u8],
    source_len: usize,
    source_hash: [u8; 16],
    macro_fingerprint: Option<[u8; 16]>,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(PREPROCESS_CACHE_SEMANTIC_VERSION.len() as u64).to_le_bytes());
    hasher.update(PREPROCESS_CACHE_SEMANTIC_VERSION);
    hasher.update(&(path_bytes.len() as u64).to_le_bytes());
    hasher.update(path_bytes);
    hasher.update(&(source_len as u64).to_le_bytes());
    hasher.update(&source_hash);
    if let Some(macro_fingerprint) = macro_fingerprint {
        hasher.update(&macro_fingerprint);
    }
    let digest = hasher.finalize();
    let mut stem = String::with_capacity(32);
    for byte in &digest.as_bytes()[..16] {
        use std::fmt::Write as _;

        let _ = write!(&mut stem, "{byte:02x}");
    }
    stem
}

pub(crate) fn classified_disk_path(dir: &std::path::Path, key: &ClassifiedCacheKey) -> PathBuf {
    dir.join(format!(
        "{}.vct",
        cache_key_stem(
            key.path.as_os_str().as_encoded_bytes(),
            key.source_len,
            key.source_hash,
            None,
        )
    ))
}
