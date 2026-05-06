//! Shannon entropy analysis for distinguishing secrets from ordinary text.
//!
//! Real secrets have high entropy (4.5+), while hashes, UUIDs, and placeholders
//! have characteristic entropy profiles that help separate true positives.

pub mod keywords;
mod scanner;

pub use scanner::{find_entropy_secrets, find_entropy_secrets_with_threshold, is_sensitive_file};

/// Threshold for keyword-context entropy detection.
pub const LOW_ENTROPY_THRESHOLD: f64 = 3.0;
pub const HIGH_ENTROPY_THRESHOLD: f64 = 4.5;
/// Threshold for keyword-independent entropy detection.
pub const VERY_HIGH_ENTROPY_THRESHOLD: f64 = 5.8;
/// Threshold for keyword-independent detection in clearly sensitive files.
pub const SENSITIVE_FILE_VERY_HIGH_ENTROPY_THRESHOLD: f64 = 5.5;

/// Shannon entropy in bits per byte.
/// Compute Shannon entropy of a byte slice, with thread-local caching.
///
/// At scale, many matches in the same file produce identical or overlapping
/// credential strings. The cache eliminates redundant entropy computations
/// using a fast hash of the input as key. Cache is bounded to prevent
/// unbounded memory growth on adversarial input.
/// Compute the Shannon entropy of a byte slice.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    // Length gate: don't cache entropy for massive buffers (e.g. minified JS)
    // that won't repeat exactly. Just calculate directly.
    if data.len() > 1024 {
        return shannon_entropy_uncached(data);
    }

    use std::cell::RefCell;
    use std::collections::HashMap;

    const MAX_CACHE_ENTRIES: usize = 4096;

    thread_local! {
        static CACHE: RefCell<HashMap<u64, f64>> = RefCell::new(HashMap::with_capacity(256));
    }

    // Fast hash for cache key — FNV-1a, same as decode pipeline
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }

    CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(&cached) = cache.get(&hash) {
            return cached;
        }
        let entropy = shannon_entropy_uncached(data);
        if cache.len() >= MAX_CACHE_ENTRIES {
            cache.clear(); // simple eviction — bounded memory
        }
        cache.insert(hash, entropy);
        entropy
    })
}

fn shannon_entropy_uncached(data: &[u8]) -> f64 {
    crate::entropy_fast::shannon_entropy_simd(data)
}

/// Compute entropy normalized to the range `0.0..=1.0`.
/// Compute entropy normalized to the range 0.0..=1.0.
pub fn normalized_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let unique_chars = {
        let mut seen = [false; 256];
        for &byte in data {
            seen[byte as usize] = true;
        }
        seen.iter().filter(|&&value| value).count()
    };

    if unique_chars <= 1 {
        return 0.0;
    }

    let max_entropy = (unique_chars as f64).log2();
    if max_entropy == 0.0 {
        return 0.0;
    }

    shannon_entropy(data) / max_entropy
}

/// Entropy-based candidate match returned by fallback secret detection.
#[derive(Debug, Clone)]
pub struct EntropyMatch {
    /// The candidate string that exceeded the entropy threshold.
    pub value: String,
    /// Shannon entropy measured for `value`.
    pub entropy: f64,
    /// The keyword context that caused the candidate to be evaluated.
    pub keyword: String,
    /// One-based source line number for the match.
    pub line: usize,
    /// Byte offset of the start of the containing line.
    pub offset: usize,
}

/// Decide whether entropy scanning should run for the given path.
/// Check if entropy analysis is appropriate for a given file path.
pub fn is_entropy_appropriate(path: Option<&str>, allow_source_files: bool) -> bool {
    let Some(path) = path else { return true };
    let lower = path.to_lowercase();

    for extension in [".json", ".lock", ".map"] {
        if lower.ends_with(extension) {
            return false;
        }
    }
    if lower.ends_with(".min.js") || lower.ends_with(".min.css") {
        return false;
    }
    if allow_source_files {
        return true;
    }

    for extension in [
        ".env",
        ".yaml",
        ".yml",
        ".toml",
        ".properties",
        ".cfg",
        ".conf",
        ".ini",
        ".config",
        ".secrets",
        ".pem",
        ".key",
        ".tfvars",
        ".hcl",
    ] {
        if lower.ends_with(extension) {
            return true;
        }
    }

    let filename = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);
    for name in [
        ".env",
        "credentials",
        "secrets",
        "apikeys",
        "docker-compose",
        ".npmrc",
        ".pypirc",
        ".netrc",
    ] {
        if filename.starts_with(name) || filename == name {
            return true;
        }
    }
    false
}
