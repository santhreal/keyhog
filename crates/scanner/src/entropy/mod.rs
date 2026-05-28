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

/// Shannon entropy in bits per byte, with thread-local caching for repeat
/// inputs ≤1KB (typical credential size). Cache evicts wholesale when full
/// to bound memory under adversarial input.
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

    // Fast hash for cache key - FNV-1a, same as decode pipeline
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
            cache.clear(); // simple eviction - bounded memory
        }
        cache.insert(hash, entropy);
        entropy
    })
}

fn shannon_entropy_uncached(data: &[u8]) -> f64 {
    crate::entropy_fast::shannon_entropy_simd(data)
}

/// Shannon entropy rescaled to `0.0..=1.0` by dividing by `log2(unique_bytes)`.
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

/// True if the file at `path` is worth running entropy scanning on.
pub fn is_entropy_appropriate(path: Option<&str>, allow_source_files: bool) -> bool {
    let Some(path) = path else { return true };
    // ASCII case-insensitive byte comparison - no whole-path lowercase
    // allocation per call. Hot path on every chunk during a scan.
    let bytes = path.as_bytes();
    let ends_ci = |suffix: &[u8]| -> bool {
        bytes.len() >= suffix.len()
            && bytes[bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    };

    for extension in [b".json".as_slice(), b".lock", b".map"] {
        if ends_ci(extension) {
            return false;
        }
    }
    if ends_ci(b".min.js") || ends_ci(b".min.css") {
        return false;
    }
    if allow_source_files {
        return true;
    }

    // Last segment after `/` or `\` - index into bytes, no alloc.
    let last_sep = bytes
        .iter()
        .rposition(|&b| b == b'/' || b == b'\\')
        .map(|i| i + 1)
        .unwrap_or(0);
    let filename = &bytes[last_sep..];

    // Package-manifest exclusion: Cargo.toml / package.json / pyproject.toml
    // / Pipfile / Gemfile / pom.xml / build.gradle have [package.keywords]
    // / "keywords" / "categories" array data that look like high-entropy
    // strings but are package metadata, not credentials. Entropy fires on
    // ["compression", "encryption", "history"] as `entropy-api-key`
    // because the array literal happens to clear the keyword + entropy
    // thresholds. Suppress on stem match, ASCII case-insensitive.
    // #15 regression: envseal dogfood, ~10 FPs per Cargo.toml.
    for stem in [
        b"Cargo.toml".as_slice(),
        b"package.json",
        b"pyproject.toml",
        b"composer.json",
        b"Pipfile",
        b"Gemfile",
        b"pom.xml",
        b"build.gradle",
        b"build.gradle.kts",
        b"build.sbt",
        b"mix.exs",
    ] {
        if filename.eq_ignore_ascii_case(stem) {
            return false;
        }
    }

    for extension in [
        b".env".as_slice(),
        b".yaml",
        b".yml",
        b".toml",
        b".properties",
        b".cfg",
        b".conf",
        b".ini",
        b".config",
        b".secrets",
        b".pem",
        b".key",
        b".tfvars",
        b".hcl",
    ] {
        if ends_ci(extension) {
            return true;
        }
    }

    // Filename-prefix match: `.env-staging`, `.env.production` should count
    // as a secret file. But `secrets.rs`, `credentials.py`, `apikeys.go`
    // are source code ABOUT credentials, not credential files - the
    // surrounding code uses `secret` / `credential` / `apikey` as
    // identifiers, and the entropy fallback was misclassifying every
    // identifier-shaped value on those lines as `entropy-api-key`.
    //
    // Split policy:
    //   - `.env` keeps the prefix-match semantics (legitimate variants
    //     exist: `.env-staging`, `.env.production`, `.envfile`).
    //   - All other names require an EXACT filename match (no extension)
    //     OR a prefix match followed by a known config extension
    //     (`secrets.env`, `credentials.yaml`, `apikeys.toml`).
    //
    // #15 regression: envseal/cli/src/tui/secrets.rs fired entropy on
    // every `Style`/`Paragraph::new` call because filename prefix
    // "secrets" matched. After this filter, scanning a `secrets.rs`
    // requires `--entropy-source-files`.
    const PREFIX_MATCH_NAMES: &[&[u8]] = &[b".env", b".npmrc", b".pypirc", b".netrc"];
    for name in PREFIX_MATCH_NAMES {
        let starts_ci =
            filename.len() >= name.len() && filename[..name.len()].eq_ignore_ascii_case(name);
        if starts_ci {
            return true;
        }
    }

    const EXACT_OR_CONFIG_EXT_NAMES: &[&[u8]] =
        &[b"credentials", b"secrets", b"apikeys", b"docker-compose"];
    const CONFIG_EXTENSIONS_AFTER_STEM: &[&[u8]] = &[
        b".env",
        b".yaml",
        b".yml",
        b".toml",
        b".properties",
        b".cfg",
        b".conf",
        b".ini",
        b".config",
        b".secrets",
        b".pem",
        b".key",
        b".tfvars",
        b".hcl",
        b".enc",
        b".vault",
        b".prod",
        b".txt",
    ];
    for name in EXACT_OR_CONFIG_EXT_NAMES {
        if filename.eq_ignore_ascii_case(name) {
            return true;
        }
        // Prefix + config extension: `secrets.yaml`, `credentials.env`,
        // `apikeys.toml`, `secrets-prod.toml`. The trailing extension
        // gate keeps `secrets.rs`, `credentials.py`, etc. on the
        // source-code path (skipped unless --entropy-source-files).
        if filename.len() > name.len() && filename[..name.len()].eq_ignore_ascii_case(name) {
            let tail = &filename[name.len()..];
            for ext in CONFIG_EXTENSIONS_AFTER_STEM {
                if tail.len() >= ext.len()
                    && tail[tail.len() - ext.len()..].eq_ignore_ascii_case(ext)
                {
                    return true;
                }
            }
        }
    }
    false
}
