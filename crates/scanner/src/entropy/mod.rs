//! Shannon entropy analysis for distinguishing secrets from ordinary text.
//!
//! Real secrets have high entropy (4.5+), while hashes, UUIDs, and placeholders
//! have characteristic entropy profiles that help separate true positives.

/// BPE "rare-not-random" precision gate (tiktoken cl100k_base bytes-per-token).
/// Gated on `entropy`: the tokenizer dep rides that feature.
#[cfg(feature = "entropy")]
pub(crate) mod bpe;
mod isolated;
pub(crate) mod keywords;
pub(crate) mod plausibility;
pub(crate) mod scanner;

// Fast Shannon-entropy primitives, relocated here from the crate root so all
// entropy code shares one home. `fast` is the scalar dispatcher that routes to
// the SIMD impls by runtime capability; the impls are arch-gated.
/// AVX-512 optimized entropy calculation.
pub(crate) mod avx512;
/// Fast scalar entropy dispatcher (routes to the SIMD impls below).
pub(crate) mod fast;
#[cfg(target_arch = "aarch64")]
pub(crate) mod fast_neon;
#[cfg(target_arch = "x86_64")]
pub(crate) mod fast_x86;

pub(crate) use scanner::KEYWORD_FREE_LABEL;
pub use scanner::{find_entropy_secrets, find_entropy_secrets_with_threshold};

/// Threshold for keyword-context entropy detection.
///
/// This is the single-owner default for the per-detector `DetectorSpec::entropy_low` field,
/// applied only when a detector leaves that field unset (not a global gate applied uniformly).
pub const LOW_ENTROPY_THRESHOLD: f64 = 3.0;

/// Default threshold for keyword-independent entropy detection.
///
/// This is the single-owner default for the per-detector `DetectorSpec::entropy_high` field,
/// applied only when a detector leaves that field unset (not a global gate applied uniformly).
pub const HIGH_ENTROPY_THRESHOLD: f64 = 4.5;

/// Floor for mixed alpha+digit tokens that carry stronger evidence than a
/// normal keyword-free substring: either the whole line is the token, or a
/// credential/auth anchor owns the quoted value. Kept below the global 4.5
/// floor but above low-entropy identifiers.
///
/// This is the single-owner default for the per-detector `DetectorSpec::mixed_alnum_floor` field,
/// applied only when a detector leaves that field unset (not a global gate applied uniformly).
pub(crate) const MIXED_ALNUM_TOKEN_THRESHOLD: f64 = 4.0;

pub(crate) const ISOLATED_BARE_ENTROPY_LABEL: &str = "none (isolated-token)";

/// Minimum length for an anchor-free (keyword-free / isolated) entropy token.
/// Single owner for the 20-char floor referenced by the keyword-free candidate
/// path (`scanner`) and the isolated-token mixed/colon shape floors
/// (`isolated`), which previously pasted the bare literal `20` in each predicate.
///
/// This is the single-owner default for the per-detector `DetectorSpec::keyword_free_min_len` field,
/// applied only when a detector leaves that field unset (not a global gate applied uniformly).
pub(crate) const KEYWORD_FREE_MIN_LEN: usize = 20;

/// Threshold for keyword-independent entropy detection.
///
/// This is the single-owner default for the per-detector `DetectorSpec::entropy_very_high` field,
/// applied only when a detector leaves that field unset (not a global gate applied uniformly).
pub const VERY_HIGH_ENTROPY_THRESHOLD: f64 = 5.8;

/// One-based offset added to a zero-based `text.lines()` index to produce the
/// [`EntropyMatch::line`] source line number. Single canonical owner for the
/// 0→1 line-base convention shared by the line-scoped scanner
/// (`scanner::find_entropy_secrets_with_threshold`) and the isolated-bare token
/// path (`isolated::collect_isolated_bare_candidates`), both add it to their
/// enumerated line index, so the convention lives in exactly one place.
pub(crate) const FIRST_SOURCE_LINE_NUMBER: usize = 1;

/// The single decision shared by the keyword-anchored and isolated-bare floor
/// policies: does the operator's Tier-A `entropy_threshold` OVERRIDE the
/// anchored floor?
///
/// An assignment keyword (`api_key=`) or an isolated opaque token is positive
/// evidence, so the anchored paths run at a LOW named floor by default
/// (recall-oriented, the anchor, not raw entropy, carries the signal). The
/// operator knob therefore engages ONLY when it is *stricter* than the blanket
/// [`HIGH_ENTROPY_THRESHOLD`]: a caller asking for a bar tighter than the global
/// high floor is honored verbatim (`Some(threshold)`); at or below HIGH, or
/// non-finite, the anchored floor applies (`None`) and each caller supplies its
/// own floor ([`LOW_ENTROPY_THRESHOLD`] for the keyword path,
/// [`MIXED_ALNUM_TOKEN_THRESHOLD`] for the isolated path).
///
/// This is a NAMED, TESTED policy, explicitly NOT a silent clamp. The two call
/// sites (`scanner::keyword_context`, `isolated::isolated_bare_entropy_threshold`)
/// used to inline byte-divergent copies of this same `> HIGH` test, which is the
/// exact ONE-PLACE hazard: one owner means a change to the override rule reaches
/// both floors at once, and the resolution at every band is pinned by tests.
pub(super) fn operator_entropy_override(entropy_threshold: f64) -> Option<f64> {
    (entropy_threshold.is_finite() && entropy_threshold > HIGH_ENTROPY_THRESHOLD)
        .then_some(entropy_threshold)
}

/// Config/secret file extensions that mark a path as entropy-appropriate. Single
/// owner: both the direct extension check and the stem+extension check in
/// [`is_entropy_appropriate_inner`] reference this set (the latter also allows
/// the [`extra_stem_config_extensions`] tail).
#[derive(serde::Deserialize)]
struct ConfigFileExtensionsFile {
    extensions: Vec<String>,
    stem_only_extensions: Vec<String>,
}

fn parse_config_file_extensions(raw: &str) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), String> {
    toml::from_str::<ConfigFileExtensionsFile>(raw)
        .map(|parsed| {
            (
                parsed
                    .extensions
                    .into_iter()
                    .map(String::into_bytes)
                    .collect(),
                parsed
                    .stem_only_extensions
                    .into_iter()
                    .map(String::into_bytes)
                    .collect(),
            )
        })
        .map_err(|error| error.to_string())
}

/// `(direct extensions, stem-only extensions)`, loaded once from the bundled
/// Tier-B `rules/config-file-extensions.toml`. `include_str!` embeds the file at
/// compile time, so a parse failure is a build defect in the bundled data, not
/// a runtime hostile-input risk (and fails closed (Law 10), naming the file).
static CONFIG_EXTENSION_LISTS: std::sync::LazyLock<(Vec<Vec<u8>>, Vec<Vec<u8>>)> =
    std::sync::LazyLock::new(|| {
        match parse_config_file_extensions(include_str!(
            "../../../../rules/config-file-extensions.toml"
        )) {
            Ok(lists) => lists,
            Err(error) => panic!(
                "rules/config-file-extensions.toml is invalid: {error}. Fix the bundled Tier-B \
                 config-file-extension list."
            ),
        }
    });

/// Config/secrets file extensions matched directly on any filename tail.
fn config_file_extensions() -> &'static [Vec<u8>] {
    &CONFIG_EXTENSION_LISTS.0
}

/// Extra extensions accepted only after a known credential stem
/// (`secrets.enc`, `credentials.vault`, …), on top of [`config_file_extensions`].
fn extra_stem_config_extensions() -> &'static [Vec<u8>] {
    &CONFIG_EXTENSION_LISTS.1
}

#[derive(serde::Deserialize)]
struct CredentialFileNamesFile {
    prefix_match: Vec<String>,
    exact_or_config_ext: Vec<String>,
}

/// Parse the Tier-B credential-store filename lists. Returns an error (rather
/// than panicking) so the single `CREDENTIAL_FILE_NAME_LISTS` owner below is the
/// one fail-closed site, and enforces that BOTH lists are non-empty.
fn parse_credential_file_names(raw: &str) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), String> {
    let parsed: CredentialFileNamesFile = toml::from_str(raw).map_err(|error| error.to_string())?;
    if parsed.prefix_match.is_empty() || parsed.exact_or_config_ext.is_empty() {
        return Err("prefix_match and exact_or_config_ext must both be non-empty".to_string());
    }
    Ok((
        parsed
            .prefix_match
            .into_iter()
            .map(String::into_bytes)
            .collect(),
        parsed
            .exact_or_config_ext
            .into_iter()
            .map(String::into_bytes)
            .collect(),
    ))
}

/// `(prefix-match names, exact-or-config-ext names)`: the credential-store
/// filenames the entropy fallback treats as secret files, loaded once from the
/// bundled Tier-B `rules/credential-file-names.toml`. Fails closed (Law 10),
/// naming the file, since a parse failure is a build defect in bundled data.
static CREDENTIAL_FILE_NAME_LISTS: std::sync::LazyLock<(Vec<Vec<u8>>, Vec<Vec<u8>>)> =
    std::sync::LazyLock::new(|| {
        match parse_credential_file_names(include_str!(
            "../../../../rules/credential-file-names.toml"
        )) {
            Ok(lists) => lists,
            Err(error) => panic!(
                "rules/credential-file-names.toml is invalid: {error}. Fix the bundled Tier-B \
                 credential-file-name list."
            ),
        }
    });

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

    thread_local! {
        static CACHE: RefCell<HashMap<u64, f64>> = RefCell::new(HashMap::with_capacity(256));
    }

    // FNV-1a content key, shared seed with every other per-scan cache.
    let hash = crate::util_hash::hash_fast(data);
    crate::util_hash::memoize_by_hash(
        &CACHE,
        hash,
        crate::util_hash::DEFAULT_MAX_CACHE_ENTRIES,
        || shannon_entropy_uncached(data),
    )
}

fn shannon_entropy_uncached(data: &[u8]) -> f64 {
    crate::entropy::fast::shannon_entropy_simd(data)
}

/// Number of DISTINCT byte values present in `data` (`0..=256`), via a single
/// pass over a 256-entry presence table.
///
/// The shared primitive behind three byte-identical copies of this loop:
/// [`normalized_entropy`]'s `log2(unique)` denominator, the confidence shape
/// gate `confidence::penalties::char_diversity`, and the ML feature
/// `ml_scorer::ml_features::unique_byte_count`. Both consumers live downstream
/// of `entropy` (each already imports from it), so this is the natural home.
pub(crate) fn unique_byte_count(data: &[u8]) -> usize {
    let mut seen = [false; 256];
    let mut count = 0usize;
    for &byte in data {
        let slot = &mut seen[byte as usize];
        if !*slot {
            *slot = true;
            count += 1;
        }
    }
    count
}

/// Shannon entropy rescaled to `0.0..=1.0` by dividing by `log2(unique_bytes)`.
pub fn normalized_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let unique_chars = unique_byte_count(data);

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
    /// Byte offset used to locate the match in preprocessed text. Most
    /// line-scoped entropy candidates use the containing line start; isolated
    /// token candidates use the token start.
    pub offset: usize,
}

/// True if the file at `path` is worth running entropy scanning on.
///
/// Path-only gate: `.json` and all source-code extensions are hard-OFF here.
/// For the keyword-anchored lift of those hard-OFFs (a `.json` body or a
/// source file that carries a secret-keyword assignment line still holds
/// real, unprefixed high-entropy secrets), call
/// [`is_entropy_appropriate_with_content`], which the entropy fallback uses.
pub fn is_entropy_appropriate(path: Option<&str>, allow_source_files: bool) -> bool {
    is_entropy_appropriate_inner(path, allow_source_files, false)
}

/// Content-aware variant of [`is_entropy_appropriate`].
///
/// `has_secret_keyword_line` is true when the chunk text contains at least one
/// secret-keyword assignment line. For config/data files this uses the same
/// broader predicate the entropy scanner uses to seed keyword contexts. For
/// source-code files it is intentionally narrower: only a same-line credential
/// assignment surface such as `apiKey = "..."` lifts the source-file hard-OFF.
/// Ordinary compiler/parser code is full of `Token`, `key`, `signature`, and
/// `digest` identifiers next to `=`/`:`; treating those as credential context
/// turns the whole source chunk into entropy noise. When set, two path-only
/// hard-OFFs are lifted:
///
///   * `.json` files (the single biggest FN wrapper - `{"auth": "<40-char
///     base64>"}` was scoring 0 while the identical `auth: "<same>"` in
///     `.yaml` was caught), and
///   * source-code files when `allow_source_files` is false (the dominant
///     go/rust/js FN shape `const apiKey = "<base64-40>"` lives in a quoted
///     RHS of a const/assignment with a secret keyword).
///
/// Both lifts are contract-safe: the keyword-assignment anchor confines the
/// recall expansion to credential-shaped lines, away from prose / identifiers,
/// and the per-candidate suppression gates on the emit path
/// (pure-identifier, prose, kebab, filename-shape, ...) still run.
///
/// `.lock` / `.map` / minified bundles stay hard-OFF unconditionally - they
/// are not credential wrappers, only alphabet-coincidence noise.
pub fn is_entropy_appropriate_with_content(
    path: Option<&str>,
    allow_source_files: bool,
    text: &str,
    secret_keywords: &[String],
) -> bool {
    let lines: Vec<&str> = text.lines().collect();
    is_entropy_appropriate_with_content_lines(path, allow_source_files, &lines, secret_keywords)
}

pub(crate) fn is_entropy_appropriate_with_content_lines(
    path: Option<&str>,
    allow_source_files: bool,
    lines: &[&str],
    secret_keywords: &[String],
) -> bool {
    let source_path = crate::decode::caesar::is_program_source_code_path(path);
    let has_secret_keyword_line = if source_path && !allow_source_files {
        lines
            .iter()
            .copied()
            .any(keywords::line_has_credential_assignment_surface)
    } else {
        !keywords::find_keyword_assignment_lines(lines, secret_keywords).is_empty()
    };
    is_entropy_appropriate_inner(path, allow_source_files, has_secret_keyword_line)
}

pub(crate) fn is_entropy_appropriate_inner(
    path: Option<&str>,
    allow_source_files: bool,
    has_secret_keyword_line: bool,
) -> bool {
    let Some(path) = path else { return true };
    // ASCII case-insensitive byte comparison - no whole-path lowercase
    // allocation per call. Hot path on every chunk during a scan.
    let bytes = path.as_bytes();
    let ends_ci = |suffix: &[u8]| -> bool {
        bytes.len() >= suffix.len()
            && bytes[bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    };

    // `.lock` / `.map` are never credential wrappers - stay hard-OFF even with
    // a keyword line. `.json` is lifted when a secret-keyword assignment line
    // is present (part (a) of the FN-recall fix): JSON is the biggest FN
    // wrapper, but only the keyword-anchored bodies hold real secrets.
    for extension in [b".lock".as_slice(), b".map"] {
        if ends_ci(extension) {
            return false;
        }
    }
    if ends_ci(b".json") && !has_secret_keyword_line {
        return false;
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
        .unwrap_or(0); // LAW10: empty/absent => documented numeric/sentinel default, recall-safe
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

    for extension in config_file_extensions() {
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
    for name in &CREDENTIAL_FILE_NAME_LISTS.0 {
        let starts_ci =
            filename.len() >= name.len() && filename[..name.len()].eq_ignore_ascii_case(name);
        if starts_ci {
            return true;
        }
    }

    for name in &CREDENTIAL_FILE_NAME_LISTS.1 {
        if filename.eq_ignore_ascii_case(name) {
            return true;
        }
        // Prefix + config extension: `secrets.yaml`, `credentials.env`,
        // `apikeys.toml`, `secrets-prod.toml`. The trailing extension
        // gate keeps `secrets.rs`, `credentials.py`, etc. on the
        // source-code path (skipped unless --entropy-source-files).
        if filename.len() > name.len() && filename[..name.len()].eq_ignore_ascii_case(name) {
            let tail = &filename[name.len()..];
            for ext in config_file_extensions()
                .iter()
                .chain(extra_stem_config_extensions())
            {
                if tail.len() >= ext.len()
                    && tail[tail.len() - ext.len()..].eq_ignore_ascii_case(ext)
                {
                    return true;
                }
            }
        }
    }

    // Source-file lift (part (b) of the FN-recall fix). Everything that
    // reaches here is a genuine source-code file (`.rs`, `.go`, `.js`,
    // `.py`, ...) that is neither a recognized config/secret file nor a
    // package manifest (both returned earlier). The dominant go/rust/js
    // FN shape is a quoted RHS of a const/assignment with a secret keyword,
    // `const apiKey = "<base64-40>"`. When the chunk carries such a
    // secret-keyword assignment line, allow entropy scanning here even
    // without `--entropy-source-files`; the per-candidate emit gates
    // (pure-identifier, prose, kebab, filename-shape, ...) reject the
    // identifier noise that motivated the source-file hard-OFF, so the
    // keyword anchor keeps this contract-safe. Manifests are unaffected -
    // they already returned `false` above, so a `name = "my-secret"` line
    // in `Cargo.toml` cannot re-enable scanning here.
    has_secret_keyword_line
}

#[cfg(test)]
#[path = "../../tests/unit/entropy_inline.rs"]
mod tests;
