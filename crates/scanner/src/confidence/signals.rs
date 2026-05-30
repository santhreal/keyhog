/// Confidence signals for a potential match.
pub struct ConfidenceSignals {
    /// Pattern has a distinctive literal prefix (e.g., `sk-proj-`, `ghp_`).
    pub has_literal_prefix: bool,
    /// Pattern uses a capture group with context anchoring.
    pub has_context_anchor: bool,
    /// Shannon entropy of the matched credential in **bits per byte** (range
    /// `0.0..=8.0`) - NOT normalized to `0..1`. Use
    /// `crate::entropy::normalized_entropy` for the rescaled value.
    pub entropy: f64,
    /// A secret-related keyword appears nearby.
    pub keyword_nearby: bool,
    /// File extension suggests config/env/secret file.
    pub sensitive_file: bool,
    /// Matched credential length.
    pub match_length: usize,
    /// Companion credential was found.
    pub has_companion: bool,
}

/// Check if a file path suggests a sensitive file.
/// Check if a file path suggests a sensitive file using Aho-Corasick.
///
/// Single AC automaton replaces O(n*m) nested loop with O(n) scan.
pub fn is_sensitive_path(path: &str) -> bool {
    use std::sync::OnceLock;

    static AC: OnceLock<Option<aho_corasick::AhoCorasick>> = OnceLock::new();

    let ac = AC.get_or_init(|| {
        aho_corasick::AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build([
                // Sensitive filenames
                ".env",
                ".env.local",
                ".env.production",
                ".env.staging",
                "credentials",
                "secrets",
                "apikeys",
                "api_keys",
                ".npmrc",
                ".pypirc",
                ".netrc",
                ".pgpass",
                "terraform.tfvars",
                "variables.tf",
                "docker-compose",
                "application.yml",
                "application.properties",
                "config.json",
                "config.yaml",
                "config.toml",
                // Sensitive extensions (matched as substrings - works because
                // extensions are at end of path and names are distinctive)
                ".pem",
                ".key",
                ".p12",
                ".pfx",
                ".jks",
                ".keystore",
                ".cer",
                ".crt",
                // CI/CD secret files
                ".github/workflows",
                "gitlab-ci.yml",
                "Jenkinsfile",
                "buildspec.yml",
                // Cloud config
                "serverless.yml",
                "sam-template",
                "helm/values",
                "chart/values",
            ])
            .ok()
    });

    ac.as_ref().is_some_and(|ac| ac.is_match(path))
}

/// Distinct-bigram density. Returns a value in `[0.0, 1.0]`: 1.0 means every
/// adjacent byte pair is unique, 0.0 means every pair repeats.
///
/// This is a **first cut** at a proxy for the BPE token-efficiency rarity
/// signal popularised by betterleaks ([Zachary Rice, "Rare Not Random"][1],
/// built on OpenAI's `cl100k_base` BPE). The true signal needs the
/// cl100k_base merge table (~1.6 MB); the lean-ci binary drops the GPU
/// stack to 13 MB and shipping the vocab would undo that win, so we
/// expose the bigram proxy now and the cl100k_base wiring lands behind
/// a future `bpe_vocab` feature.
///
/// **Empirical caveat: this proxy alone is NOT safe as an FP gate.** A
/// real `ghp_1234567890abcdef…` token scores ~0.51 (repeating digits +
/// hex bigrams) while a plain English sentence scores ~0.82+. The
/// function ships so callers (and a future ML retrain that folds it in as
/// a learned weight) can read the signal, but the unnamed-detector
/// penalty path in `apply_post_ml_penalties` intentionally does NOT call
/// `looks_like_natural_language` until the cl100k_base path lands.
///
/// Bytes outside the alnum + `-_./+=` set are skipped so embedded quote
/// marks or stray punctuation never lower the score on their own. Strings
/// shorter than 9 chars (or fewer than 4 bigrams after filtering) return
/// 1.0 because the statistic is too noisy below that length to act on.
///
/// [1]: https://lookingatcomputer.substack.com/p/rare-not-random
pub fn bigram_uniqueness(candidate: &str) -> f32 {
    let bytes: Vec<u8> = candidate
        .as_bytes()
        .iter()
        .copied()
        .filter(|&b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b'+' | b'=')
        })
        .map(|b| b.to_ascii_lowercase())
        .collect();

    if bytes.len() <= 8 {
        return 1.0;
    }

    let mut seen = [false; 65536];
    let mut unique = 0usize;
    let mut total = 0usize;
    for window in bytes.windows(2) {
        total += 1;
        let key = ((window[0] as u16) << 8) | (window[1] as u16);
        let slot = &mut seen[key as usize];
        if !*slot {
            *slot = true;
            unique += 1;
        }
    }
    if total < 4 {
        return 1.0;
    }
    unique as f32 / total as f32
}

/// True when the candidate's bigram-uniqueness is BELOW `floor`. Exposed
/// as a building block, not as a default gate. See `bigram_uniqueness` for
/// the empirical caveat: the proxy mis-orders English vs digit-heavy
/// real-secret shapes, so no production caller wires this in until the
/// cl100k_base BPE path replaces the proxy.
#[inline]
pub fn looks_like_natural_language(candidate: &str, floor: f32) -> bool {
    bigram_uniqueness(candidate) < floor
}

#[cfg(test)]
mod token_rarity_tests {
    use super::*;

    #[test]
    fn random_alphanumeric_is_high_uniqueness() {
        // 32-char random alphanumeric stand-in for an API token.
        assert!(bigram_uniqueness("Z7qFp3LkV2mNbXcD8yT4uH9wRsE6jKgA") >= 0.95);
    }

    #[test]
    fn short_strings_pass_through() {
        // Below 9 chars the statistic is too noisy: return 1.0 so the proxy
        // never fires on a short token.
        assert_eq!(bigram_uniqueness("abc"), 1.0);
        assert_eq!(bigram_uniqueness("hello"), 1.0);
    }

    #[test]
    fn bigram_proxy_orders_prose_below_random_alphanumeric() {
        // Documenting the proxy's discrimination range: random alphanumeric
        // strings score at the top of the range, English prose scores
        // somewhat below them. This is the signal direction the cl100k_base
        // BPE swap-in will sharpen.
        let random = bigram_uniqueness("Z7qFp3LkV2mNbXcD8yT4uH9wRsE6jKgA");
        let prose = bigram_uniqueness(
            "thereisnothingbeyondthisstateofwordstoseparate",
        );
        assert!(random > prose);
    }

    #[test]
    fn bigram_proxy_mismatches_digit_heavy_real_token() {
        // Pinned as a regression: a real `ghp_…1234567890…` token scores
        // BELOW typical English under the bigram proxy because the
        // 0-9 + a-f bigrams repeat heavily. This is exactly why
        // `looks_like_natural_language` is exposed as a building block but
        // NOT wired into `apply_post_ml_penalties` until the cl100k_base
        // BPE path lands.
        let token = bigram_uniqueness("ghp_1234567890abcdef1234567890abcdef1234");
        let prose = bigram_uniqueness(
            "thereisnothingbeyondthisstateofwordstoseparate",
        );
        assert!(token < prose, "proxy mis-orders digit-heavy real tokens vs prose");
    }
}
