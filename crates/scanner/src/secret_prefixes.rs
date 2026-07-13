//! Distinctive vendor secret-PREFIX vocabulary for the multiline no-hit gate.
//!
//! The prefixes live in the Tier-B `rules/multiline_secret_prefixes.toml` file and
//! are parsed once here. The single consumer is `scan_filters::has_secret_keyword_fast`,
//! which builds a CASE-SENSITIVE `AhoCorasick::new` automaton from them to decide
//! whether a chunk that produced no phase-1 hit might hold a secret SPLIT across
//! lines (and so is worth reassembly + re-scan).
//!
//! Contrast with [`crate::assignment_keywords`]: those are matched
//! case-INSENSITIVELY, so that file is stored lowercase. Here the vendor casing is
//! load-bearing (`HRKU-` is genuinely uppercase; `sk-proj-`/`ghp_`/… are the real
//! lowercase spellings), so this loader PRESERVES case exactly and does not fold or
//! require lowercase. Keeping the list in Tier-B lets a team widen split-secret
//! recall by dropping a prefix into the file without a recompile.

use std::sync::LazyLock;

#[derive(serde::Deserialize)]
struct MultilineSecretPrefixFile {
    multiline_secret_prefixes: MultilineSecretPrefixSection,
}

#[derive(serde::Deserialize)]
struct MultilineSecretPrefixSection {
    prefixes: Vec<String>,
}

static MULTILINE_SECRET_PREFIXES: LazyLock<Vec<String>> = LazyLock::new(|| {
    match parse_multiline_secret_prefixes(include_str!(
        "../../../rules/multiline_secret_prefixes.toml"
    )) {
        Ok(prefixes) => prefixes,
        Err(error) => panic!(
            "rules/multiline_secret_prefixes.toml is invalid: {error}. Fix the bundled Tier-B \
             multiline secret-prefix vocabulary; refusing to run without the split-secret \
             prefilter truth."
        ),
    }
});

/// The distinctive vendor secret prefixes (EXACT vendor casing, order-preserved).
/// The consumer matches them case-sensitively, so the casing here is authoritative.
pub(crate) fn multiline_secret_prefixes() -> &'static [String] {
    &MULTILINE_SECRET_PREFIXES
}

/// Parse and validate the multiline secret-prefix list from raw TOML: ASCII with
/// optional `_`/`-`/`.` separators, no empties, no duplicates, non-empty overall,
/// order and CASE preserved (the consumer's Aho-Corasick is case-sensitive, so the
/// exact vendor casing must survive verbatim, unlike the case-folded generic
/// assignment-keyword vocab, this passes `require_lowercase: false` and does NOT
/// lowercase).
pub(crate) fn parse_multiline_secret_prefixes(raw: &str) -> Result<Vec<String>, String> {
    let parsed: MultilineSecretPrefixFile = toml::from_str(raw)
        .map_err(|error| format!("invalid multiline_secret_prefixes.toml: {error}"))?;
    // The consumer's Aho-Corasick is case-sensitive, so casing is PRESERVED verbatim
    // (require_lowercase: false), the one axis on which this differs from the
    // case-folded assignment-keyword list.
    crate::tier_b_list::parse_token_list(
        parsed.multiline_secret_prefixes.prefixes,
        &crate::tier_b_list::ListPolicy {
            what: "multiline secret-prefix",
            require_lowercase: false,
            separators: b"_-.",
        },
    )
}


#[cfg(test)]
#[path = "../tests/unit/secret_prefixes.rs"]
mod tests;
