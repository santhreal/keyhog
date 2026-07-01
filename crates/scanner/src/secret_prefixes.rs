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

use std::collections::BTreeSet;
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
/// exact vendor casing must survive verbatim — unlike
/// [`crate::assignment_keywords::parse_assignment_keywords`], this does NOT lowercase).
pub(crate) fn parse_multiline_secret_prefixes(raw: &str) -> Result<Vec<String>, String> {
    let parsed: MultilineSecretPrefixFile = toml::from_str(raw)
        .map_err(|error| format!("invalid multiline_secret_prefixes.toml: {error}"))?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(parsed.multiline_secret_prefixes.prefixes.len());
    for raw_prefix in parsed.multiline_secret_prefixes.prefixes {
        let prefix = raw_prefix.trim();
        if prefix.is_empty() {
            return Err("multiline secret-prefix entries must not be empty".to_string());
        }
        if !prefix.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte == b'.'
        }) {
            return Err(format!(
                "multiline secret-prefix {prefix:?} must be ASCII alphanumeric with optional \
                 '_'/'-'/'.' separators"
            ));
        }
        if !seen.insert(prefix.to_string()) {
            return Err(format!("duplicate multiline secret-prefix {prefix:?}"));
        }
        out.push(prefix.to_string());
    }
    if out.is_empty() {
        return Err(
            "multiline_secret_prefixes.prefixes must contain at least one entry".to_string(),
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The EXACT list the multiline gate matched BEFORE the Tier-B move (the inline
    /// `AhoCorasick::new([...])` array in `engine/scan_filters.rs`), in order and
    /// with vendor casing. The loaded vocab must reproduce it byte-for-byte — the
    /// zero-behavior-change parity proof for the recall-critical split-secret gate.
    const LEGACY: &[&str] = &[
        "sk-proj-",
        "sk-svcacct-",
        "sk-admin-",
        "sk_live_",
        "sk_test_",
        "rk_live_",
        "pk_live_",
        "ghp_",
        "ghs_",
        "gho_",
        "ghu_",
        "ghr_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
        "xoxs-",
        "xapp-",
        "sk-ant-",
        "hf_",
        ".iam.gserviceaccount.com",
        "glpat-",
        "npm_",
        "HRKU-",
    ];

    fn toml_with(prefixes: &str) -> String {
        format!("[multiline_secret_prefixes]\nprefixes = [{prefixes}]\n")
    }

    #[test]
    fn loaded_reproduces_the_legacy_list_exactly() {
        let loaded: Vec<&str> = multiline_secret_prefixes()
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(loaded.as_slice(), LEGACY);
    }

    #[test]
    fn prefix_count_is_exactly_twenty_five() {
        // Fast tripwire; the behavioral lock in scan_filters.rs pins the contents.
        assert_eq!(multiline_secret_prefixes().len(), 25);
    }

    #[test]
    fn all_prefixes_are_ascii() {
        for prefix in multiline_secret_prefixes() {
            assert!(prefix.is_ascii(), "non-ascii prefix: {prefix}");
        }
    }

    #[test]
    fn prefixes_are_nonempty() {
        assert!(!multiline_secret_prefixes().is_empty());
        for prefix in multiline_secret_prefixes() {
            assert!(!prefix.is_empty());
        }
    }

    #[test]
    fn no_duplicate_prefixes() {
        let mut seen = BTreeSet::new();
        for prefix in multiline_secret_prefixes() {
            assert!(seen.insert(prefix), "duplicate prefix {prefix}");
        }
    }

    #[test]
    fn heroku_prefix_preserves_uppercase_casing() {
        // The whole point of the case-preserving loader: `HRKU-` is genuinely
        // uppercase and MUST survive verbatim (the consumer is case-sensitive).
        assert!(
            multiline_secret_prefixes().iter().any(|p| p == "HRKU-"),
            "HRKU- must be present with its exact uppercase casing"
        );
        assert!(
            !multiline_secret_prefixes().iter().any(|p| p == "hrku-"),
            "a lowercased hrku- is not a real Heroku prefix and must not appear"
        );
    }

    #[test]
    fn openai_prefixes_keep_lowercase_casing() {
        for p in ["sk-proj-", "sk-svcacct-", "sk-admin-"] {
            assert!(
                multiline_secret_prefixes().iter().any(|x| x == p),
                "missing exact-cased {p}"
            );
        }
    }

    #[test]
    fn deliberately_excluded_short_prefixes_are_absent() {
        // Curation pinned at the data level: the fixture-noisy short prefixes must
        // NOT be in the list.
        for excluded in ["AKIA", "eyJ"] {
            assert!(
                !multiline_secret_prefixes().iter().any(|p| p == excluded),
                "{excluded} is deliberately excluded from the multiline gate"
            );
        }
    }

    #[test]
    fn parse_preserves_case_verbatim() {
        // The key contrast with assignment_keywords: no lowercasing. Mixed-case
        // input round-trips exactly.
        let parsed =
            parse_multiline_secret_prefixes(&toml_with("\"HRKU-\", \"sk-proj-\"")).unwrap();
        assert_eq!(parsed, vec!["HRKU-", "sk-proj-"]);
    }

    #[test]
    fn parse_rejects_empty_prefix() {
        let err = parse_multiline_secret_prefixes(&toml_with("\"\"")).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn parse_rejects_duplicate_prefix() {
        let err = parse_multiline_secret_prefixes(&toml_with("\"ghp_\", \"ghp_\"")).unwrap_err();
        assert!(err.contains("duplicate"), "got: {err}");
    }

    #[test]
    fn parse_rejects_prefix_with_space() {
        let err = parse_multiline_secret_prefixes(&toml_with("\"gh p_\"")).unwrap_err();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn parse_rejects_non_ascii_prefix() {
        let err = parse_multiline_secret_prefixes(&toml_with("\"cl\u{e9}_\"")).unwrap_err();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn parse_rejects_empty_list() {
        let err = parse_multiline_secret_prefixes("[multiline_secret_prefixes]\nprefixes = []\n")
            .unwrap_err();
        assert!(err.contains("at least one"), "got: {err}");
    }

    #[test]
    fn parse_allows_dot_underscore_hyphen_separators() {
        let parsed = parse_multiline_secret_prefixes(&toml_with(
            "\".iam.gserviceaccount.com\", \"github_pat_\", \"glpat-\"",
        ))
        .unwrap();
        assert_eq!(
            parsed,
            vec![".iam.gserviceaccount.com", "github_pat_", "glpat-"]
        );
    }

    #[test]
    fn parse_is_order_preserving() {
        let parsed =
            parse_multiline_secret_prefixes(&toml_with("\"zzz_\", \"aaa_\", \"mmm_\"")).unwrap();
        assert_eq!(parsed, vec!["zzz_", "aaa_", "mmm_"]);
    }

    #[test]
    fn bundled_file_parses_and_matches_accessor() {
        let parsed = parse_multiline_secret_prefixes(include_str!(
            "../../../rules/multiline_secret_prefixes.toml"
        ))
        .expect("bundled file valid");
        assert_eq!(parsed.as_slice(), multiline_secret_prefixes());
    }

    #[test]
    fn ac_built_from_tier_b_is_case_sensitive() {
        // Prove the recall-critical consumer works from the Tier-B list: a
        // case-SENSITIVE Aho-Corasick (the default `AhoCorasick::new`) built from the
        // loaded prefixes fires on the exact vendor casing and REJECTS an uppercased
        // spelling — the behavior `has_secret_keyword_fast` depends on.
        let ac =
            aho_corasick::AhoCorasick::new(multiline_secret_prefixes().iter().map(String::as_str))
                .expect("AC builds from the Tier-B prefixes");
        assert!(ac.find(b"key=ghp_0123456789").is_some(), "exact-cased ghp_");
        assert!(ac.find(b"key=HRKU-9f8e7d6c").is_some(), "exact-cased HRKU-");
        assert!(
            ac.find(b"KEY=GHP_0123456789").is_none(),
            "an uppercased prefix must not match the case-sensitive gate"
        );
        assert!(
            ac.find(b"just some random text").is_none(),
            "a non-prefix line must not trigger the gate"
        );
    }
}
