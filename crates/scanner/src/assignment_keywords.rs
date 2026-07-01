//! Generic credential-assignment keyword vocabulary (phase-2 prefilter triggers).
//!
//! The keywords live in the Tier-B `rules/assignment_keywords.toml` file and are
//! parsed once here. Three phase-2 consumers share this one list: the
//! `ascii_case_insensitive` Aho-Corasick chunk prefilter
//! (`scan_filters::has_generic_assignment_keyword`), the no-hit prefilter stem set
//! (`phase2_generic::keywords::generic_keyword_prefilter_stems`), and the entropy
//! keyword-anchor contains-check (`phase2_entropy::helpers`). Keeping the list in
//! Tier-B data lets a team widen recall by dropping a keyword into the file without
//! a recompile.

use std::collections::BTreeSet;
use std::sync::LazyLock;

#[derive(serde::Deserialize)]
struct AssignmentKeywordFile {
    assignment_keywords: AssignmentKeywordSection,
}

#[derive(serde::Deserialize)]
struct AssignmentKeywordSection {
    keywords: Vec<String>,
}

static ASSIGNMENT_KEYWORDS: LazyLock<Vec<String>> =
    LazyLock::new(|| {
        match parse_assignment_keywords(include_str!("../../../rules/assignment_keywords.toml")) {
            Ok(keywords) => keywords,
            Err(error) => panic!(
                "rules/assignment_keywords.toml is invalid: {error}. Fix the bundled Tier-B \
             assignment-keyword vocabulary; refusing to run without the generic-credential \
             prefilter truth."
            ),
        }
    });

/// The generic credential-assignment keywords (lowercase, order-preserved). All
/// three consumers fold case, so the entries are matched case-insensitively.
pub(crate) fn assignment_keywords() -> &'static [String] {
    &ASSIGNMENT_KEYWORDS
}

/// Parse and validate the assignment-keyword list from raw TOML: lowercase ASCII
/// with optional `_`/`-`/`.` separators (the three spellings of compound keys), no
/// empties, no duplicates, non-empty overall, order preserved (the prefilter stems
/// and the AC both consume it verbatim).
pub(crate) fn parse_assignment_keywords(raw: &str) -> Result<Vec<String>, String> {
    let parsed: AssignmentKeywordFile = toml::from_str(raw)
        .map_err(|error| format!("invalid assignment_keywords.toml: {error}"))?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(parsed.assignment_keywords.keywords.len());
    for raw_keyword in parsed.assignment_keywords.keywords {
        let keyword = raw_keyword.trim();
        if keyword.is_empty() {
            return Err("assignment keyword entries must not be empty".to_string());
        }
        if keyword != keyword.to_ascii_lowercase() {
            return Err(format!(
                "assignment keyword {keyword:?} must be lowercase ASCII"
            ));
        }
        if !keyword.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || byte == b'.'
        }) {
            return Err(format!(
                "assignment keyword {keyword:?} must be ASCII alphanumeric with optional \
                 '_'/'-'/'.' separators"
            ));
        }
        if !seen.insert(keyword.to_string()) {
            return Err(format!("duplicate assignment keyword {keyword:?}"));
        }
        out.push(keyword.to_string());
    }
    if out.is_empty() {
        return Err("assignment_keywords.keywords must contain at least one entry".to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact list the scanner matched BEFORE the Tier-B move (the old
    /// `GENERIC_ASSIGNMENT_KEYWORDS` const in `engine/scan_filters.rs`), in order.
    /// The loaded vocab must reproduce it byte-for-byte — the zero-behavior-change
    /// parity proof for the recall-critical prefilter.
    const LEGACY: &[&str] = &[
        "secret",
        "password",
        "passwd",
        "pwd",
        "pass",
        "token",
        "webhook_url",
        "webhook-url",
        "webhook.url",
        "apikey",
        "api_key",
        "api-key",
        "api.key",
        "auth",
        "authorization",
        "auth_token",
        "auth-token",
        "auth.token",
        "auth_key",
        "auth-key",
        "auth.key",
        "credential",
        "private_key",
        "private-key",
        "private.key",
        "signing_key",
        "signing-key",
        "signing.key",
        "encryption_key",
        "encryption-key",
        "encryption.key",
        "access_key",
        "access-key",
        "access.key",
        "client_secret",
        "client-secret",
        "client.secret",
        "app_secret",
        "app-secret",
        "app.secret",
        "master_key",
        "master-key",
        "master.key",
        "license_key",
        "license-key",
        "license.key",
    ];

    fn toml_with(keywords: &str) -> String {
        format!("[assignment_keywords]\nkeywords = [{keywords}]\n")
    }

    #[test]
    fn loaded_reproduces_the_legacy_const_exactly() {
        let loaded: Vec<&str> = assignment_keywords().iter().map(String::as_str).collect();
        assert_eq!(loaded.as_slice(), LEGACY);
    }

    #[test]
    fn keyword_count_is_exactly_forty_six() {
        // Locks the exact size of the recall-critical prefilter vocabulary so an
        // accidental add/drop in the Tier-B file fails loudly (the parity test above
        // pins the contents; this pins the count as a fast tripwire).
        assert_eq!(assignment_keywords().len(), 46);
    }

    #[test]
    fn all_keywords_are_lowercase() {
        for keyword in assignment_keywords() {
            assert_eq!(
                keyword,
                &keyword.to_ascii_lowercase(),
                "not lowercase: {keyword}"
            );
        }
    }

    #[test]
    fn all_keywords_are_ascii() {
        for keyword in assignment_keywords() {
            assert!(keyword.is_ascii(), "non-ascii keyword: {keyword}");
        }
    }

    #[test]
    fn keywords_are_nonempty() {
        assert!(!assignment_keywords().is_empty());
        for keyword in assignment_keywords() {
            assert!(!keyword.is_empty());
        }
    }

    #[test]
    fn no_duplicate_keywords() {
        let mut seen = BTreeSet::new();
        for keyword in assignment_keywords() {
            assert!(seen.insert(keyword), "duplicate keyword {keyword}");
        }
    }

    #[test]
    fn compound_keys_ship_all_three_separator_spellings() {
        // api_key / api-key / api.key etc. — the real-world spellings must all be
        // present so the prefilter fires regardless of the source's convention.
        let set: BTreeSet<&str> = assignment_keywords().iter().map(String::as_str).collect();
        for (u, h, d) in [
            ("api_key", "api-key", "api.key"),
            ("private_key", "private-key", "private.key"),
            ("client_secret", "client-secret", "client.secret"),
            ("master_key", "master-key", "master.key"),
        ] {
            assert!(set.contains(u), "missing {u}");
            assert!(set.contains(h), "missing {h}");
            assert!(set.contains(d), "missing {d}");
        }
    }

    #[test]
    fn bare_pass_keyword_is_present() {
        // Covers the dominant `*_PASS=` CredData credential-env pattern.
        assert!(assignment_keywords().iter().any(|k| k == "pass"));
    }

    #[test]
    fn bare_key_stem_is_not_in_the_base_list() {
        // `key` is added by `generic_keyword_prefilter_stems`, NOT part of the base
        // vocabulary — pin that so a future edit does not silently widen the AC.
        assert!(
            !assignment_keywords().iter().any(|k| k == "key"),
            "the bare `key` stem must stay a consumer-side addition, not the base list"
        );
    }

    #[test]
    fn parse_rejects_uppercase_keyword() {
        let err = parse_assignment_keywords(&toml_with("\"Secret\"")).unwrap_err();
        assert!(err.contains("lowercase"), "got: {err}");
    }

    #[test]
    fn parse_rejects_empty_keyword() {
        let err = parse_assignment_keywords(&toml_with("\"\"")).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn parse_rejects_duplicate_keyword() {
        let err = parse_assignment_keywords(&toml_with("\"secret\", \"secret\"")).unwrap_err();
        assert!(err.contains("duplicate"), "got: {err}");
    }

    #[test]
    fn parse_rejects_keyword_with_space() {
        let err = parse_assignment_keywords(&toml_with("\"api key\"")).unwrap_err();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn parse_rejects_non_ascii_keyword() {
        let err = parse_assignment_keywords(&toml_with("\"cl\u{e9}\"")).unwrap_err();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn parse_rejects_empty_list() {
        let err = parse_assignment_keywords("[assignment_keywords]\nkeywords = []\n").unwrap_err();
        assert!(err.contains("at least one"), "got: {err}");
    }

    #[test]
    fn parse_allows_dot_underscore_hyphen_separators() {
        let parsed =
            parse_assignment_keywords(&toml_with("\"api.key\", \"api_key\", \"api-key\"")).unwrap();
        assert_eq!(parsed, vec!["api.key", "api_key", "api-key"]);
    }

    #[test]
    fn parse_is_order_preserving() {
        // AC-build parity does not depend on order, but the prefilter-stem set and
        // this parity test do; keep insertion order.
        let parsed =
            parse_assignment_keywords(&toml_with("\"zebra\", \"alpha\", \"mid\"")).unwrap();
        assert_eq!(parsed, vec!["zebra", "alpha", "mid"]);
    }

    #[test]
    fn bundled_file_parses_and_matches_accessor() {
        let parsed =
            parse_assignment_keywords(include_str!("../../../rules/assignment_keywords.toml"))
                .expect("bundled file valid");
        assert_eq!(parsed.as_slice(), assignment_keywords());
    }

    #[test]
    fn ac_built_from_tier_b_matches_case_insensitively() {
        // Prove the recall-critical consumer works from the Tier-B list: an
        // `ascii_case_insensitive` Aho-Corasick built from the loaded keywords fires
        // on the mixed-case and separator spellings and rejects a non-keyword.
        let ac = aho_corasick::AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(assignment_keywords().iter().map(String::as_str))
            .expect("AC builds from the Tier-B keywords");
        assert!(
            ac.find(b"SECRET=hunter2").is_some(),
            "case-insensitive `secret`"
        );
        assert!(ac.find(b"api_key: xyz").is_some(), "underscore spelling");
        assert!(ac.find(b"API.KEY=xyz").is_some(), "dotted + upper spelling");
        assert!(
            ac.find(b"just some random text").is_none(),
            "a non-keyword line must not trigger the prefilter"
        );
    }
}
