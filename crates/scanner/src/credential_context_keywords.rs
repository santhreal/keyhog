//! Tier-B credential-context keywords for the entropy scanner.
//!
//! `entropy::scanner::keyword_context` treats a high-entropy value as
//! credential-context when its line contains any of these keywords (matched
//! case-insensitively as a substring). This module owns that vocabulary as a
//! Tier-B data file (`rules/credential_context_keywords.toml`) instead of a
//! hardcoded array, so the list can be extended without a code change and can
//! never silently drift from a duplicate copy. Parsing and validation are shared
//! with the other single-column token lists via [`crate::tier_b_list`].

use crate::tier_b_list::{parse_token_list, ListPolicy};
use serde::Deserialize;
use std::sync::LazyLock;

const CREDENTIAL_CONTEXT_KEYWORDS_TOML: &str =
    include_str!("../../../rules/credential_context_keywords.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialContextKeywordsFile {
    credential_context_keywords: CredentialContextKeywordsSection,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialContextKeywordsSection {
    keywords: Vec<String>,
}

fn parse_credential_context_keywords(raw: &str) -> Result<Vec<String>, String> {
    let parsed: CredentialContextKeywordsFile = toml::from_str(raw)
        .map_err(|error| format!("invalid credential-context keywords: {error}"))?;
    parse_token_list(
        parsed.credential_context_keywords.keywords,
        &ListPolicy {
            // The match folds case, so entries are canonical lowercase. `_`/`-`
            // separators (including leading ones, e.g. `_key`) are the real-world
            // compound-identifier suffixes; `.` is deliberately not permitted here.
            what: "credential-context keyword",
            require_lowercase: true,
            separators: b"_-",
        },
    )
}

static CREDENTIAL_CONTEXT_KEYWORDS: LazyLock<Vec<String>> =
    LazyLock::new(
        || match parse_credential_context_keywords(CREDENTIAL_CONTEXT_KEYWORDS_TOML) {
            Ok(keywords) => keywords,
            Err(error) => panic!("bundled credential_context_keywords.toml is invalid: {error}"),
        },
    );

/// Credential-context keywords, matched case-insensitively as substrings by the
/// entropy scanner. Fail-closed (Law 10): invalid embedded data panics at first
/// use rather than silently degrading to an empty vocabulary.
pub(crate) fn credential_context_keywords() -> &'static [String] {
    &CREDENTIAL_CONTEXT_KEYWORDS
}

#[cfg(test)]
#[path = "../tests/unit/credential_context_keywords.rs"]
mod tests;
