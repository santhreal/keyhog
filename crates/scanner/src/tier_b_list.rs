//! Shared parse + validate primitive for Tier-B single-column token lists.
//!
//! Several Tier-B data files are just an ordered list of tokens — the phase-2
//! assignment keywords ([`crate::assignment_keywords`]) and the multiline secret
//! prefixes ([`crate::secret_prefixes`]) among them. They share the EXACT same
//! validation: trim each entry, reject empties, restrict the charset to ASCII
//! alphanumerics plus a small allowed separator set, reject duplicates, and require
//! a non-empty result. The only axes that vary per file are (1) whether entries
//! must already be lowercase (the consumer folds case) or keep their casing verbatim
//! (the consumer is case-sensitive), and (2) which separators are allowed.
//!
//! This module owns that one validator so each per-file loader stays a thin wrapper
//! over a single source of truth — no drift across copies (NO DUPLICATION), and the
//! error wording, dedup semantics, and charset rules can only ever change in one
//! place.

use std::collections::BTreeSet;

/// Validation policy for a Tier-B token list.
pub(crate) struct ListPolicy {
    /// Singular human label used in error messages, e.g. `"assignment keyword"`.
    pub what: &'static str,
    /// When `true`, every entry must already be lowercase ASCII (the consumer folds
    /// case, so the stored form is canonical lowercase). When `false`, casing is
    /// PRESERVED verbatim (the consumer matches case-sensitively).
    pub require_lowercase: bool,
    /// Separator bytes permitted in addition to ASCII alphanumerics.
    pub separators: &'static [u8],
}

impl ListPolicy {
    fn byte_allowed(&self, byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || self.separators.contains(&byte)
    }

    /// Render the allowed separators for an error message, e.g. `'_'/'-'/'.'`.
    fn separators_display(&self) -> String {
        self.separators
            .iter()
            .map(|byte| format!("'{}'", *byte as char))
            .collect::<Vec<_>>()
            .join("/")
    }
}

/// Trim, validate, and dedup-check `items` under `policy`. Order-preserving; the
/// returned tokens are the trimmed forms. Errors carry the policy's `what` label
/// and the offending token so a bad Tier-B file fails loudly with the fix in hand.
pub(crate) fn parse_token_list(
    items: Vec<String>,
    policy: &ListPolicy,
) -> Result<Vec<String>, String> {
    let what = policy.what;
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(items.len());
    for raw in items {
        let token = raw.trim();
        if token.is_empty() {
            return Err(format!("{what} entries must not be empty"));
        }
        if policy.require_lowercase && token != token.to_ascii_lowercase() {
            return Err(format!("{what} {token:?} must be lowercase ASCII"));
        }
        if !token.bytes().all(|byte| policy.byte_allowed(byte)) {
            return Err(format!(
                "{what} {token:?} must be ASCII alphanumeric with optional {} separators",
                policy.separators_display()
            ));
        }
        if !seen.insert(token.to_string()) {
            return Err(format!("duplicate {what} {token:?}"));
        }
        out.push(token.to_string());
    }
    if out.is_empty() {
        return Err(format!("{what} list must contain at least one entry"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lower(what: &'static str) -> ListPolicy {
        ListPolicy {
            what,
            require_lowercase: true,
            separators: b"_-.",
        }
    }

    fn preserve(what: &'static str) -> ListPolicy {
        ListPolicy {
            what,
            require_lowercase: false,
            separators: b"_-.",
        }
    }

    fn owned(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn accepts_a_valid_lowercase_list() {
        let out =
            parse_token_list(owned(&["secret", "api_key", "api.key"]), &lower("keyword")).unwrap();
        assert_eq!(out, vec!["secret", "api_key", "api.key"]);
    }

    #[test]
    fn accepts_a_case_preserving_list() {
        let out = parse_token_list(owned(&["HRKU-", "sk-proj-"]), &preserve("prefix")).unwrap();
        assert_eq!(out, vec!["HRKU-", "sk-proj-"]);
    }

    #[test]
    fn rejects_uppercase_when_lowercase_required() {
        let err = parse_token_list(owned(&["Secret"]), &lower("keyword")).unwrap_err();
        assert!(err.contains("lowercase"), "got: {err}");
    }

    #[test]
    fn allows_uppercase_when_not_required() {
        let out = parse_token_list(owned(&["HRKU-"]), &preserve("prefix")).unwrap();
        assert_eq!(out, vec!["HRKU-"]);
    }

    #[test]
    fn rejects_empty_entry() {
        let err = parse_token_list(owned(&[""]), &lower("keyword")).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn rejects_whitespace_only_entry() {
        let err = parse_token_list(owned(&["   "]), &lower("keyword")).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn trims_surrounding_whitespace() {
        let out = parse_token_list(owned(&["  ghp_  "]), &preserve("prefix")).unwrap();
        assert_eq!(out, vec!["ghp_"]);
    }

    #[test]
    fn rejects_duplicate() {
        let err = parse_token_list(owned(&["secret", "secret"]), &lower("keyword")).unwrap_err();
        assert!(err.contains("duplicate"), "got: {err}");
    }

    #[test]
    fn rejects_char_outside_charset() {
        let err = parse_token_list(owned(&["api key"]), &lower("keyword")).unwrap_err();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn rejects_separator_not_in_policy() {
        // A policy that allows only `_` must reject a hyphen.
        let policy = ListPolicy {
            what: "keyword",
            require_lowercase: true,
            separators: b"_",
        };
        let err = parse_token_list(owned(&["a-b"]), &policy).unwrap_err();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn allows_separator_in_policy() {
        let policy = ListPolicy {
            what: "keyword",
            require_lowercase: true,
            separators: b"-",
        };
        let out = parse_token_list(owned(&["a-b"]), &policy).unwrap();
        assert_eq!(out, vec!["a-b"]);
    }

    #[test]
    fn rejects_empty_list() {
        let err = parse_token_list(Vec::new(), &lower("keyword")).unwrap_err();
        assert!(err.contains("at least one"), "got: {err}");
    }

    #[test]
    fn is_order_preserving() {
        let out = parse_token_list(owned(&["zebra", "alpha", "mid"]), &lower("keyword")).unwrap();
        assert_eq!(out, vec!["zebra", "alpha", "mid"]);
    }

    #[test]
    fn error_message_includes_the_what_label() {
        let err = parse_token_list(owned(&[""]), &lower("widget-name")).unwrap_err();
        assert!(err.contains("widget-name"), "got: {err}");
    }

    #[test]
    fn error_message_includes_the_offending_token() {
        let err = parse_token_list(owned(&["BAD"]), &lower("keyword")).unwrap_err();
        assert!(err.contains("BAD"), "got: {err}");
    }

    #[test]
    fn separators_display_lists_each_allowed_separator() {
        let err = parse_token_list(owned(&["a b"]), &lower("keyword")).unwrap_err();
        assert!(err.contains("'_'/'-'/'.'"), "got: {err}");
    }

    #[test]
    fn dot_underscore_hyphen_all_allowed_together() {
        let out = parse_token_list(
            owned(&["a.b", "a_b", "a-b"]),
            &ListPolicy {
                what: "keyword",
                require_lowercase: true,
                separators: b"_-.",
            },
        )
        .unwrap();
        assert_eq!(out, vec!["a.b", "a_b", "a-b"]);
    }

    #[test]
    fn dedup_is_byte_exact_not_case_folded() {
        // With case preserved, `AB` and `ab` are distinct tokens and both survive —
        // dedup is exact-string, never case-folded.
        let out = parse_token_list(owned(&["AB", "ab"]), &preserve("prefix")).unwrap();
        assert_eq!(out, vec!["AB", "ab"]);
    }

    #[test]
    fn numeric_and_alnum_tokens_are_allowed() {
        let out = parse_token_list(owned(&["abc123", "9f8e"]), &preserve("prefix")).unwrap();
        assert_eq!(out, vec!["abc123", "9f8e"]);
    }
}
