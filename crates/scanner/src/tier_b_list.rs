//! Shared parse + validate primitive for Tier-B single-column token lists.
//!
//! Several Tier-B data files are just an ordered list of tokens, the phase-2
//! assignment keywords ([`crate::assignment_keywords`]) and the multiline secret
//! prefixes ([`crate::secret_prefixes`]) among them. They share the EXACT same
//! validation: trim each entry, reject empties, restrict the charset to ASCII
//! alphanumerics plus a small allowed separator set, reject duplicates, and require
//! a non-empty result. The only axes that vary per file are (1) whether entries
//! must already be lowercase (the consumer folds case) or keep their casing verbatim
//! (the consumer is case-sensitive), and (2) which separators are allowed.
//!
//! This module owns that one validator so each per-file loader stays a thin wrapper
//! over a single source of truth, no drift across copies (NO DUPLICATION), and the
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
#[path = "../tests/unit/tier_b_list.rs"]
mod tests;
