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

/// Declare a `LazyLock<Vec<String>>` backed by a single-field Tier-B TOML list
/// in `crates/scanner/rules/`.
///
/// Every Tier-B single-column list used to repeat the same four things: a
/// one-field `Deserialize` struct, a `parse_*` wrapper doing
/// `toml::from_str().map().map_err()`, a `LazyLock` calling it on an
/// `include_str!`, and a `panic!` naming the file. Twenty-odd copies varied
/// only in file name, struct name, and field name, so a fix to the error
/// wording or the empty-list contract had to be applied twenty-odd times. This
/// macro is that one copy.
///
/// `$file` is the base name inside `rules/`; the panic message names it. The
/// list must be non-empty: an empty Tier-B file would silently disable a whole
/// gate with no operator-visible signal (Law 10, fail closed).
macro_rules! tier_b_vec {
    ($(#[$meta:meta])* $vis:vis $name:ident, $file:literal, $field:ident) => {
        $(#[$meta])*
        $vis static $name: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
            #[derive(serde::Deserialize)]
            struct TierBList {
                $field: Vec<String>,
            }
            // `include_str!` embeds the file at compile time, so no
            // attacker-controlled input can reach this parse: a panic here is a
            // build-time defect in the bundled data, not a runtime hostile-input
            // risk. Fail closed and name the file so the owner knows what to fix.
            let raw = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/rules/", $file));
            let items = match toml::from_str::<TierBList>(raw) {
                Ok(parsed) => parsed.$field,
                Err(error) => panic!(
                    concat!("rules/", $file, " is invalid: {error}. Fix the bundled Tier-B data file."),
                    error = error
                ),
            };
            assert!(
                !items.is_empty(),
                concat!(
                    "rules/", $file, " is empty; refusing to run without the Tier-B list it owns."
                )
            );
            items
        });
    };
}

pub(crate) use tier_b_vec;

tier_b_vec!(
    /// Tier-B fixture / example path components. ONE owner: the suppression
    /// example-path gate (`suppression::decision`) and the path-confidence
    /// haircut (`confidence::penalties`) both read this static. They previously
    /// each declared their own struct, parser, and `LazyLock` over the same
    /// file, which is exactly the drift the shared file was meant to prevent.
    pub(crate) EXAMPLE_PATH_COMPONENTS,
    "example-path-components.toml",
    components
);
