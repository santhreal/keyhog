//! Tier-B test-fixture suppression list. Loaded from the bundled
//! `data/suppressions/test-fixtures.toml`; previously hardcoded in
//! `orchestrator.rs` as a chain of `cred == concat!("sk_", "live_",
//! …)` branches. Moving the data out of code lets a user
//! contribute a new suppression without re-compiling, lets the
//! differential bench harness honour the same list, and lets users
//! opt out entirely via `--no-suppress-test-fixtures`.

use std::collections::HashSet;

use serde::Deserialize;

/// Bundled suppression payload, parsed once at startup and queried
/// per finding. `exact` is an O(1) hash lookup; `substring` is a
/// short linear scan (the list is intentionally tiny — EXAMPLE
/// and PLACEHOLDER today; if it grows, swap the impl for an
/// aho-corasick scan without changing the public API).
#[derive(Debug)]
pub struct TestFixtureSuppressions {
    exact: HashSet<String>,
    substrings: Vec<&'static str>,
}

#[derive(Debug, Deserialize)]
struct SuppressionFile {
    #[allow(dead_code)]
    schema_version: u32,
    #[serde(default)]
    exact: Vec<ExactEntry>,
    #[serde(default)]
    substring: Vec<SubstringEntry>,
}

#[derive(Debug, Deserialize)]
struct ExactEntry {
    credential: String,
    #[allow(dead_code)]
    service: Option<String>,
    #[allow(dead_code)]
    source: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SubstringEntry {
    needle: String,
}

const BUNDLED_TOML: &str = include_str!("../data/suppressions/test-fixtures.toml");

impl TestFixtureSuppressions {
    /// Load the bundled suppression list. A malformed bundled TOML is
    /// a build error caught by the `bundled_loads_and_parses` unit
    /// test — but at runtime we degrade to an empty suppression set
    /// rather than killing the scanner mid-run if someone ships a
    /// broken binary anyway.
    #[must_use]
    pub fn bundled() -> Self {
        let parsed: SuppressionFile = match toml::from_str(BUNDLED_TOML) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "bundled test-fixtures.toml failed to parse; \
                     falling back to empty suppression set"
                );
                return Self::empty();
            }
        };
        let exact: HashSet<String> = parsed.exact.into_iter().map(|e| e.credential).collect();
        // Substrings are tiny and constant — leak the strings to
        // `&'static str` so we don't pay an alloc on every check.
        let substrings: Vec<&'static str> = parsed
            .substring
            .into_iter()
            .map(|s| Box::leak(s.needle.into_boxed_str()) as &'static str)
            .collect();
        Self { exact, substrings }
    }

    /// A do-nothing suppression list — every credential passes
    /// through. Returned when the user passes
    /// `--no-suppress-test-fixtures`.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            exact: HashSet::new(),
            substrings: Vec::new(),
        }
    }

    /// True when `cred` should be suppressed. O(1) for exact hits,
    /// O(n_substrings) for substring filtering (n=2 today).
    #[must_use]
    pub fn suppresses(&self, cred: &str) -> bool {
        if self.exact.contains(cred) {
            return true;
        }
        for needle in &self.substrings {
            if cred.contains(needle) {
                return true;
            }
        }
        false
    }

    /// Count of exact entries — used by tests + introspection
    /// (`--list-suppressions` if we ship one).
    #[must_use]
    pub fn exact_count(&self) -> usize {
        self.exact.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_loads_and_parses() {
        let s = TestFixtureSuppressions::bundled();
        // The known minimum: Stripe + GitHub + Slack + boundary
        // fixture + the literal `parameter` placeholder. If this
        // count drops we have either regressed the TOML or shipped
        // a parser bug; if it grows we added a new suppression
        // and should bump the constant deliberately.
        assert!(
            s.exact_count() >= 5,
            "expected at least 5 exact entries; got {}",
            s.exact_count(),
        );
    }

    #[test]
    fn bundled_suppresses_known_demo_keys() {
        let s = TestFixtureSuppressions::bundled();
        // Hand-typed (not copied from the TOML) so a typo in the
        // bundled file would be caught here.
        assert!(s.suppresses("sk_live_4eC39HqLyjWDarjtT1zdp7dc"));
        assert!(s.suppresses("ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX"));
        assert!(s.suppresses("xoxb-123456789012-1234567890123"));
        // Substring filter
        assert!(s.suppresses("API_KEY_EXAMPLE"));
        assert!(s.suppresses("PLACEHOLDER_token"));
    }

    #[test]
    fn bundled_does_not_suppress_real_aws_key() {
        let s = TestFixtureSuppressions::bundled();
        // The canonical bench-corpus AWS key is NOT in the
        // suppression list — confirming the suppression is
        // narrowly scoped, not a denylist on the whole detector
        // class.
        assert!(!s.suppresses("AKIAQYLPMN5HFIQR7XYA"));
        // And a random unrelated string isn't a false positive.
        assert!(!s.suppresses("just some text"));
        assert!(!s.suppresses(""));
    }

    #[test]
    fn empty_never_suppresses() {
        let s = TestFixtureSuppressions::empty();
        assert!(!s.suppresses("sk_live_4eC39HqLyjWDarjtT1zdp7dc"));
        assert!(!s.suppresses("API_KEY_EXAMPLE"));
        assert_eq!(s.exact_count(), 0);
    }
}
