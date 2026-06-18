//! Tier-B test-fixture suppression list. Loaded from the bundled
//! `crates/cli/data/suppressions/test-fixtures.toml` via `include_str!`
//! at build time; previously hardcoded in `orchestrator.rs` as a chain
//! of `cred == concat!("sk_", "live_", …)` branches. Moving the data
//! out of code lets a user contribute a new suppression without
//! re-compiling, lets the differential bench harness honour the same
//! list, and lets users opt out entirely via
//! `--no-suppress-test-fixtures`.

use std::collections::HashSet;

use serde::Deserialize;

/// Bundled suppression payload, parsed once at startup and queried
/// per finding. `exact` is an O(1) hash lookup; `substring` is a
/// short linear scan (the list is intentionally tiny - EXAMPLE
/// and PLACEHOLDER today; if it grows, swap the impl for an
/// aho-corasick scan without changing the public API).
#[derive(Debug)]
pub(crate) struct TestFixtureSuppressions {
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
    /// Load the bundled suppression list. A malformed bundled TOML is a broken
    /// build; do not continue with test-fixture suppression weakened.
    #[must_use]
    pub(crate) fn bundled() -> Self {
        match Self::from_toml(BUNDLED_TOML) {
            Ok(suppressions) => suppressions,
            Err(error) => {
                panic!(
                    "crates/cli/data/suppressions/test-fixtures.toml is invalid: {error}. \
                     Fix the bundled Tier-B test-fixture suppressions; refusing to run without \
                     suppression truth."
                )
            }
        }
    }

    pub(crate) fn from_toml(raw: &str) -> Result<Self, String> {
        let parsed: SuppressionFile =
            toml::from_str(raw).map_err(|error| format!("invalid test-fixtures.toml: {error}"))?;
        if parsed.schema_version != 1 {
            return Err(format!(
                "unsupported test-fixture suppression schema_version {}",
                parsed.schema_version
            ));
        }

        let mut exact = HashSet::with_capacity(parsed.exact.len());
        for entry in parsed.exact {
            let credential = entry.credential;
            if credential.trim().is_empty() {
                return Err("exact suppression credentials must not be empty".to_string());
            }
            if !exact.insert(credential.clone()) {
                return Err(format!(
                    "duplicate exact suppression credential {credential:?}"
                ));
            }
        }

        let mut substring_seen = HashSet::new();
        // Substrings are tiny and constant - leak the strings to
        // `&'static str` so we don't pay an alloc on every check.
        let mut substrings = Vec::with_capacity(parsed.substring.len());
        for entry in parsed.substring {
            let needle = entry.needle.trim();
            if needle.is_empty() {
                return Err("substring suppression needles must not be empty".to_string());
            }
            if !substring_seen.insert(needle.to_string()) {
                return Err(format!("duplicate substring suppression needle {needle:?}"));
            }
            substrings.push(Box::leak(needle.to_string().into_boxed_str()) as &'static str);
        }

        if exact.is_empty() && substrings.is_empty() {
            return Err("test-fixture suppressions must contain at least one entry".to_string());
        }

        Ok(Self { exact, substrings })
    }

    /// A do-nothing suppression list - every credential passes
    /// through. Returned when the user passes
    /// `--no-suppress-test-fixtures`.
    #[must_use]
    pub(crate) fn empty() -> Self {
        Self {
            exact: HashSet::new(),
            substrings: Vec::new(),
        }
    }

    /// True when `cred` should be suppressed. O(1) for exact hits,
    /// O(n_substrings) for substring filtering (n=2 today).
    #[must_use]
    pub(crate) fn suppresses(&self, cred: &str) -> bool {
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

    /// Count of exact entries - used by tests + introspection
    /// (`--list-suppressions` if we ship one).
    #[must_use]
    pub(crate) fn exact_count(&self) -> usize {
        self.exact.len()
    }
}

#[doc(hidden)]
pub(crate) mod testing {
    pub(crate) fn bundled() -> super::TestFixtureSuppressions {
        super::TestFixtureSuppressions::bundled()
    }

    pub(crate) fn empty() -> super::TestFixtureSuppressions {
        super::TestFixtureSuppressions::empty()
    }

    pub(crate) fn suppresses(suppressions: &super::TestFixtureSuppressions, cred: &str) -> bool {
        suppressions.suppresses(cred)
    }

    pub(crate) fn exact_count(suppressions: &super::TestFixtureSuppressions) -> usize {
        suppressions.exact_count()
    }

    pub(crate) fn from_toml(raw: &str) -> Result<super::TestFixtureSuppressions, String> {
        super::TestFixtureSuppressions::from_toml(raw)
    }
}
