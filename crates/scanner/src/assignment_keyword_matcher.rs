//! Shared compiled admission index for detector-owned assignment keywords.

use std::sync::Arc;

/// Corpus and config-owned keyword matcher shared by entropy and multiline
/// admission. Matching is ASCII case-insensitive substring search.
pub(crate) struct AssignmentKeywordMatcher {
    ac: Option<aho_corasick::AhoCorasick>,
    linear_fallback: Box<[String]>,
}

impl AssignmentKeywordMatcher {
    pub(crate) fn compile(secret_keywords: &[String], detector_policy_keywords: &[String]) -> Self {
        let mut seen = std::collections::HashSet::new();
        let patterns = secret_keywords
            .iter()
            .chain(detector_policy_keywords)
            .filter(|keyword| !keyword.is_empty())
            .filter(|keyword| seen.insert(keyword.to_ascii_lowercase()))
            .cloned()
            .collect::<Vec<_>>();
        if patterns.is_empty() {
            return Self {
                ac: None,
                linear_fallback: patterns.into_boxed_slice(),
            };
        }
        match aho_corasick::AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(patterns.iter().map(String::as_bytes))
        {
            Ok(ac) => Self {
                ac: Some(ac),
                linear_fallback: patterns.into_boxed_slice(),
            },
            Err(error) => {
                tracing::warn!(
                    target: "keyhog::detection",
                    %error,
                    "assignment keyword index could not be compiled; using the exact linear matcher"
                );
                Self {
                    ac: None,
                    linear_fallback: patterns.into_boxed_slice(),
                }
            }
        }
    }

    pub(crate) fn matches(&self, line: &[u8]) -> bool {
        self.ac.as_ref().map_or_else(
            || {
                self.linear_fallback
                    .iter()
                    .any(|keyword| crate::ascii_ci::ci_find_nonempty(line, keyword.as_bytes()))
            },
            |ac| ac.find(line).is_some(),
        )
    }
}

/// Rebuilds only when a programmatic caller mutates the public scanner config.
/// Exact list comparison prevents stale behavior from a digest collision.
#[derive(Default)]
pub(crate) struct AssignmentKeywordMatcherCache {
    secret_keywords: Vec<String>,
    detector_policy_keywords: Vec<String>,
    matcher: Option<Arc<AssignmentKeywordMatcher>>,
}

impl AssignmentKeywordMatcherCache {
    pub(crate) fn resolve(
        &mut self,
        secret_keywords: &[String],
        detector_policy_keywords: &[String],
    ) -> Arc<AssignmentKeywordMatcher> {
        if self.secret_keywords != secret_keywords
            || self.detector_policy_keywords != detector_policy_keywords
        {
            self.secret_keywords.clear();
            self.secret_keywords.extend_from_slice(secret_keywords);
            self.detector_policy_keywords.clear();
            self.detector_policy_keywords
                .extend_from_slice(detector_policy_keywords);
            self.matcher = None;
        }
        Arc::clone(self.matcher.get_or_insert_with(|| {
            Arc::new(AssignmentKeywordMatcher::compile(
                secret_keywords,
                detector_policy_keywords,
            ))
        }))
    }
}
