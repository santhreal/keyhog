//! Generic credential-assignment keyword vocabulary (phase-2 prefilter triggers).
//!
//! DERIVED, not hand-maintained. The generic phase-2 detector TOMLs
//! (`detectors/generic-secret.toml`, `generic-api-key.toml`,
//! `generic-keyword-secret.toml`) already carry the credential-keyword concept in
//! their `keywords` field, so the prefilter vocab is BUILT from them at load time
//! rather than duplicated in a separate `rules/assignment_keywords.toml`. There is
//! exactly ONE home for the vocabulary: the detector specs. This module unions
//! their keywords, folds case, expands the three real-world separator spellings
//! (`api_key`/`api-key`/`api.key`) in ONE place, and adds the prefilter-only `pass`
//! stem.
//!
//! Three phase-2 consumers share the derived list unchanged (still
//! `&'static [String]`): the `ascii_case_insensitive` Aho-Corasick chunk prefilter
//! (`scan_filters::has_generic_assignment_keyword`), the no-hit prefilter stem set
//! (`phase2_generic::keywords::generic_keyword_prefilter_stems`), and the entropy
//! keyword-anchor contains-check (`phase2_entropy::helpers`). Widening a generic
//! detector's `keywords` now widens the prefilter automatically, no second list to
//! keep in sync.

use keyhog_core::{DetectorKind, DetectorSpec};
use std::sync::LazyLock;

/// The three real-world spellings of a compound credential key differ only in the
/// separator between segments. Kept in ONE place so expansion never drifts.
const KEYWORD_SEPARATORS: [char; 3] = ['_', '-', '.'];

static ASSIGNMENT_KEYWORDS: LazyLock<Vec<String>> = LazyLock::new(|| {
    // Law 10: the detector corpus is baked into the binary by `build.rs`; a parse
    // failure is a BUILD/SOURCE bug, never a runtime condition an operator can act
    // on, so fail closed (panic) rather than ship a silently-narrowed prefilter.
    let detectors = match keyhog_core::load_embedded_detectors_or_fail() {
        Ok(detectors) => detectors,
        Err(error) => panic!(
            "embedded detector corpus is corrupt: {error}. The generic assignment-keyword \
             prefilter is derived from it; refusing to run without the generic-credential \
             prefilter truth."
        ),
    };
    match derive_assignment_keywords(&detectors) {
        Ok(keywords) => keywords,
        Err(error) => panic!(
            "cannot derive the generic assignment-keyword vocabulary: {error}. Fix the bundled \
             generic phase-2 detector specs (the single home for this vocabulary)."
        ),
    }
});

/// The generic credential-assignment keywords (lowercase, first-seen order). All
/// three consumers fold case, so the entries are matched case-insensitively.
pub(crate) fn assignment_keywords() -> &'static [String] {
    &ASSIGNMENT_KEYWORDS
}

/// Union the `keywords` of every `service == "generic"`, `kind == phase2-generic`
/// detector, lowercase them, and expand each into its three separator spellings.
/// The `pass` stem (the dominant `*_PASS=` CredData credential-env pattern) is a
/// real `generic-keyword-secret` keyword, so it flows through this union like any
/// other, the owning-detector find in `phase2_generic.rs` can then attribute
/// `*_PASS=` candidates to that low-floor detector (the SES_PASS recall fix). The
/// `kind` filter is load-bearing: it admits only the shapeless-secret bridge
/// detectors and EXCLUDES the regex-kind generic detectors (e.g. `generic-password`,
/// whose `keywords` carry uppercase `PASSWORD`/`DB_PASSWORD` regex anchors and
/// `://`-style markers that must never pollute the lowercase assignment prefilter).
///
/// Order-preserving with cross-detector dedup. Fails closed if no generic phase-2
/// detector is present (an empty prefilter would be an invisible recall hole) or
/// if a derived entry violates the Tier-B charset (reuses the shared validator).
pub(crate) fn derive_assignment_keywords(
    detectors: &[DetectorSpec],
) -> Result<Vec<String>, String> {
    let mut ordered: Vec<String> = Vec::new();
    let mut seen = std::collections::BTreeSet::<String>::new();
    let mut generic_phase2_detectors = 0usize;
    for detector in detectors {
        if detector.service != "generic" || detector.kind != DetectorKind::Phase2Generic {
            continue;
        }
        generic_phase2_detectors += 1;
        for keyword in &detector.keywords {
            let lower = keyword.to_ascii_lowercase();
            for spelling in separator_spellings(&lower) {
                if seen.insert(spelling.clone()) {
                    ordered.push(spelling);
                }
            }
        }
    }
    if generic_phase2_detectors == 0 {
        return Err(
            "no service=\"generic\" kind=\"phase2-generic\" detectors in the corpus; the \
             assignment-keyword prefilter would admit nothing and silently drop every \
             generic-credential chunk"
                .to_string(),
        );
    }
    // Reuse the ONE Tier-B list validator (charset/lowercase/dup/non-empty) so a
    // malformed derived entry fails closed instead of silently widening the AC.
    crate::tier_b_list::parse_token_list(
        ordered,
        &crate::tier_b_list::ListPolicy {
            what: "assignment keyword",
            require_lowercase: true,
            separators: b"_-.",
        },
    )
}

/// Expand a keyword into its separator spellings. A keyword carrying any of
/// `_`/`-`/`.` is emitted three times, once per separator (uniformly substituted),
/// so the prefilter fires regardless of the source's convention; a keyword with no
/// separator is emitted verbatim. This is the ONE place separator expansion lives.
fn separator_spellings(keyword: &str) -> Vec<String> {
    if !keyword.contains(KEYWORD_SEPARATORS) {
        return vec![keyword.to_string()];
    }
    KEYWORD_SEPARATORS
        .iter()
        .map(|&sep| {
            keyword
                .chars()
                .map(|c| {
                    if KEYWORD_SEPARATORS.contains(&c) {
                        sep
                    } else {
                        c
                    }
                })
                .collect::<String>()
        })
        .collect()
}


#[cfg(test)]
#[path = "../tests/unit/assignment_keywords.rs"]
mod tests;
