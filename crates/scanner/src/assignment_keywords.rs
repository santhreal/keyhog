//! Generic credential-assignment keyword vocabulary (phase-2 prefilter triggers).
//!
//! DERIVED, not hand-maintained. Generic entropy-owner detector TOMLs already
//! carry the credential-keyword concept in their `keywords` field, so the
//! prefilter vocab is BUILT from them at load time
//! rather than duplicated in a separate `rules/assignment_keywords.toml`. There is
//! exactly ONE home for the vocabulary: the detector specs. This module unions
//! their keywords, folds case, expands the three real-world separator spellings
//! (`api_key`/`api-key`/`api.key`) in ONE place, and adds the prefilter-only `pass`
//! stem.
//!
//! Embedded helpers share the static derived list; each `CompiledScanner` builds
//! its generic assignment regex and no-hit stem set from the active corpus via
//! `GenericAssignmentKeywordPlan`. Widening a generic detector's `keywords`
//! therefore widens every production prefilter without a second list or an
//! embedded-corpus override for replacement detectors.

use keyhog_core::DetectorSpec;
use std::sync::LazyLock;

/// The three real-world spellings of a compound credential key differ only in the
/// separator between segments. Kept in ONE place so expansion never drifts.
const KEYWORD_SEPARATORS: [char; 3] = ['_', '-', '.'];

struct EmbeddedAssignmentPolicy {
    keywords: Vec<String>,
    vendor_suffixes: Vec<String>,
    tail_suffixes: Vec<String>,
}

static ASSIGNMENT_POLICY: LazyLock<EmbeddedAssignmentPolicy> = LazyLock::new(|| {
    // LAW10: fail-closed/security; the embedded corpus is a build artifact and corruption aborts initialization rather than narrowing recall.
    let detectors = keyhog_core::load_embedded_detectors_or_fail()
        // LAW10: embedded corpus corruption aborts matcher initialization with its exact error; no reduced vocabulary is substituted.
        .unwrap_or_else(|error| panic!("embedded detector corpus is corrupt: {error}"));
    EmbeddedAssignmentPolicy {
        // LAW10: fail-closed/security; an invalid embedded keyword policy aborts initialization rather than narrowing the assignment bridge.
        keywords: derive_assignment_keywords(&detectors).unwrap_or_else(|error| {
            panic!(
                "cannot derive the generic assignment-keyword vocabulary: {error}. Fix the bundled generic phase-2 detector specs"
            )
        }),
        // LAW10: fail-closed/security; an invalid embedded suffix policy aborts initialization rather than narrowing the assignment bridge.
        vendor_suffixes: derive_generic_vendor_suffixes(&detectors).unwrap_or_else(|error| {
            panic!(
                "cannot derive generic vendor assignment suffixes: {error}. Fix the bundled generic phase-2 detector specs"
            )
        }),
        // LAW10: fail-closed/security; an invalid embedded tail policy aborts initialization rather than narrowing the assignment bridge.
        tail_suffixes: derive_generic_assignment_tail_suffixes(&detectors).unwrap_or_else(
            |error| {
                panic!(
                    "cannot derive generic assignment tail suffixes: {error}. Fix the bundled generic phase-2 detector specs"
                )
            },
        ),
    }
});

/// The embedded generic credential-assignment keywords (lowercase, first-seen
/// order). Runtime scanners compile their own projection from the active corpus.
pub(crate) fn assignment_keywords() -> &'static [String] {
    &ASSIGNMENT_POLICY.keywords
}

pub(crate) fn generic_vendor_suffixes() -> &'static [String] {
    &ASSIGNMENT_POLICY.vendor_suffixes
}

pub(crate) fn generic_assignment_tail_suffixes() -> &'static [String] {
    &ASSIGNMENT_POLICY.tail_suffixes
}

/// Union the `keywords` of every generic entropy-policy owner, lowercase them,
/// and expand each into its three separator spellings.
/// The `pass` stem (the dominant `*_PASS=` CredData credential-env pattern) is a
/// real `generic-keyword-secret` keyword, so it flows through this union like any
/// other, the owning-detector find in `phase2_generic.rs` can then attribute
/// `*_PASS=` candidates to that low-floor detector (the SES_PASS recall fix). The
/// Regex detectors participate only when they explicitly claim generic entropy
/// ownership through `entropy_policy_priority`; that makes their keyword and
/// length policy executable in a focused corpus instead of leaving a half-wired
/// owner that can classify but never generate assignment candidates.
///
/// Order-preserving with cross-detector dedup. Fails closed if no generic entropy
/// owner is present (an empty prefilter would be an invisible recall hole) or
/// if a derived entry violates the Tier-B charset (reuses the shared validator).
pub(crate) fn derive_assignment_keywords(
    detectors: &[DetectorSpec],
) -> Result<Vec<String>, String> {
    let mut ordered: Vec<String> = Vec::new();
    let mut seen = std::collections::BTreeSet::<String>::new();
    let mut generic_entropy_owners = 0usize;
    for detector in detectors {
        if !detector.owns_entropy_policy() {
            continue;
        }
        generic_entropy_owners += 1;
        for keyword in &detector.keywords {
            let lower = keyword.to_ascii_lowercase();
            for spelling in separator_spellings(&lower) {
                if seen.insert(spelling.clone()) {
                    ordered.push(spelling);
                }
            }
        }
    }
    if generic_entropy_owners == 0 {
        return Err("no generic entropy-policy owner exists in the corpus; the \
             assignment-keyword prefilter would admit nothing and silently drop every \
             generic-credential chunk"
            .to_string());
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

pub(crate) fn derive_generic_vendor_suffixes(
    detectors: &[DetectorSpec],
) -> Result<Vec<String>, String> {
    derive_unique_phase2_suffixes(
        detectors,
        |detector| &detector.generic_vendor_suffixes,
        "generic_vendor_suffixes",
        "generic vendor suffix",
    )
}

pub(crate) fn derive_generic_assignment_tail_suffixes(
    detectors: &[DetectorSpec],
) -> Result<Vec<String>, String> {
    derive_unique_phase2_suffixes(
        detectors,
        |detector| &detector.generic_assignment_tail_suffixes,
        "generic_assignment_tail_suffixes",
        "generic assignment tail suffix",
    )
}

fn derive_unique_phase2_suffixes(
    detectors: &[DetectorSpec],
    select: for<'a> fn(&'a DetectorSpec) -> &'a [String],
    field: &str,
    what: &'static str,
) -> Result<Vec<String>, String> {
    let mut owner: Option<&DetectorSpec> = None;
    for detector in detectors {
        if select(detector).is_empty() {
            continue;
        }
        if detector.kind != keyhog_core::DetectorKind::Phase2Generic {
            return Err(format!(
                "detector {:?} declares {field} but is not phase2-generic",
                detector.id
            ));
        }
        if let Some(previous) = owner {
            return Err(format!(
                "detectors {:?} and {:?} both declare {field}; exactly one phase2-generic detector may own the list",
                previous.id, detector.id
            ));
        }
        owner = Some(detector);
    }
    let Some(owner) = owner else {
        return Ok(Vec::new());
    };
    crate::tier_b_list::parse_token_list(
        select(owner).to_vec(),
        &crate::tier_b_list::ListPolicy {
            what,
            require_lowercase: true,
            separators: b"",
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
