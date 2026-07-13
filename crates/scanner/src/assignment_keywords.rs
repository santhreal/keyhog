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
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The recall-critical assignment keywords: every CredData credential-env
    /// trigger the prefilter matched BEFORE this vocabulary moved into the
    /// detector specs (the old hand-maintained `rules/assignment_keywords.toml`).
    /// The derived vocab MUST remain a SUPERSET of this set, that is the recall
    /// parity contract. It is a floor, not an equality: the derivation legitimately
    /// carries EXTRA keywords the generic detectors declare (e.g. `secret_key`,
    /// `access_token`, `passphrase`), which only widens recall.
    const RECALL_CRITICAL: &[&str] = &[
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

    /// Build a synthetic phase-2 generic detector for the derivation unit tests.
    fn phase2_generic(keywords: &[&str]) -> DetectorSpec {
        DetectorSpec {
            id: "generic-test".to_string(),
            name: "Generic Test".to_string(),
            service: "generic".to_string(),
            kind: DetectorKind::Phase2Generic,
            keywords: keywords.iter().map(|k| k.to_string()).collect(),
            ..Default::default()
        }
    }

    // ── recall parity: the derived vocab is a superset of the 46 ───────────

    #[test]
    fn recall_critical_set_is_exactly_46_unique_entries() {
        // Pin the size and dedup of the parity FLOOR itself so an accidental
        // edit to this constant cannot silently weaken the superset assertion.
        assert_eq!(RECALL_CRITICAL.len(), 46);
        let unique: BTreeSet<&&str> = RECALL_CRITICAL.iter().collect();
        assert_eq!(unique.len(), 46);
    }

    #[test]
    fn derived_vocab_is_a_superset_of_the_recall_critical_46() {
        let derived: BTreeSet<&str> = assignment_keywords().iter().map(String::as_str).collect();
        let missing: Vec<&str> = RECALL_CRITICAL
            .iter()
            .copied()
            .filter(|kw| !derived.contains(kw))
            .collect();
        assert!(
            missing.is_empty(),
            "derived vocab dropped recall-critical keywords: {missing:?}"
        );
        // Superset, not equality: the derivation carries strictly more.
        assert!(assignment_keywords().len() >= RECALL_CRITICAL.len());
    }

    #[test]
    fn extra_derived_keywords_beyond_the_46_are_the_expected_detector_declarations() {
        // The derivation legitimately widens beyond the 46 with keywords the
        // generic detectors declare; pin a concrete sample so "superset" is a real
        // observed value, not a vacuous >= check.
        let derived: BTreeSet<&str> = assignment_keywords().iter().map(String::as_str).collect();
        for extra in ["secret_key", "access_token", "signing_secret", "passphrase"] {
            assert!(derived.contains(extra), "expected extra keyword {extra}");
            assert!(
                !RECALL_CRITICAL.contains(&extra),
                "{extra} should be an EXTRA, not part of the 46"
            );
        }
    }

    // ── one home: the accessor is purely derived, no second source ─────────

    #[test]
    fn accessor_equals_a_fresh_derivation_from_the_embedded_corpus() {
        // Proves there is exactly ONE vocab home: re-deriving from the embedded
        // detector corpus reproduces the accessor byte-for-byte. If a second
        // definition (a stray list, a re-added TOML) crept in, this diverges.
        let detectors = keyhog_core::load_embedded_detectors_or_fail().expect("corpus loads");
        let fresh = derive_assignment_keywords(&detectors).expect("derivation succeeds");
        assert_eq!(fresh.as_slice(), assignment_keywords());
    }

    #[test]
    fn the_legacy_assignment_keywords_toml_is_gone() {
        // The old hand-maintained vocab file must not exist, its concept now lives
        // solely in the detector specs. A re-added file is a second home (drift).
        let legacy = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../rules/assignment_keywords.toml");
        assert!(
            !legacy.exists(),
            "rules/assignment_keywords.toml was re-created; the vocabulary has exactly one \
             home (the generic phase-2 detector specs)"
        );
    }

    // ── derivation semantics: case-fold, expansion, filter, dedup, pass ────

    #[test]
    fn derive_lowercases_detector_keywords() {
        let out = derive_assignment_keywords(&[phase2_generic(&["API_KEY"])]).unwrap();
        assert!(out.iter().any(|k| k == "api_key"));
        assert!(out.iter().any(|k| k == "api-key"));
        assert!(out.iter().any(|k| k == "api.key"));
        assert!(!out.iter().any(|k| k == "API_KEY"));
    }

    #[test]
    fn derive_expands_each_compound_into_all_three_separator_spellings() {
        let out = derive_assignment_keywords(&[phase2_generic(&["foo_bar"])]).unwrap();
        let set: BTreeSet<&str> = out.iter().map(String::as_str).collect();
        assert!(set.contains("foo_bar"));
        assert!(set.contains("foo-bar"));
        assert!(set.contains("foo.bar"));
    }

    #[test]
    fn derive_emits_a_separatorless_keyword_verbatim_once() {
        let out = derive_assignment_keywords(&[phase2_generic(&["secret"])]).unwrap();
        let occurrences = out.iter().filter(|k| k.as_str() == "secret").count();
        assert_eq!(occurrences, 1);
        // No spurious `secret-`/`secret.` variants for a keyword with no separator.
        assert!(!out.iter().any(|k| k.contains('-') || k.contains('.')));
    }

    #[test]
    fn derive_excludes_non_generic_service_detectors() {
        // A named vendor detector, even one that is phase2-generic kind, must not
        // contribute to the generic prefilter vocabulary.
        let mut aws = phase2_generic(&["aws_secret_marker"]);
        aws.service = "aws".to_string();
        let out = derive_assignment_keywords(&[aws, phase2_generic(&["secret"])]).unwrap();
        assert!(!out.iter().any(|k| k == "aws_secret_marker"));
    }

    #[test]
    fn derive_excludes_regex_kind_generic_detectors() {
        // Pins that `generic-password`-class regex detectors (uppercase/`://`
        // keywords) never pollute the lowercase assignment prefilter.
        let mut regex_generic = phase2_generic(&["regex_only_marker"]);
        regex_generic.kind = DetectorKind::Regex;
        let out =
            derive_assignment_keywords(&[regex_generic, phase2_generic(&["secret"])]).unwrap();
        assert!(!out.iter().any(|k| k == "regex_only_marker"));
    }

    #[test]
    fn derive_dedups_a_keyword_shared_across_detectors() {
        let out = derive_assignment_keywords(&[
            phase2_generic(&["secret", "token"]),
            phase2_generic(&["secret", "credential"]),
        ])
        .unwrap();
        assert_eq!(out.iter().filter(|k| k.as_str() == "secret").count(), 1);
    }

    #[test]
    fn derive_carries_the_pass_stem_from_its_real_detector_owner() {
        // `pass` is now a real `generic-keyword-secret` keyword (the `*_PASS=`
        // recall owner), so a phase2-generic detector carrying it contributes it
        // to the derived vocab like any keyword, the former PASS_STEM injection
        // is gone (ONE PLACE: one owner, no byte-identical inline copy).
        let with = derive_assignment_keywords(&[phase2_generic(&["secret", "pass"])]).unwrap();
        assert!(with.iter().any(|k| k == "pass"));
        // A detector WITHOUT `pass` no longer conjures it, its presence now
        // depends solely on its real detector owner.
        let without = derive_assignment_keywords(&[phase2_generic(&["secret"])]).unwrap();
        assert!(!without.iter().any(|k| k == "pass"));
        // INVARIANT GUARD (replaces PASS_STEM's guarantee): the SHIPPED corpus
        // MUST still derive `pass`, or `*_PASS=` recall silently dies. If
        // generic-keyword-secret ever loses the keyword, this fails loudly.
        let corpus = keyhog_core::load_embedded_detectors_or_fail().expect("embedded corpus");
        let shipped = derive_assignment_keywords(&corpus).unwrap();
        assert!(
            shipped.iter().any(|k| k == "pass"),
            "generic-keyword-secret lost its `pass` keyword; *_PASS= recall would silently drop"
        );
    }

    #[test]
    fn derive_fails_closed_when_no_generic_phase2_detector_is_present() {
        // Empty corpus.
        assert!(derive_assignment_keywords(&[]).is_err());
        // Only a regex-kind generic detector (still no phase-2 bridge).
        let mut regex_generic = phase2_generic(&["password"]);
        regex_generic.kind = DetectorKind::Regex;
        let err = derive_assignment_keywords(&[regex_generic]).unwrap_err();
        assert!(err.contains("phase2-generic"), "got: {err}");
    }

    // ── separator_spellings helper: direct truth table ─────────────────────

    #[test]
    fn separator_spellings_expands_a_single_separator_in_underscore_hyphen_dot_order() {
        assert_eq!(
            separator_spellings("api_key"),
            vec!["api_key", "api-key", "api.key"]
        );
    }

    #[test]
    fn separator_spellings_substitutes_every_separator_uniformly() {
        // A multi-separator keyword collapses to one separator per spelling.
        assert_eq!(
            separator_spellings("x-api-key"),
            vec!["x_api_key", "x-api-key", "x.api.key"]
        );
    }

    #[test]
    fn separator_spellings_returns_a_separatorless_keyword_unchanged() {
        assert_eq!(separator_spellings("secret"), vec!["secret"]);
    }

    // ── invariants of the real derived vocabulary ──────────────────────────

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
        let set: BTreeSet<&str> = assignment_keywords().iter().map(String::as_str).collect();
        for (u, h, d) in [
            ("api_key", "api-key", "api.key"),
            ("private_key", "private-key", "private.key"),
            ("client_secret", "client-secret", "client.secret"),
            ("master_key", "master-key", "master.key"),
            ("license_key", "license-key", "license.key"),
        ] {
            assert!(set.contains(u), "missing {u}");
            assert!(set.contains(h), "missing {h}");
            assert!(set.contains(d), "missing {d}");
        }
    }

    #[test]
    fn bare_pass_keyword_is_present() {
        assert!(assignment_keywords().iter().any(|k| k == "pass"));
    }

    #[test]
    fn bare_key_stem_is_not_in_the_base_list() {
        // `key` is added by `generic_keyword_prefilter_stems`, NOT the base vocab
        // pin that so a future edit does not silently widen the AC.
        assert!(
            !assignment_keywords().iter().any(|k| k == "key"),
            "the bare `key` stem must stay a consumer-side addition, not the base list"
        );
    }

    #[test]
    fn ac_built_from_derived_vocab_matches_case_insensitively() {
        // The recall-critical consumer works from the derived list: an
        // `ascii_case_insensitive` Aho-Corasick fires on mixed-case and separator
        // spellings and rejects a non-keyword.
        let ac = aho_corasick::AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(assignment_keywords().iter().map(String::as_str))
            .expect("AC builds from the derived keywords");
        assert!(
            ac.find(b"SECRET=hunter2").is_some(),
            "case-insensitive secret"
        );
        assert!(ac.find(b"api_key: xyz").is_some(), "underscore spelling");
        assert!(ac.find(b"API.KEY=xyz").is_some(), "dotted + upper spelling");
        assert!(
            ac.find(b"just some random text").is_none(),
            "a non-keyword line must not trigger the prefilter"
        );
    }
}
