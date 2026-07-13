//! Canonical detector-id strings and family predicates used by scanner logic.

pub(crate) const GENERIC_PREFIX: &str = "generic-";
pub(crate) const ENTROPY_PREFIX: &str = "entropy-";

pub(crate) const GENERIC_SECRET: &str = "generic-secret";
pub(crate) const GENERIC_KEYWORD_SECRET: &str = "generic-keyword-secret";
pub(crate) const GENERIC_API_KEY: &str = "generic-api-key";
pub(crate) const GENERIC_PASSWORD: &str = "generic-password";

pub(crate) const ENTROPY: &str = "entropy";
#[cfg(feature = "entropy")]
pub(crate) const ENTROPY_GENERIC: &str = "entropy-generic";
#[cfg(feature = "entropy")]
pub(crate) const ENTROPY_PASSWORD: &str = "entropy-password";
#[cfg(feature = "entropy")]
pub(crate) const ENTROPY_TOKEN: &str = "entropy-token";
#[cfg(feature = "entropy")]
pub(crate) const ENTROPY_API_KEY: &str = "entropy-api-key";

pub(crate) const PRIVATE_KEY: &str = "private-key";

pub(crate) const GITHUB_CLASSIC_PAT: &str = "github-classic-pat";
// Names the real `detectors/github-pat-fine-grained.toml` id. (Superseded the
// phantom `github-fine-grained-pat` const value, which matched NO detector.)
pub(crate) const GITHUB_PAT_FINE_GRAINED: &str = "github-pat-fine-grained";
// The GitLab checksum gate's source-of-truth detector. (Superseded the phantom
// `gitlab-token` const value, which matched NO detector, the glpat- validator
// gates `detectors/gitlab-personal-access-token.toml`.)
pub(crate) const GITLAB_PERSONAL_ACCESS_TOKEN: &str = "gitlab-personal-access-token";
pub(crate) const NPM_ACCESS_TOKEN: &str = "npm-access-token";
pub(crate) const PYPI_API_TOKEN: &str = "pypi-api-token";
// Always compiled (NOT `simdsieve`-gated): `crate::testing::checksum`: an
// always-built public support surface, labels the Slack checksum gate with
// this real detector id, so the const must resolve in every feature set.
// (Superseded the phantom `slack-token` validator label, which named no
// embedded detector; the xoxb-/xoxp- validator's own docs make
// `slack-bot-token` its source-of-truth detector.)
pub(crate) const SLACK_BOT_TOKEN: &str = "slack-bot-token";
pub(crate) const STRIPE_SECRET_KEY: &str = "stripe-secret-key";
// The structural-password-slot detector ids (url-credentials, sql-password,
// cli-password-flag, bearer-authorization) are NO LONGER named as consts here:
// the family is declared per-detector via `DetectorSpec::structural_password_slot`
// (their own TOMLs), and no scanner code references these ids individually, so a
// const owner would be dead. The `structural_password_slot_family_is_toml_declared`
// test below pins the exact membership against the embedded corpus.

#[inline]
pub(crate) fn is_generic_detector(detector_id: &str) -> bool {
    detector_id.starts_with(GENERIC_PREFIX)
}

#[inline]
pub(crate) fn is_entropy_detector(detector_id: &str) -> bool {
    detector_id == ENTROPY || detector_id.starts_with(ENTROPY_PREFIX)
}

#[inline]
pub(crate) fn is_private_key_fallback(detector_id: &str) -> bool {
    detector_id == PRIVATE_KEY
}

/// The "structural password slot" family: STRONG-anchor detectors whose regex
/// proves a syntactic credential SLOT (`scheme://user:<x>@host`,
/// `IDENTIFIED BY '<x>'`, `--password <x>`) but captures a FREE-FORM value the
/// way a real password is written, so the dominant SHORT all-lowercase random
/// passwords surface (the Tier-B randomness floor is skipped) while the
/// `dictionary_word_placeholder` gate (api.rs) drops the literal placeholder
/// words (`password`, `secret`) a service-anchored detector's structured capture
/// never produces. The `{6,128}` value floor in each detector drops the short
/// placeholders the bigram model cannot judge.
///
/// Membership is DECLARED PER-DETECTOR: each such detector sets
/// `structural_password_slot = true` in its own TOML (see
/// [`keyhog_core::DetectorSpec::structural_password_slot`]). This predicate reads
/// that single-owner flag rather than a hardcoded id list, so the family lives in
/// ONE place, the detector file, and a new member needs no code edit. A
/// synthetic/unknown id (no embedded spec) is never a structural password slot.
#[inline]
#[cfg(test)]
pub(crate) fn is_structural_password_slot_detector(detector_id: &str) -> bool {
    keyhog_core::detector_spec_by_id(detector_id).is_some_and(|spec| spec.structural_password_slot)
}

#[inline]
pub(crate) fn is_generic_or_entropy_detector(detector_id: &str) -> bool {
    is_generic_detector(detector_id) || is_entropy_detector(detector_id)
}

#[inline]
pub(crate) fn is_service_anchored_detector(detector_id: &str) -> bool {
    !is_generic_detector(detector_id)
        && !is_entropy_detector(detector_id)
        && !is_private_key_fallback(detector_id)
}

/// The "private-key block" family: detectors whose match SPAN is an enclosing
/// PEM/OpenSSH private-key body (`private-key`, `ssh-private-key`,
/// `github-app-private-key`). Resolution
/// (`resolution::suppress_matches_nested_in_private_key_blocks`) fully suppresses
/// any lower-specificity finding nested inside such a span.
///
/// Membership is DECLARED PER-DETECTOR via `DetectorSpec::private_key_block =
/// true` in each detector's own TOML (DET-0; was the centralized
/// `rules/detector-classification.toml` `private_key_block` id list). This reads
/// that single-owner flag. The `Result` is retained for caller compatibility
/// reading an embedded spec field is infallible, so it is always `Ok`.
#[inline]
pub(crate) fn is_private_key_block_detector(detector_id: &str) -> Result<bool, String> {
    Ok(keyhog_core::detector_spec_by_id(detector_id).is_some_and(|spec| spec.private_key_block))
}

#[cfg(test)]
mod detector_id_corpus_guard {
    //! Durable guard against detector-id drift.
    //!
    //! Every service-anchored constant in this file MUST resolve to a real id in
    //! the embedded `detectors/*.toml` corpus. A constant whose string drifts
    //! from the detector it names becomes a DEAD predicate: the scanner logic
    //! keyed on it silently matches nothing. This is exactly the latent bug the
    //! removed `stripe-api-key` const was (the real id is `stripe-secret-key`),
    //! and the same class the `github-fine-grained-pat`/`gitlab-token`/
    //! `slack-token` validator labels were. The synthetic entropy-family ids and
    //! the family prefixes are the ONLY non-corpus values, and they are
    //! enumerated + asserted absent from the corpus so a future typo cannot hide
    //! among them.
    //!
    //! Adding a new detector-id const requires listing it in `corpus_backed_consts`
    //! (real detector) or `synthetic_consts` (entropy family), otherwise it is
    //! not guarded, which is itself the maintenance contract these tests pin.

    use super::*;
    use crate::detector_catalog::bundled_detector_ids;

    /// Every const that MUST name a real embedded detector. cfg-gated to mirror
    /// each const's own feature gate so the list compiles under every feature set.
    fn corpus_backed_consts() -> Vec<(&'static str, &'static str)> {
        let v = vec![
            ("GENERIC_SECRET", GENERIC_SECRET),
            ("GENERIC_KEYWORD_SECRET", GENERIC_KEYWORD_SECRET),
            ("GENERIC_API_KEY", GENERIC_API_KEY),
            ("GENERIC_PASSWORD", GENERIC_PASSWORD),
            ("PRIVATE_KEY", PRIVATE_KEY),
            ("GITHUB_CLASSIC_PAT", GITHUB_CLASSIC_PAT),
            ("GITHUB_PAT_FINE_GRAINED", GITHUB_PAT_FINE_GRAINED),
            ("GITLAB_PERSONAL_ACCESS_TOKEN", GITLAB_PERSONAL_ACCESS_TOKEN),
            ("NPM_ACCESS_TOKEN", NPM_ACCESS_TOKEN),
            ("PYPI_API_TOKEN", PYPI_API_TOKEN),
            ("SLACK_BOT_TOKEN", SLACK_BOT_TOKEN),
            ("STRIPE_SECRET_KEY", STRIPE_SECRET_KEY),
        ];
        v
    }

    /// Synthetic finding ids assigned at runtime by the entropy phase. NOT
    /// backed by any `detectors/*.toml`. They are legitimate detector-id values
    /// on emitted findings, enumerated here so they are handled explicitly, and
    /// asserted ABSENT from the TOML corpus (a synthetic id colliding with a real
    /// detector would silently re-route scoring).
    fn synthetic_consts() -> Vec<(&'static str, &'static str)> {
        #[cfg(feature = "entropy")]
        let mut v = vec![("ENTROPY", ENTROPY)];
        #[cfg(not(feature = "entropy"))]
        let v = vec![("ENTROPY", ENTROPY)];
        #[cfg(feature = "entropy")]
        {
            v.push(("ENTROPY_GENERIC", ENTROPY_GENERIC));
            v.push(("ENTROPY_PASSWORD", ENTROPY_PASSWORD));
            v.push(("ENTROPY_TOKEN", ENTROPY_TOKEN));
            v.push(("ENTROPY_API_KEY", ENTROPY_API_KEY));
        }
        v
    }

    #[test]
    fn every_corpus_backed_const_names_a_real_embedded_detector() {
        let corpus =
            bundled_detector_ids().expect("embedded detector corpus must load fail-closed");
        let missing: Vec<String> = corpus_backed_consts()
            .into_iter()
            .filter(|(_, id)| !corpus.contains(*id))
            .map(|(name, id)| format!("{name} = {id:?}"))
            .collect();
        assert!(
            missing.is_empty(),
            "detector-id consts naming NO embedded detector (dead predicates): {missing:?}"
        );
    }

    #[test]
    fn stripe_secret_key_const_is_the_real_id_not_the_removed_phantom() {
        // The exact divergence this guard exists for: the const resolves to the
        // real `stripe-secret-key` detector, and the removed `stripe-api-key`
        // phantom names NO detector.
        let corpus = bundled_detector_ids().unwrap();
        assert_eq!(STRIPE_SECRET_KEY, "stripe-secret-key");
        assert!(corpus.contains("stripe-secret-key"));
        assert!(
            !corpus.contains("stripe-api-key"),
            "the removed phantom id must not exist"
        );
    }

    #[test]
    fn renamed_checksum_label_consts_resolve_to_real_detectors() {
        let corpus = bundled_detector_ids().unwrap();

        assert_eq!(GITHUB_PAT_FINE_GRAINED, "github-pat-fine-grained");
        assert!(corpus.contains(GITHUB_PAT_FINE_GRAINED));
        assert!(!corpus.contains("github-fine-grained-pat"));

        assert_eq!(GITLAB_PERSONAL_ACCESS_TOKEN, "gitlab-personal-access-token");
        assert!(corpus.contains(GITLAB_PERSONAL_ACCESS_TOKEN));
        assert!(!corpus.contains("gitlab-token"));

        assert_eq!(SLACK_BOT_TOKEN, "slack-bot-token");
        assert!(corpus.contains(SLACK_BOT_TOKEN));
        assert!(!corpus.contains("slack-token"));
    }

    #[test]
    fn synthetic_finding_ids_are_absent_from_the_toml_corpus() {
        let corpus = bundled_detector_ids().unwrap();
        for (name, id) in synthetic_consts() {
            assert!(
                !corpus.contains(id),
                "{name} = {id:?} is a synthetic finding id; it must not collide with a TOML detector"
            );
            assert!(
                id == ENTROPY || id.starts_with(ENTROPY_PREFIX),
                "{name} = {id:?} must be an entropy-family synthetic id"
            );
        }
    }

    #[test]
    fn family_prefixes_are_prefixes_not_detector_ids() {
        let corpus = bundled_detector_ids().unwrap();
        for (name, prefix) in [
            ("GENERIC_PREFIX", GENERIC_PREFIX),
            ("ENTROPY_PREFIX", ENTROPY_PREFIX),
        ] {
            assert!(
                prefix.ends_with('-'),
                "{name} = {prefix:?} must end with '-'"
            );
            assert!(
                !corpus.contains(prefix),
                "{name} is a family prefix, not a detector id"
            );
        }
        assert!(GENERIC_SECRET.starts_with(GENERIC_PREFIX));
        assert!(GENERIC_API_KEY.starts_with(GENERIC_PREFIX));
        assert!("entropy-generic".starts_with(ENTROPY_PREFIX));
    }

    #[test]
    fn family_predicates_classify_the_real_ids_correctly() {
        // Generic
        assert!(is_generic_detector(GENERIC_SECRET));
        assert!(is_generic_detector(GENERIC_PASSWORD));
        assert!(!is_generic_detector(GITHUB_CLASSIC_PAT));
        assert!(!is_generic_detector(STRIPE_SECRET_KEY));

        // Entropy (ENTROPY is always compiled; the "entropy-" family via prefix)
        assert!(is_entropy_detector(ENTROPY));
        assert!(is_entropy_detector("entropy-generic"));
        assert!(!is_entropy_detector(GENERIC_SECRET));
        assert!(!is_entropy_detector(GITHUB_CLASSIC_PAT));

        // Service-anchored: real services yes; generic/entropy/private-key no.
        assert!(is_service_anchored_detector(GITHUB_CLASSIC_PAT));
        assert!(is_service_anchored_detector(STRIPE_SECRET_KEY));
        assert!(is_service_anchored_detector(SLACK_BOT_TOKEN));
        assert!(is_service_anchored_detector(GITLAB_PERSONAL_ACCESS_TOKEN));
        assert!(!is_service_anchored_detector(GENERIC_SECRET));
        assert!(!is_service_anchored_detector(ENTROPY));
        assert!(!is_service_anchored_detector(PRIVATE_KEY));

        // Private-key fallback
        assert!(is_private_key_fallback(PRIVATE_KEY));
        assert!(!is_private_key_fallback(GITHUB_CLASSIC_PAT));

        // Structural password slot family: a service-anchored / generic detector
        // is never a member (membership itself is corpus-declared, pinned by
        // `structural_password_slot_family_is_toml_declared`).
        assert!(!is_structural_password_slot_detector(GITHUB_CLASSIC_PAT));
        assert!(!is_structural_password_slot_detector(GENERIC_SECRET));
    }

    /// The structural-password-slot family membership is DECLARED in the detector
    /// TOMLs (`structural_password_slot = true`), read back through
    /// `DetectorSpec::structural_password_slot`. This pins the EXACT member set
    /// against the embedded corpus, so adding/removing the flag on any detector
    /// or a typo'd id, fails loudly here. The four ids are the whole family; they
    /// are intentionally NOT scanner-code consts (no scanner path names them
    /// individually), so the list lives once, here, as the guard's expectation.
    #[test]
    fn structural_password_slot_family_is_toml_declared() {
        use std::collections::BTreeSet;
        let specs = keyhog_core::load_embedded_detectors_or_fail().expect("embedded corpus loads");
        let members: BTreeSet<&str> = specs
            .iter()
            .filter(|s| s.structural_password_slot)
            .map(|s| s.id.as_str())
            .collect();
        let expected: BTreeSet<&str> = [
            "bearer-authorization",
            "cli-password-flag",
            "sql-password",
            "url-credentials",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            members, expected,
            "structural_password_slot TOML declarations drifted from the known family"
        );
        // And the predicate agrees with the declaration for each member.
        for id in &expected {
            assert!(
                is_structural_password_slot_detector(id),
                "predicate must classify declared member `{id}` as a structural password slot"
            );
        }
    }

    /// The weak-anchor family membership is DECLARED in the detector TOMLs
    /// (`weak_anchor = true`), read back through `DetectorSpec::weak_anchor`
    /// (DET-0; migrated out of the `rules/detector-classification.toml`
    /// `weak_anchor` list). Pins the EXACT member set against the embedded corpus
    /// so adding/removing the flag on any detector, or a typo'd id, fails
    /// loudly here, preserving the "see the whole family at a glance" view the
    /// centralized list gave.
    #[test]
    fn weak_anchor_family_is_toml_declared() {
        use std::collections::BTreeSet;
        let specs = keyhog_core::load_embedded_detectors_or_fail().expect("embedded corpus loads");
        let members: BTreeSet<&str> = specs
            .iter()
            .filter(|s| s.weak_anchor)
            .map(|s| s.id.as_str())
            .collect();
        let expected: BTreeSet<&str> = [
            "activecampaign-api-key",
            "adobe-api-key",
            "aerisweather-api-credentials",
            "alchemy-api-key",
            "azure-openai-api-key",
            "bamboohr-api-key",
            "base-api-credentials",
            "calendly-api-key",
            "carbon-black-api-key",
            "census-api-key",
            "chef-automate-token",
            "crowdin-api-token",
            "etherscan-api-key",
            "flickr-api-key",
            "foundation-api-key",
            "getresponse-api-key",
            "github-oauth-secret",
            "rudder-api-token",
            "sonarcloud-token",
            "spotify-client-credentials",
            "workato-api-credentials",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            members, expected,
            "weak_anchor TOML declarations drifted from the known family"
        );
    }

    /// The private-key-block family membership is DECLARED in the detector TOMLs
    /// (`private_key_block = true`), read back through
    /// `DetectorSpec::private_key_block` (DET-0; migrated out of the
    /// `rules/detector-classification.toml` `private_key_block` list). Pins the
    /// EXACT member set and confirms the predicate agrees.
    #[test]
    fn private_key_block_family_is_toml_declared() {
        use std::collections::BTreeSet;
        let specs = keyhog_core::load_embedded_detectors_or_fail().expect("embedded corpus loads");
        let members: BTreeSet<&str> = specs
            .iter()
            .filter(|s| s.private_key_block)
            .map(|s| s.id.as_str())
            .collect();
        let expected: BTreeSet<&str> = ["github-app-private-key", "private-key", "ssh-private-key"]
            .into_iter()
            .collect();
        assert_eq!(
            members, expected,
            "private_key_block TOML declarations drifted from the known family"
        );
        for id in &expected {
            assert!(
                is_private_key_block_detector(id).expect("infallible spec read"),
                "predicate must classify declared member `{id}` as a private-key block"
            );
        }
    }
}
