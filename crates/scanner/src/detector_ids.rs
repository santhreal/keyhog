//! Canonical detector-id strings and family predicates used by scanner logic.

pub(crate) const GENERIC_PREFIX: &str = "generic-";
pub(crate) const ENTROPY_PREFIX: &str = "entropy-";

pub(crate) const REASSEMBLED_SUFFIX: &str = keyhog_core::REASSEMBLED_DETECTOR_SUFFIX;

#[inline]
pub(crate) fn policy_detector_id(detector_id: &str) -> &str {
    detector_id
        .strip_suffix(REASSEMBLED_SUFFIX)
        .unwrap_or(detector_id) // LAW10: canonical default; an ID without the synthetic suffix retains its exact identity
}
pub(crate) const GENERIC_SECRET: &str = "generic-secret";
pub(crate) const GENERIC_KEYWORD_SECRET: &str = "generic-keyword-secret";
pub(crate) const GENERIC_API_KEY: &str = "generic-api-key";
#[cfg(test)]
pub(crate) const GENERIC_PASSWORD: &str = "generic-password";

pub(crate) const ENTROPY: &str = "entropy";

pub(crate) const PRIVATE_KEY: &str = "private-key";

pub(crate) const AWS_ACCESS_KEY: &str = "aws-access-key";
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
    keyhog_core::detector_spec_by_id(detector_id).map_or_else(
        || {
            !is_generic_detector(detector_id)
                && !is_entropy_detector(detector_id)
                && !is_private_key_fallback(detector_id)
        },
        |detector| {
            detector.kind != keyhog_core::DetectorKind::Phase2Generic && !detector.private_key_block
        },
    )
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
/// that single-owner flag.
#[inline]
pub(crate) fn is_private_key_block_detector(detector_id: &str) -> bool {
    keyhog_core::detector_spec_by_id(detector_id).is_some_and(|spec| spec.private_key_block)
}

// The corpus guard lives in `tests/unit/detector_id_corpus_guard.rs`. It is
// 294 lines against 120 of actual constants, and reading this file should not
// mean scrolling past it. The `#[path]` include keeps it compiled with the
// crate so it still reaches the private constants it exists to check.
#[cfg(test)]
#[path = "../tests/unit/detector_id_corpus_guard.rs"]
mod detector_id_corpus_guard;
