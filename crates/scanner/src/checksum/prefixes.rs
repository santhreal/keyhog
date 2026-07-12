//! Single owner for every checksum-family credential prefix.
//!
//! A checksum prefix is TWO things at once: (1) a detection signal — it appears
//! verbatim in the family's `detectors/<id>.toml` pattern, which is what
//! surfaces the credential; and (2) the self-selection key each checksum
//! validator strips before recomputing the family's embedded CRC. Historically
//! each validator hard-coded its own bare `"ghp_"` / `"glpat-"` / … literal, so
//! the same prefix lived in two places (the validator AND the detector) with
//! nothing binding them — a detector-pattern edit could silently diverge from
//! the validator that gates it, and two validators could disagree on a shared
//! prefix. This module is the ONE owner of those literals.
//!
//! Because each family's checksum ALGORITHM is genuinely code (bespoke CRC width,
//! body layout, "CRC-over-what"), the validator cannot be fully data-driven — but
//! the PREFIX can be single-sourced here. [`all_checksum_prefixes`] gathers the
//! full set so the `checksum_prefixes_are_backed_by_their_detector` guard (tests)
//! can bind each to its authoritative `detectors/<id>.toml` and make the detector
//! TOML the source of truth: the validator prefix can never drift from the
//! pattern that produced the credential. (The prefix→detector binding itself
//! lives in that test, because detector-id strings belong only to
//! `detector_ids.rs` in src, per the `detector_id_owner` gate.)

/// GitHub classic personal access token: `ghp_` + 30 entropy + 6 CRC32-base62.
pub(crate) const GITHUB_CLASSIC_PAT: &str = "ghp_";
/// GitHub OAuth-family tokens that share the IDENTICAL classic body — `_` + 30
/// entropy + 6 CRC32-base62, with the CRC taken over the 30-char entropy ONLY,
/// so it is prefix-independent: `gho_` OAuth access, `ghu_` user-to-server,
/// `ghs_` server-to-server / app-installation, `ghr_` refresh. Each is surfaced
/// by its own detector but validated by the SAME classic validator, so they live
/// as one array (mirrors [`STRIPE_KEY_PREFIXES`]) rather than four literals that
/// could drift. Without this, fabricated `gho_`/`ghu_`/`ghs_`/`ghr_` tokens
/// bypassed the checksum gate entirely (a precision hole).
pub(crate) const GITHUB_OAUTH_FAMILY_PREFIXES: [&str; 4] = ["gho_", "ghu_", "ghs_", "ghr_"];
/// GitHub fine-grained personal access token: `github_pat_{22}_{59}`.
pub(crate) const GITHUB_PAT_FINE_GRAINED: &str = "github_pat_";
/// GitLab classic / routable personal access token.
pub(crate) const GITLAB_PAT: &str = "glpat-";
/// GitLab CI build token (routable, base64 CRC trailer).
pub(crate) const GITLAB_CI_BUILD_TOKEN: &str = "glcbt-";
/// GitLab runner authentication token (routable, base64 CRC trailer).
pub(crate) const GITLAB_RUNNER_TOKEN: &str = "glrt-";
/// npm access token: `npm_` + 30 entropy + 6 CRC32-base62 (GitHub-shaped).
pub(crate) const NPM_ACCESS_TOKEN: &str = "npm_";
/// PyPI API token: `pypi-` + base64 macaroon.
pub(crate) const PYPI_API_TOKEN: &str = "pypi-";
/// Slack bot token: `xoxb-…`.
pub(crate) const SLACK_BOT_TOKEN: &str = "xoxb-";
/// Slack user token: `xoxp-…`.
pub(crate) const SLACK_USER_TOKEN: &str = "xoxp-";

/// Stripe live/test secret, publishable, and restricted key prefixes. All six
/// share one checksum validator; kept as a single array so the validator and the
/// detector-binding guard read the identical set (never two drifting copies).
pub(crate) const STRIPE_KEY_PREFIXES: [&str; 6] = [
    "sk_live_", "sk_test_", "pk_live_", "pk_test_", "rk_live_", "rk_test_",
];

/// Every single-owner checksum prefix, in one slice, so the
/// `checksum_prefixes_are_backed_by_their_detector` guard (an external test) can
/// bind each to its authoritative detector TOML and prove none drifted from the
/// pattern that surfaces the credential. The detector-id binding itself lives in
/// the TEST (detector identity strings belong ONLY to `detector_ids.rs` in src,
/// per the `detector_id_owner` gate); this src slice carries only the prefix
/// literals the validators actually strip.
pub(crate) fn all_checksum_prefixes() -> Vec<&'static str> {
    let mut v = vec![
        GITHUB_CLASSIC_PAT,
        GITHUB_PAT_FINE_GRAINED,
        GITLAB_PAT,
        GITLAB_CI_BUILD_TOKEN,
        GITLAB_RUNNER_TOKEN,
        NPM_ACCESS_TOKEN,
        PYPI_API_TOKEN,
        SLACK_BOT_TOKEN,
        SLACK_USER_TOKEN,
    ];
    v.extend_from_slice(&GITHUB_OAUTH_FAMILY_PREFIXES);
    v.extend_from_slice(&STRIPE_KEY_PREFIXES);
    v
}
