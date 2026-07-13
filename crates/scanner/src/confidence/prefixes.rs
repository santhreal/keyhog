/// Canonical list of well-known service-credential prefixes.
///
/// This is the single source of truth for the prefix set. Two consumers:
///
/// 1. [`known_prefix_confidence_floor`] (this module) lifts any credential
///    starting with one of these to a 0.8 confidence floor.
/// 2. `context::inference::{is_sequential_placeholder, is_hex_sequential_placeholder}`
///    strip these prefixes before sequence-detection so a `ghp_aaaaaaaaaa`
///    placeholder still triggers the all-same-char suppression on the
///    BODY, not on the prefix.
///
/// Pre-2026-05-24 state: this list was duplicated three times across
/// `confidence/prefixes.rs` + `context/inference.rs` × 2, and the copies
/// had already drifted (KNOWN_PREFIXES missed `glcbt-`, `glrt-`,
/// `xoxs-`, `vercel_`, `sbp_`, `0x`, `rk_test_`, `sk-`; the inference
/// copies missed `PRIVATE KEY`, `-----BEGIN`, `TESTKEY_`). Consolidated
/// here (kimi-dedup audit rows #12-13).
#[derive(serde::Deserialize)]
struct Wrapper {
    prefixes: Vec<String>,
}

// `pub` (not `pub(crate)`) so `crate::testing` can `pub use` it out to the
// external test crates (confidence_known_prefix_contract, decode_caesar parity)
// that assert against the list; those re-exports need a `pub` source.
pub static KNOWN_PREFIXES: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    match parse_known_prefixes(include_str!("../../../../rules/known-prefixes.toml")) {
        Ok(prefixes) => prefixes,
        Err(error) => panic!(
            "rules/known-prefixes.toml is invalid: {error}. \
                 Fix the bundled Tier-B metadata file list."
        ),
    }
});

/// Parse the bundled Tier-B known-prefix list. Returns an error rather than
/// panicking so the `KNOWN_PREFIXES` owner above is the single fail-closed site
/// (the `no_unwrap_expect` gate bans `expect` in production source).
fn parse_known_prefixes(raw: &str) -> Result<Vec<String>, String> {
    toml::from_str::<Wrapper>(raw)
        .map(|wrapper| wrapper.prefixes)
        .map_err(|error| error.to_string())
}

/// Minimum confidence a credential carrying a well-known literal prefix is lifted
/// to. Named (not an inline `0.8`) so this floor has a single owner alongside the
/// sibling confidence floors [`super::policy::NAMED_DETECTOR_ANCHOR_FLOOR`] and
/// `crate::checksum::CHECKSUM_VALID_FLOOR`, and so the many doc references to "the
/// 0.8 floor" resolve to one constant. Locked by the `confidence_prefix_floor_*`
/// unit tests.
pub(crate) const KNOWN_PREFIX_CONFIDENCE_FLOOR: f64 = 0.8;

/// Return a minimum confidence floor for credentials with well-known literal prefixes.
///
/// Credentials carrying a placeholder word (`EXAMPLE`, `PLACEHOLDER`, `DUMMY`,
/// `FAKE`, `SAMPLE`, `CHANGEME`) do NOT get the floor. A `ghp_EXAMPLE_…`
/// or `sk_live_PLACEHOLDER_…` is a doc sample, not a credential - the
/// placeholder penalty in `apply_post_ml_penalties` had already slammed
/// these to ~0.05, but the unconditional `final_score.max(0.8)` in
/// `scan_postprocess` then lifted them straight back. Mirror corpus
/// 2026-05-29: 154 docs-example FPs across the GitHub PAT, AWS access
/// key, Slack bot token, and Stripe secret key prefix families all
/// surfaced through this exact path; this single guard kills them.
///
/// The same lift-back defeated the degenerate-repeat penalty: a known-prefix
/// placeholder like `AKIAXXXXXXXXXXXXXXXX` (16-char `X` run) was crushed to
/// ~0.08 by `apply_post_ml_penalties` and then floored back to 0.8 here. The
/// `is_degenerate_repeat` skip (CredData dogfood 2026-06-03) closes that hole
/// the same way - a 10+ identical-char run is never a real key body.
#[must_use]
pub(crate) fn known_prefix_confidence_floor(credential: &str) -> Option<f64> {
    if super::penalties::contains_placeholder_word(credential)
        || crate::decode_structure::evidence(credential).decoded_contains_placeholder()
        || super::penalties::is_degenerate_repeat(credential)
    {
        return None;
    }
    if let Some(body) = known_prefix_body(credential) {
        if crate::placeholder_words::bytes_contain_placeholder_word(body.as_bytes()) {
            return None;
        }
        return Some(KNOWN_PREFIX_CONFIDENCE_FLOOR);
    }
    None
}

/// Strip the MOST-SPECIFIC known prefix from `credential` and return the body,
/// or `None` if no known prefix matches.
///
/// When several known prefixes match (e.g. both `sk-` and `sk-proj-` match
/// `sk-proj-…`), the LONGEST wins (equivalently, the shortest resulting body).
/// This is deliberately independent of the order of `KNOWN_PREFIXES`: the correct
/// body must not depend on which shadowing prefix happens to be listed first, so a
/// future reorder or a newly-added shorter prefix cannot silently change the body
/// that feeds sequence-detection and the confidence floor.
pub(crate) fn known_prefix_body(credential: &str) -> Option<&str> {
    (&*KNOWN_PREFIXES)
        .iter()
        .filter_map(|prefix| credential.strip_prefix(prefix.as_str()))
        .min_by_key(|body| body.len())
}
