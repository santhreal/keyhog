//! `keyhog explain` migration for retired hot-id aliases.
//!
//! Moved out of `src/subcommands/explain.rs` per the `no_inline_tests_in_src`
//! gate (the inline module also carried a `.expect(...)`, which tripped
//! `subcommands_explain_no_unwrap_expect`). The tested helpers
//! `canonical_for_hot_id` / `explain_not_found` are reached through the hidden
//! testing namespace so the helper functions do not become public CLI API.

use keyhog::testing::{CliTestApi as _, API};
use keyhog_core::DetectorSpec;
use std::path::Path;

fn embedded() -> Vec<DetectorSpec> {
    // The default `detectors` sentinel: `validate_detector_path_for_scan`
    // exempts it from the "explicit path must exist" check, so when no
    // `detectors/` dir is present in the test cwd it falls back to the embedded
    // corpus (the production default). An explicit non-existent path now errors
    // by design, so we must use the sentinel, not a bogus directory name.
    API.load_detectors_or_embedded(Path::new("detectors"))
        .expect("embedded detector corpus must load")
}

/// Every retired alias retained for historical reports resolves to an existing
/// canonical detector. Current scans emit only canonical TOML ids.
#[test]
fn hot_ids_resolve_to_real_detectors() {
    let detectors = embedded();
    let ids: std::collections::HashSet<String> =
        detectors.iter().map(|d| d.id.to_lowercase()).collect();

    // The hot patterns with a canonical registry equivalent.
    for hot in [
        "hot-github_pat",
        "hot-openai_key",
        "hot-aws_key",
        "hot-aws_session_key",
        "hot-sendgrid_key",
        "hot-slack_bot_token",
        "hot-slack_user_token",
        "hot-square_secret",
    ] {
        let canon = API
            .canonical_for_hot_id(hot)
            .unwrap_or_else(|| panic!("{hot} must map to a canonical detector"));
        assert!(
            ids.contains(canon),
            "{hot} maps to '{canon}', which is not in the embedded registry \
             (detector renamed? update canonical_for_hot_id)"
        );
    }
    assert_eq!(
        API.canonical_for_hot_id("HOT-GITHUB_PAT"),
        Some("github-classic-pat"),
        "hot-id aliases should be ASCII-case-insensitive without lowercasing the request"
    );
    assert_eq!(
        API.canonical_for_hot_id("hot-square_secret"),
        Some("square-access-token"),
        "Square hot ids must resolve to Square payments, not Squarespace"
    );
}
