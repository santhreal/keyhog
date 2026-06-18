//! `keyhog explain` hot-id resolution.
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

/// Coherence: every `hot-*` id keyhog can print in a finding must resolve
/// through `explain` to a registry detector that ACTUALLY EXISTS - the exact
/// gap a user hits when they copy `hot-github_pat` from scan output into
/// `keyhog explain`. A rename of any canonical detector fails this.
#[test]
fn hot_ids_resolve_to_real_detectors() {
    let detectors = embedded();
    let ids: std::collections::HashSet<String> =
        detectors.iter().map(|d| d.id.to_lowercase()).collect();

    // The 7 hot patterns with a canonical registry equivalent.
    for hot in [
        "hot-github_pat",
        "hot-openai_key",
        "hot-aws_key",
        "hot-aws_session_key",
        "hot-sendgrid_key",
        "hot-slack_bot_token",
        "hot-slack_user_token",
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

    // Square (`sq0csp-`) has no standalone registry detector yet: it must
    // map to None and the not-found path must say so without pretending it
    // is a typo or mis-resolving to `squarespace-api-key`.
    assert!(API.canonical_for_hot_id("hot-square_secret").is_none());
    let err = API.explain_not_found(&detectors, "hot-square_secret", "hot-square_secret");
    let msg = format!("{err}");
    assert!(
        msg.contains("fast-path"),
        "hot-square_secret should explain it is a fast-path pattern, got: {msg}"
    );
}
