//! Entropy-scanner detector-policy gates + fail-closed contract
//! (`entropy/scanner.rs`), reached via the `keyhog_scanner::testing` facade.
//! Migrated from an inline `#[cfg(test)]` block to satisfy
//! `entropy_scanner_no_inline_tests`.

use keyhog_scanner::entropy::{HIGH_ENTROPY_THRESHOLD, LOW_ENTROPY_THRESHOLD};
use keyhog_scanner::testing::{
    credential_context_min_len, credential_context_too_short_rejection_for_test as too_short,
    keyword_context_threshold_for_test, trigger_desynced_line_offsets_for_test,
};

#[test]
#[should_panic(expected = "must cover every split line")]
fn desynced_line_offsets_fail_closed() {
    // A caller that hands in a `line_offsets` slice shorter than `lines` used to
    // index out of bounds deep in the scan when the `debug_assert` was compiled
    // out in release. The promoted `assert!` fails closed at the boundary.
    trigger_desynced_line_offsets_for_test();
}

#[test]
fn keyword_context_threshold_follows_shared_override() {
    // The keyword-anchored floor resolves from its detector policy: the default
    // high threshold drops to the low recall floor, a stricter request is
    // honored verbatim, a below-low request loosens via `min`, and a non-finite
    // request pins to the detector's low floor.
    let kw = vec!["token".to_string()];
    let line = "token = abc";
    assert_eq!(
        keyword_context_threshold_for_test(line, 20, HIGH_ENTROPY_THRESHOLD, &kw),
        LOW_ENTROPY_THRESHOLD
    );
    assert_eq!(keyword_context_threshold_for_test(line, 20, 6.0, &kw), 6.0);
    assert_eq!(keyword_context_threshold_for_test(line, 20, 2.0, &kw), 2.0);
    assert_eq!(
        keyword_context_threshold_for_test(line, 20, f64::NAN, &kw),
        LOW_ENTROPY_THRESHOLD
    );
}

#[test]
fn credential_context_too_short_gate_uses_detector_owned_min_len() {
    // The credential-context too-short suppression gate fires at exactly the
    // embedded API-key detector policy (8): a 7-char value is
    // `CredentialContextTooShort`, an 8-char value clears it. The facade sets
    // threshold to 0 so only the length gate, not the entropy floor, decides,
    // proving extraction and suppression consume the same compiled owner.
    let min_len = credential_context_min_len();
    let short = "a1B2c3D"; // 7 chars: below the 8-char floor
    let ok = "a1B2c3D4"; // 8 chars: at the floor
    assert_eq!(short.len(), min_len - 1);
    assert_eq!(ok.len(), min_len);
    assert!(
        too_short(short, "api_key", min_len),
        "a 7-char credential-context value must be CredentialContextTooShort"
    );
    assert!(
        !too_short(ok, "api_key", min_len),
        "an 8-char credential-context value must clear the too-short gate"
    );
}
