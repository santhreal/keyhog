//! Regression (Law 10 / recall): the top-level decode-density gate
//! `decode::has_decodable_payload` must route OCTAL-escaped chunks into
//! decode-through. Octal digits between backslashes form runs of only 3, far
//! below `MIN_DECODABLE_RUN` (24), so before this fix an octal-ONLY chunk
//! returned false, the whole decode pipeline was skipped, and the registered
//! octal decoder never ran on it (a secret hidden as `\NNN\NNN…` was silently
//! missed). This pins that `\NNN` now counts toward the gate at the same
//! `MIN_BACKSLASH_ESCAPES` (2) threshold as its `\u`/`\x` siblings, WITHOUT
//! regressing the existing base64-run / percent-escape / plain-text verdicts.
//!
//! Uses only the boolean `has_decodable_payload_for_test` facade (never a
//! decoder name), so it is immune to the in-flight decoder-registry rename
//! churn in the decode subsystem.

#![cfg(feature = "decode")]

use keyhog_scanner::testing::has_decodable_payload_for_test as gate;

#[test]
fn octal_only_chunk_now_routes_into_decode_through() {
    // Two `\NNN` C-style octal escapes = MIN_BACKSLASH_ESCAPES; nothing else in
    // the chunk reaches any other trigger (each digit run is length 3 << 24).
    // Before the fix this returned FALSE (octal was fully invisible to the gate).
    assert!(
        gate(b"\\101\\102"),
        "two \\NNN octal escapes must trip the decode gate"
    );
    assert!(
        gate(b"prefix \\101\\102\\103\\104 suffix"),
        "octal escapes embedded in surrounding text must still trip the gate"
    );
}

#[test]
fn sub_threshold_and_malformed_octal_do_not_trip_the_gate() {
    // A SINGLE octal escape is below MIN_BACKSLASH_ESCAPES (2), parity with how
    // a lone `\u`/`\x` also does not trip the gate (one escape decodes to a
    // single byte, never a secret).
    assert!(!gate(b"\\101"), "one octal escape is below threshold");
    // `\NN` (two digits) is not a 3-digit `\NNN`, so the octal arm does not
    // match; the loose digits form no 24-long run either.
    assert!(
        !gate(b"\\10\\10"),
        "two-digit \\NN is not a \\NNN octal escape"
    );
    // `\8`/`\9` are not octal digits at all.
    assert!(
        !gate(b"\\888\\999"),
        "non-octal digits after a backslash do not match the octal arm"
    );
}

#[test]
fn existing_gate_verdicts_are_unchanged() {
    // Base64/hex run at/above MIN_DECODABLE_RUN (24) still trips.
    assert!(
        gate(b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="),
        "a >=24-char base64 run still trips the gate"
    );
    // Four `%XX` percent escapes (MIN_PERCENT_ESCAPES) still trip.
    assert!(gate(b"%41%42%43%44"), "four percent escapes still trip");
    // Two `\uXXXX` escapes still trip.
    assert!(gate(b"\\u0041\\u0042"), "two \\u escapes still trip");
    // Plain prose with no encoded shape must stay OUT of decode-through.
    assert!(
        !gate(b"the quick brown fox jumps over the lazy dog"),
        "plain text must not trip the decode gate"
    );
}
