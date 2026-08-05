use super::{
    encoded_text_secret_anchors, is_strong_keyword_anchored_encoded_text_secret,
    parse_encoded_text_secret_anchors,
};

// base64 of "ThisIsAPlaintextSecretValueForTests" (decodes to printable ASCII).
const PRINTABLE_B64: &str = "VGhpc0lzQVBsYWludGV4dFNlY3JldFZhbHVlRm9yVGVzdHM=";

#[test]
fn encoded_text_secret_anchor_vocab_is_the_expected_list() {
    assert_eq!(
        encoded_text_secret_anchors(),
        &[
            "password",
            "passwd",
            "pwd",
            "passphrase",
            "token",
            "secret",
            "credential",
        ]
    );
}

// ── is_strong_keyword_anchored_encoded_text_secret ─────────────────────

#[test]
fn list_only_anchor_lifts_encoded_printable_text() {
    // `credential` earns the lift ONLY via the migrated Tier-B anchor list (it
    // has no `key`/`secret`/`token` suffix), so this exercises the list path.
    assert!(is_strong_keyword_anchored_encoded_text_secret(
        "credential",
        PRINTABLE_B64
    ));
    // `password` (a list anchor AND a suffix) also lifts.
    assert!(is_strong_keyword_anchored_encoded_text_secret(
        "passphrase",
        PRINTABLE_B64
    ));
}

#[test]
fn non_anchor_keyword_does_not_lift_encoded_text() {
    // Adversarial twin: same decodable value, but the key is not a credential
    // anchor (no lift).
    assert!(!is_strong_keyword_anchored_encoded_text_secret(
        "hostname",
        PRINTABLE_B64
    ));
}

#[test]
fn dotted_or_short_values_short_circuit_before_decode() {
    // A `.` in the value (JWT-like segmenting) and a sub-24-char value both bail
    // before the decode check, regardless of anchor.
    assert!(!is_strong_keyword_anchored_encoded_text_secret(
        "password",
        "aGVsbG8.d29ybGQ="
    ));
    assert!(!is_strong_keyword_anchored_encoded_text_secret(
        "password", "c2hvcnQ="
    ));
}

#[test]
fn encoded_text_secret_anchor_parser_round_trips_and_validates() {
    let out = parse_encoded_text_secret_anchors(
        "[encoded_text_secret_anchors]\nanchors = [\"token\", \"secret\"]\n",
    )
    .unwrap();
    assert_eq!(out, vec!["token", "secret"]);
    assert!(parse_encoded_text_secret_anchors(
        "[encoded_text_secret_anchors]\nanchors = [\"Token\"]\n"
    )
    .unwrap_err()
    .contains("lowercase"));
}
