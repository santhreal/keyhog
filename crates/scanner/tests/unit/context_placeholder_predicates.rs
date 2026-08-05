use super::{is_known_example_credential, is_monotonic_sequence_placeholder};

#[test]
fn monotonic_runs_are_placeholders() {
    // Fully-sequential ascending/descending runs of length >= 8, the
    // generalizable entropy-token FP class (`12345678`). No hardcoded literals.
    for value in [
        "12345678",  // ascending digits
        "23456789",  // ascending digits, different start
        "abcdefgh",  // ascending letters
        "87654321",  // descending digits
        "hgfedcba",  // descending letters
        "012345678", // 9-long ascending
    ] {
        assert!(
            is_monotonic_sequence_placeholder(value),
            "expected {value:?} to be a monotonic-run placeholder"
        );
    }
}

#[test]
fn real_secrets_and_short_values_are_not_monotonic() {
    for value in [
        "aK9f2Lp7Qz",  // random-looking real secret
        "1a2b3c4d5e",  // alternating, not a consecutive run
        "1234567",     // 7 chars: below the >= 8 length gate
        "s3cr3tV4lue", // real-ish mixed
        "48293017",    // 8 random digits, not sequential
    ] {
        assert!(
            !is_monotonic_sequence_placeholder(value),
            "did NOT expect {value:?} to be flagged monotonic"
        );
    }
}

/// SCOPING PROOF: the monotonic gate is ENTROPY-only. The UNIVERSAL
/// is_known_example_credential (used by strong vendor detectors) must NOT
/// suppress a monotonic value, so a vendor contract fixture whose filler token
/// is the alphabet (`sdk_key="abcdefghijklmnopqrstuvwx…"`) still surfaces
/// while the entropy path (which calls is_monotonic_sequence_placeholder) does
/// suppress it. This is the fix for the contract regression the universal
/// wiring caused.
#[test]
fn monotonic_gate_scoped_out_of_universal_example_credential() {
    assert!(is_monotonic_sequence_placeholder(
        "abcdefghijklmnopqrstuvwx"
    ));
    assert!(
        !is_known_example_credential("abcdefghijklmnopqrstuvwx"),
        "vendor-path example check must NOT suppress a sequential filler token"
    );
    // sanity: the universal check still catches the shapes it always did.
    assert!(is_known_example_credential("00000000"));
}
