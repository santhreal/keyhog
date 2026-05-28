//! Migrated from src/decode/reverse.rs

use keyhog_scanner::testing::{looks_reversible, reverse_str};

#[test]
fn round_trip_reverse() {
    assert_eq!(
        reverse_str(concat!("AK", "IAIOSFODNN7EXAMPLE")),
        "ELPMAXE7NNDOFSOIAIKA"
    );
    assert_eq!(
        reverse_str(&reverse_str(concat!("AK", "IAIOSFODNN7EXAMPLE"))),
        concat!("AK", "IAIOSFODNN7EXAMPLE")
    );
}

#[test]
fn looks_reversible_accepts_aws_key_reversal() {
    // The original adversarial fixture: reversed AWS access-key-id.
    // Reversing it produces a string starting with AKIA, which is
    // a KNOWN_PREFIXES entry - the gate fires.
    assert!(looks_reversible("ELPMAXE7NNDOFSOIAIKA"));
}

#[test]
fn looks_reversible_rejects_short_or_punctuated() {
    assert!(!looks_reversible("hello"));
    assert!(!looks_reversible("a-b-c-d-e-f-g-h-i-j"));
}

#[test]
fn looks_reversible_rejects_alphabetic_prose() {
    // Long alnum run but reversing it (`ZYX...CBA`) doesn't contain
    // any known credential prefix. Used to slip through as a decoy.
    assert!(!looks_reversible("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
    assert!(!looks_reversible("0123456789abcdefghijklmnopqr"));
}
