use super::{
    is_empty_input_hash, is_hex_sequential_placeholder, is_known_example_credential,
    is_sequential_placeholder, sequential_step_threshold,
};

// ---- is_empty_input_hash: the four canonical empty-input digests --------
#[test]
fn empty_input_hashes_of_every_length_are_recognized() {
    // MD5(""), SHA1(""), SHA256(""), SHA512("") (integrity fields, never secrets).
    assert!(is_empty_input_hash("d41d8cd98f00b204e9800998ecf8427e")); // MD5
    assert!(is_empty_input_hash(
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    )); // SHA1
    assert!(is_empty_input_hash(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )); // SHA256
        // Case-insensitive: an upper-cased digest is the same empty-input hash.
    assert!(is_empty_input_hash("D41D8CD98F00B204E9800998ECF8427E"));
}

#[test]
fn near_miss_digests_are_not_empty_input_hashes() {
    // One flipped nibble (…427e -> …427f) is a DIFFERENT hash and must survive.
    assert!(!is_empty_input_hash("d41d8cd98f00b204e9800998ecf8427f"));
    // Correct value but wrong length (truncated) must not match by prefix.
    assert!(!is_empty_input_hash("d41d8cd98f00b204e9800998ecf842")); // 30 chars
                                                                     // A digest embedded in a longer string is not the bare hash.
    assert!(!is_empty_input_hash(
        "prefix_d41d8cd98f00b204e9800998ecf8427e"
    ));
    assert!(!is_empty_input_hash("")); // empty input itself is not a digest
}

// ---- is_hex_sequential_placeholder: monotonic / wrapping hex runs -------
#[test]
fn monotonic_hex_runs_are_placeholders() {
    assert!(is_hex_sequential_placeholder("0123456789abcdef")); // ascending, 0->f
    assert!(is_hex_sequential_placeholder("fedcba9876543210")); // descending, f->0
                                                                // The 0..f cycle wraps (f->0 counts as a forward step) across 32 chars.
    assert!(is_hex_sequential_placeholder(
        "0123456789abcdef0123456789abcdef"
    ));
    // Upper-case hex sequences fold to the same run.
    assert!(is_hex_sequential_placeholder("0123456789ABCDEF"));
}

#[test]
fn random_and_nonhex_bodies_are_not_hex_sequential() {
    assert!(!is_hex_sequential_placeholder("deadbeefcafebabe")); // hex, but not a run
    assert!(!is_hex_sequential_placeholder("a3f8b2c9d1e07546")); // random hex
    assert!(!is_hex_sequential_placeholder("0123456789abcde")); // 15 chars: below the 16 gate
                                                                // Non-hex characters disqualify the whole body (letters past 'f').
    assert!(!is_hex_sequential_placeholder("ghijklmnopqrstuv"));
}

// ---- is_sequential_placeholder: all-same and repeated-pair only --------
#[test]
fn all_same_and_repeated_pair_bodies_are_placeholders() {
    assert!(is_sequential_placeholder("aaaaaaaa")); // all identical
    assert!(is_sequential_placeholder("00000000"));
    assert!(is_sequential_placeholder("abababab")); // period-2 repeated pair
    assert!(is_sequential_placeholder("=-=-=-=-")); // repeated pair, non-alnum
}

#[test]
fn higher_period_and_short_bodies_are_not_sequential_placeholders() {
    // Period-3 repetition is deliberately NOT caught (only all-same + period-2).
    assert!(!is_sequential_placeholder("abcabcabc"));
    assert!(!is_sequential_placeholder("aaaaaaa")); // 7 chars: below the >= 8 gate
    assert!(!is_sequential_placeholder("aK9f2Lp7Qz")); // real-looking secret
}

// ---- sequential_step_threshold: the single-owned 90% ratio -------------
#[test]
fn sequential_step_threshold_is_exactly_nine_tenths_floored() {
    assert_eq!(sequential_step_threshold(0), 0);
    assert_eq!(sequential_step_threshold(7), 6); // 63/10 -> 6
    assert_eq!(sequential_step_threshold(10), 9);
    assert_eq!(sequential_step_threshold(20), 18);
    assert_eq!(sequential_step_threshold(100), 90);
}

// ---- is_known_example_credential: the composed universal gate ----------
#[test]
fn universal_example_gate_covers_every_arm() {
    assert!(is_known_example_credential("MY_SECRET_KEY_EXAMPLE")); // EXAMPLE suffix
    assert!(is_known_example_credential("service-api-EXAMPLEKEY")); // EXAMPLEKEY suffix
    assert!(is_known_example_credential("xxxxxxxxxxxxxxxx")); // x-masking (>= 16, > 3/4)
    assert!(is_known_example_credential(
        "d41d8cd98f00b204e9800998ecf8427e"
    )); // empty-hash arm
    assert!(is_known_example_credential("0123456789abcdef")); // hex-sequential arm
    assert!(is_known_example_credential("55555555")); // all-same arm
}

#[test]
fn real_secrets_survive_the_universal_example_gate() {
    // A random high-entropy token trips none of the structural arms.
    assert!(!is_known_example_credential("aK9f2Lp7Qz3mN8bVxT1wR6yU"));
    assert!(!is_known_example_credential(
        "deadbeefcafebabe0feed1234567890a"
    ));
    // Fewer than 16 chars with a couple of x's is not x-masking filler.
    assert!(!is_known_example_credential("xoxb1a2b3c"));
}
