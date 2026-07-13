//! Example / placeholder credential detection.
//!
//! These heuristics are a VALUE-SHAPE responsibility, orthogonal to the
//! line-context inference in [`super::inference`]: they look only at the
//! credential string itself (its bytes, prefix, hex/sequential structure) and
//! decide whether it is a documentation placeholder, masking filler, or an
//! empty-input hash that is never a real secret. No hardcoded credential lists -
//! every suppression is based on a structural property that generalizes to all
//! credentials of that shape. Kept separate so the placeholder heuristics can be
//! tested and tuned without dragging in the surrounding-lines machinery.

/// Detect example/placeholder credentials using ONLY algorithmic heuristics.
/// No hardcoded credential lists - every suppression is based on a structural
/// property that generalizes to all credentials of that shape.
pub(crate) fn is_known_example_credential(credential: &str) -> bool {
    // EXAMPLE/EXAMPLEKEY is a universal documentation convention. Compare the
    // ASCII suffix case-insensitively against the raw bytes instead of
    // allocating a full Unicode `to_uppercase()` copy per candidate (Law 7:
    // this runs in five per-candidate suppression sites, adjudicate generic/
    // entropy/mod + suppression::decision x2). The result is byte-identical:
    // the suffixes are pure ASCII, and no non-ASCII char's Unicode uppercase is
    // a bare ASCII letter, so `to_uppercase().ends_with("EXAMPLE")` holds iff
    // the raw bytes end with `example` ignoring ASCII case.
    let bytes = credential.as_bytes();
    if crate::ascii_ci::ends_with_ignore_ascii_case(bytes, b"EXAMPLE")
        || crate::ascii_ci::ends_with_ignore_ascii_case(bytes, b"EXAMPLEKEY")
    {
        return true;
    }

    // x/X-dominated values are masking filler.
    let x_count = bytes.iter().filter(|&&b| b == b'x' || b == b'X').count();
    if bytes.len() >= 16 && x_count > bytes.len() * 3 / 4 {
        return true;
    }

    // Ascending hex pairs are documentation placeholders.
    if is_hex_sequential_placeholder(credential) {
        return true;
    }

    // These appear in integrity checks, not as secrets.
    if is_empty_input_hash(credential) {
        return true;
    }

    // Monotonic or repetitive bodies remain placeholders after stripping prefixes.
    is_sequential_placeholder(credential)
}

/// Returns true if the credential is the hash of an empty input (common in
/// integrity/checksum fields, never a real secret).
fn is_empty_input_hash(credential: &str) -> bool {
    // Length-gate FIRST, then compare case-insensitively against the raw bytes.
    // Law 7: this runs at every per-candidate suppression site (see the
    // `is_known_example_credential` note), and the previous unconditional
    // `credential.to_ascii_lowercase()` copied the whole credential for every
    // candidate, including the vast majority that are not 32/40/64 chars and
    // can never match. `[u8]::eq_ignore_ascii_case` is byte-identical here (all
    // three digests are pure ASCII) and allocates nothing. Only exact lengths
    // match, so a longer string that merely contains a digest never trips it.
    let bytes = credential.as_bytes();
    match bytes.len() {
        32 => bytes.eq_ignore_ascii_case(b"d41d8cd98f00b204e9800998ecf8427e"), // MD5("")
        40 => bytes.eq_ignore_ascii_case(b"da39a3ee5e6b4b0d3255bfef95601890afd80709"), // SHA1("")
        64 => bytes.eq_ignore_ascii_case(
            b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ), // SHA256("")
        128 => bytes.eq_ignore_ascii_case(
            b"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
              47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ), // SHA512("")
        _ => false,
    }
}

/// Fraction of adjacent steps that must be monotonic/sequential before a hex
/// body is treated as a documentation placeholder rather than a real secret:
/// 90% (`* 9 / 10`), allowing a small number of non-sequential positions.
const SEQUENTIAL_STEP_RATIO_NUMERATOR: usize = 9;
const SEQUENTIAL_STEP_RATIO_DENOMINATOR: usize = 10;

/// The `> threshold` count of sequential steps required over `step_count`
/// candidate positions. Single owner for the 90% sequential-run heuristic.
fn sequential_step_threshold(step_count: usize) -> usize {
    step_count * SEQUENTIAL_STEP_RATIO_NUMERATOR / SEQUENTIAL_STEP_RATIO_DENOMINATOR
}

pub(crate) fn is_sequential_placeholder(credential: &str) -> bool {
    // Strip ALL known service prefixes before checking for sequential/placeholder patterns.
    // Missing a prefix here = false positive (placeholder not suppressed).
    let body = credential_body_without_known_prefix(credential);
    if body.len() < 8 {
        return false;
    }

    let bytes = body.as_bytes();
    if bytes.iter().all(|&byte| byte == bytes[0]) {
        return true;
    }
    // `body.len() >= 8` is guaranteed by the length gate above.
    let pair = &bytes[..2];
    bytes
        .chunks(2)
        .all(|chunk| chunk == pair || (chunk.len() < 2 && chunk[0] == pair[0]))
}

/// True when `credential`'s body (known-prefix-stripped, len >= 8) is an
/// overwhelmingly MONOTONIC run, ascending (`12345678`, `abcdefgh`) or
/// descending (`87654321`). A real secret's adjacent bytes step ~randomly, so a
/// body whose adjacent bytes are consecutive above the shared 9/10 ratio is a
/// sequence/keyboard placeholder.
///
/// SCOPED DELIBERATELY to the ENTROPY shape path (phase2 entropy suppression),
/// NOT the universal [`is_known_example_credential`]: entropy-* matches are
/// shape/model-adjudicated so a sequential VALUE is the only evidence and should
/// suppress; but a STRONG vendor anchor (socure/openai/square `key=`) is proven
/// by its KEYWORD, so its value shape must not be second-guessed, and vendor
/// contract fixtures legitimately use sequential filler tokens
/// (`sdk_key="abcdefghijklmnopqrstuvwx123456"`). Reuses the same adjacent-step
/// counter + ratio threshold as the hex-sequence gate (ONE PLACE).
pub(crate) fn is_monotonic_sequence_placeholder(credential: &str) -> bool {
    let body = credential_body_without_known_prefix(credential);
    if body.len() < 8 {
        return false;
    }
    let bytes = body.as_bytes();
    let ascending = count_adjacent_byte_steps(bytes, ascii_forward_step);
    let descending = count_adjacent_byte_steps(bytes, ascii_reverse_step);
    let threshold = sequential_step_threshold(bytes.len().saturating_sub(1));
    ascending > threshold || descending > threshold
}

/// Adjacent bytes ascend by one code unit (`1`→`2`, `a`→`b`). `wrapping_add`
/// makes `0xff`→`0x00` non-special (it simply won't count as a step for the
/// realistic ASCII bodies this gates).
fn ascii_forward_step(previous: u8, next: u8) -> bool {
    next == previous.wrapping_add(1)
}

/// Adjacent bytes descend by one code unit (`8`→`7`, `d`→`c`).
fn ascii_reverse_step(previous: u8, next: u8) -> bool {
    previous == next.wrapping_add(1)
}

fn is_hex_sequential_placeholder(credential: &str) -> bool {
    // Same canonical prefix list as is_sequential_placeholder. Strip the
    // prefix before the hex-sequence check so e.g. `ghp_0123456789abcdef`
    // still trips the "monotonic hex" suppression on the BODY.
    let body = credential_body_without_known_prefix(credential);

    if body.len() < 16 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }

    let bytes = body.as_bytes();

    // Single-byte monotonic sequences such as 0123456789abcdef or fedcba9876543210.
    // `body.len() >= 16` is guaranteed by the length gate above.
    let ascending = count_adjacent_byte_steps(bytes, hex_forward_step);
    let descending = count_adjacent_byte_steps(bytes, hex_reverse_step);
    let threshold = sequential_step_threshold(bytes.len() - 1);
    if ascending > threshold || descending > threshold {
        return true;
    }

    let pair_count = bytes.len() / 2;
    if pair_count < 8 {
        return false;
    }

    if hex_byte_values_are_sequential(bytes, pair_count) {
        return true;
    }

    let ascending = count_pair_column_hex_steps(bytes, pair_count, 0);
    let ascending2 = count_pair_column_hex_steps(bytes, pair_count, 1);

    // `count_pair_column_hex_steps` compares `(1..pair_count)` => `pair_count - 1`
    // adjacent columns, so the threshold denominator must be `pair_count - 1`
    // (matches `hex_byte_values_are_sequential`); using `pair_count` demanded one
    // extra sequential step than actually exist.
    let threshold = sequential_step_threshold(pair_count - 1);
    ascending > threshold && ascending2 > threshold
}

fn credential_body_without_known_prefix(credential: &str) -> &str {
    crate::confidence::known_prefix_body(credential).unwrap_or(credential) // LAW10: unknown prefix => inspect full credential body, over-suppresses less, recall-safe
}

fn count_adjacent_byte_steps(bytes: &[u8], step: fn(u8, u8) -> bool) -> usize {
    bytes
        .windows(2)
        .filter(|window| step(window[0], window[1]))
        .count()
}

fn count_pair_column_hex_steps(bytes: &[u8], pair_count: usize, column: usize) -> usize {
    (1..pair_count)
        .filter(|&pair| {
            let previous = bytes[(pair - 1) * 2 + column];
            let next = bytes[pair * 2 + column];
            hex_pair_column_step(previous, next)
        })
        .count()
}

fn hex_byte_values_are_sequential(bytes: &[u8], pair_count: usize) -> bool {
    let forward = count_pair_value_steps(bytes, pair_count, |previous, next| {
        next == previous.wrapping_add(1)
    });
    let reverse = count_pair_value_steps(bytes, pair_count, |previous, next| {
        previous == next.wrapping_add(1)
    });
    let threshold = sequential_step_threshold(pair_count - 1);
    forward > threshold || reverse > threshold
}

fn count_pair_value_steps(bytes: &[u8], pair_count: usize, step: fn(u8, u8) -> bool) -> usize {
    let Some(mut previous) = hex_pair_value(bytes, 0) else {
        return 0;
    };
    let mut count = 0usize;
    for pair in 1..pair_count {
        let Some(next) = hex_pair_value(bytes, pair) else {
            return 0;
        };
        if step(previous, next) {
            count += 1;
        }
        previous = next;
    }
    count
}

fn hex_pair_value(bytes: &[u8], pair: usize) -> Option<u8> {
    let hi = crate::decode::util::hex_val(bytes[pair * 2]).ok()?; // LAW10: non-hex pair => not a sequential hex placeholder, so candidate remains reportable; recall-safe
    let lo = crate::decode::util::hex_val(bytes[pair * 2 + 1]).ok()?; // LAW10: non-hex pair => not a sequential hex placeholder, so candidate remains reportable; recall-safe
    Some((hi << 4) | lo)
}

fn hex_forward_step(previous: u8, next: u8) -> bool {
    let previous = previous.to_ascii_lowercase();
    let next = next.to_ascii_lowercase();
    next == previous + 1 || (previous == b'9' && next == b'a') || (previous == b'f' && next == b'0')
}

fn hex_reverse_step(previous: u8, next: u8) -> bool {
    let previous = previous.to_ascii_lowercase();
    let next = next.to_ascii_lowercase();
    next + 1 == previous || (previous == b'a' && next == b'9') || (previous == b'0' && next == b'f')
}

fn hex_pair_column_step(previous: u8, next: u8) -> bool {
    // `hex_forward_step` lowercases internally; `b'9'`/`b'0'` are case-invariant
    // digits, so no pre-lowercasing is needed here.
    hex_forward_step(previous, next) || (previous == b'9' && next == b'0')
}

#[cfg(test)]
mod sequential_placeholder_tests {
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
}

#[cfg(test)]
mod placeholder_suppression_adversarial_tests {
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
}
