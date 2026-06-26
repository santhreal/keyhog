use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

/// A mixed-CASE pure-hex value must NOT be classified as a uniform-case hash
/// digest: real MD5/SHA/git-SHA digests are emitted single-case by every
/// standard library, so the bare-hex-digest gate keys on `is_uniform_hex`
/// (`!(saw_lower && saw_upper)`). A deliberately MiXeD-case 32-hex value is far
/// more likely a Base16-shaped secret than a digest, so it surfaces.
///
/// The fixture must be RANDOM-looking: the earlier `AbCdEf0123456789…` value
/// was mixed-case but ALSO a near-perfect ascending hex sequence
/// (A→b→C→d→E→f→0→1→…→9), which the orthogonal sequential-placeholder gate
/// correctly suppresses regardless of case. That gate is exercised by the
/// negative-twin below; this positive isolates the case property alone.
#[test]
fn mixed_case_hex_not_hash_digest() {
    assert!(!known_example_suppressed(
        "f3A9c1E47b2D8a06Ce5B91047fD3e2Ac",
        None,
        CodeContext::Unknown,
    ));
}

/// Negative twin: a mixed-case hex value that is ALSO a monotonic ascending
/// sequence IS suppressed — not as a hash digest (it's mixed-case) but as an
/// `algorithmic_placeholder` by `is_hex_sequential_placeholder`. This documents
/// that the two gates are independent: case-mixing escapes the digest gate, but
/// not the sequential-placeholder gate.
#[test]
fn mixed_case_sequential_hex_is_algorithmic_placeholder() {
    assert!(known_example_suppressed(
        "AbCdEf0123456789AbCdEf0123456789",
        None,
        CodeContext::Unknown,
    ));
}
