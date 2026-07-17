//! DR-272: production-weight golden regression for the MoE confidence scorer.
//!
//! The existing `ml_forward_parity.rs` proves the output-stationary forward
//! KERNEL is bit-identical to a reference matmul, but it feeds SYNTHETIC random
//! weights, it never runs the SHIPPED `weights.bin` end to end. The unit tests
//! in `unit/ml_scorer.rs` run the real weights but only assert loose PROPERTY
//! bands (`> 0.7` for a real secret, `< 0.5` for a hash). Neither pins the exact
//! score the shipped model emits, so a silent `weights.bin` swap, a feature
//! reorder, or a gate/expert-layout drift that keeps scores in-band would pass
//! undetected.
//!
//! This test locks the EXACT f64 score the embedded model produces for a fixed
//! corpus. Exact bit-equality is a legitimate cross-platform contract here: the
//! forward pass is bit-identical to the row-major scalar dot product by design
//! (`ml_scorer::dense_relu_layer_t` "vectorizing across outputs never
//! reassociates a single output's sum"), which `ml_forward_parity.rs` verifies.
//! So a golden captured on one host reproduces on every host; any mismatch means
//! the shipped model or the feature pipeline genuinely changed.
//!
//! To re-baseline after an INTENTIONAL model/feature change: run the ignored
//! `capture_production_weight_goldens` test (`cargo test -p keyhog-scanner
//! --test regression_ml_production_weight_golden -- --ignored --nocapture` or
//! read the panic message) and paste the emitted `GOLDEN_BITS` array below.

#![cfg(feature = "ml")]

use keyhog_scanner::testing::ml_score_for_detector;

/// (candidate value, surrounding context) pairs spanning the score range and
/// exercising distinct feature paths: real-vendor-prefix secrets, a pure-hex
/// hash, a UUID, an explicit placeholder, a base64 blob, and prose.
const CASES: &[(&str, &str, &str, bool)] = &[
    (
        "ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R",
        "const GITHUB_TOKEN = \"{}\";",
        "github-classic-pat",
        false,
    ),
    ("AKIAIOSFODNN7EXAMPLE", "aws_access_key_id = {}", "aws-access-key", false),
    (
        "xoxb-2401234567-2401234567890-AbCdEfGhIjKlMnOpQrStUvWx",
        "slack_bot_token: {}",
        "slack-bot-token",
        false,
    ),
    ("5d41402abc4b2a76b9719d911017c592", "md5 = \"{}\"", "generic-secret", true),
    ("550e8400-e29b-41d4-a716-446655440000", "request_id: {}", "generic-api-key", true),
    ("your_api_key_here", "api_key = \"{}\"", "generic-api-key", false),
    ("aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q=", "payload = \"{}\"", "generic-secret", true),
    (
        "The quick brown fox jumps over the lazy dog",
        "// human-readable comment: {}",
        "generic-secret",
        false,
    ),
    // Ambiguous / mid-range cases, sensitive sentinels that catch a SMALL
    // weight or feature drift (unlike the saturated 0.0/1.0 cases, which only
    // trip on a large change). A JWT, a Stripe test-key shape, a bare 32-hex
    // secret with no vendor prefix, and a base64 credential-length blob in an
    // explicit key= context.
    (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        "authorization: Bearer {}",
        "jwt-token",
        false,
    ),
    ("sk_test_4eC39HqLyjWDarjtT1zdp7dc", "stripe_secret_key = \"{}\"", "stripe-secret-key", false),
    ("d1e8a70b5ccab1dc2f6f5c8e9a0b1c2d", "secret_key = \"{}\"", "generic-secret", true),
    ("aG9zdF9rZXlfMjAyNF9wcm9kdWN0aW9uX2Vudg==", "API_KEY={}", "generic-api-key", false),
];

/// `score.to_bits()` for each case, captured from the shipped `weights.bin`
/// for the 55-feature detector-conditioned model. The positive vendor shapes,
/// JWT, and anchored base64 credential saturate at 1.0; the digest, UUID,
/// placeholder, binary/prose payload, and bare hex cases saturate at 0.0.
const GOLDEN_BITS: &[u64] = &[
    4607182418800017408, // 1.0, ghp_… GitHub PAT
    4607182418800017408, // 1.0, AKIA… AWS access key
    4607182418800017408, // 1.0, xoxb-… Slack bot token
    0,                   // 0.0, md5 hex digest
    0,                   // 0.0: UUID
    0,                   // 0.0, your_api_key_here placeholder
    0,                   // 0.0, base64 blob (decodes to prose)
    0,                   // 0.0: English prose
    4607182418800017408, // 1.0, structurally valid demo JWT
    4607182418800017408, // 1.0, structurally valid Stripe test key
    0,                   // 0.0, bare 32-hex, no vendor prefix (hash-ambiguous)
    4607182418800017408, // 1.0, base64 → "host_key_2024_production_env" (real cred)
];

#[test]
fn production_weights_forward_pass_matches_golden_scores() {
    assert_eq!(
        CASES.len(),
        GOLDEN_BITS.len(),
        "CASES and GOLDEN_BITS must stay the same length",
    );
    for (i, (text, context, detector_id, entropy_channel)) in CASES.iter().enumerate() {
        let got = ml_score_for_detector(text, context, detector_id, *entropy_channel);
        let want = f64::from_bits(GOLDEN_BITS[i]);
        assert_eq!(
            got.to_bits(),
            GOLDEN_BITS[i],
            "case {i} ({text:?}): production MoE score drifted, got {got:.17} \
             (bits {}), golden {want:.17} (bits {}). The shipped weights.bin, the \
             55-feature extraction order (including detector/channel policy), or \
             the gate/expert layout changed. If \
             intentional, re-run the `capture_production_weight_goldens` test and \
             paste the new GOLDEN_BITS.",
            got.to_bits(),
            GOLDEN_BITS[i],
        );
        // Every score is a probability in [0, 1] regardless of the golden.
        assert!(
            (0.0..=1.0).contains(&got),
            "case {i}: score {got} outside [0,1]",
        );
    }
}

/// Scoring must be deterministic across repeated calls (no hidden RNG, no
/// cache-eviction non-determinism). Independent of the goldens, so it stays
/// green even while GOLDEN_BITS is being re-baselined.
#[test]
fn production_weights_scoring_is_deterministic() {
    for (text, context, detector_id, entropy_channel) in CASES {
        let a = ml_score_for_detector(text, context, detector_id, *entropy_channel);
        let b = ml_score_for_detector(text, context, detector_id, *entropy_channel);
        assert_eq!(
            a.to_bits(),
            b.to_bits(),
            "ml_score({text:?}) is non-deterministic: {a:.17} != {b:.17}",
        );
    }
}

/// Re-baseline helper: emits the current `to_bits()` goldens for every case.
/// Ignored so it never runs in the normal suite; run explicitly to capture.
#[test]
#[ignore = "capture helper, run explicitly to re-baseline GOLDEN_BITS"]
fn capture_production_weight_goldens() {
    let bits: Vec<u64> = CASES
        .iter()
        .map(|(t, c, detector_id, entropy_channel)| {
            ml_score_for_detector(t, c, detector_id, *entropy_channel).to_bits()
        })
        .collect();
    let vals: Vec<f64> = CASES
        .iter()
        .map(|(t, c, detector_id, entropy_channel)| {
            ml_score_for_detector(t, c, detector_id, *entropy_channel)
        })
        .collect();
    panic!("GOLDEN_BITS = {bits:?}\n// human-readable scores = {vals:?}");
}
