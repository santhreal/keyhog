//! Migrated from suppression::shape::canonical, the standard-base64-blob
//! shape gate (high-diversity / padded admits, low-diversity / non-mult-4
//! rejects) that kills the base64-protobuf FP class (KH-GAP-004).

use keyhog_scanner::testing::looks_like_standard_base64_blob;

// Round 1 FP-killer: base64-protobuf cause #1. A 40-char pure-alphanumeric
// base64 string (no +/) with high alphabet diversity must hit the gate.
#[test]
fn standard_base64_blob_admits_pure_alnum_high_diversity() {
    // 40-char base64 alphabet, no +/, distinct alnum >= 32, mult-of-4.
    let v = "8Xs2ny0Ng9nqVusefKpLxC7DJ1lj4YplT6m62LAg";
    assert_eq!(v.len(), 40);
    let distinct: std::collections::BTreeSet<char> = v.chars().collect();
    assert!(distinct.len() >= 32, "fixture diversity must be >= 32");
    assert!(
        looks_like_standard_base64_blob(v),
        "40-char pure-alphanumeric mult-of-4 base64 with high alphabet \
         diversity is a random-bytes shape and must be slammed",
    );
}

// Negative twin: a real AWS-secret-access-key shape (40 base62 chars with low
// alphabet diversity) must NOT hit the gate.
#[test]
fn standard_base64_blob_rejects_low_diversity_alnum() {
    let v = "AAaaBBbbCCccDDddEEee11223344556677889900";
    assert_eq!(v.len(), 40);
    let distinct: std::collections::BTreeSet<char> = v.chars().collect();
    assert!(distinct.len() < 32, "fixture diversity must be < 32");
    assert!(
        !looks_like_standard_base64_blob(v),
        "low-diversity 40-char alnum must NOT fire (real short-token \
         recall preserved); got diversity={}",
        distinct.len(),
    );
}

// Round 1 FP-killer: base64-protobuf cause #4. A 48-char padded base64 ending
// in `=` with no +/ punct must hit the gate.
#[test]
fn standard_base64_blob_admits_padded_no_punct() {
    // 48 chars, mult-of-4, ends in `=`, no `+` or `/`.
    let v = "Y9yPilpjN2WTIqtSuWGOKwSkvfmeAoLFCj099gWg24tohA==";
    assert_eq!(v.len(), 48);
    assert!(
        looks_like_standard_base64_blob(v),
        "padded 48-char base64 without +/ punct must fire via the \
         padded-admit clause (base64-protobuf cause #4)",
    );
}

// Negative twin: a 41-char base64 with no padding, mult-of-4 = false
// (41 % 4 == 1) - the strict mult-of-4 OR padding precondition keeps this off
// the gate.
#[test]
fn standard_base64_blob_rejects_non_mult4_no_pad() {
    let v = "NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1Ja";
    assert_eq!(v.len(), 41);
    assert!(
        !looks_like_standard_base64_blob(v),
        "41-char non-mult-of-4 unpadded base64 must NOT fire (the \
         length precondition fails before any admit clause)",
    );
}
