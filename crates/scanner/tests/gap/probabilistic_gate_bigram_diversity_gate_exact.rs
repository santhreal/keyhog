//! Gap test: the probabilistic noise gate's bigram-distribution branch.
//!
//! `ProbabilisticGate::looks_promising` rejects obvious high-entropy non-secrets
//! before heavy ML scoring through three layered screens: a `< 16` length
//! passthrough, a distinct-byte diversity count (`< 5` distinct => reject), a
//! UUID 8-4-4-4-12 dash-pattern reject, and finally — for candidates `>= 32`
//! bytes that survive all of the above — a bigram-distribution screen that
//! rejects when the distinct-bigram count falls below `len / 4`.
//!
//! The migrated inline tests cover the short passthrough, the dashed-UUID
//! reject, the `< 5` diversity reject (`aaaa…`), and a realistic pass — but the
//! bigram branch is SHADOWED on all of those: `aaaa…` dies at the diversity
//! count (1 distinct byte) long before reaching the bigram screen. This pins
//! the bigram branch directly with inputs that pass the diversity count (exactly
//! 5 distinct bytes) yet carry too few distinct bigrams, and proves the screen
//! only engages at `len >= 32`. All vectors were modelled against the exact
//! `bigram_slot_512` mix before assertion.

use keyhog_scanner::testing::probabilistic_gate_looks_promising_for_test as promising;

#[test]
fn bigram_diversity_gate_rejects_low_distribution_at_or_above_32() {
    // A repeated 5-char cycle: 5 distinct bytes (survives the `< 5` diversity
    // count) but only 5 distinct adjacent bigrams (ab, bc, cd, de, ea). No dash,
    // so the UUID branch never fires. At len >= 32 the bigram screen engages and
    // rejects: distinct(5) < len/4.
    assert!(
        !promising(&"abcde".repeat(8)), // 40 bytes, floor = 10
        "a 40-byte low-bigram cycle must be rejected by the distribution screen"
    );
    assert!(
        !promising(&format!("{}ab", "abcde".repeat(6))), // exactly 32 bytes, floor = 8
        "the bigram screen must engage at exactly 32 bytes and reject"
    );
}

#[test]
fn len_below_thirty_two_does_not_engage_the_bigram_screen() {
    // The SAME low-bigram cycle one byte shorter (31 bytes) is admitted: the
    // bigram screen only runs at len >= 32, so a 5-distinct-byte input below the
    // threshold survives. This proves the rejection above is the length-gated
    // bigram branch, not the diversity count or content alone.
    assert!(
        promising(&format!("{}a", "abcde".repeat(6))), // 31 bytes
        "a 31-byte low-bigram cycle is below the screen's length floor and must pass"
    );
}

#[test]
fn sufficient_bigram_diversity_and_real_tokens_are_promising() {
    // A varied 38-byte token: distinct bigrams well above len/4 -> admitted.
    assert!(
        promising("Xq7Lm2Zp9Rt4Wc8Bn1Vd6Kf3Gj0Hs5Yu2AeLoQ"),
        "a high-diversity token must be promising"
    );
    // A 64-hex SHA-256 digest: the documented case the screen must NOT kill
    // (hex digests visit far more than len/4 distinct bigrams).
    assert!(
        promising("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
        "a SHA-256 hex digest must pass the bigram screen, not be rejected"
    );
    // A real padded base64 token: rich bigram distribution -> admitted.
    assert!(
        promising("dGhlcXVpY2ticm93bmZveGp1bXBzMTIzNDU2Nzg5MA=="),
        "a padded base64 token must be promising"
    );
}
