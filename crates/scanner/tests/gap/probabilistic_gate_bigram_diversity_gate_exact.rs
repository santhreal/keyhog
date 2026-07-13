//! Gap test: the probabilistic noise gate's bigram-distribution branch.
//!
//! `ProbabilisticGate::looks_promising` rejects obvious high-entropy non-secrets
//! before heavy ML scoring through three layered screens: a `< 16` length
//! passthrough, a distinct-byte diversity count (`< 5` distinct => reject), a
//! UUID 8-4-4-4-12 dash-pattern reject, and finally, for candidates `>= 32`
//! bytes that survive all of the above, a bigram-distribution screen that
//! rejects when the distinct-bigram count falls below `len / 4`.
//!
//! The migrated inline tests cover the short passthrough, the dashed-UUID
//! reject, the `< 5` diversity reject (`aaaa…`), and a realistic pass, but the
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

// ── Property tier: no-panic + the two SOUND boundary invariants ─────────────
// The fixed vectors above pin the bigram branch precisely. These sweep the gate
// over generated input to lock the two contracts the LIVE suppression path
// (`adjudicate/mod.rs:72`: `!looks_promising(credential) ⇒ suppress as
// ProbabilisticGateNotPromising`) depends on, a false negative here suppresses
// a real secret, so these are recall guarantees, not cosmetics.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// The gate must never panic on ANY input: it byte-indexes (`s.as_bytes()`,
    /// `windows(2)`, `seen[b as usize]`, the `bigram_slot_512` mix), so a slicing
    /// or index regression would crash the scan on a hostile candidate. `(?s)`
    /// so newlines and control bytes are in the swept alphabet too.
    #[test]
    fn never_panics_on_arbitrary_input(s in "(?s).{0,80}") {
        let _ = promising(&s);
    }

    /// RECALL GUARANTEE: any candidate under 16 BYTES is unconditionally
    /// promising (the `s.len() < 16` passthrough returns `true` before any
    /// screen). The gate therefore can NEVER suppress a short secret, a
    /// regression that lowered or removed that threshold would silently drop
    /// findings. Swept over every ASCII byte-length 0..=15.
    #[test]
    fn inputs_shorter_than_16_bytes_are_always_promising(s in "[\\x00-\\x7f]{0,15}") {
        prop_assert!(s.len() < 16);
        prop_assert!(
            promising(&s),
            "a {}-byte candidate is below the 16-byte floor and must be promising",
            s.len()
        );
    }

    /// A candidate of >= 16 bytes drawn from at most four distinct letters has
    /// fewer than five distinct bytes, so the diversity screen (`count < 5`)
    /// rejects it before the UUID/bigram branches, the documented low-diversity
    /// noise reject (the `aaaa…`-class redaction-mask family).
    #[test]
    fn long_low_diversity_inputs_are_rejected(s in "[abcd]{16,64}") {
        prop_assert!(
            !promising(&s),
            "a {}-byte <=4-distinct-letter mask must be rejected by the diversity screen",
            s.len()
        );
    }
}
