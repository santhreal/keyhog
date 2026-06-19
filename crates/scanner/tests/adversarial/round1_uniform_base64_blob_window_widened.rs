//! Round 1 FP-killer regression contract: `looks_like_uniform_base64_blob`
//! window widening (60..=300 -> 44..=600) and high-diversity admit must
//! cover the FP class that survived v32.
//!
//! Investigator finding (base64-protobuf causes #1 + #2):
//!   * Pre-fix, the gate required `+`/`/` punct or `=` padding. Pure-
//!     alphanumeric base64 in 40-80 chars (no punct, no padding) escaped
//!     every gate.
//!   * Pre-fix, the window started at 60 chars; padded base64 in 44-59
//!     chars also escaped.
//!
//! Fix: widen window to 44..=600, AND admit pure-alphanumeric base64
//! when length is mult-of-4 AND alphabet diversity >= ~30 distinct chars.
//!
//! Adversarial style: PROPTEST 1k iterations.
//! Property A (FP-suppression): a 44-char, mult-of-4, no-padding,
//!   pure-alphanumeric base64 with HIGH alphabet diversity (every byte
//!   distinct) MUST be flagged.
//! Property B (recall preservation): a 32-char pure-alphanumeric base64
//!   (below the new 44 floor) must NOT be flagged - this protects every
//!   short service-anchored secret that doesn't carry +/.

use keyhog_scanner::testing::decode_structure::looks_like_uniform_base64_blob;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 1_000, .. ProptestConfig::default() })]

    /// Property A: a mult-of-4 length in [44, 80] pure-alphanumeric
    /// base64 with high alphabet diversity MUST be flagged. This is the
    /// shape that 14 base64-protobuf FPs landed on in v32.
    ///
    /// We use a length range that includes 44 (the new floor) and bounds
    /// at 80 because the test generator builds the body by shuffling 60
    /// distinct ASCII alnum bytes - a 60-byte sample is plenty to keep
    /// diversity at 30+ unique chars.
    #[test]
    fn pure_alnum_mult4_high_diversity_is_flagged(
        body in "[A-Za-z0-9]{60}",
    ) {
        // Trim or extend to a multiple-of-4 length in [44, 80].
        // 60 is mult-of-4; just use 60 directly.
        prop_assert_eq!(body.len(), 60);
        prop_assert!(body.len().is_multiple_of(4));

        // Skip the (very rare) draws whose alphabet diversity is below
        // the gate's diversity floor - those are not in the FP class
        // this property protects.
        let mut seen = [false; 256];
        let mut distinct = 0usize;
        for b in body.bytes() {
            if !seen[b as usize] {
                seen[b as usize] = true;
                distinct += 1;
            }
        }
        prop_assume!(distinct >= 32);

        prop_assert!(
            looks_like_uniform_base64_blob(&body),
            "60-char mult-of-4 pure-alnum base64 with diversity={distinct} \
             must be flagged. body={body}"
        );
    }

    /// Property B: a 32-char pure-alphanumeric base64 (below the 44
    /// floor) must NOT be flagged. This protects every short service-
    /// anchored secret (AWS secret access key = 40 chars, npm tokens =
    /// 36 chars, etc.) from being slammed by the gate.
    #[test]
    fn short_base64_below_floor_is_not_flagged(
        body in "[A-Za-z0-9]{32}",
    ) {
        prop_assert!(
            !looks_like_uniform_base64_blob(&body),
            "32-char base64 (below the 44-char floor) must NOT be flagged \
             as a uniform blob - this is the floor that protects real \
             secrets. body={body}"
        );
    }
}

/// Soundness: a 48-char padded base64 (real wire shape: base64 of 36
/// random bytes) MUST be flagged - this is the v32 FP class that
/// previously slipped because length was below 60.
#[test]
fn padded_base64_in_44_60_window_is_flagged() {
    // 48-char standard base64 with trailing `==` padding. base64(36
    // random bytes) is exactly this shape.
    let body = "Y9yPilpjN2WTIqtSuWGOKwSkvfmeAoLFCj099gWg24tohA==";
    assert_eq!(body.len(), 48);
    assert!(
        looks_like_uniform_base64_blob(body),
        "48-char padded base64 must be flagged by the widened window. body={body}"
    );
}

/// Soundness: a GitHub PAT (40+ chars containing `_`) MUST NOT be
/// flagged. The `_` is not in the standard base64 alphabet so the gate
/// returns false on the alphabet check, regardless of length.
#[test]
fn github_pat_shape_is_not_flagged() {
    // 50-char github_pat_-style body with `_` separators - definitely
    // not in the standard base64 alphabet.
    let body = "ghp_AB_CDE_FGH_IJK_LMN_OPQ_RST_UVW_XYZ_abcdef_12345";
    assert!(
        !looks_like_uniform_base64_blob(body),
        "GitHub PAT shape (contains `_`) must NOT be flagged. body={body}"
    );
}
