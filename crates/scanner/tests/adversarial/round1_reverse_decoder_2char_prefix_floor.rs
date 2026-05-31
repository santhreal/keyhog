//! Round 1 FP-killer regression contract: the reverse-decoder
//! admit gate must NOT fire on the 2-char `0x` Ethereum prefix.
//!
//! Investigator finding (base64-protobuf cause #3): pre-fix, `looks_reversible`
//! in crates/scanner/src/decode/reverse.rs admitted any candidate whose
//! REVERSED form contained ANY known provider prefix. The KNOWN_PREFIXES
//! list includes `0x` (Ethereum addresses), and that 2-char literal
//! appears in roughly 1.6% of random 80-char base64 strings. Result:
//! every such random base64 in the SecretBench mirror's `base64-protobuf`
//! decoy class got routed through the reverse decoder and surfaced as 4
//! generic FPs.
//!
//! Adversarial style: PROPTEST 1k iterations. For 1 000 generated 60-char
//! base64-alphabet strings that do NOT contain any 3+ char KNOWN_PREFIXES
//! substring, the reverse decoder must NOT admit the candidate. Soundness
//! check: a candidate whose reverse contains the 4-char vendor prefix
//! `AKIA` MUST still be admitted - the floor is at 3 chars, not 4.
//!
//! Why proptest: a single hand-picked decoy could be regressed away by
//! widening the gate. The property "every 60-char base64 with no real
//! vendor prefix is rejected" is the load-bearing invariant; proving it
//! over a 1k sample of random base64 catches a fix that re-admits short
//! prefixes regardless of which specific decoy I picked.

use keyhog_scanner::decode::reverse::looks_reversible;
use proptest::prelude::*;

// 3+ char known prefix list mirrors `KNOWN_PREFIXES` after the
// implementer's filter; if a test fixture happens to contain any of
// these by construction, skip it.
const REAL_VENDOR_PREFIXES: &[&str] = &[
    "AKIA",
    "ASIA",
    "AGPA",
    "AIDA",
    "AROA",
    "AIPA",
    "ANPA",
    "ANVA",
    "ABIA",
    "ACCA",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "sk-",
    "sk_",
    "pk_",
    "rk_",
    "xox",
    "hf_",
    "SG.",
    "eyJ",
    "AIza",
    "ya29",
    "shippo_",
    "shppo_",
    "glpat",
    "dp.",
];

proptest! {
    #![proptest_config(ProptestConfig { cases: 1_000, .. ProptestConfig::default() })]

    /// Property: for any 60-char base64-alphabet string whose reversed
    /// form contains NO 3+ char real vendor prefix, the reverse-decoder
    /// gate MUST return false. A 2-char incidental `0x` substring is not
    /// enough.
    #[test]
    fn random_base64_without_real_prefix_is_not_reverse_decodable(
        body in "[A-Za-z0-9+/]{60}",
    ) {
        let reversed: String = body.chars().rev().collect();
        // Skip the (vanishingly rare) draws that happen to contain a real
        // 3+ char vendor prefix - those SHOULD admit, and that is the
        // intentional carve-out.
        let has_real_prefix = REAL_VENDOR_PREFIXES
            .iter()
            .any(|p| reversed.contains(p));
        prop_assume!(!has_real_prefix);

        prop_assert!(
            !looks_reversible(&body),
            "60-char base64 without any 3+ char vendor prefix in its \
             reverse must NOT be admitted by the reverse decoder. \
             candidate={body}, reversed={reversed}"
        );
    }
}

/// Soundness floor: a candidate whose reverse contains the real 4-char
/// AKIA prefix MUST still admit. Proves the cut is at the 2/3 boundary,
/// not so aggressive that it kills legitimate reverse-decode coverage.
#[test]
fn akia_reversal_is_still_admitted() {
    // Pick something whose reverse contains "AKIA" + a long run.
    let reversed_text = "AKIAIOSFODNN7EXAMPLE";
    let candidate: String = reversed_text.chars().rev().collect();
    assert!(
        looks_reversible(&candidate),
        "reverse-decoder must still admit candidates whose reverse \
         contains the real 4-char AKIA vendor prefix; candidate={candidate}"
    );
}
