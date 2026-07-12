//! Recall-soundness differential for the phase-2 first-bigram prescreen.
//!
//! `FirstBigramSet::may_have_match` is a MAYBE-gate in front of the exact
//! Aho-Corasick scan: a `false` return SKIPS the AC entirely, so a false
//! negative is a SILENT RECALL LOSS — a real secret whose literal's first bigram
//! is present in the text would never be scanned. This fuzzes the bitmap gate
//! against an INDEPENDENT `HashSet` oracle over arbitrary ASCII literals + text,
//! in both case-sensitive and ASCII-case-insensitive modes, asserting EXACT
//! equivalence (the 1024×u64 bitmap matches the oracle bit-for-bit) — so no
//! bitmap index-math bug (`idx >> 6` / `idx & 63`), 4-way-unroll boundary, or
//! casefold gap can cause a silent skip. The `tests/unit/engine.rs` example test
//! pins 4 hand-picked cases; this covers the whole space, especially the
//! unrolled-loop vs scalar-tail transition at text lengths 2..=8.

use keyhog_scanner::engine::phase2::FirstBigramSet;
use proptest::prelude::*;
use std::collections::HashSet;

/// Independent oracle: the set of first-bigram `u16` keys an
/// `ascii_case_insensitive`-aware build indexes — a `HashSet` reimplementation
/// of `FirstBigramSet::from_literals`' indexing, deliberately a DIFFERENT data
/// structure than the bitmap so the differential catches index-math bugs.
fn oracle_keys(lits: &[Vec<u8>], ci: bool) -> HashSet<u16> {
    let variants = |byte: u8| -> Vec<u8> {
        if ci && byte.is_ascii_alphabetic() {
            vec![byte.to_ascii_lowercase(), byte.to_ascii_uppercase()]
        } else {
            vec![byte]
        }
    };
    let mut set = HashSet::new();
    for lit in lits {
        if lit.len() < 2 {
            continue; // a <2-byte literal triggers fail-open, excluded from this property
        }
        for ca in variants(lit[0]) {
            for cb in variants(lit[1]) {
                set.insert((ca as u16) << 8 | cb as u16);
            }
        }
    }
    set
}

fn oracle_may_match(keys: &HashSet<u16>, text: &[u8]) -> bool {
    text.windows(2)
        .any(|w| keys.contains(&((w[0] as u16) << 8 | w[1] as u16)))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// EXACT equivalence between the bitmap gate and the independent oracle, over
    /// arbitrary ASCII literals (len 2..=8, so no fail-open saturation) and ASCII
    /// text (len 0..=40, spanning every unroll/tail boundary), in both case
    /// modes. The `oracle=true ⟹ may_have_match=true` direction is the RECALL
    /// guarantee (no false negative → no silently-skipped AC scan); the converse
    /// pins that the gate stays a TIGHT over-approximation, not saturated.
    #[test]
    fn may_have_match_equals_independent_oracle(
        lits in prop::collection::vec(prop::collection::vec(0x20u8..=0x7e, 2..=8), 1..=6),
        text in prop::collection::vec(0x20u8..=0x7e, 0..=40),
        ci in any::<bool>(),
    ) {
        let set = FirstBigramSet::from_literals(lits.iter().map(|l| l.as_slice()), ci);
        // ASCII bytes are valid UTF-8, so this decode never fails.
        let text_str = std::str::from_utf8(&text).expect("ascii is valid utf-8");

        let keys = oracle_keys(&lits, ci);
        let expected = oracle_may_match(&keys, &text);
        let actual = set.may_have_match(text_str);

        prop_assert_eq!(
            actual, expected,
            "first-bigram gate disagrees with the oracle (a `false` here that should be `true` is a SILENT RECALL LOSS): lits={:?} text={:?} ci={}",
            lits, text, ci
        );
    }
}
