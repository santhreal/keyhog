//! Regression: the confirmed-pass suffix-gate literal extraction contract.
//!
//! `build_confirmed_suffix_gate` skips a confirmed pattern whose required
//! trailing literal is absent from the chunk — a recall-identical optimization
//! ONLY if `suffix_gate_literals` extracts a sound required suffix. The builder
//! was cleaned up to iterate the cached literals by reference (it deep-cloned the
//! whole `Vec<String>` per pattern), so this pins the extraction contract those
//! literals come from with asserted values: a finite set of <=4 literals, each
//! >= 6 bytes, ASCII-lowercased; otherwise empty (pattern runs unconditionally,
//! never a missed match).

use keyhog_scanner::testing::suffix_gate_literals_for_test as suffix_lits;

#[test]
fn suffix_gate_literals_extracts_only_long_finite_suffixes() {
    // A pure literal >= 6 bytes is its own required suffix, lowercased.
    assert_eq!(suffix_lits("secrettoken"), vec!["secrettoken".to_string()]);
    // Case is folded for the ASCII-case-insensitive gate AC.
    assert_eq!(suffix_lits("SECRETTOKEN"), vec!["secrettoken".to_string()]);
    // Exactly 6 bytes is the inclusive floor (MIN_LEN = 6).
    assert_eq!(suffix_lits("short1"), vec!["short1".to_string()]);

    // Below the 6-byte floor -> not selective enough -> empty (run the pattern).
    assert!(suffix_lits("short").is_empty(), "5-byte suffix is below MIN_LEN");
    assert!(suffix_lits("abc").is_empty(), "3-byte suffix is below MIN_LEN");

    // No finite required suffix literal (trailing variable char-class) -> empty.
    assert!(
        suffix_lits("[0-9]+").is_empty(),
        "a trailing digit class has no single >=6-byte required suffix"
    );

    // Empty pattern -> empty (no panic, no synthesized literal).
    assert!(suffix_lits("").is_empty(), "empty source yields no suffix literal");
}
