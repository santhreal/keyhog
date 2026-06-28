//! Regression: ONE `div_ceil(64)` sizing for every trigger bitmap.
//!
//! `engine/trigger_bitmap.rs` documents that "the word width and `div_ceil(64)`
//! sizing live in exactly one place (so a future width change can't update only
//! some sites)". That promise was unmet: `new_trigger_bitmap` open-coded
//! `n_patterns.div_ceil(64)` and `scan_coalesced::compute_coalesced_triggers`
//! open-coded `ac_len.div_ceil(64)` for its pooled scratch. Both now derive the
//! word count from the single `trigger_bitmap::words_for`.
//!
//! This pins `words_for`'s exact arithmetic AND the invariant that a freshly
//! allocated bitmap is `words_for(n)` zeroed words — so a future word-width
//! change (or an off-by-one in the ceiling) is caught with concrete integers.

use keyhog_scanner::testing::{new_trigger_bitmap_for_test as new_bitmap, trigger_bitmap_words_for_test as words_for};

#[test]
fn words_for_is_ceil_div_64_and_sizes_the_bitmap() {
    // Exact ceiling division by 64 (one u64 word per 64 pattern bits).
    assert_eq!(words_for(0), 0, "zero patterns need zero words");
    assert_eq!(words_for(1), 1);
    assert_eq!(words_for(63), 1);
    assert_eq!(words_for(64), 1, "exactly 64 bits fit in one word");
    assert_eq!(words_for(65), 2, "the 65th bit spills into a second word");
    assert_eq!(words_for(128), 2);
    assert_eq!(words_for(129), 3);

    // A freshly allocated bitmap is exactly `words_for(n)` words, all zero.
    for &n in &[0usize, 1, 64, 65, 200, 2700] {
        let bitmap = new_bitmap(n);
        assert_eq!(
            bitmap.len(),
            words_for(n),
            "new_trigger_bitmap({n}) length must come from the same words_for sizing"
        );
        assert!(
            bitmap.iter().all(|&w| w == 0),
            "a fresh trigger bitmap must be all-zero (no pattern pre-marked)"
        );
    }
}
