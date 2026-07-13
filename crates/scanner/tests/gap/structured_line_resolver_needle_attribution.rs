//! Contract for `structured/parsers/line.rs::resolve_line_number_options`: the
//! needle-locating half of structured line attribution.
//!
//! `finalize_pending_pairs` turns every extracted structured pair into a
//! `(context, value, line)` triple by asking `resolve_line_number_options` for
//! the 1-based source line of each pair's value/owned anchor. The OFFSET→line
//! table it stands on (`compute_line_offsets` + `partition_point`) is pinned by
//! `structured_line_offsets_shared_builder.rs`; this file pins the NEEDLE search
//! layered on top, the part with the subtle branches:
//!
//!   * repeated-needle dedup, two slots holding the SAME anchor string share one
//!     Aho-Corasick pattern, so BOTH take that pattern's FIRST match line (a
//!     value appearing twice attributes both pairs to the earliest line);
//!   * empty-needle skip, an empty anchor is never added as a pattern and stays
//!     `None` (line falls back to the LAW10 placeholder in the caller);
//!   * all-empty / empty-text early return, no patterns ⇒ every slot `None`;
//!   * not-found ⇒ `None` (mixed freely with located needles, per slot);
//!   * overlapping substrings: `find_overlapping_iter` (not `find_iter`) means a
//!     needle that is a prefix/substring of another (`beta` vs `beta=SECRET`)
//!     still resolves; a non-overlapping scan would drop the shorter one.
//!
//! A regression in any of these silently mis-attributes a finding's reported line
//!, the operator is pointed at the wrong line of a real leak. The example test
//! asserts exact integers; the proptest fuzzes the whole search against an
//! independent `str::find`-per-needle oracle over a tiny `{a,b,\n}` alphabet
//! (which makes duplicates, overlaps, and absences all dense).

use keyhog_scanner::testing::resolve_line_number_options_for_test as resolve;
use proptest::prelude::*;

#[test]
fn resolves_dedup_first_occurrence_overlap_absent_and_empty() {
    // line 1: "alpha=1"       bytes  0..7,  '\n' @ 7
    // line 2: "beta=SECRET"   bytes  8..19, '\n' @ 19  ("beta"@8, "SECRET"@13)
    // line 3: "gamma=2"       bytes 20..27, '\n' @ 27
    // line 4: "beta=SECRET"   bytes 28..39, '\n' @ 39  (SECOND occurrence)
    let text = "alpha=1\nbeta=SECRET\ngamma=2\nbeta=SECRET\n";

    let needles = [
        "SECRET",     // 0: appears on lines 2 AND 4 -> FIRST occurrence = line 2
        "gamma=2",    // 1: line 3
        "SECRET",     // 2: SAME string as slot 0 -> dedup -> also line 2
        "absent-key", // 3: not present -> None
        "",           // 4: empty needle -> skipped -> None
        "beta",       // 5: substring of "beta=SECRET"; first on line 2
        "beta=SECRET", // 6: overlaps "beta" at the same start; find_overlapping
                      //    must still resolve it -> line 2
    ];

    assert_eq!(
        resolve(text, &needles),
        vec![
            Some(2), // SECRET -> earliest line, not the line-4 duplicate
            Some(3), // gamma=2
            Some(2), // repeated SECRET slot shares the first-match line
            None,    // absent
            None,    // empty needle never becomes a pattern
            Some(2), // beta
            Some(2), // beta=SECRET, resolved despite overlapping beta
        ],
        "needle attribution must dedup repeats to the first occurrence, skip empty \
         needles, return None for absent needles, and resolve overlapping substrings"
    );
}

#[test]
fn empty_text_and_empty_needle_slice_are_all_none() {
    // Empty text: nothing to locate, one slot -> None (length preserved).
    assert_eq!(resolve("", &["anything"]), vec![None]);
    // Empty needle slice: no slots -> empty vec (not a panic on `needles[0]`).
    assert_eq!(resolve("abc\ndef", &[]), Vec::<Option<usize>>::new());
    // All-empty needles over non-empty text: every slot None, length preserved.
    assert_eq!(resolve("abc\ndef", &["", ""]), vec![None, None]);
}

#[test]
fn single_line_text_attributes_to_line_one() {
    // No newlines at all: every located needle is line 1, an absent one is None.
    assert_eq!(
        resolve("token=abcdef nonce=xyz", &["abcdef", "missing", "xyz"]),
        vec![Some(1), None, Some(1)]
    );
}

/// Independent oracle: the 1-based line of each needle's FIRST byte occurrence,
/// deliberately a different implementation (`str::find` per needle + a newline
/// count) than the shared Aho-Corasick + `compute_line_offsets` path, so the
/// differential catches an AC iteration-order bug, an off-by-one in the offset
/// table, a dedup slot-mapping bug, or an empty-needle mishandling.
fn oracle(text: &str, needles: &[&str]) -> Vec<Option<usize>> {
    needles
        .iter()
        .map(|needle| {
            if needle.is_empty() {
                return None;
            }
            text.find(needle).map(|off| {
                1 + text.as_bytes()[..off]
                    .iter()
                    .filter(|&&b| b == b'\n')
                    .count()
            })
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// EXACT equivalence with the oracle over a tiny `{a, b, '\n'}` alphabet:
    /// short needles over this alphabet collide constantly, so the space is dense
    /// in duplicates (dedup), overlaps (`a` vs `ab` vs `aba`), absences, and
    /// multi-line texts, exactly the branches the example test pins by hand. A
    /// `\n` may appear inside a needle, exercising multi-line anchors too.
    #[test]
    fn matches_str_find_oracle_over_small_alphabet(
        text in "[ab\n]{0,60}",
        needle_strs in prop::collection::vec("[ab\n]{0,4}", 0..=6),
    ) {
        let needles: Vec<&str> = needle_strs.iter().map(String::as_str).collect();
        prop_assert_eq!(resolve(&text, &needles), oracle(&text, &needles));
    }
}
