//! Capture-group integrity guard for the embedded detector corpus.
//!
//! `every_detector_compiles_into_scanner` (all_detectors_self_validate.rs)
//! proves every detector regex COMPILES. It does NOT prove the declared capture
//! `group` is meaningful: a pattern can compile cleanly yet declare
//! `group = 2` on a regex that only has one capture group. At scan time
//! `extract_grouped_matches` resolves the target group with
//! `locs.get(group).unwrap_or((full_start, full_end))` — so an out-of-range
//! group SILENTLY falls back to the WHOLE match (keyword + separator + value)
//! instead of the secret. That both pollutes the reported credential and
//! usually fails the detector's checksum, dropping a real secret. Neither shows
//! up as a compile error; it is invisible until someone diffs the captured
//! bytes. This file locks the invariant.
//!
//! The capture count comes from compiling each pattern through the engine's
//! EXACT builder via `detector_regex_captures_len_for_test`
//! (`compiler_compile::shared_regex_compile`), so `captures_len()` is identical
//! to what the scanner sees at run time — no duplicated builder config, no
//! size-limit mismatch on the corpus's largest patterns.
//!
//! `captures_len()` counts the implicit whole-match group 0 plus every explicit
//! group, so a declared group `g` is a valid index iff `g < captures_len`.

use keyhog_scanner::testing::detector_regex_captures_len_for_test as captures_len_of;

/// Compile `pattern` through the engine builder and return its capture-group
/// count, panicking with the offending pattern on a compile error (a bad test
/// pattern is an authoring bug; the corpus guard below reports real corpus
/// compile failures as violations rather than panicking).
fn captures_len(pattern: &str) -> usize {
    captures_len_of(pattern)
        .unwrap_or_else(|e| panic!("test pattern {pattern:?} must compile: {e}"))
}

/// A declared capture group index `g` is valid for a regex whose compiled
/// `captures_len` counts group 0 plus the explicit groups iff `g < captures_len`
/// (group 0 is the whole match; explicit groups are `1..captures_len`).
fn group_in_bounds(group: usize, captures_len: usize) -> bool {
    group < captures_len
}

fn corpus() -> Vec<keyhog_core::DetectorSpec> {
    keyhog_core::load_embedded_detectors_or_fail().expect("embedded detector corpus must load")
}

// ── the corpus guard (the real value) ───────────────────────────────────────

#[test]
fn every_pattern_declared_group_is_in_bounds_for_its_compiled_regex() {
    let mut violations: Vec<String> = Vec::new();
    for detector in corpus() {
        for (i, pattern) in detector.patterns.iter().enumerate() {
            let Some(group) = pattern.group else {
                continue; // no declared group: the whole match is the secret.
            };
            match captures_len_of(&pattern.regex) {
                Ok(len) if group_in_bounds(group, len) => {}
                Ok(len) => violations.push(format!(
                    "{} pattern[{i}] declares group={group} but its regex has only \
                     captures_len={len} (max valid group index {}); the engine would \
                     fall back to the whole match and mis-capture the credential",
                    detector.id,
                    len.saturating_sub(1),
                )),
                // A compile failure must surface here too, never be skipped
                // (Law 10: no silent fallback). It is also caught by
                // every_detector_compiles_into_scanner; reporting it here keeps
                // this guard fail-closed instead of silently passing over it.
                Err(e) => violations.push(format!(
                    "{} pattern[{i}] regex failed to compile through the engine builder: {e}",
                    detector.id
                )),
            }
        }
    }
    assert!(
        violations.is_empty(),
        "{} detector pattern(s) declare an out-of-range capture group:\n  - {}",
        violations.len(),
        violations.join("\n  - "),
    );
}

#[test]
fn every_pattern_regex_compiles_through_the_engine_builder() {
    // Complements the scanner-level compile gate by exercising the SAME builder
    // the boundedness guard relies on, over the whole corpus, and reporting the
    // exact offender by id+index if it ever regresses.
    let mut failures: Vec<String> = Vec::new();
    for detector in corpus() {
        for (i, pattern) in detector.patterns.iter().enumerate() {
            if let Err(e) = captures_len_of(&pattern.regex) {
                failures.push(format!("{} pattern[{i}]: {e}", detector.id));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} pattern(s) fail to compile through compiler_compile::shared_regex_compile:\n  - {}",
        failures.len(),
        failures.join("\n  - "),
    );
}

#[test]
fn at_least_one_detector_declares_a_capture_group() {
    // Sanity that the guard above is actually exercising real `group` values and
    // not vacuously passing because the corpus declares none.
    let with_group = corpus()
        .iter()
        .flat_map(|d| d.patterns.iter())
        .filter(|p| p.group.is_some())
        .count();
    assert!(
        with_group > 0,
        "expected some detectors to declare an explicit capture group"
    );
}

// ── seam truth: captures_len over the regex constructs the corpus uses ───────

#[test]
fn no_capture_group_has_len_one() {
    // Only the implicit whole-match group 0 exists.
    assert_eq!(captures_len(r"AKIA[0-9A-Z]{16}"), 1);
}

#[test]
fn one_capture_group_has_len_two() {
    assert_eq!(captures_len(r"token=(\w+)"), 2);
}

#[test]
fn two_capture_groups_have_len_three() {
    assert_eq!(captures_len(r"(\w+)=(\w+)"), 3);
}

#[test]
fn three_capture_groups_have_len_four() {
    assert_eq!(captures_len(r"(\w+):(\w+):(\w+)"), 4);
}

#[test]
fn non_capturing_group_does_not_increase_the_count() {
    // `(?:...)` matches but never captures, so only the trailing `(\w+)` counts.
    assert_eq!(captures_len(r"(?:secret|token)=(\w+)"), 2);
}

#[test]
fn nested_groups_each_count() {
    // Outer group plus two inner groups => 3 explicit groups => len 4.
    assert_eq!(captures_len(r"((\w+)-(\w+))"), 4);
}

#[test]
fn named_group_counts_like_an_unnamed_one() {
    assert_eq!(captures_len(r"(?P<value>\w+)"), 2);
}

#[test]
fn alternation_of_two_groups_counts_both_branches() {
    // Both branches declare a group even though only one participates per match.
    assert_eq!(captures_len(r"(?:(\w+)|(\d+))"), 3);
}

#[test]
fn optional_group_still_counts() {
    // `(\w+)?` may not participate, but it is still a declared capture group.
    assert_eq!(captures_len(r"(\w+)?=(\w+)"), 3);
}

#[test]
fn anchored_pattern_with_one_group_has_len_two() {
    assert_eq!(captures_len(r"^token=(\w+)$"), 2);
}

#[test]
fn char_class_quantifier_without_group_has_len_one() {
    assert_eq!(captures_len(r"[a-f0-9]{64}"), 1);
}

#[test]
fn inline_case_insensitive_flag_does_not_add_a_group() {
    // The engine builder already applies case-insensitivity; an inline `(?i)`
    // is redundant and, critically, is not a capture group.
    assert_eq!(captures_len(r"(?i)KEY=(\w+)"), 2);
}

#[test]
fn mixed_named_and_unnamed_groups_count_together() {
    assert_eq!(captures_len(r"(?P<a>\w+)-(?P<b>\w+)-(\d+)"), 4);
}

#[test]
fn large_bounded_quantifier_group_compiles_and_counts_once() {
    // The 8..128 value shape used across the generic/value detectors.
    assert_eq!(captures_len(r"key=([a-zA-Z0-9/+=_.-]{8,128})"), 2);
}

// ── bound predicate boundaries ───────────────────────────────────────────────

#[test]
fn group_one_in_a_two_group_regex_is_in_bounds() {
    assert!(group_in_bounds(1, 2));
}

#[test]
fn group_two_in_a_two_group_regex_is_out_of_bounds() {
    // captures_len 2 => valid indices are {0, 1}; group 2 does not exist.
    assert!(!group_in_bounds(2, 2));
}

#[test]
fn group_zero_whole_match_is_always_in_bounds() {
    assert!(group_in_bounds(0, 1));
}

#[test]
fn group_at_the_exact_upper_edge_is_in_bounds() {
    // captures_len 3 => valid indices {0, 1, 2}; group 2 is the highest valid.
    assert!(group_in_bounds(2, 3));
}

#[test]
fn group_one_past_the_upper_edge_is_out_of_bounds() {
    assert!(!group_in_bounds(3, 3));
}

#[test]
fn end_to_end_group_two_on_a_single_group_regex_is_out_of_bounds() {
    // The exact silent-mis-capture failure mode the corpus guard prevents:
    // a one-group regex (len 2) with a declared group=2.
    let len = captures_len(r"password=(\S+)");
    assert_eq!(len, 2);
    assert!(group_in_bounds(1, len), "group 1 (the value) is valid");
    assert!(
        !group_in_bounds(2, len),
        "group 2 does not exist on a one-group regex"
    );
}
