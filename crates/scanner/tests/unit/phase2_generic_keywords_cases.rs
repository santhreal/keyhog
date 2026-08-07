use super::{
    collect_generic_keyword_lines_from_positions, collect_generic_keyword_lines_with,
    collect_generic_keyword_positions_with, GenericKeywordStemSet,
};

#[test]
fn maps_positions_to_line_indexes_sorted_deduped() {
    let text = format!("{}\n{}\n{}", "a".repeat(9), "b".repeat(14), "c".repeat(10));
    let line_index = crate::context::LineContextIndex::try_new(&text).unwrap();
    let positions = [0u32, 5, 10, 24, 25, 30];
    let mut out = Vec::new();
    collect_generic_keyword_lines_from_positions(&line_index, &positions, &mut out);
    assert_eq!(out, vec![0, 1, 2]);
}

#[test]
fn positions_within_one_line_dedup_to_that_line() {
    let text = format!("{}\n{}\n{}", "a".repeat(9), "b".repeat(14), "c".repeat(10));
    let line_index = crate::context::LineContextIndex::try_new(&text).unwrap();
    let positions = [10u32, 12, 20, 24];
    let mut out = Vec::new();
    collect_generic_keyword_lines_from_positions(&line_index, &positions, &mut out);
    assert_eq!(out, vec![1]);
}

#[test]
fn empty_text_yields_empty() {
    let line_index = crate::context::LineContextIndex::try_new("").unwrap();
    let mut out = vec![7, 8, 9];
    collect_generic_keyword_lines_from_positions(&line_index, &[3u32], &mut out);
    assert!(out.is_empty());
}

/// WHY: admission planning may reuse exact generic-stem positions across
/// byte-identical payloads. One position per matching line is sufficient for
/// the line-scoped bridge, while misses and later lines must remain distinct.
#[test]
fn representative_positions_preserve_matching_lines() {
    let text = "ordinary\nphasekw=first\nplain\nphasekw:second phasekw\n";
    let stems = GenericKeywordStemSet::compile(["phasekw"]);
    let mut positions = Vec::new();
    collect_generic_keyword_positions_with(&stems, text, &mut positions);
    assert_eq!(
        positions,
        vec![
            text.find("phasekw=first").unwrap() as u32,
            text.find("phasekw:second").unwrap() as u32,
        ]
    );

    let line_index = crate::context::LineContextIndex::try_new(text).unwrap();
    let mut lines = Vec::new();
    collect_generic_keyword_lines_from_positions(&line_index, &positions, &mut lines);
    assert_eq!(lines, vec![1, 3]);
}

/// WHY: broad stems such as `pass` must not promote ordinary repeated text to
/// generic-regex candidate lines. Assignment-shaped uses, including the shipped
/// `*_PASS=` form, remain admitted at the same boundary.
#[test]
fn broad_stems_require_a_following_assignment_delimiter() {
    let text = concat!(
        "value value value\n",
        "compassion bypass passport value\n",
        "CACHE_PASS=gjbubxsu\n",
        "dbPassValue: BadCbc0#-DE&1$FA\n",
        "secret without an assignment\n",
    );
    let stems = GenericKeywordStemSet::compile(["pass", "secret"]);
    let mut lines = Vec::new();

    collect_generic_keyword_lines_with(&stems, text, &mut lines);
    let mut positions = Vec::new();
    collect_generic_keyword_positions_with(&stems, text, &mut positions);
    assert_eq!(
        positions,
        vec![
            text.find("PASS=gjbubxsu").unwrap() as u32,
            text.find("PassValue").unwrap() as u32,
        ]
    );

    assert_eq!(lines, vec![2, 3]);
}
