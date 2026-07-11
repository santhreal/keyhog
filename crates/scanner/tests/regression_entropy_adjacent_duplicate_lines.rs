use keyhog_scanner::entropy::{
    find_entropy_secrets_with_threshold, HIGH_ENTROPY_THRESHOLD, VERY_HIGH_ENTROPY_THRESHOLD,
};
use std::collections::HashSet;

#[test]
fn adjacent_identical_keyword_free_lines_keep_the_first_exact_finding() {
    let secret = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@";
    let line = format!("  value: \"{secret}\"");
    let text = format!("{line}\n{line}\n");

    let matches = find_entropy_secrets_with_threshold(
        &text,
        16,
        0,
        HIGH_ENTROPY_THRESHOLD,
        VERY_HIGH_ENTROPY_THRESHOLD,
        &[],
        &[],
        &[],
        None,
    );

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].value, secret);
    assert_eq!(
        matches[0].line, 1,
        "the first eligible copy owns attribution"
    );
    assert_eq!(matches[0].offset, 0);
}

#[test]
fn skipped_first_duplicate_does_not_hide_the_next_eligible_line() {
    let secret = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@";
    let line = format!("  value: \"{secret}\"");
    let text = format!("{line}\n{line}\n");
    let skip_lines = HashSet::from([0]);

    let matches = find_entropy_secrets_with_threshold(
        &text,
        16,
        0,
        HIGH_ENTROPY_THRESHOLD,
        VERY_HIGH_ENTROPY_THRESHOLD,
        &[],
        &[],
        &[],
        Some(&skip_lines),
    );

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].value, secret);
    assert_eq!(matches[0].line, 2);
    assert_eq!(matches[0].offset, line.len() + 1);
}
