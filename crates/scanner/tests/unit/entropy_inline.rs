use super::FIRST_SOURCE_LINE_NUMBER;

/// The hoisted canonical is the one-based origin: a zero-based `.lines()`
/// index of 0 must resolve to source line 1, and the offset must add exactly
/// one at every position (this is the arithmetic both `scanner` and
/// `isolated` perform as `line_idx + FIRST_SOURCE_LINE_NUMBER`).
#[test]
fn first_source_line_number_is_the_one_based_origin() {
    assert_eq!(FIRST_SOURCE_LINE_NUMBER, 1);
    // Exactly the production expression: `line_idx + FIRST_SOURCE_LINE_NUMBER`.
    let line_of = |zero_based_index: usize| zero_based_index + FIRST_SOURCE_LINE_NUMBER;
    assert_eq!(line_of(0), 1);
    assert_eq!(line_of(9), 10);
    assert_eq!(line_of(41), 42);
}

/// End-to-end shape of the shared convention: enumerating lines and adding
/// the canonical offset maps a three-line buffer onto the exact one-based
/// numbers `[1, 2, 3]`, so the last line (`gamma`) reports line 3.
#[test]
fn line_base_maps_enumerated_lines_to_one_based_numbers() {
    let numbered: Vec<(usize, &str)> = "alpha\nbeta\ngamma"
        .lines()
        .enumerate()
        .map(|(idx, line)| (idx + FIRST_SOURCE_LINE_NUMBER, line))
        .collect();

    assert_eq!(
        numbered,
        vec![(1, "alpha"), (2, "beta"), (3, "gamma")],
        "enumerated line index + FIRST_SOURCE_LINE_NUMBER must yield 1-based line numbers",
    );
    assert_eq!(numbered.last().map(|&(line, _)| line), Some(3));
}
