//! `whole_assignment_value` resolves a candidate's logical value by walking the
//! quote and escape state that precedes it. That walk used to start at byte 0 of
//! the chunk, so a chunk with N candidates paid N full-chunk scans: quadratic,
//! and 19% of total scan time on a real source tree.
//!
//! Both pieces of state (the active quote and the escape flag) reset
//! unconditionally at `\n` and `\r`, so the walk only needs the candidate's own
//! line. These tests pin that equivalence where it can actually break: an
//! unterminated quote on an earlier line must not leak forward, a trailing
//! backslash must not escape across the line break, and the answer must not
//! depend on how much text precedes the line.

use crate::detector_execution_policy::whole_assignment_value;

/// Resolve the span of the first occurrence of `needle` in `data`.
fn span_of(data: &str, needle: &str) -> (usize, usize, usize) {
    let start = data.find(needle).expect("needle present in fixture");
    let value = whole_assignment_value(data, start, start + needle.len());
    (value.start, value.end, value.covered_end)
}

/// The resolved value must be byte-identical no matter how much unrelated text
/// precedes the candidate's line. This is the equivalence the optimization
/// relies on, stated directly.
#[test]
fn preceding_lines_do_not_change_the_resolved_span() {
    let line = "token = \"AKIAQYLPMN5HFIQR7XYA\"\n";
    let base = whole_assignment_value(line, line.find("AKIA").unwrap(), line.len() - 2);
    let base_text = base.as_str(line).to_owned();

    for filler_lines in [1_usize, 10, 500, 5_000] {
        let prefix = "unrelated = value\n".repeat(filler_lines);
        let data = format!("{prefix}{line}");
        let start = data.find("AKIA").expect("candidate present");
        let value = whole_assignment_value(&data, start, start + "AKIAQYLPMN5HFIQR7XYA".len());
        assert_eq!(
            value.as_str(&data),
            base_text,
            "{filler_lines} preceding lines changed the resolved value"
        );
        assert_eq!(
            (value.start - prefix.len(), value.end - prefix.len()),
            (base.start, base.end),
            "{filler_lines} preceding lines shifted the span by more than the prefix"
        );
    }
}

/// An unterminated quote on an EARLIER line must not capture a candidate on a
/// later line. Reading state from byte 0 without honouring the newline reset
/// would swallow the rest of the file into one value.
#[test]
fn an_unterminated_quote_does_not_leak_past_its_line() {
    let data = "broken = \"never closed\ntoken = AKIAQYLPMN5HFIQR7XYA\n";
    let (start, end, _) = span_of(data, "AKIAQYLPMN5HFIQR7XYA");
    assert_eq!(
        &data[start..end],
        "AKIAQYLPMN5HFIQR7XYA",
        "an unterminated quote on the previous line must not extend this value"
    );
}

/// A trailing backslash is not a line continuation for quote state: the escape
/// flag resets at the break, so the next line's opening quote is a real quote.
#[test]
fn a_trailing_backslash_does_not_escape_across_the_line_break() {
    let data = "prefix = ends_with_backslash\\\ntoken = \"AKIAQYLPMN5HFIQR7XYA\"\n";
    let (start, end, covered_end) = span_of(data, "AKIAQYLPMN5HFIQR7XYA");
    assert_eq!(
        &data[start..end],
        "AKIAQYLPMN5HFIQR7XYA",
        "the value must be the quoted contents, not a run continued from the previous line"
    );
    assert_eq!(
        data.as_bytes()[covered_end - 1],
        b'"',
        "the covered span must end on the closing quote"
    );
}

/// Quote state WITHIN the line is still honoured exactly: a candidate inside a
/// quote expands to the whole quoted value, and an escaped quote does not close
/// it.
#[test]
fn in_line_quote_and_escape_state_is_still_exact() {
    let data = "token = \"outer \\\" still inside AKIAQYLPMN5HFIQR7XYA\"\n";
    let (start, end, _) = span_of(data, "AKIAQYLPMN5HFIQR7XYA");
    assert_eq!(
        &data[start..end],
        "outer \\\" still inside AKIAQYLPMN5HFIQR7XYA",
        "an escaped quote must not terminate the value"
    );
}

/// A carriage return resets the state exactly like a line feed, so a CRLF file
/// and an LF file resolve the same value. Windows checkouts are the common case
/// where a `\r`-only reset would silently differ.
#[test]
fn carriage_return_resets_state_like_a_line_feed() {
    let lf = "broken = \"never closed\ntoken = AKIAQYLPMN5HFIQR7XYA\n";
    let crlf = "broken = \"never closed\r\ntoken = AKIAQYLPMN5HFIQR7XYA\r\n";
    let (lf_start, lf_end, _) = span_of(lf, "AKIAQYLPMN5HFIQR7XYA");
    let (crlf_start, crlf_end, _) = span_of(crlf, "AKIAQYLPMN5HFIQR7XYA");
    assert_eq!(&lf[lf_start..lf_end], &crlf[crlf_start..crlf_end]);
    assert_eq!(&lf[lf_start..lf_end], "AKIAQYLPMN5HFIQR7XYA");
}

/// A candidate on the FIRST line has no preceding break, which is the boundary
/// the line-start search has to get right: it must fall back to byte 0 rather
/// than skip the line's own opening quote.
#[test]
fn a_first_line_candidate_still_sees_its_opening_quote() {
    let data = "token = \"AKIAQYLPMN5HFIQR7XYA\"\nlater = 1\n";
    let (start, end, _) = span_of(data, "AKIAQYLPMN5HFIQR7XYA");
    assert_eq!(&data[start..end], "AKIAQYLPMN5HFIQR7XYA");
    assert_eq!(
        data.as_bytes()[start - 1],
        b'"',
        "the value must begin immediately after its opening quote"
    );
}

/// Every candidate on a line with many candidates resolves to the same enclosing
/// value, independent of which one is asked about. Scanning from the line start
/// each time must not make the answer depend on candidate order.
#[test]
fn every_candidate_on_one_line_resolves_the_same_enclosing_value() {
    let data = "prev = \"closed\"\nlist = \"aaaa bbbb cccc dddd\"\n";
    let expected = "aaaa bbbb cccc dddd";
    for needle in ["aaaa", "bbbb", "cccc", "dddd"] {
        let (start, end, _) = span_of(data, needle);
        assert_eq!(
            &data[start..end],
            expected,
            "candidate {needle:?} resolved a different enclosing value"
        );
    }
}

/// The cost of resolving one candidate must depend on its LINE, not on the
/// chunk that precedes it. This is the regression that the equivalence tests
/// above cannot see: the old walk started at byte 0 and was correct, just
/// quadratic in candidates per chunk.
///
/// The bound is deliberately loose. Growing the preceding text by 256x used to
/// grow the per-call cost by roughly the same factor; anything under 8x means
/// the walk is no longer reading the whole prefix. A loose bound keeps this
/// meaningful without making it a timing-sensitive flake.
#[test]
fn resolution_cost_does_not_grow_with_preceding_chunk_size() {
    const LINE: &str = "token = \"AKIAQYLPMN5HFIQR7XYA\"\n";
    const NEEDLE: &str = "AKIAQYLPMN5HFIQR7XYA";

    fn median_nanos_per_call(prefix_lines: usize) -> u128 {
        let data = format!("{}{LINE}", "unrelated = value\n".repeat(prefix_lines));
        let start = data.find(NEEDLE).expect("candidate present");
        let end = start + NEEDLE.len();
        let mut samples = Vec::new();
        for _ in 0..7 {
            let began = std::time::Instant::now();
            for _ in 0..200 {
                std::hint::black_box(whole_assignment_value(
                    std::hint::black_box(&data),
                    start,
                    end,
                ));
            }
            samples.push(began.elapsed().as_nanos() / 200);
        }
        samples.sort_unstable();
        samples[samples.len() / 2]
    }

    // ~4 KiB of preceding text versus ~1 MiB: a 256x difference in prefix size.
    let small = median_nanos_per_call(230).max(1);
    let large = median_nanos_per_call(230 * 256);
    assert!(
        large < small * 8,
        "resolving a candidate after ~1 MiB of preceding lines took {large} ns \
         versus {small} ns after ~4 KiB; the walk is reading the whole chunk \
         again instead of just the candidate's line"
    );
}
