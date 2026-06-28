//! Regression: the structured line resolver shares ONE line-offset builder.
//!
//! `structured/parsers/line.rs::resolve_line_number_options` used to carry its
//! own `build_line_starts(text)` — a byte-for-byte copy of
//! `pipeline::compute_line_offsets` (same `bytes.len()/40 + 1` capacity, same
//! leading `push(0)`, same `memchr_iter(b'\n') -> push(pos + 1)` loop). That
//! duplicate was deleted; the resolver now calls `crate::compute_line_offsets`
//! directly (NO DUPLICATION). The line attribution it produces is unchanged
//! because the builder output is identical.
//!
//! This test pins the exact contract that attribution depends on: the shared
//! `compute_line_offsets` table, plus the resolver's `partition_point(|&start|
//! start <= offset)` lookup (`line_number_for_offset`), must map each byte
//! offset to the correct 1-based line. If a future edit re-introduces a
//! divergent local builder (a missing leading `0`, an off-by-one `pos` vs
//! `pos + 1`), the offsets below change and every structured pair's reported
//! line drifts — this catches it with asserted integers, not shape.

use keyhog_scanner::testing::compute_line_offsets;

/// The resolver's exact lookup: the first line whose start is `> offset` minus
/// one, i.e. `partition_point(start <= offset)`. Kept in lockstep with
/// `structured/parsers/line.rs::line_number_for_offset`.
fn line_number_for_offset(line_starts: &[usize], offset: usize) -> usize {
    line_starts.partition_point(|&start| start <= offset)
}

#[test]
fn structured_line_resolver_uses_shared_offset_builder() {
    // alpha\n  -> line 1, bytes 0..5,  '\n' at 5
    // beta\n   -> line 2, bytes 6..10, '\n' at 10
    // GAMMA=secret\n -> line 3, bytes 11..23, '\n' at 23
    // delta\n  -> line 4, bytes 24..29, '\n' at 29
    // (trailing empty) -> line 5, byte 30
    let text = "alpha\nbeta\nGAMMA=secret\ndelta\n";

    let offsets = compute_line_offsets(text);

    // Exact table: leading 0, then one entry per newline at `pos + 1`.
    assert_eq!(
        offsets,
        vec![0, 6, 11, 24, 30],
        "shared compute_line_offsets must produce the canonical line-start table \
         (leading 0 + each newline+1) the structured resolver relies on"
    );

    // The resolver's partition_point lookup over that table -> 1-based line.
    assert_eq!(line_number_for_offset(&offsets, 0), 1, "offset 0 is line 1 (start of 'alpha')");
    assert_eq!(
        line_number_for_offset(&offsets, 11),
        3,
        "offset 11 is line 3 (the 'G' of GAMMA=secret — the keyword anchor)"
    );
    assert_eq!(
        line_number_for_offset(&offsets, 17),
        3,
        "offset 17 (mid 'secret') still resolves to line 3, not the next line"
    );
    assert_eq!(line_number_for_offset(&offsets, 24), 4, "offset 24 is line 4 (start of 'delta')");
    assert_eq!(
        line_number_for_offset(&offsets, 30),
        5,
        "offset 30 is the trailing empty line 5"
    );
}
