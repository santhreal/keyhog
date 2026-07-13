//! Unit tests for `orchestrator::reporting` shared ticker constants. Housed in a
//! sibling `tests.rs` module (rather than an inline `#[cfg(test)] mod {}` block)
//! so the `no_inline_tests_in_src` gate stays green while these still reach the
//! parent module's private constants and renderers via `use super::*`.

use super::*;

/// The braille spinner cycle is exactly ten glyphs; `frame % FRAMES.len()`
/// steps 1/10 of a turn per tick. Pin the count and the two endpoints so a
/// reordered/trimmed table is caught.
#[test]
fn frames_is_ten_braille_spinner_glyphs() {
    assert_eq!(FRAMES.len(), 10);
    assert_eq!(FRAMES[0], "⠋");
    assert_eq!(FRAMES[9], "⠏");
}

/// The shared bar width is 22 cells. Prove it is load-bearing: a full
/// determinate bar rendered at BAR_WIDTH is exactly 22 filled `█` cells.
#[test]
fn bar_width_is_twenty_two_cells() {
    assert_eq!(BAR_WIDTH, 22);
    let full = render_progress_bar(1.0, BAR_WIDTH, false);
    assert_eq!(full.chars().count(), 22);
    assert_eq!(full.chars().filter(|&c| c == '█').count(), 22);
}

/// Single-owner proof: the scan, verification and reporting tickers all read
/// the hoisted module-level `FRAMES`/`BAR_WIDTH`: not private per-function
/// copies. Each renders the same spinner glyph for a given frame and an
/// indeterminate sweep of exactly BAR_WIDTH cells. If any function
/// reintroduced a divergent local const, one of these equalities would break.
#[test]
fn every_phase_ticker_shares_one_frames_and_bar_width_owner() {
    // `█`/`░` cells only appear in the indeterminate sweep of a no-color line.
    fn sweep_cells(line: &str) -> usize {
        line.chars().filter(|&c| c == '█' || c == '░').count()
    }

    for frame in 0..FRAMES.len() {
        // total == 0 drives render_ticker_line down its indeterminate branch.
        let scan = render_ticker_line(0, 0, 0, 0.0, frame, false);
        let verify = render_verification_ticker_line(1, 0.0, frame, false);
        let report = render_reporting_ticker_line(1, 0.0, frame, false);

        // Same spinner glyph from the shared FRAMES table (no-color => the
        // line starts with the bare spinner char, no leading SGR escape).
        let want = FRAMES[frame % FRAMES.len()];
        assert_eq!(scan.chars().next().unwrap().to_string(), want);
        assert_eq!(verify.chars().next().unwrap().to_string(), want);
        assert_eq!(report.chars().next().unwrap().to_string(), want);

        // Same sweep width from the shared BAR_WIDTH const.
        assert_eq!(sweep_cells(&scan), BAR_WIDTH);
        assert_eq!(sweep_cells(&verify), BAR_WIDTH);
        assert_eq!(sweep_cells(&report), BAR_WIDTH);
    }
}

/// `scanned` and `total` are independent Relaxed atomics sampled at two
/// instants, so the ticker can transiently read `scanned > total`. The rendered
/// line must NEVER show ">100%" or an over-total ratio: the displayed count is
/// clamped to `total`, the bar stays full, and the phase reads `finalizing`.
#[test]
fn ticker_clamps_transient_scanned_over_total_overshoot() {
    // 1001 scanned against a stale total of 1000: the raw ratio would be 100.1%.
    let line = render_ticker_line(1001, 1000, 3, 2.0, 0, false);
    assert!(
        line.contains("100%"),
        "overshoot must clamp to 100%, not >100%; line={line}"
    );
    assert!(
        !line.contains("101%") && !line.contains("100.1"),
        "no percentage above 100 may render; line={line}"
    );
    assert!(
        line.contains("1000/1000"),
        "the displayed ratio must clamp to total, not show 1001/1000; line={line}"
    );
    assert!(
        line.contains("finalizing"),
        "scanned >= total reads as finalizing; line={line}"
    );
    // The full bar is exactly BAR_WIDTH filled cells, no rail.
    assert_eq!(
        line.chars().filter(|&c| c == '█').count(),
        BAR_WIDTH,
        "a clamped-full bar is entirely filled; line={line}"
    );
    assert_eq!(
        line.chars().filter(|&c| c == '░').count(),
        0,
        "a full bar carries no dim rail; line={line}"
    );
}

/// The exact-completion boundary (`scanned == total`) renders 100%, the true
/// ratio, `finalizing`, and no ETA segment (nothing left to estimate).
#[test]
fn ticker_at_exact_completion_shows_100_percent_no_eta() {
    let line = render_ticker_line(500, 500, 0, 1.0, 0, false);
    assert!(line.contains("100%"), "line={line}");
    assert!(line.contains("500/500"), "line={line}");
    assert!(line.contains("finalizing"), "line={line}");
    assert!(!line.contains("eta"), "no eta once complete; line={line}");
}

/// One owner for singular/plural nouns: a single count is singular, everything
/// else (including zero) is plural. Guards the "Found 1 secret" grammar fix and
/// the shared ticker nouns.
#[test]
fn count_nouns_pluralize_on_the_boundary() {
    assert_eq!(secret_noun(0), "secrets");
    assert_eq!(secret_noun(1), "secret");
    assert_eq!(secret_noun(2), "secrets");
    assert_eq!(finding_noun(0), "findings");
    assert_eq!(finding_noun(1), "finding");
    assert_eq!(finding_noun(2), "findings");
}

/// The verification/reporting tickers agree with the noun owner: a single
/// item reads "secret"/"finding" (singular), two read plural.
#[test]
fn phase_tickers_use_singular_noun_for_one_item() {
    let verify_one = render_verification_ticker_line(1, 0.0, 0, false);
    assert!(
        verify_one.contains(" 1 secret ") && !verify_one.contains("secrets"),
        "single verify item is singular; line={verify_one}"
    );
    let report_two = render_reporting_ticker_line(2, 0.0, 0, false);
    assert!(
        report_two.contains(" 2 findings "),
        "two report items are plural; line={report_two}"
    );
}
