//! Law 10: a scanner-thread panic mid-scan returns PARTIAL findings and sets a
//! distinct exit code, but its only terminal output used to be a filtered-out
//! `tracing::error!`, so the run still printed "Found 0 secrets" as its last
//! word. `scanner_panic_notice` is the unconditional stderr notice the
//! completion summary now prints; pin its contract here.

use keyhog::orchestrator::scanner_panic_notice_for_test;

#[test]
fn a_completed_scan_produces_no_panic_notice() {
    // Negative twin: the scanner thread ran to completion, so there must be NO
    // incomplete-scan warning (no false alarm framing a clean result as broken).
    assert_eq!(scanner_panic_notice_for_test(false), None);
}

#[test]
fn a_panicked_scan_produces_an_unmissable_incomplete_notice() {
    let notice =
        scanner_panic_notice_for_test(true).expect("a mid-scan panic must produce a notice");
    // It must name the incompleteness and warn against reading "0 secrets" as
    // clean — the whole point of surfacing it (not just a tracing::error).
    assert!(
        notice.contains("INCOMPLETE") && notice.contains("PARTIAL"),
        "the notice must state the scan was incomplete and results are partial; got: {notice}"
    );
    assert!(
        notice.contains("not a clean result") || notice.contains("NOT a clean result"),
        "the notice must warn that a low/zero count is not a clean result; got: {notice}"
    );
}
