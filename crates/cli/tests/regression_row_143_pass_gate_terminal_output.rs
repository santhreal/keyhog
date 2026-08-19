//! WHY: Closes the defect class where pass-gate terminal output lacked structured
//! craft (volume, blob counts, bytes scanned, and execution timing) or output was
//! inconsistent with terminal palette styling (Row 143).
//! Without structured pass-gate terminal rendering, operators and pre-commit hooks
//! receive bare or unstructured pass output rather than complete scan accounting.
//!
//! What this does NOT catch: daemon transport socket errors or git index mutations.

use keyhog::testing::{CliTestApi as _, API};
use std::time::Duration;

#[test]
fn pass_gate_summary_formatting_plain() {
    let summary = API.format_pass_gate_summary(
        "guard",
        10,
        5,
        2048,
        Some(Duration::from_millis(150)),
        false,
    );
    assert_eq!(
        summary,
        "OK guard: 10 cache hit(s), 5 blob(s) scanned, 2048 byte(s) scanned in 0.15s"
    );
}

#[test]
fn pass_gate_summary_formatting_without_duration() {
    let summary = API.format_pass_gate_summary("guard", 0, 1, 100, None, false);
    assert_eq!(
        summary,
        "OK guard: 0 cache hit(s), 1 blob(s) scanned, 100 byte(s) scanned"
    );
}

#[test]
fn pass_gate_summary_formatting_ansi() {
    let summary =
        API.format_pass_gate_summary("guard", 100, 0, 0, Some(Duration::from_secs(1)), true);
    assert!(
        summary.contains("\x1b[32mOK\x1b[0m"),
        "ANSI pass gate summary must contain green OK prefix; got: {summary:?}"
    );
    assert!(summary.contains("100 cache hit(s), 0 blob(s) scanned, 0 byte(s) scanned in 1.00s"),);
}
