//! UX contract: every CLI value-parser rejection states the FIX, not just the
//! error. clap prefixes the flag name and offending input, so each parser's
//! message must add what was *expected* (the accepted range/form) plus a
//! concrete example. Previously the parse-failure branches said only "not a
//! valid floating point number" / "not a valid positive integer" with no range
//! or example, leaving the operator to guess the bounds (task #131). This pins
//! that both failure modes, unparseable input AND out-of-range input, carry
//! actionable guidance, and that the wording is uniform across every parser
//! (one shared formatter, no drift).

use keyhog::testing::{CliTestApi as _, API};
use std::path::Path;

// ── valid inputs still parse (no regression in the happy path) ────────────────

#[test]
fn min_confidence_accepts_lower_bound() {
    assert_eq!(API.parse_min_confidence("0.0").unwrap(), 0.0);
}

#[test]
fn min_confidence_accepts_upper_bound() {
    assert_eq!(API.parse_min_confidence("1.0").unwrap(), 1.0);
}

#[test]
fn decode_depth_accepts_valid() {
    assert_eq!(API.parse_decode_depth("3").unwrap(), 3);
}

#[test]
fn positive_millis_accepts_valid() {
    assert_eq!(API.parse_positive_millis("500").unwrap(), 500);
}

#[test]
fn daemon_request_timeout_accepts_valid() {
    assert_eq!(API.parse_daemon_request_timeout_secs("30").unwrap(), 30);
}

// ── parse-failure branches: range + example present (the real gap) ────────────

#[test]
fn min_confidence_unparseable_states_range_and_example() {
    let e = API.parse_min_confidence("high").unwrap_err();
    assert!(e.contains("a value in [0.0, 1.0]"), "must state range: {e}");
    assert!(e.contains("example: 0.85"), "must give example: {e}");
}

#[test]
fn verify_rate_unparseable_states_range_and_example() {
    let e = API.parse_verify_rate("fast").unwrap_err();
    assert!(
        e.contains("a positive rate in (0, 10000] rps"),
        "must state range: {e}"
    );
    assert!(e.contains("example: 50"), "must give example: {e}");
}

#[test]
fn ml_threshold_unparseable_states_range_and_example() {
    let e = API.parse_ml_threshold("xyz").unwrap_err();
    assert!(e.contains("a value in [0.0, 1.0]"), "must state range: {e}");
    assert!(e.contains("example: 0.5"), "must give example: {e}");
}

#[test]
fn decode_depth_unparseable_states_range_and_example() {
    let e = API.parse_decode_depth("deep").unwrap_err();
    assert!(e.contains("an integer in [1,"), "must state range: {e}");
    assert!(e.contains("example: 3"), "must give example: {e}");
}

#[test]
fn min_secret_len_unparseable_states_form_and_example() {
    let e = API.parse_min_secret_len("ten").unwrap_err();
    assert!(
        e.contains("a positive integer (>= 1)"),
        "must state form: {e}"
    );
    assert!(e.contains("example: 16"), "must give example: {e}");
}

#[test]
fn thread_count_unparseable_states_form_and_example() {
    let e = API.parse_positive_thread_count("lots").unwrap_err();
    assert!(
        e.contains("a positive integer (>= 1)"),
        "must state form: {e}"
    );
    assert!(e.contains("example: 4"), "must give example: {e}");
}

#[test]
fn positive_usize_unparseable_states_form_and_example() {
    let e = API.parse_positive_usize("x").unwrap_err();
    assert!(
        e.contains("a positive integer (>= 1)"),
        "must state form: {e}"
    );
    assert!(e.contains("example: 1"), "must give example: {e}");
}

#[test]
fn positive_millis_unparseable_states_form_and_example() {
    let e = API.parse_positive_millis("soon").unwrap_err();
    assert!(e.contains("milliseconds (>= 1)"), "must state form: {e}");
    assert!(e.contains("example: 500"), "must give example: {e}");
}

#[test]
fn daemon_request_timeout_unparseable_states_form_and_example() {
    let e = API.parse_daemon_request_timeout_secs("soon").unwrap_err();
    assert!(e.contains("seconds (>= 1)"), "must state form: {e}");
    assert!(e.contains("example: 30"), "must give example: {e}");
}

// ── out-of-range branches: constraint + example (and pinned legacy wording) ───

#[test]
fn min_confidence_out_of_range_keeps_pinned_wording() {
    // Other tests (flag_surface.rs) assert this exact substring (do not drift).
    let e = API.parse_min_confidence("1.5").unwrap_err();
    assert!(
        e.contains("min_confidence must be between 0.0 and 1.0"),
        "{e}"
    );
    // Routed through the shared out_of_range() owner, so the range branch now
    // carries a concrete in-range example like every sibling parser.
    assert!(e.contains("example: 0.85"), "must give example: {e}");
}

#[test]
fn ml_threshold_out_of_range_keeps_pinned_wording() {
    let e = API.parse_ml_threshold("2.0").unwrap_err();
    assert!(
        e.contains("--ml-threshold must be between 0.0 and 1.0"),
        "{e}"
    );
    assert!(e.contains("example: 0.5"), "must give example: {e}");
}

#[test]
fn verify_rate_non_positive_points_to_no_verify() {
    let e = API.parse_verify_rate("0").unwrap_err();
    assert!(
        e.contains("--no-verify"),
        "non-positive rate must point at the disable flag: {e}"
    );
}

#[test]
fn verify_rate_above_cap_names_the_cap() {
    let e = API.parse_verify_rate("20000").unwrap_err();
    assert!(e.contains("sanity cap"), "{e}");
}

#[test]
fn decode_depth_zero_states_range() {
    let e = API.parse_decode_depth("0").unwrap_err();
    assert!(e.contains("decode depth must be between 1 and"), "{e}");
    assert!(e.contains("example: 3"), "must give example: {e}");
}

#[test]
fn min_secret_len_zero_states_bound_and_example() {
    let e = API.parse_min_secret_len("0").unwrap_err();
    assert!(
        e.contains("--min-secret-len must be >= 1"),
        "must state bound: {e}"
    );
    assert!(e.contains("example: 16"), "must give example: {e}");
}

#[test]
fn thread_count_zero_states_bound_and_example() {
    let e = API.parse_positive_thread_count("0").unwrap_err();
    assert!(
        e.contains("--threads must be >= 1"),
        "must state bound: {e}"
    );
    assert!(e.contains("example: 4"), "must give example: {e}");
}

#[test]
fn positive_usize_zero_states_bound_and_example() {
    let e = API.parse_positive_usize("0").unwrap_err();
    assert!(e.contains("value must be >= 1"), "must state bound: {e}");
    assert!(e.contains("example: 1"), "must give example: {e}");
}

#[test]
fn positive_millis_zero_states_bound_and_example() {
    let e = API.parse_positive_millis("0").unwrap_err();
    assert!(
        e.contains("millisecond timeout must be >= 1"),
        "must state bound: {e}"
    );
    assert!(e.contains("example: 500"), "must give example: {e}");
}

#[test]
fn daemon_request_timeout_zero_states_bound_and_example() {
    let e = API.parse_daemon_request_timeout_secs("0").unwrap_err();
    assert!(
        e.contains("--request-timeout-secs must be >= 1"),
        "must state bound: {e}"
    );
    assert!(e.contains("example: 30"), "must give example: {e}");
}

// ── uniformity: the shared formatters keep every message shaped identically ───

/// Every unparseable-input rejection across the numeric parsers.
fn all_unparseable_errors() -> Vec<String> {
    vec![
        API.parse_min_confidence("x").unwrap_err(),
        API.parse_verify_rate("x").unwrap_err(),
        API.parse_ml_threshold("x").unwrap_err(),
        API.parse_decode_depth("x").unwrap_err(),
        API.parse_min_secret_len("x").unwrap_err(),
        API.parse_positive_thread_count("x").unwrap_err(),
        API.parse_positive_usize("x").unwrap_err(),
        API.parse_positive_millis("x").unwrap_err(),
        API.parse_daemon_request_timeout_secs("x").unwrap_err(),
    ]
}

#[test]
fn every_unparseable_message_starts_uniformly() {
    for e in all_unparseable_errors() {
        assert!(e.starts_with("not a valid "), "non-uniform prefix: {e}");
    }
}

#[test]
fn every_unparseable_message_carries_an_example() {
    for e in all_unparseable_errors() {
        assert!(e.contains("; example: "), "missing example clause: {e}");
        assert!(e.contains("Expected "), "missing expected clause: {e}");
    }
}

// ── path validation: the not-found / access errors point at a concrete fix ────

#[test]
fn nonexistent_scan_path_suggests_parent_and_cwd() {
    let missing = Path::new("/keyhog/no/such/path/definitely-not-here-9f3a2");
    let e = API
        .validate_cli_path_arg(missing, "scan path")
        .unwrap_err()
        .to_string();
    assert!(e.contains("does not exist"), "must name the condition: {e}");
    assert!(
        e.contains("parent directory"),
        "must suggest the parent-dir fix: {e}"
    );
    assert!(e.contains("scan path"), "must echo the argument name: {e}");
}

#[test]
fn nonexistent_path_does_not_claim_permission_or_filesystem_fault() {
    // A plain missing path must not be mislabeled as a permissions/mount issue.
    let missing = Path::new("/keyhog/no/such/path/definitely-not-here-7c1b8");
    let e = API
        .validate_cli_path_arg(missing, "input")
        .unwrap_err()
        .to_string();
    assert!(
        !e.contains("permission denied"),
        "missing != permission denied: {e}"
    );
}

#[test]
fn every_lower_bound_zero_message_carries_an_example() {
    let zeros = [
        API.parse_min_secret_len("0").unwrap_err(),
        API.parse_positive_thread_count("0").unwrap_err(),
        API.parse_positive_usize("0").unwrap_err(),
        API.parse_positive_millis("0").unwrap_err(),
        API.parse_daemon_request_timeout_secs("0").unwrap_err(),
    ];
    for e in zeros {
        assert!(e.contains("; example: "), "missing example clause: {e}");
        assert!(e.contains(">= 1"), "missing the >= 1 bound: {e}");
    }
}
