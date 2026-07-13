//! Regression: EXACT human/terminal (`ReportFormat::Text`) rendering contract.
//!
//! These tests pin the concrete bytes the human reporter ships for a KNOWN
//! [`VerifiedFinding`] set, exercising the ONE public surface a caller uses:
//! [`keyhog_core::write_report`] with [`ReportFormat::Text`]. Everything below
//! the trait (`TextReporter`, `report::style`) is `pub(crate)` and unreachable
//! from an integration test, which is exactly why the assertions here are the
//! operator-visible contract, not internal shapes.
//!
//! What is pinned:
//!   * the per-finding box header carries the human detector NAME and the
//!     right-aligned severity LABEL (`{:>11}`), while the internal detector_id
//!     is NOT leaked into human text;
//!   * the redacted secret, and `file:line` (and path-only when the line is
//!     unknown), render on their labeled lines with exact spacing;
//!   * the confidence bar glyphs + percentage are exact;
//!   * the `Results` roll-up counts findings EXACTLY, with singular/plural and
//!     the live / dead(=Dead∪Revoked) / unverified split;
//!   * a clean scan renders the honest "No secrets detected in the scanned
//!     files." line and NEVER claims "clean";
//!   * the example-suppression empty line phrasing (singular/plural, dogfood);
//!   * COLOR IS A PURE FUNCTION OF THE `color` FLAG: `color:false` (what the CLI
//!     resolves `NO_COLOR` to) emits ZERO ANSI escape bytes; `color:true` wraps
//!     the severity label in the exact SGR sequence;
//!   * an attacker-controlled redacted value cannot inject an ANSI escape, it
//!     is neutralized to U+FFFD even when the reporter itself runs uncolored.
//!
//! Host-independence: `write_report` is a pure formatter over an in-memory
//! `&[VerifiedFinding]`. It never touches an accelerator, so every assertion
//! holds identically on any host. Every assertion is a specific value.

use std::borrow::Cow;
use std::collections::HashMap;

use keyhog_core::{
    write_report, CredentialHash, MatchLocation, ReportFormat, Severity, VerificationResult,
    VerifiedFinding,
};

/// ESC byte. Its presence in output means ANSI/SGR coloring was emitted.
const ESC: char = '\u{1b}';

/// Build a finding with an explicit detector id/name, severity, redacted form,
/// verification, confidence and a filesystem `path:line` location.
fn finding(
    detector_id: &'static str,
    detector_name: &'static str,
    service: &'static str,
    severity: Severity,
    redacted: &'static str,
    verification: VerificationResult,
    line: Option<usize>,
    confidence: Option<f64>,
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: detector_id.into(),
        detector_name: detector_name.into(),
        service: service.into(),
        severity,
        credential_redacted: Cow::Borrowed(redacted),
        credential_hash: CredentialHash::from_bytes([0x11; 32]),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some("config/app.env".into()),
            line,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification,
        metadata: HashMap::new(),
        additional_locations: vec![],
        confidence,
    }
}

/// Canonical High AWS finding at `config/app.env:7`, confidence 0.9, unverified.
fn aws_high() -> VerifiedFinding {
    finding(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        VerificationResult::Unverifiable,
        Some(7),
        Some(0.9),
    )
}

/// Render the text report for `findings` with the given color/suppression flags.
fn render_text_full(
    findings: &[VerifiedFinding],
    color: bool,
    example_suppressions: usize,
    dogfood_active: bool,
) -> String {
    let mut buf = Vec::new();
    write_report(
        &mut buf,
        ReportFormat::Text {
            color,
            example_suppressions,
            dogfood_active,
        },
        findings,
    )
    .expect("write_report(Text) must succeed");
    String::from_utf8(buf).expect("text output must be valid UTF-8")
}

/// Uncolored render with no suppressions (the common case).
fn render_text(findings: &[VerifiedFinding]) -> String {
    render_text_full(findings, false, 0, false)
}

// ---------------------------------------------------------------------------
// Per-finding box: detector name, severity label, redacted, location
// ---------------------------------------------------------------------------

/// Positive: the box header renders the human detector NAME after the `───`
/// rule and the right-aligned (`{:>11}`) severity label. "HIGH" pads to
/// 7 leading spaces.
#[test]
fn text_header_has_name_and_right_aligned_severity() {
    let text = render_text(&[aws_high()]);
    assert!(
        text.contains("─── AWS Access Key"),
        "header must render the detector NAME after the rule, got:\n{text}"
    );
    assert!(
        text.contains("       HIGH"),
        "severity label must be right-aligned to width 11 (7 spaces + HIGH), got:\n{text}"
    );
}

/// Negative twin: the internal `detector_id` string is NOT surfaced in human
/// text (unlike SARIF's `ruleId`). The human report shows the display name.
#[test]
fn text_does_not_leak_internal_detector_id() {
    // A detector id that is verbatim-distinct from its display name and from
    // any remediation text, so its appearance could only come from the header.
    let f = finding(
        "zzz-internal-detector-id-9x7",
        "Display Name Only",
        "no-such-service-xyz",
        Severity::Medium,
        "tok_****",
        VerificationResult::Unverifiable,
        Some(3),
        Some(0.5),
    );
    let text = render_text(&[f]);
    assert!(
        text.contains("─── Display Name Only"),
        "header must show the display NAME, got:\n{text}"
    );
    assert!(
        !text.contains("zzz-internal-detector-id-9x7"),
        "internal detector_id must NOT appear in human text, got:\n{text}"
    );
}

/// Positive: the redacted secret renders on the `Secret:` line with the exact
/// spacing (`"Secret:    "` label + one separator space).
#[test]
fn text_secret_line_exact_spacing() {
    let text = render_text(&[aws_high()]);
    assert!(
        text.contains("Secret:     AKIA****"),
        "redacted secret must render as 'Secret:     AKIA****' (5 spaces), got:\n{text}"
    );
}

/// Positive: a `path:line` location renders as `file:line` on the Location line
/// with exact spacing (`"Location:  "` label + one separator space).
#[test]
fn text_location_file_and_line_exact() {
    let text = render_text(&[aws_high()]);
    assert!(
        text.contains("Location:   config/app.env:7"),
        "location must render as 'Location:   config/app.env:7', got:\n{text}"
    );
}

/// Boundary: when the line number is unknown the location is the bare path 
/// no trailing `:` and no fabricated line number.
#[test]
fn text_location_path_only_when_line_unknown() {
    let f = finding(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        VerificationResult::Unverifiable,
        None,
        Some(0.9),
    );
    let text = render_text(&[f]);
    assert!(
        text.contains("Location:   config/app.env"),
        "path-only location must still render the path, got:\n{text}"
    );
    assert!(
        !text.contains("config/app.env:"),
        "a missing line must NOT produce a trailing ':', got:\n{text}"
    );
}

/// Positive: confidence 0.9 fills 5 of 6 bar cells and prints `90%`.
#[test]
fn text_confidence_bar_and_percent_for_high_confidence() {
    let text = render_text(&[aws_high()]);
    assert!(
        text.contains("■■■■■□"),
        "confidence 0.9 must fill 5/6 bar cells, got:\n{text}"
    );
    assert!(
        text.contains("90%"),
        "confidence 0.9 must render '90%', got:\n{text}"
    );
}

/// Adversarial: `confidence` is a public field, so a library-constructed finding
/// can carry an OUT-OF-RANGE score. The reporter sanitizes into [0,1] so the bar
/// and percent agree and never render ">100%". Derived from `report/text.rs`:
/// `display_conf = clamp(0,1)`, `filled = (display_conf*6).min(6)`.
#[test]
fn text_confidence_over_one_clamps_to_full_bar_and_100_percent() {
    let f = finding(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        VerificationResult::Unverifiable,
        Some(7),
        Some(1.5), // out of range via the public field
    );
    let text = render_text(&[f]);
    assert!(
        text.contains("■■■■■■"),
        "over-range confidence must fill all 6 cells, got:\n{text}"
    );
    assert!(
        text.contains("100%"),
        "over-range confidence must clamp to '100%', got:\n{text}"
    );
    assert!(
        !text.contains("150%") && !text.contains("101%"),
        "no percentage above 100 may render, got:\n{text}"
    );
}

/// Adversarial: a NaN confidence (public field, no scanner sanitize) renders as
/// `0%` and an empty bar, never a `NaN` glyph, matching the scanner's
/// `finalize_confidence` NaN -> minimum. `f64::clamp` alone does NOT sanitize
/// NaN, so the reporter guards `is_finite()` explicitly.
#[test]
fn text_confidence_nan_renders_zero_percent_empty_bar() {
    let f = finding(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        VerificationResult::Unverifiable,
        Some(7),
        Some(f64::NAN),
    );
    let text = render_text(&[f]);
    assert!(
        text.contains("□□□□□□"),
        "NaN confidence must render a fully empty 6-cell bar, got:\n{text}"
    );
    assert!(
        text.contains("0%"),
        "NaN confidence must render '0%', got:\n{text}"
    );
    assert!(
        !text.to_lowercase().contains("nan"),
        "NaN must never leak into the rendered percent, got:\n{text}"
    );
}

/// Boundary: absent confidence renders an empty bar and `0%` (LAW10: the
/// finding is still printed with a display-only zeroed bar, never dropped).
#[test]
fn text_confidence_absent_renders_empty_bar_zero_percent() {
    let f = finding(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        VerificationResult::Unverifiable,
        Some(7),
        None,
    );
    let text = render_text(&[f]);
    assert!(
        text.contains("□□□□□□"),
        "absent confidence must render a fully-empty bar, got:\n{text}"
    );
    assert!(
        text.contains("0%"),
        "absent confidence must render '0%', got:\n{text}"
    );
}

/// Positive: a Live finding appends the `(LIVE)` verification suffix on the
/// Confidence line.
#[test]
fn text_live_finding_shows_live_suffix() {
    let f = finding(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::Critical,
        "AKIA****",
        VerificationResult::Live,
        Some(7),
        Some(0.9),
    );
    let text = render_text(&[f]);
    assert!(
        text.contains("(LIVE)"),
        "a live finding must render the '(LIVE)' verification suffix, got:\n{text}"
    );
}

// ---------------------------------------------------------------------------
// Results roll-up: exact counts and live/dead/unverified split
// ---------------------------------------------------------------------------

/// Boundary: a single finding uses the SINGULAR "1 secret found" (no trailing
/// 's'), and never the plural form.
#[test]
fn text_summary_single_is_singular() {
    let text = render_text(&[aws_high()]);
    assert!(
        text.contains("1 secret found"),
        "one finding must read '1 secret found', got:\n{text}"
    );
    assert!(
        !text.contains("1 secrets found"),
        "singular count must not be pluralized, got:\n{text}"
    );
}

/// Positive: three findings count EXACTLY as "3 secrets found" (plural).
#[test]
fn text_summary_counts_three_exactly() {
    let text = render_text(&[aws_high(), aws_high(), aws_high()]);
    assert!(
        text.contains("3 secrets found"),
        "three findings must read '3 secrets found', got:\n{text}"
    );
    assert!(
        !text.contains("2 secrets found") && !text.contains("4 secrets found"),
        "the count must be exact, got:\n{text}"
    );
}

/// Positive: a Live + an Unverifiable finding roll up as "2 secrets found",
/// with "1 live" and "1 unverified" and NO "dead".
#[test]
fn text_summary_live_and_unverified_split() {
    let live = finding(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        VerificationResult::Live,
        Some(7),
        Some(0.9),
    );
    let text = render_text(&[live, aws_high()]);
    assert!(text.contains("2 secrets found"), "got:\n{text}");
    assert!(
        text.contains("1 live"),
        "one live must show '1 live', got:\n{text}"
    );
    assert!(
        text.contains("1 unverified"),
        "the Unverifiable finding must show '1 unverified', got:\n{text}"
    );
    assert!(
        !text.contains("dead"),
        "no verified-inactive finding, so no 'dead' tally, got:\n{text}"
    );
}

/// Boundary: Dead and Revoked BOTH fold into the inactive ("dead") tally, so a
/// Dead + Revoked pair reads "2 dead" with zero "unverified".
#[test]
fn text_summary_dead_and_revoked_both_count_dead() {
    let dead = finding(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        VerificationResult::Dead,
        Some(7),
        Some(0.9),
    );
    let revoked = finding(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        VerificationResult::Revoked,
        Some(8),
        Some(0.9),
    );
    let text = render_text(&[dead, revoked]);
    assert!(text.contains("2 secrets found"), "got:\n{text}");
    assert!(
        text.contains("2 dead"),
        "Dead∪Revoked must roll into '2 dead', got:\n{text}"
    );
    assert!(
        !text.contains("unverified"),
        "verified-inactive findings must not appear as unverified, got:\n{text}"
    );
}

/// Positive: the roll-up ships the `Results` banner and the three numbered
/// next-step lines verbatim.
#[test]
fn text_summary_banner_and_next_steps() {
    let text = render_text(&[aws_high()]);
    assert!(
        text.contains("━━━ Results"),
        "results banner missing, got:\n{text}"
    );
    assert!(
        text.contains("1. Revoke active secrets in the provider's dashboard."),
        "step 1 text missing, got:\n{text}"
    );
    assert!(
        text.contains("2. Remove credentials from codebase and git history."),
        "step 2 text missing, got:\n{text}"
    );
    assert!(
        text.contains("3. Use a secure secret manager or environment variables."),
        "step 3 text missing, got:\n{text}"
    );
}

// ---------------------------------------------------------------------------
// Empty scan: honest "no findings" phrasing
// ---------------------------------------------------------------------------

/// Positive: a clean scan renders the exact honest line and NEVER claims the
/// code is "clean" (absence of secrets is unprovable) nor prints a count.
#[test]
fn text_empty_scan_honest_no_secrets_line() {
    let text = render_text(&[]);
    assert!(
        text.contains("No secrets detected in the scanned files."),
        "clean scan must render the exact honest line, got:\n{text}"
    );
    assert!(
        !text.to_lowercase().contains("clean"),
        "must never claim the code is 'clean', got:\n{text}"
    );
    assert!(
        !text.contains("secret found") && !text.contains("secrets found"),
        "clean scan must print no found-count, got:\n{text}"
    );
}

/// Boundary: with suppressed example keys and plural count (2), the empty line
/// swaps to the suppression phrasing with the `--dogfood` hint and drops the
/// honest "No secrets detected" line.
#[test]
fn text_empty_scan_example_suppressions_plural_hint() {
    let text = render_text_full(&[], false, 2, false);
    assert!(
        text.contains(
            "No real secrets, but 2 example/test keys suppressed. Pass --dogfood to see them."
        ),
        "plural suppression phrasing (with hint) mismatch, got:\n{text}"
    );
    assert!(
        !text.contains("No secrets detected in the scanned files."),
        "suppression line must replace the plain honest line, got:\n{text}"
    );
}

/// Boundary: a SINGLE suppressed key uses the singular "key" (no 's'), and when
/// `--dogfood` is already active the hint changes to point at the output above.
#[test]
fn text_empty_scan_single_suppression_dogfood_phrasing() {
    let text = render_text_full(&[], false, 1, true);
    assert!(
        text.contains("No real secrets, but 1 example/test key suppressed (see --dogfood output above for the full list)."),
        "singular + dogfood-active phrasing mismatch, got:\n{text}"
    );
    assert!(
        !text.contains("Pass --dogfood to see them"),
        "the 'Pass --dogfood' hint must be dropped when dogfood is already active, got:\n{text}"
    );
}

// ---------------------------------------------------------------------------
// Color contract (what NO_COLOR resolves to at the CLI) + injection defense
// ---------------------------------------------------------------------------

/// Adversarial/NO_COLOR contract: with `color:false` (the value the CLI resolves
/// `NO_COLOR` to) the ENTIRE report contains ZERO ANSI escape bytes, no SGR
/// coloring of any kind leaks through.
#[test]
fn text_no_color_emits_no_ansi_escapes() {
    let text = render_text(&[aws_high()]);
    assert!(
        !text.contains(ESC),
        "color:false must emit no ESC/ANSI bytes anywhere, got:\n{text:?}"
    );
    // And the empty-scan path is equally escape-free.
    let empty = render_text(&[]);
    assert!(
        !empty.contains(ESC),
        "color:false clean-scan must emit no ESC/ANSI bytes, got:\n{empty:?}"
    );
}

/// Positive twin: with `color:true` the severity label is wrapped in the exact
/// SGR sequence: HIGH uses `31`, Critical uses `1;31`: proving coloring is a
/// pure function of the flag, not the host.
#[test]
fn text_color_wraps_severity_label_in_exact_sgr() {
    let high = render_text_full(&[aws_high()], true, 0, false);
    assert!(
        high.contains("\u{1b}[31m       HIGH\u{1b}[0m"),
        "colored HIGH label must be exact SGR-31, got:\n{high:?}"
    );

    let critical_finding = finding(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::Critical,
        "AKIA****",
        VerificationResult::Unverifiable,
        Some(7),
        Some(0.9),
    );
    let crit = render_text_full(&[critical_finding], true, 0, false);
    assert!(
        crit.contains("\u{1b}[1;31m   CRITICAL\u{1b}[0m"),
        "colored CRITICAL label must be exact SGR-1;31, got:\n{crit:?}"
    );
}

/// Adversarial: an attacker-controlled redacted value that embeds a raw ANSI
/// escape sequence cannot inject color/terminal control, every control byte is
/// neutralized to U+FFFD, even though the reporter itself runs UNCOLORED.
#[test]
fn text_redacted_ansi_injection_is_neutralized() {
    let malicious = finding(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        // Raw ESC + SGR red + text + reset embedded in the redacted display.
        "\u{1b}[31mPWNED\u{1b}[0m",
        VerificationResult::Unverifiable,
        Some(7),
        Some(0.9),
    );
    let text = render_text(&[malicious]);
    assert!(
        !text.contains(ESC),
        "an injected ESC in the redacted value must be stripped, got:\n{text:?}"
    );
    assert!(
        text.contains('\u{FFFD}'),
        "stripped control bytes must be visible as U+FFFD, got:\n{text:?}"
    );
    assert!(
        !text.contains("\u{1b}[31mPWNED"),
        "the injected SGR escape sequence must not survive intact, got:\n{text:?}"
    );
    // The alphanumeric payload text itself is preserved (only controls die).
    assert!(
        text.contains("PWNED"),
        "non-control characters of the redacted value must survive, got:\n{text}"
    );
}
