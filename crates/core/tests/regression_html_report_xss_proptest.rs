//! Property contract: the HTML reporter must never let a finding field break out
//! of its inlined `<script>` element, for ANY finding. The reporter serializes
//! findings to JSON and inlines them as `<script>` raw text; `escape_for_script`
//! `\u`-escapes `<`, `>`, `/`, U+2028, U+2029 so no attacker-controlled field
//! (file path, git author/commit/date, redacted credential, service, detector
//! name, metadata) can emit a literal `</script>` (or open a new tag) and run
//! injected markup (stored XSS into a dashboard that renders the report).
//!
//! regression_html_report_script_breakout_xss.rs pins this for one crafted
//! payload; this proves the invariant holds for arbitrary hostile findings: the
//! rendered report always contains EXACTLY the template's single `</script>`
//! close (and single `<script` open), a finding can never add another, and
//! the raw JS-statement-terminating separators never survive.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{
    write_report, MatchLocation, ReportFormat, Severity, VerificationResult, VerifiedFinding,
};
use proptest::prelude::*;

/// Field strings mixing HTML/script breakout tokens with random Unicode.
fn arb_xss_field() -> impl Strategy<Value = String> {
    let fragment = prop_oneof![
        Just("</script>".to_string()),
        Just("<script>alert(1)</script>".to_string()),
        Just("<img src=x onerror=alert(1)>".to_string()),
        Just("<svg/onload=alert(1)>".to_string()),
        Just("<!--".to_string()),
        Just("-->".to_string()),
        Just("</SCRIPT >".to_string()),
        Just("\u{2028}\u{2029}".to_string()),
        Just("\\u003c/script\\u003e".to_string()),
        prop::collection::vec(any::<char>(), 0..16).prop_map(|v| v.into_iter().collect::<String>()),
    ];
    prop::collection::vec(fragment, 0..5).prop_map(|parts| parts.concat())
}

fn severity_at(idx: usize) -> Severity {
    match idx % 6 {
        0 => Severity::Info,
        1 => Severity::ClientSafe,
        2 => Severity::Low,
        3 => Severity::Medium,
        4 => Severity::High,
        _ => Severity::Critical,
    }
}

fn opt_arc(s: Option<String>) -> Option<Arc<str>> {
    s.map(|s| Arc::from(s.as_str()))
}

prop_compose! {
    fn arb_finding()(
        detector_id in arb_xss_field(),
        detector_name in arb_xss_field(),
        service in arb_xss_field(),
        credential in arb_xss_field(),
        source in arb_xss_field(),
        file_path in prop::option::of(arb_xss_field()),
        author in prop::option::of(arb_xss_field()),
        commit in prop::option::of(arb_xss_field()),
        date in prop::option::of(arb_xss_field()),
        meta in prop::collection::vec((arb_xss_field(), arb_xss_field()), 0..3),
        line in prop::option::of(0usize..1_000_000),
        sev_idx in 0usize..6,
        confidence in prop::option::of(0.0f64..1.0),
    ) -> VerifiedFinding {
        let metadata: HashMap<String, String> = meta.into_iter().collect();
        VerifiedFinding {
            detector_id: Arc::from(detector_id.as_str()),
            detector_name: Arc::from(detector_name.as_str()),
            service: Arc::from(service.as_str()),
            severity: severity_at(sev_idx),
            credential_redacted: Cow::Owned(credential),
            credential_hash: [0u8; 32].into(),
        companions_redacted: std::collections::HashMap::new(),
            location: MatchLocation {
                source: Arc::from(source.as_str()),
                file_path: opt_arc(file_path),
                line,
                offset: 0,
                commit: opt_arc(commit),
                author: opt_arc(author),
                date: opt_arc(date),
            },
            verification: VerificationResult::Live,
            metadata,
            additional_locations: vec![],
            confidence,
        }
    }
}

fn render_html(findings: &[VerifiedFinding]) -> String {
    let mut buf: Vec<u8> = Vec::new();
    write_report(
        &mut buf,
        ReportFormat::Html {
            skip_summary: Vec::new(),
            metadata: None,
        },
        findings,
    )
    .expect("finish html report");
    String::from_utf8(buf).expect("utf8 html output")
}

/// The template's own script-tag counts, established from the empty report so
/// the properties compare against ground truth rather than a hardcoded number.
fn baseline_script_counts() -> (usize, usize) {
    let empty = render_html(&[]);
    (
        empty.matches("</script>").count(),
        empty.matches("<script").count(),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    #[test]
    fn a_hostile_finding_cannot_add_a_script_tag(finding in arb_finding()) {
        let (base_close, base_open) = baseline_script_counts();
        let out = render_html(&[finding]);
        prop_assert_eq!(
            out.matches("</script>").count(),
            base_close,
            "a finding field injected an extra </script> (XSS breakout)"
        );
        prop_assert_eq!(
            out.matches("<script").count(),
            base_open,
            "a finding field injected an extra <script open tag"
        );
        // The raw JS line/paragraph separators must be escaped, never emitted
        // literally (they terminate a JS statement even inside a JSON string).
        prop_assert!(!out.contains('\u{2028}'), "raw U+2028 survived into the script");
        prop_assert!(!out.contains('\u{2029}'), "raw U+2029 survived into the script");
    }

    #[test]
    fn a_batch_of_hostile_findings_cannot_add_a_script_tag(findings in prop::collection::vec(arb_finding(), 0..6)) {
        let (base_close, _) = baseline_script_counts();
        let out = render_html(&findings);
        prop_assert_eq!(
            out.matches("</script>").count(),
            base_close,
            "a finding in the batch injected an extra </script>"
        );
    }
}

// ── Fixed adversarial vectors ──────────────────────────────────────────────

fn base_finding() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Key"),
        service: Arc::from("aws"),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("AKIA...7XYA"),
        credential_hash: [0u8; 32].into(),
        companions_redacted: std::collections::HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("config/app.env")),
            line: Some(12),
            offset: 5,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Live,
        metadata: HashMap::new(),
        additional_locations: vec![],
        confidence: Some(0.5),
    }
}

#[test]
fn a_script_close_in_every_field_never_breaks_out() {
    let (base_close, _) = baseline_script_counts();
    let payload = "</script><img src=x onerror=alert(1)>";
    let mut f = base_finding();
    f.detector_id = Arc::from(payload);
    f.detector_name = Arc::from(payload);
    f.service = Arc::from(payload);
    f.credential_redacted = Cow::Owned(payload.to_string());
    f.location.file_path = Some(Arc::from(payload));
    f.location.author = Some(Arc::from(payload));
    f.location.commit = Some(Arc::from(payload));
    f.location.date = Some(Arc::from(payload));
    f.metadata
        .insert("account_id".to_string(), payload.to_string());
    let out = render_html(&[f]);
    assert_eq!(
        out.matches("</script>").count(),
        base_close,
        "payload in every field must not add a </script>: {out}"
    );
    assert!(!out.contains(payload), "raw payload leaked: {out}");
    // The neutralized form proves the data survived, just escaped.
    assert!(
        out.contains("\\u003c\\u002fscript\\u003e"),
        "escaped </script> not present: escaping did not run"
    );
}

#[test]
fn the_empty_report_has_exactly_one_script_block() {
    let (close, open) = baseline_script_counts();
    assert_eq!(close, 1, "template must emit exactly one </script>");
    assert_eq!(open, 1, "template must emit exactly one <script open tag");
}
