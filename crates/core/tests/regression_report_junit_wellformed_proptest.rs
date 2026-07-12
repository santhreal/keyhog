//! Property contract: the JUnit reporter must emit WELL-FORMED XML for EVERY
//! finding, no matter how hostile its fields. This is the integration layer
//! above regression_report_escape_invariants.rs (which proves the escape/CDATA
//! primitives in isolation): here we prove the JUnit formatter actually USES
//! those primitives on every field it writes — a formatter that forgot to escape
//! one attribute or CDATA body would produce XML a CI JUnit consumer rejects, or
//! (worse) let an attacker-controlled file path / detector name / redacted
//! credential inject markup.
//!
//! The existing regression_report_junit_xml.rs pins exact bytes for crafted
//! inputs; this pins the "parses clean for ALL inputs" invariant that fixed
//! vectors can't cover. Validated with a real XML reader (quick-xml), driven
//! through the public `write_report(_, ReportFormat::Junit, _)` entrypoint.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{
    write_report, MatchLocation, ReportFormat, Severity, VerificationResult, VerifiedFinding,
};
use proptest::prelude::*;
use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// Parse `xml` end-to-end with a real reader; `Err` on any well-formedness fault
/// (unescaped `<`/`&`, unbalanced quotes in an attribute, mismatched or
/// prematurely-closed tags, a CDATA breakout that unbalances the tree).
fn xml_well_formed(xml: &str) -> Result<(), String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().check_end_names = true;
    loop {
        match reader.read_event() {
            Ok(Event::Eof) => return Ok(()),
            Ok(_) => {}
            Err(e) => return Err(format!("{e}")),
        }
    }
}

/// Field strings mixing known injection tokens (`]]>` CDATA breakout, raw
/// markup, attribute-quote escapes, entities, XML-illegal controls) with random
/// Unicode — far more adversarial than uniform random, which almost never emits
/// the exact `]]>` or a balanced-looking `<tag>`.
fn arb_hostile_field() -> impl Strategy<Value = String> {
    let fragment = prop_oneof![
        Just("]]>".to_string()),
        Just("<inject>".to_string()),
        Just("</failure>".to_string()),
        Just("\" onload=\"x".to_string()),
        Just("' /><evil".to_string()),
        Just("a & b < c > d".to_string()),
        Just("&amp; &#x41;".to_string()),
        Just("\u{1}\u{7}\u{1B}\u{7F}\u{85}".to_string()),
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
        detector_id in arb_hostile_field(),
        detector_name in arb_hostile_field(),
        service in arb_hostile_field(),
        credential in arb_hostile_field(),
        source in arb_hostile_field(),
        file_path in prop::option::of(arb_hostile_field()),
        author in prop::option::of(arb_hostile_field()),
        commit in prop::option::of(arb_hostile_field()),
        date in prop::option::of(arb_hostile_field()),
        error_msg in prop::option::of(arb_hostile_field()),
        line in prop::option::of(0usize..1_000_000),
        offset in 0usize..1_000_000,
        sev_idx in 0usize..6,
        confidence in prop::option::of(0.0f64..1.0),
    ) -> VerifiedFinding {
        VerifiedFinding {
            detector_id: Arc::from(detector_id.as_str()),
            detector_name: Arc::from(detector_name.as_str()),
            service: Arc::from(service.as_str()),
            severity: severity_at(sev_idx),
            credential_redacted: Cow::Owned(credential),
            credential_hash: [0u8; 32].into(),
            location: MatchLocation {
                source: Arc::from(source.as_str()),
                file_path: opt_arc(file_path),
                line,
                offset,
                commit: opt_arc(commit),
                author: opt_arc(author),
                date: opt_arc(date),
            },
            verification: match error_msg {
                Some(msg) => VerificationResult::Error(msg),
                None => VerificationResult::Live,
            },
            metadata: HashMap::new(),
            additional_locations: vec![],
            confidence,
        }
    }
}

fn render_junit(findings: &[VerifiedFinding]) -> String {
    let mut buf: Vec<u8> = Vec::new();
    write_report(&mut buf, ReportFormat::Junit, findings).expect("junit write_report");
    String::from_utf8(buf).expect("utf8 junit output")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    #[test]
    fn a_single_hostile_finding_renders_well_formed_junit(finding in arb_finding()) {
        let out = render_junit(&[finding]);
        prop_assert!(
            xml_well_formed(&out).is_ok(),
            "JUnit output is not well-formed XML: {:?}\n---\n{out}",
            xml_well_formed(&out)
        );
        // Belt-and-suspenders: no XML-1.0-illegal control codepoint survives.
        prop_assert!(
            !out.chars().any(|c| { let u = c as u32; u < 0x20 && !matches!(u, 0x09 | 0x0A | 0x0D) }),
            "JUnit output carries an XML-illegal control byte"
        );
    }

    #[test]
    fn many_hostile_findings_render_well_formed_junit(findings in prop::collection::vec(arb_finding(), 0..6)) {
        // A batch also exercises the per-finding element boundaries: a breakout
        // in finding N must not corrupt the framing of finding N+1.
        let out = render_junit(&findings);
        prop_assert!(
            xml_well_formed(&out).is_ok(),
            "multi-finding JUnit is not well-formed: {:?}",
            xml_well_formed(&out)
        );
    }
}

// ── Fixed adversarial vectors (exact breakout attempts) ────────────────────

fn base_finding() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Key"),
        service: Arc::from("aws"),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("AKIA...7XYA"),
        credential_hash: [0u8; 32].into(),
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
fn a_cdata_breakout_in_the_credential_stays_well_formed() {
    let mut f = base_finding();
    // Close the CDATA early, then try to inject a sibling element.
    f.credential_redacted = Cow::Owned("AK]]><injected>evil</injected><![CDATA[IA".to_string());
    let out = render_junit(&[f]);
    assert!(
        xml_well_formed(&out).is_ok(),
        "CDATA breakout must not unbalance the document: {out}"
    );
    // The neutralized terminator appears; a lone raw one does not.
    assert!(
        out.contains("]]]]><![CDATA[>"),
        "terminator not neutralized: {out}"
    );
}

#[test]
fn an_attribute_breakout_in_the_detector_name_stays_well_formed() {
    let mut f = base_finding();
    // The detector name flows into the `<failure message="...">` attribute.
    f.detector_name = Arc::from("x\" type=\"low\"><injected/><failure message=\"y");
    let out = render_junit(&[f]);
    assert!(
        xml_well_formed(&out).is_ok(),
        "attribute breakout must not inject markup: {out}"
    );
    // Well-formedness already proves the ATTRIBUTE didn't break out (a raw `">`
    // there would unbalance the tree). The name also appears VERBATIM in the
    // CDATA body (CDATA is literal text — that's correct, not a leak), so the
    // meaningful check is that the attribute copy was entity-escaped.
    assert!(
        out.contains("&quot;"),
        "the detector-name quote must be entity-escaped in the failure attribute: {out}"
    );
}

#[test]
fn a_file_path_breakout_in_the_testcase_name_stays_well_formed() {
    let mut f = base_finding();
    // file_path drives the `<testcase name="...">` attribute.
    f.location.file_path = Some(Arc::from("a\"/><injected/><testcase name=\"b"));
    let out = render_junit(&[f]);
    assert!(
        xml_well_formed(&out).is_ok(),
        "file-path attribute breakout must stay well-formed: {out}"
    );
}
