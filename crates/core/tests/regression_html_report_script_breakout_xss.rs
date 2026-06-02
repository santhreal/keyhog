//! Regression test for the HTML report stored-XSS findings (C3/C6/C7).
//!
//! `HtmlReporter::finish` inlines `serde_json::to_string(&findings)` verbatim
//! into a `<script>` raw-text element. `serde_json` does not escape `<`, `>`,
//! or `/`, so an attacker-controlled finding field containing the literal
//! `</script>` (file path, git author, metadata, redacted credential preview,
//! ...) terminated the script element in the browser's HTML parser and ran the
//! injected markup. The fix `\u`-escapes `<`, `>`, and `/` before embedding the
//! JSON, so no extra `</script>` (or any tag close) can appear in the output.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{
    HtmlReporter, MatchLocation, Reporter, Severity, VerificationResult, VerifiedFinding,
};

const PAYLOAD: &str = "</script><img src=x onerror=alert(1)>";

fn poisoned_finding() -> VerifiedFinding {
    let mut metadata = HashMap::new();
    metadata.insert("account_id".to_string(), PAYLOAD.to_string());

    VerifiedFinding {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Key"),
        service: Arc::from("aws"),
        severity: Severity::High,
        credential_redacted: Cow::Owned(format!("AKIA...{PAYLOAD}")),
        credential_hash: [0u8; 32],
        location: MatchLocation {
            source: Arc::from("filesystem"),
            // Attacker-named file on disk: appears in location.file_path.
            file_path: Some(Arc::from(PAYLOAD)),
            line: Some(12),
            offset: 5,
            commit: Some(Arc::from(PAYLOAD)),
            // Attacker-authored git commit metadata.
            author: Some(Arc::from(PAYLOAD)),
            date: Some(Arc::from(PAYLOAD)),
        },
        verification: VerificationResult::Live,
        metadata,
        additional_locations: vec![],
        confidence: Some(0.5),
    }
}

fn render(finding: &VerifiedFinding) -> String {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut reporter = HtmlReporter::new(&mut buf);
        reporter.report(finding).expect("report finding");
        reporter.finish().expect("finish");
    }
    String::from_utf8(buf).expect("utf8 html output")
}

#[test]
fn poisoned_finding_does_not_break_out_of_script_element() {
    let out = render(&poisoned_finding());

    // The template emits exactly one legitimate `</script>` closing tag
    // (html_script.js and html_body.html contain none). If the attacker payload
    // survived unescaped, the inlined JSON would contribute one or more
    // additional `</script>` sequences and break out of the script element.
    let script_closes = out.matches("</script>").count();
    assert_eq!(
        script_closes, 1,
        "expected exactly the one template </script> close tag, found {script_closes}; \
         attacker payload broke out of the <script> element"
    );

    // The exact injected attack string must never appear verbatim in output.
    assert!(
        !out.contains(PAYLOAD),
        "attacker payload `{PAYLOAD}` appears unescaped in the HTML report"
    );

    // The injected markup tag must not appear as live HTML.
    assert!(
        !out.contains("<img src=x onerror=alert(1)>"),
        "injected <img onerror> tag appears unescaped in the HTML report"
    );

    // The escaped form proves the data is still present, just neutralised:
    // `<`/`>`/`/` become < / > / / inside the JSON string.
    assert!(
        out.contains("\\u003c\\u002fscript\\u003e"),
        "escaped `</script>` not found; escaping did not run on the inlined JSON"
    );
}
