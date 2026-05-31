use super::report_common::sample_finding;
use keyhog_core::{JunitReporter, Reporter};

fn render(finding: &keyhog_core::VerifiedFinding) -> String {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut reporter = JunitReporter::new(&mut buf);
        reporter.report(finding).expect("report finding");
        reporter.finish().expect("finish");
    }
    String::from_utf8(buf).expect("utf8 junit output")
}

#[test]
fn junit_wraps_finding_in_testsuites_with_failure() {
    let out = render(&sample_finding());

    assert!(out.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n"));
    assert!(out.trim_end().ends_with("</testsuites>"));
    assert!(
        out.contains(
            "<testsuite name=\"keyhog\" tests=\"1\" failures=\"1\" errors=\"0\" time=\"0.0\">"
        ),
        "testsuite counts wrong: {out:?}"
    );
    assert!(
        out.contains(
            "<testcase name=\"config/app.env:12:aws-access-key\" classname=\"keyhog.findings\" time=\"0.0\">"
        ),
        "testcase name wrong: {out:?}"
    );
    assert!(
        out.contains(
            "<failure message=\"Secret detected: AWS Key, &quot;prod&quot; &lt;a&amp;b&gt; (id: aws-access-key)\" type=\"high\">"
        ),
        "failure message/type not escaped as expected: {out:?}"
    );
    assert!(out.contains("<![CDATA["));
    assert!(out.contains("Verification:  live"));
    assert!(out.contains("Confidence:    0.875"));
}

#[test]
fn junit_escapes_apostrophe_in_failure_message() {
    let mut finding = sample_finding();
    finding.detector_name = "Owner's Key".into();
    let out = render(&finding);
    assert!(out.contains("Owner&apos;s Key"));
}
