use super::report_common::sample_finding;
use crate::support::reporters::CsvReporter;
use keyhog_core::VerificationResult;

fn render(finding: &keyhog_core::VerifiedFinding) -> String {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut reporter = CsvReporter::new(&mut buf).expect("new csv reporter");
        reporter.report(finding).expect("report finding");
        reporter.finish().expect("finish");
    }
    String::from_utf8(buf).expect("utf8 csv output")
}

#[test]
fn csv_emits_header_then_escaped_row() {
    let out = render(&sample_finding());
    let mut lines = out.lines();

    assert_eq!(
        lines.next().expect("header line"),
        "detector_id,detector_name,service,severity,credential_redacted,credential_hash,companions_redacted,source,file_path,line,offset,commit,author,date,verification,confidence",
    );

    assert_eq!(
        lines.next().expect("data row"),
        "aws-access-key,\"AWS Key, \"\"prod\"\" <a&b>\",aws,high,AKIA...7XYA,deadbeef00000000000000000000000000000000000000000000000000000000,{},filesystem,config/app.env,12,5,,,,live,0.875",
    );
    assert!(
        lines.next().is_none(),
        "exactly one data row expected: {out:?}"
    );
}

#[test]
fn csv_uses_canonical_structured_verification_tokens() {
    for (verification, expected) in [
        (VerificationResult::Live, "live"),
        (VerificationResult::Revoked, "revoked"),
        (VerificationResult::Dead, "dead"),
        (VerificationResult::RateLimited, "rate_limited"),
        (VerificationResult::Error("boom".to_string()), "error: boom"),
        (VerificationResult::Unverifiable, "unverifiable"),
        (VerificationResult::Skipped, "skipped"),
    ] {
        let mut finding = sample_finding();
        finding.verification = verification;
        let out = render(&finding);
        let row = out.lines().nth(1).expect("csv data row");
        assert!(
            row.ends_with(&format!(",,,,{expected},0.875")),
            "CSV must use the canonical structured verification token: {out:?}"
        );
    }
}
