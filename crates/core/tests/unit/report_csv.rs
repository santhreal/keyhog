use super::report_common::sample_finding;
use crate::support::reporters::CsvReporter;

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
        "detector_id,detector_name,service,severity,credential_redacted,credential_hash,source,file_path,line,offset,commit,author,date,verification,confidence",
    );

    assert_eq!(
        lines.next().expect("data row"),
        "aws-access-key,\"AWS Key, \"\"prod\"\" <a&b>\",aws,high,AKIA...7XYA,deadbeef00000000000000000000000000000000000000000000000000000000,filesystem,config/app.env,12,5,,,,live,0.875",
    );
    assert!(
        lines.next().is_none(),
        "exactly one data row expected: {out:?}"
    );
}
