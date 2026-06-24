use super::report_common::sample_finding;
use keyhog_core::{write_report, ReportFormat, VerificationResult, VerifiedFinding};
use std::sync::Arc;

fn render(finding: &VerifiedFinding) -> String {
    let mut buf: Vec<u8> = Vec::new();
    write_report(
        &mut buf,
        ReportFormat::GithubAnnotations,
        std::slice::from_ref(finding),
    )
    .expect("render GitHub annotations");
    String::from_utf8(buf).expect("utf8 GitHub annotations")
}

#[test]
fn github_annotation_emits_file_line_title_and_redacted_message() {
    let out = render(&sample_finding());

    assert!(
        out.starts_with("::error "),
        "high severity must be a GitHub error annotation: {out:?}"
    );
    assert!(
        out.contains("file=config/app.env,line=12,title=keyhog high aws-access-key::"),
        "annotation must carry file, line, and title properties: {out:?}"
    );
    assert!(
        out.contains("redacted=AKIA...7XYA"),
        "annotation message must carry the redacted credential: {out:?}"
    );
    assert!(
        out.contains("verification=live confidence=0.875"),
        "annotation message must carry verification and confidence: {out:?}"
    );
}

#[test]
fn github_annotation_escapes_workflow_command_injection() {
    let mut finding = sample_finding();
    finding.location.file_path = Some(Arc::from("dir,evil:part%\nfile.env"));
    finding.location.line = Some(3);
    finding.detector_id = Arc::from("id:with,chars");
    finding.detector_name = Arc::from("Detector\n::warning title=owned::message%");
    finding.verification =
        VerificationResult::Error("bad\r\n::error title=owned::pwn%".to_string());

    let out = render(&finding);

    assert_eq!(
        out.lines().count(),
        1,
        "escaped annotation must remain one workflow-command line: {out:?}"
    );
    assert!(
        out.contains("file=dir%2Cevil%3Apart%25%0Afile.env"),
        "file property must escape comma, colon, percent, and newline: {out:?}"
    );
    assert!(
        out.contains("title=keyhog high id%3Awith%2Cchars::"),
        "title property must escape colon and comma: {out:?}"
    );
    assert!(
        out.contains("Detector%0A::warning title=owned::message%25"),
        "message data must escape newline and percent: {out:?}"
    );
    assert!(
        out.contains("verification=error: bad%0D%0A::error title=owned::pwn%25"),
        "error verification text must escape CR/LF and percent: {out:?}"
    );
}

#[test]
fn github_annotation_empty_report_is_empty_stdout() {
    let mut buf: Vec<u8> = Vec::new();
    write_report(&mut buf, ReportFormat::GithubAnnotations, &[])
        .expect("render empty GitHub annotations");
    assert!(
        buf.is_empty(),
        "GitHub annotations emit one command per finding and no empty-report skeleton"
    );
}

#[test]
fn github_annotation_uses_canonical_structured_verification_tokens() {
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
        assert!(
            out.contains(&format!("verification={expected}")),
            "GitHub annotations must use the canonical structured verification token {expected:?}: {out:?}"
        );
    }
}
