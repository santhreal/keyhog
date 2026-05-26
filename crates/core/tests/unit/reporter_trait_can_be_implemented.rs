//! Migrated from `src/report.rs` inline tests.
use keyhog_core::{MatchLocation, Reporter, Severity, VerificationResult, VerifiedFinding};
use std::collections::HashMap;
use std::sync::Arc;
struct NoopReporter;
impl Reporter for NoopReporter {
    fn report(&mut self, _finding: &VerifiedFinding) -> Result<(), keyhog_core::ReportError> {
        Ok(())
    }
    fn finish(&mut self) -> Result<(), keyhog_core::ReportError> {
        Ok(())
    }
}
#[test]
fn reporter_trait_can_be_implemented() {
    let mut reporter = NoopReporter;
    let finding = VerifiedFinding {
        detector_id: Arc::from("demo"),
        detector_name: Arc::from("Demo"),
        service: Arc::from("demo"),
        severity: Severity::Info,
        credential_redacted: std::borrow::Cow::Borrowed("****"),
        credential_hash: "abc".into(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: None,
            line: None,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Skipped,
        metadata: HashMap::new(),
        additional_locations: vec![],
        confidence: None,
    };
    reporter.report(&finding).unwrap();
    reporter.finish().unwrap();
}
