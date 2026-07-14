//! Behavioral coverage for analyzer integration with binary-source fallback.

use super::*;

struct SuccessfulAnalyzer;

impl BinaryAnalyzer for SuccessfulAnalyzer {
    fn analyze(
        &self,
        request: BinaryAnalysisRequest<'_>,
    ) -> Result<BinaryAnalysisOutcome, SourceError> {
        Ok(BinaryAnalysisOutcome::Complete(vec![Chunk {
            data: "analyzer-produced-value".into(),
            metadata: ChunkMetadata {
                base_offset: 0,
                base_line: 0,
                source_type: "binary:test-analyzer".into(),
                path: Some(crate::filesystem::display_path(request.path).into()),
                commit: None,
                author: None,
                date: None,
                mtime_ns: None,
                size_bytes: None,
                decoded_span: None,
            },
        }]))
    }
}

struct DegradedAnalyzer;

impl BinaryAnalyzer for DegradedAnalyzer {
    fn analyze(
        &self,
        _request: BinaryAnalysisRequest<'_>,
    ) -> Result<BinaryAnalysisOutcome, SourceError> {
        Ok(BinaryAnalysisOutcome::Degraded(
            BinaryAnalysisDegradation::ToolFailure {
                reason: "fixture failure".into(),
                stderr_excerpt: "fixture diagnostic".into(),
            },
        ))
    }
}

struct FailedAnalyzer;

impl BinaryAnalyzer for FailedAnalyzer {
    fn analyze(
        &self,
        _request: BinaryAnalysisRequest<'_>,
    ) -> Result<BinaryAnalysisOutcome, SourceError> {
        Err(SourceError::Other("fixture setup failure".into()))
    }
}

struct OversizedAnalyzer;

impl BinaryAnalyzer for OversizedAnalyzer {
    fn analyze(
        &self,
        request: BinaryAnalysisRequest<'_>,
    ) -> Result<BinaryAnalysisOutcome, SourceError> {
        Ok(BinaryAnalysisOutcome::Degraded(
            BinaryAnalysisDegradation::OutputTooLarge {
                actual_bytes: request.decompiled_bytes_limit.saturating_add(1),
                limit_bytes: request.decompiled_bytes_limit,
            },
        ))
    }
}

fn source_with_printable_fixture() -> (tempfile::TempDir, BinarySource) {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("fixture.bin");
    std::fs::write(&path, b"raw-printable-fixture-value").expect("write fixture");
    let source = BinarySource::strings_only(path);
    (temp, source)
}

#[test]
fn successful_analyzer_chunks_are_supplemented_by_raw_strings() {
    let (_temp, source) = source_with_printable_fixture();
    let rows = source
        .analyzer_chunks(&SuccessfulAnalyzer)
        .expect("analyzer succeeds");
    let chunks = rows.into_iter().collect::<Result<Vec<_>, _>>().unwrap();

    assert!(chunks.iter().any(|chunk| {
        chunk.metadata.source_type.as_ref() == "binary:test-analyzer"
            && chunk.data.as_ref() == "analyzer-produced-value"
    }));
    assert!(chunks.iter().any(|chunk| {
        chunk.metadata.source_type.as_ref() == "binary:strings"
            && chunk.data.as_ref().contains("raw-printable-fixture-value")
    }));
}

#[test]
fn typed_degradation_uses_strings_fallback() {
    let (_temp, source) = source_with_printable_fixture();
    let before = binary_degraded_to_strings();
    let rows = source
        .analyzer_chunks(&DegradedAnalyzer)
        .expect("degradation falls back");
    let chunks = rows.into_iter().collect::<Result<Vec<_>, _>>().unwrap();

    assert!(binary_degraded_to_strings() >= before.saturating_add(1));
    assert!(chunks
        .iter()
        .all(|chunk| { chunk.metadata.source_type.as_ref() != "binary:test-analyzer" }));
    assert!(chunks.iter().any(|chunk| {
        chunk.metadata.source_type.as_ref() == "binary:strings"
            && chunk.data.as_ref().contains("raw-printable-fixture-value")
    }));
}

#[test]
fn analyzer_setup_failure_remains_an_error_without_fallback() {
    let (_temp, source) = source_with_printable_fixture();
    let error = source
        .analyzer_chunks(&FailedAnalyzer)
        .expect_err("setup failure must not become successful fallback");

    assert!(matches!(
        error,
        SourceError::Other(message) if message == "fixture setup failure"
    ));
}

#[test]
fn oversized_analyzer_output_uses_visible_strings_fallback() {
    let (_temp, source) = source_with_printable_fixture();
    let before = binary_degraded_to_strings();
    let rows = source
        .analyzer_chunks(&OversizedAnalyzer)
        .expect("oversized output falls back");
    let chunks = rows.into_iter().collect::<Result<Vec<_>, _>>().unwrap();

    assert!(binary_degraded_to_strings() >= before.saturating_add(1));
    assert!(chunks.iter().any(|chunk| {
        chunk.metadata.source_type.as_ref() == "binary:strings"
            && chunk.data.as_ref().contains("raw-printable-fixture-value")
    }));
}
