//! The PDF string parser is bounded by a WORK budget, not just an output cap.
//!
//! Own test binary: scanning the fixture records a process-global `Unreadable`
//! skip event, and `regression_pdf_coverage_gaps_counted.rs` asserts exact
//! values for those same global counters. Sharing a process would make this
//! fixture race those assertions, which is the reason that file already keeps
//! itself out of `tests/all_tests.rs`.

mod support;

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use support::split_chunk_results;

/// One `"(()"` unit adds net +1 nesting, so no literal string ever balances.
const UNBALANCED_UNIT: &[u8; 3] = b"(()";
const FIXTURE_BYTES: usize = 256 * 1024;

fn scan_pdf(bytes: &[u8]) -> Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>> {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("bomb.pdf"), bytes).expect("write pdf");
    FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect::<Vec<_>>()
}

/// A PDF whose literal-string nesting never balances must hit the string-parser
/// work budget and surface a coverage gap.
///
/// `append_pdf_strings` restarts `parse_literal_string` at every `(`, and an
/// unbalanced literal makes that parse scan to end-of-buffer while the outer
/// cursor advances only past the FIRST `)`. That is quadratic: measured 34.5 s
/// of CPU on a 400 KB file before the budget existed, with the work-per-byte
/// ratio growing as ~n/6, so a 10 MB PDF well inside the default file cap never
/// finishes.
///
/// The assertion is on the GAP rather than on a wall time deliberately. The
/// error is deterministic and load-independent, and it disappears the moment
/// the budget stops being enforced, which is what makes this test non-vacuous.
#[test]
fn pdf_unbalanced_literal_nesting_is_bounded_by_the_string_work_budget() {
    let mut bomb = b"%PDF-1.4\n".to_vec();
    for _ in 0..FIXTURE_BYTES / UNBALANCED_UNIT.len() {
        bomb.extend_from_slice(UNBALANCED_UNIT);
    }

    let started = std::time::Instant::now();
    let rows = scan_pdf(&bomb);
    let elapsed = started.elapsed();
    let (_chunks, errors) = split_chunk_results(&rows);

    assert!(
        errors.iter().map(ToString::to_string).any(|err| {
            err.contains("string-parser work budget exhausted") && err.contains("were not scanned")
        }),
        "an unbalanced-nesting PDF must surface the work-budget coverage gap \
         instead of silently burning quadratic CPU; errors={errors:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(120),
        "bounded PDF string scanning must not regress to the quadratic path; took {elapsed:?}"
    );
}

/// A well-formed PDF must stay far inside the budget, so the guard cannot be
/// satisfied by refusing every document.
///
/// The multiplier is 512x and the worst ratio measured across 212 real PDFs was
/// 26.1x, so an honest document has roughly 20x headroom and must produce no
/// budget gap at all.
#[test]
fn well_formed_pdf_strings_stay_inside_the_work_budget() {
    let mut pdf = b"%PDF-1.4\n".to_vec();
    for _ in 0..20_000 {
        pdf.extend_from_slice(b"BT (KEYHOG_PDF_BUDGET_HEADROOM_SECRET_1234567890) Tj ET\n");
    }

    let rows = scan_pdf(&pdf);
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        !errors
            .iter()
            .map(ToString::to_string)
            .any(|err| err.contains("string-parser work budget exhausted")),
        "a well-formed PDF must not trip the work budget; errors={errors:?}"
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type.as_ref() == "filesystem/pdf"
                && chunk
                    .data
                    .contains("KEYHOG_PDF_BUDGET_HEADROOM_SECRET_1234567890")
        }),
        "a well-formed PDF must still yield its extracted strings; chunks={chunks:?}"
    );
}

/// Hitting the work budget must NOT discard strings already recovered from the
/// same document.
///
/// A cap is a refusal of the hostile REMAINDER, not a reason to throw away real
/// findings the scanner already has. The secret here parses cleanly before the
/// unbalanced tail exhausts the budget, so the scan must report BOTH the
/// credential and the coverage gap.
#[test]
fn budget_exhaustion_keeps_the_strings_recovered_before_it() {
    let mut pdf = b"%PDF-1.4\n".to_vec();
    pdf.extend_from_slice(b"BT (KEYHOG_PDF_PARTIAL_RECOVERY_SECRET_1234567890) Tj ET\n");
    for _ in 0..FIXTURE_BYTES / UNBALANCED_UNIT.len() {
        pdf.extend_from_slice(UNBALANCED_UNIT);
    }

    let rows = scan_pdf(&pdf);
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        errors
            .iter()
            .map(ToString::to_string)
            .any(|err| err.contains("string-parser work budget exhausted")),
        "the hostile tail must still be surfaced as a gap; errors={errors:?}"
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk
                .data
                .contains("KEYHOG_PDF_PARTIAL_RECOVERY_SECRET_1234567890")
        }),
        "a credential recovered before the budget tripped must still be reported \
         alongside the gap, never discarded; chunks={chunks:?}"
    );
}
