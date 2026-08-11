//! Source-instrumentation suite for the always-on adapters (filesystem walk /
//! read / queue handoff, archive decompression, stdin buffering).
//!
//! WHY: the profiler only helps isolate source bottlenecks if every adapter
//! records its stage spans and real input counts through the shared
//! `keyhog_profile` runtime. These tests pin the exact span call counts and
//! byte/unit totals for small synthetic trees so a future refactor that drops
//! (or double counts) an instrumentation site fails loudly, and they pin the
//! disabled contract: with no runtime entered, adapters record nothing and
//! still scan.

mod support;

use keyhog_core::Source;
use keyhog_profile::Stage;
use keyhog_sources::{BufferedStdinSource, FilesystemSource};
use std::io::Write;
use support::profile::{run_with_profile, stage_calls};

/// Write `files` (name, content) into a fresh tempdir and return it.
fn fixture_tree(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("fixture tempdir");
    for (name, content) in files {
        std::fs::write(dir.path().join(name), content).expect("write fixture file");
    }
    dir
}

/// A two-file tree records one acquisition, one walk, one read per file, and
/// the walked units/bytes as input totals.
///
/// Locks out: dropping the reader-thread runtime propagation (SourceRead would
/// fall to 0), and counting emitted chunks instead of walked entries (the
/// totals would drift on skipped or filtered files).
#[test]
fn filesystem_records_acquire_walk_read_and_input_totals() {
    let dir = fixture_tree(&[("alpha.txt", "alpha body\n"), ("bravo.txt", "bravo body\n")]);
    let expected_bytes: u64 = "alpha body\n".len() as u64 + "bravo body\n".len() as u64;

    let (profile, rows) = run_with_profile(|| {
        FilesystemSource::new(dir.path().to_path_buf())
            .chunks()
            .collect::<Vec<_>>()
    });

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "a healthy fixture must not report coverage errors: {errors:?}"
    );
    assert_eq!(chunks.len(), 2, "both fixture files must scan: {rows:?}");

    assert_eq!(stage_calls(&profile, Stage::SourceAcquire), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceWalk), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceRead), 2);
    assert_eq!(
        stage_calls(&profile, Stage::SourceQueueWait),
        1,
        "the default direct reader coalesces this sub-threshold tree into one handoff"
    );
    assert_eq!(profile.input_units, 2);
    assert_eq!(profile.input_bytes, expected_bytes);
}

/// Archive extraction runs under Decode and charges the extracted member
/// bytes as derived decoder bytes, while the container itself stays the one
/// walked input unit.
///
/// Locks out: conflating container bytes with extracted bytes (input_bytes
/// would count the members) and losing the Decode span when extractors move.
#[test]
fn filesystem_tgz_records_decode_span_and_derived_bytes() {
    let member = "members/secret.txt";
    let member_body = "api_key = \"AKIAFIXTURE00000001\"\n";
    let tgz = support::archive::tgz_with_entries(&[(member, member_body.as_bytes())]);
    let dir = tempfile::tempdir().expect("fixture tempdir");
    let archive_path = dir.path().join("bundle.tar.gz");
    std::fs::File::create(&archive_path)
        .expect("create archive fixture")
        .write_all(&tgz)
        .expect("write archive fixture");
    let tgz_len = tgz.len() as u64;

    let (profile, rows) = run_with_profile(|| {
        FilesystemSource::new(dir.path().to_path_buf())
            .chunks()
            .collect::<Vec<_>>()
    });

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "a healthy fixture must not report coverage errors: {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "the tar member scans as one chunk: {rows:?}"
    );
    assert!(
        chunks[0].data.contains("AKIAFIXTURE00000001"),
        "member content must reach the scanner: {:?}",
        chunks[0].data
    );

    assert_eq!(stage_calls(&profile, Stage::SourceAcquire), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceWalk), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceRead), 1);
    assert_eq!(stage_calls(&profile, Stage::Decode), 1);
    assert_eq!(profile.input_units, 1);
    assert_eq!(profile.input_bytes, tgz_len);
    assert_eq!(
        profile.workload.derived_decoder_bytes,
        Some(member_body.len() as u64)
    );
}

/// Buffered stdin records its acquisition and buffering read plus the exact
/// one-chunk payload as input totals.
///
/// Locks out: regressions where stdin buffering moves back into the CLI and
/// the adapter stops recording its own boundary.
#[test]
fn buffered_stdin_records_acquire_read_and_payload_totals() {
    let payload = b"first line\nsecond line\n";
    let (profile, rows) = run_with_profile(|| {
        BufferedStdinSource::new(payload.to_vec())
            .chunks()
            .collect::<Vec<_>>()
    });

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "a healthy fixture must not report coverage errors: {errors:?}"
    );
    assert_eq!(chunks.len(), 1, "stdin yields exactly one chunk: {rows:?}");
    assert_eq!(
        chunks[0].data.as_str(),
        std::str::from_utf8(payload).expect("payload is utf8")
    );

    assert_eq!(stage_calls(&profile, Stage::SourceAcquire), 1);
    assert_eq!(stage_calls(&profile, Stage::SourceRead), 1);
    assert_eq!(profile.input_units, 1);
    assert_eq!(profile.input_bytes, payload.len() as u64);
}

/// With no profiling runtime entered, adapters record nothing anywhere and
/// still produce their chunks.
///
/// Locks out: a fallback that records into the process-global legacy runtime
/// when no session is active, which would make every unprofiled scan pay
/// recording costs and pollute later profiled runs.
#[test]
fn adapters_record_nothing_without_a_runtime() {
    let dir = fixture_tree(&[("alpha.txt", "alpha body\n")]);

    let fs_rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    assert_eq!(fs_rows.len(), 1, "scan must still work: {fs_rows:?}");
    assert!(fs_rows[0].is_ok());

    let stdin_rows: Vec<_> = BufferedStdinSource::new(b"payload\n".to_vec())
        .chunks()
        .collect();
    assert_eq!(stdin_rows.len(), 1, "stdin must still work: {stdin_rows:?}");
    assert!(stdin_rows[0].is_ok());

    let (bytes, units) = keyhog_profile::take_input_totals();
    assert_eq!((bytes, units), (0, 0));

    let runtime = keyhog_profile::Runtime::new();
    let (spans, dropped) = runtime.take_session_span_records();
    assert!(spans.is_empty() && dropped == 0);
    let (events, annotations, loss) = runtime.take_session_typed_events();
    assert!(events.is_empty() && annotations.is_empty());
    assert_eq!(loss.point_events, 0);
    assert_eq!(loss.annotations, 0);
}
