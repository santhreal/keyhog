//! LANE (sources-safety) regressions pinning the archive/compression **budget**
//! guards under `filesystem/extract`: the 4x-`--max-file-size` aggregate
//! decompression ceiling, the per-entry uncompressed cap, and the
//! `MAX_NESTED_ARCHIVE_DEPTH` (= 8) recursion bound.
//!
//! Every test drives the PUBLIC `Source::chunks()` API on an on-disk fixture and
//! asserts an EXACT observable — an exact `skip_counts()` field value, an exact
//! error substring, an exact emitted-chunk count, or the exact inner secret bytes
//! — never a shape/`is_empty` check. Positive (in-budget), negative-twin
//! (healthy), boundary (exactly at cap / exactly at budget), and adversarial
//! (bomb, deep-nest) cases are each covered.
//!
//! Sibling coverage: `regression_decompression_bomb_and_oom_caps` pins the
//! deflated-zeros zip bomb + gzip prefix recovery + symlink refusal; this file
//! adds the exact-byte-count budget boundaries, the per-file-cap counter, the
//! nested-depth bound, and the tar-in-zip recursion budget path.
//!
//! Own test binary: the skip counters are process-global atomics, so a per-file
//! `COUNTER_LOCK` serialises the counter-asserting tests within this binary
//! (cargo runs a binary's tests in parallel by default).
#![cfg(unix)]

mod support;

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};
use std::io::Write as _;
use std::path::Path;
use std::sync::Mutex;
use support::split_chunk_results;

/// Serialises the process-global skip-counter assertions in THIS binary.
static COUNTER_LOCK: Mutex<()> = Mutex::new(());

/// The extractor's aggregate ceiling is exactly `4 * --max-file-size` (see
/// `extraction_total_budget`). Pinned here so the boundary tests read as one.
const BUDGET_FACTOR: u64 = 4;

/// `MAX_NESTED_ARCHIVE_DEPTH` in the source — the deepest archive-within-archive
/// level any extractor descends. Mirrored so the depth-bound test names it.
const MAX_NESTED_ARCHIVE_DEPTH: usize = 8;

/// Build a **Deflated** (not Stored) zip on disk. Deflated is required for the
/// budget/per-cap tests: the guard checks the *uncompressed* size, so a
/// highly-compressible entry keeps the on-disk container tiny (well under
/// `--max-file-size`, so the container itself is not gated) while its declared
/// uncompressed size can dwarf the per-entry cap or the aggregate budget. The
/// shared `support::archive::zip_with_entries` only emits Stored entries, whose
/// on-disk size equals the payload, which would trip the container size gate
/// first — hence this local Deflated builder.
fn write_deflated_zip(path: &Path, entries: &[(&str, Vec<u8>)]) {
    use zip::write::SimpleFileOptions;
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, data) in entries {
        zip.start_file(*name, opts).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap();
}

/// A `len`-byte entry that begins with `marker` and is padded with highly
/// compressible `A` bytes, so the declared uncompressed size is exactly `len`
/// while the deflated form is a few hundred bytes.
fn marked_entry(marker: &str, len: usize) -> Vec<u8> {
    assert!(marker.len() <= len);
    let mut v = Vec::with_capacity(len);
    v.extend_from_slice(marker.as_bytes());
    v.resize(len, b'A');
    v
}

/// All archive chunks whose source path is inside `archive_name` (i.e. an
/// extracted entry, path shape `…/archive_name//entry`).
fn archive_chunk_count(chunks: &[&keyhog_core::Chunk], archive_name: &str) -> usize {
    let needle = format!("{archive_name}//");
    chunks
        .iter()
        .filter(|c| {
            c.metadata
                .path
                .as_deref()
                .is_some_and(|p| p.contains(&needle))
        })
        .count()
}

// ─────────────────────────── positive / negative twin ───────────────────────

#[test]
fn small_zip_extracts_exact_inner_secret() {
    let _guard = COUNTER_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let zip = support::archive::zip_with_entries(&[(
        "config.env",
        b"AWS_SECRET_ACCESS_KEY=AKIAQYLPMN5HFIQR7XYA\n",
    )]);
    std::fs::write(dir.path().join("app.zip"), zip).unwrap();

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(1024 * 1024);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        errors.is_empty(),
        "healthy small zip must not error, got {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "single-entry zip must emit exactly one chunk"
    );
    assert_eq!(
        chunks[0].metadata.source_type.as_ref(),
        "filesystem/archive"
    );
    assert!(
        chunks[0]
            .metadata
            .path
            .as_deref()
            .unwrap()
            .ends_with("app.zip//config.env"),
        "chunk path must name the archive//entry, got {:?}",
        chunks[0].metadata.path
    );
    assert!(
        chunks[0].data.contains("AKIAQYLPMN5HFIQR7XYA"),
        "the exact inner secret must survive extraction, got {:?}",
        chunks[0].data
    );
    assert_eq!(skip_counts().archive_truncated, 0);
}

#[test]
fn healthy_zip_bumps_no_skip_counters() {
    // Negative twin: a well-formed in-budget zip trips NONE of the coverage-gap
    // counters — no false bomb/over-cap/unreadable alarm.
    let _guard = COUNTER_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let zip = support::archive::zip_with_entries(&[("a.txt", b"token=GHOSTMARKER_HEALTHY_01\n")]);
    std::fs::write(dir.path().join("ok.zip"), zip).unwrap();

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(1024 * 1024);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let counts = skip_counts();

    assert!(
        errors.is_empty(),
        "healthy zip must not error, got {errors:?}"
    );
    assert_eq!(counts.archive_truncated, 0, "no bomb guard should fire");
    assert_eq!(counts.over_max_size, 0, "no per-file cap should fire");
    assert_eq!(counts.unreadable, 0, "nothing should be unreadable");
    assert!(chunks
        .iter()
        .any(|c| c.data.contains("GHOSTMARKER_HEALTHY_01")));
}

// ────────────────────────── aggregate 4x budget boundary ────────────────────

#[test]
fn zip_total_just_under_budget_scans_every_entry() {
    // max = 64 KiB => budget = 4 * 64 KiB = 256 KiB (262144). Four 60000-byte
    // entries total 240000 < 262144: nothing is truncated, all four scanned.
    let _guard = COUNTER_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    const MAX: u64 = 64 * 1024;
    let entries: Vec<(&str, Vec<u8>)> = vec![
        ("e0.txt", marked_entry("BUDGETMARK_00", 60_000)),
        ("e1.txt", marked_entry("BUDGETMARK_01", 60_000)),
        ("e2.txt", marked_entry("BUDGETMARK_02", 60_000)),
        ("e3.txt", marked_entry("BUDGETMARK_03", 60_000)),
    ];
    write_deflated_zip(&dir.path().join("under.zip"), &entries);

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(MAX);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        errors.is_empty(),
        "under-budget zip must not error, got {errors:?}"
    );
    assert_eq!(
        skip_counts().archive_truncated,
        0,
        "under 4x budget must not truncate"
    );
    assert_eq!(
        archive_chunk_count(&chunks, "under.zip"),
        4,
        "all four in-budget entries must be scanned"
    );
    for i in 0..4 {
        let marker = format!("BUDGETMARK_0{i}");
        assert!(
            chunks.iter().any(|c| c.data.contains(&marker)),
            "entry {i} ({marker}) must be present"
        );
    }
}

#[test]
fn zip_total_over_budget_truncates_after_exact_prefix() {
    // Same 60000-byte entries, but FIVE of them: total 300000 > 262144. The
    // aggregate guard truncates BEFORE the fifth entry, so exactly four are
    // scanned, one truncation error surfaces, and the counter reads exactly 1.
    let _guard = COUNTER_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    const MAX: u64 = 64 * 1024;
    let entries: Vec<(&str, Vec<u8>)> = vec![
        ("e0.txt", marked_entry("BOMBMARK_00", 60_000)),
        ("e1.txt", marked_entry("BOMBMARK_01", 60_000)),
        ("e2.txt", marked_entry("BOMBMARK_02", 60_000)),
        ("e3.txt", marked_entry("BOMBMARK_03", 60_000)),
        ("e4.txt", marked_entry("BOMBMARK_04", 60_000)),
    ];
    write_deflated_zip(&dir.path().join("over.zip"), &entries);

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(MAX);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert_eq!(
        skip_counts().archive_truncated,
        1,
        "an over-budget zip must record exactly one truncated archive (Law 10)"
    );
    assert_eq!(
        errors.len(),
        1,
        "exactly one truncation error, not one per skipped entry"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("was truncated at"),
        "error must state truncation, got {err}"
    );
    assert!(
        err.contains("archive-bomb guard"),
        "error must name the archive-bomb guard, got {err}"
    );
    assert!(
        err.contains(&format!("budget {})", BUDGET_FACTOR * MAX)),
        "error must state the exact 4x budget {}, got {err}",
        BUDGET_FACTOR * MAX
    );
    assert!(
        err.contains("remaining entries were not scanned"),
        "error must state partial coverage, got {err}"
    );
    assert_eq!(
        archive_chunk_count(&chunks, "over.zip"),
        4,
        "exactly the four in-budget entries are scanned before the cut"
    );
    assert!(
        !chunks.iter().any(|c| c.data.contains("BOMBMARK_04")),
        "the fifth (over-budget) entry must NOT be scanned"
    );
}

#[test]
fn zip_bomb_scanned_bytes_are_bounded_by_budget() {
    // Eight over-budget entries: the guard must still cut at the budget, so the
    // total scanned bytes never exceed 4x max — the anti-OOM contract — and the
    // truncation counter stays a singleton (one break, not one per entry).
    let _guard = COUNTER_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    const MAX: u64 = 64 * 1024;
    let entries: Vec<(&str, Vec<u8>)> = (0..8u32)
        .map(|i| {
            let name: &str = Box::leak(format!("z{i}.txt").into_boxed_str());
            (name, marked_entry(&format!("OOMMARK_{i:02}"), 60_000))
        })
        .collect();
    write_deflated_zip(&dir.path().join("oom.zip"), &entries);

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(MAX);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, _errors) = split_chunk_results(&rows);

    assert_eq!(
        skip_counts().archive_truncated,
        1,
        "many over-budget entries still record exactly one truncation"
    );
    let scanned: usize = chunks
        .iter()
        .filter(|c| {
            c.metadata
                .path
                .as_deref()
                .is_some_and(|p| p.contains("oom.zip//"))
        })
        .map(|c| c.data.as_ref().len())
        .sum();
    assert!(
        scanned as u64 <= BUDGET_FACTOR * MAX,
        "scanned bytes ({scanned}) must be bounded by the 4x budget ({}) so a bomb cannot OOM",
        BUDGET_FACTOR * MAX
    );
}

// ─────────────────────────── per-entry uncompressed cap ─────────────────────

#[test]
fn zip_entry_one_over_per_file_cap_is_skipped_and_counted() {
    // per-entry cap == max_file_size. A single deflated entry whose declared
    // uncompressed size is one byte over the cap is refused via the metadata
    // check (before any read) and counted as over-max-size, with the exact size
    // and cap in the error. The tiny deflated container stays under the cap so
    // the container itself is not the thing gated.
    let _guard = COUNTER_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    const MAX: u64 = 64 * 1024; // 65536
    write_deflated_zip(
        &dir.path().join("big.zip"),
        &[("huge.txt", marked_entry("OVERCAP", (MAX + 1) as usize))],
    );

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(MAX);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert_eq!(
        skip_counts().over_max_size,
        1,
        "an entry over the per-file cap must be counted as over-max-size"
    );
    assert_eq!(
        skip_counts().archive_truncated,
        0,
        "a per-file cap skip is not a bomb truncation"
    );
    assert_eq!(errors.len(), 1, "the over-cap entry must surface one error");
    let err = errors[0].to_string();
    assert!(
        err.contains("uncompressed size 65537 exceeds per-file cap 65536"),
        "error must state the exact size and cap, got {err}"
    );
    assert_eq!(
        archive_chunk_count(&chunks, "big.zip"),
        0,
        "the over-cap entry must not be scanned into a chunk"
    );
}

#[test]
fn zip_entry_exactly_at_per_file_cap_is_scanned() {
    // Boundary twin: an entry whose uncompressed size is EXACTLY the cap is at
    // the limit, not over it, so it is scanned and no counter fires.
    let _guard = COUNTER_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    const MAX: u64 = 64 * 1024; // 65536
    write_deflated_zip(
        &dir.path().join("edge.zip"),
        &[("exact.txt", marked_entry("ATCAP_MARKER_XZ", MAX as usize))],
    );

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(MAX);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        errors.is_empty(),
        "exact-cap entry must not error, got {errors:?}"
    );
    assert_eq!(
        skip_counts().over_max_size,
        0,
        "an entry exactly at the cap is not over it"
    );
    assert_eq!(skip_counts().archive_truncated, 0);
    assert_eq!(
        archive_chunk_count(&chunks, "edge.zip"),
        1,
        "the exact-cap entry must be scanned"
    );
    assert!(chunks.iter().any(|c| c.data.contains("ATCAP_MARKER_XZ")));
}

// ─────────────────────────── nested-archive depth bound ─────────────────────

#[test]
fn nested_zip_within_depth_extracts_inner_secret() {
    // A zip-inside-a-zip (depth 1) is well under the depth bound: the inner
    // secret must be reached and its path reflect both containers.
    let _guard = COUNTER_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let inner = support::archive::zip_with_entries(&[(
        "secret.env",
        b"GITHUB_TOKEN=ghp_NESTEDdepthMARKER0123456789ABCD\n",
    )]);
    let outer = support::archive::zip_with_entries(&[("inner.zip", inner.as_slice())]);
    std::fs::write(dir.path().join("outer.zip"), outer).unwrap();

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(1024 * 1024);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        !errors
            .iter()
            .any(|e| e.to_string().contains("maximum nested archive depth")),
        "a depth-1 nest must not trip the depth bound, got {errors:?}"
    );
    assert_eq!(skip_counts().archive_truncated, 0);
    let hit = chunks
        .iter()
        .find(|c| c.data.contains("ghp_NESTEDdepthMARKER0123456789ABCD"))
        .expect("the nested inner secret must be extracted");
    assert!(
        hit.metadata
            .path
            .as_deref()
            .unwrap()
            .contains("inner.zip//secret.env"),
        "nested chunk path must reflect both containers, got {:?}",
        hit.metadata.path
    );
}

#[test]
fn nested_zip_exceeding_depth_is_refused_and_counted() {
    // Wrap a secret-bearing zip in nine further zip layers. Processing descends
    // one level per layer; at MAX_NESTED_ARCHIVE_DEPTH (8) the extractor refuses
    // to open the next embedded zip, so the innermost secret is NEVER reached.
    // The refusal is surfaced loudly and counted as unreadable (never a silent
    // clean — Law 10).
    let _guard = COUNTER_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = support::archive::zip_with_entries(&[(
        "secret.env",
        b"AWS_SECRET_ACCESS_KEY=DEEPBURIEDsecretUNREACHABLE99\n",
    )]);
    // Nine wrappers => the innermost secret sits one level past the depth bound.
    for _ in 0..(MAX_NESTED_ARCHIVE_DEPTH + 1) {
        bytes = support::archive::zip_with_entries(&[("nested.zip", bytes.as_slice())]);
    }
    std::fs::write(dir.path().join("deep.zip"), bytes).unwrap();

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(1024 * 1024);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        !chunks
            .iter()
            .any(|c| c.data.contains("DEEPBURIEDsecretUNREACHABLE99")),
        "the innermost secret past the depth bound must NOT be extracted"
    );
    let depth_err = errors
        .iter()
        .find(|e| {
            e.to_string()
                .contains("maximum nested archive depth 8 exceeded")
        })
        .unwrap_or_else(|| panic!("expected a depth-bound refusal error, got {errors:?}"));
    assert!(
        depth_err
            .to_string()
            .contains("embedded archive was not scanned"),
        "the depth refusal must state the coverage gap, got {depth_err}"
    );
    assert!(
        skip_counts().unreadable >= 1,
        "a refused over-depth embedded archive must be counted as unreadable, got {}",
        skip_counts().unreadable
    );
}

// ─────────────────────── tar-in-zip recursion budget path ────────────────────

#[test]
fn tar_nested_in_zip_extracts_inner_secret() {
    // A tar member inside a zip (the dominant docker/helm layout) must be
    // untarred and its secret found, tagged as an archive chunk whose path names
    // the tar member.
    let _guard = COUNTER_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let tar = support::archive::tar_with_file("app/secret.env", b"SLACK=xoxb-TARINZIPmarker-000\n");
    let outer = support::archive::zip_with_entries(&[("layer.tar", tar.as_slice())]);
    std::fs::write(dir.path().join("bundle.zip"), outer).unwrap();

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(1024 * 1024);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        errors.is_empty(),
        "healthy tar-in-zip must not error, got {errors:?}"
    );
    assert_eq!(skip_counts().archive_truncated, 0);
    let hit = chunks
        .iter()
        .find(|c| c.data.contains("xoxb-TARINZIPmarker-000"))
        .expect("the secret inside the nested tar must be extracted");
    assert!(
        hit.metadata
            .path
            .as_deref()
            .unwrap()
            .contains("layer.tar//"),
        "nested-tar chunk path must name the tar member, got {:?}",
        hit.metadata.path
    );
}

// ─────────────────────── single-stream gzip budget guard ─────────────────────

#[test]
fn gzip_small_stream_yields_exact_secret() {
    // Positive: a small `.gz` decompresses and scans its true bytes, tagged as a
    // compressed chunk, with no truncation.
    let _guard = COUNTER_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let gz = support::archive::gzip_bytes(b"stripe_key=sk_live_GZIPPOSITIVEmarker00\n");
    std::fs::write(dir.path().join("creds.gz"), gz).unwrap();

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(1024 * 1024);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        errors.is_empty(),
        "healthy gz must not error, got {errors:?}"
    );
    assert_eq!(skip_counts().archive_truncated, 0);
    let hit = chunks
        .iter()
        .find(|c| c.data.contains("sk_live_GZIPPOSITIVEmarker00"))
        .expect("the decompressed secret must be scanned");
    assert_eq!(hit.metadata.source_type.as_ref(), "filesystem/compressed");
}

#[test]
fn gzip_bomb_truncated_with_exact_budget_in_message() {
    // A `.gz` whose decompressed size blows the 4x budget is truncated: the
    // compressed-stream guard records one truncation and the error states the
    // EXACT budget (4 * 64 KiB = 262144) plus the partial-coverage language.
    let _guard = COUNTER_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    const MAX: u64 = 64 * 1024;
    let gz = support::archive::gzip_bytes(&vec![b'A'; 4 * 1024 * 1024]);
    std::fs::write(dir.path().join("bomb.gz"), gz).unwrap();

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(MAX);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert_eq!(
        skip_counts().archive_truncated,
        1,
        "an over-budget gzip stream must record exactly one truncation (Law 10)"
    );
    assert_eq!(
        errors.len(),
        1,
        "gzip truncation surfaces exactly one error"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("zip-bomb guard"),
        "error must name the zip-bomb guard, got {err}"
    );
    assert!(
        err.contains(&format!("budget {}", BUDGET_FACTOR * MAX)),
        "error must state the exact 4x budget {}, got {err}",
        BUDGET_FACTOR * MAX
    );
    assert!(
        err.contains("the remaining compressed stream was not scanned"),
        "error must state partial compressed-stream coverage, got {err}"
    );
    let scanned: usize = chunks
        .iter()
        .filter(|c| c.metadata.source_type.starts_with("filesystem/compressed"))
        .map(|c| c.data.as_ref().len())
        .sum();
    assert!(
        scanned as u64 <= BUDGET_FACTOR * MAX + 1,
        "decompressed scanned bytes ({scanned}) must be bounded by the 4x budget",
    );
}

// ───────────────────────── unlimited cap still bounded ──────────────────────

#[test]
fn unlimited_max_file_size_zip_fully_extracted() {
    // `--max-file-size 0` removes the per-file cap; the aggregate guard must fall
    // back to the 1 GiB uncapped ceiling (NOT collapse the budget to 0 and
    // truncate every archive to nothing). A healthy two-entry zip is fully
    // scanned with no truncation.
    let _guard = COUNTER_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let zip = support::archive::zip_with_entries(&[
        ("a.env", b"AWS=AKIAQYLPMN5HFIQR7XYA\n"),
        ("b.env", b"GCP=AIzaSyBUNCAPPEDentryTWOpresent01234567\n"),
    ]);
    std::fs::write(dir.path().join("all.zip"), zip).unwrap();

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(0);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        errors.is_empty(),
        "unlimited healthy zip must not error, got {errors:?}"
    );
    assert_eq!(
        skip_counts().archive_truncated,
        0,
        "with --max-file-size 0 the budget must be the 1 GiB ceiling, not 0"
    );
    assert_eq!(
        archive_chunk_count(&chunks, "all.zip"),
        2,
        "both entries must be scanned"
    );
    assert!(chunks
        .iter()
        .any(|c| c.data.contains("AKIAQYLPMN5HFIQR7XYA")));
    assert!(chunks
        .iter()
        .any(|c| c.data.contains("AIzaSyBUNCAPPEDentryTWOpresent01234567")));
}
