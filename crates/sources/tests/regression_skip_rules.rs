//! Regression coverage for the filesystem source's skip / ignore rules:
//! `.keyhogignore` and `.gitignore` walker-level ignores, `with_ignore_paths`
//! glob ignores, the `--max-file-size` over-size skip (with its exact operator
//! reason), and the binary-file skip (skip-extension + extensionless NUL-run
//! sniff). Every assertion pins a concrete value: the exact `SkipCounts`
//! category increment, the exact over-size error text, a specific `looks_binary`
//! truth-table bool, or the presence/absence of a unique sentinel in the
//! emitted chunk stream.
//!
//! Skip taxonomy exercised here (owned by `filesystem::extract::process_entry`
//! and `filesystem::filter` / `skip.rs`):
//!   * `.keyhogignore` / `.gitignore` / `with_ignore_paths` — filtered at the
//!     codewalk WALKER layer, BEFORE `process_entry`, so the file never becomes
//!     a chunk AND increments NO `SkipCounts` category (it is not a
//!     process-entry skip). The negative twin (`skip_counts().excluded == 0`)
//!     proves the ignore did not leak into the typed counters.
//!   * over-size — `SkipCounts::over_max_size`, plus a loud `SourceError::Other`
//!     row (Law 10: the drop is surfaced, not silent).
//!   * binary — `SkipCounts::binary` for skip-extension and extensionless
//!     NUL-run files.

use keyhog_core::{Chunk, Source, SourceError};
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};
use std::fs;
use std::path::Path;

/// Serializes the process-global skip counters across the parallel tests in this
/// binary (each integration-test file is its own process, so a file-local mutex
/// is sufficient — mirrors `default_excludes_flag.rs`). Held for the whole
/// `reset -> scan -> read skip_counts()` window of every counter-asserting test.
static SKIP_COUNTER_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn counter_guard() -> std::sync::MutexGuard<'static, ()> {
    SKIP_COUNTER_GUARD
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn rows_of(source: &FilesystemSource) -> Vec<Result<Chunk, SourceError>> {
    source.chunks().collect()
}

/// True when some emitted chunk's scanned text contains `needle`.
fn body_present(rows: &[Result<Chunk, SourceError>], needle: &str) -> bool {
    rows.iter()
        .any(|row| matches!(row, Ok(chunk) if chunk.data.contains(needle)))
}

fn error_rows(rows: &[Result<Chunk, SourceError>]) -> Vec<&SourceError> {
    rows.iter()
        .filter_map(|row| match row {
            Err(error) => Some(error),
            Ok(_) => None,
        })
        .collect()
}

// A unique control marker for the "always scanned, never skipped" file present
// in most fixtures. Distinct from every skip sentinel.
const CONTROL_MARKER: &str = "NORMAL_ALWAYS_SCANNED_CONTROL_MARKER_7f3a";

fn write_control(dir: &Path) {
    fs::write(
        dir.join("config.env"),
        format!("API_KEY={CONTROL_MARKER}\n"),
    )
    .unwrap();
}

// --------------------------------------------------------------------------
// .keyhogignore (custom ignore file — respected regardless of git presence).
// --------------------------------------------------------------------------

#[test]
fn keyhogignore_exact_filename_skips_matched_path_without_counter() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    let sentinel = "KEYHOGIGNORE_EXACT_SENTINEL_a1b2";
    fs::write(dir.path().join(".keyhogignore"), "hidden_secret.env\n").unwrap();
    fs::write(
        dir.path().join("hidden_secret.env"),
        format!("TOKEN={sentinel}\n"),
    )
    .unwrap();
    write_control(dir.path());

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows = rows_of(&source);

    assert!(
        error_rows(&rows).is_empty(),
        ".keyhogignore fixture must not emit SourceError rows"
    );
    assert!(
        body_present(&rows, CONTROL_MARKER),
        "control config.env must be walked"
    );
    assert!(
        !body_present(&rows, sentinel),
        ".keyhogignore-matched file must be skipped at the walker layer"
    );
    // Walker-layer ignore is NOT a process_entry skip: no typed category moves.
    let counts = skip_counts();
    assert_eq!(
        counts.excluded, 0,
        "a .keyhogignore skip must not increment the default-exclude counter"
    );
    assert_eq!(
        counts.binary, 0,
        "a .keyhogignore skip must not be misattributed as a binary skip"
    );
    assert_eq!(
        counts.over_max_size, 0,
        "a .keyhogignore skip must not be misattributed as an over-size skip"
    );
}

#[test]
fn keyhogignore_glob_pattern_skips_matched_extension() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    let sentinel = "KEYHOGIGNORE_GLOB_SENTINEL_c3d4";
    fs::write(dir.path().join(".keyhogignore"), "*.secret\n").unwrap();
    fs::write(
        dir.path().join("creds.secret"),
        format!("TOKEN={sentinel}\n"),
    )
    .unwrap();
    write_control(dir.path());

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows = rows_of(&source);

    assert!(
        body_present(&rows, CONTROL_MARKER),
        "control config.env must be walked"
    );
    assert!(
        !body_present(&rows, sentinel),
        "*.secret glob in .keyhogignore must skip creds.secret"
    );
    assert_eq!(skip_counts().excluded, 0);
}

#[test]
fn keyhogignore_directory_pattern_skips_whole_subtree() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    let sentinel = "KEYHOGIGNORE_DIR_SENTINEL_e5f6";
    // "logs" is NOT a built-in default-excluded dir, so any skip here is
    // attributable solely to the .keyhogignore "logs/" rule.
    fs::write(dir.path().join(".keyhogignore"), "logs/\n").unwrap();
    let logs = dir.path().join("logs");
    fs::create_dir(&logs).unwrap();
    fs::write(logs.join("inside.env"), format!("TOKEN={sentinel}\n")).unwrap();
    write_control(dir.path());

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows = rows_of(&source);

    assert!(
        body_present(&rows, CONTROL_MARKER),
        "control config.env must be walked"
    );
    assert!(
        !body_present(&rows, sentinel),
        "logs/ directory rule in .keyhogignore must skip files under logs/"
    );
    assert_eq!(skip_counts().excluded, 0);
}

// --------------------------------------------------------------------------
// with_ignore_paths (CLI --ignore-path -> negated codewalk override glob).
// --------------------------------------------------------------------------

#[test]
fn with_ignore_paths_glob_skips_matched_files_only() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    let ignored_sentinel = "IGNORE_PATH_LOG_SENTINEL_10ab";
    fs::write(
        dir.path().join("app.log"),
        format!("line TOKEN={ignored_sentinel}\n"),
    )
    .unwrap();
    // Same stem, different (non-ignored) extension: proves the glob is scoped
    // to *.log and does not over-match.
    let kept_sentinel = "IGNORE_PATH_ENV_SENTINEL_20cd";
    fs::write(
        dir.path().join("app.env"),
        format!("TOKEN={kept_sentinel}\n"),
    )
    .unwrap();

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf())
        .with_ignore_paths(vec!["*.log".to_string()]);
    let rows = rows_of(&source);

    assert!(
        !body_present(&rows, ignored_sentinel),
        "*.log passed to with_ignore_paths must skip app.log"
    );
    assert!(
        body_present(&rows, kept_sentinel),
        "with_ignore_paths(*.log) must NOT skip the sibling app.env"
    );
    assert_eq!(skip_counts().excluded, 0);
}

// --------------------------------------------------------------------------
// .gitignore honored only inside a git repo, and toggled off by
// with_respect_gitignore(false) (scan-system semantics).
// --------------------------------------------------------------------------

#[test]
fn gitignore_respected_by_default_and_reincluded_when_disabled() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    // A `.git` directory (with a HEAD) marks the tree as a repo root so
    // codewalk's require-git gitignore semantics activate without invoking the
    // git binary. `.git` is itself always skipped by the walker.
    fs::create_dir(dir.path().join(".git")).unwrap();
    fs::write(
        dir.path().join(".git").join("HEAD"),
        "ref: refs/heads/main\n",
    )
    .unwrap();
    let sentinel = "GITIGNORE_TOGGLE_SENTINEL_30ef";
    fs::write(dir.path().join(".gitignore"), "githidden.env\n").unwrap();
    fs::write(
        dir.path().join("githidden.env"),
        format!("TOKEN={sentinel}\n"),
    )
    .unwrap();
    write_control(dir.path());

    // Default: gitignore honored, so the sentinel is skipped.
    let respected = FilesystemSource::new(dir.path().to_path_buf());
    let respected_rows = rows_of(&respected);
    assert!(
        body_present(&respected_rows, CONTROL_MARKER),
        "control config.env must be walked with gitignore on"
    );
    assert!(
        !body_present(&respected_rows, sentinel),
        ".gitignore must skip githidden.env by default inside a repo"
    );

    // scan-system flips respect_gitignore off: the stashed key can't hide.
    let unrestricted =
        FilesystemSource::new(dir.path().to_path_buf()).with_respect_gitignore(false);
    let unrestricted_rows = rows_of(&unrestricted);
    assert!(
        body_present(&unrestricted_rows, sentinel),
        "with_respect_gitignore(false) must scan the .gitignored githidden.env"
    );
}

// --------------------------------------------------------------------------
// Over-size skip: exact reason + loud error row (Law 10, no silent drop).
// --------------------------------------------------------------------------

#[test]
fn oversize_file_skipped_with_exact_reason_and_surfaced_error() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    // Exactly 60 bytes, `.txt` (not a skip extension, not binary).
    let big = "OVERSIZE_SENTINEL_".to_string() + &"x".repeat(42);
    assert_eq!(big.len(), 60, "fixture size must be an exact known value");
    fs::write(dir.path().join("big.txt"), &big).unwrap();
    write_control(dir.path());

    TestApi.reset_skip_counters();
    // Cap between the 50-byte control (`API_KEY=<40-char marker>\n`) and the
    // 60-byte oversize file: the control is scanned, big.txt is skipped.
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(55);
    let rows = rows_of(&source);

    assert!(
        body_present(&rows, CONTROL_MARKER),
        "under-cap control config.env must still be scanned"
    );
    assert!(
        !body_present(&rows, "OVERSIZE_SENTINEL_"),
        "over-size big.txt content must not reach a scanned chunk"
    );
    assert_eq!(
        skip_counts().over_max_size,
        1,
        "one over-size file must increment the over_max_size counter exactly once"
    );

    let errors = error_rows(&rows);
    assert_eq!(
        errors.len(),
        1,
        "the over-size skip must surface exactly one loud SourceError row"
    );
    let error = errors[0];
    match error {
        SourceError::Other(message) => {
            assert!(
                message.contains("size 60 exceeds --max-file-size cap 55"),
                "error must name the exact size and cap, got: {message}"
            );
            assert!(
                message.contains("file was not scanned"),
                "error must state the file was not scanned, got: {message}"
            );
        }
        other => panic!("expected SourceError::Other for over-size skip, got: {other}"),
    }
}

#[test]
fn file_exactly_at_max_size_is_scanned_not_skipped() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    // Exactly 40 bytes == cap. The guard is `file_size > max_size`, so equal is
    // scanned (boundary twin of the over-size test).
    let exact = "EXACT_SENTINEL_".to_string() + &"x".repeat(25);
    assert_eq!(exact.len(), 40, "boundary fixture must be exactly the cap");
    fs::write(dir.path().join("exact.txt"), &exact).unwrap();

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(40);
    let rows = rows_of(&source);

    assert!(
        body_present(&rows, "EXACT_SENTINEL_"),
        "a file exactly at the cap must be scanned"
    );
    assert_eq!(
        skip_counts().over_max_size,
        0,
        "a file exactly at the cap must not be counted as over-size"
    );
    assert!(
        error_rows(&rows).is_empty(),
        "at-cap file must not emit an over-size error"
    );
}

#[test]
fn max_file_size_zero_means_unlimited_no_size_skip() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    let sentinel = "UNLIMITED_SENTINEL_40ba";
    let content = format!("TOKEN={sentinel}_") + &"x".repeat(500);
    fs::write(dir.path().join("unlim.txt"), &content).unwrap();

    TestApi.reset_skip_counters();
    // max_file_size(0) disables the `max_size > 0` cap entirely.
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(0);
    let rows = rows_of(&source);

    assert!(
        body_present(&rows, sentinel),
        "max_file_size(0) must scan even a large file"
    );
    assert_eq!(
        skip_counts().over_max_size,
        0,
        "max_file_size(0) must never record an over-size skip"
    );
}

// --------------------------------------------------------------------------
// Binary skip: skip-extension (denylisted ext) + extensionless NUL-run sniff.
// --------------------------------------------------------------------------

#[test]
fn binary_extension_png_skipped_and_counted_as_binary() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    let sentinel = "PNG_BINARY_SENTINEL_50dc";
    // Plain text with a binary (`png`) extension: dropped unread by the
    // skip-extension gate. Content is NOT a git-lfs pointer, so it is a plain
    // binary skip, not an LFS-pointer skip.
    fs::write(dir.path().join("logo.png"), format!("TOKEN={sentinel}\n")).unwrap();
    write_control(dir.path());

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows = rows_of(&source);

    assert!(
        body_present(&rows, CONTROL_MARKER),
        "control config.env must be scanned"
    );
    assert!(
        !body_present(&rows, sentinel),
        "a .png file must be skipped unread by the binary-extension gate"
    );
    let counts = skip_counts();
    assert_eq!(counts.binary, 1, "one .png skip must increment binary once");
    assert_eq!(
        counts.git_lfs_pointer, 0,
        "a non-pointer .png must not be recorded as a git-lfs pointer"
    );
}

#[test]
fn binary_extension_is_case_insensitive_uppercase_png() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    let sentinel = "PNG_UPPER_BINARY_SENTINEL_60ed";
    // Uppercase `.PNG`: the extension gate folds to lowercase ASCII before the
    // denylist lookup, so it must still be treated as binary.
    fs::write(dir.path().join("logo.PNG"), format!("TOKEN={sentinel}\n")).unwrap();

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows = rows_of(&source);

    assert!(
        !body_present(&rows, sentinel),
        "uppercase .PNG must be skipped like .png (case-insensitive ext match)"
    );
    assert_eq!(skip_counts().binary, 1);
}

#[test]
fn extensionless_nul_run_file_skipped_as_binary() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    let sentinel = "NULRUN_BINARY_SENTINEL_70fe";
    // No extension -> the header sniff runs; a run of >= BINARY_NUL_RUN (4) NULs
    // marks it binary and it is dropped unread.
    let mut content = vec![0u8, 0, 0, 0];
    content.extend_from_slice(format!("TOKEN={sentinel}\n").as_bytes());
    fs::write(dir.path().join("blob"), &content).unwrap();
    write_control(dir.path());

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows = rows_of(&source);

    assert!(
        body_present(&rows, CONTROL_MARKER),
        "control config.env must be scanned"
    );
    assert!(
        !body_present(&rows, sentinel),
        "an extensionless NUL-run file must be skipped by the binary prefix sniff"
    );
    assert_eq!(
        skip_counts().binary,
        1,
        "the NUL-run file must increment the binary skip counter exactly once"
    );
}

#[test]
fn extensionless_plain_text_file_is_scanned() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    let sentinel = "EXTLESS_TEXT_SENTINEL_80af";
    // "notes": no extension, no binary magic, no NUL run -> must be scanned.
    fs::write(dir.path().join("notes"), format!("TOKEN={sentinel}\n")).unwrap();

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows = rows_of(&source);

    assert!(
        body_present(&rows, sentinel),
        "an extensionless plain-text file must be scanned, not skipped as binary"
    );
    assert_eq!(
        skip_counts().binary,
        0,
        "a plain-text extensionless file must not increment the binary counter"
    );
}

// --------------------------------------------------------------------------
// Pure binary-classifier truth table (the predicate behind the binary skip).
// --------------------------------------------------------------------------

#[test]
fn looks_binary_predicate_truth_table() {
    // No scan / no counters touched, so no serialization guard needed.
    assert!(!TestApi.looks_binary(b""), "empty input is text");
    assert!(
        !TestApi.looks_binary(b"API_KEY=sk_live_ordinary_ascii_text"),
        "clean ASCII is text"
    );
    // BINARY_NUL_RUN == 4: four consecutive NULs is the binary boundary.
    assert!(
        TestApi.looks_binary(&[0u8, 0, 0, 0]),
        "a 4-byte NUL run is binary"
    );
    assert!(
        !TestApi.looks_binary(&[0u8, 0, 0]),
        "a 3-byte NUL run is below the run threshold -> text"
    );
    // SUSPICIOUS_CONTROL_BINARY_MIN == 4 and threshold suspicious*20 > total:
    // four C0 controls in a 4-byte buffer (4*20 = 80 > 4) is binary.
    assert!(
        TestApi.looks_binary(&[0x01u8, 0x02, 0x03, 0x04]),
        "four dense C0 control bytes are binary"
    );
    // A single control byte is below the minimum-count floor -> text.
    assert!(
        !TestApi.looks_binary(&[0x01u8]),
        "a single control byte is text (below the 4-byte suspicious floor)"
    );
}

// --------------------------------------------------------------------------
// Control + integration: a normal file is walked (metadata proven), and the
// three skip classes coexist with correct per-category counts in one scan.
// --------------------------------------------------------------------------

#[test]
fn normal_file_emits_chunk_with_filesystem_path_metadata() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    let sentinel = "NORMAL_METADATA_SENTINEL_90bf";
    fs::write(dir.path().join("app.env"), format!("TOKEN={sentinel}\n")).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows = rows_of(&source);

    let chunk = rows
        .iter()
        .find_map(|row| match row {
            Ok(chunk) if chunk.data.contains(sentinel) => Some(chunk),
            _ => None,
        })
        .expect("normal file must emit a chunk carrying its secret");

    assert_eq!(
        chunk.metadata.source_type.as_ref(),
        "filesystem",
        "filesystem chunk must be tagged with its source type"
    );
    let path = chunk
        .metadata
        .path
        .as_deref()
        .expect("filesystem chunk must carry a provenance path");
    assert!(
        path.ends_with("app.env"),
        "chunk path must point at app.env, got {path}"
    );
}

#[test]
fn binary_oversize_and_normal_coexist_with_per_category_counts() {
    let _guard = counter_guard();
    let dir = tempfile::tempdir().unwrap();
    // Binary (skip-extension) file.
    fs::write(
        dir.path().join("logo.png"),
        "TOKEN=COMBINED_PNG_SENTINEL_a0\n",
    )
    .unwrap();
    // Over-size file: 100 bytes vs a 40-byte cap.
    let big = "COMBINED_OVERSIZE_SENTINEL_".to_string() + &"x".repeat(73);
    assert_eq!(big.len(), 100);
    fs::write(dir.path().join("big.txt"), &big).unwrap();
    // Normal control file.
    write_control(dir.path());

    TestApi.reset_skip_counters();
    // Cap between the 50-byte control and the 100-byte oversize file: the
    // control is scanned, big.txt is skipped for size, the binary for content.
    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(55);
    let rows = rows_of(&source);

    assert!(
        body_present(&rows, CONTROL_MARKER),
        "the normal file must still be scanned amid skips"
    );
    assert!(
        !body_present(&rows, "COMBINED_PNG_SENTINEL"),
        "the binary file's content must not be scanned"
    );
    assert!(
        !body_present(&rows, "COMBINED_OVERSIZE_SENTINEL"),
        "the over-size file's content must not be scanned"
    );

    let counts = skip_counts();
    assert_eq!(counts.binary, 1, "exactly one binary skip");
    assert_eq!(counts.over_max_size, 1, "exactly one over-size skip");
    assert_eq!(
        counts.excluded, 0,
        "no default-exclude skips in this fixture"
    );
    assert_eq!(
        counts.total(),
        2,
        "total file-skip count must sum binary + over-size (1 + 1)"
    );
}
