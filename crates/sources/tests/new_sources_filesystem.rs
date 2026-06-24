//! Standalone coverage for keyhog-sources FilesystemSource public API + skip
//! counters: walking, content delivery, builder toggles (include paths, ignore
//! globs, max-file-size, gitignore respect, default excludes), the `Source`
//! trait surface, and the `SkipCounts` snapshot/reset functions.
//!
//! Every assertion checks a concrete value: which file's bytes reach a chunk,
//! the source name, the chunk metadata path, the skip-count totals — never a
//! bare `is_ok()` / `!is_empty()`.

mod support;

use keyhog_core::{Chunk, Source};
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource, SkipCounts};
use std::fs;
use std::path::Path;
use support::collect_chunks;

fn collect(src: &FilesystemSource) -> Vec<Chunk> {
    collect_chunks(src)
}

fn body_contains(chunks: &[Chunk], needle: &str) -> bool {
    chunks.iter().any(|c| c.data.contains(needle))
}

fn any_path_ends_with(chunks: &[Chunk], suffix: &str) -> bool {
    chunks
        .iter()
        .filter_map(|c| c.metadata.path.as_deref())
        .any(|p| p.ends_with(suffix))
}

// ---------------------------------------------------------------------------
// Source trait surface
// ---------------------------------------------------------------------------

#[test]
fn filesystem_source_name_is_filesystem() {
    let dir = tempfile::tempdir().unwrap();
    let src = FilesystemSource::new(dir.path().to_path_buf());
    assert_eq!(src.name(), "filesystem");
}

#[test]
fn filesystem_source_downcasts_via_as_any() {
    let dir = tempfile::tempdir().unwrap();
    let src = FilesystemSource::new(dir.path().to_path_buf());
    let any = src.as_any();
    assert!(
        any.downcast_ref::<FilesystemSource>().is_some(),
        "as_any must downcast to the concrete FilesystemSource"
    );
}

// ---------------------------------------------------------------------------
// Walking + content delivery
// ---------------------------------------------------------------------------

#[test]
fn walks_and_delivers_file_content() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("app.env"),
        "API_KEY=marker_alpha_unique_value\n",
    )
    .unwrap();
    fs::write(dir.path().join("readme.txt"), "marker_beta_unique_value\n").unwrap();

    let src = FilesystemSource::new(dir.path().to_path_buf());
    let chunks = collect(&src);
    assert!(body_contains(&chunks, "marker_alpha_unique_value"));
    assert!(body_contains(&chunks, "marker_beta_unique_value"));
    // Chunk metadata records the path with a recognizable suffix.
    assert!(any_path_ends_with(&chunks, "app.env"));
    assert!(any_path_ends_with(&chunks, "readme.txt"));
    // source_type is the filesystem tag.
    assert!(chunks
        .iter()
        .all(|c| c.metadata.source_type == "filesystem"));
}

#[test]
fn walks_nested_directories() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("a").join("b").join("c");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("deep.conf"), "deep_marker_value_xyz\n").unwrap();

    let chunks = collect(&FilesystemSource::new(dir.path().to_path_buf()));
    assert!(
        body_contains(&chunks, "deep_marker_value_xyz"),
        "nested file content must be scanned"
    );
}

#[test]
fn empty_directory_yields_no_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let chunks = collect(&FilesystemSource::new(dir.path().to_path_buf()));
    assert!(chunks.is_empty(), "empty tree yields zero chunks");
}

// ---------------------------------------------------------------------------
// with_include_paths
// ---------------------------------------------------------------------------

#[test]
fn include_paths_restricts_to_listed_files() {
    let dir = tempfile::tempdir().unwrap();
    // Canonicalize so include path matches the canonicalized walk paths.
    let included = dir.path().join("included.env");
    let excluded = dir.path().join("excluded.env");
    fs::write(&included, "kept_marker_value\n").unwrap();
    fs::write(&excluded, "dropped_marker_value\n").unwrap();
    let included_canon = included.canonicalize().unwrap();

    let src =
        FilesystemSource::new(dir.path().to_path_buf()).with_include_paths(vec![included_canon]);
    let chunks = collect(&src);
    assert!(body_contains(&chunks, "kept_marker_value"));
    assert!(
        !body_contains(&chunks, "dropped_marker_value"),
        "files not in include_paths must be skipped"
    );
}

// ---------------------------------------------------------------------------
// with_max_file_size + skip counter
// ---------------------------------------------------------------------------

#[test]
fn max_file_size_skips_oversize_file_and_bumps_counter() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().unwrap();
    // 2 KiB file with a sentinel; cap at 100 bytes => skipped.
    let big = format!("{}sentinel_over_cap\n", "x".repeat(2048));
    fs::write(dir.path().join("big.txt"), &big).unwrap();
    // A small file under the cap is the control.
    fs::write(dir.path().join("small.txt"), "small_sentinel_value\n").unwrap();

    let src = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(100);
    let chunks = collect(&src);
    assert!(
        body_contains(&chunks, "small_sentinel_value"),
        "under-cap file must still be scanned"
    );
    assert!(
        !body_contains(&chunks, "sentinel_over_cap"),
        "over-cap file content must not reach a chunk"
    );
    assert!(
        skip_counts().over_max_size >= 1,
        "the over-max-size skip counter must be bumped"
    );
}

// ---------------------------------------------------------------------------
// with_default_excludes
// ---------------------------------------------------------------------------

#[test]
fn default_excludes_drop_lockfile_then_flag_includes_it() {
    const SENTINEL: &str = "ghp_newsourceslockfilesentinel0123456789";
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("package-lock.json"),
        format!("{{ \"t\": \"{SENTINEL}\" }}\n"),
    )
    .unwrap();
    fs::write(dir.path().join("config.env"), "control_marker_value\n").unwrap();

    // Default: lockfile excluded.
    let kept = collect(&FilesystemSource::new(dir.path().to_path_buf()));
    assert!(body_contains(&kept, "control_marker_value"));
    assert!(
        !body_contains(&kept, SENTINEL),
        "package-lock.json must be excluded by default"
    );

    // Flag off: lockfile scanned.
    let included =
        collect(&FilesystemSource::new(dir.path().to_path_buf()).with_default_excludes(false));
    assert!(body_contains(&included, "control_marker_value"));
    assert!(
        body_contains(&included, SENTINEL),
        "with default-excludes off the lockfile must be scanned"
    );
}

// ---------------------------------------------------------------------------
// with_respect_gitignore
//
// codewalk 0.2.5 sets `WalkBuilder::git_ignore(respect_gitignore)` but never
// `require_git(false)`, so the `ignore` crate keeps its documented default
// (`require_git(true)`): a `.gitignore` is authoritative ONLY when a `.git`
// directory is present at/above the walk root. These tests pin that exact
// contract from both sides — honored WITH a repo, inert WITHOUT one.
// ---------------------------------------------------------------------------

#[test]
fn gitignore_respected_inside_a_repo_then_overridable() {
    let dir = tempfile::tempdir().unwrap();
    // A `.git` directory makes the `.gitignore` authoritative (require_git).
    fs::create_dir(dir.path().join(".git")).unwrap();
    fs::write(dir.path().join(".gitignore"), "secrets.env\n").unwrap();
    fs::write(dir.path().join("secrets.env"), "gitignored_marker_value\n").unwrap();
    fs::write(dir.path().join("public.env"), "public_marker_value\n").unwrap();

    // Default respects .gitignore => secrets.env is hidden.
    let respected = collect(&FilesystemSource::new(dir.path().to_path_buf()));
    assert!(body_contains(&respected, "public_marker_value"));
    assert!(
        !body_contains(&respected, "gitignored_marker_value"),
        "inside a git repo a gitignored file must be hidden by default"
    );

    // respect=false => secrets.env is scanned (scan-system behavior).
    let unrestricted =
        collect(&FilesystemSource::new(dir.path().to_path_buf()).with_respect_gitignore(false));
    assert!(
        body_contains(&unrestricted, "gitignored_marker_value"),
        "with respect_gitignore(false) the ignored file must be scanned"
    );
}

#[test]
fn gitignore_is_inert_without_a_git_directory() {
    // No `.git` dir: the `ignore` crate's require_git default means the
    // `.gitignore` is NOT honored and the listed file IS scanned. This is the
    // real, intended contract — a loose `.gitignore` cannot silently hide
    // secrets from a non-repo scan.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".gitignore"), "secrets.env\n").unwrap();
    fs::write(dir.path().join("secrets.env"), "loose_gitignore_marker\n").unwrap();

    let chunks = collect(&FilesystemSource::new(dir.path().to_path_buf()));
    assert!(
        body_contains(&chunks, "loose_gitignore_marker"),
        "without a .git directory the .gitignore must NOT hide the file"
    );
}

#[test]
fn keyhogignore_is_honored_without_a_git_directory() {
    // `.keyhogignore` is wired as a codewalk custom-ignore filename, which is
    // NOT gated on require_git — so it excludes matching files even with no
    // `.git` present. This is the keyhog-native, git-independent ignore path.
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".keyhogignore"), "ignored.env\n").unwrap();
    fs::write(dir.path().join("ignored.env"), "keyhogignored_marker\n").unwrap();
    fs::write(dir.path().join("kept.env"), "kept_keyhog_marker\n").unwrap();

    let chunks = collect(&FilesystemSource::new(dir.path().to_path_buf()));
    assert!(
        body_contains(&chunks, "kept_keyhog_marker"),
        "a file not listed in .keyhogignore must be scanned"
    );
    assert!(
        !body_contains(&chunks, "keyhogignored_marker"),
        ".keyhogignore must exclude its listed file even without a git repo"
    );
}

// ---------------------------------------------------------------------------
// with_ignore_paths
// ---------------------------------------------------------------------------

#[test]
fn ignore_paths_glob_excludes_matching_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("keep.env"), "keep_ignore_marker\n").unwrap();
    fs::write(dir.path().join("drop.log"), "drop_ignore_marker\n").unwrap();

    let src = FilesystemSource::new(dir.path().to_path_buf())
        .with_ignore_paths(vec!["*.log".to_string()]);
    let chunks = collect(&src);
    assert!(body_contains(&chunks, "keep_ignore_marker"));
    assert!(
        !body_contains(&chunks, "drop_ignore_marker"),
        "*.log glob must exclude drop.log"
    );
}

// ---------------------------------------------------------------------------
// source construction
// ---------------------------------------------------------------------------

#[test]
fn filesystem_source_new_is_readable() {
    let dir = tempfile::tempdir().unwrap();
    let src = FilesystemSource::new(dir.path().to_path_buf());
    let chunks = collect(&src);
    assert!(chunks.is_empty(), "fresh empty source should be readable");
}

// ---------------------------------------------------------------------------
// SkipCounts snapshot / reset
// ---------------------------------------------------------------------------

#[test]
fn skip_counts_total_sums_all_categories() {
    let c = SkipCounts {
        over_max_size: 2,
        binary: 3,
        excluded: 5,
        unreadable: 7,
        git_object_unreadable: 29,
        archive_truncated: 11,
        // Partial-coverage signals — deliberately NOT part of the whole-file
        // skip total, so non-zero values here must not change total().
        binary_section_name_unresolved: 13,
        source_truncated: 17,
        structured_source_parse_failures: 19,
        archive_duplicate_scan_unavailable: 23,
    };
    assert_eq!(
        c.total(),
        28,
        "total() sums only the five whole-file skip categories; partial-coverage \
         counters are surfaced separately and excluded"
    );
}

#[test]
fn skip_counts_default_is_all_zero() {
    let c = SkipCounts::default();
    assert_eq!(c, SkipCounts::default());
    assert_eq!(c.total(), 0);
}

#[test]
fn reset_skip_counters_zeroes_every_category() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.set_skip_counts(SkipCounts {
        over_max_size: 11,
        binary: 22,
        excluded: 33,
        unreadable: 44,
        git_object_unreadable: 99,
        archive_truncated: 0,
        binary_section_name_unresolved: 55,
        source_truncated: 66,
        structured_source_parse_failures: 77,
        archive_duplicate_scan_unavailable: 88,
    });

    TestApi.reset_skip_counters();

    let snap = skip_counts();
    assert_eq!(snap.over_max_size, 0);
    assert_eq!(snap.binary, 0);
    assert_eq!(snap.excluded, 0);
    assert_eq!(snap.unreadable, 0);
    assert_eq!(
        snap.git_object_unreadable, 0,
        "reset_skip_counters must also zero git object coverage-gap counters"
    );
    assert_eq!(
        snap.binary_section_name_unresolved, 0,
        "reset_skip_counters must also zero the binary section partial-parse counter"
    );
    assert_eq!(
        snap.source_truncated, 0,
        "reset_skip_counters must also zero source-level truncation counters"
    );
    assert_eq!(
        snap.structured_source_parse_failures, 0,
        "reset_skip_counters must also zero structured source parse-failure counters"
    );
    assert_eq!(
        snap.archive_duplicate_scan_unavailable, 0,
        "reset_skip_counters must also zero archive duplicate-scan partial-coverage counters"
    );
    assert_eq!(snap.total(), 0);
}

#[test]
fn skip_counts_reads_live_counters() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    TestApi.bump_git_object_unreadable(5);
    let snap = skip_counts();
    assert_eq!(snap.binary, 0, "unrelated skip counters stay untouched");
    assert_eq!(
        snap.git_object_unreadable, 5,
        "snapshot must read the live git-object coverage-gap atomic value"
    );
    TestApi.set_skip_counts(SkipCounts {
        binary: 9,
        git_object_unreadable: 7,
        ..SkipCounts::default()
    });
    let snap = skip_counts();
    assert_eq!(snap.binary, 9, "set_skip_counts must set binary skips");
    assert_eq!(
        snap.git_object_unreadable, 7,
        "set_skip_counts must set git object coverage gaps through SkipCounts"
    );
    TestApi.reset_skip_counters();
}

// ---------------------------------------------------------------------------
// Non-existent root: chunks() yields an error, never silently empty.
// ---------------------------------------------------------------------------

#[test]
fn missing_root_yields_source_error() {
    let missing = Path::new("/nonexistent/keyhog/test/path/xyz");
    let src = FilesystemSource::new(missing.to_path_buf());
    let results: Vec<_> = src.chunks().collect();
    assert_eq!(results.len(), 1, "missing root must yield one error item");
    assert!(
        results[0].is_err(),
        "missing root must surface SourceError instead of flattening to empty"
    );
}
