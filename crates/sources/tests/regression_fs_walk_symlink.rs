//! Regression coverage for the `keyhog-sources` filesystem walker's tree
//! traversal, depth handling, symlink refusal, and hidden-file contract.
//!
//! The walker's pinned contract (see `filesystem/filter.rs::walker_config`):
//!   * `follow_symlinks(false)` — a symlink is NEVER traversed, so a symlink
//!     cycle can never spin the walk into an infinite loop and a symlinked file
//!     is never read twice.
//!   * `skip_hidden(false)` — dotfiles and dot-directories ARE scanned (a
//!     leaked key stashed in `.env` must not hide behind a leading dot).
//!   * The final symlink component is refused at read time via `O_NOFOLLOW`,
//!     and an archive-extension symlink discovered during the walk is refused
//!     LOUDLY with a `SourceError` (link-swap exfiltration guard), never
//!     silently dropped.
//!
//! Every assertion pins a concrete value: an exact file/chunk count, an exact
//! boolean, an exact substring of a refusal error, or an exact "scanned exactly
//! once" multiplicity. No test asserts only `!is_empty()`.

use keyhog_core::{Chunk, Source, SourceError};
use keyhog_sources::FilesystemSource;
use std::collections::BTreeSet;
use std::fs;

/// Drain a source, partitioning chunk rows from surfaced error rows. Never
/// panics on an error row — several symlink/refusal contracts INTENTIONALLY
/// surface a `SourceError`, and swallowing it would hide the loud-refusal
/// guarantee under test.
fn drain(src: &FilesystemSource) -> (Vec<Chunk>, Vec<SourceError>) {
    let mut chunks = Vec::new();
    let mut errors = Vec::new();
    for row in src.chunks() {
        match row {
            Ok(chunk) => chunks.push(chunk),
            Err(error) => errors.push(error),
        }
    }
    (chunks, errors)
}

/// Number of DISTINCT files (by recorded chunk path) whose scanned content
/// contains `needle`. Robust to a file being windowed into multiple chunks:
/// this counts files, so "scanned exactly once" is a count of `1`.
fn files_containing(chunks: &[Chunk], needle: &str) -> usize {
    let mut hit_paths: BTreeSet<String> = BTreeSet::new();
    for chunk in chunks {
        if chunk.data.contains(needle) {
            let path = chunk
                .metadata
                .path
                .clone()
                .unwrap_or_else(|| String::from("<no-path>"));
            hit_paths.insert(path);
        }
    }
    hit_paths.len()
}

/// Distinct scanned file paths across all chunks.
fn distinct_paths(chunks: &[Chunk]) -> BTreeSet<String> {
    chunks
        .iter()
        .filter_map(|c| c.metadata.path.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// Depth / nested-directory traversal
// ---------------------------------------------------------------------------

#[test]
fn nested_tree_walked_to_exact_depth_and_full_file_set() {
    // One file planted at each depth 0..=4 under a chain that shares NONE of
    // the default-excluded directory names.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let d1 = root.join("alpha");
    let d2 = d1.join("bravo");
    let d3 = d2.join("charlie");
    let d4 = d3.join("delta");
    fs::create_dir_all(&d4).unwrap();

    fs::write(root.join("f0.txt"), "depth0_marker_zero\n").unwrap();
    fs::write(d1.join("f1.txt"), "depth1_marker_one\n").unwrap();
    fs::write(d2.join("f2.txt"), "depth2_marker_two\n").unwrap();
    fs::write(d3.join("f3.txt"), "depth3_marker_three\n").unwrap();
    fs::write(d4.join("f4.txt"), "depth4_marker_four\n").unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(root.to_path_buf()));
    assert!(
        errors.is_empty(),
        "a clean nested tree must surface zero error rows, got: {errors:?}"
    );
    // Exactly five files discovered — the walker reached the deepest leaf and
    // did not miss or duplicate an intermediate level.
    assert_eq!(
        distinct_paths(&chunks).len(),
        5,
        "walker must discover exactly one file at each of depths 0..=4"
    );
    for marker in [
        "depth0_marker_zero",
        "depth1_marker_one",
        "depth2_marker_two",
        "depth3_marker_three",
        "depth4_marker_four",
    ] {
        assert_eq!(
            files_containing(&chunks, marker),
            1,
            "each depth marker must be scanned in exactly one file: {marker}"
        );
    }
}

#[test]
fn deep_leaf_marker_scanned_exactly_once() {
    // Depth-8 chain: proves the walk neither stops short nor re-emits the leaf.
    let dir = tempfile::tempdir().unwrap();
    let mut leaf = dir.path().to_path_buf();
    for seg in ["l1", "l2", "l3", "l4", "l5", "l6", "l7", "l8"] {
        leaf = leaf.join(seg);
    }
    fs::create_dir_all(&leaf).unwrap();
    fs::write(leaf.join("buried.conf"), "deep_leaf_marker_unique_8\n").unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(dir.path().to_path_buf()));
    assert!(
        errors.is_empty(),
        "clean deep chain must have no errors: {errors:?}"
    );
    assert_eq!(
        files_containing(&chunks, "deep_leaf_marker_unique_8"),
        1,
        "the depth-8 leaf must be scanned exactly once"
    );
    assert_eq!(
        distinct_paths(&chunks).len(),
        1,
        "only the single buried file exists in the tree"
    );
}

#[test]
fn flat_directory_exact_file_count() {
    let dir = tempfile::tempdir().unwrap();
    for (idx, name) in ["one.txt", "two.env", "three.conf", "four.ini"]
        .iter()
        .enumerate()
    {
        fs::write(dir.path().join(name), format!("flat_marker_{idx}\n")).unwrap();
    }
    let (chunks, errors) = drain(&FilesystemSource::new(dir.path().to_path_buf()));
    assert!(
        errors.is_empty(),
        "clean flat dir must have no errors: {errors:?}"
    );
    assert_eq!(
        distinct_paths(&chunks).len(),
        4,
        "a flat directory of four small files must yield exactly four scanned files"
    );
    for idx in 0..4 {
        assert_eq!(
            files_containing(&chunks, &format!("flat_marker_{idx}")),
            1,
            "each flat file must be scanned exactly once (idx {idx})"
        );
    }
}

// ---------------------------------------------------------------------------
// Hidden / dotfile contract  (skip_hidden(false))
// ---------------------------------------------------------------------------

#[test]
fn hidden_dotfile_is_scanned() {
    // No `.git` dir => no gitignore authority; the dotfile must be scanned
    // because the walker sets skip_hidden(false).
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join(".hidden_env"),
        "hidden_dotfile_marker_abc\n",
    )
    .unwrap();
    fs::write(dir.path().join("visible.txt"), "visible_marker_def\n").unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(dir.path().to_path_buf()));
    assert!(
        errors.is_empty(),
        "clean dotfile tree must have no errors: {errors:?}"
    );
    assert_eq!(
        files_containing(&chunks, "hidden_dotfile_marker_abc"),
        1,
        "a leading-dot file must NOT be hidden from the scan (skip_hidden=false)"
    );
    assert_eq!(
        files_containing(&chunks, "visible_marker_def"),
        1,
        "the sibling visible file is scanned too"
    );
    assert_eq!(distinct_paths(&chunks).len(), 2, "exactly two files exist");
}

#[test]
fn hidden_dot_directory_contents_are_scanned() {
    // `.settings` is NOT a default-excluded directory (unlike `.git`/`.cache`),
    // so a dot-DIRECTORY's contents are walked because skip_hidden is off.
    let dir = tempfile::tempdir().unwrap();
    let hidden_dir = dir.path().join(".settings");
    fs::create_dir(&hidden_dir).unwrap();
    fs::write(hidden_dir.join("app.conf"), "dot_dir_content_marker_xyz\n").unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(dir.path().to_path_buf()));
    assert!(
        errors.is_empty(),
        "clean dot-dir tree must have no errors: {errors:?}"
    );
    assert_eq!(
        files_containing(&chunks, "dot_dir_content_marker_xyz"),
        1,
        "a file inside a non-excluded dot-directory must be scanned exactly once"
    );
}

#[test]
fn default_excluded_dot_git_directory_is_not_walked() {
    // `.git` IS a default-excluded dir: its contents must be dropped by
    // default. A stray secret in `.git/config` is out of the normal-scan
    // contract (scan-system flips this elsewhere).
    let dir = tempfile::tempdir().unwrap();
    let git_dir = dir.path().join(".git");
    fs::create_dir(&git_dir).unwrap();
    fs::write(git_dir.join("config"), "git_internal_marker_should_drop\n").unwrap();
    fs::write(dir.path().join("real.txt"), "kept_after_git_marker\n").unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(dir.path().to_path_buf()));
    assert!(errors.is_empty(), "no errors expected: {errors:?}");
    assert_eq!(
        files_containing(&chunks, "git_internal_marker_should_drop"),
        0,
        ".git directory contents must be excluded from the default walk"
    );
    assert_eq!(
        files_containing(&chunks, "kept_after_git_marker"),
        1,
        "a sibling real file is still scanned"
    );
}

// ---------------------------------------------------------------------------
// default-excluded directory toggle
// ---------------------------------------------------------------------------

#[test]
fn node_modules_dir_excluded_by_default_then_included_with_flag() {
    const SENTINEL: &str = "node_modules_dir_sentinel_value_777";
    let dir = tempfile::tempdir().unwrap();
    let nm = dir.path().join("node_modules").join("pkg");
    fs::create_dir_all(&nm).unwrap();
    fs::write(nm.join("index.js"), format!("var t = \"{SENTINEL}\";\n")).unwrap();
    fs::write(dir.path().join("app.txt"), "app_control_marker\n").unwrap();

    // Default: whole node_modules subtree dropped.
    let (kept, kept_err) = drain(&FilesystemSource::new(dir.path().to_path_buf()));
    assert!(kept_err.is_empty(), "no errors expected: {kept_err:?}");
    assert_eq!(
        files_containing(&kept, SENTINEL),
        0,
        "node_modules content must be excluded by default"
    );
    assert_eq!(
        files_containing(&kept, "app_control_marker"),
        1,
        "the control file outside node_modules is scanned"
    );

    // Flag off: node_modules content scanned.
    let (incl, incl_err) =
        drain(&FilesystemSource::new(dir.path().to_path_buf()).with_default_excludes(false));
    assert!(incl_err.is_empty(), "no errors expected: {incl_err:?}");
    assert_eq!(
        files_containing(&incl, SENTINEL),
        1,
        "with default-excludes off the node_modules file must be scanned exactly once"
    );
}

// ---------------------------------------------------------------------------
// Symlink cycle / traversal refusal  (follow_symlinks(false)) — unix only
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn symlink_directory_cycle_terminates_and_scans_target_once() {
    use std::os::unix::fs::symlink;
    // root/real/leak.txt  +  root/loop -> root  (a self-referential cycle).
    // With follow_symlinks(false) the walk must terminate (this test finishing
    // proves no infinite loop) and the target file is scanned exactly once,
    // never re-visited through the loop.
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::write(real.join("leak.txt"), "cycle_target_marker_once\n").unwrap();
    symlink(dir.path(), dir.path().join("loop")).unwrap();

    let (chunks, _errors) = drain(&FilesystemSource::new(dir.path().to_path_buf()));
    assert_eq!(
        files_containing(&chunks, "cycle_target_marker_once"),
        1,
        "the cycle target must be scanned exactly once; a followed symlink loop \
         would re-scan it (or hang) — the walker must NOT follow symlinks"
    );
}

#[cfg(unix)]
#[test]
fn symlink_to_sibling_directory_is_not_followed() {
    use std::os::unix::fs::symlink;
    // dirA/secret.txt is the only real content. dirB/mirror -> ../dirA.
    // follow_symlinks(false) => secret.txt scanned once (via dirA), never a
    // second time through dirB/mirror.
    let dir = tempfile::tempdir().unwrap();
    let dir_a = dir.path().join("dirA");
    let dir_b = dir.path().join("dirB");
    fs::create_dir(&dir_a).unwrap();
    fs::create_dir(&dir_b).unwrap();
    fs::write(dir_a.join("secret.txt"), "sibling_symlink_marker_uno\n").unwrap();
    symlink(&dir_a, dir_b.join("mirror")).unwrap();

    let (chunks, _errors) = drain(&FilesystemSource::new(dir.path().to_path_buf()));
    assert_eq!(
        files_containing(&chunks, "sibling_symlink_marker_uno"),
        1,
        "a directory symlink must not be traversed; target scanned exactly once"
    );
}

#[cfg(unix)]
#[test]
fn symlink_to_plain_file_is_not_read_twice() {
    use std::os::unix::fs::symlink;
    // real.txt + alias.txt -> real.txt. The real file is scanned once; the
    // symlink is either skipped at walk time or refused by O_NOFOLLOW at read
    // time — either way the content is scanned exactly once, never doubled.
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.txt");
    fs::write(&real, "plain_symlink_marker_solo\n").unwrap();
    symlink(&real, dir.path().join("alias.txt")).unwrap();

    let (chunks, _errors) = drain(&FilesystemSource::new(dir.path().to_path_buf()));
    assert_eq!(
        files_containing(&chunks, "plain_symlink_marker_solo"),
        1,
        "a symlink to a plain file must not cause the content to be scanned twice"
    );
}

#[cfg(unix)]
#[test]
fn broken_symlink_does_not_abort_walk_of_sibling_files() {
    use std::os::unix::fs::symlink;
    // A dangling symlink (target never existed) must not stop the scan of a
    // real sibling file, and must not itself produce content.
    let dir = tempfile::tempdir().unwrap();
    symlink(
        dir.path().join("does_not_exist_target"),
        dir.path().join("dangling.txt"),
    )
    .unwrap();
    fs::write(dir.path().join("healthy.txt"), "healthy_sibling_marker\n").unwrap();

    let (chunks, _errors) = drain(&FilesystemSource::new(dir.path().to_path_buf()));
    assert_eq!(
        files_containing(&chunks, "healthy_sibling_marker"),
        1,
        "a dangling symlink must not abort the walk of a healthy sibling"
    );
    // The dangling symlink resolves to nothing, so its (nonexistent) target
    // content can never appear.
    assert_eq!(
        distinct_paths(&chunks)
            .iter()
            .filter(|p| p.ends_with("does_not_exist_target"))
            .count(),
        0,
        "a broken symlink target must never be materialized as a scanned path"
    );
}

// ---------------------------------------------------------------------------
// Archive-symlink refusal is LOUD (link-swap exfiltration guard) — unix only
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn archive_extension_symlink_in_walk_is_refused_loudly() {
    use std::os::unix::fs::symlink;
    // `payload.zip` is a symlink to an out-of-tree target. Expanding it would
    // read+decompress the target — the link-swap exfiltration class. The walker
    // must refuse it with a visible SourceError, never silently skip it, while
    // still scanning the real sibling (partial scan must not read as clean).
    let dir = tempfile::tempdir().unwrap();
    symlink("/etc/hostname", dir.path().join("payload.zip")).unwrap();
    fs::write(
        dir.path().join("normal.txt"),
        "normal_alongside_archive_link\n",
    )
    .unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(dir.path().to_path_buf()));
    assert_eq!(
        files_containing(&chunks, "normal_alongside_archive_link"),
        1,
        "the real sibling file must still be scanned despite the refused archive symlink"
    );
    let joined: Vec<String> = errors.iter().map(ToString::to_string).collect();
    // Find the archive-symlink refusal specifically (a read-refusal row for the
    // same path may also exist; the archive guard is the one under test).
    let refusal = joined
        .iter()
        .find(|m| {
            m.contains("archive symlink expansion is blocked to prevent link-swap exfiltration")
        })
        .unwrap_or_else(|| panic!("expected the loud archive-symlink refusal; got {joined:?}"));
    assert!(
        refusal.contains("payload.zip"),
        "the archive-symlink refusal must name payload.zip, got: {refusal}"
    );
}

#[cfg(unix)]
#[test]
fn tar_symlink_in_walk_is_refused_with_tar_specific_message() {
    use std::os::unix::fs::symlink;
    // The `.tar` branch of `archive_symlink_error` emits a tar-specific
    // refusal wording distinct from the generic archive message.
    let dir = tempfile::tempdir().unwrap();
    symlink("/etc/hostname", dir.path().join("bundle.tar")).unwrap();

    let (_chunks, errors) = drain(&FilesystemSource::new(dir.path().to_path_buf()));
    let joined: Vec<String> = errors.iter().map(ToString::to_string).collect();
    let refusal = joined
        .iter()
        .find(|m| m.contains("refusing to open archive at a symlink path"))
        .unwrap_or_else(|| panic!("expected the tar-specific refusal; got {joined:?}"));
    assert!(
        refusal.contains("bundle.tar") && refusal.contains("tar file was not scanned"),
        "tar symlink refusal must name bundle.tar with the tar-specific wording, got: {refusal}"
    );
}

#[cfg(unix)]
#[test]
fn plain_named_symlink_to_dir_is_not_flagged_as_archive() {
    use std::os::unix::fs::symlink;
    // A NON-archive-extension directory symlink is a negative twin of the
    // archive-refusal tests: it is simply not traversed and produces NO
    // refusal error (the loud refusal is scoped to expandable/archive links).
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("outside");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("t.txt"), "outside_target_marker\n").unwrap();
    symlink(&target, dir.path().join("plainlink")).unwrap();
    fs::write(dir.path().join("inside.txt"), "inside_root_marker\n").unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(dir.path().to_path_buf()));
    // The archive/link-swap refusal is scoped to expandable-extension links; a
    // plain-named directory symlink must NEVER trip that loud refusal path.
    let archive_refusals = errors
        .iter()
        .map(ToString::to_string)
        .filter(|m| m.contains("archive symlink expansion is blocked to prevent link-swap"))
        .count();
    assert_eq!(
        archive_refusals, 0,
        "a plain (non-archive) directory symlink must not raise an archive-symlink refusal, got: {errors:?}"
    );
    // The in-tree file is scanned; the symlinked-in `outside` dir is NOT
    // traversed (follow_symlinks=false), so its content is scanned exactly
    // once via the real `outside` path only — and here `outside` is itself
    // inside the root, so exactly once.
    assert_eq!(
        files_containing(&chunks, "inside_root_marker"),
        1,
        "the in-root file is scanned exactly once"
    );
    assert_eq!(
        files_containing(&chunks, "outside_target_marker"),
        1,
        "the real `outside` dir is walked once; the symlink to it is not followed"
    );
}
