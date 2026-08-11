//! Enumeration order is reproducible, and that is load-bearing.
//!
//! `FilesystemSource::chunks` external-merges bounded native-byte path runs for
//! unbounded Unix walks, then reconstructs one `FileEntry` at a time for the
//! reader pool. This avoids retaining one absolute `PathBuf` allocation per
//! file without changing the externally observed order.
//!
//! The sort is not tidiness: batch composition follows chunk arrival order,
//! and autoroute keys persisted decisions by batch shape. Filesystem iteration
//! order is not portable across filesystems, so relying on arrival order would
//! make a freshly calibrated cache miss on replay.
//!
//! These tests pin what compact discovery must preserve: the same set exactly
//! once, sorted by native path, independent of walk or reader concurrency.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::num::NonZeroUsize;
use tempfile::TempDir;

/// A tree wide and deep enough that a parallel walker really does interleave
/// its subtrees, rather than finishing one directory before starting the next.
fn wide_tree() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    for branch in 0..12 {
        let sub = dir.path().join(format!("dir{branch:02}"));
        std::fs::create_dir_all(&sub).expect("create subdir");
        for leaf in 0..40 {
            std::fs::write(
                sub.join(format!("f{leaf:03}.txt")),
                format!("value = {leaf}\n"),
            )
            .expect("write leaf");
        }
    }
    dir
}

fn enumerate(root: &std::path::Path) -> Vec<String> {
    FilesystemSource::new(root.to_path_buf())
        .chunks()
        .filter_map(Result::ok)
        .filter_map(|chunk| chunk.metadata.path.map(|path| path.to_string()))
        .collect()
}

/// Twenty runs over the same tree produce one identical path order.
///
/// One run proves nothing here: a parallel walk can look ordered by luck. The
/// failure this guards against is intermittent, so the assertion has to be too
/// stubborn to pass by chance.
#[test]
fn enumeration_order_is_identical_across_repeated_walks() {
    let tree = wide_tree();
    let first = enumerate(tree.path());

    assert_eq!(
        first.len(),
        12 * 40,
        "every planted file must be enumerated"
    );

    for run in 2..=20 {
        assert_eq!(
            enumerate(tree.path()),
            first,
            "run {run} enumerated the same tree in a different order, which would change batch \
             composition and make a calibrated autoroute cache miss on replay"
        );
    }
}

/// The order is sorted by path, not merely stable.
///
/// Stability alone could be satisfied by a walker that happens to be
/// deterministic on this filesystem and is not on another. Sorted order is a
/// property of the code, so it holds everywhere.
#[test]
fn enumeration_order_is_sorted_by_path() {
    let tree = wide_tree();
    let paths = enumerate(tree.path());

    let mut expected = paths.clone();
    expected.sort();

    assert_eq!(
        paths, expected,
        "entries must be yielded in sorted path order"
    );
}

/// Nothing is lost or duplicated.
///
/// An order check cannot see a dropped or repeated entry. A channel-based
/// parallel walker can do both, on a full queue or a retry, so this is the
/// assertion any faster walk has to keep passing.
#[test]
fn the_walk_enumerates_every_file_exactly_once() {
    let tree = wide_tree();
    let paths = enumerate(tree.path());

    let unique: std::collections::BTreeSet<&String> = paths.iter().collect();
    assert_eq!(
        unique.len(),
        paths.len(),
        "a file was enumerated more than once"
    );
    assert_eq!(unique.len(), 12 * 40, "a file was missed");
}

/// Compact discovery stores native Unix path bytes, not lossy UTF-8.
///
/// A lossy path table could alias two distinct files and either drop one or
/// read the wrong file after sorting.
#[cfg(unix)]
#[test]
fn non_utf8_paths_survive_compact_sorted_discovery_exactly_once() {
    use std::os::unix::ffi::OsStringExt;

    let tree = TempDir::new().expect("tempdir");
    let raw_names = [
        b"a-\x80.txt".to_vec(),
        b"a-\x81.txt".to_vec(),
        b"z-valid.txt".to_vec(),
    ];
    for (index, name) in raw_names.iter().enumerate() {
        std::fs::write(
            tree.path().join(std::ffi::OsString::from_vec(name.clone())),
            format!("value = {index}\n"),
        )
        .expect("write non-UTF-8 path");
    }

    let rows = FilesystemSource::new(tree.path().to_path_buf())
        .chunks()
        .map(|row| {
            row.expect("non-UTF-8 path remains readable")
                .data
                .as_str()
                .to_owned()
        })
        .collect::<Vec<_>>();

    assert_eq!(
        rows,
        ["value = 0\n", "value = 1\n", "value = 2\n"],
        "native path ordering and file identity must survive compact discovery"
    );
}

/// A file used directly as the scan root has an empty relative path.
///
/// Joining that empty path back onto the file root adds a trailing separator,
/// turning the file into an invalid directory path and producing zero coverage.
#[test]
fn direct_file_root_survives_empty_relative_path_reconstruction() {
    let tree = TempDir::new().expect("tempdir");
    let file = tree.path().join("secret.env");
    std::fs::write(&file, b"direct-file-root\n").expect("write direct file");

    let chunks = FilesystemSource::new(file)
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("direct file root remains readable");

    assert_eq!(chunks.len(), 1, "direct file root must yield one chunk");
    assert_eq!(
        chunks[0].data.as_str(),
        "direct-file-root\n",
        "empty relative-path reconstruction must reopen the file itself"
    );
}

/// Compact discovery on Linux uses an anonymous memory-backed spool, so a scan
/// remains read-only with respect to the container filesystem.
#[cfg(target_os = "linux")]
#[test]
fn compact_discovery_does_not_require_a_writable_temp_directory() {
    const CHILD_ENV: &str = "KEYHOG_TEST_READ_ONLY_DISCOVERY_CHILD";
    const ROOT_ENV: &str = "KEYHOG_TEST_READ_ONLY_DISCOVERY_ROOT";

    if std::env::var_os(CHILD_ENV).is_some() {
        let root = std::env::var_os(ROOT_ENV).expect("child scan root");
        let chunks = FilesystemSource::new(std::path::PathBuf::from(root))
            .chunks()
            .collect::<Result<Vec<_>, _>>()
            .expect("discovery must not write through TMPDIR");
        assert_eq!(chunks.len(), 1, "the planted file must be scanned");
        assert_eq!(chunks[0].data.as_str(), "read-only discovery\n");
        return;
    }

    let tree = TempDir::new().expect("tempdir");
    let root = tree.path().join("scan-root");
    std::fs::create_dir(&root).expect("create scan root");
    std::fs::write(root.join("input.txt"), b"read-only discovery\n").expect("write fixture");
    let not_a_directory = tree.path().join("not-a-directory");
    std::fs::write(&not_a_directory, b"blocks tempfile creation").expect("write TMPDIR blocker");

    let status = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .args([
            "--exact",
            "compact_discovery_does_not_require_a_writable_temp_directory",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .env(ROOT_ENV, &root)
        .env("TMPDIR", &not_a_directory)
        .status()
        .expect("run isolated discovery child");

    assert!(
        status.success(),
        "filesystem discovery attempted to create a scratch file through TMPDIR"
    );
}

/// One direct reader and four ordered readers emit identical chunks and errors.
///
/// The multi-window file covers part boundaries as well as entry ordering.
#[test]
fn reader_width_preserves_exact_chunk_output_order() {
    let tree = wide_tree();
    let large = "value = reader parity\n".repeat(150_000);
    std::fs::write(tree.path().join("multi-window.txt"), large).expect("write multi-window file");

    let collect = |width| {
        FilesystemSource::new(tree.path().to_path_buf())
            .with_reader_threads(NonZeroUsize::new(width).expect("nonzero"))
            .chunks()
            .map(|row| {
                row.map(|chunk| {
                    (
                        chunk.metadata.source_type.to_string(),
                        chunk.metadata.path.map(|path| path.to_string()),
                        chunk.metadata.base_offset,
                        chunk.data.as_str().to_owned(),
                    )
                })
                .map_err(|error| format!("{error:#}"))
            })
            .collect::<Vec<_>>()
    };

    let ordered = collect(4);
    let direct = collect(1);
    assert_eq!(direct, ordered);
}
