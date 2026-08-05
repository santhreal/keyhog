//! Enumeration order is reproducible, and that is load-bearing.
//!
//! `FilesystemSource::chunks` collects every entry and sorts by path before
//! yielding. The sort is not tidiness: batch composition follows the order
//! chunks arrive in, autoroute keys its persisted decisions by batch shape, and
//! a walk that emitted the tree differently on each run would make a freshly
//! calibrated cache miss on replay.
//!
//! Enumeration is also a prefix that blocks every read, so on many-small-file
//! trees it is a fifth of the run: 0.24 s of a 1.14 s scan over 15,000 files.
//! Swapping in `codewalk`'s parallel walker cuts that to 0.098 s and the whole
//! scan to 1.07 s with byte-identical reports, and it was tried and reverted.
//! A sibling test then saw two unreadable coverage gaps where it plants one.
//! It passes in isolation and under `--test-threads=1`, and fails only under
//! the default parallel harness, so something about the parallel walk disturbs
//! the process-global skip counters across concurrent tests. The mechanism is
//! not understood, and unreadable entries are a fail-closed recall surface, so
//! the change is not shipped on a theory. KH-1587 holds the measurement, the
//! ruled-out explanations, and what a future attempt has to prove.
//!
//! These pin what any future attempt has to preserve: the same set, exactly
//! once, in sorted order, whatever the walk does underneath.

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
            std::fs::write(sub.join(format!("f{leaf:03}.txt")), format!("value = {leaf}\n"))
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

    assert_eq!(first.len(), 12 * 40, "every planted file must be enumerated");

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

    assert_eq!(paths, expected, "entries must be yielded in sorted path order");
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

/// A single reader thread does not change what is enumerated.
///
/// Reader width and walk width are separate knobs, and constraining one must
/// not silently change the input set.
#[test]
fn reader_width_does_not_change_the_enumerated_set() {
    let tree = wide_tree();
    let wide = enumerate(tree.path());

    let narrow: Vec<String> = FilesystemSource::new(tree.path().to_path_buf())
        .with_reader_threads(NonZeroUsize::new(1).expect("nonzero"))
        .chunks()
        .filter_map(Result::ok)
        .filter_map(|chunk| chunk.metadata.path.map(|path| path.to_string()))
        .collect();

    assert_eq!(narrow, wide);
}
