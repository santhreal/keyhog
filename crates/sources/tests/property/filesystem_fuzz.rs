//! Random-input fuzz: 1..16 files with random bytes + random extensions into a
//! temp dir, drain `FilesystemSource::chunks()` to completion. Beyond the
//! original no-panic smoke, this now asserts real PROVENANCE invariants (6321):
//!   * every yielded chunk maps back to a file we actually wrote — no fabricated
//!     path, no `..` traversal component escaping the tree;
//!   * a second independent drain of the same tree yields the identical set of
//!     chunk paths (enumeration is deterministic, not order-/drop-dependent).
//! A `!path.is_empty()`-style shape assertion would have missed a walker that
//! fabricated or dropped paths; these pin the actual file↔chunk correspondence.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use std::collections::BTreeSet;
use std::path::{Component, Path};

fn filesystem_fuzz_config() -> ProptestConfig {
    ProptestConfig {
        // 500 cases: 10x the old shape-only budget for real coverage of hostile
        // names/extensions, deliberately kept well under the 10k pure-CPU ceiling
        // because each case spins a real `TempDir`, writes up to 16 files, and
        // drains the source TWICE (I/O-bound). 10k here would dominate the whole
        // source-crate gate for no added signal — the invariants below are
        // structural, so they saturate long before 10k.
        cases: 500,
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "tests/property/filesystem_fuzz.proptest-regressions",
        ))),
        ..ProptestConfig::default()
    }
}

/// Sorted `Ok`-chunk path basenames from a fresh drain of `dir`.
fn drain_ok_basenames(dir: &Path) -> Vec<String> {
    let source = FilesystemSource::new(dir.to_path_buf());
    let mut names: Vec<String> = source
        .chunks()
        .filter_map(|r| r.ok())
        .filter_map(|c| {
            c.metadata.path.as_deref().and_then(|p| {
                Path::new(p)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
            })
        })
        .collect();
    names.sort();
    names
}

proptest! {
    #![proptest_config(filesystem_fuzz_config())]

    #[test]
    fn random_files_dont_panic_and_chunks_map_to_written_files(
        files in prop::collection::vec(
            (
                "[a-z]{1,8}",
                prop::option::of(prop::sample::select(vec![
                    "txt", "log", "py", "js", "yaml", "json",
                    "gz", "zst", "lz4", "zip", "tar",
                    "pem", "key", "env", "lock",
                ])),
                prop::collection::vec(any::<u8>(), 0..512),
            ),
            1..16,
        ),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let mut written: BTreeSet<String> = BTreeSet::new();
        for (i, (stem, ext, bytes)) in files.iter().enumerate() {
            let name = match ext {
                Some(e) => format!("{i}_{stem}.{e}"),
                None => format!("{i}_{stem}"),
            };
            // Random byte slices may not be valid UTF-8 — write them raw so the
            // source's binary-detection path is also covered.
            let _ = std::fs::write(dir.path().join(&name), bytes);
            written.insert(name);
        }

        // First drain: no panic, and every yielded chunk's path is one we wrote.
        let source = FilesystemSource::new(dir.path().to_path_buf());
        let results = source.chunks().collect::<Vec<_>>();
        for r in &results {
            let Ok(chunk) = r else { continue }; // Err rows are acceptable (unreadable/hostile file)
            let Some(p) = chunk.metadata.path.as_deref() else { continue };
            let path = Path::new(p);
            prop_assert!(
                !path.components().any(|c| matches!(c, Component::ParentDir)),
                "chunk path {p:?} contains a `..` traversal component",
            );
            match path.file_name() {
                Some(fname) => {
                    let base = fname.to_string_lossy().into_owned();
                    prop_assert!(
                        written.contains(&base),
                        "chunk references a file never written: {base:?} (written={written:?})",
                    );
                }
                None => prop_assert!(false, "chunk path {p:?} has no file name"),
            }
        }

        // Enumeration is deterministic: reuse the first drain's basenames and
        // compare to an independent second drain.
        let mut first: Vec<String> = results
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .filter_map(|c| {
                c.metadata
                    .path
                    .as_deref()
                    .and_then(|p| Path::new(p).file_name().map(|n| n.to_string_lossy().into_owned()))
            })
            .collect();
        first.sort();
        let second = drain_ok_basenames(dir.path());
        prop_assert_eq!(first, second, "FilesystemSource enumeration is non-deterministic");
    }
}

proptest! {
    #![proptest_config(filesystem_fuzz_config())]

    /// CONTENT RECALL (6385): a plain-text file's bytes must reach the chunk data
    /// VERBATIM. The provenance fuzz above pins WHICH files are yielded but nothing
    /// about their CONTENT — a truncation or lossy-decode bug in the source read
    /// path (the recurring "validator bypass on fast path" class: gpudeflate data
    /// loss, capped_read truncation) would silently drop the credential bytes before
    /// the scanner ever sees them, and a `!is_empty()` shape check would miss it.
    /// This plants a unique marker in an ASCII `.env` file (a plain, text-classified,
    /// non-compressed extension — no binary/decompress path) surrounded by random
    /// ASCII, drains the source, and asserts the marker survives into a chunk. The
    /// file is deliberately kept well under any chunk size so the marker lands in a
    /// single chunk (no cross-chunk split to reassemble).
    #[test]
    fn plaintext_file_content_reaches_chunk_data_verbatim(
        marker in "[A-Za-z0-9]{16,48}",
        prefix in prop::collection::vec(
            prop::sample::select(b" \n\t=:\"'.,abcXYZ0123".to_vec()),
            0..300,
        ),
        suffix in prop::collection::vec(
            prop::sample::select(b" \n\t=:\"'.,abcXYZ0123".to_vec()),
            0..300,
        ),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let mut content = Vec::with_capacity(prefix.len() + marker.len() + suffix.len());
        content.extend_from_slice(&prefix);
        content.extend_from_slice(marker.as_bytes());
        content.extend_from_slice(&suffix);
        std::fs::write(dir.path().join("planted.env"), &content).unwrap();

        let source = FilesystemSource::new(dir.path().to_path_buf());
        let carried = source
            .chunks()
            .filter_map(|r| r.ok())
            .any(|c| c.data.contains(marker.as_str()));

        prop_assert!(
            carried,
            "FilesystemSource dropped the planted marker {:?} from a {}-byte plain-text file \
             (truncation/lossy read in the source path)",
            marker,
            content.len(),
        );
    }
}
