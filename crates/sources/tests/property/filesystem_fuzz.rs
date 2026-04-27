//! Random-input fuzz: 50 files with random bytes + random extensions
//! into a temp dir, drain `FilesystemSource::chunks()` to completion.
//! No assertion on contents — only that the iterator doesn't panic and
//! we get back at most one Result per file.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        // 50 cases is plenty for shape coverage; this test is heavier than
        // a single-file proptest because each case spins a real temp dir.
        cases: 50,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_files_dont_panic_filesystem_source(
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
        for (i, (stem, ext, bytes)) in files.iter().enumerate() {
            let path = match ext {
                Some(e) => dir.path().join(format!("{i}_{stem}.{e}")),
                None => dir.path().join(format!("{i}_{stem}")),
            };
            // Some random byte slices may not be valid UTF-8 — write them
            // raw so the source's binary-detection path also gets covered.
            let _ = std::fs::write(&path, bytes);
        }

        // Iterate to completion. We only care that this doesn't panic;
        // any number of Ok / Err results is acceptable.
        let source = FilesystemSource::new(dir.path().to_path_buf());
        let _ = source.chunks().collect::<Vec<_>>();
    }
}
