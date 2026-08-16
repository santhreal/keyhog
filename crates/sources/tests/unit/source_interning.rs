//! Unit tests for source type and file extension interning in `keyhog-sources` and `keyhog-core`.
//!
//! Validates:
//! 1. `intern_source_type` returns pointer-identical (`Arc::ptr_eq`) `Arc<str>` references
//!    for canonical source types, eliminating per-chunk heap allocation during walks.
//! 2. `intern_file_extension` returns pointer-identical `Arc<str>` references for common
//!    file extensions.
//! 3. Fallback path for unseeded/unknown source types and extensions safely allocates without panic.
//! 4. `ChunkMetadata` constructor and builder helpers correctly utilize interned references.
//! 5. `FilesystemSource` emits chunks whose `source_type` is pointer-identical to the static interned pool.

use keyhog_core::{
    common_file_extensions, common_source_types, intern_extension, intern_file_extension,
    intern_source_type, ChunkMetadata, Source, SOURCE_TYPE_DOCKER, SOURCE_TYPE_FILESYSTEM,
    SOURCE_TYPE_FILESYSTEM_ARCHIVE, SOURCE_TYPE_FILESYSTEM_BINARY_STRINGS,
    SOURCE_TYPE_FILESYSTEM_PDF, SOURCE_TYPE_FILESYSTEM_WINDOWED, SOURCE_TYPE_GIT,
    SOURCE_TYPE_GIT_DIFF, SOURCE_TYPE_GIT_HISTORY, SOURCE_TYPE_GIT_STAGED, SOURCE_TYPE_STDIN,
};
use keyhog_sources::FilesystemSource;
use std::path::PathBuf;
use std::sync::Arc;

#[test]
fn canonical_source_types_are_pointer_identical() {
    let s1 = intern_source_type("filesystem");
    let s2 = intern_source_type("filesystem");
    assert!(
        Arc::ptr_eq(&s1, &s2),
        "intern_source_type must return pointer-identical Arc<str> for 'filesystem'"
    );
    assert!(
        Arc::ptr_eq(&s1, &SOURCE_TYPE_FILESYSTEM),
        "intern_source_type('filesystem') must match SOURCE_TYPE_FILESYSTEM static"
    );

    let w1 = intern_source_type("filesystem/windowed");
    let w2 = intern_source_type("filesystem/windowed");
    assert!(
        Arc::ptr_eq(&w1, &w2),
        "intern_source_type must return pointer-identical Arc<str> for 'filesystem/windowed'"
    );
    assert!(Arc::ptr_eq(&w1, &SOURCE_TYPE_FILESYSTEM_WINDOWED));

    let b1 = intern_source_type("filesystem:binary-strings");
    let b2 = intern_source_type("filesystem:binary-strings");
    assert!(Arc::ptr_eq(&b1, &b2));
    assert!(Arc::ptr_eq(&b1, &SOURCE_TYPE_FILESYSTEM_BINARY_STRINGS));

    let a1 = intern_source_type("filesystem/archive");
    let a2 = intern_source_type("filesystem/archive");
    assert!(Arc::ptr_eq(&a1, &a2));
    assert!(Arc::ptr_eq(&a1, &SOURCE_TYPE_FILESYSTEM_ARCHIVE));

    let p1 = intern_source_type("filesystem/pdf");
    let p2 = intern_source_type("filesystem/pdf");
    assert!(Arc::ptr_eq(&p1, &p2));
    assert!(Arc::ptr_eq(&p1, &SOURCE_TYPE_FILESYSTEM_PDF));

    let g1 = intern_source_type("git");
    let g2 = intern_source_type("git");
    assert!(Arc::ptr_eq(&g1, &g2));
    assert!(Arc::ptr_eq(&g1, &SOURCE_TYPE_GIT));

    let gd1 = intern_source_type("git-diff");
    let gd2 = intern_source_type("git-diff");
    assert!(Arc::ptr_eq(&gd1, &gd2));
    assert!(Arc::ptr_eq(&gd1, &SOURCE_TYPE_GIT_DIFF));

    let gh1 = intern_source_type("git-history");
    let gh2 = intern_source_type("git-history");
    assert!(Arc::ptr_eq(&gh1, &gh2));
    assert!(Arc::ptr_eq(&gh1, &SOURCE_TYPE_GIT_HISTORY));

    let gs1 = intern_source_type("git-staged");
    let gs2 = intern_source_type("git-staged");
    assert!(Arc::ptr_eq(&gs1, &gs2));
    assert!(Arc::ptr_eq(&gs1, &SOURCE_TYPE_GIT_STAGED));

    let st1 = intern_source_type("stdin");
    let st2 = intern_source_type("stdin");
    assert!(Arc::ptr_eq(&st1, &st2));
    assert!(Arc::ptr_eq(&st1, &SOURCE_TYPE_STDIN));

    let d1 = intern_source_type("docker");
    let d2 = intern_source_type("docker");
    assert!(Arc::ptr_eq(&d1, &d2));
    assert!(Arc::ptr_eq(&d1, &SOURCE_TYPE_DOCKER));
}

#[test]
fn common_file_extensions_are_pointer_identical() {
    let exts = [
        "rs", "go", "py", "js", "ts", "json", "yaml", "toml", "env", "md", "txt", "tar", "gz",
        "zip", "7z", "pdf", "png", "lock",
    ];
    for ext in exts {
        let e1 = intern_file_extension(ext);
        let e2 = intern_file_extension(ext);
        assert!(
            Arc::ptr_eq(&e1, &e2),
            "intern_file_extension must return pointer-identical Arc<str> for '{ext}'"
        );
        assert_eq!(&*e1, ext);

        let e3 = intern_extension(ext);
        assert!(
            Arc::ptr_eq(&e1, &e3),
            "intern_extension alias must match intern_file_extension for '{ext}'"
        );
    }
}

#[test]
fn unknown_source_type_and_extension_fall_back_cleanly() {
    let custom_source = "custom-backend-type-999";
    let c1 = intern_source_type(custom_source);
    let c2 = intern_source_type(custom_source);
    assert_eq!(&*c1, custom_source);
    assert_eq!(&*c2, custom_source);
    // Dynamic fallbacks create distinct Arc allocations, but preserve exact string content.
    assert_eq!(&*c1, &*c2);

    let custom_ext = "myrareextension123";
    let e1 = intern_file_extension(custom_ext);
    let e2 = intern_file_extension(custom_ext);
    assert_eq!(&*e1, custom_ext);
    assert_eq!(&*e2, custom_ext);
}

#[test]
fn chunk_metadata_helpers_use_interning() {
    let meta = ChunkMetadata::for_source("filesystem", Some(Arc::from("test.txt")));
    assert!(
        Arc::ptr_eq(&meta.source_type, &SOURCE_TYPE_FILESYSTEM),
        "ChunkMetadata::for_source must intern source_type"
    );
    assert_eq!(meta.path.as_deref(), Some("test.txt"));

    let meta2 = ChunkMetadata::default().with_source_type("git-diff");
    assert!(
        Arc::ptr_eq(&meta2.source_type, &SOURCE_TYPE_GIT_DIFF),
        "ChunkMetadata::with_source_type must intern source_type"
    );

    let mut meta3 = ChunkMetadata::default();
    meta3.set_source_type("docker");
    assert!(
        Arc::ptr_eq(&meta3.source_type, &SOURCE_TYPE_DOCKER),
        "ChunkMetadata::set_source_type must intern source_type"
    );
}

#[test]
fn filesystem_source_emits_interned_source_type_chunks() {
    let dir = tempfile::tempdir().unwrap();
    let file1 = dir.path().join("file1.rs");
    let file2 = dir.path().join("file2.py");
    std::fs::write(&file1, "TOKEN=file1_secret\n").unwrap();
    std::fs::write(&file2, "TOKEN=file2_secret\n").unwrap();

    let source = FilesystemSource::new(PathBuf::from(dir.path()));
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

    assert_eq!(chunks.len(), 2);
    for chunk in &chunks {
        assert!(
            Arc::ptr_eq(&chunk.metadata.source_type, &SOURCE_TYPE_FILESYSTEM),
            "FilesystemSource chunk must have pointer-identical source_type Arc<str>"
        );
        assert!(chunk.metadata.path.is_some());
    }
}

#[test]
fn common_catalog_enumerators_are_non_empty() {
    let source_types = common_source_types();
    assert!(source_types.len() >= 20);
    assert!(source_types.contains(&"filesystem"));
    assert!(source_types.contains(&"git-diff"));

    let file_extensions = common_file_extensions();
    assert!(file_extensions.len() >= 50);
    assert!(file_extensions.contains(&"rs"));
    assert!(file_extensions.contains(&"json"));
}
