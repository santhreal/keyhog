//! Unit tests for source type and file extension interning in `keyhog-core`.

use keyhog_core::{
    common_file_extensions, common_source_types, intern_extension, intern_file_extension,
    intern_source_type, ChunkMetadata, SOURCE_TYPE_FILESYSTEM, SOURCE_TYPE_FILESYSTEM_WINDOWED,
    SOURCE_TYPE_GIT, SOURCE_TYPE_GIT_DIFF, SOURCE_TYPE_STDIN,
};
use std::sync::Arc;

#[test]
fn intern_source_type_returns_cached_arc_for_known_sources() {
    let s1 = intern_source_type("filesystem");
    let s2 = intern_source_type("filesystem");
    assert!(Arc::ptr_eq(&s1, &s2));
    assert!(Arc::ptr_eq(&s1, &SOURCE_TYPE_FILESYSTEM));

    let g1 = intern_source_type("git");
    let g2 = intern_source_type("git");
    assert!(Arc::ptr_eq(&g1, &g2));
    assert!(Arc::ptr_eq(&g1, &SOURCE_TYPE_GIT));

    let gd1 = intern_source_type("git-diff");
    let gd2 = intern_source_type("git-diff");
    assert!(Arc::ptr_eq(&gd1, &gd2));
    assert!(Arc::ptr_eq(&gd1, &SOURCE_TYPE_GIT_DIFF));

    let st1 = intern_source_type("stdin");
    let st2 = intern_source_type("stdin");
    assert!(Arc::ptr_eq(&st1, &st2));
    assert!(Arc::ptr_eq(&st1, &SOURCE_TYPE_STDIN));
}

#[test]
fn intern_file_extension_returns_cached_arc_for_common_extensions() {
    let exts = [
        "rs", "go", "py", "js", "ts", "json", "toml", "yaml", "md", "txt", "zip",
    ];
    for ext in exts {
        let e1 = intern_file_extension(ext);
        let e2 = intern_file_extension(ext);
        assert!(Arc::ptr_eq(&e1, &e2));
        assert_eq!(&*e1, ext);

        let e3 = intern_extension(ext);
        assert!(Arc::ptr_eq(&e1, &e3));
    }
}

#[test]
fn unknown_values_allocate_cleanly() {
    let unk_src = "completely-unknown-source-xyz";
    let s1 = intern_source_type(unk_src);
    assert_eq!(&*s1, unk_src);

    let unk_ext = "unknownext999";
    let e1 = intern_file_extension(unk_ext);
    assert_eq!(&*e1, unk_ext);
}

#[test]
fn chunk_metadata_builder_helpers() {
    let meta = ChunkMetadata::for_source("filesystem/windowed", Some(Arc::from("lib.rs")));
    assert!(Arc::ptr_eq(
        &meta.source_type,
        &SOURCE_TYPE_FILESYSTEM_WINDOWED
    ));
    assert_eq!(meta.path.as_deref(), Some("lib.rs"));

    let meta2 = ChunkMetadata::default().with_source_type("git-diff");
    assert!(Arc::ptr_eq(&meta2.source_type, &SOURCE_TYPE_GIT_DIFF));

    let mut meta3 = ChunkMetadata::default();
    meta3.set_source_type("filesystem");
    assert!(Arc::ptr_eq(&meta3.source_type, &SOURCE_TYPE_FILESYSTEM));
}

#[test]
fn common_lists_contain_canonical_entries() {
    for &src in common_source_types() {
        let a1 = intern_source_type(src);
        let a2 = intern_source_type(src);
        assert!(Arc::ptr_eq(&a1, &a2));
        assert_eq!(&*a1, src);
    }

    for &ext in common_file_extensions() {
        let e1 = intern_file_extension(ext);
        let e2 = intern_file_extension(ext);
        assert!(Arc::ptr_eq(&e1, &e2));
        assert_eq!(&*e1, ext);
    }

    assert!(common_source_types().contains(&"filesystem"));
    assert!(common_source_types().contains(&"web:js"));
    assert!(common_source_types().contains(&"wire:har:request"));
    assert!(common_source_types().contains(&"filesystem/archive-binary"));
    assert!(common_file_extensions().contains(&"rs"));
    assert!(common_file_extensions().contains(&"json"));
}
