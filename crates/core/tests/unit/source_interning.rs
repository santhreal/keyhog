//! Unit tests for source type interning in `keyhog-core`.

use keyhog_core::{
    common_source_types, intern_source_type, SOURCE_TYPE_FILESYSTEM,
    SOURCE_TYPE_FILESYSTEM_WINDOWED, SOURCE_TYPE_GIT, SOURCE_TYPE_GIT_DIFF, SOURCE_TYPE_STDIN,
};
use std::sync::Arc;

#[test]
fn intern_source_type_returns_cached_arc_for_known_sources() {
    let s1 = intern_source_type("filesystem");
    let s2 = intern_source_type("filesystem");
    assert!(Arc::ptr_eq(&s1, &s2));
    assert!(Arc::ptr_eq(&s1, &SOURCE_TYPE_FILESYSTEM));

    let w1 = intern_source_type("filesystem/windowed");
    let w2 = intern_source_type("filesystem/windowed");
    assert!(Arc::ptr_eq(&w1, &w2));
    assert!(Arc::ptr_eq(&w1, &SOURCE_TYPE_FILESYSTEM_WINDOWED));
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
fn unknown_values_allocate_cleanly() {
    let unk_src = "completely-unknown-source-xyz";
    let s1 = intern_source_type(unk_src);
    let s2 = intern_source_type(unk_src);
    assert_eq!(&*s1, unk_src);
    assert_eq!(&*s2, unk_src);
}

#[test]
fn common_lists_contain_canonical_entries() {
    for &src in common_source_types() {
        let a1 = intern_source_type(src);
        let a2 = intern_source_type(src);
        assert!(Arc::ptr_eq(&a1, &a2));
        assert_eq!(&*a1, src);
    }

    assert!(common_source_types().contains(&"filesystem"));
    assert!(common_source_types().contains(&"filesystem/windowed"));
    assert!(common_source_types().contains(&"web:js"));
    assert!(common_source_types().contains(&"wire:har:request"));
    assert!(common_source_types().contains(&"filesystem/archive-binary"));
}
