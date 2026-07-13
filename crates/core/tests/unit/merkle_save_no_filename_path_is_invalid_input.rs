//! `save`/`save_with_spec` acquire a sibling `.lock` file via the shared state-file lock,
//! which rejects a cache path with no final component (`/`, or a `..`-terminated
//! path) with `ErrorKind::InvalidInput`: there is nowhere to place the lock.
//! Crucially the check is the FIRST thing `save_inner` does, before any
//! filesystem write, so a malformed path fails closed without side effects. Prior
//! merkle save tests only exercised well-formed `tempdir().join("merkle.idx")`
//! paths; these pin the error BOUNDARY (both the `kind` an operator matches on
//! and the fix-relevant message), a case an operator hits by passing a directory
//! or a stripped path to `--incremental-cache`.

use keyhog_core::testing::{CoreTestApi, TestApi};
use std::path::Path;

#[test]
fn merkle_save_to_path_without_file_name_is_invalid_input() {
    let index = TestApi.merkle_empty();
    let err = TestApi
        .merkle_save(&index, Path::new("/"))
        .expect_err("saving to a path with no file name must fail, not silently succeed");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidInput,
        "a filenameless cache path must map to InvalidInput"
    );
    assert!(
        err.to_string().contains("has no file name"),
        "the error must name the fix-relevant cause; got: {err}"
    );
}

/// A `..`-terminated relative path also has no `file_name`, so it must be
/// rejected identically, the guard keys on the missing final component, not on
/// the path being the filesystem root. (The error is returned before
/// `create_dir_all`, so no `some/dir` tree is materialized.)
#[test]
fn merkle_save_to_parent_dir_terminated_path_is_invalid_input() {
    let index = TestApi.merkle_empty();
    let err = TestApi
        .merkle_save(&index, Path::new("some/dir/.."))
        .expect_err("a `..`-terminated path has no file name and must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}
