//! Multi-root `keyhog watch` contract.
//!
//! `keyhog scan a/ b/ c/` accepts several roots; this gate proves `watch`
//! mirrors that surface coherently (Law 4, extend the architecture, do not
//! leave a sibling command behind). Three layers, each asserting concrete
//! values, never `!is_empty()`:
//!
//!   1. clap parsing, multiple positionals land in `WatchArgs::paths`, in
//!      order, alongside the `--backend` / `--detectors` / `--quiet` flags.
//!   2. `resolve_watch_roots`: the shared scan-root folding (canonicalize,
//!      drop nested/duplicate roots, keep order) PLUS the directory-only
//!      constraint that scan does not impose.
//!   3. `roots_hint`: the `keyhog scan <hint>` remediation string baked into
//!      every watcher error message.

use clap::Parser;
use keyhog::args::WatchArgs;
use keyhog::testing::{CliTestApi as _, API};
use std::path::PathBuf;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Layer 1: clap parsing of multiple positional roots.
// ---------------------------------------------------------------------------

fn parse(args: &[&str]) -> WatchArgs {
    WatchArgs::try_parse_from(args).expect("watch args parse")
}

#[test]
fn watch_default_path_resolves_to_current_dir() {
    let args = parse(&["watch"]);
    assert_eq!(
        args.paths,
        vec![PathBuf::from(".")],
        "a path-less `keyhog watch` must default to exactly the current directory"
    );
}

#[test]
fn watch_single_positional_root() {
    let args = parse(&["watch", "src"]);
    assert_eq!(args.paths, vec![PathBuf::from("src")]);
}

#[test]
fn watch_two_positional_roots_in_order() {
    let args = parse(&["watch", "src", "config"]);
    assert_eq!(
        args.paths,
        vec![PathBuf::from("src"), PathBuf::from("config")],
        "both positional roots must be captured in the order given"
    );
}

#[test]
fn watch_three_positional_roots_in_order() {
    let args = parse(&["watch", "a", "b", "c"]);
    assert_eq!(
        args.paths,
        vec![PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c"),],
    );
}

#[test]
fn watch_backend_flag_coexists_with_multi_root() {
    let args = parse(&["watch", "a", "b", "--backend", "cpu"]);
    assert_eq!(args.paths, vec![PathBuf::from("a"), PathBuf::from("b")]);
    assert_eq!(
        args.backend.as_deref(),
        Some("cpu"),
        "an explicit backend must not be swallowed into the positional root set"
    );
}

#[test]
fn watch_quiet_flag_before_roots() {
    let args = parse(&["watch", "--quiet", "a", "b"]);
    assert_eq!(args.paths, vec![PathBuf::from("a"), PathBuf::from("b")]);
    assert!(
        args.quiet,
        "--quiet preceding the roots must still set quiet"
    );
}

#[test]
fn watch_detectors_flag_does_not_consume_a_root() {
    // The `--detectors d` value must bind to the flag, leaving `a` and `b` as
    // the two positional roots (an interleaved option may not eat a root).
    let args = parse(&["watch", "a", "--detectors", "d", "b"]);
    assert_eq!(args.paths, vec![PathBuf::from("a"), PathBuf::from("b")]);
    assert_eq!(args.detectors, PathBuf::from("d"));
}

#[test]
fn watch_rejects_unknown_flag() {
    let parsed = WatchArgs::try_parse_from(["watch", "a", "--bogus"]);
    assert!(
        parsed.is_err(),
        "an unknown flag must be a hard parse error, not folded into paths"
    );
}

// ---------------------------------------------------------------------------
// Layer 2: resolve_watch_roots (shared folding + directory-only constraint).
// ---------------------------------------------------------------------------

#[test]
fn single_existing_dir_resolves_to_its_canonical_self() {
    let dir = TempDir::new().expect("tempdir");
    let resolved = API
        .watch_resolve_roots(&[dir.path().to_path_buf()])
        .expect("single dir resolves");
    assert_eq!(
        resolved,
        vec![dir.path().canonicalize().expect("canonical dir")],
        "a lone directory root must resolve to exactly its canonical path"
    );
}

#[test]
fn two_distinct_dirs_both_kept_in_order() {
    let a = TempDir::new().expect("tempdir a");
    let b = TempDir::new().expect("tempdir b");
    let resolved = API
        .watch_resolve_roots(&[a.path().to_path_buf(), b.path().to_path_buf()])
        .expect("two dirs resolve");
    assert_eq!(
        resolved,
        vec![
            a.path().canonicalize().expect("canonical a"),
            b.path().canonicalize().expect("canonical b"),
        ],
        "two unrelated roots must both survive, in first-seen order"
    );
}

#[test]
fn three_distinct_dirs_preserve_first_seen_order() {
    let a = TempDir::new().expect("tempdir a");
    let b = TempDir::new().expect("tempdir b");
    let c = TempDir::new().expect("tempdir c");
    let resolved = API
        .watch_resolve_roots(&[
            a.path().to_path_buf(),
            b.path().to_path_buf(),
            c.path().to_path_buf(),
        ])
        .expect("three dirs resolve");
    assert_eq!(
        resolved,
        vec![
            a.path().canonicalize().expect("canonical a"),
            b.path().canonicalize().expect("canonical b"),
            c.path().canonicalize().expect("canonical c"),
        ],
    );
}

#[test]
fn exact_duplicate_dir_folds_to_one() {
    let dir = TempDir::new().expect("tempdir");
    let resolved = API
        .watch_resolve_roots(&[dir.path().to_path_buf(), dir.path().to_path_buf()])
        .expect("duplicate dir resolves");
    assert_eq!(
        resolved,
        vec![dir.path().canonicalize().expect("canonical dir")],
        "the same directory passed twice must fold to a single root"
    );
}

#[test]
fn nested_child_folds_into_parent() {
    let parent = TempDir::new().expect("tempdir parent");
    let child = parent.path().join("sub");
    std::fs::create_dir(&child).expect("create child dir");
    let resolved = API
        .watch_resolve_roots(&[parent.path().to_path_buf(), child.clone()])
        .expect("nested resolves");
    assert_eq!(
        resolved,
        vec![parent.path().canonicalize().expect("canonical parent")],
        "a child already covered by its watched parent must fold away"
    );
}

#[test]
fn child_then_parent_order_still_folds_to_parent() {
    let parent = TempDir::new().expect("tempdir parent");
    let child = parent.path().join("sub");
    std::fs::create_dir(&child).expect("create child dir");
    // Child FIRST: nesting is absorbed by the ancestor regardless of order.
    let resolved = API
        .watch_resolve_roots(&[child.clone(), parent.path().to_path_buf()])
        .expect("nested resolves");
    assert_eq!(
        resolved,
        vec![parent.path().canonicalize().expect("canonical parent")],
        "nested-root folding must be order-independent"
    );
}

#[test]
fn parent_dot_dot_path_canonicalizes_to_parent() {
    let parent = TempDir::new().expect("tempdir parent");
    let child = parent.path().join("sub");
    std::fs::create_dir(&child).expect("create child dir");
    // `sub/..` exists and canonicalizes back to `parent`.
    let dotted = child.join("..");
    let resolved = API
        .watch_resolve_roots(&[dotted])
        .expect("dotted path resolves");
    assert_eq!(
        resolved,
        vec![parent.path().canonicalize().expect("canonical parent")],
        "a `.. `-bearing root must canonicalize before it is watched"
    );
}

#[test]
fn nonexistent_root_fails_closed() {
    let dir = TempDir::new().expect("tempdir");
    let missing = dir.path().join("does-not-exist");
    let err = API
        .watch_resolve_roots(&[missing])
        .expect_err("a missing root must fail closed, never be silently skipped");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("does-not-exist") || msg.to_lowercase().contains("canonicalize"),
        "the error must name the unresolved root; got: {msg}"
    );
}

#[test]
fn file_root_rejected_as_not_a_directory() {
    let dir = TempDir::new().expect("tempdir");
    let file = dir.path().join("notes.txt");
    std::fs::write(&file, b"plain file, not a watchable tree\n").expect("write file");
    let err = API
        .watch_resolve_roots(&[file.clone()])
        .expect_err("a file root must be rejected, watch monitors directories");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("is not a directory"),
        "the rejection must state the directory constraint; got: {msg}"
    );
    assert!(
        msg.contains("keyhog scan"),
        "the rejection must point a file at `keyhog scan`; got: {msg}"
    );
}

#[test]
fn dir_plus_unrelated_file_rejected_on_the_file() {
    let dir = TempDir::new().expect("tempdir dir");
    let other = TempDir::new().expect("tempdir other");
    let file = other.path().join("config.env");
    std::fs::write(&file, b"PASSWORD=hunter2\n").expect("write file");
    // The file is NOT nested under `dir`, so it survives folding and must then
    // be rejected by the directory-only constraint (no silent drop, Law 10).
    let err = API
        .watch_resolve_roots(&[dir.path().to_path_buf(), file.clone()])
        .expect_err("a non-directory among the roots must reject the whole watch");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("is not a directory") && msg.contains("config.env"),
        "the rejection must name the offending file root; got: {msg}"
    );
}

#[test]
fn empty_request_yields_empty_set() {
    let resolved = API
        .watch_resolve_roots(&[])
        .expect("empty request resolves");
    assert_eq!(
        resolved,
        Vec::<PathBuf>::new(),
        "an empty root request must yield an empty set, matching `keyhog scan`"
    );
}

// ---------------------------------------------------------------------------
// Layer 3: roots_hint (the `keyhog scan <hint>` remediation string).
// ---------------------------------------------------------------------------

#[test]
fn roots_hint_single_root_is_that_path() {
    let hint = API.watch_roots_hint(&[PathBuf::from("/srv/app")]);
    assert_eq!(hint, "/srv/app");
}

#[test]
fn roots_hint_joins_multiple_with_space() {
    let hint = API.watch_roots_hint(&[PathBuf::from("/a"), PathBuf::from("/b")]);
    assert_eq!(
        hint, "/a /b",
        "multiple roots must join with a space so the hint is a valid \
         `keyhog scan /a /b` command"
    );
}

#[test]
fn roots_hint_preserves_order() {
    let hint = API.watch_roots_hint(&[
        PathBuf::from("/z"),
        PathBuf::from("/y"),
        PathBuf::from("/x"),
    ]);
    assert_eq!(
        hint, "/z /y /x",
        "the hint must keep the watched-root order"
    );
}

#[test]
fn roots_hint_empty_is_empty_string() {
    let hint = API.watch_roots_hint(&[]);
    assert_eq!(hint, "", "no roots must produce an empty hint, not panic");
}
