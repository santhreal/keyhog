//! Regression coverage for the `keyhog-sources` filesystem walker's NESTED
//! `.gitignore` precedence, distinct from the flat skip-rule coverage in
//! `regression_skip_rules.rs`.
//!
//! Pinned contract (see `filesystem/filter.rs::walker_config` ->
//! `respect_gitignore(true)`, which lowers to codewalk `git_ignore(true)` ->
//! `ignore::WalkBuilder` with the crate-default `require_git = true`):
//!   * `.gitignore` files are honored ONLY inside a git repository. A bare
//!     `.git/` directory (with a `HEAD`) is enough to mark the repo root; the
//!     git binary is never invoked. Without a `.git/` the `.gitignore` files
//!     are completely inert (negative twin below).
//!   * Nested `.gitignore` files are LAYERED, deepest-directory-wins: a rule in
//!     a subdirectory's `.gitignore` overrides a conflicting rule from a parent
//!     `.gitignore` because the closer matcher is consulted first.
//!   * A `!pattern` negation re-includes a file a shallower (or earlier, in the
//!     same file) rule excluded, and the re-inclusion is scoped to the exact
//!     pattern/subtree, never leaking to siblings or the parent directory.
//!   * `with_respect_gitignore(false)` (scan-system) makes the whole nested
//!     tree scannable so a key stashed behind `.gitignore` cannot hide.
//!
//! Host-independence: this is a pure walker/IO contract, no accelerator
//! (Hyperscan/SIMD/GPU) is involved, so every assertion is deterministic on any
//! host. Every assertion pins a concrete value: an exact scanned-file count, an
//! exact "scanned exactly once" multiplicity (`1`) or "dropped" multiplicity
//! (`0`), or an exact relative-path set. No test asserts only `!is_empty()`.

use keyhog_core::{Chunk, Source, SourceError};
use keyhog_sources::FilesystemSource;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Drain a source, partitioning chunk rows from surfaced error rows. A clean
/// (symlink-free) gitignore fixture must never surface an error row, so the
/// tests assert `errors` is empty and would otherwise expose a regression.
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
/// contains `needle`. Robust to a file being windowed into multiple chunks.
/// "Scanned exactly once" is a count of `1`; "dropped" is `0`.
fn files_containing(chunks: &[Chunk], needle: &str) -> usize {
    let mut hit_paths: BTreeSet<String> = BTreeSet::new();
    for chunk in chunks {
        if chunk.data.contains(needle) {
            let path = chunk
                .metadata
                .path
                .as_deref()
                .unwrap_or("<no-path>")
                .to_string();
            hit_paths.insert(path);
        }
    }
    hit_paths.len()
}

/// The set of scanned files as `/`-joined paths relative to the walk root.
/// Used by the exact-scanned-set test so a single assertion pins the whole
/// admitted/skipped partition.
fn scanned_relpaths(chunks: &[Chunk], root: &Path) -> BTreeSet<String> {
    let root_canon = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    chunks
        .iter()
        .filter_map(|c| c.metadata.path.as_deref())
        .map(|p| {
            let pb = Path::new(p);
            pb.strip_prefix(&root_canon)
                .map(|rel| rel.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| p.to_string())
        })
        .collect()
}

/// Number of distinct scanned files.
fn scanned_count(chunks: &[Chunk]) -> usize {
    chunks
        .iter()
        .filter_map(|c| c.metadata.path.clone())
        .collect::<BTreeSet<_>>()
        .len()
}

/// Mark `root` as a git repository so codewalk's `require_git = true` gitignore
/// semantics activate WITHOUT invoking the git binary (mirrors the proven setup
/// in `regression_skip_rules.rs`). A bare `.git/HEAD` suffices; `.git` is itself
/// a default-excluded directory so it never becomes a scanned file.
fn init_git_repo(root: &Path) {
    let git = root.join(".git");
    fs::create_dir(&git).unwrap();
    fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
}

// ---------------------------------------------------------------------------
// Baseline: a single root .gitignore has authority inside a repo.
// ---------------------------------------------------------------------------

#[test]
fn root_gitignore_ignores_named_file_but_keeps_sibling() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_git_repo(root);
    fs::write(root.join(".gitignore"), "ignored.env\n").unwrap();
    fs::write(root.join("ignored.env"), "TOKEN=ROOT_IGNORED_MARKER_01\n").unwrap();
    fs::write(root.join("kept.env"), "TOKEN=ROOT_KEPT_MARKER_02\n").unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(root.to_path_buf()));
    assert!(
        errors.is_empty(),
        "clean gitignore tree has no errors: {errors:?}"
    );
    assert_eq!(
        files_containing(&chunks, "ROOT_IGNORED_MARKER_01"),
        0,
        "the root .gitignore must drop the named ignored.env inside a repo"
    );
    assert_eq!(
        files_containing(&chunks, "ROOT_KEPT_MARKER_02"),
        1,
        "the un-ignored sibling kept.env is scanned exactly once"
    );
}

// ---------------------------------------------------------------------------
// Nested precedence: a child .gitignore re-includes what the parent ignored.
// ---------------------------------------------------------------------------

#[test]
fn child_negation_reincludes_file_parent_pattern_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_git_repo(root);
    // Parent ignores every .env at any depth; child re-includes exactly keep.env.
    fs::write(root.join(".gitignore"), "*.env\n").unwrap();
    let sub = root.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join(".gitignore"), "!keep.env\n").unwrap();

    fs::write(root.join("top.env"), "TOKEN=TOP_ENV_DROP_10\n").unwrap();
    fs::write(sub.join("keep.env"), "TOKEN=SUB_KEEP_ENV_KEEP_11\n").unwrap();
    fs::write(sub.join("other.env"), "TOKEN=SUB_OTHER_ENV_DROP_12\n").unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(root.to_path_buf()));
    assert!(errors.is_empty(), "no errors expected: {errors:?}");
    assert_eq!(
        files_containing(&chunks, "TOP_ENV_DROP_10"),
        0,
        "root top.env stays ignored by the parent *.env rule"
    );
    assert_eq!(
        files_containing(&chunks, "SUB_KEEP_ENV_KEEP_11"),
        1,
        "the deeper child '!keep.env' re-includes sub/keep.env (deepest matcher wins)"
    );
    assert_eq!(
        files_containing(&chunks, "SUB_OTHER_ENV_DROP_12"),
        0,
        "sub/other.env is NOT named by the negation, so the parent *.env still ignores it"
    );
}

// ---------------------------------------------------------------------------
// Child scoping: a new ignore rule in a child applies only to its subtree.
// ---------------------------------------------------------------------------

#[test]
fn child_gitignore_new_rule_scoped_to_subtree_only() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_git_repo(root);
    // No *.log rule at the root; the child introduces it.
    fs::write(root.join(".gitignore"), "\n").unwrap();
    let sub = root.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join(".gitignore"), "*.log\n").unwrap();

    fs::write(root.join("root.log"), "TOKEN=ROOT_LOG_KEPT_20\n").unwrap();
    fs::write(sub.join("child.log"), "TOKEN=SUB_LOG_DROP_21\n").unwrap();
    fs::write(sub.join("keep.txt"), "TOKEN=SUB_TXT_KEPT_22\n").unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(root.to_path_buf()));
    assert!(errors.is_empty(), "no errors expected: {errors:?}");
    assert_eq!(
        files_containing(&chunks, "ROOT_LOG_KEPT_20"),
        1,
        "root.log is scanned: the *.log ignore lives only in the child .gitignore"
    );
    assert_eq!(
        files_containing(&chunks, "SUB_LOG_DROP_21"),
        0,
        "sub/child.log is dropped by the child's own *.log rule"
    );
    assert_eq!(
        files_containing(&chunks, "SUB_TXT_KEPT_22"),
        1,
        "a non-matching sibling in the same subdir is still scanned"
    );
}

// ---------------------------------------------------------------------------
// Child un-ignores an exact filename the parent ignored.
// ---------------------------------------------------------------------------

#[test]
fn child_negation_of_exact_filename_overrides_parent() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_git_repo(root);
    fs::write(root.join(".gitignore"), "secret.txt\n").unwrap();
    let sub = root.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join(".gitignore"), "!secret.txt\n").unwrap();

    fs::write(root.join("secret.txt"), "TOKEN=ROOT_SECRET_DROP_30\n").unwrap();
    fs::write(sub.join("secret.txt"), "TOKEN=SUB_SECRET_KEEP_31\n").unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(root.to_path_buf()));
    assert!(errors.is_empty(), "no errors expected: {errors:?}");
    assert_eq!(
        files_containing(&chunks, "ROOT_SECRET_DROP_30"),
        0,
        "root/secret.txt is ignored by the root rule; the child negation cannot reach up"
    );
    assert_eq!(
        files_containing(&chunks, "SUB_SECRET_KEEP_31"),
        1,
        "sub/secret.txt is re-included by the child '!secret.txt'"
    );
}

// ---------------------------------------------------------------------------
// Three-level precedence: ignore -> re-include -> ignore, deepest wins.
// ---------------------------------------------------------------------------

#[test]
fn three_level_gitignore_precedence_deepest_wins() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_git_repo(root);
    let sub = root.join("sub");
    let deep = sub.join("deep");
    fs::create_dir_all(&deep).unwrap();

    fs::write(root.join(".gitignore"), "*.cfg\n").unwrap(); // level 0: ignore
    fs::write(sub.join(".gitignore"), "!*.cfg\n").unwrap(); // level 1: re-include
    fs::write(deep.join(".gitignore"), "*.cfg\n").unwrap(); // level 2: ignore again

    fs::write(root.join("a.cfg"), "TOKEN=L0_CFG_DROP_40\n").unwrap();
    fs::write(sub.join("b.cfg"), "TOKEN=L1_CFG_KEEP_41\n").unwrap();
    fs::write(deep.join("c.cfg"), "TOKEN=L2_CFG_DROP_42\n").unwrap();
    fs::write(root.join("ctrl.txt"), "TOKEN=CTRL_KEEP_43\n").unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(root.to_path_buf()));
    assert!(errors.is_empty(), "no errors expected: {errors:?}");
    assert_eq!(
        files_containing(&chunks, "L0_CFG_DROP_40"),
        0,
        "level-0 a.cfg is ignored by the root *.cfg"
    );
    assert_eq!(
        files_containing(&chunks, "L1_CFG_KEEP_41"),
        1,
        "level-1 b.cfg is re-included by sub '!*.cfg'"
    );
    assert_eq!(
        files_containing(&chunks, "L2_CFG_DROP_42"),
        0,
        "level-2 c.cfg is ignored again by the deepest *.cfg (deepest matcher wins)"
    );
    assert_eq!(
        files_containing(&chunks, "CTRL_KEEP_43"),
        1,
        "an unrelated control .txt at the root is scanned"
    );
}

// ---------------------------------------------------------------------------
// A child wildcard re-include applies through the child's whole subtree but
// never leaks up into the parent directory.
// ---------------------------------------------------------------------------

#[test]
fn child_wildcard_reinclude_covers_subtree_not_parent() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_git_repo(root);
    let sub = root.join("sub");
    let deep = sub.join("deep");
    fs::create_dir_all(&deep).unwrap();

    fs::write(root.join(".gitignore"), "*.env\n").unwrap();
    fs::write(sub.join(".gitignore"), "!*.env\n").unwrap();

    fs::write(root.join("r.env"), "TOKEN=PARENT_ENV_DROP_50\n").unwrap();
    fs::write(sub.join("s.env"), "TOKEN=SUB_ENV_KEEP_51\n").unwrap();
    fs::write(deep.join("d.env"), "TOKEN=DEEP_ENV_KEEP_52\n").unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(root.to_path_buf()));
    assert!(errors.is_empty(), "no errors expected: {errors:?}");
    assert_eq!(
        files_containing(&chunks, "PARENT_ENV_DROP_50"),
        0,
        "the parent-directory r.env stays ignored: the child '!*.env' cannot reach up"
    );
    assert_eq!(
        files_containing(&chunks, "SUB_ENV_KEEP_51"),
        1,
        "sub/s.env is re-included by the child '!*.env'"
    );
    assert_eq!(
        files_containing(&chunks, "DEEP_ENV_KEEP_52"),
        1,
        "the child '!*.env' re-include reaches the deeper sub/deep/d.env too"
    );
}

// ---------------------------------------------------------------------------
// Within a single .gitignore, the LAST matching pattern wins.
// ---------------------------------------------------------------------------

#[test]
fn same_file_last_matching_pattern_wins() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_git_repo(root);
    // Ignore every .secret, then re-include allow.secret with a later negation.
    fs::write(root.join(".gitignore"), "*.secret\n!allow.secret\n").unwrap();
    fs::write(root.join("allow.secret"), "TOKEN=ALLOW_SECRET_KEEP_60\n").unwrap();
    fs::write(root.join("deny.secret"), "TOKEN=DENY_SECRET_DROP_61\n").unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(root.to_path_buf()));
    assert!(errors.is_empty(), "no errors expected: {errors:?}");
    assert_eq!(
        files_containing(&chunks, "ALLOW_SECRET_KEEP_60"),
        1,
        "the later '!allow.secret' negation wins over the earlier '*.secret'"
    );
    assert_eq!(
        files_containing(&chunks, "DENY_SECRET_DROP_61"),
        0,
        "deny.secret is only matched by '*.secret', so it stays ignored"
    );
}

// ---------------------------------------------------------------------------
// A parent-level re-include can itself be overridden by a deeper re-ignore.
// ---------------------------------------------------------------------------

#[test]
fn parent_reinclude_overridden_by_deeper_reignore() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_git_repo(root);
    let sub = root.join("sub");
    fs::create_dir(&sub).unwrap();

    // Root: ignore all .txt, then re-include important.txt.
    fs::write(root.join(".gitignore"), "*.txt\n!important.txt\n").unwrap();
    // Child: re-ignore important.txt within sub.
    fs::write(sub.join(".gitignore"), "important.txt\n").unwrap();

    fs::write(root.join("important.txt"), "TOKEN=ROOT_IMPORTANT_KEEP_70\n").unwrap();
    fs::write(root.join("other.txt"), "TOKEN=ROOT_OTHER_DROP_71\n").unwrap();
    fs::write(sub.join("important.txt"), "TOKEN=SUB_IMPORTANT_DROP_72\n").unwrap();
    fs::write(sub.join("note.env"), "TOKEN=SUB_NOTE_KEEP_73\n").unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(root.to_path_buf()));
    assert!(errors.is_empty(), "no errors expected: {errors:?}");
    assert_eq!(
        files_containing(&chunks, "ROOT_IMPORTANT_KEEP_70"),
        1,
        "root/important.txt is scanned via the root '!important.txt' re-include"
    );
    assert_eq!(
        files_containing(&chunks, "ROOT_OTHER_DROP_71"),
        0,
        "root/other.txt matches only '*.txt' and stays ignored"
    );
    assert_eq!(
        files_containing(&chunks, "SUB_IMPORTANT_DROP_72"),
        0,
        "sub/important.txt is re-ignored by the deeper child rule (deepest wins over parent re-include)"
    );
    assert_eq!(
        files_containing(&chunks, "SUB_NOTE_KEEP_73"),
        1,
        "the unrelated sub/note.env control is scanned"
    );
}

// ---------------------------------------------------------------------------
// Planted-secret provenance: an ignored-then-negated file is truly scanned.
// ---------------------------------------------------------------------------

#[test]
fn planted_secret_in_ignored_then_negated_file_is_scanned() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_git_repo(root);
    fs::write(root.join(".gitignore"), "*.env\n").unwrap();
    let sub = root.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join(".gitignore"), "!creds.env\n").unwrap();

    // A concrete AWS-looking access-key-id string planted in the re-included file
    // and, as the negative twin, in the file that stays ignored.
    let reincluded_secret = "AKIA_PLANTED_REINCLUDED_ZZ9988";
    let hidden_secret = "AKIA_PLANTED_HIDDEN_QQ1122";
    fs::write(
        sub.join("creds.env"),
        format!("aws_key={reincluded_secret}\n"),
    )
    .unwrap();
    fs::write(
        root.join("hidden.env"),
        format!("aws_key={hidden_secret}\n"),
    )
    .unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(root.to_path_buf()));
    assert!(errors.is_empty(), "no errors expected: {errors:?}");
    assert_eq!(
        files_containing(&chunks, reincluded_secret),
        1,
        "the planted secret in the ignored-then-negated file MUST reach a scanned chunk"
    );
    assert_eq!(
        files_containing(&chunks, hidden_secret),
        0,
        "the planted secret in the still-ignored root/hidden.env must NOT be scanned"
    );
    // Provenance check: the chunk carrying the re-included secret must name creds.env.
    let creds_chunk = chunks
        .iter()
        .find(|c| c.data.contains(reincluded_secret))
        .expect("a chunk must carry the re-included secret");
    let path = creds_chunk
        .metadata
        .path
        .as_deref()
        .expect("scanned chunk must carry a provenance path");
    assert!(
        path.ends_with("creds.env"),
        "the re-included secret's chunk must point at creds.env, got {path}"
    );
}

// ---------------------------------------------------------------------------
// Negative twin: WITHOUT a .git/ the nested .gitignore rules are fully inert.
// ---------------------------------------------------------------------------

#[test]
fn nested_gitignore_inert_without_git_repo() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Deliberately NO init_git_repo: require_git = true means .gitignore is
    // ignored outside a git repository, so everything is scanned.
    fs::write(root.join(".gitignore"), "*.env\n").unwrap();
    let sub = root.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join(".gitignore"), "!keep.env\n").unwrap();

    fs::write(root.join("top.env"), "TOKEN=NOGIT_TOP_84\n").unwrap();
    fs::write(sub.join("keep.env"), "TOKEN=NOGIT_KEEP_85\n").unwrap();
    fs::write(sub.join("other.env"), "TOKEN=NOGIT_OTHER_86\n").unwrap();

    let (chunks, errors) = drain(&FilesystemSource::new(root.to_path_buf()));
    assert!(errors.is_empty(), "no errors expected: {errors:?}");
    assert_eq!(
        files_containing(&chunks, "NOGIT_TOP_84"),
        1,
        "without a .git/ the parent '*.env' ignore is inert; top.env is scanned"
    );
    assert_eq!(
        files_containing(&chunks, "NOGIT_KEEP_85"),
        1,
        "without a .git/ keep.env is scanned (both rules inert)"
    );
    assert_eq!(
        files_containing(&chunks, "NOGIT_OTHER_86"),
        1,
        "without a .git/ other.env is scanned too (no gitignore authority)"
    );
}

// ---------------------------------------------------------------------------
// scan-system: with_respect_gitignore(false) scans the whole nested tree.
// ---------------------------------------------------------------------------

#[test]
fn respect_gitignore_off_scans_ignored_and_negated_tree() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_git_repo(root);
    fs::write(root.join(".gitignore"), "*.env\n").unwrap();
    let sub = root.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join(".gitignore"), "!keep.env\n").unwrap();

    fs::write(root.join("top.env"), "TOKEN=SYS_TOP_90\n").unwrap();
    fs::write(sub.join("keep.env"), "TOKEN=SYS_KEEP_91\n").unwrap();
    fs::write(sub.join("other.env"), "TOKEN=SYS_OTHER_92\n").unwrap();

    // First prove the DEFAULT (gitignore on) drops top.env and other.env.
    let (on_chunks, _on_err) = drain(&FilesystemSource::new(root.to_path_buf()));
    assert_eq!(
        files_containing(&on_chunks, "SYS_TOP_90"),
        0,
        "with gitignore on, the parent-ignored top.env is dropped"
    );

    // scan-system flips it off: every stashed key becomes scannable.
    let (off_chunks, off_err) =
        drain(&FilesystemSource::new(root.to_path_buf()).with_respect_gitignore(false));
    assert!(off_err.is_empty(), "no errors expected: {off_err:?}");
    assert_eq!(
        files_containing(&off_chunks, "SYS_TOP_90"),
        1,
        "with_respect_gitignore(false) must scan the parent-ignored top.env"
    );
    assert_eq!(
        files_containing(&off_chunks, "SYS_KEEP_91"),
        1,
        "keep.env is scanned regardless"
    );
    assert_eq!(
        files_containing(&off_chunks, "SYS_OTHER_92"),
        1,
        "with_respect_gitignore(false) must scan the parent-ignored other.env too"
    );
}

// ---------------------------------------------------------------------------
// The whole partition in ONE assertion: exact set of scanned relative paths.
// ---------------------------------------------------------------------------

#[test]
fn nested_gitignore_exact_scanned_relpath_set() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_git_repo(root);
    fs::write(root.join(".gitignore"), "*.env\n").unwrap();
    let sub = root.join("sub");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join(".gitignore"), "!keep.env\n").unwrap();

    fs::write(root.join("top.env"), "drop_top\n").unwrap(); // dropped
    fs::write(root.join("readme.txt"), "keep_readme\n").unwrap(); // kept
    fs::write(sub.join("keep.env"), "keep_env\n").unwrap(); // re-included
    fs::write(sub.join("other.env"), "drop_other\n").unwrap(); // dropped
    fs::write(sub.join("config.txt"), "keep_config\n").unwrap(); // kept

    let (chunks, errors) = drain(&FilesystemSource::new(root.to_path_buf()));
    assert!(errors.is_empty(), "no errors expected: {errors:?}");

    // The `.gitignore` files themselves are ordinary scannable text (skip_hidden
    // is false and they are not default-excluded), so they appear in the set.
    let expected: BTreeSet<String> = [
        ".gitignore",
        "readme.txt",
        "sub/.gitignore",
        "sub/keep.env",
        "sub/config.txt",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();

    let got = scanned_relpaths(&chunks, root);
    assert_eq!(
        got, expected,
        "the exact scanned set must be the two .gitignore files plus the kept/re-included content; \
         top.env and sub/other.env must be absent"
    );
    assert_eq!(
        scanned_count(&chunks),
        5,
        "exactly five files are scanned across the nested-gitignore tree"
    );
}
