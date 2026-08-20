//! Regression gate: tests must not read crate source via a bare CWD-relative
//! path.
//!
//! A `read_to_string("src/...")` (or `File::open` / `fs::read` of a `"src/..."`
//! / `"crates/..."` / `"../<crate>/src/..."` literal) resolves the relative
//! path against the **process working directory**, which only equals the
//! package root under a plain `cargo test`. The same call fails with `NotFound`
//! when the test binary is run directly, under `cargo-nextest` (CWD = workspace
//! root, not package), or whenever a sibling test mutates the global CWD, a
//! deterministic structural check turned into a parallel-load flake.
//!
//! The fix is the canonical [`keyhog_core::testing::read_crate_source`] helper,
//! anchored to the compile-time `CARGO_MANIFEST_DIR`. This gate keeps the bug
//! class closed: it walks every `*.rs` under `tests/` and fails if any file
//! opens a crate-source path relative to the CWD.

use std::path::PathBuf;

/// File-read entry points whose first argument, when it is a string literal
/// beginning with a crate-source prefix, is CWD-relative and therefore fragile.
const READ_ENTRY_POINTS: &[&str] = &["read_to_string(", "File::open(", "fs::read("];

/// Classify a string-literal argument body as a CWD-relative *crate source*
/// read, returning the offending prefix kind, or `None` if the literal is not
/// crate source (a temp path, a fixture, an absolute path, …).
///
/// In scope: `src/...` and `crates/...` (this crate / the workspace), plus
/// `../.../src/...` (a sibling crate's source read from a parent-relative path
/// e.g. a core test introspecting `../cli/src/...`). Out of scope: `./`,
/// `tests/`, absolute, and any non-`/src/` parent path, runtime data, not
/// crate-source introspection.
fn crate_source_prefix(body: &str) -> Option<&'static str> {
    if body.starts_with("src/") {
        Some("src/")
    } else if body.starts_with("crates/") {
        Some("crates/")
    } else if body.starts_with("../") && body.contains("/src/") {
        Some("../")
    } else {
        None
    }
}

#[test]
fn no_test_reads_crate_source_relative_to_cwd() {
    let tests_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    // The gate file references the banned forms in prose/needles; exclude it so
    // it cannot flag itself. Matched by file name, not full path.
    let self_name = "no_cwd_relative_source_reads.rs";

    let mut offenders: Vec<String> = Vec::new();
    for path in walk_rs_files(&tests_root) {
        if path.file_name().and_then(|n| n.to_str()) == Some(self_name) {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read test file {}: {e}", path.display()));
        for (line_no, line) in text.lines().enumerate() {
            if let Some(prefix) = cwd_relative_source_read(line) {
                offenders.push(format!(
                    "{}:{} reads a \"{prefix}…\" crate-source literal relative to the CWD",
                    path.display(),
                    line_no + 1
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "tests must read crate source via keyhog_core::testing::read_crate_source \
         (CARGO_MANIFEST_DIR-anchored), not relative to the working directory. Offenders:\n{}",
        offenders.join("\n")
    );
}

/// If `line` calls a file-read entry point directly on a string literal that
/// begins with a crate-source prefix, return that prefix; otherwise `None`.
/// Exercised below against crafted positive/negative lines (filesystem-free).
fn cwd_relative_source_read(line: &str) -> Option<&'static str> {
    for entry in READ_ENTRY_POINTS {
        let mut from = 0;
        while let Some(rel) = line[from..].find(entry) {
            let after_open = from + rel + entry.len();
            let arg = line[after_open..].trim_start();
            if let Some(body) = arg.strip_prefix('"') {
                if let Some(hit) = crate_source_prefix(body) {
                    return Some(hit);
                }
            }
            from = after_open;
        }
    }
    None
}

/// Recursively collect `*.rs` files under `root` (skipping `mod.rs`, which only
/// wires submodules and never reads source).
fn walk_rs_files(root: &PathBuf) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_rs_files(&path));
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs")
            && path.file_name().and_then(|s| s.to_str()) != Some("mod.rs")
        {
            out.push(path);
        }
    }
    out
}

// ── Predicate unit coverage (pure, filesystem-free) ─────────────────────────

#[test]
fn predicate_flags_read_to_string_of_src_literal() {
    assert_eq!(
        cwd_relative_source_read(r#"    let s = std::fs::read_to_string("src/merkle_index.rs");"#),
        Some("src/")
    );
}

#[test]
fn predicate_flags_read_to_string_of_crates_literal() {
    assert_eq!(
        cwd_relative_source_read(r#"read_to_string("crates/core/src/lib.rs")"#),
        Some("crates/")
    );
}

#[test]
fn predicate_flags_cross_crate_parent_src_literal() {
    assert_eq!(
        cwd_relative_source_read(r#"read_to_string("../cli/src/orchestrator/dispatch.rs")"#),
        Some("../")
    );
}

#[test]
fn predicate_flags_file_open_of_src_literal() {
    assert_eq!(
        cwd_relative_source_read(r#"File::open("src/spec/validate.rs")"#),
        Some("src/")
    );
}

#[test]
fn predicate_flags_fs_read_of_src_literal() {
    assert_eq!(
        cwd_relative_source_read(r#"let b = fs::read("src/calibration.rs");"#),
        Some("src/")
    );
}

#[test]
fn predicate_tolerates_whitespace_before_argument() {
    assert_eq!(
        cwd_relative_source_read(r#"read_to_string(  "src/x.rs")"#),
        Some("src/")
    );
}

#[test]
fn predicate_ignores_manifest_anchored_join() {
    assert_eq!(
        cwd_relative_source_read(r#"std::fs::read_to_string(root.join(rel)).expect("x")"#),
        None
    );
}

#[test]
fn predicate_ignores_concat_manifest_dir() {
    assert_eq!(
        cwd_relative_source_read(
            r#"read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))"#
        ),
        None
    );
}

#[test]
fn predicate_ignores_canonical_read_crate_source() {
    assert_eq!(
        cwd_relative_source_read(
            r#"keyhog_core::testing::read_crate_source("src/merkle_index.rs")"#
        ),
        None
    );
}

#[test]
fn predicate_ignores_tempdir_absolute_literal() {
    assert_eq!(
        cwd_relative_source_read(r#"read_to_string("/tmp/x.rs")"#),
        None
    );
}

#[test]
fn predicate_ignores_non_source_relative_literal() {
    assert_eq!(
        cwd_relative_source_read(r#"read_to_string("tests/fixtures/a.txt")"#),
        None
    );
    assert_eq!(
        cwd_relative_source_read(r#"read_to_string("./data.json")"#),
        None
    );
}

#[test]
fn predicate_ignores_parent_relative_non_source_literal() {
    assert_eq!(
        cwd_relative_source_read(r#"read_to_string("../fixtures/data.txt")"#),
        None
    );
}

#[test]
fn predicate_ignores_empty_line() {
    assert_eq!(cwd_relative_source_read(""), None);
    assert_eq!(cwd_relative_source_read("   // a comment"), None);
}

#[test]
fn predicate_ignores_src_substring_not_at_literal_start() {
    assert_eq!(
        cwd_relative_source_read(r#"read_to_string("my-src/x.rs")"#),
        None
    );
}

#[test]
fn predicate_handles_two_reads_on_one_line() {
    let line = r#"read_to_string(root.join(a)); read_to_string("src/b.rs");"#;
    assert_eq!(cwd_relative_source_read(line), Some("src/"));
}

#[test]
fn walk_finds_this_gate_file() {
    let tests_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let files = walk_rs_files(&tests_root);
    assert!(
        files
            .iter()
            .any(|p| p.file_name().and_then(|n| n.to_str())
                == Some("no_cwd_relative_source_reads.rs")),
        "walker must discover the gate's own file"
    );
}

#[test]
fn walk_skips_mod_rs() {
    let tests_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let files = walk_rs_files(&tests_root);
    assert!(
        !files
            .iter()
            .any(|p| p.file_name().and_then(|n| n.to_str()) == Some("mod.rs")),
        "walker must skip mod.rs wiring files"
    );
}

#[test]
fn walk_returns_only_rs_files() {
    let tests_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    for p in walk_rs_files(&tests_root) {
        assert_eq!(
            p.extension().and_then(|s| s.to_str()),
            Some("rs"),
            "non-rs file: {}",
            p.display()
        );
    }
}

#[test]
fn walk_missing_dir_is_empty_not_panic() {
    let missing = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/__does_not_exist__");
    assert!(walk_rs_files(&missing).is_empty());
}
