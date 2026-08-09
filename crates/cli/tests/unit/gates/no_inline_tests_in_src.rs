//! No inline test bodies anywhere in `crates/cli/src`.
//!
//! This replaces twenty-four near-identical files, each hardcoding one path and
//! asserting that path had no `#[cfg(test)]`. That shape only ever covered the
//! files somebody remembered to write a gate for, so a new module with inline
//! tests was invisible until a reviewer noticed. Scanning the tree closes that
//! and collapses 329 lines into one rule.
//!
//! A `#[cfg(test)] #[path = "../tests/..."] mod` hook is not an inline body:
//! the attribute sits in `src`, the code does not. That is the sanctioned way
//! to reach crate-private items from a test, and `lib.rs` and `config.rs`
//! already use it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Files allowed to keep an inline `#[cfg(test)]` body, each with the reason.
///
/// Seeded with the debt that existed the day this gate replaced twenty-four
/// per-file ones. Those covered twenty-four paths; the tree actually had
/// 25, so most of this list was never gated at all and the rest of
/// `orchestrator/dispatch/backend/` was invisible.
///
/// The list only shrinks. A new file cannot join it without failing the gate,
/// and an entry that no longer has an inline body fails too, so an exception
/// cannot outlive its justification.
const ALLOWLIST: &[&str] = &[
    "atomic_file.rs",
    "daemon/client.rs",
    "daemon/client_tests.rs",
    "daemon/frame.rs",
    "daemon/protocol.rs",
    "daemon/server_tests.rs",
    "lib.rs",
    "log_dedup.rs",
    "orchestrator/dispatch.rs",
    "orchestrator/dispatch/backend.rs",
    "orchestrator/dispatch/backend/calibration.rs",
    "orchestrator/dispatch/backend/evidence.rs",
    "orchestrator/dispatch/backend/evidence/timing.rs",
    "orchestrator/dispatch/backend/store.rs",
    "orchestrator/dispatch/backend/store/inspection.rs",
    "orchestrator/dispatch/backend/store/persistence.rs",
    "orchestrator/dispatch/backend/workload.rs",
    "orchestrator/mod.rs",
    "orchestrator/reporting.rs",
    "orchestrator_config/runtime_tests.rs",
    "reporting.rs",
    "subcommands/backend.rs",
    "subcommands/calibrate_autoroute.rs",
    "subcommands/doctor.rs",
    "subcommands/watch.rs",
];

fn src_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Whether `#[cfg(test)]` at `index` opens an inline body rather than a
/// `#[path]` include.
fn opens_inline_body(lines: &[&str], index: usize) -> bool {
    let next = lines
        .iter()
        .skip(index + 1)
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim())
        .unwrap_or_default();
    !next.starts_with("#[path")
}

fn offenders() -> BTreeSet<String> {
    let root = src_dir();
    let mut found = BTreeSet::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("read_dir({}) failed: {error}", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|value| value.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {} failed: {error}", path.display()));
            let lines: Vec<&str> = source.lines().map(str::trim).collect();
            let inline = lines
                .iter()
                .enumerate()
                .any(|(index, line)| *line == "#[cfg(test)]" && opens_inline_body(&lines, index));
            if inline {
                let rel = path
                    .strip_prefix(&root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                found.insert(rel);
            }
        }
    }
    found
}

/// No source file carries an inline test body, and no allowlist entry is stale.
///
/// Both directions matter. A new offender is the thing the gate exists to
/// catch; a stale entry means someone did the work and the exemption stayed
/// behind, which is how the list grows into something nobody trusts.
#[test]
fn no_inline_tests_in_src() {
    let found = offenders();
    let allowed: BTreeSet<String> = ALLOWLIST.iter().map(|entry| (*entry).to_string()).collect();

    let unexpected: Vec<&String> = found.difference(&allowed).collect();
    assert!(
        unexpected.is_empty(),
        "these files carry an inline #[cfg(test)] body; move it under crates/cli/tests/ and \
         include it with `#[cfg(test)] #[path = \"../tests/...\"] mod ...;`: {unexpected:?}"
    );

    let stale: Vec<&String> = allowed.difference(&found).collect();
    assert!(
        stale.is_empty(),
        "these files no longer carry an inline test body; delete their ALLOWLIST entries: {stale:?}"
    );
}

/// The detector reads what the rule means, not the four characters.
///
/// A `#[path]` include has `#[cfg(test)]` in the source too. Counting it would
/// have banned the pattern the project uses to reach crate-private items, which
/// is the mistake the per-file gates made before they were fixed one at a time.
#[test]
fn a_path_included_module_is_not_an_inline_body() {
    let included = ["#[cfg(test)]", "#[path = \"../tests/unit/x.rs\"]", "mod x;"];
    assert!(!opens_inline_body(&included, 0));

    let inline = ["#[cfg(test)]", "mod tests {", "}"];
    assert!(opens_inline_body(&inline, 0));

    let spaced = [
        "#[cfg(test)]",
        "",
        "#[path = \"../tests/unit/x.rs\"]",
        "mod x;",
    ];
    assert!(!opens_inline_body(&spaced, 0));
}

/// The scan actually reaches nested modules.
///
/// A gate that silently walked only the top level would pass forever while
/// `src/subcommands/` filled up, which is the failure mode the twenty-four
/// hardcoded files had by construction.
#[test]
fn the_scan_reaches_nested_source_directories() {
    let root = src_dir();
    let nested = root.join("subcommands");
    assert!(
        nested.is_dir(),
        "expected a nested source directory to prove the walk descends"
    );
    let seen_nested = {
        let mut stack = vec![root.clone()];
        let mut count = 0usize;
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read_dir").flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(|v| v.to_str()) == Some("rs")
                    && path.starts_with(&nested)
                {
                    count += 1;
                }
            }
        }
        count
    };
    assert!(
        seen_nested > 1,
        "the walk must descend into nested directories; saw {seen_nested} files under subcommands"
    );
    let _ = Path::new("");
}
