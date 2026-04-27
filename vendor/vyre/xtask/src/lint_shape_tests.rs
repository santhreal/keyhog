//! `cargo xtask lint-shape-tests` — detect tests with only shape-only assertions.
//!
//! Enforces CLAUDE.md REAL TESTS rule: a test must assert specific expected
//! values, not merely check that something parsed, succeeded, or is non-empty.
//!
//! Walks every `#[test]` / `#[tokio::test]` in vyre-* + libs/tools/surgec +
//! libs/surge.  Flags as SHAPE any test whose `assert*!` calls are exclusively:
//!   - `assert!(result.is_ok())`
//!   - `assert!(result.is_err())`
//!   - `assert!(!findings.is_empty())`
//!   - `assert!(vec.len() > 0)`
//!   - `assert!(parse(s).is_ok())`
//!   - `assert_eq!(parse_then_serialize(x), x)`   (roundtrip-only)
//!
//! A test is TRUTH if it has at least one assert that names a specific value.
//!
//! Outputs `TEST_AUDIT_<datestamp>.md` at repo root.
//! Exits 1 if the percentage of shape tests in non-trivial test files exceeds
//! the threshold (default 0.0, tunable via `--threshold`).

#[path = "lint_shape_tests/classify.rs"]
mod classify;
#[path = "lint_shape_tests/report.rs"]
mod report;

use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use syn::spanned::Spanned;
use syn::{Attribute, File, Item, ItemFn};

use classify::classify_test;
use report::write_report;

/// Classification of a single test function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Classification {
    /// Only shape-only assertions.
    Shape,
    /// At least one truth assertion.
    Truth,
    /// No assert*! macros found — trivial / skipped in percentage.
    NoAsserts,
}

impl Classification {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Classification::Shape => "SHAPE",
            Classification::Truth => "TRUTH",
            Classification::NoAsserts => "NO_ASSERTS",
        }
    }
}

/// One row of the audit report.
#[derive(Debug)]
pub(crate) struct Finding {
    pub(crate) crate_name: String,
    pub(crate) module_path: String,
    pub(crate) test_name: String,
    pub(crate) file: PathBuf,
    pub(crate) line: usize,
    pub(crate) classification: Classification,
    pub(crate) reason: String,
}

/// Entry point for the `lint-shape-tests` subcommand.
pub fn run(args: &[String]) {
    let threshold = parse_threshold(args);

    let vyre_workspace = std::env::current_dir()
        .expect("xtask must run from the vyre workspace (libs/performance/matching/vyre)");
    let repo_root = vyre_workspace
        .ancestors()
        .nth(4)
        .map(Path::to_path_buf)
        .expect("Fix: vyre workspace must remain nested under libs/performance/matching/vyre.");

    let mut findings = Vec::new();

    // vyre-* crates live under the vyre workspace root.
    for entry in std::fs::read_dir(&vyre_workspace).unwrap_or_else(|e| {
        panic!(
            "Fix: cannot read vyre workspace dir {}: {e}",
            vyre_workspace.display()
        );
    }) {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("vyre-") && entry.path().is_dir() {
            walk_dir(&entry.path(), &name_str, &mut findings);
        }
    }

    // Additional out-of-workspace crates.
    for (path, name) in [
        (repo_root.join("libs/tools/surgec"), "surgec"),
        (repo_root.join("libs/surge"), "surge"),
    ] {
        if path.exists() {
            walk_dir(&path, name, &mut findings);
        }
    }

    let datestamp = iso_today();
    let report_path = repo_root.join(format!("TEST_AUDIT_{datestamp}.md"));
    write_report(&report_path, &findings);

    let non_trivial: Vec<_> = findings
        .iter()
        .filter(|f| f.classification != Classification::NoAsserts)
        .collect();
    let shape_count = non_trivial
        .iter()
        .filter(|f| f.classification == Classification::Shape)
        .count();

    let pct = if non_trivial.is_empty() {
        0.0
    } else {
        100.0 * shape_count as f64 / non_trivial.len() as f64
    };

    println!("=== lint-shape-tests ===");
    println!("Threshold:  {threshold:.1}%");
    println!("Tests:      {}", non_trivial.len());
    println!("SHAPE:      {shape_count}");
    println!("Percentage: {pct:.1}%");
    println!("Report:     {}", report_path.display());

    if pct > threshold {
        eprintln!();
        eprintln!(
            "Fix: {pct:.1}% shape tests in non-trivial test files (threshold {threshold:.1}%). \
             Add specific value assertions (assert_eq!(field, expected), etc.). \
             See {} for details.",
            report_path.display()
        );
        process::exit(1);
    }

    println!("All clear.");
}

fn iso_today() -> String {
    let output = std::process::Command::new("date")
        .arg("+%Y-%m-%d")
        .output()
        .expect("date command failed");
    String::from_utf8(output.stdout)
        .expect("date output is valid UTF-8")
        .trim()
        .to_string()
}

fn parse_threshold(args: &[String]) -> f64 {
    args.windows(2)
        .find(|w| w[0] == "--threshold")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(0.0)
}

/// Recursively walk `.rs` files under `dir` and audit test functions.
fn walk_dir(dir: &Path, crate_name: &str, findings: &mut Vec<Finding>) {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name == "target" || name == ".git" || name.starts_with('.') {
                    continue;
                }
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                audit_file(&path, crate_name, findings);
            }
        }
    }
}

/// Parse a single Rust file and classify every `#[test]` function.
fn audit_file(file: &Path, crate_name: &str, findings: &mut Vec<Finding>) {
    let source = match fs::read_to_string(file) {
        Ok(s) => s,
        Err(_) => return,
    };
    let ast: File = match syn::parse_file(&source) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Warning: failed to parse {}: {e}", file.display());
            return;
        }
    };

    let base_mod = base_module_name(file);
    visit_items(&ast.items, &base_mod, file, crate_name, findings);
}

/// Derive a base module name from a file path for top-level items.
fn base_module_name(path: &Path) -> String {
    if path.file_name() == Some(std::ffi::OsStr::new("mod.rs")) {
        path.parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string()
    } else {
        path.file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string()
    }
}

/// Recursively visit items, tracking the module path.
pub(crate) fn visit_items(
    items: &[Item],
    mod_path: &str,
    file: &Path,
    crate_name: &str,
    findings: &mut Vec<Finding>,
) {
    for item in items {
        match item {
            Item::Fn(func) => {
                if is_test_function(func) {
                    let (classification, reason) = classify_test(func);
                    let test_name = func.sig.ident.to_string();
                    let line = func.span().start().line;
                    findings.push(Finding {
                        crate_name: crate_name.to_string(),
                        module_path: mod_path.to_string(),
                        test_name,
                        file: file.to_path_buf(),
                        line,
                        classification,
                        reason,
                    });
                }
            }
            Item::Mod(item_mod) => {
                let new_path = if mod_path.is_empty() {
                    item_mod.ident.to_string()
                } else {
                    format!("{}::{}", mod_path, item_mod.ident)
                };
                if let Some((_, inner)) = &item_mod.content {
                    visit_items(inner, &new_path, file, crate_name, findings);
                }
            }
            _ => {}
        }
    }
}

/// Determine whether a function carries `#[test]` or `#[tokio::test]`.
pub(crate) fn is_test_function(func: &ItemFn) -> bool {
    func.attrs.iter().any(is_test_attr)
}

fn is_test_attr(attr: &Attribute) -> bool {
    let path = attr.path();
    if path.is_ident("test") {
        return true;
    }
    if let Some(seg) = path.segments.last() {
        if seg.ident == "test" {
            return true;
        }
    }
    false
}
