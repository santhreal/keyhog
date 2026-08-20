//! KH-GAP-004 (cli slice): production files must not host inline test blocks.

use std::path::{Path, PathBuf};

/// True if the file hosts an inline `#[cfg(test)]`-gated module BLOCK
/// (`#[cfg(test)] mod <name> { ... }`), the pattern the Santh folder contract
/// forbids in production source. A COMPLIANT sibling declaration
/// (`#[cfg(test)] mod tests;`, whose body lives in a separate `tests.rs`) ends
/// in `;` and is intentionally allowed. Any module NAME is caught, not just
/// `tests`, so a `mod low_ram_cap_tests { .. }` cannot slip through.
fn has_inline_test_block(content: &str) -> bool {
    let lines: Vec<&str> = content.lines().collect();
    lines.iter().enumerate().any(|(i, line)| {
        if line.trim() != "#[cfg(test)]" {
            return false;
        }
        // The item this attribute gates: the next non-blank, non-attribute line.
        lines[i + 1..]
            .iter()
            .find(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with("#[")
            })
            .is_some_and(|item| {
                let t = item.trim();
                t.starts_with("mod ") && t.ends_with('{')
            })
    })
}

fn scan_rust_sources(dir: &Path, offenders: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir({}) failed: {e}", dir.display()));
    for entry in entries {
        let entry =
            entry.unwrap_or_else(|e| panic!("read_dir({}) entry failed: {e}", dir.display()));
        let path = entry.path();
        if path.is_dir() {
            scan_rust_sources(&path, offenders);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()));
        if path.file_name().and_then(|name| name.to_str()) == Some("tests.rs") {
            continue;
        }
        if has_inline_test_block(&content) {
            offenders.push(path);
        }
    }
}

#[test]
fn no_inline_tests_in_src() {
    let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    scan_rust_sources(&src_dir, &mut offenders);
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "{} cli/src files still contain inline `mod tests {{` blocks - migrate to tests/unit/ or a separate test module:\n  - {}",
        offenders.len(),
        offenders
            .iter()
            .map(|p| p
                .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .unwrap_or(p)
                .display()
                .to_string())
            .collect::<Vec<_>>()
            .join("\n  - ")
    );
}
