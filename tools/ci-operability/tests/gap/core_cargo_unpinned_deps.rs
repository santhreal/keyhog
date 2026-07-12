//! KH-GAP-112: STANDARD supply chain requires exact-version pins (`=x.y.z`) on external deps.

use super::support::repo_root;

fn dependency_section_lines<'a>(toml: &'a str, section: &'a str) -> Vec<&'a str> {
    let needle = format!("[{section}]");
    let mut in_section = false;
    let mut lines = Vec::new();
    for line in toml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_section = trimmed == needle;
            continue;
        }
        if in_section {
            lines.push(line);
        }
    }
    lines
}

fn is_floating_dep_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return false;
    }
    if trimmed.contains("version = \"=") {
        return false;
    }
    if trimmed.contains("workspace = true") || trimmed.contains("path =") {
        return false;
    }
    if let Some((_, rhs)) = trimmed.split_once('=') {
        let rhs = rhs.trim();
        if rhs.starts_with('"') && !rhs.starts_with("\"=") {
            return true;
        }
    }
    trimmed.starts_with("version = \"") && !trimmed.contains("version = \"=")
}

#[test]
fn keyhog_core_dependencies_are_exact_pinned() {
    let toml = std::fs::read_to_string(repo_root().join("crates/core/Cargo.toml"))
        .expect("core Cargo.toml");
    let mut offenders = Vec::new();
    for section in ["dependencies", "dev-dependencies"] {
        for line in dependency_section_lines(&toml, section) {
            if is_floating_dep_line(line) {
                offenders.push(line.trim().to_string());
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "keyhog-core must pin external deps with exact versions; floating: {offenders:?}"
    );
}
