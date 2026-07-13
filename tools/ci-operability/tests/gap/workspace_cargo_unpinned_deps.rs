//! KH-GAP-112: the workspace supply chain requires exact-version pins (`=x.y.z`) on external deps.

use super::support::repo_root;

fn dependency_section_lines(toml: &str) -> Vec<&str> {
    let mut in_section = false;
    let mut lines = Vec::new();
    for line in toml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            let section = trimmed.trim_matches(['[', ']']);
            in_section = section == "workspace.dependencies"
                || section == "dependencies"
                || section == "dev-dependencies"
                || section == "build-dependencies"
                || section.ends_with(".dependencies")
                || section.ends_with(".dev-dependencies")
                || section.ends_with(".build-dependencies");
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
fn workspace_direct_dependencies_are_exact_pinned() {
    let root = repo_root();
    let mut manifests = vec![root.join("Cargo.toml")];
    manifests.extend(
        std::fs::read_dir(root.join("crates"))
            .expect("read crates directory")
            .filter_map(Result::ok)
            .map(|entry| entry.path().join("Cargo.toml"))
            .filter(|path| path.is_file()),
    );
    let mut offenders = Vec::new();
    for manifest in manifests {
        let toml = std::fs::read_to_string(&manifest).expect("read workspace Cargo.toml");
        for line in dependency_section_lines(&toml) {
            if is_floating_dep_line(line) {
                offenders.push(format!(
                    "{}: {}",
                    manifest.strip_prefix(&root).unwrap_or(&manifest).display(),
                    line.trim()
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "KeyHog workspace dependencies must use workspace/path ownership or exact external versions; floating: {offenders:?}"
    );
}
