//! Scanner test wiring guard.
//!
//! Cargo auto-discovers only `tests/*.rs`. Files below `tests/<dir>/` compile
//! only when a parent `mod`, a root driver `#[path]`, or an explicit Cargo
//! `[[test]]` path reaches them. This guard models those real wiring routes so
//! helpers and target-spec binaries are not false positives, while orphan test
//! shards cannot sit on disk unseen.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

fn tests_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn scanner_src_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn normalize_path(path: PathBuf) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn rust_files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry
            .unwrap_or_else(|e| panic!("read entry under {}: {e}", dir.display()))
            .path();
        if path.is_dir() {
            rust_files_under(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(normalize_path(path));
        }
    }
}

fn module_dirs_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry
            .unwrap_or_else(|e| panic!("read entry under {}: {e}", dir.display()))
            .path();
        if !path.is_dir() {
            continue;
        }
        if path.join("mod.rs").exists() {
            out.push(normalize_path(path.clone()));
        }
        module_dirs_under(&path, out);
    }
}

fn strip_line_comment(line: &str) -> &str {
    line.split_once("//").map_or(line, |(head, _)| head)
}

fn path_attr(line: &str) -> Option<String> {
    let line = strip_line_comment(line).trim();
    let rest = line.strip_prefix("#[path")?.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let (path, _) = rest.split_once('"')?;
    Some(path.to_string())
}

fn module_name(line: &str) -> Option<String> {
    let line = strip_line_comment(line).trim().trim_end_matches(';').trim();
    let rest = line
        .strip_prefix("pub(crate) mod ")
        .or_else(|| line.strip_prefix("pub mod "))
        .or_else(|| line.strip_prefix("mod "))?;
    rest.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
        .then(|| rest.to_string())
}

fn module_target(parent: &Path, name: &str) -> Option<PathBuf> {
    let file = normalize_path(parent.join(format!("{name}.rs")));
    if file.exists() {
        return Some(file);
    }
    let dir_mod = normalize_path(parent.join(name).join("mod.rs"));
    if dir_mod.exists() {
        return Some(dir_mod);
    }
    None
}

fn path_attr_target(parent: &Path, attr: &str) -> Option<PathBuf> {
    let target = normalize_path(parent.join(attr));
    if target.exists() {
        Some(target)
    } else {
        None
    }
}

fn wired_by_rust_modules(root: &Path) -> BTreeSet<PathBuf> {
    let mut sources = Vec::new();
    rust_files_under(root, &mut sources);

    let mut wired = BTreeSet::new();
    for source in sources {
        let parent = source
            .parent()
            .unwrap_or_else(|| panic!("{} has parent", source.display()));
        let src = std::fs::read_to_string(&source)
            .unwrap_or_else(|e| panic!("read {}: {e}", source.display()));
        let mut pending_path = None;
        for line in src.lines() {
            if let Some(path) = path_attr(line) {
                pending_path = Some(path);
                continue;
            }
            let Some(name) = module_name(line) else {
                continue;
            };
            let target = if let Some(path) = pending_path.take() {
                path_attr_target(parent, &path)
            } else {
                module_target(parent, &name)
            };
            if let Some(target) = target {
                wired.insert(target);
            }
        }
    }
    wired
}

fn explicit_cargo_test_targets(root: &Path) -> BTreeSet<PathBuf> {
    let cargo_toml = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let src = std::fs::read_to_string(&cargo_toml)
        .unwrap_or_else(|e| panic!("read {}: {e}", cargo_toml.display()));
    src.lines()
        .filter_map(|line| {
            let line = strip_line_comment(line).trim();
            let rest = line.strip_prefix("path")?.trim_start();
            let rest = rest.strip_prefix('=')?.trim_start();
            let rest = rest.strip_prefix('"')?;
            let (path, _) = rest.split_once('"')?;
            path.strip_prefix("tests/")
                .map(|rel| normalize_path(root.join(rel)))
        })
        .filter(|path| path.exists())
        .collect()
}

fn auto_discovered_root_targets(root: &Path) -> BTreeSet<PathBuf> {
    std::fs::read_dir(root)
        .unwrap_or_else(|e| panic!("read {}: {e}", root.display()))
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            (path.extension().and_then(|ext| ext.to_str()) == Some("rs"))
                .then(|| normalize_path(path))
        })
        .collect()
}

fn sibling_targets(dir: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry
            .unwrap_or_else(|e| panic!("read entry under {}: {e}", dir.display()))
            .path();
        if path.is_dir() {
            let mod_rs = normalize_path(path.join("mod.rs"));
            if mod_rs.exists() {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("utf8 module dir")
                    .to_string();
                out.push((name, mod_rs));
            }
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        if path.file_name().is_some_and(|name| name == "mod.rs") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|name| name.to_str())
            .expect("utf8 module file")
            .to_string();
        out.push((name, normalize_path(path)));
    }
    out.sort();
    out
}

fn manifest_phantoms(dir: &Path) -> Vec<String> {
    let manifest = dir.join("mod.rs");
    let src = std::fs::read_to_string(&manifest)
        .unwrap_or_else(|e| panic!("read {}: {e}", manifest.display()));
    let mut phantoms = Vec::new();
    let mut pending_path = false;
    for line in src.lines() {
        if path_attr(line).is_some() {
            pending_path = true;
            continue;
        }
        let Some(name) = module_name(line) else {
            continue;
        };
        if pending_path {
            pending_path = false;
            continue;
        }
        if module_target(dir, &name).is_none() {
            phantoms.push(name);
        }
    }
    phantoms
}

pub fn assert_all_scanner_test_module_files_are_wired() {
    let root = tests_root();
    let mut wired = wired_by_rust_modules(&root);
    // Unit shards may be owned by the production module they exercise through
    // a `#[cfg(test)] #[path = "../../tests/..."] mod tests;` declaration.
    // Those are real compiled routes, not orphans, so inspect both sides of the
    // crate boundary before declaring coverage invisible.
    wired.extend(wired_by_rust_modules(&scanner_src_root()));
    wired.extend(explicit_cargo_test_targets(&root));
    wired.extend(auto_discovered_root_targets(&root));

    let mut dirs = Vec::new();
    module_dirs_under(&root, &mut dirs);
    dirs.sort();

    let mut problems = Vec::new();
    for dir in dirs {
        let mut orphans = Vec::new();
        for (name, target) in sibling_targets(&dir) {
            if !wired.contains(&target) {
                orphans.push(name);
            }
        }
        let phantoms = manifest_phantoms(&dir);
        if !orphans.is_empty() || !phantoms.is_empty() {
            let rel = dir.strip_prefix(&root).unwrap_or(&dir).display();
            problems.push(format!(
                "{rel}/mod.rs: orphans={orphans:?}; phantoms={phantoms:?}"
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "scanner test module wiring drift; orphaned files are invisible coverage loss:\n{}",
        problems.join("\n")
    );
}

pub fn assert_suite_sibling_files_are_wired(suite_rel: &str) {
    let root = tests_root();
    let dir = normalize_path(root.join(suite_rel));
    let mut wired = wired_by_rust_modules(&root);
    wired.extend(wired_by_rust_modules(&scanner_src_root()));
    wired.extend(explicit_cargo_test_targets(&root));
    wired.extend(auto_discovered_root_targets(&root));

    let orphans: Vec<String> = sibling_targets(&dir)
        .into_iter()
        .filter_map(|(name, target)| (!wired.contains(&target)).then_some(name))
        .collect();
    let phantoms = manifest_phantoms(&dir);

    assert!(
        orphans.is_empty() && phantoms.is_empty(),
        "{suite_rel}/mod.rs wiring drift; orphans={orphans:?}; phantoms={phantoms:?}"
    );
}
