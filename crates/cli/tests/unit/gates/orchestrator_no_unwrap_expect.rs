//! Gate `orchestrator`: no .unwrap( / .expect( in production source lines.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[test]
fn orchestrator_no_unwrap_expect() {
    let root = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator"));
    let mut files = Vec::new();
    collect_rust_sources(&root, &mut files);
    files.sort();
    let external_test_modules = externally_split_test_modules(&files);
    let external_test_module_dirs: Vec<_> = external_test_modules
        .iter()
        .map(|path| path.with_extension(""))
        .filter(|path| path.is_dir())
        .collect();

    let mut offenders: Vec<(String, usize, String)> = Vec::new();
    for path in files {
        if external_test_modules.contains(&path)
            || external_test_module_dirs
                .iter()
                .any(|directory| path.starts_with(directory))
        {
            continue;
        }
        let display = path
            .strip_prefix(concat!(env!("CARGO_MANIFEST_DIR"), "/"))
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| path.display().to_string());
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} source readable: {error}", path.display()));
        let mut test_module_depth: Option<i32> = None;
        let mut pending_cfg_test = false;

        for (i, line) in src.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") {
                continue;
            }
            if t == "#[cfg(test)]" {
                pending_cfg_test = true;
                continue;
            }
            if pending_cfg_test && (t.starts_with("mod tests") || t.starts_with("pub mod tests")) {
                test_module_depth = Some(brace_delta(line));
                pending_cfg_test = false;
                continue;
            }
            pending_cfg_test = false;

            if let Some(depth) = test_module_depth.as_mut() {
                *depth += brace_delta(line);
                if *depth <= 0 {
                    test_module_depth = None;
                }
                continue;
            }

            if t.contains(".unwrap(") || t.contains(".expect(") {
                offenders.push((display.clone(), i + 1, line.to_string()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "orchestrator: unwrap/expect in production source at {:?}",
        offenders.iter().take(8).collect::<Vec<_>>()
    );
}

fn externally_split_test_modules(files: &[PathBuf]) -> BTreeSet<PathBuf> {
    let sources: Vec<_> = files
        .iter()
        .map(|owner| {
            let source = std::fs::read_to_string(owner)
                .unwrap_or_else(|error| panic!("{} source readable: {error}", owner.display()));
            (owner, source)
        })
        .collect();
    let mut test_modules = BTreeSet::new();

    loop {
        let before = test_modules.len();
        for (owner, source) in &sources {
            let inherited_test_module = test_modules.contains(*owner);
            let mut pending_cfg_test = false;
            let mut explicit_path: Option<&str> = None;
            for line in source.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with("//") {
                    continue;
                }
                if trimmed == "#[cfg(test)]" {
                    pending_cfg_test = true;
                    explicit_path = None;
                    continue;
                }
                if !inherited_test_module && !pending_cfg_test {
                    continue;
                }
                if let Some(path) = trimmed
                    .strip_prefix("#[path = \"")
                    .and_then(|rest| rest.strip_suffix("\"]"))
                {
                    explicit_path = Some(path);
                    continue;
                }
                if trimmed.starts_with("#[") {
                    continue;
                }
                if let Some(name) = trimmed
                    .strip_prefix("mod ")
                    .and_then(|rest| rest.strip_suffix(';'))
                {
                    let parent = owner.parent().expect("Rust source has parent directory");
                    let candidate = explicit_path.map_or_else(
                        || {
                            if owner.file_name().and_then(|name| name.to_str()) == Some("mod.rs") {
                                parent.join(format!("{name}.rs"))
                            } else {
                                parent
                                    .join(owner.file_stem().expect("Rust source has a file stem"))
                                    .join(format!("{name}.rs"))
                            }
                        },
                        |path| parent.join(path),
                    );
                    if candidate.is_file() {
                        test_modules.insert(candidate);
                    }
                }
                pending_cfg_test = false;
                explicit_path = None;
            }
        }
        if test_modules.len() == before {
            break;
        }
    }

    test_modules
}

fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read orchestrator dir {}: {error}", dir.display()))
    {
        let entry = entry.unwrap_or_else(|error| panic!("read orchestrator entry: {error}"));
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, out);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) == Some("rs")
            && path.file_name().and_then(|name| name.to_str()) != Some("tests.rs")
        {
            out.push(path);
        }
    }
}

fn brace_delta(line: &str) -> i32 {
    line.chars().fold(0, |depth, ch| match ch {
        '{' => depth + 1,
        '}' => depth - 1,
        _ => depth,
    })
}
