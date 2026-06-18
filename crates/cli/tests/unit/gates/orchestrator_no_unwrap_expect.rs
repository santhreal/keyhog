//! Gate `orchestrator`: no .unwrap( / .expect( in production source lines.

#[test]
fn orchestrator_no_unwrap_expect() {
    let root = std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator"));
    let mut files = Vec::new();
    collect_rust_sources(&root, &mut files);
    files.sort();

    let mut offenders: Vec<(String, usize, String)> = Vec::new();
    for path in files {
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

fn collect_rust_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
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
