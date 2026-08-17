//! Gate `filesystem`: no .unwrap( / .expect( in production source lines.

#[test]
fn filesystem_no_unwrap_expect() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fs_dir = manifest_dir.join("src/filesystem");
    let mut files = Vec::new();

    fn collect_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    collect_rs_files(&path, out);
                } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }
    }

    collect_rs_files(&fs_dir, &mut files);
    files.push(manifest_dir.join("src/filesystem.rs"));

    let mut offenders: Vec<(String, usize, String)> = Vec::new();
    for file_path in files {
        let rel = file_path
            .strip_prefix(manifest_dir)
            .unwrap_or(&file_path)
            .display()
            .to_string();
        if rel.contains("test_support") {
            continue;
        }
        let src = std::fs::read_to_string(&file_path).expect("source readable");
        let mut in_test_cfg = false;
        for (i, line) in src.lines().enumerate() {
            let t = line.trim();
            if (t.contains("#[cfg(") && t.contains("test"))
                || t.starts_with("mod tests")
                || t.starts_with("mod test")
            {
                in_test_cfg = true;
            }
            if in_test_cfg || t.starts_with("//") {
                continue;
            }
            if t.contains(".unwrap(") || t.contains(".expect(") {
                offenders.push((rel.clone(), i + 1, line.to_string()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "filesystem: unwrap/expect in production source at {:?}",
        offenders.iter().take(5).collect::<Vec<_>>()
    );
}
