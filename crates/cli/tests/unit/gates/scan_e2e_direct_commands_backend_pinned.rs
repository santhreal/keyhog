#[test]
fn scan_e2e_direct_commands_backend_pinned() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2e");
    let mut problems = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read e2e dir") {
        let entry = entry.expect("read e2e entry");
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read e2e source");
        let mut cursor = 0usize;
        while let Some(offset) = src[cursor..].find("Command::new(binary())") {
            let start = cursor + offset;
            let rest = &src[start..];
            let end = [".output()", ".spawn()", ".status()"]
                .iter()
                .filter_map(|marker| rest.find(marker))
                .min()
                .map(|end| start + end)
                .unwrap_or(src.len());
            let block = &src[start..end];
            let is_scan = block.contains("\"scan\"") || block.contains(".arg(\"scan\")");
            let pinned = block.contains("\"--backend\"")
                || block.contains("\"--daemon=on\"")
                || block.contains(".arg(\"--daemon=on\")");
            if is_scan && !pinned {
                problems.push(format!(
                    "{} has a direct keyhog scan subprocess without explicit backend evidence",
                    path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
                        .unwrap_or(&path)
                        .display()
                ));
            }
            cursor = end.saturating_add(1);
        }
    }

    assert!(
        problems.is_empty(),
        "non-routing e2e scan tests must pin a diagnostic backend; default auto \
         is reserved for autoroute tests with persisted calibration evidence:\n{}",
        problems.join("\n")
    );
}
