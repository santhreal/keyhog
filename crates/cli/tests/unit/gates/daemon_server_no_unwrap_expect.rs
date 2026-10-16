//! Gate `daemon::server`: no .unwrap( / .expect( in production source lines.

#[test]
fn daemon_server_no_unwrap_expect() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders: Vec<(String, usize, String)> = Vec::new();
    for rel in [
        "src/daemon/server.rs",
        "src/daemon/server/guard_policy.rs",
        "src/daemon/server/target_dispatch.rs",
    ] {
        let src = std::fs::read_to_string(root.join(rel)).expect("source readable");
        for (i, line) in src.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") || t.contains("#[cfg(test)]") {
                continue;
            }
            if t.contains(".unwrap(") || t.contains(".expect(") {
                offenders.push((rel.to_string(), i + 1, line.to_string()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "daemon::server: unwrap/expect in production source at {:?}",
        offenders.iter().take(5).collect::<Vec<_>>()
    );
}
