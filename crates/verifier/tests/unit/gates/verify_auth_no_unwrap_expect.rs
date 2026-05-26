//! Gate `verify::auth`: no .unwrap( / .expect( in production source lines.

#[test]
fn verify_auth_no_unwrap_expect() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/verify/auth.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let mut offenders: Vec<(usize, &str)> = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let t = line.trim();
        if t.starts_with("//") || t.contains("#[cfg(test)]") {
            continue;
        }
        if t.contains(".unwrap(") || t.contains(".expect(") {
            offenders.push((i + 1, line));
        }
    }
    assert!(
        offenders.is_empty(),
        "verify::auth: unwrap/expect in production source at {:?}",
        offenders.iter().take(5).collect::<Vec<_>>()
    );
}
