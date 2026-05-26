//! Gate `daemon::server`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn daemon_server_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/daemon/server.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "daemon::server: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "daemon::server: todo!/unimplemented! forbidden in non-test source"
    );
}
