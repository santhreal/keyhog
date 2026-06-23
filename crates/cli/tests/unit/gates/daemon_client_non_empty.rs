//! Gate `daemon::client`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn daemon_client_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/daemon/client.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "daemon::client: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "daemon::client: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        prod.contains("const DAEMON_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);")
            && prod.contains("tokio::time::timeout(DAEMON_HANDSHAKE_TIMEOUT, client.recv())")
            && prod.contains("handshake timeout waiting for Hello"),
        "daemon client Hello handshake receive must have an operator-visible timeout"
    );
}
