//! Gate `daemon::client`: modularity file cap (500 LOC).

#[test]
fn daemon_client_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/daemon/client.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "daemon::client: {lines} lines exceeds 500-line cap — split module"
    );
}
