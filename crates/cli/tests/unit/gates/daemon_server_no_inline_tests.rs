//! Gate `daemon::server`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn daemon_server_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/daemon/server.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "daemon::server: move inline tests to crates/cli/tests/"
    );
}
