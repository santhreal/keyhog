//! Gate `daemon::client`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn daemon_client_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/daemon/client.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "daemon::client: move inline tests to crates/cli/tests/"
    );
}
