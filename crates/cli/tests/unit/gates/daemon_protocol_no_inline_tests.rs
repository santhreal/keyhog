//! Gate `daemon::protocol`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn daemon_protocol_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/daemon/protocol.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "daemon::protocol: move inline tests to crates/cli/tests/"
    );
}
