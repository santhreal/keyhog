//! Gate `daemon::client`: test functions stay in external split modules.

#[test]
fn daemon_client_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/daemon/client.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !has_test_function(&src),
        "daemon::client: move test functions to the external client_tests module"
    );
}

fn has_test_function(source: &str) -> bool {
    source.lines().map(str::trim).any(|line| {
        line == "#[test]" || line.starts_with("#[tokio::test") || line.starts_with("#[rstest")
    })
}
