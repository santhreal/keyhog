//! Gate `daemon::frame`: test functions stay in external split modules.

#[test]
fn daemon_frame_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/daemon/frame.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !has_test_function(&src),
        "daemon::frame: move test functions to the external frame test modules"
    );
}

fn has_test_function(source: &str) -> bool {
    source.lines().map(str::trim).any(|line| {
        line == "#[test]" || line.starts_with("#[tokio::test") || line.starts_with("#[rstest")
    })
}
