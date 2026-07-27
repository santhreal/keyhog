//! LR2-A8 harness integration: the private daemon wire owner stays versioned.

#[test]
fn daemon_wire_version_has_a_private_nonzero_owner() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/daemon/protocol.rs");
    let source = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "read private daemon protocol owner {}: {error}",
            path.display()
        )
    });
    let declaration = source
        .lines()
        .map(str::trim)
        .find_map(|line| {
            line.strip_prefix("pub(crate) const WIRE_VERSION: u32 = ")
                .and_then(|value| value.strip_suffix(';'))
        })
        .expect("daemon protocol must privately own WIRE_VERSION");
    let wire_version = declaration
        .parse::<u32>()
        .expect("WIRE_VERSION must be a u32 literal");

    assert_ne!(wire_version, 0, "daemon WIRE_VERSION must be nonzero");
    assert!(
        !source
            .lines()
            .map(str::trim)
            .any(|line| line.starts_with("pub const WIRE_VERSION")),
        "daemon WIRE_VERSION must not be exposed outside the crate"
    );
}
