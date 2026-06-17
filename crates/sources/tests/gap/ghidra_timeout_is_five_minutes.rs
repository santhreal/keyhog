//! Ghidra subprocess wall clock must match shared timeouts module.

#[cfg(feature = "binary")]
#[test]
fn ghidra_timeout_is_five_minutes() {
    assert_eq!(
        keyhog_sources::testing::ghidra_analysis_timeout(),
        std::time::Duration::from_secs(300),
        "GHIDRA_ANALYSIS must stay at 300s"
    );
}

#[cfg(not(feature = "binary"))]
#[test]
fn ghidra_timeout_requires_binary_feature() {
    assert!(
        !cfg!(feature = "binary"),
        "compile with --features binary to assert GHIDRA_ANALYSIS"
    );
}
