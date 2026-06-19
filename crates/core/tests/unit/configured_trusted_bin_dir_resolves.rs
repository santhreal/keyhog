//! Configured trusted binary directories extend safe binary resolution.

use keyhog_core::{resolve_safe_bin, set_extra_trusted_dirs};
use tempfile::TempDir;

#[test]
fn configured_trusted_bin_dir_resolves() {
    let _guard = super::SAFE_BIN_LOCK
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let dir = TempDir::new().expect("tempdir");
    let bin_name = "keyhog-safe-bin-configured-test";
    let bin = dir.path().join(bin_name);
    std::fs::write(&bin, b"#!/bin/sh\nexit 0\n").expect("write fake binary");

    set_extra_trusted_dirs(vec![dir.path().to_path_buf()]);
    let resolved = resolve_safe_bin(bin_name);
    set_extra_trusted_dirs(Vec::new());

    assert_eq!(
        resolved.as_deref(),
        Some(bin.as_path()),
        "absolute configured trusted dirs must be part of safe binary resolution"
    );
}
