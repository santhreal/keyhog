//! Relative trusted binary directories are ignored.

use keyhog_core::{resolve_safe_bin, set_extra_trusted_dirs};
use std::path::PathBuf;

#[test]
fn relative_configured_trusted_bin_dir_ignored() {
    let _guard = super::SAFE_BIN_LOCK
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let bin_name = "keyhog-safe-bin-relative-test";

    set_extra_trusted_dirs(vec![PathBuf::from(".")]);
    let resolved = resolve_safe_bin(bin_name);
    set_extra_trusted_dirs(Vec::new());

    assert!(
        resolved.is_none(),
        "relative trusted dirs must not make safe binary resolution depend on cwd"
    );
}
