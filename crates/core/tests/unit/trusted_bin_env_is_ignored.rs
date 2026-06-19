//! Ambient KEYHOG_TRUSTED_BIN_DIR must not expand the binary trust boundary.

use keyhog_core::{resolve_safe_bin, set_extra_trusted_dirs};
use std::ffi::OsString;
use std::sync::Mutex;
use tempfile::TempDir;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn restore_env(key: &str, previous: Option<OsString>) {
    unsafe {
        match previous {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }
}

#[test]
fn trusted_bin_env_is_ignored() {
    let _safe_bin_guard = super::SAFE_BIN_LOCK
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let previous = std::env::var_os("KEYHOG_TRUSTED_BIN_DIR");
    let dir = TempDir::new().expect("tempdir");
    let bin_name = "keyhog-safe-bin-env-test";
    std::fs::write(dir.path().join(bin_name), b"#!/bin/sh\nexit 0\n").expect("write fake binary");

    set_extra_trusted_dirs(Vec::new());
    unsafe { std::env::set_var("KEYHOG_TRUSTED_BIN_DIR", dir.path()) };
    let resolved = resolve_safe_bin(bin_name);
    restore_env("KEYHOG_TRUSTED_BIN_DIR", previous);

    assert!(
        resolved.is_none(),
        "KEYHOG_TRUSTED_BIN_DIR must be ignored; use .keyhog.toml [system].trusted_bin_dirs instead"
    );
}
