use keyhog_core::testing::{
    lockdown_cache_entry_error_is_violation, lockdown_disk_cache_violations,
};
use std::ffi::OsString;
use std::sync::Mutex;
use tempfile::TempDir;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn with_xdg_cache_home(test: impl FnOnce(&TempDir)) {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let cache_home = TempDir::new().expect("cache tempdir");
    let previous = std::env::var_os("XDG_CACHE_HOME");
    unsafe { std::env::set_var("XDG_CACHE_HOME", cache_home.path()) };

    test(&cache_home);

    restore_env("XDG_CACHE_HOME", previous);
}

fn restore_env(key: &str, previous: Option<OsString>) {
    unsafe {
        match previous {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }
}

fn compiled_hyperscan_cache_name() -> String {
    format!("hs-{}.db", "a".repeat(64))
}

fn compiled_hyperscan_cache_bytes() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"KHHS");
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(b"serialized-hyperscan-body");
    bytes
}

#[test]
fn empty_keyhog_cache_dir_is_not_lockdown_violation() {
    with_xdg_cache_home(|cache_home| {
        let keyhog_cache = cache_home.path().join("keyhog");
        std::fs::create_dir_all(&keyhog_cache).expect("create empty cache dir");

        assert!(
            lockdown_disk_cache_violations().is_empty(),
            "empty keyhog cache dir must not fail lockdown"
        );
    });
}

#[test]
fn compiled_hyperscan_cache_file_is_not_lockdown_violation() {
    with_xdg_cache_home(|cache_home| {
        let keyhog_cache = cache_home.path().join("keyhog");
        std::fs::create_dir_all(&keyhog_cache).expect("create cache dir");
        std::fs::write(
            keyhog_cache.join(compiled_hyperscan_cache_name()),
            compiled_hyperscan_cache_bytes(),
        )
        .expect("write compiled cache");

        assert!(
            lockdown_disk_cache_violations().is_empty(),
            "exact-shape compiled Hyperscan cache with KHHS/v1 header must not fail lockdown"
        );
    });
}

#[test]
fn hs_db_without_compiled_cache_header_is_lockdown_violation() {
    with_xdg_cache_home(|cache_home| {
        let keyhog_cache = cache_home.path().join("keyhog");
        std::fs::create_dir_all(&keyhog_cache).expect("create cache dir");
        std::fs::write(keyhog_cache.join(compiled_hyperscan_cache_name()), b"[]\n")
            .expect("write fake hs cache");

        assert_eq!(
            lockdown_disk_cache_violations(),
            vec![keyhog_cache],
            "an hs-named file without the compiled-cache marker must fail lockdown"
        );
    });
}

#[test]
fn loose_hs_db_filename_is_lockdown_violation_even_with_cache_header() {
    with_xdg_cache_home(|cache_home| {
        let keyhog_cache = cache_home.path().join("keyhog");
        std::fs::create_dir_all(&keyhog_cache).expect("create cache dir");
        std::fs::write(
            keyhog_cache.join("hs-findings.db"),
            compiled_hyperscan_cache_bytes(),
        )
        .expect("write loose-name cache");

        assert_eq!(
            lockdown_disk_cache_violations(),
            vec![keyhog_cache],
            "loose hs-*.db names must not bypass the past-findings cache gate"
        );
    });
}

#[test]
fn non_empty_keyhog_cache_dir_is_lockdown_violation() {
    with_xdg_cache_home(|cache_home| {
        let keyhog_cache = cache_home.path().join("keyhog");
        std::fs::create_dir_all(&keyhog_cache).expect("create cache dir");
        std::fs::write(keyhog_cache.join("findings.json"), b"[]\n").expect("write cache content");

        assert_eq!(
            lockdown_disk_cache_violations(),
            vec![keyhog_cache],
            "non-empty keyhog cache dir must fail lockdown"
        );
    });
}

#[test]
fn cache_entry_read_error_is_lockdown_violation() {
    assert!(
        lockdown_cache_entry_error_is_violation(),
        "a per-entry read_dir error must fail closed instead of being filtered out"
    );
}
