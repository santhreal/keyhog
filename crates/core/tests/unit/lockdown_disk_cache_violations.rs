use keyhog_core::hardening::lockdown_disk_cache_violations;
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
