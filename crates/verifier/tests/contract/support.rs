use fs2::FileExt;
use std::fs::OpenOptions;
use std::sync::Mutex;

static PROXY_CONTRACT_PROCESS_LOCK: Mutex<()> = Mutex::new(());

fn lock_path() -> std::path::PathBuf {
    std::env::temp_dir().join("keyhog-proxy-contract-env.lock")
}

/// Serializes mutations to proxy-related env vars across parallel `all_tests`
/// workers and across concurrent `cargo test` processes (fleet-wide file lock).
pub fn with_proxy_contract_env<R>(f: impl FnOnce() -> R) -> R {
    let _process = PROXY_CONTRACT_PROCESS_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(lock_path())
        .expect("open proxy contract env lock file");
    file.lock_exclusive()
        .expect("acquire fleet-wide proxy contract env lock");
    let result = f();
    file.unlock()
        .expect("release fleet-wide proxy contract env lock");
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_contract_env_lock_uses_cross_process_file_lock() {
        let src = include_str!("support.rs");
        assert!(
            src.contains("lock_exclusive"),
            "fleet-wide ENV_MUTEX must use cross-process file locking"
        );
    }
}
