use fs2::FileExt;
use std::fs::OpenOptions;
use std::sync::Mutex;

static PROXY_CONTRACT_PROCESS_LOCK: Mutex<()> = Mutex::new(());
const PROXY_ENV_VARS: &[&str] = &[
    "KEYHOG_PROXY",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

struct ProxyEnvSnapshot(Vec<(&'static str, Option<String>)>);

impl ProxyEnvSnapshot {
    fn capture_and_clear() -> Self {
        let saved = PROXY_ENV_VARS
            .iter()
            .map(|var| (*var, std::env::var(var).ok()))
            .collect::<Vec<_>>();
        for var in PROXY_ENV_VARS {
            unsafe {
                std::env::remove_var(var);
            }
        }
        Self(saved)
    }
}

impl Drop for ProxyEnvSnapshot {
    fn drop(&mut self) {
        for (var, value) in self.0.drain(..) {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(var, value),
                    None => std::env::remove_var(var),
                }
            }
        }
    }
}

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
    let _env = ProxyEnvSnapshot::capture_and_clear();
    let result = f();
    file.unlock()
        .expect("release fleet-wide proxy contract env lock");
    result
}

#[cfg(test)]
mod tests {
    #[test]
    fn proxy_contract_env_lock_uses_cross_process_file_lock() {
        let src = include_str!("support.rs");
        assert!(
            src.contains("lock_exclusive"),
            "fleet-wide ENV_MUTEX must use cross-process file locking"
        );
    }
}
