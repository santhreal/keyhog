#[path = "support/mod.rs"]
mod support;

mod telemetry_serial {
    pub(super) fn lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        let lock = LOCK.get_or_init(|| std::sync::Mutex::new(()));
        match lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                lock.clear_poison();
                poisoned.into_inner()
            }
        }
    }
}

mod root_facade {
    pub(crate) mod support {
        pub(crate) use crate::support::*;
    }

    #[path = "../unit/root_facade/homoglyph_ascii_skip_parity.rs"]
    mod homoglyph_ascii_skip_parity;
}
