//! Process termination helpers for scanner paths that cannot return `Result`.
//!
//! The CLI owns the public exit-code table. These helpers exist only for deep
//! scanner paths that are intentionally allowed to hard-stop the process when a
//! caller-selected backend would otherwise degrade silently inside a parallel
//! scan.

use std::sync::OnceLock;

/// Mirrors `keyhog::exit_codes::EXIT_REQUIRE_GPU_UNMET`.
///
/// Kept private to this crate and source-checked by the CLI contract test so
/// the unavoidable scanner hard exits cannot drift from the documented CLI
/// process contract.
pub(crate) const REQUIRE_GPU_UNMET_EXIT_CODE: i32 = 12;
/// Mirrors `keyhog::exit_codes::EXIT_SYSTEM_ERROR`.
pub(crate) const BACKEND_UNAVAILABLE_EXIT_CODE: i32 = 3;

/// Optional pre-exit hook (CLI installs warn-dedup summary dump).
///
/// `std::process::exit` skips Drop, so rate-limited WARN summaries would be
/// lost without an explicit flush here (KH-1316).
static PRE_EXIT_HOOK: OnceLock<fn()> = OnceLock::new();

/// Register a function to run immediately before scanner hard-stop exits.
///
/// The first successful registration wins; later calls are ignored so tests
/// and nested hosts cannot overwrite the CLI hook silently.
pub fn set_pre_exit_hook(hook: fn()) {
    let _ = PRE_EXIT_HOOK.set(hook); // LAW10: first hook remains active; duplicate registration loses no scan or exit behavior
}

pub(crate) fn pre_exit_hook_for_test() -> Option<fn()> {
    PRE_EXIT_HOOK.get().copied()
}

/// One owner for the `keyhog: <message>` notice + hard exit shared by every
/// scanner hard-stop. Both exit paths emit the identical prefix and terminate
/// here so the operator-facing format cannot drift between them; the only
/// difference a caller chooses is the documented exit `code`.
fn exit_with(code: i32, message: impl AsRef<str>) -> ! {
    if let Some(hook) = PRE_EXIT_HOOK.get() {
        hook();
    }
    eprintln!("keyhog: {}", message.as_ref());
    std::process::exit(code);
}

pub(crate) fn require_gpu_unmet(message: impl AsRef<str>) -> ! {
    exit_with(REQUIRE_GPU_UNMET_EXIT_CODE, message)
}

pub(crate) fn backend_unavailable(message: impl AsRef<str>) -> ! {
    exit_with(BACKEND_UNAVAILABLE_EXIT_CODE, message)
}
