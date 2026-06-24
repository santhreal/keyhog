//! Process termination helpers for scanner paths that cannot return `Result`.
//!
//! The CLI owns the public exit-code table. These helpers exist only for deep
//! scanner paths that are intentionally allowed to hard-stop the process when a
//! caller-selected backend would otherwise degrade silently inside a parallel
//! scan.

/// Mirrors `keyhog::exit_codes::EXIT_REQUIRE_GPU_UNMET`.
///
/// Kept private to this crate and source-checked by the CLI contract test so
/// the unavoidable scanner hard exits cannot drift from the documented CLI
/// process contract.
pub(crate) const REQUIRE_GPU_UNMET_EXIT_CODE: i32 = 12;
/// Mirrors `keyhog::exit_codes::EXIT_SYSTEM_ERROR`.
pub(crate) const BACKEND_UNAVAILABLE_EXIT_CODE: i32 = 3;

pub(crate) fn require_gpu_unmet(message: impl AsRef<str>) -> ! {
    eprintln!("keyhog: {}", message.as_ref());
    std::process::exit(REQUIRE_GPU_UNMET_EXIT_CODE);
}

pub(crate) fn backend_unavailable(message: impl AsRef<str>) -> ! {
    eprintln!("keyhog: {}", message.as_ref());
    std::process::exit(BACKEND_UNAVAILABLE_EXIT_CODE);
}
