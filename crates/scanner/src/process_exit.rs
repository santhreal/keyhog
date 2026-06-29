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

/// One owner for the `keyhog: <message>` notice + hard exit shared by every
/// scanner hard-stop. Both exit paths emit the identical prefix and terminate
/// here so the operator-facing format cannot drift between them; the only
/// difference a caller chooses is the documented exit `code`.
fn exit_with(code: i32, message: impl AsRef<str>) -> ! {
    eprintln!("keyhog: {}", message.as_ref());
    std::process::exit(code);
}

pub(crate) fn require_gpu_unmet(message: impl AsRef<str>) -> ! {
    exit_with(REQUIRE_GPU_UNMET_EXIT_CODE, message)
}

pub(crate) fn backend_unavailable(message: impl AsRef<str>) -> ! {
    exit_with(BACKEND_UNAVAILABLE_EXIT_CODE, message)
}
