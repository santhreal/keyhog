//! Process termination helpers for scanner paths that cannot return `Result`.
//!
//! The CLI owns the public exit-code table. These helpers exist only for deep
//! scanner paths that are intentionally allowed to hard-stop the process when
//! `--require-gpu` would otherwise degrade silently inside a parallel scan.

/// Mirrors `keyhog::exit_codes::EXIT_REQUIRE_GPU_UNMET`.
///
/// Kept private to this crate and source-checked by the CLI contract test so
/// the unavoidable scanner hard exits cannot drift from the documented CLI
/// process contract.
pub(crate) const REQUIRE_GPU_UNMET_EXIT_CODE: i32 = 12;

pub(crate) fn require_gpu_unmet(message: impl AsRef<str>) -> ! {
    eprintln!("keyhog: {}", message.as_ref());
    std::process::exit(REQUIRE_GPU_UNMET_EXIT_CODE);
}
