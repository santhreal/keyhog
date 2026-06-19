//! KH-GAP-002: explicit failure when the selected GPU backend is unavailable.
//!
//! Also: one-shot loud warning on runtime GPU dispatch failure that
//! degrades to CPU. The hardware probe + compile-time visibility
//! warnings can't catch the case where GPU acquisition succeeds but
//! a specific scan dispatch fails (vyre lowering rejecting a
//! program, CUDA driver returning a transient error, etc.). Per
//! the no-silent-fallback rule, the user needs to know the scan
//! didn't actually use the GPU they thought was active.

use crate::hw_probe::ScanBackend;

use super::CompiledScanner;

/// Process-lifetime guard so the runtime-degrade warning fires once
/// per process, not once per scan or once per chunk.
static RUNTIME_DEGRADE_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// Read the resolved GPU runtime policy exactly once per process.
/// `deny_silent_gpu_degrade` can be invoked per chunk on multi-thousand-chunk
/// scans. The values are process-global and can't change mid-run anyway, so a
/// OnceLock is exact.
///
/// The `no_gpu` flag is true when the resolved policy disables GPU. The
/// degrade-warning paths consume this to suppress the "GPU dispatch failed"
/// message when CPU/SIMD was explicitly requested.
fn cached_gpu_runtime_policy_flags() -> (bool, bool) {
    static FLAGS: std::sync::OnceLock<(bool, bool)> = std::sync::OnceLock::new();
    *FLAGS.get_or_init(|| {
        let no_gpu = crate::gpu::env_no_gpu();
        let require_gpu = crate::gpu::env_require_gpu();
        (no_gpu, require_gpu)
    })
}

/// Error message when routing forces GPU/MegaScan but the scanner cannot dispatch.
#[must_use]
pub(crate) fn gpu_forced_unavailable_message(
    scanner: &CompiledScanner,
    backend: ScanBackend,
) -> Option<String> {
    if !matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan) {
        return None;
    }
    if scanner.gpu_stack_usable() {
        return None;
    }
    Some(format!(
        "{} selected but GPU stack unavailable (gpu_literals={}, gpu_backend={}, gpu_matcher={}) - \
         silent CPU fallback is forbidden; choose --backend simd/auto or install a compatible GPU adapter",
        backend.label(),
        scanner.gpu_literals.is_some(),
        scanner.gpu_backend.is_some(),
        scanner.gpu_matcher().is_some(),
    ))
}

/// Exit with an explicit message when policy forces GPU and the stack
/// is down. Otherwise, when the scanner asked for GPU but is about
/// to degrade to CPU at runtime, emit a one-shot stderr warning so
/// the user sees the silent fallback they didn't ask for. Use
/// `--no-gpu` to silence the warning, or `--require-gpu` to exit (2) instead.
///
/// ## Why a `std::process::exit(2)` survives in the library here (M12)
///
/// The clean fail-closed path for `--require-gpu` on a no-GPU host
/// is the CLI preflight ([`crate::gpu::require_gpu_preflight`], called from
/// `orchestrator::run` before any scan) which returns the documented
/// `ExitCode` through the CLI - no library `process::exit`, so embedders
/// stay alive. This function's hard exit covers a *different*, narrower
/// case: `--backend gpu`/`mega-scan` FORCED a per-chunk GPU dispatch
/// that then found the stack unusable, deep inside the parallel scan loop
/// where there is no `Result` channel back to the caller (it runs under
/// `par_iter` map closures returning `Vec<RawMatch>`). For that forced-
/// dispatch contract the no-silent-fallback rule requires an immediate
/// stop, and the only correct stop signal from inside that closure is the
/// process exit. The hazard for embedders is bounded: it fires only when
/// the embedder explicitly forced a GPU backend (or the policy required GPU)
/// AND reached GPU dispatch with a broken stack -
/// not on the ordinary no-GPU auto-routing path, which the CLI preflight
/// now owns.
pub(crate) fn deny_silent_gpu_degrade(scanner: &CompiledScanner, backend: ScanBackend) {
    deny_silent_gpu_degrade_with_reason(scanner, backend, None);
}

pub(crate) fn deny_silent_gpu_degrade_with_reason(
    scanner: &CompiledScanner,
    backend: ScanBackend,
    reason: Option<&str>,
) {
    if let Some(msg) = gpu_forced_unavailable_message(scanner, backend) {
        eprintln!("keyhog: {msg}");
        std::process::exit(2);
    }
    if !matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan) {
        return;
    }
    if reason.is_none() && scanner.gpu_stack_usable() {
        return;
    }
    let (no_gpu, require_gpu) = cached_gpu_runtime_policy_flags();
    if require_gpu {
        if let Some(reason) = reason {
            eprintln!(
                "keyhog: --require-gpu requested but the GPU dispatch failed at runtime \
({reason}) (literals={}, backend={}, matcher={}). Refusing to silently degrade.",
                scanner.gpu_literals.is_some(),
                scanner.gpu_backend.is_some(),
                scanner.gpu_matcher().is_some(),
            );
        } else {
            eprintln!(
                "keyhog: --require-gpu requested but the GPU dispatch failed at runtime \
(literals={}, backend={}, matcher={}). Refusing to silently degrade.",
                scanner.gpu_literals.is_some(),
                scanner.gpu_backend.is_some(),
                scanner.gpu_matcher().is_some(),
            );
        }
        std::process::exit(2);
    }
    if no_gpu {
        return;
    }
    if RUNTIME_DEGRADE_WARNED.set(()).is_ok() {
        if let Some(reason) = reason {
            eprintln!(
                "keyhog: GPU dispatch failed at runtime ({reason}); this scan and any subsequent \
ones in this process degrade to CPU/SIMD. Use --no-gpu to silence, or \
--require-gpu to hard-fail next time."
            );
        } else {
            eprintln!(
                "keyhog: GPU dispatch failed at runtime; this scan and any subsequent \
ones in this process degrade to CPU/SIMD. Often a transient driver issue or a \
program the GPU lowering pipeline rejects (check the preceding tracing::error \
line for the underlying message). Use --no-gpu to silence, or \
--require-gpu to hard-fail next time."
            );
        }
    }
}
