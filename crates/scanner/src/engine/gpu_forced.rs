//! KH-GAP-002: explicit failure when `KEYHOG_BACKEND` forces GPU but stack unavailable.
//!
//! Also: one-shot loud warning on runtime GPU dispatch failure that
//! degrades to CPU. The hardware probe + compile-time visibility
//! warnings can't catch the case where GPU acquisition succeeds but
//! a specific scan dispatch fails (vyre lowering rejecting a
//! program, CUDA driver returning a transient error, etc.). Per
//! the no-silent-fallback rule, the user needs to know the scan
//! didn't actually use the GPU they thought was active.

use crate::hw_probe::{forced_backend_from_env, ScanBackend};

use super::CompiledScanner;

/// Process-lifetime guard so the runtime-degrade warning fires once
/// per process, not once per scan or once per chunk.
static RUNTIME_DEGRADE_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// Same one-shot guard, scoped to the MegaScan rule-pipeline degrade
/// path. The two paths fail for different reasons (literal-set: bad
/// gpu_backend / matcher; MegaScan: regex compile reject) so we want
/// each to surface independently rather than have one silence the
/// other.
static MEGASCAN_DEGRADE_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// Read KEYHOG_NO_GPU / KEYHOG_REQUIRE_GPU exactly once per process.
/// Both `deny_silent_gpu_degrade` and `deny_silent_megascan_degrade`
/// can be invoked per chunk on multi-thousand-chunk scans; un-cached
/// `std::env::var` is a 200ns+ syscall per call. The values are
/// process-global and can't change mid-run anyway, so a OnceLock is
/// exact.
///
/// The `no_gpu` flag is true when EITHER the user set
/// `KEYHOG_NO_GPU=1` OR we auto-detected a CI runner (see
/// `crate::gpu::env_no_gpu`). The degrade-warning paths consume this
/// to suppress the "GPU dispatch failed" message that CI runs would
/// otherwise emit on every scan - on a CI runner there is no GPU,
/// the CPU path is the right path, and no warning is needed.
fn cached_gpu_env_flags() -> (bool, bool) {
    static FLAGS: std::sync::OnceLock<(bool, bool)> = std::sync::OnceLock::new();
    *FLAGS.get_or_init(|| {
        let no_gpu = crate::gpu::env_no_gpu();
        let require_gpu = std::env::var("KEYHOG_REQUIRE_GPU").as_deref() == Ok("1");
        (no_gpu, require_gpu)
    })
}

/// Error message when env forces GPU/MegaScan but the scanner cannot dispatch.
#[must_use]
pub fn gpu_forced_unavailable_message(
    scanner: &CompiledScanner,
    backend: ScanBackend,
) -> Option<String> {
    let forced = forced_backend_from_env()?;
    if !matches!(forced, ScanBackend::Gpu | ScanBackend::MegaScan) {
        return None;
    }
    if !matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan) {
        return None;
    }
    if scanner.gpu_stack_usable() {
        return None;
    }
    Some(format!(
        "KEYHOG_BACKEND={} but GPU stack unavailable (gpu_literals={}, gpu_backend={}, gpu_matcher={}) - \
         silent CPU fallback is forbidden; unset KEYHOG_BACKEND or install a compatible GPU adapter",
        forced.label(),
        scanner.gpu_literals.is_some(),
        scanner.gpu_backend.is_some(),
        scanner.gpu_matcher().is_some(),
    ))
}

/// Exit with an explicit message when env forces GPU and the stack
/// is down. Otherwise, when the scanner asked for GPU but is about
/// to degrade to CPU at runtime, emit a one-shot stderr warning so
/// the user sees the silent fallback they didn't ask for. Set
/// KEYHOG_NO_GPU=1 to silence the warning, or KEYHOG_REQUIRE_GPU=1
/// to exit (2) instead.
pub fn deny_silent_gpu_degrade(scanner: &CompiledScanner, backend: ScanBackend) {
    deny_silent_gpu_degrade_with_reason(scanner, backend, None);
}

pub fn deny_silent_gpu_degrade_with_reason(
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
    let (no_gpu, require_gpu) = cached_gpu_env_flags();
    if require_gpu {
        if let Some(reason) = reason {
            eprintln!(
                "keyhog: KEYHOG_REQUIRE_GPU=1 but the GPU dispatch failed at runtime \
({reason}) (literals={}, backend={}, matcher={}). Refusing to silently degrade.",
                scanner.gpu_literals.is_some(),
                scanner.gpu_backend.is_some(),
                scanner.gpu_matcher().is_some(),
            );
        } else {
            eprintln!(
                "keyhog: KEYHOG_REQUIRE_GPU=1 but the GPU dispatch failed at runtime \
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
ones in this process degrade to CPU/SIMD. Set KEYHOG_NO_GPU=1 to silence, or \
KEYHOG_REQUIRE_GPU=1 to hard-fail next time."
            );
        } else {
            eprintln!(
                "keyhog: GPU dispatch failed at runtime; this scan and any subsequent \
ones in this process degrade to CPU/SIMD. Often a transient driver issue or a \
program the GPU lowering pipeline rejects (check the preceding tracing::error \
line for the underlying message). Set KEYHOG_NO_GPU=1 to silence, or \
KEYHOG_REQUIRE_GPU=1 to hard-fail next time."
            );
        }
    }
}

/// Signal the MegaScan degrade-to-literal-set path. The literal-set
/// fallback is still a legitimate degradation (same recall, slower on
/// large pattern sets) but the user asked for the regex-NFA pipeline
/// explicitly. We respect KEYHOG_REQUIRE_GPU (hard-fail) and emit a
/// one-shot stderr warning otherwise. KEYHOG_NO_GPU silences it.
///
/// `reason` is a human-readable cause string passed by the caller
/// (regex pipeline compile failed, batch over `MEGASCAN_INPUT_LEN`,
/// no GPU backend handle). It surfaces in the warning so the operator
/// can see *why* MegaScan dispatched as literal-set.
pub fn deny_silent_megascan_degrade(reason: &str) {
    let (no_gpu, require_gpu) = cached_gpu_env_flags();
    if require_gpu {
        eprintln!(
            "keyhog: KEYHOG_REQUIRE_GPU=1 but MegaScan rule-pipeline dispatch failed ({reason}). \
Refusing to silently fall back to literal-set."
        );
        std::process::exit(2);
    }
    if no_gpu {
        return;
    }
    if MEGASCAN_DEGRADE_WARNED.set(()).is_ok() {
        eprintln!(
            "keyhog: MegaScan rule-pipeline unavailable ({reason}); this scan and any \
subsequent ones in this process degrade to the literal-set GPU dispatch. \
Set KEYHOG_NO_GPU=1 to silence, or KEYHOG_REQUIRE_GPU=1 to hard-fail next time."
        );
    }
}

impl CompiledScanner {
    /// True when literals, backend handle, and compiled matcher are all present.
    pub(crate) fn gpu_stack_usable(&self) -> bool {
        self.gpu_literals.is_some() && self.gpu_backend.is_some() && self.gpu_matcher().is_some()
    }
}
