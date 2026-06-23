pub(super) fn mib_per_second(bytes: usize, elapsed: std::time::Duration) -> f64 {
    if bytes == 0 || elapsed.is_zero() {
        return 0.0;
    }
    bytes as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64()
}

pub(super) fn report_phase2_gpu_admission_loss(error: impl std::fmt::Display) {
    let error = error.to_string();
    static PHASE2_GPU_ADMISSION_LOSS_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if PHASE2_GPU_ADMISSION_LOSS_WARNED.set(()).is_ok() {
        eprintln!(
            "keyhog: phase-2 GPU regex-DFA admission failed ({error}); CPU admission remains \
             authoritative for this scan. GPU speed evidence is incomplete."
        );
    }
    tracing::warn!(
        target: "keyhog::gpu",
        %error,
        "phase-2 GPU regex-DFA admission failed; CPU admission remains authoritative",
    );
}

pub(super) fn report_positioned_gpu_candidate_loss(error: impl std::fmt::Display) {
    let error = error.to_string();
    static POSITIONED_GPU_CANDIDATE_LOSS_WARNED: std::sync::OnceLock<()> =
        std::sync::OnceLock::new();
    if POSITIONED_GPU_CANDIDATE_LOSS_WARNED.set(()).is_ok() {
        eprintln!(
            "keyhog: positioned GPU candidate collection unavailable ({error}); CPU \
             confirmed-anchor and generic keyword collection remain authoritative. GPU speed \
             evidence is incomplete."
        );
    }
    tracing::warn!(
        target: "keyhog::gpu",
        %error,
        "positioned GPU candidate collection unavailable; CPU collection remains authoritative",
    );
}
