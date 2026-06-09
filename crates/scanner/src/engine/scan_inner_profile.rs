//! `scan_inner` prepare/phase-1 overhead profiler, split out of `engine/scan.rs`
//! to keep that file under the standard 500-LOC cap.
//!
//! MEASUREMENT (`KEYHOG_PROFILE_SCANINNER=1`): per-`scan_inner` `prepare_chunk`
//! (preprocessing) + phase-1 (`collect_triggered_patterns`) overhead — the part
//! the phase-2 profiler does NOT capture, paid once per chunk incl. every decode
//! sub-chunk. `scan_inner_profile_dump()` prints + resets. Zero-cost unset.

use std::sync::atomic::AtomicU64;

pub(super) static SCAN_PREPARE_NS: AtomicU64 = AtomicU64::new(0);
pub(super) static SCAN_PHASE1_NS: AtomicU64 = AtomicU64::new(0);
pub(super) static SCAN_INNER_CALLS: AtomicU64 = AtomicU64::new(0);

pub(super) fn scan_inner_prof_enabled() -> bool {
    static EN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_PROFILE_SCANINNER").as_deref() == Ok("1"))
}

/// Print + reset the prepare/phase-1 overhead counters.
pub fn scan_inner_profile_dump() {
    use std::sync::atomic::Ordering::Relaxed;
    let prep = SCAN_PREPARE_NS.swap(0, Relaxed) as f64 / 1e6;
    let p1 = SCAN_PHASE1_NS.swap(0, Relaxed) as f64 / 1e6;
    let calls = SCAN_INNER_CALLS.swap(0, Relaxed);
    eprintln!(
        "scan_inner overhead: calls={calls} prepare={prep:.1}ms phase1={p1:.1}ms \
         ({:.2} µs/call prep+p1)",
        if calls > 0 {
            (prep + p1) * 1000.0 / calls as f64
        } else {
            0.0
        }
    );
}
