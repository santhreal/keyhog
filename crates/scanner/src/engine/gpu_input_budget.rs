//! VRAM-adaptive GPU batch-input sizing.
//!
//! This module owns the live GPU region-presence byte-budget selector used for
//! routing and cache-key stability.

use std::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// VRAM sizing table — ONE owner for every threshold and byte budget.
//
// The adaptive `gpu_batch_input_limit_for_vram_mb` match arms below are the SOLE
// readers of these; nothing is a bare magic number inline. The `_UNKNOWN` floor
// (128 MiB) doubles as the lower clamp bound and the `_HIGH` budget (1 GiB) as
// the upper clamp bound for any Tier-A override, so the operator can never drive
// the buffer outside the range the table itself honors.
// ---------------------------------------------------------------------------

/// `>= 24 GiB` VRAM (RTX 4090 / 5090, A100 / H100) -> 1 GiB input.
const VRAM_MB_TIER_HIGH: u64 = 24 * 1024;
const GPU_BATCH_INPUT_LIMIT_HIGH: usize = 1024 * 1024 * 1024;
/// `12 - 23 GiB` VRAM (RTX 3090, RTX 4080, M-Max) -> 512 MiB input.
const VRAM_MB_TIER_MID: u64 = 12 * 1024;
const GPU_BATCH_INPUT_LIMIT_MID: usize = 512 * 1024 * 1024;
/// `8 - 11 GiB` VRAM (RTX 3080, RTX 4070, M-Pro) -> 256 MiB input.
const VRAM_MB_TIER_LOW: u64 = 8 * 1024;
const GPU_BATCH_INPUT_LIMIT_LOW: usize = 256 * 1024 * 1024;

/// Conservative floor for hosts with low or unknown VRAM. Unknown must not
/// inherit the 8-11 GiB tier: absence of adapter memory evidence is the same
/// safety class as low-memory/iGPU/software adapters. Also the lower clamp bound
/// for a Tier-A override (see [`set_gpu_batch_input_limit`]).
const GPU_BATCH_INPUT_LIMIT_UNKNOWN: usize = 128 * 1024 * 1024;

/// Process-wide GPU batch-input override in bytes. `0` = unset (use the
/// VRAM-adaptive table). Set ONCE at scan startup — before the first
/// [`gpu_batch_input_limit`] call caches the value — from resolved config (Tier-A:
/// compiled default -> `.keyhog.toml` -> `--gpu-batch-input-limit`). Mirrors the
/// `REGEX_DFA_LIMIT_OVERRIDE` process-global pattern so the routing/cache-key
/// path needs no per-call plumbing.
static GPU_BATCH_INPUT_LIMIT_OVERRIDE: AtomicUsize = AtomicUsize::new(0);

/// The `[floor, cap]` the resolved GPU batch input limit is clamped into: the
/// 128 MiB unknown-host floor and the 1 GiB pre-compile-time ceiling that bound
/// the VRAM table. A Tier-A override is clamped into this range so no config/CLI
/// value can request a buffer the sizing contract forbids.
#[must_use]
pub fn gpu_batch_input_limit_bounds() -> (usize, usize) {
    (GPU_BATCH_INPUT_LIMIT_UNKNOWN, GPU_BATCH_INPUT_LIMIT_HIGH)
}

/// Override the GPU batch input limit for this process. Call before scanning.
/// `0` resets to the VRAM-adaptive default; any other value is clamped into
/// [`gpu_batch_input_limit_bounds`] at read time. Tier-A config knob
/// (compiled default -> TOML -> CLI), the sizing analogue of
/// [`crate::types::set_regex_dfa_limit`].
pub fn set_gpu_batch_input_limit(bytes: usize) {
    GPU_BATCH_INPUT_LIMIT_OVERRIDE.store(bytes, Ordering::Relaxed);
}

/// Clamp a raw Tier-A override into [`gpu_batch_input_limit_bounds`]. Pure — testable
/// without the process-global, so the clamp contract is proven deterministically.
pub(crate) fn clamp_gpu_batch_input_limit(bytes: usize) -> usize {
    let (floor, cap) = gpu_batch_input_limit_bounds();
    bytes.clamp(floor, cap)
}

/// Resolve the Tier-A override into an effective byte budget, or `None` when
/// unset (`0`). Split out so the cached entry point stays thin. Reads the
/// process-global; the clamp itself lives in [`clamp_gpu_batch_input_limit`].
pub(crate) fn gpu_batch_input_limit_override() -> Option<usize> {
    match GPU_BATCH_INPUT_LIMIT_OVERRIDE.load(Ordering::Relaxed) {
        0 => None,
        n => Some(clamp_gpu_batch_input_limit(n)),
    }
}

/// VRAM-adaptive GPU batch-input limit. Bigger buffers mean fewer
/// device dispatches per multi-TB scan; each kernel launch is a fixed
/// ~50-300 µs cost regardless of payload, so doubling the input
/// halves dispatch overhead. Capped by host VRAM (input + transition
/// tables + match output must fit) and by a 1 GiB upper bound so the
/// pre-compile time stays bounded.
///
/// | VRAM detected     | Input length | Adapter examples                 |
/// |-------------------|--------------|----------------------------------|
/// | >= 24 GiB         | 1 GiB        | RTX 4090 / 5090, A100 / H100     |
/// | 12 - 23 GiB       | 512 MiB      | RTX 3090, RTX 4080, M-Max        |
/// | 8 - 11 GiB        | 256 MiB      | RTX 3080, RTX 4070, M-Pro        |
/// |  < 8 GiB / Unknown| 128 MiB      | iGPU, software, no-GPU CI runner |
///
/// Cached on first call; the result is stable for the process
/// lifetime so routing and cache identities stay consistent across
/// every batch.
pub fn gpu_batch_input_limit() -> usize {
    // Read the explicit Tier-A value on every call. Only the hardware-derived
    // default is cached, so setting or clearing the override can never be
    // silently ignored merely because another caller resolved the default first.
    if let Some(len) = gpu_batch_input_limit_override() {
        tracing::debug!(
            target: "keyhog::routing",
            gpu_batch_input_limit = len,
            "GPU batch input limit set from Tier-A override"
        );
        return len;
    }
    use std::sync::OnceLock;
    static CACHED: OnceLock<usize> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let caps = crate::hw_probe::probe_hardware();
        let len = gpu_batch_input_limit_for_vram_mb(caps.gpu_vram_mb);
        tracing::debug!(
            target: "keyhog::routing",
            gpu_vram_mb = ?caps.gpu_vram_mb,
            gpu_batch_input_limit = len,
            "GPU batch input limit sized for VRAM"
        );
        len
    })
}

pub(crate) fn gpu_batch_input_limit_for_vram_mb(gpu_vram_mb: Option<u64>) -> usize {
    match gpu_vram_mb {
        Some(mb) if mb >= VRAM_MB_TIER_HIGH => GPU_BATCH_INPUT_LIMIT_HIGH,
        Some(mb) if mb >= VRAM_MB_TIER_MID => GPU_BATCH_INPUT_LIMIT_MID,
        Some(mb) if mb >= VRAM_MB_TIER_LOW => GPU_BATCH_INPUT_LIMIT_LOW,
        Some(_) | None => GPU_BATCH_INPUT_LIMIT_UNKNOWN,
    }
}

#[cfg(test)]
mod tier_a_tests {
    use super::*;

    const MIB: usize = 1024 * 1024;

    #[test]
    fn sizing_bounds_are_the_floor_and_cap() {
        let (floor, cap) = gpu_batch_input_limit_bounds();
        assert_eq!(floor, 128 * MIB, "floor is the 128 MiB unknown-host budget");
        assert_eq!(cap, 1024 * MIB, "cap is the 1 GiB pre-compile ceiling");
        assert_eq!(floor, GPU_BATCH_INPUT_LIMIT_UNKNOWN);
        assert_eq!(cap, GPU_BATCH_INPUT_LIMIT_HIGH);
    }

    #[test]
    fn override_clamps_into_sizing_bounds() {
        // Below the floor is lifted to the floor; above the cap is pinned to the
        // cap; an in-range value passes through untouched. This is the whole
        // Tier-A contract, proven without touching the process-global cache.
        assert_eq!(clamp_gpu_batch_input_limit(1), 128 * MIB);
        assert_eq!(clamp_gpu_batch_input_limit(64 * MIB), 128 * MIB);
        assert_eq!(clamp_gpu_batch_input_limit(300 * MIB), 300 * MIB);
        assert_eq!(clamp_gpu_batch_input_limit(1024 * MIB), 1024 * MIB);
        assert_eq!(clamp_gpu_batch_input_limit(usize::MAX), 1024 * MIB);
    }

    #[test]
    fn vram_table_reads_only_the_named_owners() {
        // Every arm maps to its named byte-budget owner at the exact threshold
        // boundary and one MiB below it — no bare magic numbers remain inline.
        assert_eq!(
            gpu_batch_input_limit_for_vram_mb(Some(VRAM_MB_TIER_HIGH)),
            GPU_BATCH_INPUT_LIMIT_HIGH
        );
        assert_eq!(
            gpu_batch_input_limit_for_vram_mb(Some(VRAM_MB_TIER_HIGH - 1)),
            GPU_BATCH_INPUT_LIMIT_MID
        );
        assert_eq!(
            gpu_batch_input_limit_for_vram_mb(Some(VRAM_MB_TIER_MID)),
            GPU_BATCH_INPUT_LIMIT_MID
        );
        assert_eq!(
            gpu_batch_input_limit_for_vram_mb(Some(VRAM_MB_TIER_MID - 1)),
            GPU_BATCH_INPUT_LIMIT_LOW
        );
        assert_eq!(
            gpu_batch_input_limit_for_vram_mb(Some(VRAM_MB_TIER_LOW)),
            GPU_BATCH_INPUT_LIMIT_LOW
        );
        assert_eq!(
            gpu_batch_input_limit_for_vram_mb(Some(VRAM_MB_TIER_LOW - 1)),
            GPU_BATCH_INPUT_LIMIT_UNKNOWN
        );
        assert_eq!(
            gpu_batch_input_limit_for_vram_mb(Some(0)),
            GPU_BATCH_INPUT_LIMIT_UNKNOWN
        );
        assert_eq!(
            gpu_batch_input_limit_for_vram_mb(None),
            GPU_BATCH_INPUT_LIMIT_UNKNOWN
        );
    }

    #[test]
    fn override_resolves_to_none_when_unset_and_clamped_when_set() {
        // `gpu_batch_input_limit_override` reads the process-global; the default
        // process state is unset. Set-then-reset around the assertions so this
        // test does not leak override state into the cached `gpu_batch_input_limit`.
        assert_eq!(
            gpu_batch_input_limit_override(),
            None,
            "override is unset by default"
        );
        set_gpu_batch_input_limit(9 * 1024 * MIB); // above cap
        assert_eq!(gpu_batch_input_limit_override(), Some(1024 * MIB));
        set_gpu_batch_input_limit(200 * MIB); // in range
        assert_eq!(gpu_batch_input_limit_override(), Some(200 * MIB));
        set_gpu_batch_input_limit(0); // reset to unset
        assert_eq!(gpu_batch_input_limit_override(), None);

        // Resolving the adaptive default first must not freeze out a later
        // explicit override. Only the hardware-derived value is cached.
        let adaptive = gpu_batch_input_limit();
        set_gpu_batch_input_limit(200 * MIB);
        assert_eq!(gpu_batch_input_limit(), 200 * MIB);
        set_gpu_batch_input_limit(0);
        assert_eq!(gpu_batch_input_limit(), adaptive);
    }
}
