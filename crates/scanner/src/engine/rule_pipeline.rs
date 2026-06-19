//! VRAM-adaptive MegaScan input sizing.
//!
//! No scan path builds or dispatches vyre's old `RulePipeline` regex-NFA engine:
//! `--backend mega-scan` collapses onto the megakernel. This module owns only
//! the live byte-budget selector used for routing and cache-key stability.

/// Maximum input buffer length the MegaScan `RulePipeline` is
/// pre-compiled for. Chosen to match the orchestrator's
/// `BATCH_BYTES_BUDGET` so any normal coalesced batch fits the
/// pre-built pipeline without needing recompile-per-batch. Batches
/// larger than this fall back to the literal-set path.
///
/// Kept as the conservative default for hosts without GPU info or
/// for callers (tests, fuzzers) that want a stable byte budget. The
/// adaptive size for the running host is exposed via
/// [`megascan_input_len`].
const MEGASCAN_INPUT_LEN_DEFAULT: usize = 256 * 1024 * 1024;

/// VRAM-adaptive megascan input length. Bigger buffers mean fewer
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
/// lifetime so the rule-pipeline cache key stays consistent across
/// every batch.
pub fn megascan_input_len() -> usize {
    use std::sync::OnceLock;
    static CACHED: OnceLock<usize> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let caps = crate::hw_probe::probe_hardware();
        let len = match caps.gpu_vram_mb {
            Some(mb) if mb >= 24 * 1024 => 1024 * 1024 * 1024,
            Some(mb) if mb >= 12 * 1024 => 512 * 1024 * 1024,
            Some(mb) if mb >= 8 * 1024 => 256 * 1024 * 1024,
            Some(_) => 128 * 1024 * 1024,
            None => MEGASCAN_INPUT_LEN_DEFAULT,
        };
        tracing::debug!(
            target: "keyhog::routing",
            gpu_vram_mb = ?caps.gpu_vram_mb,
            megascan_input_len = len,
            "MegaScan input length sized for VRAM"
        );
        len
    })
}
