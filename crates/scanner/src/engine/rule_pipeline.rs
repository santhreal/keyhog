//! VRAM-adaptive MegaScan input sizing.
//!
//! No scan path builds or dispatches vyre's old `RulePipeline` regex-NFA engine:
//! `--backend mega-scan` collapses onto the GPU region-presence route. This
//! module owns only the live byte-budget selector used for routing and
//! cache-key stability.

/// Conservative floor for hosts with low or unknown VRAM. Unknown must not
/// inherit the 8-11 GiB tier: absence of adapter memory evidence is the same
/// safety class as low-memory/iGPU/software adapters.
const MEGASCAN_INPUT_LEN_UNKNOWN: usize = 128 * 1024 * 1024;

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
        let len = megascan_input_len_for_vram_mb(caps.gpu_vram_mb);
        tracing::debug!(
            target: "keyhog::routing",
            gpu_vram_mb = ?caps.gpu_vram_mb,
            megascan_input_len = len,
            "MegaScan input length sized for VRAM"
        );
        len
    })
}

pub(crate) fn megascan_input_len_for_vram_mb(gpu_vram_mb: Option<u64>) -> usize {
    match gpu_vram_mb {
        Some(mb) if mb >= 24 * 1024 => 1024 * 1024 * 1024,
        Some(mb) if mb >= 12 * 1024 => 512 * 1024 * 1024,
        Some(mb) if mb >= 8 * 1024 => 256 * 1024 * 1024,
        Some(_) | None => MEGASCAN_INPUT_LEN_UNKNOWN,
    }
}
