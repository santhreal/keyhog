//! Display formatting helpers shared between CLI subcommands.
//!
//! The system-scan orchestrator (`subcommands::scan_system`) and other
//! subcommands previously kept near-identical `format_bytes` fns that
//! drifted (one handled TiB, another stopped at GiB). They now all
//! consume the same `format_bytes` here, so a future bump to PiB (when
//! someone tries to scan a 100 PB cluster archive) lands in one place.

/// Format a byte count as a human-readable string with the closest
/// power-of-two unit (B / KiB / MiB / GiB / TiB). Two-decimal precision
/// matches the prior CLI output verbatim so existing snapshot tests
/// stay green across the consolidation.
#[must_use]
pub(crate) fn format_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    const TIB: u64 = 1024 * 1024 * 1024 * 1024;
    if n >= TIB {
        format!("{:.2} TiB", n as f64 / TIB as f64)
    } else if n >= GIB {
        format!("{:.2} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.2} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.2} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}
