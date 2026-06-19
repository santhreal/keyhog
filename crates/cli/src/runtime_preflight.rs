//! Runtime preflight checks that must happen before scan work starts.

use anyhow::Result;

/// Reject malformed bundled/runtime data before scan surfaces can silently run
/// without the protections the operator expects.
pub(crate) fn validate_scan_runtime_config() -> Result<()> {
    keyhog_core::validate_canary_accounts().map_err(anyhow::Error::msg)?;
    Ok(())
}
