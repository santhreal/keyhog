//! Validation boundary for process env that can still change scan/runtime behavior.

use anyhow::Result;

/// Reject malformed scan-affecting env before scan surfaces can silently run
/// with a different detector/protection/routing state than the operator asked
/// for.
pub fn validate_scan_runtime_env() -> Result<()> {
    keyhog_core::aws::validate_canary_accounts().map_err(anyhow::Error::msg)?;
    Ok(())
}
