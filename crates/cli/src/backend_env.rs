//! Validation boundary for the `KEYHOG_BACKEND` process override.

use anyhow::{bail, Result};

const VALID_BACKEND_VALUES: &str = "auto, gpu, gpu-zero-copy, literal-set, mega-scan, megascan, \
gpu-mega-scan, regex-nfa, rule-pipeline, simd, simd-regex, hyperscan, cpu, cpu-fallback, scalar";

/// Reject malformed `KEYHOG_BACKEND` before any scan/backend surface can treat
/// it as "unset" and silently auto-route.
pub fn validate_keyhog_backend_env() -> Result<()> {
    let raw = match std::env::var("KEYHOG_BACKEND") {
        Ok(raw) => raw,
        Err(std::env::VarError::NotPresent) => return Ok(()),
        Err(std::env::VarError::NotUnicode(value)) => {
            bail!(
                "invalid KEYHOG_BACKEND value {:?}: value is not valid UTF-8. \
                 Supported values: {VALID_BACKEND_VALUES}. \
                 Fix: unset KEYHOG_BACKEND or set it to one supported backend value.",
                value
            );
        }
    };

    if raw.trim().eq_ignore_ascii_case("auto")
        || keyhog_scanner::hw_probe::parse_backend_str(&raw).is_some()
    {
        return Ok(());
    }

    bail!(
        "invalid KEYHOG_BACKEND value {:?}. Supported values: {VALID_BACKEND_VALUES}. \
         Fix: unset KEYHOG_BACKEND or set it to one supported backend value.",
        raw
    );
}
