//! CLI path validation.

use anyhow::Result;
use std::path::Path;

pub(crate) fn validate_cli_path_arg(path: &Path, name: &str) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("{} path does not exist: {}", name, path.display());
    }
    Ok(())
}
