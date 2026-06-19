//! CLI path validation.

use anyhow::Result;
use std::path::Path;

pub(crate) fn validate_cli_path_arg(path: &Path, name: &str) -> Result<()> {
    if path.as_os_str().to_str().is_none() {
        anyhow::bail!(
            "{name} '{}' has a non-UTF-8 filename. keyhog requires UTF-8 paths so detection \
             output stays valid JSON. Rename the file or scan its parent directory instead.",
            path.display()
        );
    }

    match std::fs::metadata(path) {
        Ok(meta) => {
            if meta.is_file() {
                std::fs::File::open(path).map_err(|error| {
                    anyhow::anyhow!(
                        "cannot read {name} '{}': {error}. Fix file permissions (`chmod +r {}`) \
                         and re-run.",
                        path.display(),
                        path.display()
                    )
                })?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(
                "{name} '{}' does not exist. Check the spelling and re-run.",
                path.display()
            );
        }
        Err(error) => {
            anyhow::bail!(
                "cannot stat {name} '{}': {error}. Likely a permissions or filesystem issue.",
                path.display()
            );
        }
    }
    Ok(())
}
