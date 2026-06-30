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
                "{name} '{}' does not exist. Check the spelling, confirm it is relative to the \
                 current directory (`pwd`), or scan its parent directory instead.",
                path.display()
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            anyhow::bail!(
                "cannot access {name} '{}': permission denied. Grant traverse/read permission on \
                 it and its parent directories (`chmod +rx`), or run keyhog as a user that can.",
                path.display()
            );
        }
        Err(error) => {
            anyhow::bail!(
                "cannot stat {name} '{}': {error}. Re-check the path and that the filesystem is \
                 mounted and healthy; if it lives on a network mount, confirm the mount is up.",
                path.display()
            );
        }
    }
    Ok(())
}
