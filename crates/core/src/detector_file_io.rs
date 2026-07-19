use std::io::Read;
use std::path::Path;

/// Maximum accepted size for one on-disk detector TOML file.
///
/// Detector specs are control-plane data, not scan input. A multi-megabyte
/// detector file is either corrupt or hostile. The runtime loader and build
/// script include this module directly so both paths enforce the same bound.
pub const DETECTOR_TOML_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Read one detector TOML without allowing metadata races to bypass the cap.
pub fn read_detector_toml_file(path: &Path) -> std::io::Result<String> {
    let file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len > DETECTOR_TOML_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "detector TOML {} exceeds {} byte cap; split the detector corpus or remove the oversized file",
                path.display(),
                DETECTOR_TOML_FILE_BYTES
            ),
        ));
    }

    let mut contents = String::with_capacity(len as usize);
    file.take(DETECTOR_TOML_FILE_BYTES.saturating_add(1))
        .read_to_string(&mut contents)?;
    if contents.len() as u64 > DETECTOR_TOML_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "detector TOML {} grew past {} byte cap while reading; rerun after the file is stable",
                path.display(),
                DETECTOR_TOML_FILE_BYTES
            ),
        ));
    }
    Ok(contents)
}
