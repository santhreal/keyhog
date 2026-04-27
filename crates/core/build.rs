use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map_err(|error| io::Error::other(format!("CARGO_MANIFEST_DIR is not set: {error}")))?;
    let out_dir = env::var("OUT_DIR")
        .map_err(|error| io::Error::other(format!("OUT_DIR is not set: {error}")))?;
    let output_path = Path::new(&out_dir).join("embedded_detectors.rs");

    let candidates = [
        Path::new(&manifest_dir).join("detectors"),
        Path::new(&manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("detectors"))
            .unwrap_or_default(),
    ];

    let detectors_dir = candidates
        .iter()
        .find(|path| path.exists() && path.is_dir());
    let Some(detectors_dir) = detectors_dir else {
        println!("cargo:warning=detectors/ directory not found, embedded detectors will be empty");
        write_embedded_detectors(&output_path, &[])?;
        return Ok(());
    };

    let entries = read_detector_entries(detectors_dir)?;
    if entries.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "detectors directory '{}' contains no .toml files. Fix: add detector TOML files or remove the empty directory",
                detectors_dir.display()
            ),
        )
        .into());
    }

    write_embedded_detectors(&output_path, &entries)?;

    println!("cargo:rerun-if-changed={}", detectors_dir.display());
    println!(
        "cargo:warning=Embedded {} detectors ({} bytes)",
        entries.len(),
        entries
            .iter()
            .map(|(_, content)| content.len())
            .sum::<usize>()
    );
    Ok(())
}

fn read_detector_entries(detectors_dir: &Path) -> io::Result<Vec<(String, String)>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(detectors_dir).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to read detectors directory '{}': {}. Fix: check directory permissions",
                detectors_dir.display(),
                error
            ),
        )
    })? {
        let entry = entry.map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "failed to enumerate detectors in '{}': {}. Fix: check directory permissions",
                    detectors_dir.display(),
                    error
                ),
            )
        })?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            let name = file_name(&path)?;
            let content = fs::read_to_string(&path).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "failed to read detector '{}': {}. Fix: check file permissions and TOML encoding",
                        path.display(),
                        error
                    ),
                )
            })?;
            entries.push((name, content));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries)
}

fn write_embedded_detectors(output_path: &PathBuf, entries: &[(String, String)]) -> io::Result<()> {
    let mut code = String::from("pub const EMBEDDED_DETECTORS: &[(&str, &str)] = &[\n");
    for (name, content) in entries {
        code.push_str(&format!("    ({name:?}, {content:?}),\n"));
    }
    code.push_str("];\n");
    fs::write(output_path, code).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to write generated detector table '{}': {}. Fix: verify OUT_DIR is writable",
                output_path.display(),
                error
            ),
        )
    })
}

fn file_name(path: &Path) -> io::Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "detector path '{}' does not have a valid UTF-8 file name. Fix: rename the detector file",
                    path.display()
                ),
            )
        })
}
