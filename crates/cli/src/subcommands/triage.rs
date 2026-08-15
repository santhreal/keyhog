use crate::args::TriageArgs;
use anyhow::{anyhow, Result};
use keyhog_core::triage::{TriageEnvelope, MAX_TRIAGE_INPUT_BYTES, MAX_TRIAGE_OUTPUT_BYTES};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

pub(crate) fn run(args: TriageArgs) -> Result<ExitCode> {
    if args.suppressions == args.pattern_feedback
        || args.input == args.suppressions
        || args.input == args.pattern_feedback
    {
        return Err(anyhow!(
            "triage input and output destinations must be distinct"
        ));
    }

    let input = read_bounded_regular_file(&args.input)?;
    let detector_digest = active_detector_digest()?;
    let envelope =
        TriageEnvelope::from_json(&input, &detector_digest).map_err(|error| anyhow!(error))?;
    let (suppressions, feedback) = envelope.into_outputs();
    let suppression_bytes = serde_json::to_vec_pretty(&suppressions)
        .map_err(|_| anyhow!("failed to serialize runtime suppressions"))?;
    let feedback_bytes = serde_json::to_vec_pretty(&feedback)
        .map_err(|_| anyhow!("failed to serialize pattern feedback"))?;
    if suppression_bytes.len() > MAX_TRIAGE_OUTPUT_BYTES
        || feedback_bytes.len() > MAX_TRIAGE_OUTPUT_BYTES
    {
        return Err(anyhow!("triage output exceeds the byte limit"));
    }

    validate_new_output(&args.suppressions)?;
    validate_new_output(&args.pattern_feedback)?;
    let mut suppression_file = create_private_file(&args.suppressions)?;
    let mut feedback_file = match create_private_file(&args.pattern_feedback) {
        Ok(file) => file,
        Err(error) => {
            let _ = std::fs::remove_file(&args.suppressions);
            return Err(error);
        }
    };
    if suppression_file.write_all(&suppression_bytes).is_err()
        || suppression_file.write_all(b"\n").is_err()
        || suppression_file.sync_all().is_err()
    {
        drop(feedback_file);
        let _ = std::fs::remove_file(&args.suppressions);
        let _ = std::fs::remove_file(&args.pattern_feedback);
        return Err(anyhow!("failed to write triage outputs"));
    }
    if feedback_file.write_all(&feedback_bytes).is_err()
        || feedback_file.write_all(b"\n").is_err()
        || feedback_file.sync_all().is_err()
    {
        drop(suppression_file);
        let _ = std::fs::remove_file(&args.suppressions);
        let _ = std::fs::remove_file(&args.pattern_feedback);
        return Err(anyhow!("failed to write triage outputs"));
    }
    Ok(ExitCode::SUCCESS)
}

fn active_detector_digest() -> Result<String> {
    let detectors = keyhog_core::load_embedded_detectors_or_fail()
        .map_err(|_| anyhow!("active detector corpus could not be loaded"))?;
    let scanner = keyhog_scanner::CompiledScanner::compile_with_gpu_policy(
        detectors,
        keyhog_scanner::GpuInitPolicy::ForceDisabled,
    )
    .map_err(|_| anyhow!("active detector corpus could not be compiled"))?;
    Ok(format!("{:016x}", scanner.runtime_status().detector_digest))
}

fn read_bounded_regular_file(path: &Path) -> Result<Vec<u8>> {
    reject_symlink_components(path)?;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| anyhow!("triage input is unavailable"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(anyhow!("triage input must be a regular non-symlink file"));
    }
    if metadata.len() > MAX_TRIAGE_INPUT_BYTES as u64 {
        return Err(anyhow!("triage envelope exceeds the byte limit"));
    }
    let file = File::open(path).map_err(|_| anyhow!("triage input is unavailable"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_TRIAGE_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow!("triage input could not be read"))?;
    if bytes.len() > MAX_TRIAGE_INPUT_BYTES {
        return Err(anyhow!("triage envelope exceeds the byte limit"));
    }
    Ok(bytes)
}

fn validate_new_output(path: &Path) -> Result<()> {
    reject_symlink_components(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(anyhow!("triage output destination already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(anyhow!("triage output destination is unavailable")),
    }
}

fn reject_symlink_components(path: &Path) -> Result<()> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(anyhow!("triage paths cannot contain parent traversal"));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {
                current.push(component.as_os_str());
            }
            Component::ParentDir => {
                return Err(anyhow!("triage paths cannot contain parent traversal"));
            }
            Component::Normal(part) => {
                current.push(part);
                match std::fs::symlink_metadata(&current) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(anyhow!("triage paths cannot traverse symlinks"));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                    Err(_) => return Err(anyhow!("triage path validation failed")),
                }
            }
        }
    }
    Ok(())
}

fn create_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|_| anyhow!("triage output destination could not be created"))
}
