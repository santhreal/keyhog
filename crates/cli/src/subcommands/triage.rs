use crate::args::TriageArgs;
use anyhow::{anyhow, Result};
use std::process::ExitCode;

#[cfg(unix)]
use keyhog_core::triage::{TriageEnvelope, MAX_TRIAGE_INPUT_BYTES, MAX_TRIAGE_OUTPUT_BYTES};
#[cfg(unix)]
use std::ffi::{CString, OsStr};
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::path::Component;
#[cfg(unix)]
use std::path::Path;

#[cfg(windows)]
pub(crate) fn run(_args: TriageArgs) -> Result<ExitCode> {
    Err(anyhow!(
        "keyhog triage requires descriptor-relative no-follow file access, which is unavailable on this Windows build"
    ))
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn run(_args: TriageArgs) -> Result<ExitCode> {
    Err(anyhow!(
        "keyhog triage is unsupported on this platform because safe descriptor-relative file access is unavailable"
    ))
}

#[cfg(unix)]
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

    let mut suppression_file = create_private_file(&args.suppressions)?;
    let mut feedback_file = match create_private_file(&args.pattern_feedback) {
        Ok(file) => file,
        Err(error) => {
            suppression_file.cleanup();
            return Err(error);
        }
    };
    if write_private_output(&mut suppression_file.file, &suppression_bytes).is_err() {
        suppression_file.cleanup();
        feedback_file.cleanup();
        return Err(anyhow!("failed to write triage outputs"));
    }
    if write_private_output(&mut feedback_file.file, &feedback_bytes).is_err() {
        suppression_file.cleanup();
        feedback_file.cleanup();
        return Err(anyhow!("failed to write triage outputs"));
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(unix)]
fn active_detector_digest() -> Result<String> {
    let detectors = keyhog_core::embedded_detector_specs().to_vec();
    let scanner = keyhog_scanner::CompiledScanner::compile_with_gpu_policy(
        detectors,
        keyhog_scanner::GpuInitPolicy::ForceDisabled,
    )
    .map_err(|_| anyhow!("active detector corpus could not be compiled"))?;
    Ok(format!("{:016x}", scanner.runtime_status().detector_digest))
}

#[cfg(unix)]
fn write_private_output(file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()
}

#[cfg(unix)]
struct HeldParent {
    directory: OwnedFd,
    final_name: CString,
}

#[cfg(unix)]
pub(crate) struct PrivateOutput {
    file: File,
    parent: HeldParent,
}

#[cfg(unix)]
impl PrivateOutput {
    fn cleanup(self) {
        // SAFETY: directory is a valid open directory descriptor and final_name is NUL-terminated.
        unsafe {
            libc::unlinkat(
                self.parent.directory.as_raw_fd(),
                self.parent.final_name.as_ptr(),
                0,
            );
        }
    }
}

#[cfg(unix)]
fn read_bounded_regular_file(path: &Path) -> Result<Vec<u8>> {
    read_bounded_regular_file_with_hook(path, || {})
}

#[cfg(unix)]
pub(crate) fn read_bounded_regular_file_with_hook(
    path: &Path,
    hook: impl FnOnce(),
) -> Result<Vec<u8>> {
    let parent = open_parent_with_hook(path, hook)?;
    let descriptor = openat(
        parent.directory.as_raw_fd(),
        &parent.final_name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )
    .map_err(|_| anyhow!("triage input is unavailable"))?;
    let metadata = descriptor_metadata(descriptor.as_raw_fd())
        .map_err(|_| anyhow!("triage input is unavailable"))?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(anyhow!("triage input must be a regular non-symlink file"));
    }
    let length = u64::try_from(metadata.st_size)
        .map_err(|_| anyhow!("triage input must be a regular non-symlink file"))?;
    if length > MAX_TRIAGE_INPUT_BYTES as u64 {
        return Err(anyhow!("triage envelope exceeds the byte limit"));
    }
    let file: File = descriptor.into();
    let mut bytes = Vec::with_capacity(length as usize);
    file.take((MAX_TRIAGE_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow!("triage input could not be read"))?;
    if bytes.len() > MAX_TRIAGE_INPUT_BYTES {
        return Err(anyhow!("triage envelope exceeds the byte limit"));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> Result<PrivateOutput> {
    create_private_file_with_hook(path, || {})
}

#[cfg(unix)]
pub(crate) fn create_private_file_with_hook(
    path: &Path,
    hook: impl FnOnce(),
) -> Result<PrivateOutput> {
    let parent = open_parent_with_hook(path, hook)?;
    let descriptor = openat(
        parent.directory.as_raw_fd(),
        &parent.final_name,
        libc::O_WRONLY
            | libc::O_CREAT
            | libc::O_EXCL
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK,
        0o600,
    )
    .map_err(|_| anyhow!("triage output destination could not be created"))?;
    let metadata = descriptor_metadata(descriptor.as_raw_fd())
        .map_err(|_| anyhow!("triage output destination could not be created"))?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(anyhow!(
            "triage output destination could not be created as a regular file"
        ));
    }
    Ok(PrivateOutput {
        file: descriptor.into(),
        parent,
    })
}

#[cfg(unix)]
fn open_parent_with_hook(path: &Path, hook: impl FnOnce()) -> Result<HeldParent> {
    let mut components = Vec::new();
    let mut absolute = false;
    for component in path.components() {
        match component {
            Component::RootDir => absolute = true,
            Component::CurDir => {}
            Component::Normal(part) => components.push(part),
            Component::ParentDir => {
                return Err(anyhow!("triage paths cannot contain parent traversal"));
            }
            Component::Prefix(_) => {
                return Err(anyhow!(
                    "triage path prefix is unsupported on this platform"
                ));
            }
        }
    }
    let (final_name, parents) = components
        .split_last()
        .ok_or_else(|| anyhow!("triage path must name a file"))?;
    let mut directory = open_directory(if absolute {
        OsStr::new("/")
    } else {
        OsStr::new(".")
    })
    .map_err(|_| anyhow!("triage path root is unavailable"))?;
    for component in parents {
        let name = c_string(component)?;
        directory = openat(
            directory.as_raw_fd(),
            &name,
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0,
        )
        .map_err(|_| anyhow!("triage paths cannot traverse symlinks or non-directories"))?;
    }
    let held = HeldParent {
        directory,
        final_name: c_string(final_name)?,
    };
    hook();
    Ok(held)
}

#[cfg(unix)]
fn open_directory(path: &OsStr) -> std::io::Result<OwnedFd> {
    let name = c_string_io(path)?;
    // SAFETY: name is a valid null-terminated C string.
    let descriptor = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
        )
    };
    owned_fd(descriptor)
}

#[cfg(unix)]
fn openat(
    directory: libc::c_int,
    name: &CString,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<OwnedFd> {
    // SAFETY: directory is a valid fd or AT_FDCWD, and name is a null-terminated C string.
    let descriptor = unsafe { libc::openat(directory, name.as_ptr(), flags, mode as libc::c_uint) };
    owned_fd(descriptor)
}

#[cfg(unix)]
fn owned_fd(descriptor: libc::c_int) -> std::io::Result<OwnedFd> {
    if descriptor < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: descriptor is verified non-negative and newly opened.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

#[cfg(unix)]
fn descriptor_metadata(descriptor: libc::c_int) -> std::io::Result<libc::stat> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: metadata pointer is valid uninitialized memory for libc::stat.
    if unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fstat succeeded with return code 0, fully initializing metadata.
    Ok(unsafe { metadata.assume_init() })
}

#[cfg(unix)]
fn c_string(component: &OsStr) -> Result<CString> {
    c_string_io(component).map_err(|_| anyhow!("triage path contains an invalid component"))
}

#[cfg(unix)]
fn c_string_io(component: &OsStr) -> std::io::Result<CString> {
    CString::new(component.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path component contains NUL",
        )
    })
}
