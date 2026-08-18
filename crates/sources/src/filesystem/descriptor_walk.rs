use keyhog_core::SourceError;
use std::ffi::{CString, OsString};
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub(super) enum DescriptorEntryKind {
    File { size: u64 },
    Directory,
    Symlink { target: PathBuf },
    Other,
}

pub(super) struct DescriptorEntry {
    pub(super) path: PathBuf,
    pub(super) kind: DescriptorEntryKind,
}

pub(super) fn walk_descriptor_relative(
    root: &Path,
    mut visit: impl FnMut(&DescriptorEntry) -> Result<bool, SourceError>,
) -> Result<(), SourceError> {
    let mut pending = vec![Vec::<OsString>::new()];
    while let Some(mut relative) = pending.pop() {
        let mut directory = open_directory_chain(root, &relative).map_err(|error| {
            SourceError::Other(format!(
                "failed to open descriptor-relative filesystem directory '{}': {error}; directory was not scanned",
                root.join(relative.iter().collect::<PathBuf>()).display()
            ))
        })?;

        loop {
            let mut child_directories = visit_directory(&directory, root, &relative, &mut visit)?;
            if child_directories.len() == 1 {
                let Some(child) = child_directories.pop() else {
                    return Err(SourceError::Other(
                        "descriptor-relative walker lost its only child directory".to_string(),
                    ));
                };
                directory = open_child_directory(&directory, &child).map_err(|error| {
                    SourceError::Other(format!(
                        "failed to open descriptor-relative filesystem directory '{}': {error}; directory was not scanned",
                        root.join(relative.iter().collect::<PathBuf>()).join(&child).display()
                    ))
                })?;
                relative.push(child);
                continue;
            }

            for child in child_directories.into_iter().rev() {
                let mut child_relative = relative.clone();
                child_relative.push(child);
                pending.push(child_relative);
            }
            break;
        }
    }
    Ok(())
}

fn open_directory_chain(root: &Path, relative: &[OsString]) -> std::io::Result<File> {
    let mut directory = open_root_directory(root)?;
    for component in relative {
        directory = open_child_directory(&directory, component)?;
    }
    Ok(directory)
}

fn open_root_directory(root: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    options.open(root)
}

fn open_child_directory(parent: &File, name: &OsString) -> std::io::Result<File> {
    let name = CString::new(name.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "filesystem path component contains a NUL byte",
        )
    })?;
    // SAFETY: parent is a valid directory file descriptor, and name is a null-terminated C string.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is non-negative and newly opened by openat.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn visit_directory(
    directory: &File,
    root: &Path,
    relative: &[OsString],
    visit: &mut impl FnMut(&DescriptorEntry) -> Result<bool, SourceError>,
) -> Result<Vec<OsString>, SourceError> {
    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let logical_dir = root.join(relative.iter().collect::<PathBuf>());
    let entries = std::fs::read_dir(&proc_path).map_err(|error| {
        SourceError::Other(format!(
            "failed to enumerate descriptor-relative filesystem directory '{}': {error}; directory was not scanned",
            logical_dir.display()
        ))
    })?;
    let mut child_directories = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            SourceError::Other(format!(
                "failed to enumerate an entry below descriptor-relative directory '{}': {error}; entry was not scanned",
                logical_dir.display()
            ))
        })?;
        let name = entry.file_name();
        let logical_path = logical_dir.join(&name);
        let file_type = entry.file_type().map_err(|error| {
            SourceError::Other(format!(
                "failed to classify descriptor-relative filesystem entry '{}': {error}; entry was not scanned",
                logical_path.display()
            ))
        })?;
        let kind = if file_type.is_file() {
            let size = entry
                .metadata()
                .map_err(|error| {
                    SourceError::Other(format!(
                        "failed to stat descriptor-relative filesystem file '{}': {error}; file was not scanned",
                        logical_path.display()
                    ))
                })?
                .len();
            DescriptorEntryKind::File { size }
        } else if file_type.is_dir() {
            DescriptorEntryKind::Directory
        } else if file_type.is_symlink() {
            let target = std::fs::read_link(entry.path()).map_err(|error| {
                SourceError::Other(format!(
                    "failed to inspect descriptor-relative filesystem symlink '{}': {error}; link target was not scanned",
                    logical_path.display()
                ))
            })?;
            DescriptorEntryKind::Symlink { target }
        } else {
            DescriptorEntryKind::Other
        };
        let row = DescriptorEntry {
            path: logical_path,
            kind,
        };
        if visit(&row)? && matches!(row.kind, DescriptorEntryKind::Directory) {
            child_directories.push(name);
        }
    }
    child_directories.sort_unstable_by(|left, right| {
        left.as_os_str()
            .as_bytes()
            .cmp(right.as_os_str().as_bytes())
    });
    Ok(child_directories)
}
