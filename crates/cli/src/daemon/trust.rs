//! Trust boundary checks for the daemon Unix socket.
//!
//! The daemon socket carries scan targets and scan payloads. Treating any file
//! at the configured path as a daemon is a local secret-exposure bug, so both
//! server and client paths use this single owner for parent-dir, socket-file,
//! and connected-peer validation.

use anyhow::{bail, Context, Result};
use std::path::Path;

pub(super) fn ensure_private_socket_dir(parent: &Path) -> Result<()> {
    let parent = effective_parent(parent);
    let parent_was_implicit = parent == Path::new(".");

    if !parent_was_implicit {
        validate_existing_ancestors_no_symlink(parent)?;
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("creating daemon socket parent dir {}", parent.display()))?;
    }

    let meta = validate_socket_parent_identity(parent)?;
    let mode = unix_mode(&meta);
    if mode != 0o700 {
        if parent_was_implicit {
            bail!(
                "daemon: implicit socket parent {} is mode {mode:#o}; refusing to bind a \
                 credential-streaming daemon socket in a group/other-accessible current \
                 directory. Pass --socket with a path under a private 0700 directory.",
                parent.display()
            );
        }
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).with_context(
            || {
                format!(
                    "daemon: tightening socket parent dir {} from mode {mode:#o} to 0700",
                    parent.display()
                )
            },
        )?;
        eprintln!(
            "keyhog daemon: tightened socket parent dir {} from mode {mode:#o} to 0700",
            parent.display()
        );
    }
    Ok(())
}

pub(super) fn validate_socket_for_connect(socket_path: &Path) -> Result<()> {
    validate_socket_parent_for_connect(socket_path)?;
    validate_socket_file(socket_path)
}

pub(super) fn remove_stale_socket_if_trusted(socket_path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(socket_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("stat daemon socket {}", socket_path.display()));
        }
    }

    validate_socket_file(socket_path)?;
    match std::os::unix::net::UnixStream::connect(socket_path) {
        Ok(_) => bail!(
            "daemon: socket {} is already bound by another keyhog daemon (refuse to clobber). \
             Run `keyhog daemon stop` first, or pass --socket to use a different path.",
            socket_path.display()
        ),
        Err(error) => {
            tracing::warn!(
                socket = %socket_path.display(),
                %error,
                "removing trusted stale daemon socket (no listener on the other end)"
            );
            std::fs::remove_file(socket_path).with_context(|| {
                format!("daemon: removing stale socket {}", socket_path.display())
            })?;
            Ok(())
        }
    }
}

pub(super) fn set_socket_mode_user_only(socket_path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::symlink_metadata(socket_path)
        .with_context(|| format!("stat daemon socket {}", socket_path.display()))?;
    if meta.file_type().is_symlink() {
        bail!(
            "daemon: socket {} is a symlink after bind; refusing to trust it",
            socket_path.display()
        );
    }
    let mut perms = meta.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(socket_path, perms)
        .with_context(|| format!("daemon: chmod 0600 on socket {}", socket_path.display()))?;
    validate_socket_file(socket_path)
}

pub(super) fn verify_connected_peer(
    stream: &tokio::net::UnixStream,
    socket_path: &Path,
) -> Result<()> {
    let peer_uid = connected_peer_uid(stream).with_context(|| {
        format!(
            "daemon client: verifying peer uid for {}",
            socket_path.display()
        )
    })?;
    let me = current_uid();
    if peer_uid != me {
        bail!(
            "daemon client: peer at {} is uid {peer_uid}, not this user uid {me}; refusing to \
             send scan paths or content to an untrusted daemon socket.",
            socket_path.display()
        );
    }
    Ok(())
}

pub(super) fn connected_peer_uid(stream: &tokio::net::UnixStream) -> Result<libc::uid_t> {
    platform_connected_peer_uid(stream)
}

/// Server-side twin of [`verify_connected_peer`]: reject any accepted connection
/// whose peer uid is not this daemon's uid. The 0600 socket mode + 0700 parent
/// dir are the primary boundary, but a bind-race before `set_socket_mode_user_only`
/// chmods 0600, or root connecting, would otherwise reach the scan path with no
/// peer-cred gate. Applied symmetrically with the client so neither side trusts
/// a cross-uid peer.
pub(super) fn verify_accepted_peer(stream: &tokio::net::UnixStream) -> Result<()> {
    let peer_uid =
        connected_peer_uid(stream).context("daemon: verifying uid of a connecting peer")?;
    let me = current_uid();
    if peer_uid != me {
        bail!(
            "daemon: rejecting connection from uid {peer_uid}, not this daemon's uid {me}; the \
             credential-streaming socket serves only its owner."
        );
    }
    Ok(())
}

fn validate_socket_parent_for_connect(socket_path: &Path) -> Result<()> {
    let parent = match socket_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(parent) => parent,
        None => Path::new("."),
    };
    let meta = validate_socket_parent_identity(parent)?;
    let mode = unix_mode(&meta);
    if mode & 0o022 != 0 {
        bail!(
            "daemon client: socket parent dir {} is mode {mode:#o}; refusing to trust a daemon \
             socket in a group/other-writable directory. Restart the daemon under a private \
             runtime/cache directory or pass --no-daemon.",
            parent.display()
        );
    }
    Ok(())
}

fn validate_socket_parent_identity(parent: &Path) -> Result<std::fs::Metadata> {
    use std::os::unix::fs::MetadataExt;
    validate_no_symlink_ancestors(parent)?;
    let meta = std::fs::symlink_metadata(parent)
        .with_context(|| format!("stat daemon socket parent dir {}", parent.display()))?;
    if meta.file_type().is_symlink() {
        bail!(
            "daemon: socket parent dir {} is a symlink; refusing to use it because it could \
             redirect the credential-streaming socket into attacker-controlled space.",
            parent.display()
        );
    }
    if !meta.is_dir() {
        bail!(
            "daemon: socket parent path {} is not a directory; pass --socket under a private \
             directory owned by this user.",
            parent.display()
        );
    }
    let owner = meta.uid();
    let me = current_uid();
    if owner != me {
        bail!(
            "daemon: socket parent dir {} is owned by uid {owner}, not this user uid {me}; \
             refusing to use an untrusted daemon socket directory.",
            parent.display()
        );
    }
    Ok(meta)
}

#[derive(Clone, Copy)]
enum MissingAncestorPolicy {
    Error,
    Tolerate,
}

#[derive(Clone, Copy)]
enum AncestorUse {
    TrustSocket,
    CreateSocketDir,
}

fn validate_no_symlink_ancestors(path: &Path) -> Result<()> {
    validate_ancestors_no_symlink(path, MissingAncestorPolicy::Error, AncestorUse::TrustSocket)
}

fn validate_existing_ancestors_no_symlink(path: &Path) -> Result<()> {
    validate_ancestors_no_symlink(
        path,
        MissingAncestorPolicy::Tolerate,
        AncestorUse::CreateSocketDir,
    )
}

fn validate_ancestors_no_symlink(
    path: &Path,
    missing_policy: MissingAncestorPolicy,
    ancestor_use: AncestorUse,
) -> Result<()> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match std::fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(symlink_ancestor_error(path, ancestor, ancestor_use));
            }
            Ok(_) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && matches!(missing_policy, MissingAncestorPolicy::Tolerate) => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("stat daemon socket path component {}", ancestor.display())
                });
            }
        }
    }
    Ok(())
}

fn symlink_ancestor_error(
    path: &Path,
    ancestor: &Path,
    ancestor_use: AncestorUse,
) -> anyhow::Error {
    match ancestor_use {
        AncestorUse::TrustSocket => anyhow::anyhow!(
            "daemon: socket path {} contains symlink component {}; refusing to trust a \
             credential-streaming daemon socket through a redirectable path.",
            path.display(),
            ancestor.display()
        ),
        AncestorUse::CreateSocketDir => anyhow::anyhow!(
            "daemon: socket path {} contains symlink component {}; refusing to create \
             daemon socket directories through a redirectable path.",
            path.display(),
            ancestor.display()
        ),
    }
}

fn validate_socket_file(socket_path: &Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let meta = std::fs::symlink_metadata(socket_path)
        .with_context(|| format!("stat daemon socket {}", socket_path.display()))?;
    // This trust check guards both the client's connect-and-send path
    // (validate_socket_for_connect) and the server's bind-time paths
    // (remove_stale_socket_if_trusted, set_socket_mode_user_only), so the
    // messages stay context-neutral ("refusing to trust") rather than
    // client-framed ("refusing to send") - a `daemon start` failure must not
    // print "daemon client:" at the operator.
    if meta.file_type().is_symlink() {
        bail!(
            "daemon: socket {} is a symlink; refusing to trust a redirectable daemon socket.",
            socket_path.display()
        );
    }
    if !meta.file_type().is_socket() {
        bail!(
            "daemon: {} is not a Unix socket; refusing to treat it as a keyhog daemon.",
            socket_path.display()
        );
    }
    let owner = meta.uid();
    let me = current_uid();
    if owner != me {
        bail!(
            "daemon: socket {} is owned by uid {owner}, not this user uid {me}; refusing to \
             trust it.",
            socket_path.display()
        );
    }
    let mode = unix_mode(&meta);
    if mode != 0o600 {
        bail!(
            "daemon: socket {} is mode {mode:#o}, expected 0o600; refusing to trust a \
             group/other-accessible daemon socket.",
            socket_path.display()
        );
    }
    Ok(())
}

fn unix_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

fn current_uid() -> libc::uid_t {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

fn effective_parent(parent: &Path) -> &Path {
    if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    }
}

#[cfg(target_os = "linux")]
fn platform_connected_peer_uid(stream: &tokio::net::UnixStream) -> Result<libc::uid_t> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;

    let mut cred = MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the fd belongs to a live UnixStream, `cred` points to enough
    // writable memory for a ucred, and `len` starts with that buffer size.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("getsockopt(SO_PEERCRED)");
    }
    if len < std::mem::size_of::<libc::ucred>() as libc::socklen_t {
        bail!("getsockopt(SO_PEERCRED) returned a truncated credential record");
    }
    // SAFETY: getsockopt succeeded and reported a complete ucred record.
    let cred = unsafe { cred.assume_init() };
    Ok(cred.uid)
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn platform_connected_peer_uid(stream: &tokio::net::UnixStream) -> Result<libc::uid_t> {
    use std::os::fd::AsRawFd;

    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: getpeereid only reads the live socket fd and writes uid/gid.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("getpeereid");
    }
    Ok(uid)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn platform_connected_peer_uid(_stream: &tokio::net::UnixStream) -> Result<libc::uid_t> {
    bail!(
        "daemon client: this Unix target has no supported peer-credential API; refusing to \
         send scan paths or content over the daemon socket. Run `keyhog scan --no-daemon ...` \
         or use Linux/macOS/BSD for daemon mode."
    )
}

#[doc(hidden)]
pub(crate) mod testing {
    use anyhow::Result;
    use std::path::Path;

    pub(crate) fn ensure_private_socket_dir(parent: &Path) -> Result<()> {
        super::ensure_private_socket_dir(parent)
    }

    pub(crate) fn remove_stale_socket_if_trusted(socket_path: &Path) -> Result<()> {
        super::remove_stale_socket_if_trusted(socket_path)
    }

    pub(crate) fn validate_socket_for_connect(socket_path: &Path) -> Result<()> {
        super::validate_socket_for_connect(socket_path)
    }

    pub(crate) fn connected_peer_uid(stream: &tokio::net::UnixStream) -> Result<libc::uid_t> {
        super::connected_peer_uid(stream)
    }

    pub(crate) fn verify_accepted_peer(stream: &tokio::net::UnixStream) -> Result<()> {
        super::verify_accepted_peer(stream)
    }

    pub(crate) fn current_uid() -> libc::uid_t {
        super::current_uid()
    }
}
