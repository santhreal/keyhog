//! Regression tests encoding every pure-function behavior in the daemon
//! server before modularization. Each test names the function it pins and
//! the invariant it defends. These must stay green across the move refactor.

use super::{
    backend_recovery_status_from_receipt, compute_git_blob_oid, default_socket_path,
    file_type_label, filesystem_identity, is_transient_accept_error, is_work_request,
    pin_regular_file, refused_file_type_message, warm_route_error, MassBatchDispatch,
    RequestIdAllocator,
};
use crate::daemon::protocol::{Request, Response, WarmBackendIdentity, WarmBackendStatus};
use keyhog_core::guard_state::{FilesystemIdentity, GitHashAlgorithm};
use keyhog_scanner::{BackendRecoveryReceipt, RecoveredInputRange, ScanBackend};
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::Path;

// ── Helpers ──────────────────────────────────────────────────────────

fn ready_warm_backend() -> WarmBackendStatus {
    WarmBackendStatus {
        ready: true,
        daemon_generation: "test-gen".to_string(),
        identity: WarmBackendIdentity {
            engine: "test".to_string(),
            gpu_artifact: None,
            binary_sha256: "abc".to_string(),
            detector_rules_digest: "def".to_string(),
            config_digest: "ghi".to_string(),
        },
        required_backends: vec!["cpu-fallback".to_string()],
        initialized_backends: vec!["cpu-fallback".to_string()],
        reason: None,
        repair_command: None,
    }
}

fn not_ready_warm_backend(reason: Option<&str>, repair: Option<&str>) -> WarmBackendStatus {
    WarmBackendStatus {
        ready: false,
        daemon_generation: "test-gen".to_string(),
        identity: WarmBackendIdentity {
            engine: "test".to_string(),
            gpu_artifact: None,
            binary_sha256: "abc".to_string(),
            detector_rules_digest: "def".to_string(),
            config_digest: "ghi".to_string(),
        },
        required_backends: vec![],
        initialized_backends: vec![],
        reason: reason.map(|s| s.to_string()),
        repair_command: repair.map(|s| s.to_string()),
    }
}

// ── is_transient_accept_error ────────────────────────────────────────

/// WHY: a transient accept error must not kill the daemon. The classifier
/// must return true for interrupted, would-block, and connection-aborted.
#[test]
fn transient_accept_error_classifies_std_error_kinds() {
    assert!(is_transient_accept_error(&std::io::Error::new(
        ErrorKind::Interrupted,
        "EINTR"
    )));
    assert!(is_transient_accept_error(&std::io::Error::new(
        ErrorKind::WouldBlock,
        "EAGAIN"
    )));
    assert!(is_transient_accept_error(&std::io::Error::new(
        ErrorKind::ConnectionAborted,
        "ECONNABORTED"
    )));
}

/// WHY: EMFILE (24) and ENFILE (23) are the most important transient
/// failures for a daemon under a connection burst. std maps them to
/// ErrorKind::Other, so the classifier must match on raw errno.
#[cfg(unix)]
#[test]
fn transient_accept_error_catches_fd_exhaustion_via_raw_errno() {
    assert!(is_transient_accept_error(
        &std::io::Error::from_raw_os_error(24)
    ));
    assert!(is_transient_accept_error(
        &std::io::Error::from_raw_os_error(23)
    ));
}

/// WHY: errors that are not transient must be classified as fatal so the
/// daemon does not spin forever on an unrecoverable listener failure.
#[test]
fn transient_accept_error_rejects_unrelated_errors() {
    assert!(!is_transient_accept_error(&std::io::Error::new(
        ErrorKind::NotFound,
        "socket gone"
    )));
    assert!(!is_transient_accept_error(&std::io::Error::new(
        ErrorKind::PermissionDenied,
        "perms"
    )));
    assert!(!is_transient_accept_error(&std::io::Error::new(
        ErrorKind::ConnectionReset,
        "ECONNRESET"
    )));
    #[cfg(unix)]
    assert!(!is_transient_accept_error(
        &std::io::Error::from_raw_os_error(13)
    ));
}

// ── warm_route_error ─────────────────────────────────────────────────

/// WHY: a ready warm backend must produce no error response so scans
/// proceed normally.
#[test]
fn warm_route_error_returns_none_when_ready() {
    assert!(warm_route_error(&ready_warm_backend()).is_none());
}

/// WHY: a not-ready backend with both reason and repair command must
/// produce an error that includes both, so the operator knows what is
/// wrong and how to fix it.
#[test]
fn warm_route_error_includes_reason_and_repair_when_both_present() {
    let status = not_ready_warm_backend(
        Some("GPU driver crashed"),
        Some("keyhog daemon stop && keyhog daemon start"),
    );
    let resp = warm_route_error(&status).expect("not-ready must produce an error");
    match resp {
        Response::Error { message } => {
            assert!(
                message.contains("GPU driver crashed"),
                "message must contain reason: {message}"
            );
            assert!(
                message.contains("keyhog daemon stop && keyhog daemon start"),
                "message must contain repair command: {message}"
            );
        }
        _ => panic!("expected Response::Error, got {resp:?}"),
    }
}

/// WHY: a not-ready backend with neither reason nor repair must produce a
/// generic fallback message that tells the operator to restart, not an
/// empty or partial error.
#[test]
fn warm_route_error_falls_back_when_reason_and_repair_absent() {
    let status = not_ready_warm_backend(None, None);
    let resp = warm_route_error(&status).expect("not-ready must produce an error");
    match resp {
        Response::Error { message } => {
            assert!(
                message.contains("internally inconsistent"),
                "fallback message must mention inconsistency: {message}"
            );
            assert!(
                message.contains("keyhog daemon stop && keyhog daemon start"),
                "fallback must still tell the operator to restart: {message}"
            );
        }
        _ => panic!("expected Response::Error, got {resp:?}"),
    }
}

/// WHY: a not-ready backend with a reason but no repair command must include
/// the reason in the error message and suggest the default restart command,
/// not drop the known cause behind a generic "internally inconsistent" message.
#[test]
fn warm_route_error_includes_reason_when_only_reason_present() {
    let status = not_ready_warm_backend(Some("GPU missing"), None);
    let resp = warm_route_error(&status).expect("not-ready must produce an error");
    match resp {
        Response::Error { message } => {
            assert!(
                message.contains("GPU missing"),
                "message must include the known reason: {message}"
            );
            assert!(
                message.contains("keyhog daemon stop && keyhog daemon start"),
                "message must suggest the default restart: {message}"
            );
            assert!(
                !message.contains("internally inconsistent"),
                "a known reason must not be hidden behind the generic fallback: {message}"
            );
        }
        _ => panic!("expected Response::Error, got {resp:?}"),
    }
}

/// WHY: a not-ready backend with no reason but a repair command must surface
/// the provided repair command, not discard it behind the generic fallback.
#[test]
fn warm_route_error_includes_repair_when_only_repair_present() {
    let status = not_ready_warm_backend(None, Some("keyhog autoroute recalibrate"));
    let resp = warm_route_error(&status).expect("not-ready must produce an error");
    match resp {
        Response::Error { message } => {
            assert!(
                message.contains("keyhog autoroute recalibrate"),
                "message must include the provided repair command: {message}"
            );
            assert!(
                !message.contains("internally inconsistent"),
                "a known repair command must not be hidden behind the generic fallback: {message}"
            );
        }
        _ => panic!("expected Response::Error, got {resp:?}"),
    }
}

// ── is_work_request ──────────────────────────────────────────────────

/// WHY: control requests (Hello, Health, Shutdown, GuardList, GuardRemove,
/// GuardStatus) must not be classified as work so they stay answerable
/// when the data plane is saturated.
#[test]
fn is_work_request_rejects_control_requests() {
    assert!(!is_work_request(&Request::Hello));
    assert!(!is_work_request(&Request::Health));
    assert!(!is_work_request(&Request::Shutdown));
    assert!(!is_work_request(&Request::GuardList));
    assert!(!is_work_request(&Request::GuardRemove {
        root: String::new()
    }));
    assert!(!is_work_request(&Request::GuardStatus {
        root: String::new(),
    }));
}

/// WHY: scan and mass requests must be classified as work so they consume
/// a data-plane permit and are refused when the daemon is saturated or
/// draining.
#[test]
fn is_work_request_accepts_scan_and_mass_requests() {
    assert!(is_work_request(&Request::ScanText {
        path: None,
        text: String::new(),
        dogfood: false,
        profile: false,
    }));
    assert!(is_work_request(&Request::ScanPath {
        path: "/tmp/x".to_string(),
        working_dir: None,
        dogfood: false,
        profile: false,
    }));
    assert!(is_work_request(&Request::MassBegin {
        dogfood: false,
        profile: false,
    }));
    assert!(is_work_request(&Request::MassBatch { chunks: Vec::new() }));
    assert!(is_work_request(&Request::MassFilesystemBegin {
        root: "/tmp".to_string(),
        max_file_size: 1024,
        ignore_paths: Vec::new(),
        respect_default_excludes: true,
        reader_threads: None,
        incremental_cache: None,
    }));
    assert!(is_work_request(&Request::MassFilesystemDrain));
    assert!(is_work_request(&Request::GuardCommitBegin {
        repo_path: String::new(),
        index_fingerprint: String::new(),
        hash_algorithm: "sha1".to_string(),
        entries: Vec::new(),
    }));
    assert!(is_work_request(&Request::GuardCommitBlob {
        transaction_id: 0,
        blob_oid: String::new(),
        object_size: 0,
        payload: Vec::new(),
    }));
    assert!(is_work_request(&Request::GuardCommitFinish {
        transaction_id: 0,
        client_objects_streamed: 0,
        client_bytes_streamed: 0,
    }));
    assert!(is_work_request(&Request::GuardAdd {
        root: String::new(),
        mode: "repo".to_string(),
    }));
    assert!(is_work_request(&Request::GuardReconcile {
        root: String::new(),
    }));
}

/// WHY: MassEnd is classified as work so it is only sent on a data-plane
/// admitted connection, but admission_refusal exempts it from the drain
/// refusal so an in-flight transaction can finish during shutdown.
#[test]
fn is_work_request_accepts_mass_end() {
    assert!(is_work_request(&Request::MassEnd));
}

// ── compute_git_blob_oid ─────────────────────────────────────────────

fn test_blob_chunks(data: &str) -> (u64, Vec<keyhog_core::Chunk>) {
    let size = data.len() as u64;
    let chunks = if data.is_empty() {
        Vec::new()
    } else {
        vec![keyhog_core::Chunk {
            data: data.to_string().into(),
            metadata: keyhog_core::ChunkMetadata::default(),
        }]
    };
    (size, chunks)
}

/// WHY: the Git blob OID for an empty payload must match Git's canonical
/// hash. SHA-1 of `blob 0\0` is the well-known empty-tree blob hash.
#[test]
fn git_blob_oid_sha1_empty_payload() {
    let (size, chunks) = test_blob_chunks("");
    let oid = compute_git_blob_oid(GitHashAlgorithm::Sha1, size, &chunks);
    assert_eq!(oid, "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
}

/// WHY: the Git blob OID for a known payload must match Git's output.
/// "hello world" (without newline) has a well-known SHA-1 blob hash.
#[test]
fn git_blob_oid_sha1_known_payload() {
    let (size, chunks) = test_blob_chunks("hello world");
    let oid = compute_git_blob_oid(GitHashAlgorithm::Sha1, size, &chunks);
    assert_eq!(oid, "95d09f2b10159347eece71399a7e2e907ea3df4f");
}

/// WHY: SHA-256 must produce a different hash from SHA-1 for the same
/// payload, and it must match Git's SHA-256 blob format.
#[test]
fn git_blob_oid_sha256_known_payload() {
    let (size, chunks) = test_blob_chunks("hello world");
    let oid = compute_git_blob_oid(GitHashAlgorithm::Sha256, size, &chunks);
    assert_eq!(
        oid,
        "fee53a18d32820613c0527aa79be5cb30173c823a9b448fa4817767cc84c6f03"
    );
    assert_eq!(oid.len(), 64, "SHA-256 OID must be 64 hex chars");
    let sha1 = compute_git_blob_oid(GitHashAlgorithm::Sha1, size, &chunks);
    assert_ne!(oid, sha1, "SHA-256 and SHA-1 must differ");
}

/// WHY: the header must include the exact byte length, so payloads of
/// different sizes produce different OIDs.
#[test]
fn git_blob_oid_distinguishes_sizes() {
    let (size_a, chunks_a) = test_blob_chunks("a");
    let (size_aa, chunks_aa) = test_blob_chunks("aa");
    let a = compute_git_blob_oid(GitHashAlgorithm::Sha1, size_a, &chunks_a);
    let aa = compute_git_blob_oid(GitHashAlgorithm::Sha1, size_aa, &chunks_aa);
    assert_ne!(a, aa, "different sizes must produce different OIDs");
}
// ── file_type_label ──────────────────────────────────────────────────

/// WHY: each file type must produce a human-readable label so the refusal
/// message tells the operator what the path actually is.
#[cfg(unix)]
#[test]
fn file_type_label_covers_all_types() {
    // We cannot construct std::fs::FileType directly, so test via
    // real filesystem objects.
    let dir = tempfile::tempdir().unwrap();
    let dir_meta = std::fs::metadata(dir.path()).unwrap();
    assert_eq!(file_type_label(&dir_meta.file_type()), "a directory");

    let link_path = dir.path().join("link");
    let target = dir.path().join("target.txt");
    std::fs::write(&target, "x").unwrap();
    std::os::unix::fs::symlink(&target, &link_path).unwrap();
    let link_meta = std::fs::symlink_metadata(&link_path).unwrap();
    assert_eq!(file_type_label(&link_meta.file_type()), "a symbolic link");

    // Socket
    let sock_path = dir.path().join("test.sock");
    if let Ok(_listener) = std::os::unix::net::UnixListener::bind(&sock_path) {
        let sock_meta = std::fs::symlink_metadata(&sock_path).unwrap();
        assert_eq!(file_type_label(&sock_meta.file_type()), "a socket");
    }

    // FIFO
    let fifo_path = dir.path().join("test.fifo");
    if std::process::Command::new("mkfifo")
        .arg(&fifo_path)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        let fifo_meta = std::fs::symlink_metadata(&fifo_path).unwrap();
        assert_eq!(file_type_label(&fifo_meta.file_type()), "a FIFO");
    }

    // Character device
    if let Ok(char_meta) = std::fs::metadata("/dev/null") {
        assert_eq!(
            file_type_label(&char_meta.file_type()),
            "a character device"
        );
    }
}

// ── refused_file_type_message ────────────────────────────────────────

/// WHY: the refusal message must include the path and the file type label
/// so the operator knows what was rejected and why.
#[cfg(unix)]
#[test]
fn refused_file_type_message_includes_path_and_type() {
    let dir = tempfile::tempdir().unwrap();
    let dir_meta = std::fs::metadata(dir.path()).unwrap();
    let msg = refused_file_type_message(dir.path(), &dir_meta.file_type());
    assert!(
        msg.contains("refusing to scan"),
        "message must state refusal: {msg}"
    );
    assert!(
        msg.contains("regular files only"),
        "message must state the constraint: {msg}"
    );
    assert!(
        msg.contains("a directory"),
        "message must include the type label: {msg}"
    );
    assert!(
        msg.contains("--daemon=off"),
        "message must offer the in-process alternative: {msg}"
    );
}

// ── filesystem_identity ──────────────────────────────────────────────

/// WHY: a path that exists must return its real device and inode, not
/// zeros, so guard root registration can detect inode recycling.
#[cfg(unix)]
#[test]
fn filesystem_identity_returns_real_dev_and_inode_for_existing_path() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("file.txt");
    std::fs::write(&file_path, "x").unwrap();
    let identity = filesystem_identity(&file_path);
    assert_ne!(
        identity,
        FilesystemIdentity {
            device: 0,
            inode: 0
        },
        "existing file must have nonzero dev and inode"
    );
}

/// WHY: a path that does not exist must return zeros, not panic, so
/// registration can proceed and the root existence check happens
/// separately.
#[cfg(unix)]
#[test]
fn filesystem_identity_returns_zeros_for_missing_path() {
    let identity = filesystem_identity(Path::new("/nonexistent/keyhog-test-identity"));
    assert_eq!(
        identity,
        FilesystemIdentity {
            device: 0,
            inode: 0
        },
        "missing path must return zero identity"
    );
}

/// WHY: two files in the same directory must have the same device but
/// different inodes, so the identity is specific enough to detect
/// replacement.
#[cfg(unix)]
#[test]
fn filesystem_identity_distinguishes_files_by_inode() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    std::fs::write(&a, "a").unwrap();
    std::fs::write(&b, "b").unwrap();
    let id_a = filesystem_identity(&a);
    let id_b = filesystem_identity(&b);
    assert_eq!(id_a.device, id_b.device, "same dir must share device");
    assert_ne!(
        id_a.inode, id_b.inode,
        "different files must differ by inode"
    );
}

// ── pin_regular_file ─────────────────────────────────────────────────

/// WHY: a regular file must be pinned successfully, and the returned
/// handle must hold the same inode.
#[cfg(unix)]
#[test]
fn pin_regular_file_accepts_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("regular.txt");
    std::fs::write(&file_path, "content").unwrap();
    let pinned = pin_regular_file(&file_path).expect("regular file must be accepted");
    let pinned_meta = pinned.0.metadata().unwrap();
    let path_meta = std::fs::symlink_metadata(&file_path).unwrap();
    assert_eq!(
        pinned_meta.dev(),
        path_meta.dev(),
        "pinned handle must match path device"
    );
    assert_eq!(
        pinned_meta.ino(),
        path_meta.ino(),
        "pinned handle must match path inode"
    );
}

/// WHY: a directory must be rejected with a message that names it as a
/// directory, not opened and walked as a tree.
#[cfg(unix)]
#[test]
fn pin_regular_file_rejects_directory() {
    let dir = tempfile::tempdir().unwrap();
    let err = pin_regular_file(dir.path()).expect_err("directory must be rejected");
    assert!(
        err.contains("a directory"),
        "error must name the type: {err}"
    );
    assert!(
        err.contains("regular files only"),
        "error must state the constraint: {err}"
    );
}

/// WHY: a symlink must be rejected, not followed, so a symlink swapped in
/// after classification cannot redirect the scan to different content.
#[cfg(unix)]
#[test]
fn pin_regular_file_rejects_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.txt");
    std::fs::write(&target, "content").unwrap();
    let link = dir.path().join("link.txt");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let err = pin_regular_file(&link).expect_err("symlink must be rejected");
    assert!(
        err.contains("a symbolic link") || err.contains("symbolic link"),
        "error must name symlink: {err}"
    );
}

/// WHY: a nonexistent path must be rejected with an error, not panic.
#[test]
fn pin_regular_file_rejects_missing_path() {
    let err = pin_regular_file(Path::new("/nonexistent/keyhog-pin-test"))
        .expect_err("missing path must be rejected");
    assert!(
        err.contains("cannot identify"),
        "error must state the failure: {err}"
    );
}

// ── backend_recovery_status_from_receipt ─────────────────────────────

/// WHY: the receipt must be converted to a response status that preserves
/// the backend labels, ranges, and aggregate counts exactly.
#[test]
fn backend_recovery_status_preserves_receipt_fields() {
    let receipt = BackendRecoveryReceipt::new(
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
        vec![
            RecoveredInputRange::new(0, 0, 100),
            RecoveredInputRange::new(2, 50, 200),
        ],
        "SIMD backend failed".to_string(),
    );
    let status = backend_recovery_status_from_receipt(&receipt);
    assert_eq!(status.failed_backend, "simd-regex");
    assert_eq!(status.recovery_backend, "cpu-fallback");
    assert_eq!(status.reason, "SIMD backend failed");
    assert_eq!(status.recovered_ranges.len(), 2);
    assert_eq!(status.recovered_ranges[0].chunk_index, 0);
    assert_eq!(status.recovered_ranges[0].byte_start, 0);
    assert_eq!(status.recovered_ranges[0].byte_end, 100);
    assert_eq!(status.recovered_ranges[1].chunk_index, 2);
    assert_eq!(status.recovered_ranges[1].byte_start, 50);
    assert_eq!(status.recovered_ranges[1].byte_end, 200);
    assert_eq!(status.recovered_chunks, 2);
    assert_eq!(status.recovered_bytes, 100 + 150);
}

/// WHY: an empty receipt (no ranges) must produce zero counts, not panic.
#[test]
fn backend_recovery_status_with_no_ranges() {
    let receipt = BackendRecoveryReceipt::new(
        ScanBackend::GpuCuda,
        ScanBackend::SimdCpu,
        vec![],
        "GPU unavailable".to_string(),
    );
    let status = backend_recovery_status_from_receipt(&receipt);
    assert!(status.recovered_ranges.is_empty());
    assert_eq!(status.recovered_chunks, 0);
    assert_eq!(status.recovered_bytes, 0);
    assert_eq!(status.failed_backend, "gpu-cuda-region-presence");
    assert_eq!(status.recovery_backend, "simd-regex");
}

// ── MassBatchDispatch::error ─────────────────────────────────────────

/// WHY: the error constructor must produce a dispatch with zero chunks,
/// bytes, and no findings, so the mass session accounting stays correct
/// even when a batch fails.
#[test]
fn mass_batch_dispatch_error_zeros_all_counters() {
    let dispatch = MassBatchDispatch::error("test error".to_string());
    assert_eq!(dispatch.chunks, 0);
    assert_eq!(dispatch.bytes, 0);
    assert!(!dispatch.gpu);
    assert!(dispatch.finding_paths.is_empty());
    assert_eq!(dispatch.pathless_findings, 0);
    match dispatch.response {
        Response::Error { message } => assert_eq!(message, "test error"),
        _ => panic!("expected Response::Error"),
    }
}

// ── RequestIdAllocator ───────────────────────────────────────────────

/// WHY: the allocator must produce unique ids under sequential allocation
/// and each id must carry the daemon generation string.
#[test]
fn request_id_allocator_produces_unique_ids_with_generation() {
    let alloc = RequestIdAllocator::new("gen-abc".to_string());
    let id0 = alloc.next();
    let id1 = alloc.next();
    let id2 = alloc.next();
    assert_ne!(id0, id1, "ids must be unique");
    assert_ne!(id1, id2, "ids must be unique");
    assert_ne!(id0, id2, "ids must be unique");
    assert!(id0.contains("gen-abc"), "id must carry generation: {id0}");
    assert!(id1.contains("gen-abc"), "id must carry generation: {id1}");
}

// ── default_socket_path ──────────────────────────────────────────────

/// Serializes env-var mutation so parallel test threads do not race on
/// the process-global XDG_RUNTIME_DIR.
static SOCKET_PATH_ENV_GUARD: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Drop guard that restores an env var to its original value (or removes
/// it if it was unset). Ensures cleanup even if an assertion panics.
struct EnvRestore {
    key: &'static str,
    old: Option<std::ffi::OsString>,
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        match &self.old {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

/// WHY: when XDG_RUNTIME_DIR is set, the socket must live there (per-user,
/// tmpfs-backed, auto-cleaned on logout). When unset, it must fall back to
/// the cache directory under keyhog/server.sock. Both branches are tested
/// in one test under a shared mutex so parallel test threads cannot
/// observe each other's env mutation. The drop guard restores the env
/// var even if an assertion panics.
#[cfg(unix)]
#[test]
fn default_socket_path_prefers_xdg_then_falls_back_to_cache() {
    let _guard = SOCKET_PATH_ENV_GUARD.lock();
    let _restore = EnvRestore {
        key: "XDG_RUNTIME_DIR",
        old: std::env::var_os("XDG_RUNTIME_DIR"),
    };

    // Branch 1: XDG_RUNTIME_DIR set.
    let dir = tempfile::tempdir().unwrap();
    let xdg = dir.path().to_path_buf();
    std::env::set_var("XDG_RUNTIME_DIR", &xdg);
    let path = default_socket_path();
    assert_eq!(path, xdg.join("keyhog.sock"));

    // Branch 2: XDG_RUNTIME_DIR unset.
    std::env::remove_var("XDG_RUNTIME_DIR");
    let path = default_socket_path();
    assert!(
        path.ends_with(std::path::Path::new("keyhog/server.sock")),
        "fallback path must be under keyhog/server.sock: {path:?}"
    );
}
