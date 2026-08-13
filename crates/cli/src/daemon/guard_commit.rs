//! Client-side guard commit transaction: sends the exact staged
//! manifest to a compatible guard daemon, streams required blob
//! payloads, validates the receipt, and returns the finding count.
//!
//! This is the Milestone 1 hook integration. When a compatible guard
//! daemon is available, `keyhog scan --git-staged` uses this path
//! instead of the in-process staged scan. The daemon's clean
//! attestation cache skips blobs whose content and policy identity
//! are unchanged, so repeated commits of the same clean blobs do not
//! re-scan.
//!
//! The client must not transmit clean-hit payloads. Only blobs the
//! daemon names as required (cache misses) are streamed.

use crate::daemon::client::{self, Client};
use crate::daemon::protocol::{self, GuardWireManifestEntry, Request, Response};
use anyhow::{bail, Context, Result};
use keyhog_core::guard_state::GuardReceipt;
use keyhog_sources::{StagedEntryKind, StagedManifest, StagedManifestEntry};
use std::path::Path;

/// Maximum blob payload size the client will stream in one frame.
/// Matches the daemon's `max_blob_bytes` limit in `GuardCommitPlan`.
const MAX_BLOB_BYTES: usize = 8 * 1024 * 1024;

/// Result of a guard commit transaction.
pub(crate) struct GuardCommitResult {
    /// Number of unsuppressed findings (after suppression pipeline).
    pub findings_count: u64,
    /// Number of coverage gaps.
    pub coverage_gaps: u64,
    /// Terminal state label from the daemon.
    #[allow(dead_code)]
    pub terminal_state: String,
    /// Whether the index fingerprint changed during the transaction
    /// (concurrent index mutation).
    pub fingerprint_changed: bool,
    /// Clean attestation cache hits (blobs not re-scanned).
    pub cache_hits: u64,
    /// Blobs actually scanned by the daemon.
    pub blobs_scanned: u64,
    /// Total bytes scanned by the daemon.
    pub bytes_scanned: u64,
}

/// Run a guard commit transaction against a compatible daemon.
///
/// Steps:
/// 1. Acquire the staged manifest from the repository.
/// 2. Send `GuardCommitBegin` with manifest entries.
/// 3. Receive `GuardCommitPlan` naming clean hits and required blobs.
/// 4. For each required blob, read the object from the repo and send
///    `GuardCommitBlob`. Skip clean hits (no payload read).
/// 5. Send `GuardCommitFinish`.
/// 6. Validate the receipt: conservation of objects and bytes.
/// 7. Reacquire the staged manifest fingerprint. If changed, retry
///    once. If still changed, return `fingerprint_changed = true`.
pub(crate) async fn run_guard_commit(
    socket_path: &Path,
    repo_path: &Path,
    detector_rules_digest: &str,
) -> Result<GuardCommitResult> {
    // Canonicalize the repo path so the daemon can verify the staged
    // fingerprint against the correct working tree, not its own CWD.
    let repo_path = match std::fs::canonicalize(repo_path) {
        Ok(p) => p,
        Err(e) => bail!(
            "guard commit: cannot resolve repo path {}: {e}",
            repo_path.display()
        ),
    };
    let mut conn =
        client::connect_with_detector_rules_digest(socket_path, detector_rules_digest.to_string())
            .await
            .context("guard commit: connect to daemon")?;

    // Verify the daemon supports the guard wire protocol.
    if let Some(status) = conn.warm_backend_status() {
        if !status.ready {
            bail!(
                "guard commit: daemon warm backend is not ready; \
                 repair with `keyhog daemon stop && keyhog daemon start`"
            );
        }
    }

    match run_guard_commit_on_connection(&mut conn, &repo_path).await {
        Ok(result) if result.fingerprint_changed => {
            // Retry once: the index changed during the first transaction.
            // The second pass re-acquires the manifest with the current state.
            let retry = run_guard_commit_on_connection(&mut conn, &repo_path).await?;
            Ok(retry)
        }
        other => other,
    }
}

/// Run the guard commit transaction on an existing connection.
/// Separated so a fingerprint-change retry reuses the same connection.
async fn run_guard_commit_on_connection(
    conn: &mut Client,
    repo_path: &Path,
) -> Result<GuardCommitResult> {
    // 1. Acquire the staged manifest.
    let manifest = StagedManifest::acquire(repo_path)
        .map_err(|e| anyhow::anyhow!("guard commit: staged manifest: {e}"))?;

    // 2. Convert manifest entries to wire entries.
    let wire_entries: Vec<GuardWireManifestEntry> = manifest
        .entries
        .iter()
        .map(|e| manifest_entry_to_wire(e))
        .collect();

    let hash_algorithm = match manifest.hash_algorithm {
        keyhog_core::guard_state::GitHashAlgorithm::Sha1 => "sha1",
        keyhog_core::guard_state::GitHashAlgorithm::Sha256 => "sha256",
    };

    // 3. Send GuardCommitBegin.
    let begin_request = Request::GuardCommitBegin {
        repo_path: repo_path.display().to_string(),
        index_fingerprint: manifest.index_fingerprint.clone(),
        hash_algorithm: hash_algorithm.to_string(),
        entries: wire_entries,
    };
    let plan_response = conn.round_trip(&begin_request).await?;

    let (transaction_id, required_blob_oids) = match plan_response {
        Response::GuardCommitPlan {
            transaction_id,
            clean_hits: _,
            required_blob_oids,
            ..
        } => (transaction_id, required_blob_oids),
        Response::Error { message } => {
            bail!("guard commit: daemon rejected begin: {message}");
        }
        other => bail!(
            "guard commit: expected GuardCommitPlan, got {}",
            protocol::response_kind(&other)
        ),
    };

    // 4. Stream required blob payloads. Clean hits are skipped: the
    //    client must not read or transmit clean-hit blob bytes.
    let mut total_bytes_streamed: u64 = 0;
    for oid in &required_blob_oids {
        let payload = keyhog_sources::read_staged_blob(repo_path, oid)
            .map_err(|e| anyhow::anyhow!("guard commit: read blob {oid}: {e}"))?;
        if payload.len() > MAX_BLOB_BYTES {
            bail!(
                "guard commit: blob {} exceeds {} byte limit",
                oid,
                MAX_BLOB_BYTES
            );
        }
        total_bytes_streamed += payload.len() as u64;
        let chunk = keyhog_core::Chunk {
            data: String::from_utf8_lossy(&payload).into_owned().into(),
            metadata: keyhog_core::ChunkMetadata {
                source_type: "git-staged".into(),
                path: Some(oid.clone().into()),
                ..Default::default()
            },
        };
        let blob_request = Request::GuardCommitBlob {
            transaction_id,
            blob_oid: oid.clone(),
            object_size: payload.len() as u64,
            payload: vec![chunk],
        };
        let blob_response = conn.round_trip(&blob_request).await?;
        match blob_response {
            Response::GuardCommitBlobAck { .. } => {}
            Response::Error { message } => {
                bail!("guard commit: daemon rejected blob {oid}: {message}");
            }
            other => bail!(
                "guard commit: expected GuardCommitBlobAck for {oid}, got {}",
                protocol::response_kind(&other)
            ),
        }
    }

    // 5. Send GuardCommitFinish.
    let client_objects_streamed = required_blob_oids.len() as u64;
    let finish_request = Request::GuardCommitFinish {
        transaction_id,
        client_objects_streamed,
        client_bytes_streamed: total_bytes_streamed,
    };
    let finish_response = conn.round_trip(&finish_request).await?;

    let (receipt, terminal_state_label) = match finish_response {
        Response::GuardCommitReceipt {
            objects_requested,
            objects_hit,
            objects_scanned,
            objects_skipped,
            bytes_requested,
            bytes_hit,
            bytes_scanned,
            findings_count,
            coverage_gaps,
            terminal_state,
            ..
        } => {
            let label = terminal_state.clone();
            let r = GuardReceipt {
                objects_requested,
                objects_hit,
                objects_scanned,
                objects_skipped,
                bytes_requested,
                bytes_hit,
                bytes_scanned,
                findings_count,
                coverage_gaps,
                terminal_state: keyhog_core::guard_state::GuardRootState::Indexing,
                policy_identity: keyhog_core::guard_state::GuardPolicyIdentity {
                    build_identity: String::new(),
                    detector_digest: String::new(),
                    suppression_digest: String::new(),
                    keyhogignore_digest: String::new(),
                    config_digest: String::new(),
                    decode_policy_version: 0,
                    source_policy_digest: String::new(),
                    guard_schema_version: 0,
                    report_semantics_version: 0,
                },
                terminal_sequence: 0,
            };
            (r, label)
        }
        Response::Error { message } => {
            bail!("guard commit: daemon rejected finish: {message}");
        }
        other => bail!(
            "guard commit: expected GuardCommitReceipt, got {}",
            protocol::response_kind(&other)
        ),
    };

    // 6. Validate conservation: objects and bytes must add up.
    if let Err(e) = receipt.validate_conservation() {
        bail!("guard commit: conservation check failed: {e}");
    }

    // 7. Reacquire the staged manifest fingerprint. If the index
    //    changed during the transaction, the scanned content may not
    //    match what is now staged.
    let fingerprint_changed = !manifest.fingerprint_matches(repo_path);

    Ok(GuardCommitResult {
        findings_count: receipt.findings_count,
        coverage_gaps: receipt.coverage_gaps,
        terminal_state: terminal_state_label,
        fingerprint_changed,
        cache_hits: receipt.objects_hit,
        blobs_scanned: receipt.objects_scanned,
        bytes_scanned: receipt.bytes_scanned,
    })
}

/// Convert a `StagedManifestEntry` to a `GuardWireManifestEntry`.
fn manifest_entry_to_wire(entry: &StagedManifestEntry) -> GuardWireManifestEntry {
    let kind = match entry.kind {
        StagedEntryKind::File => "file",
        StagedEntryKind::Deletion => "deletion",
        StagedEntryKind::Symlink => "symlink",
        StagedEntryKind::Submodule => "submodule",
    };
    GuardWireManifestEntry {
        path: String::from_utf8_lossy(&entry.path_bytes).into_owned(),
        kind: kind.to_string(),
        object_oid: entry.object_oid.clone(),
        object_size: entry.object_size,
        raw_mode: entry.raw_mode,
    }
}
