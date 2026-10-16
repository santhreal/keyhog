//! Guard root policy hashing, filesystem watcher event processing, and periodic root scrubbing.

use std::path::Path;
use std::sync::Arc;
use sha2::Digest;
use super::{BaselineResult, ServerState};

/// Spawn a background task that polls the guard filesystem watcher and
/// processes events through the guard state machine. Events are
/// coalesced within a short window before applying transitions.
pub(super) fn spawn_guard_watcher_loop(state: Arc<ServerState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let coalesce_window =
            std::time::Duration::from_millis(state.guard_watcher.lock().coalesce_window_ms());
        // Periodic scrub (Row 132): tracks per-root scrub timing.
        // Unauthoritative roots default to 60s periodic scrub when no operator
        // scrub interval is configured.
        let mut last_scrub_times: std::collections::HashMap<Vec<u8>, std::time::Instant> =
            std::collections::HashMap::new();
        let mut last_scrub_tick = std::time::Instant::now();
        loop {
            tokio::select! {
                _ = state.shutdown.notified() => return,
                _ = tokio::time::sleep(coalesce_window) => {
                    let events = state.guard_watcher.lock().poll_events();
                    if let Some(reason) = state.guard_watcher.lock().disconnection_reason() {
                        if !state.guard.is_watcher_disconnected() {
                            state.guard.record_watcher_disconnection(&reason);
                            tracing::warn!(
                                "daemon: guard watcher backend disconnected ({}); failing closed and transitioning roots out of Current",
                                reason
                            );
                        }
                    }
                    for (root, evts) in events {
                        process_guard_events(&state, &root, evts);
                    }
                    // Sweep abandoned transactions each cycle.
                    state.guard.sweep_stale_transactions();

                    // Periodic scrub: check all Current roots against their
                    // configured or default unauthoritative scrub interval.
                    if last_scrub_tick.elapsed() >= std::time::Duration::from_secs(1) {
                        last_scrub_tick = std::time::Instant::now();
                        scrub_guard_roots(&state, &mut last_scrub_times);
                    }
                }
            }
        }
    })
}

/// Mark Current roots dirty for re-reconciliation when their scrub interval has elapsed (Row 132).
///
/// If an operator scrub interval is configured, roots are scrubbed on that schedule.
/// If no operator scrub interval is configured, unauthoritative roots (NFS, SMB/CIFS, FUSE, 9P)
/// are automatically scrubbed on a default 60-second schedule to detect changes that kernel
/// filesystem events missed.
pub(super) fn scrub_guard_roots(
    state: &ServerState,
    last_scrub_times: &mut std::collections::HashMap<Vec<u8>, std::time::Instant>,
) {
    use keyhog_core::guard_state::{GuardRootState, GuardTransition};
    let roots = state.guard.list_roots();
    let current_root_paths: std::collections::HashSet<_> =
        roots.iter().map(|r| r.canonical_path.clone()).collect();
    last_scrub_times.retain(|k, _| current_root_paths.contains(k));

    let mut scrubbed = 0;
    let now = std::time::Instant::now();
    let current_root_paths: std::collections::HashSet<_> =
        roots.iter().map(|r| r.canonical_path.clone()).collect();
    last_scrub_times.retain(|k, _| current_root_paths.contains(k));
    for record in roots {
        if record.state == GuardRootState::Current {
            let interval = if let Some(configured) = state.guard_scrub_interval {
                Some(configured)
            } else if !record.filesystem_authority.authoritative {
                Some(std::time::Duration::from_secs(
                    crate::daemon::fs_probe::DEFAULT_UNAUTHORITATIVE_SCRUB_INTERVAL_SECS,
                ))
            } else {
                None
            };

            if let Some(interval) = interval {
                let last_time = last_scrub_times.get(&record.canonical_path).copied();
                let should_scrub = match last_time {
                    Some(t) => now.duration_since(t) >= interval,
                    None => {
                        // Record baseline time on first observation in Current
                        last_scrub_times.insert(record.canonical_path.clone(), now);
                        false
                    }
                };

                if should_scrub {
                    let path_str = String::from_utf8_lossy(&record.canonical_path);
                    match state.guard.transition_root_with_cause(
                        &record.canonical_path,
                        &GuardTransition::EventAccepted,
                        "filesystem scrub: periodic change event on unauthoritative root",
                    ) {
                        Ok(_) => {
                            tracing::info!(
                                "daemon: scrub: mark root dirty for re-reconciliation: {}",
                                path_str
                            );
                            scrubbed += 1;
                            last_scrub_times.remove(&record.canonical_path);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "daemon: scrub: failed to transition root {} to dirty: {}",
                                path_str,
                                e
                            );
                        }
                    }
                }
            }
        } else {
            last_scrub_times.remove(&record.canonical_path);
        }
    }
    if scrubbed > 0 {
        tracing::info!(
            "daemon: scrub triggered reconciliation for {} root(s)",
            scrubbed
        );
    }
}

/// Process a batch of guard events for one root. Advisory filesystem
/// events mark the root dirty (EventAccepted) only when it is in a
/// state that accepts that transition (Current or Blocked). Overflow
/// (ReconcileSubtree) uses CoverageLost, which is legal from every
/// active post-baseline state. Events or overflow on roots still in
/// Indexing are recorded via flags so the baseline handler can choose
/// Dirty or Degraded after the scan completes — applying CoverageLost
/// mid-index would leave Indexing early and make the terminal
/// Reconciliation* transition illegal. Events on Dirty, Degraded,
/// StalePolicy, and Stopped roots are no-ops: those states already
/// account for unscanned changes.
/// Check if a given file path is a guard policy file (.keyhogignore, .keyhog.toml, suppressions).
pub fn is_policy_path(path: &Path) -> bool {
    let file_name = match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name,
        None => return false,
    };
    if file_name == ".keyhogignore"
        || file_name == ".keyhogignore.toml"
        || file_name == ".keyhog.toml"
        || file_name == "test-fixtures.toml"
        || file_name.ends_with(".suppressions.toml")
        || file_name.ends_with("_suppressions.toml")
        || file_name == "suppressions.toml"
    {
        return true;
    }
    for component in path.components() {
        if let std::path::Component::Normal(c) = component {
            let s = c.to_string_lossy();
            if s == "suppressions" || s == ".keyhog" {
                if let Some(ext) = path.extension() {
                    if ext == "toml" || ext == "json" {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Compute `.keyhogignore` / `.keyhogignore.toml` digest for a guard root.
pub fn compute_keyhogignore_digest(root: &Path) -> String {
    let legacy = root.join(".keyhogignore");
    let toml = root.join(".keyhogignore.toml");
    let legacy_bytes = std::fs::read(&legacy).ok(); // LAW10: absent legacy ignore file yields empty/absent digest; intended default
    let toml_bytes = std::fs::read(&toml).ok(); // LAW10: absent toml ignore file yields empty/absent digest; intended default
    if legacy_bytes.is_none() && toml_bytes.is_none() {
        return keyhog_core::guard_state::GuardPolicyIdentity::default_keyhogignore_digest();
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"keyhog-ignore-v1:");
    if let Some(bytes) = legacy_bytes {
        hasher.update(b"legacy:");
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    if let Some(bytes) = toml_bytes {
        hasher.update(b"toml:");
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    hex::encode(hasher.finalize().as_bytes())
}

/// Compute `.keyhog.toml` scan configuration digest for a guard root.
pub fn compute_config_digest(root: &Path) -> String {
    let root_config = root.join(".keyhog.toml");
    match std::fs::read(&root_config) {
        Ok(bytes) => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"keyhog-config-v1:");
            hasher.update(&bytes);
            hex::encode(hasher.finalize().as_bytes())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::orchestrator::autoroute_default_config_identity()
        }
        // A present but unreadable config yields a distinct identity, so the root
        // transitions to StalePolicy instead of passing as unchanged.
        Err(error) => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"keyhog-config-unreadable-v1:");
            hasher.update(format!("{:?}", error.kind()).as_bytes());
            hex::encode(hasher.finalize().as_bytes())
        }
    }
}

/// Compute suppression digest for a guard root, combining bundled test fixtures and root-local suppression files.
pub fn compute_suppression_digest(root: &Path) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"keyhog-suppressions-v1:bundled:");
    hasher.update(
        crate::test_fixture_suppressions::TestFixtureSuppressions::bundled_raw().as_bytes(),
    );
    for candidate in [
        ".keyhog/suppressions.toml",
        "suppressions.toml",
        "test-fixtures.toml",
    ] {
        let p = root.join(candidate);
        if let Ok(bytes) = std::fs::read(&p) {
            // LAW10: absent local suppression file has no runtime effect
            hasher.update(b":local:");
            hasher.update(candidate.as_bytes());
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(&bytes);
        }
    }
    hex::encode(hasher.finalize().as_bytes())
}

/// Compute source policy digest for a guard root.
pub fn compute_source_policy_digest(_root: &Path) -> String {
    keyhog_core::guard_state::GuardPolicyIdentity::default_source_policy_digest()
}

/// Compute the complete effective `GuardPolicyIdentity` for a guard root.
pub fn compute_root_policy_identity(
    root: &Path,
    build_identity: &str,
    detector_digest: &str,
) -> keyhog_core::guard_state::GuardPolicyIdentity {
    keyhog_core::guard_state::GuardPolicyIdentity {
        build_identity: build_identity.to_string(),
        detector_digest: detector_digest.to_string(),
        suppression_digest: compute_suppression_digest(root),
        keyhogignore_digest: compute_keyhogignore_digest(root),
        config_digest: compute_config_digest(root),
        decode_policy_version: keyhog_core::guard_state::GUARD_DECODE_POLICY_VERSION,
        source_policy_digest: compute_source_policy_digest(root),
        guard_schema_version: keyhog_core::guard_state::GUARD_SCHEMA_VERSION,
        report_semantics_version: keyhog_core::guard_state::GUARD_REPORT_SEMANTICS_VERSION,
    }
}

pub(super) fn process_guard_events(
    state: &ServerState,
    root: &Path,
    events: Vec<keyhog_sources::guard::GuardEvent>,
) {
    if events.is_empty() {
        return;
    }
    use keyhog_sources::guard::GuardEvent;

    let root_bytes = std::os::unix::ffi::OsStrExt::as_bytes(root.as_os_str());
    let has_overflow = events
        .iter()
        .any(|e| matches!(e, GuardEvent::ReconcileSubtree(_)));
    let is_potential_policy_change = events.iter().any(|e| match e {
        GuardEvent::Create(p)
        | GuardEvent::Modify(p)
        | GuardEvent::Remove(p)
        | GuardEvent::ReconcileSubtree(p) => is_policy_path(p),
        GuardEvent::Rename { from, to } => is_policy_path(from) || is_policy_path(to),
        GuardEvent::Barrier(_) => false,
    });
    let current_state = state.guard.root_state(root_bytes);

    let has_policy_change = if is_potential_policy_change {
        let new_identity =
            compute_root_policy_identity(root, KEYHOG_VERSION, &state.detector_rules_digest);
        let existing = state.guard.get_root_policy_identity(root_bytes);
        let changed = match &existing {
            Some(existing) => !existing.is_compatible_with(&new_identity),
            None => true,
        };
        state
            .guard
            .set_root_policy_identity(root_bytes, new_identity);
        changed
    } else {
        false
    };

    match guard_event_action_with_policy(current_state, has_overflow, has_policy_change) {
        GuardEventAction::Ignore => {}
        GuardEventAction::MarkDuringIndexing { coverage_lost } => {
            state.guard.mark_dirty_during_indexing(root_bytes);
            if coverage_lost {
                state.guard.mark_coverage_lost_during_indexing(root_bytes);
            }
        }
        GuardEventAction::Transition(transition) => {
            let cause = if has_overflow {
                "watcher overflow: event buffer overflowed or channel disconnected".to_string()
            } else if has_policy_change {
                "policy change: configuration or suppression rules modified".to_string()
            } else {
                format!(
                    "filesystem watcher: {} change events accepted",
                    events.len()
                )
            };
            match state
                .guard
                .transition_root_with_cause(root_bytes, &transition, cause)
            {
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        "daemon: guard transition failed for {}: {}",
                        root.display(),
                        e
                    );
                }
            }
        }
    }
}

/// Action to take on a guard event depending on root state, overflow, and policy change condition.
#[derive(Debug, PartialEq, Eq)]
pub enum GuardEventAction {
    /// Ignore event for stopped or unmonitored root.
    Ignore,
    /// Mark coverage or dirtiness during active baseline indexing.
    MarkDuringIndexing { coverage_lost: bool },
    /// Apply a state transition immediately to the root.
    Transition(keyhog_core::guard_state::GuardTransition),
}

/// Determine the appropriate action for a guard event given the current root state, overflow, and policy change conditions.
pub fn guard_event_action_with_policy(
    current_state: Option<keyhog_core::guard_state::GuardRootState>,
    has_overflow: bool,
    has_policy_change: bool,
) -> GuardEventAction {
    use keyhog_core::guard_state::{GuardRootState, GuardTransition};
    if has_overflow {
        match current_state {
            Some(GuardRootState::Stopped) | None => GuardEventAction::Ignore,
            Some(GuardRootState::Indexing) => GuardEventAction::MarkDuringIndexing {
                coverage_lost: true,
            },
            // A stale-policy root is already in the repair state reconciliation
            // clears, so an overflow adds nothing. A degraded root is not: the
            // state machine keeps `(Degraded, CoverageLost)` legal precisely so
            // repeat coverage loss stays counted and operator-visible.
            Some(GuardRootState::StalePolicy) => GuardEventAction::Ignore,
            _ => GuardEventAction::Transition(GuardTransition::CoverageLost),
        }
    } else if has_policy_change {
        match current_state {
            Some(GuardRootState::Stopped) | None => GuardEventAction::Ignore,
            Some(GuardRootState::Indexing) => GuardEventAction::MarkDuringIndexing {
                coverage_lost: false,
            },
            Some(GuardRootState::Degraded) => GuardEventAction::Ignore,
            Some(GuardRootState::StalePolicy) => GuardEventAction::Ignore,
            _ => GuardEventAction::Transition(GuardTransition::PolicyChanged),
        }
    } else {
        match current_state {
            Some(GuardRootState::Current) | Some(GuardRootState::Blocked) => {
                GuardEventAction::Transition(GuardTransition::EventAccepted)
            }
            Some(GuardRootState::Indexing) => GuardEventAction::MarkDuringIndexing {
                coverage_lost: false,
            },
            _ => GuardEventAction::Ignore,
        }
    }
}

/// Determine the appropriate action for a guard event given the current root state.
pub fn guard_event_action(
    current_state: Option<keyhog_core::guard_state::GuardRootState>,
    has_overflow: bool,
) -> GuardEventAction {
    guard_event_action_with_policy(current_state, has_overflow, false)
}
pub(super) fn guard_attestation_identity(
    base: &keyhog_core::guard_state::GuardPolicyIdentity,
    source_paths: &[String],
) -> keyhog_core::guard_state::GuardPolicyIdentity {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"keyhog-guard-source-paths-v1");
    for path in source_paths {
        hasher.update(&(path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
    }
    let mut identity = base.clone();
    identity.source_policy_digest = format!(
        "{}:staged-paths:{}",
        base.source_policy_digest,
        hex::encode(hasher.finalize().as_bytes())
    );
    identity
}

pub(super) fn guard_commit_terminal_state(
    blocking_findings_count: u64,
    coverage_gaps: u64,
) -> keyhog_core::guard_state::GuardRootState {
    use keyhog_core::guard_state::GuardRootState;
    if blocking_findings_count > 0 {
        GuardRootState::Blocked
    } else if coverage_gaps > 0 {
        GuardRootState::Degraded
    } else {
        GuardRootState::Current
    }
}

pub(super) fn baseline_terminal_transition(
    scan_result: BaselineResult,
    coverage_lost_during_indexing: bool,
) -> keyhog_core::guard_state::GuardTransition {
    use keyhog_core::guard_state::GuardTransition;
    match scan_result {
        BaselineResult::Findings => GuardTransition::ReconciliationFindings,
        BaselineResult::Degraded => GuardTransition::ReconciliationDegraded,
        BaselineResult::Clean if coverage_lost_during_indexing => {
            GuardTransition::ReconciliationDegraded
        }
        BaselineResult::Clean => GuardTransition::ReconciliationClean,
    }
}

