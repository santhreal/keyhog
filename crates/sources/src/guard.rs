//! Guard event normalization and subscribe-first reconciliation protocol.
//!
//! This module owns the normalized event types and the subscribe-first
//! reconciliation protocol shared between the foreground watch mode and the
//! background guard daemon. It does not own scanner execution or daemon
//! scheduling.
//!
//! ## Subscribe-first reconciliation
//!
//! The initial walk must close the race between registering a watcher and
//! scanning existing bytes:
//!
//! 1. Canonicalize and validate the root without following symlinks.
//! 2. Register the native watcher before starting the baseline walk.
//! 3. Start a bounded in-memory event buffer with a monotonically increasing
//!    sequence.
//! 4. Walk and scan the current tree through the existing filesystem source
//!    policy.
//! 5. Replay every buffered event in sequence.
//! 6. If the native backend reports overflow or the buffer reaches its hard
//!    cap, mark the root degraded and restart one bounded reconciliation.
//! 7. Persist the terminal sequence and root receipt atomically.
//! 8. Announce `current` or `blocked` only after persistence succeeds.

use std::path::PathBuf;

/// Normalized filesystem event for the guard event queue.
///
/// Coalescing reduces repeated path events while preserving the strongest
/// required work. `Remove + Create` becomes replacement, not a no-op.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GuardEvent {
    /// A new file or directory appeared.
    Create(PathBuf),
    /// An existing file's content changed.
    Modify(PathBuf),
    /// A file or directory was removed.
    Remove(PathBuf),
    /// A file or directory was renamed.
    Rename {
        /// Source path.
        from: PathBuf,
        /// Destination path.
        to: PathBuf,
    },
    /// A directory appeared that needs subtree reconciliation (its existing
    /// children were not observed as individual events).
    ReconcileSubtree(PathBuf),
    /// A sequence barrier: all events up to this sequence must be processed
    /// before proceeding past this point.
    Barrier(u64),
}

impl GuardEvent {
    /// The path this event concerns, if any. `Rename` returns the
    /// destination; `Barrier` returns `None`.
    pub fn primary_path(&self) -> Option<&std::path::Path> {
        match self {
            GuardEvent::Create(p) | GuardEvent::Modify(p) | GuardEvent::Remove(p) => Some(p),
            GuardEvent::Rename { to, .. } | GuardEvent::ReconcileSubtree(to) => Some(to),
            GuardEvent::Barrier(_) => None,
        }
    }

    /// Whether this event requires scanning (as opposed to just bookkeeping).
    pub fn requires_scan(&self) -> bool {
        matches!(
            self,
            GuardEvent::Create(_)
                | GuardEvent::Modify(_)
                | GuardEvent::ReconcileSubtree(_)
                | GuardEvent::Rename { .. }
        )
    }

    /// Stable kind label for status output.
    pub fn kind_label(&self) -> &'static str {
        match self {
            GuardEvent::Create(_) => "create",
            GuardEvent::Modify(_) => "modify",
            GuardEvent::Remove(_) => "remove",
            GuardEvent::Rename { .. } => "rename",
            GuardEvent::ReconcileSubtree(_) => "reconcile-subtree",
            GuardEvent::Barrier(_) => "barrier",
        }
    }
}

/// Coalesce two events for the same path into the strongest required work.
///
/// `Remove + Create` becomes `Create` (replacement, not a no-op).
/// `Create + Modify` becomes `Create` (the create already implies a scan).
/// `Modify + Modify` stays `Modify`.
/// `Remove + Remove` stays `Remove`.
pub fn coalesce_events(existing: &GuardEvent, incoming: &GuardEvent) -> GuardEvent {
    use GuardEvent::*;
    match (existing, incoming) {
        // Remove then Create = replacement (scan the new content).
        (Remove(_), Create(p)) => Create(p.clone()),
        // Create then Modify = still a create (scan covers the modify).
        (Create(_), Modify(_)) => existing.clone(),
        // Any + Remove = remove wins (file is gone).
        (_, Remove(p)) => Remove(p.clone()),
        // Remove then Modify = create (file came back with new content).
        (Remove(_), Modify(p)) => Create(p.clone()),
        // Modify + Modify = modify.
        (Modify(_), Modify(_)) => incoming.clone(),
        // Default: incoming wins.
        _ => incoming.clone(),
    }
}

/// Configuration for the guard event queue and reconciliation.
#[derive(Debug, Clone)]
pub struct GuardReconciliationConfig {
    /// Maximum queued events per root.
    pub max_pending_events_per_root: usize,
    /// Coalescing window in milliseconds.
    pub coalesce_window_ms: u64,
    /// Maximum files for one subtree reconciliation.
    pub subtree_max_files: usize,
    /// Maximum depth for one subtree reconciliation.
    pub subtree_max_depth: usize,
}

impl Default for GuardReconciliationConfig {
    fn default() -> Self {
        Self {
            max_pending_events_per_root: 8192,
            coalesce_window_ms: 100,
            subtree_max_files: 10_000,
            subtree_max_depth: 64,
        }
    }
}

/// Result of a subscribe-first reconciliation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationResult {
    /// Reconciliation completed with no findings.
    Clean {
        /// Terminal event sequence after replay.
        terminal_sequence: u64,
    },
    /// Reconciliation completed with unsuppressed findings.
    Findings {
        /// Terminal event sequence after replay.
        terminal_sequence: u64,
        /// Number of findings (without secret values).
        findings_count: u64,
    },
    /// Reconciliation completed but coverage is incomplete.
    Degraded {
        /// Terminal event sequence after replay.
        terminal_sequence: u64,
        /// Human-readable degradation reason.
        reason: String,
    },
    /// Native watcher reported overflow during reconciliation.
    Overflow {
        /// Human-readable overflow detail.
        detail: String,
    },
}

/// Bounded event buffer with a monotonically increasing sequence.
///
/// Each root has one buffer. Overflow immediately marks the root degraded.
/// Dropping the oldest event and continuing is prohibited.
#[derive(Debug)]
pub struct EventBuffer {
    events: Vec<(u64, GuardEvent)>,
    next_sequence: u64,
    cap: usize,
    overflowed: bool,
}

impl EventBuffer {
    /// Create a new buffer with the given capacity.
    pub fn new(cap: usize) -> Self {
        Self {
            events: Vec::with_capacity(cap.min(1024)),
            next_sequence: 1,
            cap,
            overflowed: false,
        }
    }

    /// Push an event, returning its assigned sequence number.
    /// Returns `None` if the buffer has overflowed.
    pub fn push(&mut self, event: GuardEvent) -> Option<u64> {
        if self.overflowed {
            return None;
        }
        if self.events.len() >= self.cap {
            self.overflowed = true;
            return None;
        }
        let seq = self.next_sequence;
        self.next_sequence += 1;
        self.events.push((seq, event));
        Some(seq)
    }

    /// Mark the buffer as overflowed (e.g. from native watcher overflow).
    pub fn mark_overflow(&mut self) {
        self.overflowed = true;
    }

    /// Whether the buffer has overflowed.
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Current number of buffered events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Drain all buffered events in sequence order.
    pub fn drain(&mut self) -> Vec<(u64, GuardEvent)> {
        std::mem::take(&mut self.events)
    }

    /// The next sequence number that will be assigned.
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Capacity of the buffer.
    pub fn cap(&self) -> usize {
        self.cap
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn coalesce_remove_then_create_is_replacement() {
        let existing = GuardEvent::Remove(PathBuf::from("/a"));
        let incoming = GuardEvent::Create(PathBuf::from("/a"));
        let result = coalesce_events(&existing, &incoming);
        assert!(matches!(result, GuardEvent::Create(_)));
    }

    #[test]
    fn coalesce_create_then_modify_is_create() {
        let existing = GuardEvent::Create(PathBuf::from("/a"));
        let incoming = GuardEvent::Modify(PathBuf::from("/a"));
        let result = coalesce_events(&existing, &incoming);
        assert!(matches!(result, GuardEvent::Create(_)));
    }

    #[test]
    fn coalesce_any_then_remove_is_remove() {
        let existing = GuardEvent::Create(PathBuf::from("/a"));
        let incoming = GuardEvent::Remove(PathBuf::from("/a"));
        let result = coalesce_events(&existing, &incoming);
        assert!(matches!(result, GuardEvent::Remove(_)));
    }

    #[test]
    fn coalesce_modify_then_modify_is_modify() {
        let existing = GuardEvent::Modify(PathBuf::from("/a"));
        let incoming = GuardEvent::Modify(PathBuf::from("/a"));
        let result = coalesce_events(&existing, &incoming);
        assert!(matches!(result, GuardEvent::Modify(_)));
    }

    #[test]
    fn coalesce_remove_then_modify_is_create() {
        let existing = GuardEvent::Remove(PathBuf::from("/a"));
        let incoming = GuardEvent::Modify(PathBuf::from("/a"));
        let result = coalesce_events(&existing, &incoming);
        assert!(matches!(result, GuardEvent::Create(_)));
    }

    #[test]
    fn event_buffer_push_assigns_sequence() {
        let mut buf = EventBuffer::new(10);
        let seq1 = buf.push(GuardEvent::Create(PathBuf::from("/a"))).unwrap();
        let seq2 = buf.push(GuardEvent::Modify(PathBuf::from("/b"))).unwrap();
        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.next_sequence(), 3);
    }

    #[test]
    fn event_buffer_overflow_returns_none() {
        let mut buf = EventBuffer::new(2);
        buf.push(GuardEvent::Create(PathBuf::from("/a"))).unwrap();
        buf.push(GuardEvent::Create(PathBuf::from("/b"))).unwrap();
        let result = buf.push(GuardEvent::Create(PathBuf::from("/c")));
        assert!(result.is_none());
        assert!(buf.overflowed());
    }

    #[test]
    fn event_buffer_mark_overflow() {
        let mut buf = EventBuffer::new(10);
        buf.mark_overflow();
        assert!(buf.overflowed());
        let result = buf.push(GuardEvent::Create(PathBuf::from("/a")));
        assert!(result.is_none());
    }

    #[test]
    fn event_buffer_drain_empties_and_preserves_order() {
        let mut buf = EventBuffer::new(10);
        buf.push(GuardEvent::Create(PathBuf::from("/a"))).unwrap();
        buf.push(GuardEvent::Modify(PathBuf::from("/b"))).unwrap();
        buf.push(GuardEvent::Remove(PathBuf::from("/c"))).unwrap();

        let drained = buf.drain();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].0, 1);
        assert_eq!(drained[1].0, 2);
        assert_eq!(drained[2].0, 3);
        assert!(buf.is_empty());
    }

    #[test]
    fn event_requires_scan_classification() {
        assert!(GuardEvent::Create(PathBuf::from("/a")).requires_scan());
        assert!(GuardEvent::Modify(PathBuf::from("/a")).requires_scan());
        assert!(!GuardEvent::Remove(PathBuf::from("/a")).requires_scan());
        assert!(GuardEvent::ReconcileSubtree(PathBuf::from("/a")).requires_scan());
        assert!(
            GuardEvent::Rename {
                from: PathBuf::from("/a"),
                to: PathBuf::from("/b")
            }
            .requires_scan()
        );
        assert!(!GuardEvent::Barrier(42).requires_scan());
    }

    #[test]
    fn event_kind_labels() {
        assert_eq!(GuardEvent::Create(PathBuf::from("/a")).kind_label(), "create");
        assert_eq!(GuardEvent::Modify(PathBuf::from("/a")).kind_label(), "modify");
        assert_eq!(GuardEvent::Remove(PathBuf::from("/a")).kind_label(), "remove");
        assert_eq!(
            GuardEvent::Rename {
                from: PathBuf::from("/a"),
                to: PathBuf::from("/b")
            }
            .kind_label(),
            "rename"
        );
        assert_eq!(
            GuardEvent::ReconcileSubtree(PathBuf::from("/a")).kind_label(),
            "reconcile-subtree"
        );
        assert_eq!(GuardEvent::Barrier(42).kind_label(), "barrier");
    }

    #[test]
    fn event_primary_path() {
        assert_eq!(
            GuardEvent::Create(PathBuf::from("/a")).primary_path(),
            Some(Path::new("/a"))
        );
        assert_eq!(
            GuardEvent::Rename {
                from: PathBuf::from("/a"),
                to: PathBuf::from("/b")
            }
            .primary_path(),
            Some(Path::new("/b"))
        );
        assert_eq!(GuardEvent::Barrier(42).primary_path(), None);
    }

    #[test]
    fn reconciliation_config_defaults() {
        let config = GuardReconciliationConfig::default();
        assert_eq!(config.max_pending_events_per_root, 8192);
        assert_eq!(config.coalesce_window_ms, 100);
        assert_eq!(config.subtree_max_files, 10_000);
        assert_eq!(config.subtree_max_depth, 64);
    }
}
