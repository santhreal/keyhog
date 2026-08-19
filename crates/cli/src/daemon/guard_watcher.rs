//! Daemon-resident filesystem watcher for guard roots.
//!
//! This module manages native filesystem watchers for registered guard
//! roots. It uses the `notify` crate (inotify on Linux, FSEvents on
//! macOS, ReadDirectoryChangesW on Windows) to receive change events
//! without polling.
//!
//! The watcher is advisory: it provides early feedback while files
//! change. It never authorizes a commit by itself. A commit is allowed
//! only after the exact staged-object transaction proves the content
//! is clean.
//!
//! ## Subscribe-first
//!
//! The watcher is registered BEFORE the baseline walk starts, so events
//! that arrive during the walk are buffered and replayed after the walk
//! completes. This closes the race between watcher registration and
//! scanning existing bytes.

use keyhog_sources::guard::{EventBuffer, GuardEvent, GuardReconciliationConfig};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;

/// One watched root and its event buffer.
struct WatchedRoot {
    /// Bounded event buffer with monotonic sequence.
    buffer: Arc<Mutex<EventBuffer>>,
}

/// Manages filesystem watchers for all guard roots.
///
/// Detects channel disconnection and thread failure to enforce fail-closed
/// reconciliation across all registered roots when event monitoring is lost.
pub struct GuardWatcher {
    /// The native watcher handle. One watcher serves all roots.
    /// `None` when the platform watcher could not be created.
    watcher: Option<RecommendedWatcher>,
    /// Channel receiver for events from the native watcher.
    rx: mpsc::Receiver<notify::Result<notify::Event>>,
    /// Tracked roots: canonical path -> watched root state.
    roots: HashMap<PathBuf, WatchedRoot>,
    /// Reconciliation config (bounds for subtree reconciliation).
    config: GuardReconciliationConfig,
    /// Explicit flag indicating the watcher is running in disabled/unmonitored mode.
    disabled: bool,
    /// Named reason why the watcher disconnected, if disconnection occurred.
    disconnection_reason: parking_lot::Mutex<Option<String>>,
}

impl GuardWatcher {
    /// Create a new guard watcher with the given config.
    pub fn new(config: GuardReconciliationConfig) -> Result<Self, String> {
        let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
        let watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            let _ = tx.send(res);
        })
        .map_err(|e| format!("failed to create filesystem watcher: {}", e))?;
        Ok(Self {
            watcher: Some(watcher),
            rx,
            roots: HashMap::new(),
            config,
            disabled: false,
            disconnection_reason: parking_lot::Mutex::new(None),
        })
    }

    /// Create a disabled watcher that never produces events. Guard
    /// still works via commit transactions; it just loses advisory
    /// filesystem events.
    pub fn new_disabled() -> Self {
        let (_tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
        Self {
            watcher: None,
            rx,
            roots: HashMap::new(),
            config: GuardReconciliationConfig::default(),
            disabled: true,
            disconnection_reason: parking_lot::Mutex::new(None),
        }
    }

    /// Create a watcher backed by an explicit channel receiver for testing.
    #[doc(hidden)]
    pub fn with_channel_for_test(
        rx: mpsc::Receiver<notify::Result<notify::Event>>,
        config: GuardReconciliationConfig,
    ) -> Self {
        Self {
            watcher: None,
            rx,
            roots: HashMap::new(),
            config,
            disabled: false,
            disconnection_reason: parking_lot::Mutex::new(None),
        }
    }

    /// Returns the configured coalesce window in milliseconds.
    pub fn coalesce_window_ms(&self) -> u64 {
        self.config.coalesce_window_ms
    }

    /// Register a new root for watching. The watcher is started before
    /// the baseline walk so events during the walk are captured.
    pub fn add_root(&mut self, path: PathBuf) -> Result<(), String> {
        if self.roots.contains_key(&path) {
            return Err(format!("root already watched: {}", path.display()));
        }
        if self.is_disconnected() {
            return Err(format!(
                "failed to watch {}: watcher backend disconnected ({})",
                path.display(),
                self.disconnection_reason().unwrap_or_else(|| "channel closed".to_string())
            ));
        }
        if let Some(ref mut watcher) = self.watcher {
            watcher
                .watch(&path, RecursiveMode::Recursive)
                .map_err(|e| {
                    format!(
                        "failed to watch {}: {}; on Linux raise fs.inotify.max_user_watches",
                        path.display(),
                        e
                    )
                })?;
        }
        let buffer = Arc::new(Mutex::new(EventBuffer::new(
            self.config.max_pending_events_per_root,
        )));
        self.roots.insert(path, WatchedRoot { buffer });
        Ok(())
    }

    /// Remove a root from watching.
    pub fn remove_root(&mut self, path: &std::path::Path) {
        if self.roots.remove(path).is_some() {
            if let Some(ref mut watcher) = self.watcher {
                let _ = watcher.unwatch(path);
            }
        }
    }
    /// Poll for events from the native watcher. Returns normalized
    /// guard events grouped by root path. Non-blocking. Drains the
    /// per-root buffer as events are handed to the caller, so the
    /// buffer does not grow unbounded. If the buffer overflowed, a
    /// single `ReconcileSubtree` event is emitted for that root and
    /// the overflow flag is cleared.
    pub fn poll_events(&self) -> Vec<(PathBuf, Vec<GuardEvent>)> {
        let mut results: HashMap<PathBuf, Vec<GuardEvent>> = HashMap::new();
        if self.disabled {
            return Vec::new();
        }
        loop {
            match self.rx.try_recv() {
                Ok(Ok(event)) => {
                    if let Some(path) = event.paths.first() {
                        if let Some(root) = self.find_root_for_path(path) {
                            let guard_events = normalize_notify_event(&event);
                            if let Some(buffer) = self.roots.get(&root) {
                                let mut buf = buffer.buffer.lock();
                                for ge in &guard_events {
                                    buf.push(ge.clone());
                                }
                            }
                        }
                    }
                }
                Ok(Err(_)) => {
                    for root in self.roots.keys() {
                        results
                            .entry(root.clone())
                            .or_default()
                            .push(GuardEvent::ReconcileSubtree(root.clone()));
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    let reason = "watcher backend disconnected: notify event channel closed";
                    let newly_disconnected = {
                        let mut reason_guard = self.disconnection_reason.lock();
                        if reason_guard.is_none() {
                            *reason_guard = Some(reason.to_string());
                            true
                        } else {
                            false
                        }
                    };
                    if newly_disconnected {
                        tracing::warn!("daemon: guard watcher event channel disconnected; failing closed for all watched roots");
                    }
                    for root in self.roots.keys() {
                        results
                            .entry(root.clone())
                            .or_default()
                            .push(GuardEvent::ReconcileSubtree(root.clone()));
                    }
                    break;
                }
            }
        }
        // Drain each root's buffer and check for overflow. If overflowed,
        // emit a ReconcileSubtree event and reset the overflow flag so
        // the buffer can accept new events after reconciliation.
        for (root, watched) in &self.roots {
            let mut buf = watched.buffer.lock();
            if buf.overflowed() {
                results
                    .entry(root.clone())
                    .or_default()
                    .push(GuardEvent::ReconcileSubtree(root.clone()));
                buf.drain_and_reset();
            } else {
                let buffered: Vec<GuardEvent> = buf.drain().into_iter().map(|(_, ge)| ge).collect();
                if !buffered.is_empty() {
                    results.entry(root.clone()).or_default().extend(buffered);
                }
            }
        }
        results.into_iter().collect()
    }

    /// Find which registered root a path belongs to.
    fn find_root_for_path(&self, path: &std::path::Path) -> Option<PathBuf> {
        for root in self.roots.keys() {
            if path.starts_with(root) {
                return Some(root.clone());
            }
        }
        None
    }

    /// Number of watched roots.
    #[allow(dead_code)]
    pub fn root_count(&self) -> usize {
        self.roots.len()
    }

    #[allow(dead_code)]
    /// Whether any roots are watched.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Number of pending events in the buffer for a root.
    pub fn pending_event_count(&self, root: &std::path::Path) -> usize {
        self.roots
            .get(root)
            .map(|r| r.buffer.lock().len())
            .unwrap_or(0)
    }

    /// Whether the watcher is in disabled (unmonitored) mode.
    pub fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// Whether the watcher backend has disconnected.
    pub fn is_disconnected(&self) -> bool {
        self.disconnection_reason.lock().is_some()
    }

    /// Named reason why the watcher disconnected, if any.
    pub fn disconnection_reason(&self) -> Option<String> {
        self.disconnection_reason.lock().clone()
    }

    /// Record an explicit watcher disconnection reason.
    pub fn record_disconnection(&self, reason: &str) {
        let mut reason_guard = self.disconnection_reason.lock();
        if reason_guard.is_none() {
            *reason_guard = Some(reason.to_string());
        }
    }

    /// Status label for operator inspection.
    pub fn watcher_status(&self) -> &'static str {
        if self.is_disconnected() {
            "disconnected"
        } else if self.disabled {
            "unmonitored"
        } else {
            "watching"
        }
    }

    /// Whether the watcher is actively monitoring filesystem events.
    pub fn is_watching(&self) -> bool {
        !self.disabled && !self.is_disconnected() && self.watcher.is_some()
    }
}

/// Convert a notify::Event into normalized GuardEvent(s).
fn normalize_notify_event(event: &notify::Event) -> Vec<GuardEvent> {
    let path = event.paths.first().cloned().unwrap_or_default();
    match event.kind {
        EventKind::Create(_) => vec![GuardEvent::Create(path)],
        EventKind::Modify(_) => vec![GuardEvent::Modify(path)],
        EventKind::Remove(_) => vec![GuardEvent::Remove(path)],
        _ => {
            if !event.paths.is_empty() {
                vec![GuardEvent::Modify(path)]
            } else {
                Vec::new()
            }
        }
    }
}
#[cfg(test)]
#[path = "../../tests/unit/daemon_guard_watcher.rs"]
mod tests;
