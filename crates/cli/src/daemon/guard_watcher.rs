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
        }
    }

    /// Create a guard watcher connected to a custom event channel.
    /// Used for deterministic simulation and tests without native watcher hooks.
    pub fn new_with_channel(
        config: GuardReconciliationConfig,
    ) -> (Self, mpsc::Sender<notify::Result<notify::Event>>) {
        let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
        (
            Self {
                watcher: None,
                rx,
                roots: HashMap::new(),
                config,
            },
            tx,
        )
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
        if let Some(watcher) = &mut self.watcher {
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
            if let Some(watcher) = &mut self.watcher {
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
        loop {
            match self.rx.try_recv() {
                Ok(Ok(event)) => {
                    if event.paths.is_empty() {
                        // Empty paths vector indicates fidelity loss or unresolvable
                        // bulk event: trigger subtree reconciliation across all roots.
                        for root in self.roots.keys() {
                            results
                                .entry(root.clone())
                                .or_default()
                                .push(GuardEvent::ReconcileSubtree(root.clone()));
                        }
                    } else {
                        // Process and attribute ALL paths present on the event to ALL matching
                        // enclosing roots so nested and parent roots both receive events.
                        for path in &event.paths {
                            let roots = self.find_matching_roots_for_path(path);
                            for root in roots {
                                let guard_event =
                                    normalize_notify_path_event(&event.kind, path);
                                if let Some(buffer) = self.roots.get(&root) {
                                    let mut buf = buffer.buffer.lock();
                                    buf.push(guard_event);
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
                Err(mpsc::TryRecvError::Disconnected) => break,
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
                let buffered: Vec<GuardEvent> =
                    buf.drain().into_iter().map(|(_, ge)| ge).collect();
                if !buffered.is_empty() {
                    results.entry(root.clone()).or_default().extend(buffered);
                }
            }
        }
        results.into_iter().collect()
    }

    /// Find all registered roots that are prefixes of a path.
    /// When roots are nested, returns all enclosing roots so parent roots
    /// receive events for changes inside sub-roots.
    fn find_matching_roots_for_path(&self, path: &std::path::Path) -> Vec<PathBuf> {
        let mut matched = Vec::new();
        for root in self.roots.keys() {
            if path.starts_with(root) {
                matched.push(root.clone());
            }
        }
        matched
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
}

/// Convert a notify::Event for a specific path into a normalized GuardEvent.
fn normalize_notify_path_event(kind: &EventKind, path: &std::path::Path) -> GuardEvent {
    match kind {
        EventKind::Create(_) => GuardEvent::Create(path.to_path_buf()),
        EventKind::Modify(_) => GuardEvent::Modify(path.to_path_buf()),
        EventKind::Remove(_) => GuardEvent::Remove(path.to_path_buf()),
        _ => GuardEvent::Modify(path.to_path_buf()),
    }
}

/// Convert a notify::Event into normalized GuardEvent(s).
pub fn normalize_notify_event(event: &notify::Event) -> Vec<GuardEvent> {
    if event.paths.is_empty() {
        let path = PathBuf::default();
        return match event.kind {
            EventKind::Create(_) => vec![GuardEvent::Create(path)],
            EventKind::Modify(_) => vec![GuardEvent::Modify(path)],
            EventKind::Remove(_) => vec![GuardEvent::Remove(path)],
            _ => vec![GuardEvent::Modify(path)],
        };
    }
    event
        .paths
        .iter()
        .map(|path| normalize_notify_path_event(&event.kind, path))
        .collect()
}
#[cfg(test)]
#[path = "../../tests/unit/daemon_guard_watcher.rs"]
mod tests;
