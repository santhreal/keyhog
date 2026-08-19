use std::path::PathBuf;

use clap::Parser;

/// Subcommand args for `keyhog guard {add, remove, up, down, list, status, reconcile, rebuild, feed}`.
#[derive(Parser)]
pub struct GuardArgs {
    #[command(subcommand)]
    pub action: GuardAction,
}

#[derive(clap::Subcommand)]
pub enum GuardAction {
    /// Register a repository or filesystem root for continuous guard
    /// protection. Waits for initial reconciliation to complete before
    /// returning. When guarding a Git repository in `repo` mode, also
    /// attempts to install the managed pre-commit hook (skipped if a foreign
    /// hook already exists, or if `--no-hook` is passed).
    Add {
        /// Root path to guard.
        root: PathBuf,
        /// Guard mode: `repo` uses Git object IDs for exact staged-content
        /// identity; `filesystem` uses content hashes without immutable Git
        /// OIDs.
        #[arg(long, value_name = "MODE", default_value = "repo")]
        mode: String,
        /// Do not install or update the Git pre-commit hook during registration.
        #[arg(long)]
        no_hook: bool,
        /// Override the socket path.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Stop protecting a root and remove its persisted non-secret state.
    /// Also removes any KeyHog-owned Git pre-commit hook unless `--keep-hook`
    /// is passed.
    Remove {
        /// Root path to unguard.
        root: PathBuf,
        /// Keep the Git pre-commit hook in place when unregistering.
        #[arg(long)]
        keep_hook: bool,
        /// Override the socket path.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Start or ensure the background guard daemon is running and ready.
    /// When the daemon is already running, reports that it is active.
    /// Reconciles registered roots loaded from the durable store.
    Up {
        /// Force a specific scan backend (default `auto` uses autoroute).
        #[arg(long, value_name = "BACKEND")]
        backend: Option<String>,
        /// Override the socket path.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Stop the background guard daemon cleanly. Persisted root registrations
    /// and durable indexes remain on disk and resume on the next `guard up`.
    Down {
        /// Override the socket path.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// List all registered guard roots and their current states.
    List {
        /// Override the socket path.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Print the exact state and current policy identity of a guarded root.
    /// When no root is specified, summarizes all registered roots.
    Status {
        /// Root path to inspect (summarizes all registered roots when omitted).
        root: Option<PathBuf>,
        /// Output format: `human` or `json`.
        #[arg(long, value_name = "FORMAT", default_value = "human")]
        format: String,
        /// Override the socket path.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Force a full reconciliation of a guarded root after an intentional
    /// policy or filesystem change.
    Reconcile {
        /// Root path to reconcile.
        root: PathBuf,
        /// Override the socket path.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Delete and recreate the durable guard store for a root. Use after
    /// store corruption or when the persisted state is irrecoverably stale.
    /// The root is re-registered and a full reconciliation is triggered.
    Rebuild {
        /// Root path to rebuild.
        root: PathBuf,
        /// Guard mode: `repo` or `filesystem`. Defaults to `repo`.
        #[arg(long, value_name = "MODE", default_value = "repo")]
        mode: String,
        /// Override the socket path.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Expose continuous transition feed and event log with causes across guarded roots.
    #[command(alias = "events", alias = "log", alias = "transitions")]
    Feed {
        /// Filter feed to a specific root path.
        #[arg(long, value_name = "ROOT")]
        root: Option<PathBuf>,
        /// Maximum number of recent transitions to display (default 50).
        #[arg(long, value_name = "LIMIT", default_value = "50")]
        limit: usize,
        /// Output format: `human` or `json`.
        #[arg(long, value_name = "FORMAT", default_value = "human")]
        format: String,
        /// Override the socket path.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
}
