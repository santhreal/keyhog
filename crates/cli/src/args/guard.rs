use std::path::PathBuf;

use clap::Parser;

/// Subcommand args for `keyhog guard {add, remove, list, status, reconcile}`.
#[derive(Parser)]
pub struct GuardArgs {
    #[command(subcommand)]
    pub action: GuardAction,
}

#[derive(clap::Subcommand)]
pub enum GuardAction {
    /// Register a repository or filesystem root for continuous guard
    /// protection. Waits for initial reconciliation to complete before
    /// returning.
    Add {
        /// Root path to guard.
        root: PathBuf,
        /// Guard mode: `repo` uses Git object IDs for exact staged-content
        /// identity; `filesystem` uses content hashes without immutable Git
        /// OIDs.
        #[arg(long, value_name = "MODE", default_value = "repo")]
        mode: String,
    },
    /// Stop protecting a root and remove its persisted non-secret state.
    Remove {
        /// Root path to unguard.
        root: PathBuf,
    },
    /// List all registered guard roots and their current states.
    List,
    /// Print the exact state and current policy identity of a guarded root.
    Status {
        /// Root path to inspect.
        root: PathBuf,
        /// Output format: `human` or `json`.
        #[arg(long, value_name = "FORMAT", default_value = "human")]
        format: String,
    },
    /// Force a full reconciliation of a guarded root after an intentional
    /// policy or filesystem change.
    Reconcile {
        /// Root path to reconcile.
        root: PathBuf,
    },
}
