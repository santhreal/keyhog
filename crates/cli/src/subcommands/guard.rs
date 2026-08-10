//! `keyhog guard {add, remove, list, status, reconcile}` subcommand.
//!
//! Connects to the daemon and sends guard control frames. When no daemon
//! is available, reports that clearly instead of silently doing nothing.

use crate::args::{GuardAction, GuardArgs};
use crate::daemon::client;
use crate::daemon::protocol::{Request, Response, response_kind};
use crate::exit_codes;
use crate::style;
use std::process::ExitCode;

use crate::daemon::server::default_socket_path;

pub(crate) async fn run(args: GuardArgs) -> anyhow::Result<ExitCode> {
    match args.action {
        GuardAction::Add { root, mode } => run_add(root, mode).await,
        GuardAction::Remove { root } => run_remove(root).await,
        GuardAction::List => run_list().await,
        GuardAction::Status { root, format } => run_status(root, format).await,
        GuardAction::Reconcile { root } => run_reconcile(root).await,
    }
}

async fn run_add(root: std::path::PathBuf, mode: String) -> anyhow::Result<ExitCode> {
    let socket = default_socket_path();
    let mut conn = match client::connect(&socket).await {
        Ok(conn) => conn,
        Err(error) => {
            anyhow::bail!(
                "guard add: no compatible daemon at {} (start one with `keyhog daemon start`): {error}",
                socket.display()
            );
        }
    };

    let canonical = canonicalize_root(&root)?;
    let request = Request::GuardAdd {
        root: canonical,
        mode,
    };
    let canonical_for_reconcile = match conn.round_trip(&request).await? {
        Response::GuardAdded {
            root: ref added_root,
            state: ref add_state,
            terminal_sequence,
        } => {
            let palette = style::for_stderr();
            eprintln!(
                "{} guard: root {} registered (state {}, sequence {})",
                style::pass("OK", &palette),
                root.display(),
                add_state,
                terminal_sequence
            );
            added_root.clone()
        }
        Response::Error { message } => {
            anyhow::bail!("{message}");
        }
        other => {
            anyhow::bail!(
                "guard add: protocol mismatch (got {})",
                response_kind(&other)
            );
        }
    };
    // Trigger baseline reconciliation so the root reaches a terminal
    // state. The help text promises this waits for the initial check.
    let reconcile_request = Request::GuardReconcile {
        root: canonical_for_reconcile.clone(),
    };
    match conn.round_trip(&reconcile_request).await? {
        Response::GuardReconcileStarted { root: _ } => {
            // Reconciliation completed. Query the final state.
            let status_request = Request::GuardStatus {
                root: canonical_for_reconcile,
            };
            match conn.round_trip(&status_request).await? {
                Response::GuardStatusResult { state, findings_count, .. } => {
                    let palette = style::for_stderr();
                    eprintln!(
                        "{} guard: reconciliation complete, root is {}",
                        style::pass("OK", &palette),
                        state
                    );
                    if matches!(
                        state.as_str(),
                        "stopped" | "indexing" | "degraded" | "stale-policy"
                    ) {
                        Ok(ExitCode::from(exit_codes::EXIT_SOURCE_FAILED))
                    } else if state == "blocked" || findings_count > 0 {
                        Ok(ExitCode::from(exit_codes::EXIT_FINDINGS))
                    } else {
                        Ok(ExitCode::SUCCESS)
                    }
                }
                Response::Error { message } => {
                    anyhow::bail!("guard add: status after reconcile: {message}");
                }
                other => {
                    anyhow::bail!(
                        "guard add: status protocol mismatch (got {})",
                        response_kind(&other)
                    );
                }
            }
        }
        Response::Error { message } => {
            anyhow::bail!("guard add: reconcile failed: {message}");
        }
        other => {
            anyhow::bail!(
                "guard add: reconcile protocol mismatch (got {})",
                response_kind(&other)
            );
        }
    }
}

async fn run_remove(root: std::path::PathBuf) -> anyhow::Result<ExitCode> {
    let socket = default_socket_path();
    let mut conn = match client::connect(&socket).await {
        Ok(conn) => conn,
        Err(error) => {
            anyhow::bail!(
                "guard remove: no compatible daemon at {} (start one with `keyhog daemon start`): {error}",
                socket.display()
            );
        }
    };

    let canonical = canonicalize_root(&root)?;
    let request = Request::GuardRemove {
        root: canonical,
    };
    match conn.round_trip(&request).await? {
        Response::GuardRemoved => {
            let palette = style::for_stderr();
            eprintln!(
                "{} guard: removed {}",
                style::pass("OK", &palette),
                root.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        Response::Error { message } => {
            anyhow::bail!("{message}");
        }
        other => {
            anyhow::bail!(
                "guard remove: protocol mismatch (got {})",
                response_kind(&other)
            );
        }
    }
}

async fn run_list() -> anyhow::Result<ExitCode> {
    let socket = default_socket_path();
    let mut conn = match client::connect(&socket).await {
        Ok(c) => c,
        Err(e) => {
            anyhow::bail!(
                "guard list: no compatible daemon at {} (start one with `keyhog daemon start`): {e}",
                socket.display()
            );
        }
    };

    let request = Request::GuardList;
    match conn.round_trip(&request).await? {
        Response::GuardListResult { roots } => {
            if roots.is_empty() {
                let palette = style::for_stderr();
                eprintln!(
                    "{} no guard roots registered",
                    style::pass("OK", &palette)
                );
            } else {
                let palette = style::for_stderr();
                eprintln!(
                    "{} {} guard root{} registered",
                    style::pass("OK", &palette),
                    roots.len(),
                    if roots.len() == 1 { "" } else { "s" }
                );
                for entry in &roots {
                    eprintln!(
                        "  {}  {}  seq={}",
                        entry.root,
                        entry.state,
                        entry.terminal_sequence
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Response::Error { message } => {
            let palette = style::for_stderr();
            eprintln!(
                "{} guard list: {}",
                style::warn("WARN", &palette),
                message
            );
            Ok(ExitCode::from(exit_codes::EXIT_SOURCE_FAILED))
        }
        other => {
            let palette = style::for_stderr();
            eprintln!(
                "{} guard list: unexpected daemon response: {}",
                style::warn("WARN", &palette),
                response_kind(&other)
            );
            Ok(ExitCode::from(exit_codes::EXIT_SOURCE_FAILED))
        }
    }
}

async fn run_status(
    root: std::path::PathBuf,
    format: String,
) -> anyhow::Result<ExitCode> {
    let socket = default_socket_path();
    let mut conn = match client::connect(&socket).await {
        Ok(conn) => conn,
        Err(error) => {
            anyhow::bail!(
                "guard status: no compatible daemon at {} (start one with `keyhog daemon start`): {error}",
                socket.display()
            );
        }
    };

    let canonical = canonicalize_root(&root)?;
    let request = Request::GuardStatus {
        root: canonical,
    };
    match conn.round_trip(&request).await? {
        Response::GuardStatusResult {
            root: daemon_root,
            mode,
            state,
            terminal_sequence,
            accepted_event_sequence,
            completed_event_sequence,
            pending_events,
            files_scanned,
            bytes_scanned,
            attestation_hits,
            attestation_misses,
            findings_count,
            coverage_gaps,
            initial_reconciliation_time,
            last_reconciliation_time,
            scanner_residency,
            backend_route_label,
            build_identity_short,
            detector_digest_short,
            suppression_digest_short,
            config_digest_short,
            autoroute_evidence_status,
            store_schema_version,
            store_path,
            repair_command,
        } => {
            if format != "human" && format != "json" {
                anyhow::bail!(
                    "guard status: invalid format '{}': expected 'human' or 'json'",
                    format
                );
            }
            if format == "json" {
                let json = serde_json::json!({
                    "root": daemon_root,
                    "mode": mode,
                    "state": state,
                    "terminal_sequence": terminal_sequence,
                    "accepted_event_sequence": accepted_event_sequence,
                    "completed_event_sequence": completed_event_sequence,
                    "pending_events": pending_events,
                    "files_scanned": files_scanned,
                    "bytes_scanned": bytes_scanned,
                    "attestation_hits": attestation_hits,
                    "attestation_misses": attestation_misses,
                    "findings_count": findings_count,
                    "coverage_gaps": coverage_gaps,
                    "initial_reconciliation_time": initial_reconciliation_time,
                    "last_reconciliation_time": last_reconciliation_time,
                    "scanner_residency": scanner_residency,
                    "backend_route_label": backend_route_label,
                    "build_identity_short": build_identity_short,
                    "detector_digest_short": detector_digest_short,
                    "suppression_digest_short": suppression_digest_short,
                    "config_digest_short": config_digest_short,
                    "autoroute_evidence_status": autoroute_evidence_status,
                    "store_schema_version": store_schema_version,
                    "store_path": store_path,
                    "repair_command": repair_command,
                });
                println!("{json}");
            } else {
                let palette = style::for_stderr();
                eprintln!("root:           {}", daemon_root);
                eprintln!("mode:           {mode}");
                eprintln!("state:          {state}");
                eprintln!("sequence:       {terminal_sequence}");
                eprintln!("accepted seq:   {accepted_event_sequence}");
                eprintln!("completed seq:  {completed_event_sequence}");
                eprintln!("pending events: {pending_events}");
                eprintln!("files scanned:  {files_scanned}");
                eprintln!("bytes scanned:  {bytes_scanned}");
                eprintln!("cache hits:     {attestation_hits}");
                eprintln!("cache misses:   {attestation_misses}");
                eprintln!("findings:       {findings_count}");
                eprintln!("coverage gaps:  {coverage_gaps}");
                if let Some(t) = initial_reconciliation_time {
                    eprintln!("initial recon:  {t}");
                }
                if let Some(t) = last_reconciliation_time {
                    eprintln!("last recon:     {t}");
                }
                eprintln!("residency:      {scanner_residency}");
                eprintln!("backend route:  {backend_route_label}");
                if !build_identity_short.is_empty() {
                    eprintln!("build digest:   {build_identity_short}");
                }
                if !detector_digest_short.is_empty() {
                    eprintln!("detector:       {detector_digest_short}");
                }
                if !suppression_digest_short.is_empty() {
                    eprintln!("suppression:    {suppression_digest_short}");
                }
                if !config_digest_short.is_empty() {
                    eprintln!("config:         {config_digest_short}");
                }
                eprintln!("autoroute:      {autoroute_evidence_status}");
                eprintln!("store schema:   {store_schema_version}");
                if !store_path.is_empty() {
                    eprintln!("store path:     {store_path}");
                }
                if state == "degraded" || state == "stale-policy" {
                    eprintln!(
                        "{} repair: {repair_command}",
                        style::warn("WARN", &palette)
                    );
                }
            }
            // Exit 13 for degraded/stale/stopped/indexing states.
            // Exit 1 for blocked state (unsuppressed findings).
            // Exit 1 for any state with findings_count > 0.
            if matches!(
                state.as_str(),
                "degraded" | "stale-policy" | "stopped" | "indexing"
            ) {
                Ok(ExitCode::from(exit_codes::EXIT_SOURCE_FAILED))
            } else if state == "blocked" || findings_count > 0 {
                Ok(ExitCode::from(exit_codes::EXIT_FINDINGS))
            } else {
                Ok(ExitCode::SUCCESS)
            }
        }
        Response::Error { message } => {
            anyhow::bail!("{message}");
        }
        other => {
            anyhow::bail!(
                "guard status: protocol mismatch (got {})",
                response_kind(&other)
            );
        }
    }
}

async fn run_reconcile(root: std::path::PathBuf) -> anyhow::Result<ExitCode> {
    let socket = default_socket_path();
    let mut conn = match client::connect(&socket).await {
        Ok(conn) => conn,
        Err(error) => {
            anyhow::bail!(
                "guard reconcile: no compatible daemon at {} (start one with `keyhog daemon start`): {error}",
                socket.display()
            );
        }
    };
    let canonical = canonicalize_root(&root)?;
    let request = Request::GuardReconcile {
        root: canonical.clone(),
    };
    match conn.round_trip(&request).await? {
        Response::GuardReconcileStarted { root: _ } => {
            // Reconciliation completed synchronously. Query the
            // final state to report it to the operator.
            let status_request = Request::GuardStatus {
                root: canonical.clone(),
            };
            match conn.round_trip(&status_request).await? {
                Response::GuardStatusResult { state, findings_count, .. } => {
                    let palette = style::for_stderr();
                    eprintln!(
                        "{} guard: reconciliation complete for {}, state is {}",
                        style::pass("OK", &palette),
                        root.display(),
                        state
                    );
                    if matches!(
                        state.as_str(),
                        "stopped" | "indexing" | "degraded" | "stale-policy"
                    ) {
                        Ok(ExitCode::from(exit_codes::EXIT_SOURCE_FAILED))
                    } else if state == "blocked" || findings_count > 0 {
                        Ok(ExitCode::from(exit_codes::EXIT_FINDINGS))
                    } else {
                        Ok(ExitCode::SUCCESS)
                    }
                }
                Response::Error { message } => {
                    anyhow::bail!("guard reconcile: status after reconcile: {message}");
                }
                other => {
                    anyhow::bail!(
                        "guard reconcile: status protocol mismatch (got {})",
                        response_kind(&other)
                    );
                }
            }
        }
        Response::Error { message } => {
            anyhow::bail!("{message}");
        }
        other => {
            anyhow::bail!(
                "guard reconcile: protocol mismatch (got {})",
                response_kind(&other)
            );
        }
    }
}

/// Canonicalize a root path on the client side before sending it to the
/// daemon. The daemon must not re-resolve relative paths against its own
/// working directory. Non-UTF-8 paths are rejected with an explicit error
/// rather than silently mangled by lossy conversion.
fn canonicalize_root(root: &std::path::Path) -> anyhow::Result<String> {
    let canonical = std::fs::canonicalize(root)
        .map_err(|e| anyhow::anyhow!("guard: cannot canonicalize {}: {}", root.display(), e))?;
    canonical
        .into_os_string()
        .into_string()
        .map_err(|s| anyhow::anyhow!("guard: root path is not valid UTF-8: {:?}", s))
}
