//! `keyhog guard {add, remove, up, down, list, status, reconcile, rebuild}` subcommand.
//!
//! Connects to the daemon and sends guard control frames. Starts or stops
//! the background daemon via `guard up` / `guard down`.

use crate::args::{GuardAction, GuardArgs};
use crate::daemon::client;
use crate::daemon::protocol::{response_kind, Request, Response};
use crate::exit_codes;
use crate::style;
use std::process::ExitCode;

use crate::daemon::server::default_socket_path;

pub(crate) async fn run(args: GuardArgs) -> anyhow::Result<ExitCode> {
    match args.action {
        GuardAction::Add {
            root,
            mode,
            no_hook,
            socket,
        } => run_add(root, mode, no_hook, socket).await,
        GuardAction::Remove {
            root,
            keep_hook,
            socket,
        } => run_remove(root, keep_hook, socket).await,
        GuardAction::Up { backend, socket } => run_up(backend, socket).await,
        GuardAction::Down { socket } => run_down(socket).await,
        GuardAction::List { socket } => run_list(socket).await,
        GuardAction::Status {
            root,
            format,
            socket,
        } => run_status(root, format, socket).await,
        GuardAction::Reconcile { root, socket } => run_reconcile(root, socket).await,
        GuardAction::Rebuild { root, mode, socket } => run_rebuild(root, mode, socket).await,
    }
}

async fn run_up(
    backend: Option<String>,
    socket: Option<std::path::PathBuf>,
) -> anyhow::Result<ExitCode> {
    let socket = socket.unwrap_or_else(default_socket_path);
    let palette = style::for_stderr();

    // If daemon is already running and reachable, report status and reconcile.
    if let Ok(mut conn) = client::connect(&socket).await {
        eprintln!(
            "{} guard: daemon already active at {}",
            style::pass("OK", &palette),
            socket.display()
        );
        if let Ok(Response::GuardListResult { roots }) = conn.round_trip(&Request::GuardList).await
        {
            if !roots.is_empty() {
                eprintln!(
                    "{} {} guard root{} registered",
                    style::pass("OK", &palette),
                    roots.len(),
                    if roots.len() == 1 { "" } else { "s" }
                );
                for root in &roots {
                    let _ = conn
                        .round_trip(&Request::GuardReconcile {
                            root: root.root.clone(),
                        })
                        .await;
                }
            }
        }
        return Ok(ExitCode::SUCCESS);
    }

    // Spawn daemon process in the background.
    let current_exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(current_exe);
    cmd.arg("daemon").arg("start");
    if let Some(b) = &backend {
        cmd.arg("--backend").arg(b);
    }
    cmd.arg("--socket").arg(&socket);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn keyhog daemon process: {e}"))?;

    // Poll socket readiness with backoff.
    let start_time = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(45);
    let mut conn = loop {
        if let Ok(Some(status)) = child.try_wait() {
            anyhow::bail!("guard up: daemon process exited unexpectedly with status {status}");
        }
        match client::connect(&socket).await {
            Ok(c) => break c,
            Err(_) => {
                if start_time.elapsed() >= timeout {
                    anyhow::bail!(
                        "guard up: timed out waiting for daemon to start at {}",
                        socket.display()
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    };

    eprintln!(
        "{} guard: daemon is up at {}",
        style::pass("OK", &palette),
        socket.display()
    );

    // Reconcile registered roots loaded from durable store.
    if let Ok(Response::GuardListResult { roots }) = conn.round_trip(&Request::GuardList).await {
        if !roots.is_empty() {
            eprintln!(
                "{} {} guard root{} registered from durable store",
                style::pass("OK", &palette),
                roots.len(),
                if roots.len() == 1 { "" } else { "s" }
            );
            for root in &roots {
                let _ = conn
                    .round_trip(&Request::GuardReconcile {
                        root: root.root.clone(),
                    })
                    .await;
            }
        }
    }

    Ok(ExitCode::SUCCESS)
}

async fn run_down(socket: Option<std::path::PathBuf>) -> anyhow::Result<ExitCode> {
    let socket = socket.unwrap_or_else(default_socket_path);
    let palette = style::for_stderr();

    let mut conn = match client::connect_any_version(&socket).await {
        Ok(c) => c,
        Err(_) => {
            eprintln!(
                "{} guard: daemon is not running at {}",
                style::pass("OK", &palette),
                socket.display()
            );
            return Ok(ExitCode::SUCCESS);
        }
    };

    match conn.round_trip(&Request::Shutdown).await? {
        Response::Shutdown => {
            eprintln!(
                "{} guard: daemon stopped; registrations and durable state preserved",
                style::pass("OK", &palette)
            );
            Ok(ExitCode::SUCCESS)
        }
        other => {
            anyhow::bail!(
                "guard down: unexpected daemon response ({})",
                response_kind(&other)
            );
        }
    }
}

async fn run_add(
    root: std::path::PathBuf,
    mode: String,
    no_hook: bool,
    socket: Option<std::path::PathBuf>,
) -> anyhow::Result<ExitCode> {
    let socket = socket.unwrap_or_else(default_socket_path);
    let mut conn = match client::connect(&socket).await {
        Ok(conn) => conn,
        Err(error) => {
            anyhow::bail!(
                "guard add: no compatible daemon at {} (start one with `keyhog guard up`): {error}",
                socket.display()
            );
        }
    };

    let canonical = canonicalize_root(&root)?;
    let request = Request::GuardAdd {
        root: canonical,
        mode: mode.clone(),
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
                root: canonical_for_reconcile.clone(),
            };
            match conn.round_trip(&status_request).await? {
                Response::GuardStatusResult {
                    state,
                    findings_count,
                    ..
                } => {
                    let palette = style::for_stderr();
                    eprintln!(
                        "{} guard: reconciliation complete, root is {}",
                        style::pass("OK", &palette),
                        state
                    );
                    if mode == "repo" && !no_hook {
                        match crate::subcommands::hook::install_at_repo(
                            std::path::Path::new(&canonical_for_reconcile),
                            false,
                        ) {
                            Ok((hook_path, _status)) => {
                                eprintln!(
                                    "{} guard: pre-commit hook active at {}",
                                    style::pass("OK", &palette),
                                    hook_path.display()
                                );
                            }
                            Err(err) => {
                                eprintln!(
                                    "{} guard: pre-commit hook not installed: {err}",
                                    style::warn("WARN", &palette)
                                );
                            }
                        }
                    }
                    Ok(exit_for_guard_state(&state, findings_count))
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

async fn run_remove(
    root: std::path::PathBuf,
    keep_hook: bool,
    socket: Option<std::path::PathBuf>,
) -> anyhow::Result<ExitCode> {
    let socket = socket.unwrap_or_else(default_socket_path);
    let mut conn = match client::connect(&socket).await {
        Ok(conn) => conn,
        Err(error) => {
            anyhow::bail!(
                "guard remove: no compatible daemon at {} (start one with `keyhog guard up`): {error}",
                socket.display()
            );
        }
    };

    let canonical = resolve_root_for_control(&root)?;
    let request = Request::GuardRemove {
        root: canonical.clone(),
    };
    match conn.round_trip(&request).await? {
        Response::GuardRemoved => {
            let palette = style::for_stderr();
            eprintln!(
                "{} guard: removed {}",
                style::pass("OK", &palette),
                root.display()
            );
            if !keep_hook {
                if let Ok(Some(hook_path)) =
                    crate::subcommands::hook::uninstall_at_repo(std::path::Path::new(&canonical))
                {
                    eprintln!(
                        "{} guard: pre-commit hook removed from {}",
                        style::pass("OK", &palette),
                        hook_path.display()
                    );
                }
            }
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

async fn run_list(socket: Option<std::path::PathBuf>) -> anyhow::Result<ExitCode> {
    let socket = socket.unwrap_or_else(default_socket_path);
    let mut conn = match client::connect(&socket).await {
        Ok(c) => c,
        Err(e) => {
            anyhow::bail!(
                "guard list: no compatible daemon at {} (start one with `keyhog guard up`): {e}",
                socket.display()
            );
        }
    };

    let request = Request::GuardList;
    match conn.round_trip(&request).await? {
        Response::GuardListResult { roots } => {
            if roots.is_empty() {
                let palette = style::for_stderr();
                eprintln!("{} no guard roots registered", style::pass("OK", &palette));
            } else {
                let palette = style::for_stderr();
                eprintln!(
                    "{} {} guard root{} registered",
                    style::pass("OK", &palette),
                    roots.len(),
                    if roots.len() == 1 { "" } else { "s" }
                );
                for entry in &roots {
                    println!(
                        "  {}  {}  seq={}",
                        entry.root, entry.state, entry.terminal_sequence
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Response::Error { message } => {
            let palette = style::for_stderr();
            eprintln!("{} guard list: {}", style::warn("WARN", &palette), message);
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
    socket: Option<std::path::PathBuf>,
) -> anyhow::Result<ExitCode> {
    let socket = socket.unwrap_or_else(default_socket_path);
    let mut conn = match client::connect(&socket).await {
        Ok(conn) => conn,
        Err(error) => {
            anyhow::bail!(
                "guard status: no compatible daemon at {} (start one with `keyhog guard up`): {error}",
                socket.display()
            );
        }
    };

    let canonical = resolve_root_for_control(&root)?;
    let request = Request::GuardStatus { root: canonical };
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
                println!("root:           {}", daemon_root);
                println!("mode:           {mode}");
                println!("state:          {state}");
                println!("sequence:       {terminal_sequence}");
                println!("accepted seq:   {accepted_event_sequence}");
                println!("completed seq:  {completed_event_sequence}");
                println!("pending events: {pending_events}");
                println!("files scanned:  {files_scanned}");
                println!("bytes scanned:  {bytes_scanned}");
                println!("cache hits:     {attestation_hits}");
                println!("cache misses:   {attestation_misses}");
                println!("findings:       {findings_count}");
                println!("coverage gaps:  {coverage_gaps}");
                if let Some(t) = initial_reconciliation_time {
                    println!("initial recon:  {t}");
                }
                if let Some(t) = last_reconciliation_time {
                    println!("last recon:     {t}");
                }
                println!("residency:      {scanner_residency}");
                println!("backend route:  {backend_route_label}");
                if !build_identity_short.is_empty() {
                    println!("build digest:   {build_identity_short}");
                }
                if !detector_digest_short.is_empty() {
                    println!("detector:       {detector_digest_short}");
                }
                if !suppression_digest_short.is_empty() {
                    println!("suppression:    {suppression_digest_short}");
                }
                if !config_digest_short.is_empty() {
                    println!("config:         {config_digest_short}");
                }
                println!("autoroute:      {autoroute_evidence_status}");
                println!("store schema:   {store_schema_version}");
                if !store_path.is_empty() {
                    println!("store path:     {store_path}");
                }
                if state == "degraded" || state == "stale-policy" {
                    eprintln!("{} repair: {repair_command}", style::warn("WARN", &palette));
                }
            }
            // Exit 13 for any state that is not a proven-clean Current root.
            Ok(exit_for_guard_state(&state, findings_count))
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

async fn run_reconcile(
    root: std::path::PathBuf,
    socket: Option<std::path::PathBuf>,
) -> anyhow::Result<ExitCode> {
    let socket = socket.unwrap_or_else(default_socket_path);
    let mut conn = match client::connect(&socket).await {
        Ok(conn) => conn,
        Err(error) => {
            anyhow::bail!(
                "guard reconcile: no compatible daemon at {} (start one with `keyhog guard up`): {error}",
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
                Response::GuardStatusResult {
                    state,
                    findings_count,
                    ..
                } => {
                    let palette = style::for_stderr();
                    eprintln!(
                        "{} guard: reconciliation complete for {}, state is {}",
                        style::pass("OK", &palette),
                        root.display(),
                        state
                    );
                    Ok(exit_for_guard_state(&state, findings_count))
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

/// Rebuild the guard state for a root. This removes the root from the
/// guard, which clears its persisted state and attestations from the
/// durable store, then re-adds it, triggering a fresh baseline
/// reconciliation. Use after store corruption or when the persisted
/// state is irrecoverably stale.
async fn run_rebuild(
    root: std::path::PathBuf,
    mode: String,
    socket: Option<std::path::PathBuf>,
) -> anyhow::Result<ExitCode> {
    let socket = socket.unwrap_or_else(default_socket_path);
    let mut conn = match client::connect(&socket).await {
        Ok(conn) => conn,
        Err(error) => {
            anyhow::bail!(
                "guard rebuild: no compatible daemon at {} (start one with `keyhog guard up`): {error}",
                socket.display()
            );
        }
    };
    let canonical = canonicalize_root(&root)?;
    let palette = style::for_stderr();

    // 1. Remove the root from the guard. This clears its durable store
    //    entries (root record, root gaps, attestations for that root).
    let remove_request = Request::GuardRemove {
        root: canonical.clone(),
    };
    match conn.round_trip(&remove_request).await? {
        Response::GuardRemoved => {
            eprintln!(
                "{} guard: removed root {} for rebuild",
                style::pass("OK", &palette),
                root.display()
            );
        }
        Response::Error { message } => {
            // If the root is not registered, continue with rebuild.
            if message.contains("not registered") {
                eprintln!(
                    "{} guard: root {} was not registered, proceeding with add",
                    style::warn("WARN", &palette),
                    root.display()
                );
            } else {
                anyhow::bail!("guard rebuild: remove failed: {message}");
            }
        }
        other => {
            anyhow::bail!(
                "guard rebuild: remove protocol mismatch (got {})",
                response_kind(&other)
            );
        }
    }

    // 2. Re-add the root. This triggers a fresh baseline reconciliation.
    let add_request = Request::GuardAdd {
        root: canonical.clone(),
        mode: mode.clone(),
    };
    let added_root = match conn.round_trip(&add_request).await? {
        Response::GuardAdded {
            root: ref added_root,
            state: ref add_state,
            terminal_sequence,
        } => {
            eprintln!(
                "{} guard: root {} re-registered for rebuild (state {}, sequence {})",
                style::pass("OK", &palette),
                root.display(),
                add_state,
                terminal_sequence
            );
            added_root.clone()
        }
        Response::Error { message } => {
            anyhow::bail!("guard rebuild: add failed: {message}");
        }
        other => {
            anyhow::bail!(
                "guard rebuild: add protocol mismatch (got {})",
                response_kind(&other)
            );
        }
    };

    // 3. Wait for baseline reconciliation so rebuild reports a terminal state,
    // matching `guard add` and the exit-code docs.
    let reconcile_request = Request::GuardReconcile {
        root: added_root.clone(),
    };
    match conn.round_trip(&reconcile_request).await? {
        Response::GuardReconcileStarted { root: _ } => {
            let status_request = Request::GuardStatus { root: added_root };
            match conn.round_trip(&status_request).await? {
                Response::GuardStatusResult {
                    state,
                    findings_count,
                    terminal_sequence,
                    ..
                } => {
                    eprintln!(
                        "{} guard: rebuild complete for {}, state is {} (sequence {})",
                        style::pass("OK", &palette),
                        root.display(),
                        state,
                        terminal_sequence
                    );
                    Ok(exit_for_guard_state(&state, findings_count))
                }
                Response::Error { message } => {
                    anyhow::bail!("guard rebuild: status after reconcile: {message}");
                }
                other => {
                    anyhow::bail!(
                        "guard rebuild: status protocol mismatch (got {})",
                        response_kind(&other)
                    );
                }
            }
        }
        Response::Error { message } => {
            anyhow::bail!("guard rebuild: reconcile failed: {message}");
        }
        other => {
            anyhow::bail!(
                "guard rebuild: reconcile protocol mismatch (got {})",
                response_kind(&other)
            );
        }
    }
}

/// Map a guard root state label to the CLI exit code byte.
/// Dirty is unproven (events observed, not yet reconciled) and must not
/// report success. Exit 13 for any non-proven-clean state; exit 1 for
/// blocked / findings; exit 0 only for current with zero findings.
fn exit_code_for_guard_state(state: &str, findings_count: u64) -> u8 {
    if matches!(
        state,
        "degraded" | "stale-policy" | "stopped" | "indexing" | "dirty"
    ) {
        exit_codes::EXIT_SOURCE_FAILED
    } else if state == "blocked" || findings_count > 0 {
        exit_codes::EXIT_FINDINGS
    } else {
        exit_codes::EXIT_SUCCESS
    }
}

fn exit_for_guard_state(state: &str, findings_count: u64) -> ExitCode {
    ExitCode::from(exit_code_for_guard_state(state, findings_count))
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

/// Resolve a root for daemon control frames when the directory may already
/// be gone (remove / status of a deleted root). Prefer canonicalize; on
/// NotFound fall back to an absolute lexical path so the daemon can still
/// match the registered key.
fn resolve_root_for_control(root: &std::path::Path) -> anyhow::Result<String> {
    match std::fs::canonicalize(root) {
        Ok(canonical) => canonical
            .into_os_string()
            .into_string()
            .map_err(|s| anyhow::anyhow!("guard: root path is not valid UTF-8: {:?}", s)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let absolute = if root.is_absolute() {
                root.to_path_buf()
            } else {
                std::env::current_dir()
                    .map_err(|e| {
                        anyhow::anyhow!("guard: cannot resolve cwd for {}: {}", root.display(), e)
                    })?
                    .join(root)
            };
            absolute
                .into_os_string()
                .into_string()
                .map_err(|s| anyhow::anyhow!("guard: root path is not valid UTF-8: {:?}", s))
        }
        Err(err) => Err(anyhow::anyhow!(
            "guard: cannot resolve {}: {}",
            root.display(),
            err
        )),
    }
}
#[cfg(test)]
#[path = "../../tests/unit/subcommands_guard_exit_codes.rs"]
mod exit_code_for_guard_state_tests;

#[cfg(test)]
#[path = "../../tests/unit/subcommands_guard_resolve_root.rs"]
mod resolve_root_for_control_tests;
