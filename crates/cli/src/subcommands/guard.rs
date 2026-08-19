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
            root: added_root,
            state: add_state,
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
    match client::connect(&socket).await {
        Ok(conn) => run_list_online(conn).await,
        Err(_) => run_list_offline(),
    }
}

async fn run_list_online(mut conn: client::Client) -> anyhow::Result<ExitCode> {
    let request = Request::GuardList;
    match conn.round_trip(&request).await? {
        Response::GuardListResult { roots } => {
            let palette = style::for_stderr();
            if roots.is_empty() {
                eprintln!("{} no guard roots registered", style::pass("OK", &palette));
            } else {
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

fn run_list_offline() -> anyhow::Result<ExitCode> {
    let palette = style::for_stderr();
    let state_path = crate::config::load_guard_state_path(None);
    let roots = match state_path.as_deref() {
        Some(path) if path.exists() => {
            let store =
                keyhog_core::guard_store::DurableGuardStore::open_read_only(path).map_err(|e| {
                    anyhow::anyhow!(
                        "guard list: failed to open durable store at {}: {e}",
                        path.display()
                    )
                })?;
            let registry = store.load_roots().map_err(|e| {
                anyhow::anyhow!(
                    "guard list: failed to read durable store at {}: {e}",
                    path.display()
                )
            })?;
            let mut list: Vec<_> = registry.list().into_iter().cloned().collect();
            list.sort_by(|a, b| a.canonical_path.cmp(&b.canonical_path));
            list
        }
        _ => Vec::new(),
    };

    if roots.is_empty() {
        eprintln!(
            "{} no guard roots registered (no daemon active)",
            style::pass("OK", &palette)
        );
    } else {
        eprintln!(
            "{} {} guard root{} registered (no daemon active)",
            style::pass("OK", &palette),
            roots.len(),
            if roots.len() == 1 { "" } else { "s" }
        );
        for entry in &roots {
            println!(
                "  {}  {}  seq={}",
                String::from_utf8_lossy(&entry.canonical_path),
                entry.state,
                entry.terminal_sequence
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

struct GuardStatusView {
    root: String,
    mode: String,
    state: String,
    filesystem_type: String,
    filesystem_authoritative: bool,
    filesystem_unauthoritative_reason: Option<String>,
    scrub_interval_secs: u64,
    terminal_sequence: u64,
    accepted_event_sequence: u64,
    completed_event_sequence: u64,
    pending_events: u64,
    files_scanned: u64,
    bytes_scanned: u64,
    attestation_hits: u64,
    attestation_misses: u64,
    findings_count: u64,
    coverage_gaps: u64,
    initial_reconciliation_time: Option<u64>,
    last_reconciliation_time: Option<u64>,
    scanner_residency: String,
    watcher_backend: String,
    watcher_latency_tier: String,
    watcher_poll_interval_ms: Option<u64>,
    backend_route_label: String,
    build_identity_short: String,
    detector_digest_short: String,
    suppression_digest_short: String,
    config_digest_short: String,
    autoroute_evidence_status: String,
    store_schema_version: u32,
    store_path: String,
    repair_command: String,
}

impl GuardStatusView {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "root": self.root,
            "mode": self.mode,
            "state": self.state,
            "filesystem_type": self.filesystem_type,
            "filesystem_authoritative": self.filesystem_authoritative,
            "filesystem_unauthoritative_reason": self.filesystem_unauthoritative_reason,
            "scrub_interval_secs": self.scrub_interval_secs,
            "terminal_sequence": self.terminal_sequence,
            "accepted_event_sequence": self.accepted_event_sequence,
            "completed_event_sequence": self.completed_event_sequence,
            "pending_events": self.pending_events,
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "attestation_hits": self.attestation_hits,
            "attestation_misses": self.attestation_misses,
            "findings_count": self.findings_count,
            "coverage_gaps": self.coverage_gaps,
            "initial_reconciliation_time": self.initial_reconciliation_time,
            "last_reconciliation_time": self.last_reconciliation_time,
            "scanner_residency": self.scanner_residency,
            "watcher_backend": self.watcher_backend,
            "watcher_latency_tier": self.watcher_latency_tier,
            "watcher_poll_interval_ms": self.watcher_poll_interval_ms,
            "backend_route_label": self.backend_route_label,
            "build_identity_short": self.build_identity_short,
            "detector_digest_short": self.detector_digest_short,
            "suppression_digest_short": self.suppression_digest_short,
            "config_digest_short": self.config_digest_short,
            "autoroute_evidence_status": self.autoroute_evidence_status,
            "store_schema_version": self.store_schema_version,
            "store_path": self.store_path,
            "repair_command": self.repair_command,
        })
    }

    fn print_human(&self) {
        let palette = style::for_stderr();
        println!("root:           {}", self.root);
        println!("mode:           {}", self.mode);
        println!("state:          {}", self.state);
        let fs_auth_label = if self.filesystem_authoritative {
            "authoritative".to_string()
        } else if let Some(reason) = &self.filesystem_unauthoritative_reason {
            format!("unauthoritative: {reason}")
        } else {
            "unauthoritative".to_string()
        };
        println!("filesystem:     {} ({fs_auth_label})", self.filesystem_type);
        if self.scrub_interval_secs > 0 {
            println!("scrub interval: {}s", self.scrub_interval_secs);
        }
        println!("sequence:       {}", self.terminal_sequence);
        println!("accepted seq:   {}", self.accepted_event_sequence);
        println!("completed seq:  {}", self.completed_event_sequence);
        println!("pending events: {}", self.pending_events);
        println!("files scanned:  {}", self.files_scanned);
        println!("bytes scanned:  {}", self.bytes_scanned);
        println!("cache hits:     {}", self.attestation_hits);
        println!("cache misses:   {}", self.attestation_misses);
        println!("findings:       {}", self.findings_count);
        println!("coverage gaps:  {}", self.coverage_gaps);
        if let Some(t) = self.initial_reconciliation_time {
            println!("initial recon:  {t}");
        }
        if let Some(t) = self.last_reconciliation_time {
            println!("last recon:     {t}");
        }
        println!("residency:      {}", self.scanner_residency);
        println!(
            "watcher:        {} ({})",
            self.watcher_backend, self.watcher_latency_tier
        );
        if let Some(poll_ms) = self.watcher_poll_interval_ms {
            println!("poll interval:  {poll_ms}ms");
        }
        println!("backend route:  {}", self.backend_route_label);
        if !self.build_identity_short.is_empty() {
            println!("build digest:   {}", self.build_identity_short);
        }
        if !self.detector_digest_short.is_empty() {
            println!("detector:       {}", self.detector_digest_short);
        }
        if !self.suppression_digest_short.is_empty() {
            println!("suppression:    {}", self.suppression_digest_short);
        }
        if !self.config_digest_short.is_empty() {
            println!("config:         {}", self.config_digest_short);
        }
        println!("autoroute:      {}", self.autoroute_evidence_status);
        println!("store schema:   {}", self.store_schema_version);
        if !self.store_path.is_empty() {
            println!("store path:     {}", self.store_path);
        }
        if self.state == "degraded" || self.state == "stale-policy" {
            eprintln!(
                "{} repair: {}",
                style::warn("WARN", &palette),
                self.repair_command
            );
        }
    }

    fn from_record(record: &keyhog_core::guard_state::GuardRootRecord, store_path: &str) -> Self {
        let (
            files_scanned,
            bytes_scanned,
            attestation_hits,
            attestation_misses,
            findings_count,
            coverage_gaps,
        ) = if let Some(receipt) = &record.last_receipt {
            (
                receipt.objects_scanned,
                receipt.bytes_scanned,
                receipt.objects_hit,
                receipt
                    .objects_requested
                    .saturating_sub(receipt.objects_hit + receipt.objects_skipped),
                receipt.findings_count,
                receipt.coverage_gaps,
            )
        } else {
            (0, 0, 0, 0, 0, 0)
        };
        let canonical_str = String::from_utf8_lossy(&record.canonical_path).into_owned();
        Self {
            root: canonical_str.clone(),
            mode: record.mode.label().to_string(),
            state: record.state.label().to_string(),
            filesystem_type: record.filesystem_authority.filesystem_type.clone(),
            filesystem_authoritative: record.filesystem_authority.authoritative,
            filesystem_unauthoritative_reason: record
                .filesystem_authority
                .unauthoritative_reason
                .clone(),
            scrub_interval_secs: 0,
            terminal_sequence: record.terminal_sequence,
            accepted_event_sequence: record.accepted_event_sequence,
            completed_event_sequence: record.completed_event_sequence,
            pending_events: 0,
            files_scanned,
            bytes_scanned,
            attestation_hits,
            attestation_misses,
            findings_count,
            coverage_gaps,
            initial_reconciliation_time: record.initial_reconciliation_time,
            last_reconciliation_time: record.last_reconciliation_time,
            scanner_residency: "offline".to_string(),
            watcher_backend: "none (daemon offline)".to_string(),
            watcher_latency_tier: "offline".to_string(),
            watcher_poll_interval_ms: None,
            backend_route_label: record.backend_route_label.clone(),
            build_identity_short: String::new(),
            detector_digest_short: String::new(),
            suppression_digest_short: String::new(),
            config_digest_short: String::new(),
            autoroute_evidence_status: "unproven (daemon offline)".to_string(),
            store_schema_version: keyhog_core::guard_state::GUARD_SCHEMA_VERSION,
            store_path: store_path.to_string(),
            repair_command: format!("keyhog guard reconcile {canonical_str}"),
        }
    }
}

async fn run_status(
    root: Option<std::path::PathBuf>,
    format: String,
    socket: Option<std::path::PathBuf>,
) -> anyhow::Result<ExitCode> {
    if format != "human" && format != "json" {
        anyhow::bail!(
            "guard status: invalid format '{}': expected 'human' or 'json'",
            format
        );
    }
    let socket = socket.unwrap_or_else(default_socket_path);
    match client::connect(&socket).await {
        Ok(conn) => run_status_online(conn, root, &format).await,
        Err(_) => run_status_offline(root, &format),
    }
}

async fn run_status_online(
    mut conn: client::Client,
    root: Option<std::path::PathBuf>,
    format: &str,
) -> anyhow::Result<ExitCode> {
    if let Some(root_path) = root {
        let canonical = resolve_root_for_control(&root_path)?;
        let request = Request::GuardStatus { root: canonical };
        match conn.round_trip(&request).await? {
            Response::GuardStatusResult {
                root: daemon_root,
                mode,
                state,
                filesystem_type,
                filesystem_authoritative,
                filesystem_unauthoritative_reason,
                scrub_interval_secs,
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
                watcher_backend,
                watcher_latency_tier,
                watcher_poll_interval_ms,
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
                let view = GuardStatusView {
                    root: daemon_root,
                    mode,
                    state,
                    filesystem_type,
                    filesystem_authoritative,
                    filesystem_unauthoritative_reason,
                    scrub_interval_secs,
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
                    watcher_backend,
                    watcher_latency_tier,
                    watcher_poll_interval_ms,
                    backend_route_label,
                    build_identity_short,
                    detector_digest_short,
                    suppression_digest_short,
                    config_digest_short,
                    autoroute_evidence_status,
                    store_schema_version,
                    store_path,
                    repair_command,
                };
                if format == "json" {
                    println!("{}", view.to_json());
                } else {
                    view.print_human();
                }
                Ok(exit_for_guard_state(&view.state, view.findings_count))
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
    } else {
        let request = Request::GuardList;
        match conn.round_trip(&request).await? {
            Response::GuardListResult { roots } => {
                let palette = style::for_stderr();
                if roots.is_empty() {
                    if format == "json" {
                        println!(
                            "{}",
                            serde_json::json!({
                                "daemon": "active",
                                "total": 0,
                                "roots": [],
                            })
                        );
                    } else {
                        eprintln!("{} no guard roots registered", style::pass("OK", &palette));
                    }
                    return Ok(ExitCode::SUCCESS);
                }

                let mut views = Vec::with_capacity(roots.len());
                for entry in &roots {
                    let req = Request::GuardStatus {
                        root: entry.root.clone(),
                    };
                    match conn.round_trip(&req).await? {
                        Response::GuardStatusResult {
                            root,
                            mode,
                            state,
                            filesystem_type,
                            filesystem_authoritative,
                            filesystem_unauthoritative_reason,
                            scrub_interval_secs,
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
                            watcher_backend,
                            watcher_latency_tier,
                            watcher_poll_interval_ms,
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
                            views.push(GuardStatusView {
                                root,
                                mode,
                                state,
                                filesystem_type,
                                filesystem_authoritative,
                                filesystem_unauthoritative_reason,
                                scrub_interval_secs,
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
                                watcher_backend,
                                watcher_latency_tier,
                                watcher_poll_interval_ms,
                                backend_route_label,
                                build_identity_short,
                                detector_digest_short,
                                suppression_digest_short,
                                config_digest_short,
                                autoroute_evidence_status,
                                store_schema_version,
                                store_path,
                                repair_command,
                            });
                        }
                        Response::Error { message } => {
                            anyhow::bail!("guard status for '{}': {}", entry.root, message);
                        }
                        other => {
                            anyhow::bail!(
                                "guard status for '{}': protocol mismatch (got {})",
                                entry.root,
                                response_kind(&other)
                            );
                        }
                    }
                }

                let mut overall_exit = exit_codes::EXIT_SUCCESS;
                for view in &views {
                    let code = exit_code_for_guard_state(&view.state, view.findings_count);
                    if code == exit_codes::EXIT_FINDINGS {
                        overall_exit = exit_codes::EXIT_FINDINGS;
                    } else if code == exit_codes::EXIT_SOURCE_FAILED
                        && overall_exit != exit_codes::EXIT_FINDINGS
                    {
                        overall_exit = exit_codes::EXIT_SOURCE_FAILED;
                    }
                }

                if format == "json" {
                    let root_jsons: Vec<_> = views.iter().map(|v| v.to_json()).collect();
                    println!(
                        "{}",
                        serde_json::json!({
                            "daemon": "active",
                            "total": views.len(),
                            "roots": root_jsons,
                        })
                    );
                } else {
                    eprintln!(
                        "{} {} guard root{} registered",
                        style::pass("OK", &palette),
                        views.len(),
                        if views.len() == 1 { "" } else { "s" }
                    );
                    for (i, view) in views.iter().enumerate() {
                        if i > 0 {
                            println!();
                        }
                        view.print_human();
                    }
                }

                Ok(ExitCode::from(overall_exit))
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
}

fn run_status_offline(root: Option<std::path::PathBuf>, format: &str) -> anyhow::Result<ExitCode> {
    let palette = style::for_stderr();
    if let Some(root_path) = root {
        let canonical = resolve_root_for_control(&root_path)?;
        let state_path = crate::config::load_guard_state_path(Some(&root_path))
            .or_else(|| crate::config::load_guard_state_path(None));
        let path = match state_path {
            Some(p) if p.exists() => p,
            _ => {
                anyhow::bail!(
                    "guard status: root not registered in durable store: {} (no daemon active)",
                    canonical
                );
            }
        };
        let store =
            keyhog_core::guard_store::DurableGuardStore::open_read_only(&path).map_err(|e| {
                anyhow::anyhow!(
                    "guard status: failed to read durable store at {}: {e}",
                    path.display()
                )
            })?;
        let record = match store.get_root(canonical.as_bytes())? {
            Some(r) => r,
            None => {
                anyhow::bail!(
                    "guard status: root not registered in durable store: {} (no daemon active)",
                    canonical
                );
            }
        };
        let view = GuardStatusView::from_record(&record, &path.display().to_string());
        if format == "json" {
            println!("{}", view.to_json());
        } else {
            view.print_human();
        }
        Ok(exit_for_guard_state(&view.state, view.findings_count))
    } else {
        let state_path = crate::config::load_guard_state_path(None);
        let (roots, store_path_str) = match state_path.as_deref() {
            Some(path) if path.exists() => {
                let store = keyhog_core::guard_store::DurableGuardStore::open_read_only(path)
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "guard status: failed to read durable store at {}: {e}",
                            path.display()
                        )
                    })?;
                let registry = store.load_roots().map_err(|e| {
                    anyhow::anyhow!(
                        "guard status: failed to read durable store at {}: {e}",
                        path.display()
                    )
                })?;
                let mut list: Vec<_> = registry.list().into_iter().cloned().collect();
                list.sort_by(|a, b| a.canonical_path.cmp(&b.canonical_path));
                (list, path.display().to_string())
            }
            _ => (Vec::new(), String::new()),
        };

        if roots.is_empty() {
            if format == "json" {
                println!(
                    "{}",
                    serde_json::json!({
                        "daemon": "offline",
                        "total": 0,
                        "roots": [],
                    })
                );
            } else {
                eprintln!(
                    "{} no guard roots registered (no daemon active)",
                    style::pass("OK", &palette)
                );
            }
            return Ok(ExitCode::SUCCESS);
        }

        let views: Vec<_> = roots
            .iter()
            .map(|r| GuardStatusView::from_record(r, &store_path_str))
            .collect();

        let mut overall_exit = exit_codes::EXIT_SUCCESS;
        for view in &views {
            let code = exit_code_for_guard_state(&view.state, view.findings_count);
            if code == exit_codes::EXIT_FINDINGS {
                overall_exit = exit_codes::EXIT_FINDINGS;
            } else if code == exit_codes::EXIT_SOURCE_FAILED
                && overall_exit != exit_codes::EXIT_FINDINGS
            {
                overall_exit = exit_codes::EXIT_SOURCE_FAILED;
            }
        }

        if format == "json" {
            let root_jsons: Vec<_> = views.iter().map(|v| v.to_json()).collect();
            println!(
                "{}",
                serde_json::json!({
                    "daemon": "offline",
                    "total": views.len(),
                    "roots": root_jsons,
                })
            );
        } else {
            eprintln!(
                "{} {} guard root{} registered (no daemon active)",
                style::pass("OK", &palette),
                views.len(),
                if views.len() == 1 { "" } else { "s" }
            );
            for (i, view) in views.iter().enumerate() {
                if i > 0 {
                    println!();
                }
                view.print_human();
            }
        }

        Ok(ExitCode::from(overall_exit))
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
            root: added_root,
            state: add_state,
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
