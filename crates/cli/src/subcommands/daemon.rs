//! `keyhog daemon {start,stop,status}` - manage a long-lived
//! scanner process that amortizes the ~3 s `CompiledScanner::compile`
//! cold start across many client invocations (pre-commit hooks, IDE
//! save handlers, CI per-commit pipelines).

use crate::args::DaemonArgs;
use crate::daemon::client;
use crate::daemon::protocol::{Request, Response};
use crate::daemon::server::{self, default_socket_path};
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::ExitCode;

pub async fn run(args: DaemonArgs) -> Result<ExitCode> {
    match args.action {
        crate::args::DaemonAction::Start { socket, detectors } => start(socket, detectors).await,
        crate::args::DaemonAction::Stop { socket } => stop(socket).await,
        crate::args::DaemonAction::Status { socket } => status(socket).await,
    }
}

async fn start(socket: Option<PathBuf>, detectors_dir: PathBuf) -> Result<ExitCode> {
    crate::backend_env::validate_scan_runtime_env()?;

    let socket = socket.unwrap_or_else(default_socket_path);
    // Use the same load-or-embedded fallback that `scan`, `watch`, `scan-system`
    // and `explain` go through. Before this, `daemon start` ran
    // `keyhog_core::load_detectors(&"detectors")` directly and bailed with
    // `failed to read detector file detectors: No such file or directory`
    // on every install where the user hadn't `cd`'d into a checked-out
    // repo - which is every install via `install.sh` / `cargo install`.
    let detectors = crate::orchestrator_config::load_detectors_or_embedded(&detectors_dir)
        .with_context(|| {
            format!(
                "daemon start: load detectors from {}",
                detectors_dir.display()
            )
        })?;
    server::run(socket, detectors).await?;
    Ok(ExitCode::SUCCESS)
}

async fn stop(socket: Option<PathBuf>) -> Result<ExitCode> {
    let socket = socket.unwrap_or_else(default_socket_path);
    let mut conn = client::connect(&socket).await.with_context(|| {
        format!(
            "daemon stop: no daemon at {} (already stopped?)",
            socket.display()
        )
    })?;
    match conn.round_trip(&Request::Shutdown).await? {
        Response::Shutdown => {
            eprintln!("keyhog daemon stopped");
            Ok(ExitCode::SUCCESS)
        }
        other => {
            anyhow::bail!(
                "daemon stop: protocol mismatch (got {}). Restart with \
                 `keyhog daemon stop --force || true && keyhog daemon start` \
                 to clear stuck state.",
                response_kind(&other)
            )
        }
    }
}

async fn status(socket: Option<PathBuf>) -> Result<ExitCode> {
    let socket = socket.unwrap_or_else(default_socket_path);
    let mut conn = client::connect(&socket).await.with_context(|| {
        format!(
            "daemon status: no daemon at {} (start one with `keyhog daemon start`)",
            socket.display()
        )
    })?;
    match conn.round_trip(&Request::Health).await? {
        Response::Health {
            uptime_secs,
            scans_served,
            active_scans,
            detector_count,
        } => {
            println!(
                "keyhog daemon: uptime {}s · {} scans served · {} active · {} detectors",
                uptime_secs, scans_served, active_scans, detector_count
            );
            Ok(ExitCode::SUCCESS)
        }
        other => anyhow::bail!(
            "daemon status: protocol mismatch (got {}). Restart with \
             `keyhog daemon stop && keyhog daemon start` to clear stuck state.",
            response_kind(&other)
        ),
    }
}

/// One-word kind label for a daemon Response. Keeps user-facing error
/// messages free of the {:?} debug dump which can leak internal field
/// names + payload bytes (some of which are credential-shaped).
fn response_kind(response: &Response) -> &'static str {
    match response {
        Response::Hello { .. } => "Hello",
        Response::Health { .. } => "Health",
        Response::ScanResults { .. } => "ScanResults",
        Response::Shutdown => "Shutdown",
        Response::Error { .. } => "Error",
    }
}
