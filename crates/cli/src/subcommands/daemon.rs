//! `keyhog daemon {start,stop,status}` - manage a long-lived
//! scanner process that amortizes the ~3 s `CompiledScanner::compile`
//! cold start across many client invocations (pre-commit hooks, IDE
//! save handlers, CI per-commit pipelines).

use crate::args::DaemonArgs;
use crate::daemon::client;
use crate::daemon::protocol::{response_kind, Request, Response};
use crate::daemon::server::{self, default_socket_path};
use crate::style;
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

pub(crate) async fn run(args: DaemonArgs) -> Result<ExitCode> {
    match args.action {
        crate::args::DaemonAction::Start {
            socket,
            detectors,
            cache_dir,
            backend,
            request_timeout_secs,
        } => start(socket, detectors, cache_dir, backend, request_timeout_secs).await,
        crate::args::DaemonAction::Stop { socket } => stop(socket).await,
        crate::args::DaemonAction::Status { socket } => status(socket).await,
    }
}

async fn start(
    socket: Option<PathBuf>,
    detectors_dir: PathBuf,
    cache_dir: Option<PathBuf>,
    backend: Option<String>,
    request_timeout_secs: u64,
) -> Result<ExitCode> {
    crate::runtime_preflight::validate_scan_runtime_config()?;
    crate::orchestrator_config::configure_hyperscan_cache_dir(cache_dir)?;
    let backend_override = crate::orchestrator_config::parse_backend_override(backend.as_deref())?;

    let socket = socket.unwrap_or_else(default_socket_path); // LAW10: absent config => documented default; Tier-A knob, recall-irrelevant
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
    let options = server::ServerOptions {
        request_read_timeout: Duration::from_secs(request_timeout_secs),
    };
    server::run_with_backend_override(socket, detectors, options, backend_override).await?;
    Ok(ExitCode::SUCCESS)
}

async fn stop(socket: Option<PathBuf>) -> Result<ExitCode> {
    let socket = socket.unwrap_or_else(default_socket_path); // LAW10: absent config => documented default; Tier-A knob, recall-irrelevant
                                                             // `connect_any_version`, not `connect`: a daemon left running across a
                                                             // `keyhog update` reports an older keyhog version, and the whole point of
                                                             // `daemon stop` is to clear exactly that stale daemon. The strict
                                                             // version-gated `connect` (used by the scan route) would REFUSE to talk to
                                                             // it, stranding the stale process; `stop` must still be able to shut it down.
    let mut conn = client::connect_any_version(&socket)
        .await
        .with_context(|| {
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
    let socket = socket.unwrap_or_else(default_socket_path); // LAW10: absent config => documented default; Tier-A knob, recall-irrelevant
                                                             // `connect_any_version`: `status` is diagnostic — an operator inspecting a
                                                             // daemon left running across an upgrade NEEDS to see it (so they can decide
                                                             // to restart it), not get a refusal. The strict version-gated `connect`
                                                             // would hide the very stale daemon the operator is trying to find.
    let mut conn = client::connect_any_version(&socket)
        .await
        .with_context(|| {
            format!(
                "daemon status: no daemon at {} (start one with `keyhog daemon start`)",
                socket.display()
            )
        })?;
    // Surface staleness LOUDLY: a daemon left running across a `keyhog update`
    // serves an OLDER detector corpus. The scan route already refuses it
    // (`connect` fails closed), but an operator running `status` must SEE that
    // the daemon is stale — otherwise the healthy-looking uptime line hides the
    // very reason their scans are silently routed in-process.
    let stale = conn.is_stale();
    let daemon_version = conn.daemon_version().to_string();
    let stale_reason = conn.stale_reason().map(str::to_string);
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
            println!(
                "scan scope: eligible stdin/single-file scans before baseline, Merkle \
                 skip-cache, and verification; directories, git/remote sources, policy \
                 changes, baseline, and --verify run in-process."
            );
            if stale {
                let palette = style::for_stderr();
                eprintln!(
                    "{} this daemon's build/corpus identity does not match the client \
                     (daemon keyhog {}, client {}; {}): scan connections refuse it; \
                     `--daemon=auto` runs in process and `--daemon=on` fails until you restart it: \
                     `keyhog daemon stop && keyhog daemon start`.",
                    style::warn("WARN", &palette),
                    daemon_version,
                    env!("CARGO_PKG_VERSION"),
                    stale_reason.as_deref().unwrap_or("identity mismatch"),
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        other => anyhow::bail!(
            "daemon status: protocol mismatch (got {}). Restart with \
             `keyhog daemon stop && keyhog daemon start` to clear stuck state.",
            response_kind(&other)
        ),
    }
}
