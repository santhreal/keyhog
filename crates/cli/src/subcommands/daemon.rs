//! `keyhog daemon {start,stop,status}` - manage a long-lived
//! scanner process that amortizes the ~3 s `CompiledScanner::compile`
//! cold start across many client invocations (pre-commit hooks, IDE
//! save handlers, CI per-commit pipelines).

use crate::args::DaemonArgs;
use crate::daemon::client;
use crate::daemon::control;
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
            detectors_cli_explicit,
            cache_dir,
            backend,
            request_timeout_secs,
            mass,
            mass_gpu_primary,
        } => {
            start(
                socket,
                detectors,
                detectors_cli_explicit,
                cache_dir,
                backend,
                request_timeout_secs,
                mass,
                mass_gpu_primary,
            )
            .await
        }
        crate::args::DaemonAction::Stop { socket } => stop(socket).await,
        crate::args::DaemonAction::Status { socket } => status(socket).await,
    }
}

async fn start(
    socket: Option<PathBuf>,
    detectors_dir: PathBuf,
    detectors_cli_explicit: bool,
    cache_dir: Option<PathBuf>,
    backend: Option<String>,
    request_timeout_secs: u64,
    mass: bool,
    mass_gpu_primary: bool,
) -> Result<ExitCode> {
    crate::runtime_preflight::validate_scan_runtime_config()?;
    crate::orchestrator_config::configure_hyperscan_cache_dir(cache_dir)?;
    let backend_override = crate::orchestrator_config::parse_backend_override(backend.as_deref())?;
    let gpu_policy =
        crate::orchestrator_config::gpu_runtime_policy_for_backend_override(backend_override)?;
    keyhog_scanner::gpu::set_gpu_runtime_policy(gpu_policy);
    let hardware = crate::orchestrator::probe_route_hardware(backend_override, gpu_policy);
    crate::orchestrator_config::configure_persistent_daemon_threads(hardware.physical_cores)?;
    if gpu_policy == keyhog_scanner::gpu::GpuRuntimePolicy::Required {
        keyhog_scanner::gpu::require_gpu_preflight()
            .map_err(crate::orchestrator::daemon_gpu_preflight_failure)?;
    }

    let socket = socket.unwrap_or_else(default_socket_path); // LAW10: absent config => documented default; Tier-A knob, recall-irrelevant
    let (detectors, detector_rules_digest) = if detectors_cli_explicit {
        crate::orchestrator_config::validate_explicit_detector_path(&detectors_dir, true)?;
        let detectors_dir = crate::orchestrator_config::auto_discover_detectors(&detectors_dir)?;
        let detectors = crate::subcommands::detectors::load_detector_corpus(&detectors_dir)
            .with_context(|| {
                format!(
                    "daemon start: load detectors from {}",
                    detectors_dir.display()
                )
            })?;
        let rules_digest = keyhog_core::hex_encode(&keyhog_core::compute_spec_hash(&detectors));
        (detectors, rules_digest)
    } else {
        (
            keyhog_core::load_embedded_detectors_or_fail()
                .context("daemon start: load embedded detectors")?,
            keyhog_core::detector_digest().to_owned(),
        )
    };
    let (
        guard_hot_index_budget,
        guard_recon_config,
        guard_scanner_idle_timeout,
        guard_store_path,
        guard_scrub_interval,
    ) = load_guard_config();
    let options = server::ServerOptions {
        request_read_timeout: Duration::from_secs(request_timeout_secs),
        mass_service: mass,
        mass_gpu_primary_required: mass_gpu_primary,
    };
    server::run_with_backend_override(
        socket,
        detectors,
        detector_rules_digest,
        options,
        backend_override,
        guard_hot_index_budget,
        guard_recon_config,
        guard_scanner_idle_timeout,
        guard_store_path,
        guard_scrub_interval,
    )
    .await?;
    Ok(ExitCode::SUCCESS)
}

async fn stop(socket: Option<PathBuf>) -> Result<ExitCode> {
    let socket = socket.unwrap_or_else(default_socket_path); // LAW10: absent config => documented default; Tier-A knob, recall-irrelevant
                                                             // `connect_any_version`, not `connect`: a daemon left running across a
                                                             // `keyhog update` reports an older keyhog version, and the whole point of
                                                             // `daemon stop` is to clear exactly that stale daemon. The strict
                                                             // version-gated `connect` (used by the scan route) would REFUSE to talk to
                                                             // it, stranding the stale process; `stop` must still be able to shut it down.
    let connected = keyhog_profile::instrument_future(
        keyhog_profile::Stage::Preprocess,
        client::connect_any_version(&socket),
    )
    .await;
    let mut conn = match connected {
        Ok(conn) => conn,
        // The typed handshake failed. That does not mean nothing is running:
        // an older-wire or otherwise unreadable daemon still owns the socket
        // and still has to be stoppable (KH-552, KH-641).
        Err(typed_error) => return stop_over_control_channel(&socket, typed_error).await,
    };
    match conn.round_trip(&Request::Shutdown).await? {
        Response::Shutdown => {
            // Shutdown receipt publication.
            let _report_span = keyhog_profile::span(keyhog_profile::Stage::Reporting);
            eprintln!("keyhog daemon stopped");
            Ok(ExitCode::SUCCESS)
        }
        other => {
            anyhow::bail!(
                "daemon stop: protocol mismatch (got {}). Shutdown was not confirmed, and the \
                 incompatible daemon socket was left untouched. Stop the daemon with the matching \
                 KeyHog version or the service manager that started it before starting a replacement.",
                response_kind(&other)
            )
        }
    }
}

/// Stop a daemon this build cannot complete a typed handshake with.
///
/// Only reached after [`client::connect_any_version`] failed. It re-establishes
/// the connection over the version-independent administration channel, which
/// reads the reply envelope instead of the typed DTO, so a prior-wire daemon
/// remains stoppable. Absence stays absence: if nothing is listening, this
/// reports that and never claims a live peer was stopped.
async fn stop_over_control_channel(
    socket: &std::path::Path,
    typed_error: anyhow::Error,
) -> Result<ExitCode> {
    let (mut channel, identity) = match control::ControlChannel::connect(socket).await {
        Ok(connected) => connected,
        Err(error) if error.is_absent() => {
            return Err(error.into_error().context(format!(
                "daemon stop: no daemon at {} (already stopped?)",
                socket.display()
            )));
        }
        Err(error) => {
            anyhow::bail!(
                "daemon stop: a daemon at {} is live but {} over both the scan wire ({typed_error:#}) \
                 and the administration channel ({error}). Its socket was left untouched; stop the \
                 process through the service manager that started it.",
                socket.display(),
                error.kind(),
            );
        }
    };
    channel.shutdown().await.map_err(|error| {
        error.into_error().context(format!(
            "daemon stop: the live daemon at {} ({identity}) refused administration shutdown; \
             its socket was left untouched",
            socket.display()
        ))
    })?;
    let _report_span = keyhog_profile::span(keyhog_profile::Stage::Reporting);
    eprintln!(
        "keyhog daemon stopped over the administration channel: it is not scan-compatible with \
         this build ({identity}; {typed_error:#})"
    );
    Ok(ExitCode::SUCCESS)
}

async fn status(socket: Option<PathBuf>) -> Result<ExitCode> {
    let socket = socket.unwrap_or_else(default_socket_path); // LAW10: absent config => documented default; Tier-A knob, recall-irrelevant
                                                             // `connect_any_version`: `status` is diagnostic, an operator inspecting a
                                                             // daemon left running across an upgrade NEEDS to see it (so they can decide
                                                             // to restart it), not get a refusal. The strict version-gated `connect`
                                                             // would hide the very stale daemon the operator is trying to find.
    let connected = keyhog_profile::instrument_future(
        keyhog_profile::Stage::Preprocess,
        client::connect_any_version(&socket),
    )
    .await;
    let mut conn = match connected {
        Ok(conn) => conn,
        // A failed typed handshake used to be reported as "no daemon", so a
        // live wire-incompatible or malformed peer looked identical to an empty
        // socket path and the operator had nothing to act on (KH-641).
        Err(typed_error) => return status_over_control_channel(&socket, typed_error).await,
    };
    // Surface staleness LOUDLY: a daemon left running across a `keyhog update`
    // serves an OLDER detector corpus. The scan route already refuses it
    // (`connect` fails closed), but an operator running `status` must SEE that
    // the daemon is stale, otherwise the healthy-looking uptime line hides the
    // very reason their scans are silently routed in-process.
    let mut stale = conn.is_stale();
    let daemon_version = conn.daemon_version().to_string();
    let backend_policy = conn.backend_policy().to_string();
    let mass_service = conn.is_mass_service();
    let mut stale_reason = conn.stale_reason().map(str::to_string);
    let hello_warm_backend = conn
        .warm_backend_status()
        .context("daemon status: Hello omitted required warm-backend status")?
        .clone();
    match conn.round_trip(&Request::Health).await? {
        Response::Health {
            uptime_secs,
            scans_served,
            active_scans,
            detector_count,
            backend_recoveries,
            last_backend_fault,
            guard_roots_registered,
            guard_roots_current,
            guard_roots_blocked,
            guard_roots_degraded,
            guard_active_transactions,
            warm_backend,
        } => {
            if warm_backend.daemon_generation != hello_warm_backend.daemon_generation {
                anyhow::bail!(
                    "daemon status: daemon generation changed between Hello ({}) and Health ({}). Retry status; if it recurs, restart with `keyhog daemon stop && keyhog daemon start`.",
                    hello_warm_backend.daemon_generation,
                    warm_backend.daemon_generation
                );
            }
            if warm_backend.identity != hello_warm_backend.identity
                || warm_backend.required_backends != hello_warm_backend.required_backends
            {
                anyhow::bail!(
                    "daemon status: warm-route identity or required backend set changed within daemon generation {}; restart with `keyhog daemon stop && keyhog daemon start`",
                    warm_backend.daemon_generation
                );
            }
            let exact_mismatches = client::current_warm_backend_mismatches(&warm_backend)?;
            if !exact_mismatches.is_empty() {
                stale = true;
                let exact_reason = exact_mismatches.join("; ");
                stale_reason = Some(match stale_reason.take() {
                    Some(control_reason) if control_reason != exact_reason => {
                        format!("{control_reason}; {exact_reason}")
                    }
                    Some(control_reason) => control_reason,
                    None => exact_reason,
                });
            }
            if warm_backend.ready {
                println!(
                    "warm backend: ready · generation {} · engine {} · binary {} · detectors {} · config {} · GPU artifact {}",
                    warm_backend.daemon_generation,
                    warm_backend.identity.engine,
                    warm_backend.identity.binary_sha256,
                    warm_backend.identity.detector_rules_digest,
                    warm_backend.identity.config_digest,
                    match warm_backend.identity.gpu_artifact.as_deref() {
                        Some(artifact) => artifact,
                        None => "none",
                    }
                );
            } else {
                let (reason, repair) = match (
                    warm_backend.reason.as_deref(),
                    warm_backend.repair_command.as_deref(),
                ) {
                    (Some(reason), Some(repair)) => (reason.to_string(), repair.to_string()),
                    (Some(reason), None) => (
                        reason.to_string(),
                        crate::daemon::warm_identity::REPAIR_COMMAND.to_string(),
                    ),
                    (None, Some(repair)) => ("unknown".to_string(), repair.to_string()),
                    (None, None) => {
                        anyhow::bail!(
                            "daemon status: warm-backend status is internally inconsistent; restart with `{}`",
                            crate::daemon::warm_identity::REPAIR_COMMAND
                        )
                    }
                };
                println!(
                    "warm backend: not ready · generation {} · {reason} · repair `{repair}`",
                    warm_backend.daemon_generation
                );
            }
            println!(
                "keyhog daemon: uptime {}s · {} scans served · {} active · {} detectors",
                uptime_secs, scans_served, active_scans, detector_count
            );
            if guard_roots_registered > 0 {
                println!(
                    "guard: {} root(s) registered · {} current · {} blocked · {} degraded · {} active transaction(s)",
                    guard_roots_registered,
                    guard_roots_current,
                    guard_roots_blocked,
                    guard_roots_degraded,
                    guard_active_transactions,
                );
            }
            if mass_service {
                println!(
                    "scan scope: bounded directory, Git, archive, binary, remote, and cloud \
                     batches via --daemon=mass; warm stdin/single-file requests remain available. \
                     Daemon-local filesystems accept spec-bound Merkle incremental state. Baseline, \
                     verification, lockdown, and per-request scanner policy remain in-process."
                );
            } else {
                println!(
                    "scan scope: warm stdin/single-file requests only; start with --mass for \
                     bounded source transactions. Warm daemon requests return before baseline, \
                     Merkle state, verification, lockdown, and per-request scanner policy; those \
                     post-steps run in-process."
                );
            }
            if backend_policy == "autoroute" {
                println!("backend policy: autoroute (persisted warm-route evidence)");
            } else if backend_policy == "autoroute-degraded" {
                println!(
                    "backend policy: autoroute degraded (one or more workload routes quarantined; affected requests fail closed without scanning; run `keyhog calibrate-autoroute`)"
                );
            } else {
                println!(
                    "backend policy: forced {backend_policy} (daemon startup diagnostic override)"
                );
            }
            if let Some(fault) = last_backend_fault {
                println!(
                    "backend health: {} recovered request(s); last fault {} recovered {} byte(s) through {}. The affected route is quarantined until recalibration.",
                    backend_recoveries,
                    fault.failed_backend,
                    fault.recovered_bytes,
                    fault.recovery_backend,
                );
            } else if backend_policy == "autoroute-degraded" {
                println!(
                    "backend health: persisted autoroute quarantine loaded; affected requests fail closed without scanning"
                );
            } else {
                println!("backend health: no recovered runtime faults");
            }
            if stale {
                let palette = style::for_stderr();
                let reason = match stale_reason.as_deref() {
                    Some(reason) => reason,
                    None => anyhow::bail!(
                        "daemon status: client marked the daemon stale without an exact readiness or identity mismatch"
                    ),
                };
                eprintln!(
                    "{} this daemon's warm-route readiness/identity is not compatible with the client \
                     (daemon keyhog {}, client {}; {}): scan connections refuse it; \
                     `--daemon=auto` runs in process and `--daemon=on` fails until you restart it: \
                     `keyhog daemon stop && keyhog daemon start`.",
                    style::warn("WARN", &palette),
                    daemon_version,
                    env!("CARGO_PKG_VERSION"),
                    reason,
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

/// Report on a daemon this build cannot complete a typed handshake with.
///
/// Absence and a live incompatible peer are different operator situations and
/// get different verdicts and exits: nothing running is an error naming the
/// missing daemon, while a live peer is named with the identity the stable
/// administration channel could read, so the operator knows a process is still
/// holding the socket and can stop it (KH-641, KH-552).
async fn status_over_control_channel(
    socket: &std::path::Path,
    typed_error: anyhow::Error,
) -> Result<ExitCode> {
    let (_channel, identity) = match control::ControlChannel::connect(socket).await {
        Ok(connected) => connected,
        Err(error) if error.is_absent() => {
            return Err(error.into_error().context(format!(
                "daemon status: no daemon at {} (start one with `keyhog daemon start`)",
                socket.display()
            )));
        }
        Err(error) => {
            anyhow::bail!(
                "daemon status: a daemon at {} is live but {} over both the scan wire \
                 ({typed_error:#}) and the administration channel ({error}). Stop it with \
                 `keyhog daemon stop`, or through the service manager that started it.",
                socket.display(),
                error.kind(),
            );
        }
    };
    let palette = style::for_stderr();
    eprintln!(
        "{} a live daemon at {} is not scan-compatible with this build ({identity}; \
         {typed_error:#}). Scans will not route to it: `--daemon=auto` runs in process and \
         `--daemon=on` fails. Clear it with `keyhog daemon stop`.",
        style::warn("WARN", &palette),
        socket.display()
    );
    Ok(ExitCode::from(crate::exit_codes::EXIT_HEALTH_FAILURE))
}

/// Load the `[guard].hot_index_memory` setting from `.keyhog.toml`.
/// Returns `None` when the file is absent, the `[guard]` section is
/// absent, or the value cannot be parsed. Errors are logged as warnings
/// Load guard configuration from the KeyHog config file. Returns
/// the hot index memory budget and the reconciliation config.
/// Missing or invalid values fall back to defaults and do not
fn load_guard_config() -> (
    Option<usize>,
    keyhog_sources::guard::GuardReconciliationConfig,
    Option<u64>,
    Option<PathBuf>,
    Option<u64>,
) {
    let config_path = match crate::config::find_config_file(None) {
        Some(p) => p,
        None => {
            return (
                None,
                keyhog_sources::guard::GuardReconciliationConfig::default(),
                None,
                None,
                None,
            )
        }
    };
    let raw = match std::fs::read_to_string(&config_path) {
        Ok(content) => content,
        Err(e) => {
            tracing::warn!("daemon: failed to read {}: {}", config_path.display(), e);
            return (
                None,
                keyhog_sources::guard::GuardReconciliationConfig::default(),
                None,
                None,
                None,
            );
        }
    };
    let config: crate::config::ConfigFile = match toml::from_str(&raw) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("daemon: failed to parse {}: {}", config_path.display(), e);
            return (
                None,
                keyhog_sources::guard::GuardReconciliationConfig::default(),
                None,
                None,
                None,
            );
        }
    };
    let guard = match config.guard {
        Some(g) => g,
        None => {
            return (
                None,
                keyhog_sources::guard::GuardReconciliationConfig::default(),
                None,
                None,
                None,
            )
        }
    };
    let budget = guard
        .hot_index_memory
        .as_deref()
        .and_then(|s| match crate::value_parsers::parse_byte_size(s) {
            Ok(bytes) => Some(bytes),
            Err(err) => {
                tracing::warn!("daemon: invalid guard hot_index_memory '{s}': {err}");
                None
            }
        });
    let defaults = keyhog_sources::guard::GuardReconciliationConfig::default();
    let recon_config = keyhog_sources::guard::GuardReconciliationConfig {
        max_pending_events_per_root: guard
            .max_pending_events_per_root
            .unwrap_or(defaults.max_pending_events_per_root),
        coalesce_window_ms: guard
            .coalesce_window
            .as_deref()
            .and_then(parse_duration_ms)
            .unwrap_or(defaults.coalesce_window_ms),
        subtree_max_files: guard
            .subtree_max_files
            .unwrap_or(defaults.subtree_max_files),
        subtree_max_depth: guard
            .subtree_max_depth
            .unwrap_or(defaults.subtree_max_depth),
    };
    let scanner_idle_timeout_secs = guard
        .scanner_idle_timeout
        .as_deref()
        .and_then(parse_duration_secs);
    let state_path = guard.state_path.as_deref().and_then(expand_state_path);
    // Lockdown mode forbids on-disk persistence. If [lockdown] require = true
    // is set alongside [guard].state_path, reject the durable store and
    // operate in ephemeral mode.
    let state_path = if state_path.is_some()
        && config
            .lockdown
            .as_ref()
            .and_then(|l| l.require)
            .unwrap_or(false)
    {
        tracing::warn!(
            "daemon: [guard].state_path ignored because [lockdown] require = true; \
             guard operating in ephemeral mode (no durable persistence)"
        );
        None
    } else {
        state_path
    };

    let scrub_interval_secs = guard
        .scrub_interval
        .as_deref()
        .and_then(parse_duration_secs);
    (
        budget,
        recon_config,
        scanner_idle_timeout_secs,
        state_path,
        scrub_interval_secs,
    )
}

/// Expand a state path string, resolving `~` to the home directory.
/// Returns `None` if expansion fails.
fn expand_state_path(s: &str) -> Option<PathBuf> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s.starts_with('~') {
        let home = std::env::var_os("HOME")?;
        let expanded = s.replacen("~", std::path::Path::new(&home).to_str()?, 1);
        Some(PathBuf::from(expanded))
    } else {
        Some(PathBuf::from(s))
    }
}


/// Parse a human-readable duration string (e.g. "100ms", "5s", "1m").
/// Returns milliseconds. Returns `None` on parse failure.
fn parse_duration_ms(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let split = s.find(|c: char| !c.is_ascii_digit() && c != '.');
    let (num_str, unit_str) = match split {
        Some(idx) => (&s[..idx], s[idx..].trim()),
        None => (s, ""),
    };
    let num: f64 = num_str.parse().ok()?;
    let millis = match unit_str.to_lowercase().as_str() {
        "ms" => num,
        "s" => num * 1000.0,
        "m" => num * 1000.0 * 60.0,
        "h" => num * 1000.0 * 60.0 * 60.0,
        _ => return None,
    };
    Some(millis as u64)
}

/// Parse a human-readable duration string (e.g. "5m", "1h", "300s").
/// Returns seconds. Returns `None` on parse failure.
fn parse_duration_secs(s: &str) -> Option<u64> {
    parse_duration_ms(s).map(|ms| ms / 1000)
}
