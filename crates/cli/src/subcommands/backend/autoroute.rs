//! `keyhog backend --autoroute`: read-only rendering of the persisted
//! autoroute calibration cache.
//!
//! Every value printed here comes from measured, persisted calibration
//! evidence, never from a hardware heuristic, so operators can tell proof
//! from diagnosis by which subcommand produced the output.

use crate::exit_codes::EXIT_HEALTH_FAILURE;
use crate::style;
use anyhow::Result;
use std::process::ExitCode;

/// `keyhog backend --autoroute`: render the persisted autoroute calibration
/// cache so an operator can see which resolved configs and workload buckets are
/// calibrated and which invalid states block automatic scans. Read-only.
pub(super) fn run_autoroute_inspection(
    json: bool,
    autoroute_cache: Option<&str>,
    verbose: bool,
) -> Result<ExitCode> {
    let path = crate::autoroute_cache_path::resolve_autoroute_cache_path(autoroute_cache)
        .map_err(|message| anyhow::anyhow!(message))?;
    // Calibration-cache inspection, profiled as an incremental lookup.
    let inspection = {
        let _cache_span = keyhog_profile::span(keyhog_profile::Stage::IncrementalLookup);
        crate::orchestrator::inspect_autoroute_cache(path.as_deref())
    };
    let health = inspection.readiness();
    let exit = autoroute_inspection_exit_code(health);

    if json {
        let mut value = serde_json::to_value(&inspection)?;
        value["health"] = serde_json::Value::String(health.as_str().to_string());
        value["repair_command"] = health
            .repair_command()
            .map(|command| serde_json::Value::String(command.to_string()))
            // LAW10: JSON `null` is the explicit serialized representation of an absent recovery command, not a hidden replacement.
            .unwrap_or(serde_json::Value::Null);
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(exit);
    }

    let p = style::for_stdout();
    println!("{}## autoroute calibration cache{}", p.bold, p.reset);
    println!(
        "  health:          {}{}{}",
        p.cyan,
        health.as_str(),
        p.reset
    );
    match &inspection.path {
        Some(path) => println!("  path:            {path}"),
        None => println!("  path:            (disabled)"),
    }

    // Report cache faults, then distinguish route-blocking multi-backend state
    // from an unused artifact in a single-backend build.
    if let Some(error) = &inspection.error {
        println!("  status:          {}{}{}", p.yellow, error, p.reset);
        println!();
        if !inspection.calibration_required {
            let direct_backend = direct_backend_or_error(inspection.direct_backend)?;
            println!(
                "This cache artifact is not used by automatic scans in a single-backend build. \
                 Automatic scans resolve {direct_backend} directly."
            );
            return Ok(exit);
        }
        println!(
            "Repair: `{}`.",
            health
                .required_repair_command()
                .map_err(anyhow::Error::msg)?
        );
        println!("An explicit `--backend` is a diagnostic override, not autoroute evidence.");
        return Ok(exit);
    }

    // Cache absence is unhealthy only when this build has a routing choice.
    if !inspection.present {
        if !inspection.calibration_required {
            let direct_backend = direct_backend_or_error(inspection.direct_backend)?;
            println!(
                "  status:          {}calibration not required{} (single compiled backend)",
                p.green, p.reset
            );
            println!();
            println!(
                "Automatic scans resolve {direct_backend} directly. No autoroute cache is needed \
                 for this build."
            );
            return Ok(exit);
        }
        println!(
            "  status:          {}not calibrated yet{}",
            p.yellow, p.reset
        );
        println!();
        println!(
            "No autoroute cache exists here yet, so automatic scans fail closed without \
             selecting a backend or scanning input. Repair: `{}`. An explicit `--backend` is \
             a diagnostic override, not autoroute evidence.",
            health
                .required_repair_command()
                .map_err(anyhow::Error::msg)?
        );
        return Ok(exit);
    }

    if let Some(version) = inspection.version {
        println!("  schema version:  {version}");
    }
    if let (Some(binary), Some(git)) = (&inspection.binary_version, &inspection.git_hash) {
        println!("  built for:       keyhog {binary} ({git})");
    }
    if let Some(digest) = &inspection.executable_sha256 {
        println!("  executable hash: sha256:{digest}");
    }
    match inspection.identity_matches_build {
        Some(true) => println!(
            "  identity:        {}matches this build{} (host/detector/rules verified at scan time)",
            p.green, p.reset
        ),
        Some(false) => {
            println!(
                "  identity:        {}STALE (real scans will reject this cache){}",
                p.red, p.reset
            );
            if let Some(reason) = &inspection.identity_mismatch_reason {
                println!("                   {reason}");
            }
            println!(
                "  repair:          `{}`",
                health
                    .required_repair_command()
                    .map_err(anyhow::Error::msg)?
            );
        }
        None => {}
    }
    if let Some(detector) = &inspection.detector_digest {
        println!("  detector digest: {detector}");
    }
    if let Some(rules) = &inspection.rules_digest {
        println!("  rules digest:    {rules}");
    }

    println!();
    let total_decisions: usize = inspection.configs.iter().map(|c| c.decision_count).sum();
    println!(
        "{}{} calibrated config(s), {} workload decision(s){}",
        p.bold,
        inspection.configs.len(),
        total_decisions,
        p.reset
    );
    let mut one_shot_gpu = 0usize;
    let mut one_shot_cuda = 0usize;
    let mut one_shot_metal = 0usize;
    let mut one_shot_wgpu = 0usize;
    let mut daemon_gpu = 0usize;
    let mut daemon_cuda = 0usize;
    let mut daemon_metal = 0usize;
    let mut daemon_wgpu = 0usize;
    let mut vyre_gpu_receipts = 0usize;
    let mut first_gpu_workload = None;
    for config in &inspection.configs {
        for decision in &config.decisions {
            if let Some(backend) = keyhog_scanner::hw_probe::parse_backend_str(&decision.backend) {
                if backend.is_gpu() {
                    one_shot_gpu += 1;
                    first_gpu_workload.get_or_insert(decision.workload.clone());
                    match backend {
                        keyhog_scanner::ScanBackend::GpuCuda => one_shot_cuda += 1,
                        keyhog_scanner::ScanBackend::GpuMetal => one_shot_metal += 1,
                        keyhog_scanner::ScanBackend::GpuWgpu => one_shot_wgpu += 1,
                        _ => {}
                    }
                }
            }
            if let Some(backend) =
                keyhog_scanner::hw_probe::parse_backend_str(&decision.daemon_backend)
            {
                if backend.is_gpu() {
                    daemon_gpu += 1;
                    match backend {
                        keyhog_scanner::ScanBackend::GpuCuda => daemon_cuda += 1,
                        keyhog_scanner::ScanBackend::GpuMetal => daemon_metal += 1,
                        keyhog_scanner::ScanBackend::GpuWgpu => daemon_wgpu += 1,
                        _ => {}
                    }
                }
            }
            vyre_gpu_receipts += decision
                .candidate_receipts
                .iter()
                .filter(|receipt| {
                    keyhog_scanner::hw_probe::parse_backend_str(&receipt.backend)
                        .is_some_and(|backend| backend.is_gpu())
                })
                .count();
        }
    }
    println!(
        "  route summary: one-shot GPU {one_shot_gpu}/{total_decisions} (CUDA {one_shot_cuda}, Metal {one_shot_metal}, WGPU {one_shot_wgpu}); daemon GPU {daemon_gpu}/{total_decisions} (CUDA {daemon_cuda}, Metal {daemon_metal}, WGPU {daemon_wgpu}); VYRE candidate receipts {vyre_gpu_receipts}"
    );
    if inspection.runtime_fault_count > 0 {
        println!(
            "  runtime health:  {}{} quarantined workload decision(s){}; repair: `keyhog calibrate-autoroute`",
            p.yellow, inspection.runtime_fault_count, p.reset
        );
    } else {
        println!(
            "  runtime health:  {}no quarantined routes{}",
            p.green, p.reset
        );
    }
    if let Some(workload) = first_gpu_workload {
        println!("  first calibrated GPU bucket: {workload}");
    } else {
        println!(
            "  GPU route: no calibrated workload currently selects GPU; run `keyhog calibrate-autoroute` after fixing GPU health"
        );
    }
    println!("  recalibrate:      `keyhog calibrate-autoroute` (measures all eligible GPU peers)");
    if !verbose {
        println!("  details:           omitted; add `--verbose` for every workload receipt");
        return Ok(exit);
    }
    for config in &inspection.configs {
        println!();
        println!(
            "  {}config {}{}  -  {} decision(s), {} quarantined",
            p.cyan,
            config.config_digest,
            p.reset,
            config.decision_count,
            config.quarantined_decision_count,
        );
        println!("    host: {}", config.host);
        for decision in &config.decisions {
            let measurement_receipts = decision
                .measured_points
                .iter()
                .map(|point| {
                    format!(
                        "{}B/{}chunk(s):generator={}:payload={}:shape={}",
                        point.sample_bytes,
                        point.sample_chunks,
                        point.measurement_generator,
                        point.payload_digest,
                        point.measurement_shape_digest,
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            let parity_receipts = decision
                .candidate_receipts
                .iter()
                .map(|receipt| {
                    let pipeline = receipt
                        .gpu_dispatch_capability
                        .as_deref()
                        .map(|capability| {
                            let input = receipt.gpu_slot_input_capacity_bytes.unwrap_or_else(|| {
                                panic!("validated GPU receipt has an input capacity")
                            });
                            let matches = receipt.gpu_slot_match_capacity.unwrap_or_else(|| {
                                panic!("validated GPU receipt has a match capacity")
                            });
                            format!("/pipeline={capability}:input={input}:matches={matches}")
                        })
                        .unwrap_or_default();
                    format!(
                        "{}+plain-localizer={}+keyword-localizer={}+gpu-pipeline-depth={}:result={}/trials={}/receipt={}{pipeline}",
                        receipt.backend,
                        receipt.phase2_plain_localizer,
                        receipt.phase2_keyword_localizer,
                        receipt.gpu_pipeline_depth,
                        receipt.correctness_digest,
                        receipt.completed_trials,
                        receipt.evidence_digest,
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            let route_timings = decision
                .route_timings
                .iter()
                .map(|timing| {
                    let warm = timing
                        .warm_ms
                        .map(|ms| format!("/warm={ms}ms"))
                        // LAW10: an absent optional warm-up measurement has no display suffix; the measured cold route remains unchanged and visible.
                        .unwrap_or_default();
                    format!(
                        "{}[plain={},keyword={},gpu-depth={}]={}ms{warm}",
                        timing.backend,
                        timing.phase2_plain_localizer,
                        timing.phase2_keyword_localizer,
                        timing.gpu_pipeline_depth,
                        timing.one_shot_ms
                    )
                })
                .collect::<Vec<_>>()
                .join(" ");
            let margin = decision
                .selected_margin_ns
                .map(|ns| format!(" margin={}µs", ns / 1_000))
                .unwrap_or_default(); // LAW10: display-only optional derived margin; recall-safe
            let daemon_margin = decision
                .daemon_selected_margin_ns
                .map(|ns| format!(" margin={}µs", ns / 1_000))
                .unwrap_or_default(); // LAW10: display-only optional derived margin; recall-safe
            println!("    {}", decision.workload);
            if decision.runtime_quarantined {
                println!(
                    "        runtime:     {}QUARANTINED{} backend={} fault={}",
                    p.yellow,
                    p.reset,
                    decision
                        .runtime_fault_backend
                        .as_deref()
                        // LAW10: this display sentinel makes missing runtime-fault route metadata explicit in operator output.
                        .unwrap_or("unknown"),
                    decision
                        .runtime_fault_reason
                        .as_deref()
                        // LAW10: this display sentinel makes missing runtime-fault evidence explicit in operator output.
                        .unwrap_or("not recorded"),
                );
            }
            println!(
                "        evidence age: {} (calibrated_at_unix_ms={})",
                render_age_ms(decision.calibration_age_ms),
                decision.calibrated_at_unix_ms
            );
            println!("        measurements: {measurement_receipts}");
            println!("        parity:      {parity_receipts}");
            println!(
                "        one-shot -> {}+plain-localizer={}+keyword-localizer={}+gpu-pipeline-depth={}  {}[{} B / {} chunk(s);{} basis={}]{}",
                decision.backend,
                decision.phase2_plain_localizer,
                decision.phase2_keyword_localizer,
                decision.gpu_pipeline_depth,
                p.dim,
                decision.sample_bytes,
                decision.sample_chunks,
                margin,
                decision.selection_basis,
                p.reset
            );
            println!(
                "        daemon   -> {}+plain-localizer={}+keyword-localizer={}+gpu-pipeline-depth={}  {}[warm evidence{}; basis={}]{}",
                decision.daemon_backend,
                decision.daemon_phase2_plain_localizer,
                decision.daemon_phase2_keyword_localizer,
                decision.daemon_gpu_pipeline_depth,
                p.dim,
                daemon_margin,
                decision.daemon_selection_basis,
                p.reset
            );
            println!("        route timings: {route_timings}");
        }
    }
    Ok(exit)
}

fn autoroute_inspection_exit_code(health: crate::orchestrator::AutorouteReadiness) -> ExitCode {
    use crate::orchestrator::AutorouteReadiness;

    match health {
        AutorouteReadiness::Direct | AutorouteReadiness::Ready => ExitCode::SUCCESS,
        AutorouteReadiness::Quarantined
        | AutorouteReadiness::CalibrationRequired
        | AutorouteReadiness::Disabled
        | AutorouteReadiness::Stale
        | AutorouteReadiness::Invalid => ExitCode::from(EXIT_HEALTH_FAILURE),
    }
}

fn direct_backend_or_error(direct_backend: Option<&'static str>) -> Result<&'static str> {
    direct_backend.ok_or_else(|| {
        anyhow::anyhow!(
            "autoroute inspection omitted the direct backend for a single-backend build"
        )
    })
}

fn render_age_ms(age_ms: u128) -> String {
    const SECOND_MS: u128 = 1_000;
    const MINUTE_MS: u128 = 60 * SECOND_MS;
    const HOUR_MS: u128 = 60 * MINUTE_MS;
    const DAY_MS: u128 = 24 * HOUR_MS;

    if age_ms < SECOND_MS {
        format!("{age_ms}ms")
    } else if age_ms < MINUTE_MS {
        format!("{}s", age_ms / SECOND_MS)
    } else if age_ms < HOUR_MS {
        format!("{}m", age_ms / MINUTE_MS)
    } else if age_ms < DAY_MS {
        format!("{}h", age_ms / HOUR_MS)
    } else {
        format!("{}d", age_ms / DAY_MS)
    }
}
