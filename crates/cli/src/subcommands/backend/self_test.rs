//! `keyhog backend --self-test`: execute the real GPU probes and report a
//! pass/degrade/fail verdict.
//!
//! Unlike the heuristic report this DISPATCHES work, so its JSON is measured
//! evidence about this host rather than a capability guess.

use super::{is_known_vyre_lowering_gap, KEYHOG_GPU_MAX_BUFFER_CAP_MB};
use crate::exit_codes::{EXIT_BACKEND_SELF_TEST_FAILED, EXIT_SUCCESS};
use crate::style::{self, Palette};
use anyhow::Result;
use keyhog_scanner::hw_probe::{probe_hardware, HardwareCaps};
use serde::Serialize;
use std::process::ExitCode;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BackendSelfTestStatus {
    Pass,
    Fail,
    Warning,
    Known,
    Skip,
}

#[derive(Debug, Serialize)]
pub(crate) struct BackendSelfTestProbe {
    pub(crate) name: &'static str,
    pub(crate) status: BackendSelfTestStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) direct_matches: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) coalesced_matches: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) matches: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) backend_id: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) backend_route: Option<&'static str>,
}

impl BackendSelfTestProbe {
    fn pass(name: &'static str) -> Self {
        Self {
            name,
            status: BackendSelfTestStatus::Pass,
            message: None,
            direct_matches: None,
            coalesced_matches: None,
            matches: None,
            backend_id: None,
            backend_route: None,
        }
    }

    fn fail(name: &'static str, message: String) -> Self {
        Self {
            status: BackendSelfTestStatus::Fail,
            message: Some(message),
            ..Self::pass(name)
        }
    }

    fn known(name: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: BackendSelfTestStatus::Known,
            message: Some(message.into()),
            ..Self::pass(name)
        }
    }

    fn warning(name: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: BackendSelfTestStatus::Warning,
            message: Some(message.into()),
            ..Self::pass(name)
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BackendSelfTestRouteSelection {
    NotMeasured,
}

#[derive(Debug, Serialize)]
pub(crate) struct BackendSelfTestReport {
    pub(crate) ok: bool,
    pub(crate) status: BackendSelfTestStatus,
    pub(crate) exit_code: u8,
    pub(crate) gpu_available: bool,
    pub(crate) gpu_is_software: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) gpu_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) gpu_max_buffer_mb: Option<u64>,
    pub(crate) healthy_gpu_backends: Vec<&'static str>,
    /// A health probe does not measure comparative route performance.
    pub(crate) route_selection: BackendSelfTestRouteSelection,
    pub(crate) probes: Vec<BackendSelfTestProbe>,
}

impl BackendSelfTestReport {
    fn exit_code(&self) -> ExitCode {
        ExitCode::from(self.exit_code)
    }
}

pub(super) fn run_self_test(json: bool, require_gpu: bool, gpu_disabled: bool) -> Result<ExitCode> {
    let report = if gpu_disabled {
        disabled_gpu_self_test_report()
    } else {
        collect_self_test_report(require_gpu)
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_self_test_report(&report);
    }
    Ok(report.exit_code())
}

fn disabled_gpu_self_test_report() -> BackendSelfTestReport {
    BackendSelfTestReport {
        ok: true,
        status: BackendSelfTestStatus::Skip,
        exit_code: EXIT_SUCCESS,
        gpu_available: false,
        gpu_is_software: false,
        gpu_name: None,
        gpu_max_buffer_mb: None,
        healthy_gpu_backends: Vec::new(),
        route_selection: BackendSelfTestRouteSelection::NotMeasured,
        probes: vec![BackendSelfTestProbe {
            name: "gpu_adapter",
            status: BackendSelfTestStatus::Skip,
            message: Some("GPU probing disabled by --no-gpu".to_string()),
            direct_matches: None,
            coalesced_matches: None,
            matches: None,
            backend_id: None,
            backend_route: None,
        }],
    }
}

fn collect_self_test_report(require_gpu: bool) -> BackendSelfTestReport {
    // Self-test probe collection, profiled as preprocessing.
    let _collect_span = keyhog_profile::span(keyhog_profile::Stage::Preprocess);
    let hw = probe_hardware();
    let region_presence = keyhog_scanner::gpu::gpu_region_presence_self_test();
    let acquired_backends: Vec<_> = match &region_presence {
        Ok(report) => report.peers.iter().map(|peer| peer.backend).collect(),
        Err(error) => error.acquired_backends.clone(),
    };

    if (!hw.gpu_available || hw.gpu_is_software) && acquired_backends.is_empty() {
        return unavailable_gpu_self_test_report(hw, require_gpu);
    }

    let mut all_ok = true;
    let mut probes = Vec::with_capacity(1 + acquired_backends.len());
    let has_wgpu = acquired_backends.contains(&keyhog_scanner::ScanBackend::GpuWgpu);
    let healthy_gpu_backends = region_presence
        .as_ref()
        // LAW10: a region-presence error is emitted as the failing `gpu_region_presence` probe below; this list contains only successful peers.
        .ok()
        .map(|report| {
            report
                .peers
                .iter()
                .map(|peer| crate::orchestrator_config::backend_override_cli_value(peer.backend))
                .collect()
        })
        // LAW10: an errored region-presence report has no healthy peers and is surfaced as a failed self-test probe below.
        .unwrap_or_default();

    // Test 1: VYRE's direct match-triple literal-set diagnostic. Production
    // scanning uses the scratch region-presence API exercised end to end by
    // the next probe. A direct-mode failure with the classified lowering
    // signature is visible as KNOWN, but never exempts the production probe.
    if !has_wgpu {
        probes.push(BackendSelfTestProbe::warning(
            "vyre_literal_set",
            "WGPU peer was not acquired; direct WGPU match-triple diagnostics are not applicable",
        ));
    } else {
        match keyhog_scanner::gpu::vyre_gpu_self_test() {
            Ok(report) => {
                let mut probe = BackendSelfTestProbe::pass("vyre_literal_set");
                probe.direct_matches = Some(report.direct_matches);
                probe.coalesced_matches = Some(report.coalesced_matches);
                probes.push(probe);
            }
            Err(error) => {
                let known_lowering_gap = is_known_vyre_lowering_gap(&error);
                if known_lowering_gap {
                    probes.push(BackendSelfTestProbe::known(
                    "vyre_literal_set",
                    "VYRE IR lowering rejects the direct match-triple form; the production region-presence path is checked separately below",
                ));
                } else {
                    probes.push(BackendSelfTestProbe::warning(
                    "vyre_literal_set",
                    format!(
                        "VYRE direct match-triple diagnostic failed ({error}); production scan eligibility is determined by gpu_region_presence"
                    ),
                ));
                }
            }
        }
    }

    // Test 2: the production region-presence route. It builds a minimal
    // detector, dispatches through the same scanner path as a selected GPU
    // scan, and compares the final findings with the portable CPU reference.
    match region_presence {
        Ok(report) => {
            for peer in report.peers {
                let mut probe = BackendSelfTestProbe::pass("gpu_region_presence");
                probe.matches = Some(peer.matches);
                probe.backend_id = Some(peer.backend_id);
                probe.backend_route = Some(crate::orchestrator_config::backend_override_cli_value(
                    peer.backend,
                ));
                probes.push(probe);
            }
        }
        Err(error) => {
            probes.push(BackendSelfTestProbe::fail(
                "gpu_region_presence",
                error.to_string(),
            ));
            all_ok = false;
        }
    }

    BackendSelfTestReport {
        ok: all_ok,
        status: if all_ok {
            BackendSelfTestStatus::Pass
        } else {
            BackendSelfTestStatus::Fail
        },
        exit_code: if all_ok {
            0
        } else {
            EXIT_BACKEND_SELF_TEST_FAILED
        },
        gpu_available: hw.gpu_available || !acquired_backends.is_empty(),
        gpu_is_software: hw.gpu_is_software && acquired_backends.is_empty(),
        gpu_name: hw.gpu_name.clone(),
        gpu_max_buffer_mb: hw.gpu_vram_mb,
        healthy_gpu_backends,
        route_selection: BackendSelfTestRouteSelection::NotMeasured,
        probes,
    }
}

pub(super) fn unavailable_gpu_self_test_report(
    hw: &HardwareCaps,
    require_gpu: bool,
) -> BackendSelfTestReport {
    let reason = if !hw.gpu_available {
        "no GPU adapter detected"
    } else {
        "only software adapter (llvmpipe/lavapipe/swiftshader): won't be used for scans"
    };
    let status = if require_gpu {
        BackendSelfTestStatus::Fail
    } else {
        BackendSelfTestStatus::Skip
    };
    let message = if require_gpu {
        format!("--require-gpu requested but {reason}")
    } else {
        reason.to_string()
    };
    BackendSelfTestReport {
        ok: !require_gpu,
        status,
        exit_code: if require_gpu {
            EXIT_BACKEND_SELF_TEST_FAILED
        } else {
            EXIT_SUCCESS
        },
        gpu_available: hw.gpu_available,
        gpu_is_software: hw.gpu_is_software,
        gpu_name: hw.gpu_name.clone(),
        gpu_max_buffer_mb: hw.gpu_vram_mb,
        healthy_gpu_backends: Vec::new(),
        route_selection: BackendSelfTestRouteSelection::NotMeasured,
        probes: vec![BackendSelfTestProbe {
            name: "gpu_adapter",
            status,
            message: Some(message),
            direct_matches: None,
            coalesced_matches: None,
            matches: None,
            backend_id: None,
            backend_route: None,
        }],
    }
}

fn print_self_test_report(report: &BackendSelfTestReport) {
    let palette = style::for_stdout();
    println!("## GPU self-test");
    if report.status == BackendSelfTestStatus::Skip {
        let message = report
            .probes
            .first()
            .and_then(|probe| probe.message.as_deref())
            .unwrap_or("GPU self-test skipped"); // LAW10: absent name/label => display default; reporting-only, recall-safe
        println!("  {}: {message}", style::warn("SKIP", &palette));
        return;
    }

    for probe in &report.probes {
        print!("  {:<17} ... ", probe.name);
        match probe.status {
            BackendSelfTestStatus::Pass => print_pass_probe(probe, &palette),
            BackendSelfTestStatus::Fail => {
                let message = probe.message.as_deref().unwrap_or("probe failed"); // LAW10: absent name/label => display default; reporting-only, recall-safe
                println!("{}  {message}", style::fail("FAIL", &palette));
            }
            BackendSelfTestStatus::Warning => {
                let message = probe.message.as_deref().unwrap_or("diagnostic warning"); // LAW10: absent probe detail => reporting-only display label; status remains visible
                println!("{}  {message}", style::warn("WARN", &palette));
            }
            BackendSelfTestStatus::Known => {
                let message = probe.message.as_deref().unwrap_or("known limitation"); // LAW10: absent name/label => display default; reporting-only, recall-safe
                println!("{} {message}.", style::warn("KNOWN", &palette));
            }
            BackendSelfTestStatus::Skip => {
                let message = probe.message.as_deref().unwrap_or("probe skipped"); // LAW10: absent name/label => display default; reporting-only, recall-safe
                println!("{}  {message}", style::warn("SKIP", &palette));
            }
        }
    }

    println!();
    if report.ok {
        println!(
            "{} GPU self-test passed, scans on this box can route to GPU.",
            style::pass("PASS", &palette)
        );
        println!(
            "  Self-test proves backend health only. `keyhog backend --autoroute` shows the measured route."
        );
    } else {
        let stderr_palette = style::for_stderr();
        eprintln!(
            "{} GPU self-test failed; GPU routes are unavailable until fixed. \
             Use --backend simd/cpu or --no-gpu for an explicit CPU-only scan.",
            style::fail("FAIL", &stderr_palette)
        );
    }
}

fn print_pass_probe(probe: &BackendSelfTestProbe, palette: &Palette) {
    let pass = style::pass("PASS", palette);
    match probe.name {
        "vyre_literal_set" => println!(
            "{pass}  (direct={}, coalesced={})",
            format_probe_metric(probe.direct_matches),
            format_probe_metric(probe.coalesced_matches)
        ),
        "gpu_region_presence" => println!(
            "{pass}  (matches={}, route={}, backend={})",
            format_probe_metric(probe.matches),
            probe.backend_route.unwrap_or("unknown"), // LAW10: absent name/label => display default; reporting-only, recall-safe
            probe.backend_id.unwrap_or("unknown") // LAW10: absent name/label => display default; reporting-only, recall-safe
        ),
        _ => println!("{pass}"),
    }
}

pub(super) fn format_probe_metric<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "unknown".to_string(), |value| value.to_string())
}

pub(super) fn render_self_test_json_for_contract(report: &BackendSelfTestReport) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(Into::into)
}

pub(super) fn format_gpu_max_buffer(max_buffer_mb: u64) -> String {
    let base = if max_buffer_mb >= 1024 {
        format!("{} GB", max_buffer_mb / 1024)
    } else {
        format!("{max_buffer_mb} MB")
    };
    if max_buffer_mb >= KEYHOG_GPU_MAX_BUFFER_CAP_MB {
        format!(">={base} (keyhog cap; wgpu max_buffer_size)")
    } else {
        format!("{base} (wgpu max_buffer_size)")
    }
}
