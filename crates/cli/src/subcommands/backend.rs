//! `keyhog backend` - inspect backend selection inputs for this hardware.
//!
//! Prints detected hardware (cores, SIMD, GPU, Hyperscan, io_uring), the
//! steady-state heuristic backend for this box, and a routing-decision matrix
//! at the documented crossover thresholds. Normal `scan --backend auto`
//! consumes persisted install-time calibration evidence rather than this fixed
//! heuristic table.
//!
//! Backend overrides are explicit scan flags (`keyhog scan --backend ...`);
//! this report shows the hardware/workload heuristic matrix.

use crate::args::BackendArgs;
use anyhow::Result;
use std::process::ExitCode;

mod autoroute;
mod report;
mod self_test;

use autoroute::run_autoroute_inspection;
use report::print_backend_report;
use self_test::run_self_test;
use std::sync::LazyLock;

#[cfg(test)]
use self_test::{unavailable_gpu_self_test_report, BackendSelfTestStatus};

const KEYHOG_GPU_MAX_BUFFER_CAP_MB: u64 = 256 * 1024;

/// Tier-B VYRE self-test error classification data loaded from
/// `rules/gpu-lowering-gaps.toml`. Both backend self-test and doctor use
/// [`is_known_vyre_lowering_gap`], so the operator-visible health surfaces
/// classify the same VYRE lowering error identically.
#[derive(serde::Deserialize)]
pub(crate) struct GpuLoweringGapRules {
    /// Substrings that mark a known VYRE direct-match lowering limitation. The
    /// production region-presence path has a separate mandatory probe.
    pub(crate) lowering_gap_markers: Vec<String>,
}

fn parse_gpu_lowering_gap_rules(raw: &str) -> Result<GpuLoweringGapRules, String> {
    toml::from_str::<GpuLoweringGapRules>(raw).map_err(|error| error.to_string())
}

/// The embedded Tier-B classification set. A parse failure or an EMPTY marker
/// set is a BUILD bug in bundled data, not a runtime condition, so it panics
/// in the `LazyLock` init (fail closed). An empty set would silently treat every
/// GPU self-test error as a hard FAIL, breaking the installer/doctor on hosts
/// whose production region-presence scans are correct (Law 10: never
/// silently degrade a hardcoded/bundled classification into a scanner-off state).
pub(crate) static GPU_LOWERING_GAP_RULES: LazyLock<GpuLoweringGapRules> = LazyLock::new(|| {
    match parse_gpu_lowering_gap_rules(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/rules/gpu-lowering-gaps.toml"
    ))) {
        Ok(rules) => {
            assert!(
                !rules.lowering_gap_markers.is_empty(),
                "rules/gpu-lowering-gaps.toml must define non-empty lowering_gap_markers; \
                 an empty set would misclassify every VYRE self-test error as a hard FAIL"
            );
            rules
        }
        Err(error) => panic!(
            "rules/gpu-lowering-gaps.toml is invalid: {error}. \
             Fix the bundled Tier-B GPU-lowering-gap classification data."
        ),
    }
});

/// True when the diagnostic VYRE direct-match probe names a known IR-lowering
/// gap. The separate production region-presence probe still must pass.
pub(crate) fn is_known_vyre_lowering_gap(error: &str) -> bool {
    GPU_LOWERING_GAP_RULES
        .lowering_gap_markers
        .iter()
        .any(|marker| error.contains(marker))
}

pub(crate) fn run(args: BackendArgs) -> Result<ExitCode> {
    let gpu_policy = if args.require_gpu {
        keyhog_scanner::gpu::GpuRuntimePolicy::Required
    } else if args.no_gpu {
        keyhog_scanner::gpu::GpuRuntimePolicy::Disabled
    } else {
        keyhog_scanner::gpu::GpuRuntimePolicy::Auto
    };
    keyhog_scanner::gpu::set_gpu_runtime_policy(gpu_policy);
    if args.self_test {
        return run_self_test(args.json, args.require_gpu, args.no_gpu);
    }
    if args.autoroute {
        return run_autoroute_inspection(args.json, args.autoroute_cache.as_deref(), args.verbose);
    }
    print_backend_report(&args)?;
    Ok(ExitCode::SUCCESS)
}

#[doc(hidden)]
pub(crate) mod testing {
    use anyhow::Result;

    pub(crate) fn render_failing_region_presence_probe_json() -> Result<String> {
        let report = super::self_test::BackendSelfTestReport {
            ok: false,
            status: super::self_test::BackendSelfTestStatus::Fail,
            exit_code: crate::exit_codes::EXIT_BACKEND_SELF_TEST_FAILED,
            gpu_available: true,
            gpu_is_software: false,
            gpu_name: Some("NVIDIA GeForce RTX 5090".to_string()),
            gpu_max_buffer_mb: Some(262_144),
            healthy_gpu_backends: vec!["gpu-wgpu"],
            route_selection: super::self_test::BackendSelfTestRouteSelection::NotMeasured,
            probes: vec![
                super::self_test::BackendSelfTestProbe {
                    name: "vyre_literal_set",
                    status: super::self_test::BackendSelfTestStatus::Known,
                    message: Some(
                        "vyre IR lowering rejects literal_set's subgroup form".to_string(),
                    ),
                    direct_matches: None,
                    coalesced_matches: None,
                    matches: None,
                    backend_id: None,
                    backend_route: None,
                },
                super::self_test::BackendSelfTestProbe {
                    name: "gpu_region_presence",
                    status: super::self_test::BackendSelfTestStatus::Fail,
                    message: Some("GPU region-presence dispatch failed".to_string()),
                    direct_matches: None,
                    coalesced_matches: None,
                    matches: None,
                    backend_id: Some("cuda"),
                    backend_route: Some("gpu-cuda"),
                },
                super::self_test::BackendSelfTestProbe {
                    name: "gpu_region_presence",
                    status: super::self_test::BackendSelfTestStatus::Pass,
                    message: None,
                    direct_matches: None,
                    coalesced_matches: None,
                    matches: Some(1),
                    backend_id: Some("wgpu"),
                    backend_route: Some("gpu-wgpu"),
                },
            ],
        };

        super::self_test::render_self_test_json_for_contract(&report)
    }

    pub(crate) fn format_gpu_max_buffer(max_buffer_mb: u64) -> String {
        super::self_test::format_gpu_max_buffer(max_buffer_mb)
    }

    pub(crate) fn format_probe_count_metric(value: Option<usize>) -> String {
        super::self_test::format_probe_metric(value)
    }

    pub(crate) fn format_probe_mb_metric(value: Option<u64>) -> String {
        super::self_test::format_probe_metric(value)
    }
}

#[cfg(test)]
mod tests;
