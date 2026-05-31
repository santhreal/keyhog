//! `keyhog backend` - inspect the auto-routing decision for this hardware.
//!
//! Prints detected hardware (cores, SIMD, GPU, Hyperscan, io_uring), the
//! steady-state backend the orchestrator would pick on this box, and a
//! routing-decision matrix at the documented crossover thresholds. Useful
//! for confirming the GPU is actually being routed to on a build where you
//! expect it (CI matrix, post-install smoke check).
//!
//! Honors the `KEYHOG_BACKEND={gpu,simd,cpu}` env var override.

use crate::args::BackendArgs;
use anyhow::Result;
use keyhog_scanner::hw_probe::{
    classify_gpu_tier, gpu_min_bytes_for_tier, gpu_solo_bytes_for_tier, probe_hardware,
    select_backend, thresholds, GpuTier,
};
use serde::Serialize;
use std::process::ExitCode;

/// Exit code for `backend --self-test` when one of the GPU dispatch
/// proofs fails. Distinct from the scan-side exit codes so a CI
/// release gate can fail closed on real GPU breakage.
const EXIT_SELF_TEST_FAILED: u8 = 4;

pub fn run(args: BackendArgs) -> Result<ExitCode> {
    if args.self_test {
        return run_self_test(args.json);
    }
    print_backend_report(&args)?;
    Ok(ExitCode::SUCCESS)
}

fn print_backend_report(args: &BackendArgs) -> Result<()> {
    let hw = probe_hardware();

    println!("## hardware");
    println!("  physical_cores:    {}", hw.physical_cores);
    println!("  logical_cores:     {}", hw.logical_cores);
    println!(
        "  simd:              {}",
        if hw.has_avx512 {
            "AVX-512"
        } else if hw.has_avx2 {
            "AVX2"
        } else if hw.has_neon {
            "NEON"
        } else {
            "scalar"
        }
    );
    println!(
        "  gpu:               {} {}",
        if hw.gpu_available {
            hw.gpu_name.as_deref().unwrap_or("yes")
        } else {
            "not detected"
        },
        if hw.gpu_is_software {
            "(software renderer: disabled)"
        } else {
            ""
        }
    );
    if let Some(buf) = hw.gpu_vram_mb {
        // `gpu_vram_mb` is actually `wgpu::Limits::max_buffer_size`,
        // not VRAM (wgpu has no portable VRAM query). Display under
        // the accurate label so this report doesn't claim an 8 GB
        // laptop GPU has 256 GB of memory.
        if buf >= 1024 {
            println!("  gpu_max_buffer:    {} GB", buf / 1024);
        } else {
            println!("  gpu_max_buffer:    {buf} MB");
        }
    }
    if let Some(mem) = hw.total_memory_mb {
        println!("  total_memory:      {mem} MB");
    }
    println!(
        "  hyperscan:         {}",
        if hw.hyperscan_available {
            "compiled-in"
        } else {
            "absent"
        }
    );
    println!(
        "  io_uring:          {}",
        if hw.io_uring_available {
            "available"
        } else {
            "n/a"
        }
    );

    if let Ok(forced) = std::env::var("KEYHOG_BACKEND") {
        println!();
        println!("## env override");
        println!("  KEYHOG_BACKEND={forced}");
    }

    let pat = args.patterns;
    println!();
    println!("## routing decision matrix (pattern_count = {pat})");
    // Tier-aware: pull the active GPU's actual thresholds so the
    // matrix reflects what THIS box would route to, not the legacy
    // low-tier defaults that didn't apply to RTX 40/50-class adapters.
    let active_tier = classify_gpu_tier(hw.gpu_name.as_deref());
    let active_min = gpu_min_bytes_for_tier(active_tier);
    let active_solo = gpu_solo_bytes_for_tier(active_tier);
    let scenarios: &[(u64, &str)] = &[
        (0, "idle (size=0)"),
        (4 * 1024, "4 KiB single chunk"),
        (1024 * 1024, "1 MiB chunk"),
        (2 * 1024 * 1024, "2 MiB chunk (high-tier min)"),
        (4 * 1024 * 1024, "4 MiB chunk"),
        (
            16 * 1024 * 1024,
            "16 MiB chunk (high-tier solo / mid-tier min)",
        ),
        (active_min.saturating_sub(1), "just under tier min_bytes"),
        (active_min, "tier min_bytes exactly"),
        (active_solo.saturating_sub(1), "just under tier solo cap"),
        (active_solo, "tier solo cap exactly"),
        (1024 * 1024 * 1024, "1 GiB single chunk"),
    ];
    for (bytes, label) in scenarios {
        let backend = select_backend(hw, *bytes, pat);
        println!("  {:<42} → {}", label, backend.label());
    }

    if let Some(bytes) = args.probe_bytes {
        println!();
        let backend = select_backend(hw, bytes, pat);
        println!("## --probe-bytes {bytes}");
        println!("  → {}", backend.label());
    }

    println!();
    println!("## gpu tier (heuristic from adapter name)");
    let tier = classify_gpu_tier(hw.gpu_name.as_deref());
    let tier_label = match tier {
        GpuTier::High => "High (RTX 40/50, A100/H100, M-Max)",
        GpuTier::Mid => "Mid (RTX 20/30, GTX 16, Arc, M-Pro/base)",
        GpuTier::Low => "Low / unknown",
    };
    println!("  classified:                {tier_label}");
    println!(
        "  effective min bytes:       {} (tier {:?})",
        fmt_bytes(gpu_min_bytes_for_tier(tier)),
        tier
    );
    println!(
        "  effective solo cap:        {}",
        fmt_bytes(gpu_solo_bytes_for_tier(tier))
    );

    println!();
    println!("## thresholds (per-tier table)");
    println!(
        "  high tier  min/solo       = {} / {}",
        fmt_bytes(thresholds::GPU_MIN_BYTES_HIGH_TIER),
        fmt_bytes(thresholds::GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER)
    );
    println!(
        "  mid tier   min/solo       = {} / {}",
        fmt_bytes(thresholds::GPU_MIN_BYTES_MID_TIER),
        fmt_bytes(thresholds::GPU_BYTES_BREAKEVEN_SOLO_MID_TIER)
    );
    println!(
        "  low tier   min/solo       = {} / {}",
        fmt_bytes(thresholds::GPU_MIN_BYTES),
        fmt_bytes(thresholds::GPU_BYTES_BREAKEVEN_SOLO)
    );
    println!(
        "  GPU_PATTERN_BREAKEVEN     = {} patterns",
        thresholds::GPU_PATTERN_BREAKEVEN
    );

    println!();
    println!(
        "Force a backend with: KEYHOG_BACKEND={{gpu|simd|cpu}}  (or `keyhog scan --backend ...`)"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendSelfTestStatus {
    Pass,
    Fail,
    Known,
    Skip,
}

#[derive(Debug, Serialize)]
pub struct BackendSelfTestProbe {
    pub name: &'static str,
    pub status: BackendSelfTestStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scores: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_buffer_mb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_matches: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coalesced_matches: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_id: Option<&'static str>,
}

impl BackendSelfTestProbe {
    fn pass(name: &'static str) -> Self {
        Self {
            name,
            status: BackendSelfTestStatus::Pass,
            message: None,
            adapter_name: None,
            scores: None,
            max_buffer_mb: None,
            direct_matches: None,
            coalesced_matches: None,
            matches: None,
            backend_id: None,
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
}

#[derive(Debug, Serialize)]
pub struct BackendSelfTestReport {
    pub ok: bool,
    pub status: BackendSelfTestStatus,
    pub exit_code: u8,
    pub gpu_available: bool,
    pub gpu_is_software: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_max_buffer_mb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_backend: Option<&'static str>,
    pub probes: Vec<BackendSelfTestProbe>,
}

impl BackendSelfTestReport {
    fn exit_code(&self) -> ExitCode {
        ExitCode::from(self.exit_code)
    }
}

fn run_self_test(json: bool) -> Result<ExitCode> {
    let report = collect_self_test_report();
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_self_test_report(&report);
    }
    Ok(report.exit_code())
}

fn collect_self_test_report() -> BackendSelfTestReport {
    let hw = probe_hardware();

    if !hw.gpu_available || hw.gpu_is_software {
        let reason = if !hw.gpu_available {
            "no GPU adapter detected"
        } else {
            "only software adapter (llvmpipe/lavapipe/swiftshader): won't be used for scans"
        };
        return BackendSelfTestReport {
            ok: true,
            status: BackendSelfTestStatus::Skip,
            exit_code: 0,
            gpu_available: hw.gpu_available,
            gpu_is_software: hw.gpu_is_software,
            gpu_name: hw.gpu_name.clone(),
            gpu_max_buffer_mb: hw.gpu_vram_mb,
            recommended_backend: Some("simd-regex"),
            probes: vec![BackendSelfTestProbe {
                name: "gpu_adapter",
                status: BackendSelfTestStatus::Skip,
                message: Some(reason.to_string()),
                adapter_name: None,
                scores: None,
                max_buffer_mb: None,
                direct_matches: None,
                coalesced_matches: None,
                matches: None,
                backend_id: None,
            }],
        };
    }

    let mut all_ok = true;
    let mut probes = Vec::with_capacity(3);

    // Test 1: keyhog's MoE compute dispatch.
    match keyhog_scanner::gpu::gpu_self_test() {
        Ok(report) => {
            let mut probe = BackendSelfTestProbe::pass("moe_kernel");
            probe.adapter_name = Some(report.adapter_name);
            probe.scores = Some(report.scores);
            probe.max_buffer_mb = report.vram_mb;
            probes.push(probe);
        }
        Err(error) => {
            probes.push(BackendSelfTestProbe::fail("moe_kernel", error));
            all_ok = false;
        }
    }

    // Test 2: vyre literal-set GPU dispatch. This path is NOT the
    // production scan path on the current vyre version (the
    // canonical pre-emit lowering rejects the subgroup form that
    // append_match_subgroup emits, so the production scan flow
    // routes through the AC kernel in scan_coalesced_gpu_ac_phase1).
    // The literal_set scanner is exercised here only as a
    // diagnostic; a FAIL with "_vyre_match_leader is referenced
    // before binding" reflects a known vyre IR-lowering gap, not a
    // missing GPU stack. We report it as a known limitation so
    // operators don't conclude their GPU is broken when scans
    // actually still run on the AC kernel path.
    match keyhog_scanner::gpu::vyre_gpu_self_test() {
        Ok(report) => {
            let mut probe = BackendSelfTestProbe::pass("vyre_literal_set");
            probe.direct_matches = Some(report.direct_matches);
            probe.coalesced_matches = Some(report.coalesced_matches);
            probes.push(probe);
        }
        Err(error) => {
            let known_lowering_gap = error.contains("_vyre_match_leader")
                || error.contains("canonical pre-emit lowering")
                || error.contains("subgroup_ballot");
            if known_lowering_gap {
                probes.push(BackendSelfTestProbe::known(
                    "vyre_literal_set",
                    "vyre IR lowering rejects literal_set's subgroup form; scans use the AC kernel path checked below",
                ));
            } else {
                probes.push(BackendSelfTestProbe::fail("vyre_literal_set", error));
                all_ok = false;
            }
        }
    }

    // Test 3: AC kernel dispatch (the production scan path for every
    // GPU backend after the literal_set rejection moved everything to
    // AC by default). Build a minimal one-detector CompiledScanner
    // and route a scan through scan_coalesced_gpu_ac_phase1.
    match keyhog_scanner::gpu::vyre_ac_kernel_self_test() {
        Ok(report) => {
            let mut probe = BackendSelfTestProbe::pass("vyre_ac_kernel");
            probe.matches = Some(report.matches);
            probe.backend_id = Some(report.backend_id);
            probes.push(probe);
        }
        Err(error) => {
            probes.push(BackendSelfTestProbe::fail("vyre_ac_kernel", error));
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
        exit_code: if all_ok { 0 } else { EXIT_SELF_TEST_FAILED },
        gpu_available: hw.gpu_available,
        gpu_is_software: hw.gpu_is_software,
        gpu_name: hw.gpu_name.clone(),
        gpu_max_buffer_mb: hw.gpu_vram_mb,
        recommended_backend: if all_ok {
            Some("gpu")
        } else {
            Some("simd-regex")
        },
        probes,
    }
}

fn print_self_test_report(report: &BackendSelfTestReport) {
    println!("## GPU self-test");
    if report.status == BackendSelfTestStatus::Skip {
        let message = report
            .probes
            .first()
            .and_then(|probe| probe.message.as_deref())
            .unwrap_or("GPU self-test skipped");
        println!("  \x1b[33mSKIP\x1b[0m: {message}");
        return;
    }

    for probe in &report.probes {
        print!("  {:<17} ... ", probe.name);
        match probe.status {
            BackendSelfTestStatus::Pass => print_pass_probe(probe),
            BackendSelfTestStatus::Fail => {
                let message = probe.message.as_deref().unwrap_or("probe failed");
                println!("\x1b[31mFAIL\x1b[0m  {message}");
            }
            BackendSelfTestStatus::Known => {
                let message = probe.message.as_deref().unwrap_or("known limitation");
                println!("\x1b[33mKNOWN\x1b[0m {message}.");
            }
            BackendSelfTestStatus::Skip => {
                let message = probe.message.as_deref().unwrap_or("probe skipped");
                println!("\x1b[33mSKIP\x1b[0m  {message}");
            }
        }
    }

    println!();
    if report.ok {
        println!("\x1b[32m✓ GPU self-test passed\x1b[0m, scans on this box can route to GPU.");
    } else {
        eprintln!(
            "\x1b[31m✗ GPU self-test failed\x1b[0m, keyhog will fall back to SIMD/CPU on this box."
        );
    }
}

fn print_pass_probe(probe: &BackendSelfTestProbe) {
    match probe.name {
        "moe_kernel" => println!(
            "\x1b[32mPASS\x1b[0m  ({}, scores={}, max_buffer={} MB)",
            probe.adapter_name.as_deref().unwrap_or("unknown adapter"),
            probe.scores.unwrap_or(0),
            probe.max_buffer_mb.unwrap_or(0)
        ),
        "vyre_literal_set" => println!(
            "\x1b[32mPASS\x1b[0m  (direct={}, coalesced={})",
            probe.direct_matches.unwrap_or(0),
            probe.coalesced_matches.unwrap_or(0)
        ),
        "vyre_ac_kernel" => println!(
            "\x1b[32mPASS\x1b[0m  (matches={}, backend={})",
            probe.matches.unwrap_or(0),
            probe.backend_id.unwrap_or("unknown")
        ),
        _ => println!("\x1b[32mPASS\x1b[0m"),
    }
}

#[doc(hidden)]
pub fn render_self_test_json_for_contract(report: &BackendSelfTestReport) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(Into::into)
}

fn fmt_bytes(n: u64) -> String {
    if n >= 1024 * 1024 * 1024 {
        format!("{} GiB", n / (1024 * 1024 * 1024))
    } else if n >= 1024 * 1024 {
        format!("{} MiB", n / (1024 * 1024))
    } else if n >= 1024 {
        format!("{} KiB", n / 1024)
    } else {
        format!("{n} B")
    }
}
