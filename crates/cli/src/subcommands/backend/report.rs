//! `keyhog backend` default output: the hardware capability probe and the
//! steady-state routing heuristic matrix for this host.
//!
//! DIAGNOSTIC ONLY. Nothing here is measured on this host's real workload;
//! `--autoroute` renders the persisted, measured evidence instead.

use super::self_test::format_gpu_max_buffer;
use crate::args::BackendArgs;
use crate::format::format_bytes;
use crate::style;
use anyhow::Result;
use keyhog_scanner::hw_probe::{
    gpu_routing_profile, gpu_routing_profiles, probe_hardware, select_backend_verdict, simd_label,
};

pub(super) fn print_backend_report(args: &BackendArgs) -> Result<()> {
    // Probe collection, then report publication.
    let hw = {
        let _collect_span = keyhog_profile::span(keyhog_profile::Stage::Preprocess);
        probe_hardware()
    };
    let _report_span = keyhog_profile::span(keyhog_profile::Stage::Reporting);

    println!("## compiled capabilities");
    println!(
        "  simd_backend:      {}",
        if keyhog_scanner::hw_probe::simd_backend_compiled() {
            "compiled-in"
        } else {
            "disabled (compile with --features simd)"
        }
    );
    println!(
        "  gpu_backend:       {}",
        if keyhog_scanner::hw_probe::gpu_backend_compiled() {
            "compiled-in"
        } else {
            "disabled (compile with --features gpu)"
        }
    );
    println!();
    println!("## hardware");
    println!("  physical_cores:    {}", hw.physical_cores);
    println!("  logical_cores:     {}", hw.logical_cores);
    println!(
        "  simd:              {}",
        simd_label(hw.has_avx512, hw.has_avx2, hw.has_neon)
    );
    let gpu_display = keyhog_scanner::hw_probe::format_gpu_status(hw);
    println!("  gpu:               {gpu_display}");
    if let Some(buf) = hw.gpu_vram_mb {
        // `gpu_vram_mb` is actually `wgpu::Limits::max_buffer_size`,
        // not VRAM (wgpu has no portable VRAM query). Display under
        // the accurate label so this report doesn't claim an 8 GB
        // laptop GPU has 256 GB of memory.
        println!("  gpu_max_buffer:    {}", format_gpu_max_buffer(buf));
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

    let pat = effective_pattern_count(args)?;
    println!();
    println!("## routing decision matrix (pattern_count = {pat})");
    {
        // Heuristic-vs-measured honesty: this matrix is the fixed hardware
        // heuristic, NOT what a real `--backend auto` scan uses. Say so in the
        // output itself, not just the module docs, so an operator reading this
        // table never concludes it is the live routing decision.
        let p = style::for_stdout();
        println!(
            "  {}note: heuristic reference only. `scan --backend auto` routes from the\n  \
             persisted autoroute calibration cache (see `keyhog backend --autoroute`),\n  \
             never from this table.{}",
            p.dim, p.reset
        );
    }
    // Tier-aware: pull the active GPU's actual thresholds so the
    // matrix reflects what THIS box would route to, not the legacy
    // low-tier defaults that didn't apply to RTX 40/50-class adapters.
    let active_profile = gpu_routing_profile(hw.gpu_name.as_deref());
    let active_min = active_profile.min_bytes;
    let active_solo = active_profile.solo_bytes;
    let scenarios: &[(u64, &str)] = &[
        (0, "idle (size=0)"),
        (4 * 1024, "4 KiB single chunk"),
        (1024 * 1024, "1 MiB chunk"),
        (8 * 1024 * 1024, "8 MiB required GPU target"),
        (64 * 1024 * 1024, "64 MiB measured no-win boundary"),
        (active_min.saturating_sub(1), "just under tier min_bytes"),
        (active_min, "tier min_bytes exactly"),
        (active_solo.saturating_sub(1), "just under tier solo cap"),
        (active_solo, "tier solo cap exactly"),
        (1024 * 1024 * 1024, "1 GiB single chunk"),
    ];
    for (bytes, label) in scenarios {
        let verdict = select_backend_verdict(hw, *bytes, pat);
        println!(
            "  {:<42} {} reason={} ({})",
            label,
            verdict.backend.label(),
            verdict.reason.label(),
            verdict.reason_detail()
        );
    }

    if let Some(bytes) = args.probe_bytes {
        println!();
        let verdict = select_backend_verdict(hw, bytes, pat);
        println!("## --probe-bytes {bytes}");
        println!("  backend: {}", verdict.backend.label());
        println!(
            "  reason:  {} ({})",
            verdict.reason.label(),
            verdict.reason_detail()
        );
    }

    println!();
    println!("## gpu tier (heuristic from adapter name)");
    let tier = gpu_routing_profile(hw.gpu_name.as_deref());
    let tier_label = format!("{} ({})", tier.tier, tier.description);
    println!("  classified:                {tier_label}");
    println!(
        "  effective min bytes:       {} (tier {})",
        format_bytes(tier.min_bytes),
        tier.tier
    );
    println!(
        "  effective solo cap:        {}",
        format_bytes(tier.solo_bytes)
    );

    println!();
    println!("## thresholds (per-tier table)");
    for profile in gpu_routing_profiles() {
        println!(
            "  {:<4} tier  min/solo/pattern = {} / {} / {}",
            profile.tier,
            format_bytes(profile.min_bytes),
            format_bytes(profile.solo_bytes),
            profile.pattern_breakeven
        );
    }

    println!();
    println!(
        "Force a scan backend with: keyhog scan --backend <auto|gpu-cuda|gpu-wgpu|simd|cpu> ..."
    );
    Ok(())
}

fn effective_pattern_count(args: &BackendArgs) -> Result<usize> {
    if let Some(patterns) = args.patterns {
        return Ok(patterns);
    }
    let detectors = keyhog_core::load_embedded_detectors_or_fail()
        .map_err(|error| anyhow::anyhow!("backend: load embedded detectors: {error}"))?;
    let scanner = keyhog_scanner::CompiledScanner::compile(detectors)
        .map_err(|error| anyhow::anyhow!("backend: compile embedded scanner: {error}"))?;
    Ok(scanner.runtime_status().pattern_count)
}
