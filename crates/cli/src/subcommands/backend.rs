//! `keyhog backend` — inspect the auto-routing decision for this hardware.
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
use keyhog_scanner::hw_probe::{probe_hardware, select_backend, thresholds, ScanBackend};
use std::process::ExitCode;

/// Exit code for `backend --self-test` when one of the GPU dispatch
/// proofs fails. Distinct from the scan-side exit codes so a CI
/// release gate can fail closed on real GPU breakage.
const EXIT_SELF_TEST_FAILED: u8 = 4;

pub fn run(args: BackendArgs) -> Result<ExitCode> {
    if args.self_test {
        return run_self_test();
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
            "(software renderer — disabled)"
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
    let scenarios: &[(u64, &str)] = &[
        (0, "idle (size=0)"),
        (4 * 1024, "4 KiB single chunk"),
        (4 * 1024 * 1024, "4 MiB chunk"),
        (thresholds::GPU_MIN_BYTES - 1, "just under GPU_MIN_BYTES"),
        (thresholds::GPU_MIN_BYTES, "GPU_MIN_BYTES exactly"),
        (
            thresholds::GPU_BYTES_BREAKEVEN_SOLO - 1,
            "just under GPU_BYTES_BREAKEVEN_SOLO",
        ),
        (
            thresholds::GPU_BYTES_BREAKEVEN_SOLO,
            "GPU_BYTES_BREAKEVEN_SOLO exactly",
        ),
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
    println!("## thresholds");
    println!(
        "  GPU_MIN_BYTES                = {}",
        fmt_bytes(thresholds::GPU_MIN_BYTES)
    );
    println!(
        "  GPU_BYTES_BREAKEVEN_SOLO     = {}",
        fmt_bytes(thresholds::GPU_BYTES_BREAKEVEN_SOLO)
    );
    println!(
        "  GPU_PATTERN_BREAKEVEN        = {} patterns",
        thresholds::GPU_PATTERN_BREAKEVEN
    );

    println!();
    let cur = ScanBackend::Gpu.label();
    println!("Force a backend with: KEYHOG_BACKEND={{gpu|simd|cpu}}  (or `keyhog scan --backend ...`)");
    let _ = cur;
    Ok(())
}

fn run_self_test() -> Result<ExitCode> {
    println!("## GPU self-test");
    let hw = probe_hardware();

    if !hw.gpu_available || hw.gpu_is_software {
        let reason = if !hw.gpu_available {
            "no GPU adapter detected"
        } else {
            "only software adapter (llvmpipe/lavapipe/swiftshader) — won't be used for scans"
        };
        println!("  \x1b[33mSKIP\x1b[0m: {reason}");
        // Skip is not a failure — gracefully exit 0 so CI on a headless
        // runner without a GPU doesn't block the release.
        return Ok(ExitCode::SUCCESS);
    }

    let mut all_ok = true;

    // Test 1: keyhog's MoE compute dispatch.
    print!("  moe_kernel       ... ");
    match keyhog_scanner::gpu::gpu_self_test() {
        Ok(report) => println!(
            "\x1b[32mPASS\x1b[0m  ({}, scores={}, max_buffer={} MB)",
            report.adapter_name,
            report.scores,
            report.vram_mb.unwrap_or(0)
        ),
        Err(error) => {
            println!("\x1b[31mFAIL\x1b[0m  {error}");
            all_ok = false;
        }
    }

    // Test 2: vyre literal-set GPU dispatch — the actual scan path.
    print!("  vyre_literal_set ... ");
    match keyhog_scanner::gpu::vyre_gpu_self_test() {
        Ok(report) => println!(
            "\x1b[32mPASS\x1b[0m  (direct={}, coalesced={})",
            report.direct_matches, report.coalesced_matches
        ),
        Err(error) => {
            println!("\x1b[31mFAIL\x1b[0m  {error}");
            all_ok = false;
        }
    }

    println!();
    if all_ok {
        println!("\x1b[32m✓ GPU self-test passed\x1b[0m — scans on this box can route to GPU.");
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!("\x1b[31m✗ GPU self-test failed\x1b[0m — keyhog will fall back to SIMD/CPU on this box.");
        Ok(ExitCode::from(EXIT_SELF_TEST_FAILED))
    }
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
