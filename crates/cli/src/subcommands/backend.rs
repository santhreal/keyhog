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

pub fn run(args: BackendArgs) -> Result<()> {
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
    println!("Force a backend with: KEYHOG_BACKEND={{gpu|simd|cpu}}");
    let _ = cur;
    Ok(())
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
