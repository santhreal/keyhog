//! `keyhog doctor` - install + environment health check.
//!
//! One command that answers "is my keyhog install healthy and will it
//! actually detect secrets on this box?" - the diagnostic heart of the
//! installer. Reuses the binary's own `hw_probe` (no shell-script GPU
//! detection to drift from the runtime), checks the install is on `PATH`,
//! confirms the detector corpus is embedded, and runs a real end-to-end
//! self-test: it plants a synthetic secret, scans it through the actual
//! `CompiledScanner` pipeline, and confirms the finding surfaces. Exits
//! non-zero if the self-test fails so a post-install hook or CI smoke gate
//! can fail closed on a broken binary.

use crate::args::DoctorArgs;
use crate::installer::scan_engine_self_test;
use crate::style::Palette;
use anyhow::Result;
use keyhog_scanner::hw_probe::probe_hardware;
use std::process::ExitCode;

/// Exit code when the scan-engine self-test fails - distinct from scan-side
/// codes so a post-install gate can fail closed on a broken binary.
const EXIT_DOCTOR_UNHEALTHY: u8 = 4;

pub fn run(_args: DoctorArgs) -> Result<ExitCode> {
    let mut healthy = true;
    let mut warned = false;
    let Palette {
        green,
        red,
        yellow,
        dim,
        bold,
        reset,
    } = Palette::for_stdout();

    println!("{bold}keyhog doctor{reset}  v{}", env!("CARGO_PKG_VERSION"));

    // ── Host ──────────────────────────────────────────────────────────
    let hw = probe_hardware();
    let simd = if hw.has_avx512 {
        "AVX-512"
    } else if hw.has_avx2 {
        "AVX2"
    } else if hw.has_neon {
        "NEON"
    } else {
        "scalar"
    };
    println!("\n{bold}host{reset}");
    println!(
        "  os/arch        {} / {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!(
        "  cpu            {} physical / {} logical cores",
        hw.physical_cores, hw.logical_cores
    );
    println!("  simd           {simd}");
    let gpu = if !hw.gpu_available {
        format!("{dim}not detected (CPU/SIMD path){reset}")
    } else if hw.gpu_is_software {
        format!("{yellow}software renderer (disabled for scans){reset}")
    } else {
        format!("{green}{}{reset}", hw.gpu_name.as_deref().unwrap_or("yes"))
    };
    println!("  gpu            {gpu}");
    println!(
        "  hyperscan      {}",
        if hw.hyperscan_available {
            format!("{green}compiled-in{reset}")
        } else {
            format!("{dim}absent (regex fallback){reset}")
        }
    );

    // ── Install ───────────────────────────────────────────────────────
    println!("\n{bold}install{reset}");
    match std::env::current_exe() {
        Ok(exe) => {
            println!("  binary         {}", exe.display());
            if let Some(dir) = exe.parent() {
                let on_path = std::env::var_os("PATH")
                    .map(|p| std::env::split_paths(&p).any(|d| d == dir))
                    .unwrap_or(false);
                if on_path {
                    println!("  on PATH        {green}yes{reset}");
                } else {
                    warned = true;
                    println!(
                        "  on PATH        {yellow}no{reset}  {dim}add: export PATH=\"{}:$PATH\"{reset}",
                        dir.display()
                    );
                }
            }
        }
        Err(e) => {
            warned = true;
            println!("  binary         {yellow}unknown ({e}){reset}");
        }
    }
    println!("  version        v{}", env!("CARGO_PKG_VERSION"));

    // ── Detector corpus ───────────────────────────────────────────────
    println!("\n{bold}detectors{reset}");
    let embedded = keyhog_core::embedded_detector_count();
    if embedded > 0 {
        println!("  embedded       {green}{embedded}{reset} service detectors");
    } else {
        healthy = false;
        println!("  embedded       {red}0 - corpus missing from binary{reset}");
    }

    // ── End-to-end self-test ──────────────────────────────────────────
    // Compile a synthetic single-detector scanner and confirm a planted
    // secret round-trips through compile -> scan -> extract -> report.
    // Proves the scan pipeline is functional on this build/host without
    // the ~3s full-corpus compile or example-suppression interference.
    println!("\n{bold}self-test{reset}");
    match scan_engine_self_test() {
        Ok(true) => println!(
            "  scan engine    {green}PASS{reset}  {dim}planted secret detected end-to-end{reset}"
        ),
        Ok(false) => {
            healthy = false;
            println!("  scan engine    {red}FAIL{reset}  planted secret was NOT detected");
        }
        Err(e) => {
            healthy = false;
            println!("  scan engine    {red}FAIL{reset}  {e}");
        }
    }

    // ── Summary ───────────────────────────────────────────────────────
    println!();
    if healthy && !warned {
        println!("{green}{bold}✓ keyhog is healthy.{reset}");
        Ok(ExitCode::SUCCESS)
    } else if healthy {
        println!("{yellow}{bold}keyhog works, with warnings above.{reset}");
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!("{red}{bold}✗ keyhog is unhealthy - see failures above.{reset}");
        Ok(ExitCode::from(EXIT_DOCTOR_UNHEALTHY))
    }
}
