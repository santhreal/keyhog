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
use anyhow::Result;
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::hw_probe::probe_hardware;
use keyhog_scanner::CompiledScanner;
use std::process::ExitCode;

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

/// Exit code when the scan-engine self-test fails - distinct from scan-side
/// codes so a post-install gate can fail closed on a broken binary.
const EXIT_DOCTOR_UNHEALTHY: u8 = 4;

pub fn run(_args: DoctorArgs) -> Result<ExitCode> {
    let mut healthy = true;
    let mut warned = false;

    println!("{BOLD}keyhog doctor{RESET}  v{}", env!("CARGO_PKG_VERSION"));

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
    println!("\n{BOLD}host{RESET}");
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
        format!("{DIM}not detected (CPU/SIMD path){RESET}")
    } else if hw.gpu_is_software {
        format!("{YELLOW}software renderer (disabled for scans){RESET}")
    } else {
        format!("{GREEN}{}{RESET}", hw.gpu_name.as_deref().unwrap_or("yes"))
    };
    println!("  gpu            {gpu}");
    println!(
        "  hyperscan      {}",
        if hw.hyperscan_available {
            format!("{GREEN}compiled-in{RESET}")
        } else {
            format!("{DIM}absent (regex fallback){RESET}")
        }
    );

    // ── Install ───────────────────────────────────────────────────────
    println!("\n{BOLD}install{RESET}");
    match std::env::current_exe() {
        Ok(exe) => {
            println!("  binary         {}", exe.display());
            if let Some(dir) = exe.parent() {
                let on_path = std::env::var_os("PATH")
                    .map(|p| std::env::split_paths(&p).any(|d| d == dir))
                    .unwrap_or(false);
                if on_path {
                    println!("  on PATH        {GREEN}yes{RESET}");
                } else {
                    warned = true;
                    println!(
                        "  on PATH        {YELLOW}no{RESET}  {DIM}add: export PATH=\"{}:$PATH\"{RESET}",
                        dir.display()
                    );
                }
            }
        }
        Err(e) => {
            warned = true;
            println!("  binary         {YELLOW}unknown ({e}){RESET}");
        }
    }
    println!("  version        v{}", env!("CARGO_PKG_VERSION"));

    // ── Detector corpus ───────────────────────────────────────────────
    println!("\n{BOLD}detectors{RESET}");
    let embedded = keyhog_core::embedded_detector_count();
    if embedded > 0 {
        println!("  embedded       {GREEN}{embedded}{RESET} service detectors");
    } else {
        healthy = false;
        println!("  embedded       {RED}0 - corpus missing from binary{RESET}");
    }

    // ── End-to-end self-test ──────────────────────────────────────────
    // Compile a synthetic single-detector scanner and confirm a planted
    // secret round-trips through compile -> scan -> extract -> report.
    // Proves the scan pipeline is functional on this build/host without
    // the ~3s full-corpus compile or example-suppression interference.
    println!("\n{BOLD}self-test{RESET}");
    match scan_engine_self_test() {
        Ok(true) => println!(
            "  scan engine    {GREEN}PASS{RESET}  {DIM}planted secret detected end-to-end{RESET}"
        ),
        Ok(false) => {
            healthy = false;
            println!("  scan engine    {RED}FAIL{RESET}  planted secret was NOT detected");
        }
        Err(e) => {
            healthy = false;
            println!("  scan engine    {RED}FAIL{RESET}  {e}");
        }
    }

    // ── Summary ───────────────────────────────────────────────────────
    println!();
    if healthy && !warned {
        println!("{GREEN}{BOLD}✓ keyhog is healthy.{RESET}");
        Ok(ExitCode::SUCCESS)
    } else if healthy {
        println!("{YELLOW}{BOLD}keyhog works, with warnings above.{RESET}");
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!("{RED}{BOLD}✗ keyhog is unhealthy - see failures above.{RESET}");
        Ok(ExitCode::from(EXIT_DOCTOR_UNHEALTHY))
    }
}

/// Build a one-detector scanner, plant a matching synthetic secret, and
/// confirm it surfaces. Uses a unique non-generic prefix so it neither
/// collides with a real detector nor trips example/placeholder suppression.
fn scan_engine_self_test() -> Result<bool> {
    const PLANTED: &str = "KHDOCTOR_A1b2C3d4E5f6";
    let detector = DetectorSpec {
        id: "kh-doctor-selftest".into(),
        name: "doctor self-test".into(),
        service: "doctor".into(),
        severity: Severity::Low,
        patterns: vec![PatternSpec {
            regex: "KHDOCTOR_[A-Za-z0-9]{12}".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        keywords: vec!["KHDOCTOR".into()],
        ..Default::default()
    };
    let scanner = CompiledScanner::compile(vec![detector])?;
    let chunk = Chunk {
        data: format!("api_secret = {PLANTED}").into(),
        metadata: ChunkMetadata {
            source_type: "doctor".into(),
            path: Some("doctor-selftest.txt".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk);
    Ok(matches.iter().any(|m| m.credential.as_ref() == PLANTED))
}
