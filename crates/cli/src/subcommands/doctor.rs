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
use crate::exit_codes::EXIT_DOCTOR_UNHEALTHY;
use crate::installer::scan_engine_self_test;
use crate::style::{self, Palette};
use anyhow::Result;
use keyhog_scanner::hw_probe::{probe_hardware, simd_label};
use std::process::ExitCode;

fn canonicalize_for_shadow_check(path: std::path::PathBuf) -> std::path::PathBuf {
    std::fs::canonicalize(&path).unwrap_or(path) // LAW10: canonicalize failure => original path for reporting-only PATH-shadow diagnostic; recall-safe
}

/// True iff `dir` is one of the entries in `pathvar`, comparing CANONICAL forms
/// so a trailing-slash / symlinked / `.`-relative PATH entry
/// (`~/.local/bin/` vs `~/.local/bin`) still matches. Pure over its inputs so the
/// normalization contract is unit-testable without mutating the process PATH.
fn dir_is_on_path(dir: &std::path::Path, pathvar: &std::ffi::OsStr) -> bool {
    let target = canonicalize_for_shadow_check(dir.to_path_buf());
    std::env::split_paths(pathvar).any(|d| canonicalize_for_shadow_check(d) == target)
}

fn current_exe_for_shadow_check() -> Option<std::path::PathBuf> {
    std::env::current_exe()
        .ok() // LAW10: unavailable executable path => omit reporting-only shadow comparison; recall-safe
        .map(canonicalize_for_shadow_check)
}

pub(crate) fn run(_args: DoctorArgs) -> Result<ExitCode> {
    let mut healthy = true;
    let mut warned = false;
    let palette = style::for_stdout();
    let Palette {
        green,
        red,
        yellow,
        dim,
        bold,
        reset,
        ..
    } = palette;

    println!("{bold}keyhog doctor{reset}  v{}", env!("CARGO_PKG_VERSION"));

    // ── Host ──────────────────────────────────────────────────────────
    let hw = probe_hardware();
    let simd = simd_label(hw.has_avx512, hw.has_avx2, hw.has_neon);
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
        format!("{green}{}{reset}", hw.gpu_name.as_deref().unwrap_or("yes")) // LAW10: absent name/label => display default; reporting-only, recall-safe
    };
    println!("  gpu            {gpu}");
    println!(
        "  hyperscan      {}",
        if hw.hyperscan_available {
            format!("{green}compiled-in{reset}")
        } else {
            // Law 10: surface the reduced coverage, don't dim it. Keyword-anchored
            // detection is fully preserved (the keyword-gated regex fallback runs on
            // every chunk regardless of Hyperscan), but BARE context-less tokens
            // e.g. a standalone Twilio AccountSid `AC…` with no nearby keyword, fire
            // only via Hyperscan's full-regex scan, so their coverage is reduced on
            // this build. Verified empirically: TWILIO_AUTH_TOKEN / DATADOG_API_KEY
            // still fire here; only the no-keyword bare-shape case is affected.
            format!(
                "{yellow}absent{reset}  keyword-anchored detection preserved via the \
                 regex fallback; bare context-less tokens have reduced coverage, \
                 install the simd/full build for complete recall"
            )
        }
    );

    // ── Install ───────────────────────────────────────────────────────
    println!("\n{bold}install{reset}");
    match std::env::current_exe() {
        Ok(exe) => {
            println!("  binary         {}", exe.display());
            if let Some(dir) = exe.parent() {
                // Canonicalize BOTH the install dir and each PATH entry before
                // comparing, so a trailing-slash / symlinked / `.`-relative PATH
                // entry (`~/.local/bin/` vs `~/.local/bin`) is not a false "on
                // PATH: no". The raw `d == dir` string compare missed those and
                // disagreed with the installer's normalized `Test-PathContainsDir`
                // and the shadow check below (which already canonicalizes).
                let on_path = std::env::var_os("PATH")
                    .map(|p| dir_is_on_path(dir, &p))
                    .unwrap_or(false); // LAW10: empty/absent => documented numeric default, recall-safe
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

    // Shadowing: a DIFFERENT keyhog earlier on PATH masks this one. `keyhog`
    // typed at a shell may resolve to a stale /usr/local/bin/keyhog ahead of
    // the freshly-installed ~/.local/bin/keyhog - so the user runs an old
    // binary and every "I updated but nothing changed" report traces back
    // here. A classic bad install the in-process self-test cannot see
    // (it only ever exercises the running binary).
    let exe_name = if cfg!(windows) {
        "keyhog.exe"
    } else {
        "keyhog"
    };
    let mut on_path: Vec<std::path::PathBuf> = Vec::new();
    if let Some(pathvar) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&pathvar) {
            let cand = dir.join(exe_name);
            if cand.is_file() {
                let canon = canonicalize_for_shadow_check(cand);
                if !on_path.contains(&canon) {
                    on_path.push(canon);
                }
            }
        }
    }
    let running = current_exe_for_shadow_check();
    match on_path.len() {
        0 => println!(
            "  resolves       {dim}not on PATH (invoke by full path or add its dir){reset}"
        ),
        1 => println!("  resolves       {green}one keyhog on PATH{reset}"),
        n => {
            warned = true;
            println!(
                "  resolves       {yellow}{n} keyhog binaries on PATH - possible shadowing:{reset}"
            );
            for p in &on_path {
                println!("                 {dim}{}{reset}", p.display());
            }
        }
    }
    if let (Some(run), Some(first)) = (&running, on_path.first()) {
        if run != first {
            warned = true;
            println!(
                "  {yellow}shadowed{reset}       PATH resolves keyhog to {} but THIS binary is {}.\n                 {dim}An older install is ahead on PATH; remove it or fix PATH order.{reset}",
                first.display(),
                run.display()
            );
        }
    }

    // ── Detector corpus ───────────────────────────────────────────────
    println!("\n{bold}detectors{reset}");
    let embedded = keyhog_core::embedded_detector_count();
    if embedded > 0 {
        println!("  embedded       {green}{embedded}{reset} service detectors");
    } else {
        healthy = false;
        println!("  embedded       {red}0 - corpus missing from binary{reset}");
    }

    // ── Autoroute calibration coverage ────────────────────────────────
    // The default `keyhog scan` resolves a backend from persisted autoroute
    // evidence. An uncovered workload warns and completes through scalar
    // correctness recovery, without calling that recovery an autoroute result.
    // Surface whether this binary and host are calibrated so an operator can
    // distinguish complete recovery from a measured fastest route. Readiness
    // and repair come from the same typed contract as
    // `backend --autoroute`; doctor only decides how that state affects its
    // aggregate health report.
    println!("\n{bold}autoroute{reset}");
    let autoroute_cache = crate::autoroute_cache_path::resolve_autoroute_cache_path(None)
        .ok() // LAW10: reporting-only doctor cache-path resolve; display default, recall-safe
        .flatten();
    let autoroute = crate::orchestrator::inspect_autoroute_cache(autoroute_cache.as_deref());
    let readiness = autoroute.readiness();
    match readiness {
        crate::orchestrator::AutorouteReadiness::Direct => {
            if let Some(backend) = autoroute.direct_backend {
                println!(
                    "  calibration    {green}not required{reset}  {dim}automatic scans route directly to {backend}{reset}"
                );
            } else {
                healthy = false;
                println!(
                    "  calibration    {red}INVALID{reset}  {dim}single-backend inspection omitted its direct route{reset}"
                );
            }
        }
        crate::orchestrator::AutorouteReadiness::Ready => {
            let decisions: usize = autoroute.configs.iter().map(|c| c.decision_count).sum();
            println!(
                "  calibration    {green}{} config(s), {} decision(s){reset}  {dim}`keyhog backend --autoroute` for detail{reset}",
                autoroute.configs.len(),
                decisions
            );
        }
        crate::orchestrator::AutorouteReadiness::Quarantined => {
            warned = true;
            println!(
                "  calibration    {yellow}QUARANTINED{reset}  {dim}{} runtime-faulted route(s); repair: `{}`{reset}",
                autoroute.runtime_fault_count,
                readiness
                    .required_repair_command()
                    .map_err(anyhow::Error::msg)?
            );
        }
        crate::orchestrator::AutorouteReadiness::CalibrationRequired => {
            warned = true;
            println!(
                "  calibration    {yellow}NOT CALIBRATED{reset}  {dim}automatic scans complete through visible scalar correctness recovery; repair: `{}`{reset}",
                readiness
                    .required_repair_command()
                    .map_err(anyhow::Error::msg)?
            );
        }
        crate::orchestrator::AutorouteReadiness::Disabled => {
            warned = true;
            println!(
                "  calibration    {yellow}DISABLED{reset}  {dim}automatic routing needs a writable cache; repair: `{}`{reset}",
                readiness
                    .required_repair_command()
                    .map_err(anyhow::Error::msg)?
            );
        }
        crate::orchestrator::AutorouteReadiness::Stale => {
            warned = true;
            println!(
                "  calibration    {yellow}STALE{reset}  {dim}cache is for a different build; repair: `{}`{reset}",
                readiness
                    .required_repair_command()
                    .map_err(anyhow::Error::msg)?
            );
        }
        crate::orchestrator::AutorouteReadiness::Invalid => {
            warned = true;
            if let Some(error) = &autoroute.error {
                println!("  calibration    {yellow}INVALID{reset}  {dim}{error}{reset}");
            } else {
                println!(
                    "  calibration    {yellow}INVALID{reset}  {dim}cache readiness is incomplete{reset}"
                );
            }
            println!(
                "                 {dim}repair: `{}`; explicit `--backend` is diagnostic only{reset}",
                readiness
                    .required_repair_command()
                    .map_err(anyhow::Error::msg)?
            );
        }
    }

    // ── End-to-end self-test ──────────────────────────────────────────
    // Compile a synthetic single-detector scanner and confirm a planted
    // secret round-trips through compile -> scan -> extract -> report.
    // Proves the scan pipeline is functional on this build/host without
    // the ~3s full-corpus compile or example-suppression interference.
    println!("\n{bold}self-test{reset}");
    match scan_engine_self_test() {
        Ok(true) => println!(
            "  scan engine    {}  {dim}planted secret detected end-to-end{reset}",
            style::pass("PASS", &palette)
        ),
        Ok(false) => {
            healthy = false;
            println!(
                "  scan engine    {}  planted secret was NOT detected",
                style::fail("FAIL", &palette)
            );
        }
        Err(e) => {
            healthy = false;
            println!("  scan engine    {}  {e}", style::fail("FAIL", &palette));
        }
    }

    // GPU scan-path self-test. Before this, `doctor` reported "keyhog works"
    // while `backend --self-test` exited 4 on a broken production GPU path - the
    // two health checks disagreed and a user trusting `doctor` never learned
    // their GPU path was dead. Surface the production GPU verdict here too.
    //
    // A FAIL is UNHEALTHY, not a warning: on a GPU-capable host calibration
    // must measure the GPU peer. A broken GPU region-presence path makes that
    // peer ineligible, while a previously selected automatic GPU route recovers
    // visibly through its measured-correct recovery peer and is quarantined.
    // Required-GPU and explicit GPU requests remain hard contracts. Therefore
    // "keyhog is healthy" while the GPU scan path is dead is a lie. `doctor`
    // must agree with `backend --self-test` (which exits 4) and report
    // unhealthy. (Explicit `--backend cpu/simd` runs still work, but that is a
    // manual override of a broken default, not health.)
    // Skipped on no-GPU / software-renderer hosts (matches backend --self-test's
    // SKIP path, so a headless CI box stays green).
    let region_presence = keyhog_scanner::gpu::gpu_region_presence_self_test();
    let acquired_backends: Vec<_> = match &region_presence {
        Ok(report) => report.peers.iter().map(|peer| peer.backend).collect(),
        Err(error) => error.acquired_backends.clone(),
    };
    if !acquired_backends.is_empty() || (hw.gpu_available && !hw.gpu_is_software) {
        match region_presence {
            Ok(report) => {
                for peer in report.peers {
                    println!(
                        "  gpu scan path  {}  {dim}region presence findings={}, route={}, backend={}{reset}",
                        style::pass("PASS", &palette),
                        peer.matches,
                        peer.backend.label(),
                        peer.backend_id
                    );
                }
            }
            Err(e) => {
                healthy = false;
                println!(
                    "  gpu scan path  {}  GPU region-presence self-test failed; GPU routes are unavailable until fixed. Automatic scans with a persisted GPU route recover visibly through their measured-correct peer and quarantine the faulted route; required-GPU and explicit GPU scans fail. Fix the GPU path and recalibrate, or use an explicit CPU/SIMD backend for diagnostics.\n                 {dim}{e}{reset}\n                 {dim}run `keyhog backend --self-test` for the full GPU diagnostic{reset}",
                    style::fail("FAIL", &palette)
                );
            }
        }

        if acquired_backends.contains(&keyhog_scanner::ScanBackend::GpuWgpu) {
            match keyhog_scanner::gpu::vyre_gpu_self_test() {
                Ok(report) => println!(
                    "  gpu literal    {}  {dim}direct={}, coalesced={}{reset}",
                    style::pass("PASS", &palette),
                    report.direct_matches,
                    report.coalesced_matches
                ),
                Err(e) => {
                    let known_lowering_gap =
                        crate::subcommands::backend::is_known_vyre_lowering_gap(&e);
                    if known_lowering_gap {
                        warned = true;
                        println!(
                        "  gpu literal    {}  VYRE's direct match-triple diagnostic has a known lowering limitation (the canonical pre-emit lowering rejects the subgroup_ballot form append_match_subgroup emits, surfacing as `_vyre_match_leader is referenced before binding`); the production region-presence path is checked separately above.\n                 {dim}{e}{reset}\n                 {dim}run `keyhog backend --self-test --json` for machine-readable GPU diagnostics{reset}",
                        style::warn("WARN", &palette)
                    );
                    } else {
                        warned = true;
                        println!(
                        "  gpu literal    {}  VYRE direct match-triple diagnostic failed; production scan eligibility is determined by the region-presence probe above.\n                 {dim}{e}{reset}\n                 {dim}run `keyhog backend --self-test --json` for machine-readable GPU diagnostics{reset}",
                        style::warn("WARN", &palette)
                    );
                    }
                }
            }

            match keyhog_scanner::gpu::gpu_self_test() {
                Ok(report) => {
                    let max_buffer = match report.vram_mb {
                        Some(mb) => mb.to_string(),
                        None => "unknown".to_string(), // LAW10: absent GPU buffer limit => reporting-only display label; self-test already proved dispatch/parity
                    };
                    println!(
                    "  gpu moe path   {}  {dim}MoE shader matches CPU reference, adapter={}, scores={}, max_buffer={} MB{reset}",
                    style::pass("PASS", &palette),
                    report.adapter_name,
                    report.scores,
                    max_buffer
                );
                }
                Err(e) => {
                    let parity_degrade = crate::subcommands::backend::is_moe_parity_degrade(&e);
                    if parity_degrade {
                        warned = true;
                        println!(
                        "  gpu moe path   {}  GPU MoE shader diverges from the CPU MoE reference; GPU ML acceleration is disabled on this host and scoring uses the deterministic CPU MoE path.\n                 {dim}{e}{reset}\n                 {dim}run `keyhog backend --self-test --json` for machine-readable GPU diagnostics{reset}",
                        style::warn("WARN", &palette)
                    );
                    } else {
                        healthy = false;
                        println!(
                        "  gpu moe path   {}  GPU MoE self-test failed; GPU routes are unavailable until fixed. GPU ML acceleration is unavailable until fixed.\n                 {dim}{e}{reset}\n                 {dim}run `keyhog backend --self-test --json` for machine-readable GPU diagnostics{reset}",
                        style::fail("FAIL", &palette)
                    );
                    }
                }
            }
        }
    }

    // ── Summary ───────────────────────────────────────────────────────
    println!();
    if healthy && !warned {
        println!("{} keyhog is healthy.", style::pass("PASS", &palette));
        Ok(ExitCode::SUCCESS)
    } else if healthy {
        println!(
            "{} keyhog works, with warnings above.",
            style::warn("WARN", &palette)
        );
        Ok(ExitCode::SUCCESS)
    } else {
        let stderr_palette = style::for_stderr();
        eprintln!(
            "{} keyhog is unhealthy - see failures above.",
            style::fail("FAIL", &stderr_palette)
        );
        Ok(ExitCode::from(EXIT_DOCTOR_UNHEALTHY))
    }
}

pub(crate) mod testing {
    pub(crate) fn canonicalize_for_shadow_check(path: std::path::PathBuf) -> std::path::PathBuf {
        super::canonicalize_for_shadow_check(path)
    }
}

// PATH-membership unit tests live in a sibling `doctor/tests.rs` module (not an
// inline `#[cfg(test)] mod {}` block) so the KH-GAP-004 `no_inline_tests_in_src`
// gate stays green.
#[cfg(test)]
mod tests;
