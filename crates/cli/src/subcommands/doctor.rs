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
    // The default `keyhog scan` resolves a backend from the persisted autoroute
    // cache and FAILS CLOSED (exit 2) on a workload it has no decision for
    // Law 10: never guess a substitute. Surface whether this binary+host is
    // calibrated so a user understands an "autoroute calibration required" scan
    // error. This is informational and never marks the install unhealthy: an
    // uncalibrated cache is the expected pre-`--calibrate` state (and single-
    // backend / portable builds never fail closed, so they need no decision). A
    // STALE cache, one written by a different build, is a WARN (exit stays 0),
    // because auto scans reject it until re-calibrated while explicit `--backend`
    // still works. Reuses the same inspection primitive as `backend --autoroute`.
    println!("\n{bold}autoroute{reset}");
    let autoroute_cache = crate::autoroute_cache_path::resolve_autoroute_cache_path(None)
        .ok() // LAW10: reporting-only doctor cache-path resolve; display default, recall-safe
        .flatten();
    let autoroute = crate::orchestrator::inspect_autoroute_cache(autoroute_cache.as_deref());
    if let Some(error) = &autoroute.error {
        warned = true;
        println!("  calibration    {yellow}unusable{reset}  {dim}{error}{reset}");
        println!(
            "                 {dim}auto scans fail closed until re-calibrated; explicit `--backend` still works{reset}"
        );
    } else if !autoroute.present {
        println!(
            "  calibration    {dim}not calibrated: run `keyhog calibrate-autoroute` (or `install.sh --calibrate` / `install.ps1 -Calibrate`), or scan with an explicit `--backend`{reset}"
        );
    } else {
        let decisions: usize = autoroute.configs.iter().map(|c| c.decision_count).sum();
        if autoroute.identity_matches_build == Some(false) {
            warned = true;
            println!(
                "  calibration    {yellow}STALE{reset}  {dim}cache is for a different build; auto scans will reject it, re-run `keyhog calibrate-autoroute` or `install.sh --calibrate`{reset}"
            );
        } else {
            println!(
                "  calibration    {green}{} config(s), {} decision(s){reset}  {dim}`keyhog backend --autoroute` for detail{reset}",
                autoroute.configs.len(),
                decisions
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
    // while `backend --self-test` exited 4 on a broken GPU AC kernel - the
    // two health checks disagreed and a user trusting `doctor` never learned
    // their GPU path was dead. Surface the production GPU verdict here too.
    //
    // A FAIL is UNHEALTHY, not a warning: on a GPU-capable host the default
    // auto-scan resolves to the GPU route, and autoroute is fail-closed - it
    // refuses to silently substitute CPU/SIMD for a GPU decision it cannot
    // make (Law 10). A broken GPU AC kernel therefore breaks the DEFAULT scan
    // the moment calibration tries to record a GPU runtime identity, so
    // "keyhog is healthy" while the GPU scan path is dead is a lie. `doctor`
    // must agree with `backend --self-test` (which exits 4) and report
    // unhealthy. (Explicit `--backend cpu/simd` runs still work, but that is a
    // manual override of a broken default, not health.)
    // Skipped on no-GPU / software-renderer hosts (matches backend --self-test's
    // SKIP path, so a headless CI box stays green).
    if hw.gpu_available && !hw.gpu_is_software {
        match keyhog_scanner::gpu::vyre_ac_kernel_self_test() {
            Ok(report) => println!(
                "  gpu scan path  {}  {dim}AC kernel matches={}, backend={}{reset}",
                style::pass("PASS", &palette),
                report.matches,
                report.backend_id
            ),
            Err(e) => {
                healthy = false;
                println!(
                    "  gpu scan path  {}  GPU AC kernel self-test failed; GPU routes are unavailable until fixed. The default GPU scan route is BROKEN on this host (auto scans fail closed rather than silently route to CPU/SIMD). Fix the GPU path, or scan with an explicit `--backend cpu`/`--backend simd` override.\n                 {dim}{e}{reset}\n                 {dim}run `keyhog backend --self-test` for the full GPU diagnostic{reset}",
                    style::fail("FAIL", &palette)
                );
            }
        }

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
                        "  gpu literal    {}  vyre literal-set path has a known lowering limitation (the canonical pre-emit lowering rejects the subgroup_ballot form append_match_subgroup emits, surfacing as `_vyre_match_leader is referenced before binding`); scans use the AC kernel path checked above.\n                 {dim}{e}{reset}\n                 {dim}run `keyhog backend --self-test --json` for machine-readable GPU diagnostics{reset}",
                        style::warn("WARN", &palette)
                    );
                } else {
                    healthy = false;
                    println!(
                        "  gpu literal    {}  GPU literal-set self-test failed; GPU routes are unavailable until fixed.\n                 {dim}{e}{reset}\n                 {dim}run `keyhog backend --self-test --json` for machine-readable GPU diagnostics{reset}",
                        style::fail("FAIL", &palette)
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
