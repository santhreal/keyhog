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
use anyhow::{bail, Context, Result};
use keyhog_scanner::hw_probe::{probe_hardware, simd_label};
use keyhog_scanner::{BigramPrefilterState, BigramPrefilterStatus, CompiledScanner};
use std::process::ExitCode;

fn canonicalize_for_shadow_check(path: std::path::PathBuf) -> std::path::PathBuf {
    std::fs::canonicalize(&path).unwrap_or(path) // LAW10: canonicalize failure => original path for reporting-only PATH-shadow diagnostic; recall-safe
}

/// Collect the host hardware probe. Doctor's check-collection phase, profiled
/// as preprocessing; kept as one seam so the profiling suite can drive the
/// real probe without spawning the binary.
pub(crate) fn collect_host_probe() -> &'static keyhog_scanner::hw_probe::HardwareCaps {
    let _collect_span = keyhog_profile::span(keyhog_profile::Stage::Preprocess);
    probe_hardware()
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

const fn should_run_gpu_self_tests(gpu_available: bool, gpu_is_software: bool) -> bool {
    gpu_available && !gpu_is_software
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct BloomEvidenceSummary {
    pub(super) corpus_name: String,
    pub(super) corpus_revision: String,
    pub(super) input_count: u64,
    pub(super) eligible_input_count: u64,
    pub(super) rejected_input_count: u64,
    pub(super) rejection_basis_points: u16,
    pub(super) unavailable_reason_counts: std::collections::BTreeMap<String, u64>,
    pub(super) finding_count: u64,
    pub(super) findings_sha256: String,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct BloomOperatorDiagnostic {
    pub(super) density: String,
    pub(super) corpus_rejection: String,
    pub(super) finding_parity: String,
    pub(super) state: &'static str,
    pub(super) action: Option<&'static str>,
    pub(super) warned: bool,
    pub(super) unhealthy: bool,
}

fn format_basis_points(value: u16) -> String {
    format!("{}.{:02}%", value / 100, value % 100)
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn load_bloom_evidence(
    path: &std::path::Path,
    status: BigramPrefilterStatus,
    detector_corpus_sha256: &str,
    scanner_detector_digest: u64,
) -> Result<BloomEvidenceSummary> {
    let bytes =
        std::fs::read(path).with_context(|| format!("read Bloom evidence {}", path.display()))?;
    let receipt: crate::bloom_diagnostic::BloomCorpusResult = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse Bloom evidence {}", path.display()))?;
    if receipt.schema_version != "bloom-evidence-v1" {
        bail!(
            "Bloom evidence schema {:?} is unsupported",
            receipt.schema_version
        );
    }
    if receipt.corpus_name.trim().is_empty() || receipt.corpus_revision.trim().is_empty() {
        bail!("Bloom evidence must name its corpus and revision");
    }
    for (name, digest) in [
        ("fixture", receipt.fixture_sha256.as_str()),
        ("corpus", receipt.corpus_sha256.as_str()),
        ("detector corpus", receipt.detector_corpus_sha256.as_str()),
        ("enabled findings", receipt.enabled_findings_sha256.as_str()),
        ("bypassed findings", receipt.bypass_findings_sha256.as_str()),
    ] {
        if !is_lower_hex(digest, 64) {
            bail!("Bloom evidence {name} digest is not lowercase SHA-256");
        }
    }
    if receipt.detector_corpus_sha256 != detector_corpus_sha256 {
        bail!("Bloom evidence was measured with a different detector corpus");
    }
    if receipt.scanner_detector_digest != format!("{scanner_detector_digest:016x}") {
        bail!("Bloom evidence was measured with a different compiled scanner");
    }
    if receipt.input_count == 0
        || receipt.declared_input_count
            != receipt
                .input_count
                .saturating_add(receipt.unavailable_input_count)
        || receipt.eligible_input_count > receipt.input_count
        || receipt.rejected_input_count > receipt.eligible_input_count
        || receipt
            .admitted_input_count
            .saturating_add(receipt.rejected_input_count)
            != receipt.input_count
        || u64::from(receipt.rejection_basis_points)
            != receipt.rejected_input_count.saturating_mul(10_000) / receipt.input_count
    {
        bail!("Bloom evidence input accounting is inconsistent");
    }
    if receipt
        .unavailable_reason_counts
        .keys()
        .any(|reason| reason != "source-file-missing")
        || receipt
            .unavailable_reason_counts
            .values()
            .copied()
            .sum::<u64>()
            != receipt.unavailable_input_count
    {
        bail!("Bloom evidence unavailable reason accounting is inconsistent");
    }
    if receipt.rejected_input_count == 0 {
        bail!("Bloom evidence rejected zero named corpus inputs");
    }
    let expected_state = match status.state {
        BigramPrefilterState::Healthy => "healthy",
        BigramPrefilterState::Saturated => "saturated-fail-open",
        BigramPrefilterState::Invalid => "invalid-fail-open",
    };
    if receipt.state != expected_state
        || receipt.populated_slots != status.populated_slots
        || receipt.total_slots != status.total_slots
        || receipt.saturation_threshold_slots != status.saturation_threshold_slots
        || receipt.density_basis_points != status.density_basis_points
    {
        bail!("Bloom evidence prefilter state does not match this scanner");
    }
    if !receipt.findings_identical
        || receipt.enabled_finding_count != receipt.bypass_finding_count
        || receipt.enabled_findings_sha256 != receipt.bypass_findings_sha256
    {
        bail!("Bloom evidence does not prove exact enabled/bypassed finding parity");
    }
    Ok(BloomEvidenceSummary {
        corpus_name: receipt.corpus_name,
        corpus_revision: receipt.corpus_revision,
        input_count: receipt.input_count,
        eligible_input_count: receipt.eligible_input_count,
        rejected_input_count: receipt.rejected_input_count,
        rejection_basis_points: receipt.rejection_basis_points,
        unavailable_reason_counts: receipt.unavailable_reason_counts,
        finding_count: receipt.enabled_finding_count,
        findings_sha256: receipt.enabled_findings_sha256,
    })
}

pub(super) fn bloom_operator_diagnostic(
    status: BigramPrefilterStatus,
    evidence: Option<&BloomEvidenceSummary>,
) -> BloomOperatorDiagnostic {
    let density = format!(
        "{} ({}/{} slots; saturates at {})",
        format_basis_points(status.density_basis_points),
        status.populated_slots,
        status.total_slots,
        status.saturation_threshold_slots
    );
    let corpus_rejection = evidence.map_or_else(
        || "UNMEASURED (provide --bloom-evidence from `make -C benchmarks bloom`)".to_string(),
        |receipt| {
            let unavailable = receipt
                .unavailable_reason_counts
                .iter()
                .map(|(reason, count)| format!("{reason}={count}"))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{} ({}/{} inputs; {} bloom-eligible; {}@{}; unavailable {})",
                format_basis_points(receipt.rejection_basis_points),
                receipt.rejected_input_count,
                receipt.input_count,
                receipt.eligible_input_count,
                receipt.corpus_name,
                receipt.corpus_revision,
                unavailable,
            )
        },
    );
    let finding_parity = evidence.map_or_else(
        || "UNPROVEN (no real-corpus differential receipt loaded)".to_string(),
        |receipt| {
            format!(
                "IDENTICAL ({} findings; sha256 {})",
                receipt.finding_count, receipt.findings_sha256
            )
        },
    );
    let (state, action, warned, unhealthy) = match status.state {
        BigramPrefilterState::Healthy
            if evidence.is_some_and(|receipt| receipt.rejected_input_count > 0) =>
        {
            ("HEALTHY / CORPUS-PROVEN", None, false, false)
        }
        BigramPrefilterState::Healthy if evidence.is_some() => (
            "HEALTHY / NO CORPUS REJECTION",
            Some(
                "the measured corpus was rejected at 0%; review literal growth or retire this prefilter if representative corpora remain at 0%",
            ),
            true,
            false,
        ),
        BigramPrefilterState::Healthy => (
            "HEALTHY / CORPUS UNMEASURED",
            Some(
                "run `make -C benchmarks bloom`, then pass its result with --bloom-evidence",
            ),
            true,
            false,
        ),
        BigramPrefilterState::Saturated => (
            "SATURATED / FAIL-OPEN",
            Some(
                "downstream scanning remains enabled for recall; reduce literal-prefix density or enlarge the table to restore filtering",
            ),
            true,
            false,
        ),
        BigramPrefilterState::Invalid => (
            "INVALID / FAIL-OPEN",
            Some(
                "downstream scanning remains enabled for recall; repair or rebuild this binary before relying on prefilter performance",
            ),
            false,
            true,
        ),
    };
    BloomOperatorDiagnostic {
        density,
        corpus_rejection,
        finding_parity,
        state,
        action,
        warned,
        unhealthy,
    }
}

pub(crate) fn run(args: DoctorArgs) -> Result<ExitCode> {
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
    let hw = collect_host_probe();
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
    let gpu_raw = keyhog_scanner::hw_probe::format_gpu_status(&hw);
    let gpu = if hw.gpu_available && !hw.gpu_is_software {
        format!("{green}{gpu_raw}{reset}")
    } else if hw.gpu_is_software {
        format!("{yellow}{gpu_raw}{reset}")
    } else {
        format!("{dim}{gpu_raw}{reset}")
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

    // Density is live scanner state. Effectiveness and recall safety come only
    // from a digest-bound real-corpus receipt; a tiny built-in sample must not
    // be promoted to production evidence.
    let detectors = keyhog_core::embedded_detector_specs().to_vec();
    let detector_corpus_sha256: Result<String> =
        keyhog_core::compute_detector_corpus_digest(&detectors)
            .map(keyhog_core::hex_encode)
            .map_err(Into::into);
    let scanner = CompiledScanner::compile(detectors).map_err(Into::into);
    match (detector_corpus_sha256, scanner) {
        (Ok(detector_corpus_sha256), Ok(scanner)) => {
            let status = scanner.bigram_prefilter_status();
            let evidence = args
                .bloom_evidence
                .as_deref()
                .map(|path| {
                    load_bloom_evidence(
                        path,
                        status,
                        &detector_corpus_sha256,
                        scanner.runtime_status().detector_digest,
                    )
                })
                .transpose();
            let loaded_evidence = match &evidence {
                Ok(receipt) => receipt.as_ref(),
                Err(error) => {
                    eprintln!("Bloom evidence unavailable: {error:#}");
                    None
                }
            };
            let diagnostic = bloom_operator_diagnostic(status, loaded_evidence);
            let state_color = if diagnostic.unhealthy {
                red
            } else if diagnostic.warned {
                yellow
            } else {
                green
            };
            println!("  bloom density  {}", diagnostic.density);
            println!("  bloom state    {state_color}{}{reset}", diagnostic.state);
            println!("  bloom reject   {}", diagnostic.corpus_rejection);
            println!("  bloom parity   {}", diagnostic.finding_parity);
            if let Err(error) = evidence {
                healthy = false;
                println!("  bloom evidence {red}INVALID{reset}  {dim}{error:#}{reset}");
            }
            if let Some(action) = diagnostic.action {
                println!("  bloom action   {dim}{action}{reset}");
            }
            healthy &= !diagnostic.unhealthy;
            warned |= diagnostic.warned;
        }
        (Err(error), _) | (_, Err(error)) => {
            healthy = false;
            println!(
                "  bloom state    {red}INVALID / FAIL-OPEN{reset}  {dim}scanner compilation failed: {error}; repair or rebuild this binary{reset}"
            );
        }
    }

    // ── Autoroute calibration coverage ────────────────────────────────
    // The default `keyhog scan` resolves a backend from persisted autoroute
    // evidence. An uncovered workload remains unscanned and makes the run
    // non-successful. Surface whether this binary and host are calibrated so an
    // operator can distinguish a measured fastest route from invalid state.
    // Readiness and repair come from the same typed contract as
    // `backend --autoroute`; doctor only decides how that state affects its
    // aggregate health report.
    println!("\n{bold}autoroute{reset}");
    // Without an explicit path this reports the platform default, which is not
    // the file a project-configured scan uses. `--autoroute-cache` takes the
    // same value as `scan --autoroute-cache` and `[system].autoroute_cache`, so
    // doctor and `backend --autoroute` can be pointed at one exact file, and
    // the resolved path is printed either way rather than left implicit.
    let autoroute_cache = match crate::autoroute_cache_path::resolve_autoroute_cache_path(
        args.autoroute_cache.as_deref(),
    ) {
        Ok(Some(path)) => {
            println!("  cache path     {dim}{}{reset}", path.display());
            Some(path)
        }
        Ok(None) => {
            println!("  cache path     {dim}(disabled){reset}");
            None
        }
        Err(error) => {
            healthy = false;
            println!("  cache path     {red}INVALID{reset}  {dim}{error}{reset}");
            None
        }
    };
    let execution_pack_dir = crate::execution_pack_install::installed_execution_pack_directory()?;
    println!(
        "  pack path      {dim}{}{reset}",
        execution_pack_dir.display()
    );
    let installed_pack_binding = if execution_pack_dir.exists() {
        match crate::execution_pack_install::load_authenticated_binding(&execution_pack_dir, None) {
            Ok(binding) => {
                println!(
                    "  pack state     {green}AUTHENTICATED{reset}  {dim}{} policy/backend pack(s), manifest {}{reset}",
                    binding.packs.len(),
                    keyhog_core::hex_encode(&binding.manifest_digest),
                );
                Some(binding)
            }
            Err(error) => {
                healthy = false;
                println!(
                    "  pack state     {red}INVALID{reset}  {dim}{error:#}; rebuild with `keyhog compile-execution-packs`{reset}"
                );
                None
            }
        }
    } else {
        warned = true;
        println!(
            "  pack state     {yellow}NOT INSTALLED{reset}  {dim}using the embedded detector corpus; install an authenticated generation to avoid runtime compilation{reset}"
        );
        None
    };
    let route_pack_binding = autoroute_cache
        .as_deref()
        .filter(|path| path.is_file())
        .map(crate::orchestrator::load_execution_pack_generation_binding)
        .transpose()
        .map(Option::flatten);
    let autoroute = crate::orchestrator::inspect_autoroute_cache(autoroute_cache.as_deref());
    let readiness = autoroute.readiness();
    match (&installed_pack_binding, route_pack_binding) {
        (Some(installed), Ok(Some(routed))) if *installed == routed => println!(
            "  route binding  {green}EXACT{reset}  {dim}calibration names this authenticated generation{reset}"
        ),
        (Some(_), Ok(Some(_))) => {
            healthy = false;
            println!(
                "  route binding  {red}STALE{reset}  {dim}calibration names a different pack generation; repair: `keyhog calibrate-autoroute`{reset}"
            );
        }
        (Some(_), Ok(None))
            if matches!(readiness, crate::orchestrator::AutorouteReadiness::Ready | crate::orchestrator::AutorouteReadiness::Quarantined) =>
        {
            healthy = false;
            println!(
                "  route binding  {red}MISSING{reset}  {dim}calibration is not bound to installed packs; repair: `keyhog calibrate-autoroute`{reset}"
            );
        }
        (_, Err(error)) => {
            healthy = false;
            println!("  route binding  {red}INVALID{reset}  {dim}{error:#}{reset}");
        }
        _ => println!(
            "  route binding  {dim}not published{reset}  {dim}calibration is disabled, absent, or not required{reset}"
        ),
    }
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
                "  calibration    {yellow}NOT CALIBRATED{reset}  {dim}automatic scans fail closed without scanning; repair: `{}`{reset}",
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
    if should_run_gpu_self_tests(hw.gpu_available, hw.gpu_is_software) {
        let region_presence = keyhog_scanner::gpu::gpu_region_presence_self_test();
        let acquired_backends: Vec<_> = match &region_presence {
            Ok(report) => report.peers.iter().map(|peer| peer.backend).collect(),
            Err(error) => error.acquired_backends.clone(),
        };
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
                    "  gpu scan path  {}  GPU region-presence self-test failed; GPU routes are unavailable until fixed. Automatic scans with a persisted GPU route recover visibly through their measured-correct peer and quarantine the faulted route; required-GPU and explicit GPU scans fail. auto scans fail closed rather than silently route to CPU/SIMD. Fix the GPU path and recalibrate, or use an explicit CPU/SIMD backend for diagnostics.\n                 {dim}{e}{reset}\n                 {dim}run `keyhog backend --self-test` for the full GPU diagnostic{reset}",
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

    pub(crate) fn should_run_gpu_self_tests(gpu_available: bool, gpu_is_software: bool) -> bool {
        super::should_run_gpu_self_tests(gpu_available, gpu_is_software)
    }
}

// PATH-membership unit tests live in a sibling `doctor/tests.rs` module (not an
// inline `#[cfg(test)] mod {}` block) so the KH-GAP-004 `no_inline_tests_in_src`
// gate stays green.
#[cfg(test)]
mod tests;
