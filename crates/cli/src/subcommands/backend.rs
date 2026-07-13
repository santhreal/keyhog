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
use crate::exit_codes::{EXIT_BACKEND_SELF_TEST_FAILED, EXIT_SUCCESS};
use crate::format::format_bytes;
use crate::style::{self, Palette};
use anyhow::Result;
use keyhog_scanner::hw_probe::{
    gpu_routing_profile, gpu_routing_profiles, probe_hardware, select_backend_verdict, simd_label,
    HardwareCaps,
};
use serde::Serialize;
use std::process::ExitCode;
use std::sync::LazyLock;

const KEYHOG_GPU_MAX_BUFFER_CAP_MB: u64 = 256 * 1024;

/// Tier-B GPU self-test error CLASSIFICATION data, loaded from
/// `rules/gpu-lowering-gaps.toml`. Single source of truth shared by this
/// module's `collect_self_test_report` and `subcommands::doctor` (both classify
/// via [`is_known_vyre_lowering_gap`] / [`is_moe_parity_degrade`]), so the two
/// health surfaces can never drift into disagreeing about whether the same GPU
/// error is fatal. Operators extend the classifier by editing the Tier-B file,
/// never the code.
#[derive(serde::Deserialize)]
pub(crate) struct GpuLoweringGapRules {
    /// Substrings that mark a known VYRE direct-match lowering limitation. The
    /// production region-presence path has a separate mandatory probe.
    pub(crate) lowering_gap_markers: Vec<String>,
    /// Substrings that mark a GPU-MoE-vs-CPU-MoE parity divergence (detection
    /// fails closed to the deterministic CPU MoE), not a hard dispatch failure.
    pub(crate) moe_parity_degrade_markers: Vec<String>,
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
    match parse_gpu_lowering_gap_rules(include_str!("../../../../rules/gpu-lowering-gaps.toml")) {
        Ok(rules) => {
            assert!(
                !rules.lowering_gap_markers.is_empty()
                    && !rules.moe_parity_degrade_markers.is_empty(),
                "rules/gpu-lowering-gaps.toml must define non-empty lowering_gap_markers and \
                 moe_parity_degrade_markers; an empty set would misclassify every GPU self-test \
                 error as a hard FAIL"
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

/// True when a GPU self-test error is a GPU/CPU MoE parity divergence (GPU ML
/// acceleration degrades to the CPU MoE), not a hard dispatch failure.
pub(crate) fn is_moe_parity_degrade(error: &str) -> bool {
    GPU_LOWERING_GAP_RULES
        .moe_parity_degrade_markers
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
        return run_self_test(args.json, args.require_gpu);
    }
    if args.autoroute {
        return run_autoroute_inspection(args.json);
    }
    print_backend_report(&args)?;
    Ok(ExitCode::SUCCESS)
}

/// `keyhog backend --autoroute`: render the persisted autoroute calibration
/// cache so an operator can see which resolved configs and workload buckets are
/// calibrated (and to which backend), diagnosing a fail-closed scan. Read-only.
fn run_autoroute_inspection(json: bool) -> Result<ExitCode> {
    let path = crate::autoroute_cache_path::resolve_autoroute_cache_path(None)
        .map_err(|message| anyhow::anyhow!(message))?;
    let inspection = crate::orchestrator::inspect_autoroute_cache(path.as_deref());

    if json {
        println!("{}", serde_json::to_string_pretty(&inspection)?);
        return Ok(ExitCode::SUCCESS);
    }

    let p = style::for_stdout();
    println!("{}## autoroute calibration cache{}", p.bold, p.reset);
    match &inspection.path {
        Some(path) => println!("  path:            {path}"),
        None => println!("  path:            (disabled)"),
    }

    // Unusable cache (disabled / unreadable / wrong version / corrupt): a real
    // scan fails closed on the same input, so say so loudly with the next step.
    if let Some(error) = &inspection.error {
        println!("  status:          {}{}{}", p.yellow, error, p.reset);
        println!();
        println!(
            "Run `keyhog calibrate-autoroute` to (re)build the cache in place, or \
             `install.sh --calibrate` (Unix) / `install.ps1 -Calibrate` (Windows), or scan \
             with an explicit `--backend`."
        );
        return Ok(ExitCode::SUCCESS);
    }

    // Cache file absent: simply not calibrated yet.
    if !inspection.present {
        println!(
            "  status:          {}not calibrated yet{}",
            p.yellow, p.reset
        );
        println!();
        println!(
            "No autoroute cache here yet: auto scans fail closed until calibrated. Run \
             `keyhog calibrate-autoroute` to prime it in place, or `install.sh --calibrate` \
             (Unix) / `install.ps1 -Calibrate` (Windows), or scan with an explicit `--backend`."
        );
        return Ok(ExitCode::SUCCESS);
    }

    if let Some(version) = inspection.version {
        println!("  schema version:  {version}");
    }
    if let (Some(binary), Some(git)) = (&inspection.binary_version, &inspection.git_hash) {
        println!("  built for:       keyhog {binary} ({git})");
    }
    match inspection.identity_matches_build {
        Some(true) => println!(
            "  identity:        {}matches this build{} (host/detector/rules verified at scan time)",
            p.green, p.reset
        ),
        Some(false) => {
            println!(
                "  identity:        {}STALE (real scans will reject this cache){}",
                p.red, p.reset
            );
            if let Some(reason) = &inspection.identity_mismatch_reason {
                println!("                   {reason}");
            }
        }
        None => {}
    }
    if let Some(host) = &inspection.host {
        println!("  host:            {host}");
    }
    if let Some(detector) = &inspection.detector_digest {
        println!("  detector digest: {detector}");
    }
    if let Some(rules) = &inspection.rules_digest {
        println!("  rules digest:    {rules}");
    }

    println!();
    let total_decisions: usize = inspection.configs.iter().map(|c| c.decision_count).sum();
    println!(
        "{}{} calibrated config(s), {} workload decision(s){}",
        p.bold,
        inspection.configs.len(),
        total_decisions,
        p.reset
    );
    for config in &inspection.configs {
        println!();
        println!(
            "  {}config {}{}  -  {} decision(s)",
            p.cyan, config.config_digest, p.reset, config.decision_count
        );
        for decision in &config.decisions {
            let cpu = decision
                .cpu_ms
                .map(|ms| format!(" cpu={ms}ms"))
                .unwrap_or_default(); // LAW10: display-only optional timing; finding still printed; recall-safe
            let gpu = decision
                .gpu_ms
                .map(|ms| format!(" gpu={ms}ms"))
                .unwrap_or_default(); // LAW10: display-only optional timing; finding still printed; recall-safe
            let margin = decision
                .selected_margin_ns
                .map(|ns| format!(" margin={}µs", ns / 1_000))
                .unwrap_or_default(); // LAW10: display-only optional derived margin; recall-safe
            println!("    {}", decision.workload);
            println!(
                "        -> {}  {}[{} B / {} chunk(s); simd={}ms{}{}{}]{}",
                decision.backend,
                p.dim,
                decision.sample_bytes,
                decision.sample_chunks,
                decision.simd_ms,
                cpu,
                gpu,
                margin,
                p.reset
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn print_backend_report(args: &BackendArgs) -> Result<()> {
    let hw = probe_hardware();

    println!("## hardware");
    println!("  physical_cores:    {}", hw.physical_cores);
    println!("  logical_cores:     {}", hw.logical_cores);
    println!(
        "  simd:              {}",
        simd_label(hw.has_avx512, hw.has_avx2, hw.has_neon)
    );
    println!(
        "  gpu:               {} {}",
        if hw.gpu_available {
            hw.gpu_name.as_deref().unwrap_or("yes") // LAW10: absent name/label => display default; reporting-only, recall-safe
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
    println!("Force a scan backend with: keyhog scan --backend <auto|gpu|simd|cpu> ...");
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BackendSelfTestStatus {
    Pass,
    Fail,
    Warning,
    Known,
    Skip,
}

#[derive(Debug, Serialize)]
pub(crate) struct BackendSelfTestProbe {
    pub(crate) name: &'static str,
    pub(crate) status: BackendSelfTestStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) adapter_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) scores: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) max_buffer_mb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) direct_matches: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) coalesced_matches: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) matches: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) backend_id: Option<&'static str>,
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

    fn warning(name: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: BackendSelfTestStatus::Warning,
            message: Some(message.into()),
            ..Self::pass(name)
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct BackendSelfTestReport {
    pub(crate) ok: bool,
    pub(crate) status: BackendSelfTestStatus,
    pub(crate) exit_code: u8,
    pub(crate) gpu_available: bool,
    pub(crate) gpu_is_software: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) gpu_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) gpu_max_buffer_mb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recommended_backend: Option<&'static str>,
    pub(crate) probes: Vec<BackendSelfTestProbe>,
}

impl BackendSelfTestReport {
    fn exit_code(&self) -> ExitCode {
        ExitCode::from(self.exit_code)
    }
}

fn run_self_test(json: bool, require_gpu: bool) -> Result<ExitCode> {
    let report = collect_self_test_report(require_gpu);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_self_test_report(&report);
    }
    Ok(report.exit_code())
}

fn collect_self_test_report(require_gpu: bool) -> BackendSelfTestReport {
    let hw = probe_hardware();

    if !hw.gpu_available || hw.gpu_is_software {
        return unavailable_gpu_self_test_report(hw, require_gpu);
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
            // A GPU-MoE-vs-CPU-MoE parity divergence is a real shader/weights
            // fault, but it does NOT break detection: `batch_score_features` fails
            // closed to the CPU MoE (correct + deterministic), so scans on this
            // host produce the same findings, just without GPU ML acceleration.
            // Report it as a KNOWN limitation (like the vyre_literal_set lowering
            // gap below) instead of a hard FAIL, so `--self-test` and the installer
            // stay green for a host whose scans are correct, while still naming the
            // fault loudly so it gets fixed. A genuine GPU-unavailable/dispatch
            // failure stays a FAIL.
            let parity_degrade = is_moe_parity_degrade(&error);
            if parity_degrade {
                probes.push(BackendSelfTestProbe::known("moe_kernel", &error));
            } else {
                probes.push(BackendSelfTestProbe::fail("moe_kernel", error));
                all_ok = false;
            }
        }
    }

    // Test 2: VYRE's direct match-triple literal-set diagnostic. Production
    // scanning uses the scratch region-presence API exercised end to end by
    // the next probe. A direct-mode failure with the classified lowering
    // signature is visible as KNOWN, but never exempts the production probe.
    match keyhog_scanner::gpu::vyre_gpu_self_test() {
        Ok(report) => {
            let mut probe = BackendSelfTestProbe::pass("vyre_literal_set");
            probe.direct_matches = Some(report.direct_matches);
            probe.coalesced_matches = Some(report.coalesced_matches);
            probes.push(probe);
        }
        Err(error) => {
            let known_lowering_gap = is_known_vyre_lowering_gap(&error);
            if known_lowering_gap {
                probes.push(BackendSelfTestProbe::known(
                    "vyre_literal_set",
                    "VYRE IR lowering rejects the direct match-triple form; the production region-presence path is checked separately below",
                ));
            } else {
                probes.push(BackendSelfTestProbe::warning(
                    "vyre_literal_set",
                    format!(
                        "VYRE direct match-triple diagnostic failed ({error}); production scan eligibility is determined by gpu_region_presence"
                    ),
                ));
            }
        }
    }

    // Test 3: the production region-presence route. It builds a minimal
    // detector, dispatches through the same scanner path as a selected GPU
    // scan, and compares the final findings with the portable CPU reference.
    match keyhog_scanner::gpu::gpu_region_presence_self_test() {
        Ok(report) => {
            let mut probe = BackendSelfTestProbe::pass("gpu_region_presence");
            probe.matches = Some(report.matches);
            probe.backend_id = Some(report.backend_id);
            probes.push(probe);
        }
        Err(error) => {
            probes.push(BackendSelfTestProbe::fail("gpu_region_presence", error));
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
        exit_code: if all_ok {
            0
        } else {
            EXIT_BACKEND_SELF_TEST_FAILED
        },
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

fn unavailable_gpu_self_test_report(hw: &HardwareCaps, require_gpu: bool) -> BackendSelfTestReport {
    let reason = if !hw.gpu_available {
        "no GPU adapter detected"
    } else {
        "only software adapter (llvmpipe/lavapipe/swiftshader): won't be used for scans"
    };
    let status = if require_gpu {
        BackendSelfTestStatus::Fail
    } else {
        BackendSelfTestStatus::Skip
    };
    let message = if require_gpu {
        format!("--require-gpu requested but {reason}")
    } else {
        reason.to_string()
    };
    BackendSelfTestReport {
        ok: !require_gpu,
        status,
        exit_code: if require_gpu {
            EXIT_BACKEND_SELF_TEST_FAILED
        } else {
            EXIT_SUCCESS
        },
        gpu_available: hw.gpu_available,
        gpu_is_software: hw.gpu_is_software,
        gpu_name: hw.gpu_name.clone(),
        gpu_max_buffer_mb: hw.gpu_vram_mb,
        recommended_backend: Some("simd-regex"),
        probes: vec![BackendSelfTestProbe {
            name: "gpu_adapter",
            status,
            message: Some(message),
            adapter_name: None,
            scores: None,
            max_buffer_mb: None,
            direct_matches: None,
            coalesced_matches: None,
            matches: None,
            backend_id: None,
        }],
    }
}

fn print_self_test_report(report: &BackendSelfTestReport) {
    let palette = style::for_stdout();
    println!("## GPU self-test");
    if report.status == BackendSelfTestStatus::Skip {
        let message = report
            .probes
            .first()
            .and_then(|probe| probe.message.as_deref())
            .unwrap_or("GPU self-test skipped"); // LAW10: absent name/label => display default; reporting-only, recall-safe
        println!("  {}: {message}", style::warn("SKIP", &palette));
        return;
    }

    for probe in &report.probes {
        print!("  {:<17} ... ", probe.name);
        match probe.status {
            BackendSelfTestStatus::Pass => print_pass_probe(probe, &palette),
            BackendSelfTestStatus::Fail => {
                let message = probe.message.as_deref().unwrap_or("probe failed"); // LAW10: absent name/label => display default; reporting-only, recall-safe
                println!("{}  {message}", style::fail("FAIL", &palette));
            }
            BackendSelfTestStatus::Warning => {
                let message = probe.message.as_deref().unwrap_or("diagnostic warning"); // LAW10: absent probe detail => reporting-only display label; status remains visible
                println!("{}  {message}", style::warn("WARN", &palette));
            }
            BackendSelfTestStatus::Known => {
                let message = probe.message.as_deref().unwrap_or("known limitation"); // LAW10: absent name/label => display default; reporting-only, recall-safe
                println!("{} {message}.", style::warn("KNOWN", &palette));
            }
            BackendSelfTestStatus::Skip => {
                let message = probe.message.as_deref().unwrap_or("probe skipped"); // LAW10: absent name/label => display default; reporting-only, recall-safe
                println!("{}  {message}", style::warn("SKIP", &palette));
            }
        }
    }

    println!();
    if report.ok {
        println!(
            "{} GPU self-test passed, scans on this box can route to GPU.",
            style::pass("PASS", &palette)
        );
    } else {
        let stderr_palette = style::for_stderr();
        eprintln!(
            "{} GPU self-test failed; GPU routes are unavailable until fixed. \
             Use --backend simd/cpu or --no-gpu for an explicit CPU-only scan.",
            style::fail("FAIL", &stderr_palette)
        );
    }
}

fn print_pass_probe(probe: &BackendSelfTestProbe, palette: &Palette) {
    let pass = style::pass("PASS", palette);
    match probe.name {
        "moe_kernel" => println!(
            "{pass}  ({}, scores={}, max_buffer={} MB)",
            probe.adapter_name.as_deref().unwrap_or("unknown adapter"), // LAW10: absent name/label => display default; reporting-only, recall-safe
            format_probe_metric(probe.scores),
            format_probe_metric(probe.max_buffer_mb)
        ),
        "vyre_literal_set" => println!(
            "{pass}  (direct={}, coalesced={})",
            format_probe_metric(probe.direct_matches),
            format_probe_metric(probe.coalesced_matches)
        ),
        "gpu_region_presence" => println!(
            "{pass}  (matches={}, backend={})",
            format_probe_metric(probe.matches),
            probe.backend_id.unwrap_or("unknown") // LAW10: absent name/label => display default; reporting-only, recall-safe
        ),
        _ => println!("{pass}"),
    }
}

fn format_probe_metric<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "unknown".to_string(), |value| value.to_string())
}

fn render_self_test_json_for_contract(report: &BackendSelfTestReport) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(Into::into)
}

fn format_gpu_max_buffer(max_buffer_mb: u64) -> String {
    let base = if max_buffer_mb >= 1024 {
        format!("{} GB", max_buffer_mb / 1024)
    } else {
        format!("{max_buffer_mb} MB")
    };
    if max_buffer_mb >= KEYHOG_GPU_MAX_BUFFER_CAP_MB {
        format!(">={base} (keyhog cap; wgpu max_buffer_size)")
    } else {
        format!("{base} (wgpu max_buffer_size)")
    }
}

#[doc(hidden)]
pub(crate) mod testing {
    use anyhow::Result;

    pub(crate) fn render_failing_region_presence_probe_json() -> Result<String> {
        let report = super::BackendSelfTestReport {
            ok: false,
            status: super::BackendSelfTestStatus::Fail,
            exit_code: super::EXIT_BACKEND_SELF_TEST_FAILED,
            gpu_available: true,
            gpu_is_software: false,
            gpu_name: Some("NVIDIA GeForce RTX 5090".to_string()),
            gpu_max_buffer_mb: Some(262_144),
            recommended_backend: Some("simd-regex"),
            probes: vec![
                super::BackendSelfTestProbe {
                    name: "moe_kernel",
                    status: super::BackendSelfTestStatus::Pass,
                    message: None,
                    adapter_name: Some("NVIDIA GeForce RTX 5090".to_string()),
                    scores: Some(64),
                    max_buffer_mb: Some(262_144),
                    direct_matches: None,
                    coalesced_matches: None,
                    matches: None,
                    backend_id: None,
                },
                super::BackendSelfTestProbe {
                    name: "vyre_literal_set",
                    status: super::BackendSelfTestStatus::Known,
                    message: Some(
                        "vyre IR lowering rejects literal_set's subgroup form".to_string(),
                    ),
                    adapter_name: None,
                    scores: None,
                    max_buffer_mb: None,
                    direct_matches: None,
                    coalesced_matches: None,
                    matches: None,
                    backend_id: None,
                },
                super::BackendSelfTestProbe {
                    name: "gpu_region_presence",
                    status: super::BackendSelfTestStatus::Fail,
                    message: Some("GPU region-presence dispatch failed".to_string()),
                    adapter_name: None,
                    scores: None,
                    max_buffer_mb: None,
                    direct_matches: None,
                    coalesced_matches: None,
                    matches: None,
                    backend_id: None,
                },
            ],
        };

        super::render_self_test_json_for_contract(&report)
    }

    pub(crate) fn format_gpu_max_buffer(max_buffer_mb: u64) -> String {
        super::format_gpu_max_buffer(max_buffer_mb)
    }

    pub(crate) fn format_probe_count_metric(value: Option<usize>) -> String {
        super::format_probe_metric(value)
    }

    pub(crate) fn format_probe_mb_metric(value: Option<u64>) -> String {
        super::format_probe_metric(value)
    }
}

#[cfg(test)]
mod tests;
