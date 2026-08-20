//! `keyhog calibrate-autoroute`: drive the full install-time autoroute
//! calibration sweep in one command.
//!
//! The installers used to hand-roll this probe loop twice. POSIX sh in
//! `install.sh`, PowerShell in `install.ps1`: generating a stdin + filesystem
//! workload ladder and then running `keyhog scan --autoroute-calibrate` once
//! per (scan-policy preset × workload) so every bucket a real scan looks up is
//! persisted before the scan path goes live. That orchestration now lives here,
//! in one testable place; the installer keeps only the external source probes
//! (git / docker / web) that need environment orchestration this command does
//! not own (Screwdriver Principle: one job, the core workload sweep, done
//! precisely).
//!
//! Each policy owns one production [`crate::orchestrator::ScanOrchestrator`]
//! and reuses its compiled scanner plus initialized backend peers across the
//! workload ladder. Every representative still enters through the canonical
//! source and measured-router paths. Rebuilding the full scanner in a fresh
//! child process for every representative made install calibration take
//! hours while measuring startup work that is not part of the route decision.

use crate::args::{AutorouteCalibrationPolicy, CalibrateAutorouteArgs, ScanArgs};
use crate::orchestrator::ScanOrchestrator;
use crate::style::Palette;
use anyhow::{Context, Result};
use clap::Parser;
use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::{Arc, Mutex};

/// This binary's own scan-policy preset flags, swept in addition to the default
/// policy. Each resolves a distinct autoroute config digest, so each needs its
/// own calibrated decisions to claim a fastest route. Until then, a normal
/// `keyhog scan <preset>` fails closed without scanning.
/// Keep in sync with the `--fast` / `--deep` / `--precision` flags in
/// `args::scan`; the `every_documented_preset_resolves` e2e gate fails if a
/// preset is missing a calibrated decision.
const SCAN_POLICY_PRESETS: &[&str] = &["--fast", "--deep", "--precision"];
const MAX_INCONCLUSIVE_CALIBRATION_ATTEMPTS: usize = 3;

fn selected_policy_flags(policy: AutorouteCalibrationPolicy) -> Vec<Option<&'static str>> {
    match policy {
        AutorouteCalibrationPolicy::Default => vec![None],
        AutorouteCalibrationPolicy::Fast => vec![Some("--fast")],
        AutorouteCalibrationPolicy::Deep => vec![Some("--deep")],
        AutorouteCalibrationPolicy::Precision => vec![Some("--precision")],
        AutorouteCalibrationPolicy::All => std::iter::once(None)
            .chain(SCAN_POLICY_PRESETS.iter().copied().map(Some))
            .collect(),
    }
}

/// A 1 KiB block of plain, low-decode-density text. The installer builds probes
/// as whole 1 KiB blocks; mirroring the block size keeps a Rust-generated probe
/// in the exact same size / decode-density bucket a shell-generated one landed.
const PLAIN_SEED: &str = "src path one. scan text two. keyhog route plain. config value sample. ";

/// Valid, checksum-bearing sparse trigger used in plain calibration probes.
/// One occurrence per 64 KiB makes the route measurement exercise real
/// phase-2 confirmation without turning the sample into an artificial secret
/// dump. A zero-trigger calibration systematically overstates GPU wins because
/// phase 2 remains host work for every backend.
const SPARSE_TRIGGER: &[u8] = b"GITHUB_TOKEN=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\n";
const SPARSE_TRIGGER_INTERVAL: usize = 64 * 1024;

/// A 1 KiB block dense with base64 runs, the decode-heavy bucket the scanner's
/// decode-through path is timed against. Mirrors the installer's seed.
const DECODE_HEAVY_SEED: &str = "apiVersion:v1 kind:Secret data token:QUtJQUlPU0ZPRE5ON0VYQU1QTEVBS0lBSU9TRk9ETk43RVhBTVBMRT0= payload:c2stcHJvai1BQkNkZWZHSElKS0xtbm9QUVJTVFVWV1hZWjAxMjM0NTY3ODkwPQ== ";

/// One calibration workload and its canonical source materialization shape.
enum Workload {
    /// Pipe `bytes` of plain content over stdin.
    Stdin { label: &'static str, bytes: usize },
    /// A single file of exactly `bytes`; `decode_heavy` selects the base64-dense block.
    File {
        label: &'static str,
        bytes: usize,
        decode_heavy: bool,
    },
    /// A directory of `files` files, each `kib` KiB of plain content.
    Tree {
        label: String,
        files: usize,
        kib: usize,
    },
    /// A tar archive whose extracted members exercise payload-derived filesystem routing.
    Tar {
        label: String,
        members: usize,
        kib: usize,
    },
    /// An exact source identity measured with both streamed and known-size metadata shapes.
    SourceClass {
        label: String,
        source_class: &'static str,
        bytes: usize,
        has_full_size: bool,
    },
}

impl Workload {
    fn label(&self) -> &str {
        match self {
            Workload::Stdin { label, .. } | Workload::File { label, .. } => label,
            Workload::Tree { label, .. }
            | Workload::Tar { label, .. }
            | Workload::SourceClass { label, .. } => label.as_str(),
        }
    }
}

/// The core stdin + filesystem workload ladder. The sizes span the autoroute
/// byte and decode-density bands a real scan resolves. Tree probes cover every
/// production fused count because bounded decoder admission may distinguish
/// adjacent counts within one logarithmic chunk band.
fn core_workload_plan() -> Vec<Workload> {
    let mut workloads = vec![
        Workload::Stdin {
            label: "stdin 64 KiB workload",
            bytes: 64 * 1024,
        },
        Workload::File {
            label: "1 B workload",
            bytes: 1,
            decode_heavy: false,
        },
        Workload::File {
            label: "2 B workload",
            bytes: 2,
            decode_heavy: false,
        },
        Workload::File {
            label: "4 B workload",
            bytes: 4,
            decode_heavy: false,
        },
        Workload::File {
            label: "8 B workload",
            bytes: 8,
            decode_heavy: false,
        },
        Workload::File {
            label: "16 B workload",
            bytes: 16,
            decode_heavy: false,
        },
        Workload::File {
            label: "32 B workload",
            bytes: 32,
            decode_heavy: false,
        },
        Workload::File {
            label: "64 B workload",
            bytes: 64,
            decode_heavy: false,
        },
        Workload::File {
            label: "128 B workload",
            bytes: 128,
            decode_heavy: false,
        },
        Workload::File {
            label: "256 B workload",
            bytes: 256,
            decode_heavy: false,
        },
        Workload::File {
            label: "512 B workload",
            bytes: 512,
            decode_heavy: false,
        },
        Workload::File {
            label: "1 KiB workload",
            bytes: 1024,
            decode_heavy: false,
        },
        Workload::File {
            label: "2 KiB workload",
            bytes: 2 * 1024,
            decode_heavy: false,
        },
        Workload::File {
            label: "4 KiB workload",
            bytes: 4 * 1024,
            decode_heavy: false,
        },
        Workload::File {
            label: "8 KiB workload",
            bytes: 8 * 1024,
            decode_heavy: false,
        },
        Workload::File {
            label: "16 KiB workload",
            bytes: 16 * 1024,
            decode_heavy: false,
        },
        Workload::File {
            label: "32 KiB workload",
            bytes: 32 * 1024,
            decode_heavy: false,
        },
        Workload::File {
            label: "64 KiB workload",
            bytes: 64 * 1024,
            decode_heavy: false,
        },
        Workload::File {
            label: "128 KiB workload",
            bytes: 128 * 1024,
            decode_heavy: false,
        },
        Workload::File {
            label: "256 KiB workload",
            bytes: 256 * 1024,
            decode_heavy: false,
        },
        Workload::File {
            label: "512 KiB workload",
            bytes: 512 * 1024,
            decode_heavy: false,
        },
        Workload::File {
            label: "1 MiB workload",
            bytes: 1024 * 1024,
            decode_heavy: false,
        },
        Workload::File {
            label: "2 MiB workload",
            bytes: 2 * 1024 * 1024,
            decode_heavy: false,
        },
        Workload::File {
            label: "4 MiB workload",
            bytes: 4 * 1024 * 1024,
            decode_heavy: false,
        },
        Workload::File {
            label: "4 MiB + 1 byte workload",
            bytes: 4 * 1024 * 1024 + 1,
            decode_heavy: false,
        },
        Workload::File {
            label: "8 MiB - 1 byte workload",
            bytes: 8 * 1024 * 1024 - 1,
            decode_heavy: false,
        },
        Workload::File {
            label: "8 MiB workload",
            bytes: 8 * 1024 * 1024,
            decode_heavy: false,
        },
        Workload::File {
            label: "8 MiB + 1 byte workload",
            bytes: 8 * 1024 * 1024 + 1,
            decode_heavy: false,
        },
        Workload::File {
            label: "16 MiB - 1 byte workload",
            bytes: 16 * 1024 * 1024 - 1,
            decode_heavy: false,
        },
        Workload::File {
            label: "16 MiB workload",
            bytes: 16 * 1024 * 1024,
            decode_heavy: false,
        },
        Workload::File {
            label: "32 MiB workload",
            bytes: 32 * 1024 * 1024,
            decode_heavy: false,
        },
        Workload::File {
            label: "decode-heavy 4 KiB workload",
            bytes: 4 * 1024,
            decode_heavy: true,
        },
        Workload::File {
            label: "decode-heavy 64 KiB workload",
            bytes: 64 * 1024,
            decode_heavy: true,
        },
        Workload::File {
            label: "decode-heavy 256 KiB workload",
            bytes: 256 * 1024,
            decode_heavy: true,
        },
    ];
    let fused_batch_counts = crate::orchestrator_config::fused_batch_calibration_counts();
    workloads.extend(
        fused_batch_counts
            .iter()
            .copied()
            .map(|files| Workload::Tree {
                label: format!("{files} x 4 KiB files workload"),
                files,
                kib: 4,
            }),
    );
    workloads.extend(fused_batch_counts.into_iter().map(|members| Workload::Tar {
        label: format!("{members} x 4 KiB tar members workload"),
        members,
        kib: 4,
    }));
    for source_class in crate::orchestrator::canonical_source_classes() {
        for has_full_size in [false, true] {
            workloads.push(Workload::SourceClass {
                label: format!(
                    "source class {source_class} ({}) workload",
                    if has_full_size {
                        "known-size"
                    } else {
                        "streamed"
                    }
                ),
                source_class,
                bytes: 64 * 1024,
                has_full_size,
            });
        }
    }
    workloads
}

#[cfg(any(test, feature = "ci-lean"))]
fn bounded_e2e_workload_plan(mut workloads: Vec<Workload>) -> Result<Vec<Workload>> {
    workloads.retain(|workload| {
        matches!(
            workload.label(),
            "1 KiB workload" | "4 KiB workload" | "64 KiB workload"
        )
    });
    if workloads.len() != 3 {
        anyhow::bail!(
            "bounded-e2e-v1 expected three canonical file workloads, found {}",
            workloads.len()
        );
    }
    Ok(workloads)
}

#[cfg(any(test, feature = "ci-lean"))]
fn selected_workload_plan() -> Result<Vec<Workload>> {
    const FIXTURE_ENV: &str = "KEYHOG_CI_AUTOROUTE_WORKLOAD_FIXTURE";
    const AUTH_ENV: &str = "KEYHOG_CI_AUTOROUTE_WORKLOAD_FIXTURE_AUTH";
    const AUTH: &str = "core-workload-plan-v1";

    let workloads = core_workload_plan();
    let Some(fixture) = std::env::var_os(FIXTURE_ENV) else {
        return Ok(workloads);
    };
    if std::env::var(AUTH_ENV).as_deref() != Ok(AUTH) {
        anyhow::bail!(
            "test-only autoroute workload fixture authorization failed; {AUTH_ENV} must equal {AUTH:?}"
        );
    }
    match fixture.to_string_lossy().as_ref() {
        "bounded-e2e-v1" => bounded_e2e_workload_plan(workloads),
        fixture => {
            anyhow::bail!("unsupported {FIXTURE_ENV} value {fixture:?}; expected bounded-e2e-v1")
        }
    }
}

#[cfg(not(any(test, feature = "ci-lean")))]
fn selected_workload_plan() -> Result<Vec<Workload>> {
    Ok(core_workload_plan())
}

/// Build `total` bytes of calibration content by repeating `seed`'s 1 KiB block.
/// The final repetition is truncated for sub-KiB and non-aligned probes, matching
/// the installers' exact-byte probe writers.
fn calibration_bytes(seed: &str, total: usize) -> Vec<u8> {
    let block = calibration_block(seed);
    if total == 0 {
        return Vec::new();
    }
    let reps = total.div_ceil(block.len());
    let mut out = Vec::with_capacity(reps * block.len());
    for _ in 0..reps {
        out.extend_from_slice(&block);
    }
    out.truncate(total);
    out
}

fn plain_calibration_bytes(total: usize) -> Vec<u8> {
    let mut bytes = calibration_bytes(PLAIN_SEED, total);
    if total < SPARSE_TRIGGER_INTERVAL {
        return bytes;
    }
    for end in (SPARSE_TRIGGER_INTERVAL..=total).step_by(SPARSE_TRIGGER_INTERVAL) {
        let start = end - SPARSE_TRIGGER.len();
        bytes[start..end].copy_from_slice(SPARSE_TRIGGER);
    }
    bytes
}

/// Expand `seed` to exactly 1024 bytes (repeat then truncate), matching the
/// installer's `printf '%.1024s'` block.
fn calibration_block(seed: &str) -> Vec<u8> {
    let mut block = String::with_capacity(1024 + seed.len());
    while block.len() < 1024 {
        block.push_str(seed);
    }
    block.truncate(1024);
    block.into_bytes()
}

/// A measurement whose intervals merely overlap now resolves to a dead-heat
/// route instead of failing, so what remains retryable is a measurement that
/// produced no usable timing at all or whose points disagree about the backend.
fn retryable_inconclusive_calibration(error: &anyhow::Error) -> bool {
    let diagnostic = format!("{error:#}");
    diagnostic.contains("calibration timing does not resolve one route")
        || diagnostic.contains("no confidence-supported one-shot route")
        || diagnostic.contains("no confidence-supported daemon route")
        || diagnostic.contains(
            "workload class changes its confidence-supported backend across measured points",
        )
        || diagnostic.contains("workload class changes its confidence-supported remaining")
        || diagnostic.contains("workload evidence has no unanimous")
        || diagnostic.contains("workload point does not resolve one")
        || (diagnostic.contains("workload point has no ")
            && diagnostic.contains(" recovery route after "))
}

fn policy_cli_value(policy: AutorouteCalibrationPolicy) -> &'static str {
    match policy {
        AutorouteCalibrationPolicy::Default => "default",
        AutorouteCalibrationPolicy::Fast => "fast",
        AutorouteCalibrationPolicy::Deep => "deep",
        AutorouteCalibrationPolicy::Precision => "precision",
        AutorouteCalibrationPolicy::All => "all",
    }
}

type MeasuredRouteClass = (String, String, String);

fn write_measurement_receipts(path: &Path, receipts: &BTreeSet<MeasuredRouteClass>) -> Result<()> {
    let bytes =
        serde_json::to_vec(receipts).context("serializing autoroute measurement receipts")?;
    crate::atomic_file::write_bytes(path, &bytes)
        .with_context(|| format!("writing autoroute measurement receipts {}", path.display()))
}

fn read_measurement_receipts(path: &Path) -> Result<BTreeSet<MeasuredRouteClass>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading autoroute measurement receipts {}", path.display()))?;
    let receipts = serde_json::from_slice(&bytes)
        .with_context(|| format!("decoding autoroute measurement receipts {}", path.display()))?;
    Ok(receipts)
}

/// The argv one isolated policy child runs.
///
/// Every flag that reaches the parent and changes what a probe MEASURES has to
/// reach the child, because the child is what measures. `--no-config` did not:
/// `install.sh` asked for the compiled-in baseline, the parent honored it, and
/// the four children resolved whatever `.keyhog.toml` the install directory
/// happened to carry. A 40-minute install then published 629 decisions under
/// four config digests no ordinary scan requests, and the first `keyhog scan`
/// after it exited 2 with "none matching config digest".
///
/// The three flags the parent owns rather than forwards are `--policy` (the
/// child calibrates exactly one), `--autoroute-cache` (children write the
/// parent's staged transaction, not the live cache) and
/// `--measurement-receipts` (one sink per child).
fn isolated_policy_argv(
    args: &CalibrateAutorouteArgs,
    policy_name: &str,
    staged_cache_path: &Path,
    receipt_path: &Path,
) -> Vec<OsString> {
    let mut argv = vec![
        OsString::from("calibrate-autoroute"),
        OsString::from("--policy"),
        OsString::from(policy_name),
        OsString::from("--autoroute-cache"),
        staged_cache_path.as_os_str().to_owned(),
        OsString::from("--measurement-receipts"),
        receipt_path.as_os_str().to_owned(),
    ];
    if args.no_config {
        argv.push(OsString::from("--no-config"));
    }
    if args.quiet {
        argv.push(OsString::from("--quiet"));
    }
    if let Some(packs) = args.execution_packs.as_deref() {
        argv.push(OsString::from("--execution-packs"));
        argv.push(packs.as_os_str().to_owned());
    }
    if let Some(key) = args.signing_key.as_deref() {
        argv.push(OsString::from("--signing-key"));
        argv.push(key.as_os_str().to_owned());
    }
    argv
}

fn run_all_policies_in_isolated_processes(args: &CalibrateAutorouteArgs) -> Result<ExitCode> {
    let workload_count = selected_workload_plan()?.len();
    let live_cache_path =
        crate::autoroute_cache_path::resolve_autoroute_cache_path(args.autoroute_cache.as_deref())
            .map_err(anyhow::Error::msg)?
            .ok_or_else(|| {
                anyhow::anyhow!("autoroute calibration requires a writable cache file")
            })?;
    let workspace = tempfile::Builder::new()
        .prefix("keyhog-autoroute-all-")
        .tempdir()
        .context("creating the all-policy autoroute transaction workspace")?;
    let transaction = crate::orchestrator::StagedAutorouteCache::begin(
        &live_cache_path,
        &workspace.path().join("autoroute-all-staged.json"),
    )
    .with_context(|| {
        format!(
            "preparing an all-policy autoroute generation for {}",
            live_cache_path.display()
        )
    })?;
    let staged_cache_path = transaction.staged_path().to_path_buf();
    let executable = keyhog_core::current_executable_path().map_err(anyhow::Error::msg)?;
    let mut measured_routes = BTreeSet::new();
    for policy in [
        AutorouteCalibrationPolicy::Default,
        AutorouteCalibrationPolicy::Fast,
        AutorouteCalibrationPolicy::Deep,
        AutorouteCalibrationPolicy::Precision,
    ] {
        let policy_name = policy_cli_value(policy);
        let receipt_path = workspace
            .path()
            .join(format!("autoroute-{policy_name}-receipts.json"));
        let mut command = Command::new(&executable);
        command.args(isolated_policy_argv(
            args,
            policy_name,
            &staged_cache_path,
            &receipt_path,
        ));
        let status = command
            .status()
            .with_context(|| format!("starting isolated {policy_name} autoroute calibration"))?;
        if !status.success() {
            anyhow::bail!(
                "isolated {policy_name} autoroute calibration failed with {status}; the live \
                 autoroute cache was not changed. Remediation: rerun `keyhog \
                 calibrate-autoroute` on an idle host; use an explicit `--backend` only for a \
                 diagnostic scan"
            );
        }
        let policy_receipts = read_measurement_receipts(&receipt_path)
            .with_context(|| format!("{policy_name} calibration returned no usable receipt set"))?;
        if policy_receipts.is_empty() {
            anyhow::bail!(
                "isolated {policy_name} autoroute calibration reported success without any \
                 measured route receipts; the live autoroute cache was not changed"
            );
        }
        measured_routes.extend(policy_receipts);
    }

    if let Some(binding) = resolve_execution_pack_binding(
        args.execution_packs.as_deref(),
        args.signing_key.as_deref(),
    )? {
        crate::orchestrator::bind_autoroute_cache_to_execution_packs(&staged_cache_path, binding)
            .context("binding all-policy calibration evidence to exact execution packs")?;
    }

    let staged_inspection = crate::orchestrator::inspect_autoroute_cache(Some(&staged_cache_path));
    if let Some(error) = staged_inspection.error.as_deref() {
        anyhow::bail!(
            "isolated policy calibrations completed, but staged cache readback failed: {error}; \
             the live autoroute cache was not changed"
        );
    }
    if !matches!(
        staged_inspection.readiness(),
        crate::orchestrator::AutorouteReadiness::Ready
            | crate::orchestrator::AutorouteReadiness::Quarantined
    ) {
        anyhow::bail!(
            "isolated policy calibrations completed, but staged cache readiness is {}; the live \
             autoroute cache was not changed; repair: `{}`",
            staged_inspection.readiness().as_str(),
            staged_inspection
                .readiness()
                .required_repair_command()
                .map_err(anyhow::Error::msg)?
        );
    }
    let staged_routes = staged_inspection
        .configs
        .iter()
        .flat_map(|config| {
            config.decisions.iter().map(|decision| {
                (
                    config.config_digest.clone(),
                    config.host_identity.clone(),
                    decision.workload.clone(),
                )
            })
        })
        .collect();
    calibration_summary_counts(&staged_routes, &measured_routes)?;
    transaction.publish(&measured_routes).with_context(|| {
        format!(
            "publishing the complete all-policy autoroute generation to {}",
            live_cache_path.display()
        )
    })?;

    let inspection = crate::orchestrator::inspect_autoroute_cache(Some(&live_cache_path));
    if let Some(error) = inspection.error.as_deref() {
        anyhow::bail!("all-policy autoroute generation published, but readback failed: {error}");
    }
    let live_routes = inspection
        .configs
        .iter()
        .flat_map(|config| {
            config.decisions.iter().map(|decision| {
                (
                    config.config_digest.clone(),
                    config.host_identity.clone(),
                    decision.workload.clone(),
                )
            })
        })
        .collect();
    let (decisions, measured_decisions) =
        calibration_summary_counts(&live_routes, &measured_routes)?;
    let palette = crate::style::for_stdout();
    println!(
        "{} ran {} workload probes across 4 scan policies in isolated policy processes; \
         atomically published {measured_decisions} measured route classes; combined cache \
         contains {decisions} route decisions",
        crate::style::pass("PASS", &palette),
        workload_count * 4
    );
    Ok(ExitCode::SUCCESS)
}

/// The execution-pack generation this calibration binds its evidence to.
///
/// An operator who names a generation gets it or an error: an unauthenticated
/// directory they asked for is a failure, not something to work around.
///
/// With no flag the installed generation is used when it authenticates, because
/// that is the artifact set the probes just ran against. Requiring the flag
/// instead left every ordinary install unbound: `install.sh` calls
/// `keyhog calibrate-autoroute` with no arguments, so `keyhog doctor` reported
/// `route binding MISSING` on a host that had just calibrated successfully, and
/// the repair line it printed named a hidden flag. A missing or unauthenticated
/// generation leaves the evidence unbound, exactly as an install without packs
/// does.
fn resolve_execution_pack_binding(
    requested: Option<&Path>,
    signing_key: Option<&Path>,
) -> Result<Option<crate::execution_pack_install::ExecutionPackGenerationBinding>> {
    if let Some(directory) = requested {
        return crate::execution_pack_install::load_authenticated_binding(directory, signing_key)
            .map(Some)
            .context("loading authenticated execution-pack generation for calibration");
    }
    let installed = crate::execution_pack_install::installed_execution_pack_directory()
        .context("resolving the installed execution-pack generation for calibration")?;
    if !installed.exists() {
        return Ok(None);
    }
    match crate::execution_pack_install::load_authenticated_binding(&installed, signing_key) {
        Ok(binding) => Ok(Some(binding)),
        Err(error) => {
            eprintln!(
                "keyhog: installed execution-pack generation is not authenticated ({error}); autoroute evidence stays unbound"
            );
            Ok(None)
        }
    }
}

pub(crate) fn run(args: CalibrateAutorouteArgs) -> Result<ExitCode> {
    // Calibration EXISTS to persist routing decisions; `--autoroute-cache off`
    // disables persistence, so every probe would fail closed ("calibration did
    // not persist a routing decision"). Reject it up front with one clear line
    // instead of a flood of per-probe failures.
    if args
        .autoroute_cache
        .as_deref()
        .is_some_and(|cache| cache.trim().eq_ignore_ascii_case("off"))
    {
        anyhow::bail!(
            "`--autoroute-cache off` disables persistence, but calibrate-autoroute exists to \
             persist routing decisions; every probe would fail closed. Drop the flag to use the \
             default cache, or pass a writable file path."
        );
    }
    let execution_pack_binding = resolve_execution_pack_binding(
        args.execution_packs.as_deref(),
        args.signing_key.as_deref(),
    )?;
    if !keyhog_scanner::hw_probe::multiple_backends_compiled() {
        if !args.quiet {
            println!(
                "{} direct scalar route requires no autoroute timing calibration",
                crate::style::pass("PASS", &crate::style::for_stdout())
            );
        }
        return Ok(ExitCode::SUCCESS);
    }
    if args.policy == AutorouteCalibrationPolicy::All {
        return run_all_policies_in_isolated_processes(&args);
    }

    let cache_path =
        crate::autoroute_cache_path::resolve_autoroute_cache_path(args.autoroute_cache.as_deref())
            .map_err(anyhow::Error::msg)?;
    let workspace = tempfile::Builder::new()
        .prefix("keyhog-autoroute-prime-")
        .tempdir()
        .context("could not create the autoroute calibration workspace")?;
    let live_cache_path = cache_path.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "autoroute calibration requires a writable cache file; `off`, `0`, and an empty path disable persistence"
        )
    })?;
    let transaction = crate::orchestrator::StagedAutorouteCache::begin(
        live_cache_path,
        &workspace.path().join("autoroute-staged.json"),
    )
    .with_context(|| {
        format!(
            "preparing an isolated autoroute calibration generation for {}",
            live_cache_path.display()
        )
    })?;

    let workloads = selected_workload_plan()?;
    let policy_flags = selected_policy_flags(args.policy);
    let total = workloads.len() * policy_flags.len();

    let p = crate::style::for_stdout();
    if !args.quiet {
        println!(
            "{bold}Autoroute calibration{reset} {dim}({total} core workload probes across {passes} scan {policy_word}){reset}",
            bold = p.bold,
            reset = p.reset,
            dim = p.dim,
            passes = policy_flags.len(),
            policy_word = if policy_flags.len() == 1 { "policy" } else { "policies" },
        );
    }

    let mut idx = 0usize;
    let mut failed = 0usize;
    let mut inconclusive_failed = 0usize;
    let mut failed_probe_labels = Vec::new();
    failed_probe_labels
        .try_reserve_exact(total)
        .context("reserving autoroute failure diagnostics")?;
    let measured_points = Arc::new(Mutex::new(BTreeSet::new()));
    let hardware = keyhog_scanner::hw_probe::probe_hardware();
    let physical_gpu_available = hardware.gpu_available && !hardware.gpu_is_software;
    // Probe sweep: the calibration measurement (collect/compute) phase.
    let sweep_span = keyhog_profile::span(keyhog_profile::Stage::Preprocess);
    for policy in &policy_flags {
        let policy_label = policy.unwrap_or("default policy"); // LAW10: documented default label only; it does not select a fallback backend
        let scan_args = calibration_scan_args(
            Some(transaction.staged_path()),
            *policy,
            physical_gpu_available,
            args.no_config,
        )
        .with_context(|| format!("constructing {policy_label} calibration runtime"))?;
        let mut orchestrator = ScanOrchestrator::new(scan_args)
            .with_context(|| format!("initializing {policy_label} calibration runtime"))?;
        orchestrator
            .prepare_autoroute_calibration_gpu_artifact()
            .with_context(|| {
                format!("preparing every eligible backend for {policy_label} calibration")
            })?;
        orchestrator
            .observe_autoroute_calibration_measurements(Arc::clone(&measured_points))
            .with_context(|| format!("observing {policy_label} calibration route receipts"))?;
        let mut sweep = ProbeSweep {
            orchestrator: &mut orchestrator,
            workspace: workspace.path(),
            policy_label,
            total,
            quiet: args.quiet,
            palette: &p,
        };
        for workload in &workloads {
            idx += 1;
            let mut attempt = 1usize;
            loop {
                let measured_before = measured_points
                    .lock()
                    .map_err(|_| anyhow::anyhow!("autoroute measurement observer lock poisoned"))?
                    .clone();
                match sweep.run_probe(workload, idx) {
                    Ok(()) => break,
                    Err(error)
                        if attempt < MAX_INCONCLUSIVE_CALIBRATION_ATTEMPTS
                            && retryable_inconclusive_calibration(&error) =>
                    {
                        *measured_points.lock().map_err(|_| {
                            anyhow::anyhow!("autoroute measurement observer lock poisoned")
                        })? = measured_before;
                        attempt += 1;
                        eprintln!(
                            "    {} inconclusive timing evidence; retrying {}/{}: {error:#}",
                            crate::style::warn("retry:", &p),
                            attempt,
                            MAX_INCONCLUSIVE_CALIBRATION_ATTEMPTS,
                        );
                    }
                    Err(error) => {
                        failed += 1;
                        if retryable_inconclusive_calibration(&error) {
                            inconclusive_failed += 1;
                        }
                        failed_probe_labels.push(format!("{policy_label}: {}", workload.label()));
                        // The probe already printed its FAIL line; surface the cause
                        // loudly (Law 10) rather than swallowing it behind the counter.
                        eprintln!("    {} {error:#}", crate::style::fail("reason:", &p));
                        break;
                    }
                }
            }
        }
    }

    if failed > 0 {
        let failed_probe_list = failed_probe_labels.join(", ");
        if failed == inconclusive_failed {
            // Timing overlap is an honest absence of routing evidence, never a
            // successful calibration. Keep the terminal diagnostic stable so
            // installers and operators can distinguish this retryable state
            // from parity, persistence, and corpus failures.
            anyhow::bail!(
                "autoroute calibration is inconclusive for [{failed_probe_list}]; no routing \
                 generation was published. Remediation: rerun `keyhog calibrate-autoroute` on \
                 an idle host; use an explicit `--backend` only for a diagnostic scan"
            );
        }
        anyhow::bail!(
            "autoroute calibration failed for {failed}/{total} workload probes \
             [{failed_probe_list}]; persisted routing was not updated for every required bucket"
        );
    }

    drop(sweep_span);
    if let Some(binding) = execution_pack_binding {
        crate::orchestrator::bind_autoroute_cache_to_execution_packs(
            transaction.staged_path(),
            binding,
        )
        .context("binding calibration evidence to exact execution packs")?;
    }
    // Persisted cache readback after the sweep, profiled as an incremental
    // lookup.
    let inspection = {
        let _cache_span = keyhog_profile::span(keyhog_profile::Stage::IncrementalLookup);
        crate::orchestrator::inspect_autoroute_cache(Some(transaction.staged_path()))
    };
    if let Some(error) = inspection.error.as_deref() {
        anyhow::bail!(
            "autoroute calibration probes succeeded, but persisted cache readback failed: {error}"
        );
    }
    if !inspection.present {
        anyhow::bail!(
            "autoroute calibration probes succeeded, but no persisted cache was found during readback"
        );
    }
    let readiness = inspection.readiness();
    match readiness {
        crate::orchestrator::AutorouteReadiness::Ready
        | crate::orchestrator::AutorouteReadiness::Quarantined => {}
        crate::orchestrator::AutorouteReadiness::Direct => anyhow::bail!(
            "autoroute calibration is not applicable because this build has one direct backend"
        ),
        _ => anyhow::bail!(
            "autoroute calibration probes succeeded, but persisted cache readback is {}; repair: `{}`",
            readiness.as_str(),
            readiness
                .required_repair_command()
                .map_err(anyhow::Error::msg)?
        ),
    }
    let measured_points = measured_points
        .lock()
        .map_err(|_| {
            anyhow::anyhow!(
                "autoroute measured-route observer lock was poisoned, so the calibration summary cannot be trusted; rerun `keyhog calibrate-autoroute`"
            )
        })?;
    let persisted_points = inspection
        .configs
        .iter()
        .flat_map(|config| {
            config.decisions.iter().flat_map(|decision| {
                decision.measured_points.iter().map(|point| {
                    crate::orchestrator::AutorouteMeasurementReceipt {
                        config_digest: config.config_digest.clone(),
                        host_identity: config.host_identity.clone(),
                        workload: decision.workload.clone(),
                        measurement_shape_digest: point.measurement_shape_digest.clone(),
                    }
                })
            })
        })
        .collect::<BTreeSet<_>>();
    let measured_route_classes = measured_points
        .iter()
        .map(|receipt| {
            (
                receipt.config_digest.clone(),
                receipt.host_identity.clone(),
                receipt.workload.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let persisted_route_classes = persisted_points
        .iter()
        .map(|receipt| {
            (
                receipt.config_digest.clone(),
                receipt.host_identity.clone(),
                receipt.workload.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let (persisted_decisions, measured_unique_decisions) =
        calibration_summary_counts(&persisted_route_classes, &measured_route_classes)?;
    let measured_point_count =
        calibration_point_summary_count(&persisted_points, &measured_points)?;
    if persisted_decisions == 0 {
        anyhow::bail!(
            "autoroute calibration probes succeeded, but persisted cache readback contained no route decisions"
        );
    }
    // Fresh calibration routers reject reuse until a workload key is measured
    // in this run. Count their canonical post-save receipts. Existing rows
    // under the same config digest or another host are cache inventory, not
    // evidence that this invocation measured them.
    if measured_unique_decisions == 0 {
        anyhow::bail!(
            "autoroute calibration probes succeeded, but persisted cache readback contained no newly measured route classes"
        );
    }
    let cache_note = match args.autoroute_cache.as_deref() {
        Some(path) => path.to_string(),
        None => "the default autoroute cache".to_string(),
    };
    // Generation publication, profiled as reporting.
    let _publish_span = keyhog_profile::span(keyhog_profile::Stage::Reporting);
    transaction
        .publish(&measured_route_classes)
        .with_context(|| {
            format!(
                "publishing the complete autoroute calibration generation to {}",
                live_cache_path.display()
            )
        })?;
    let inspection = crate::orchestrator::inspect_autoroute_cache(Some(live_cache_path));
    if let Some(error) = inspection.error.as_deref() {
        anyhow::bail!("autoroute calibration published, but live cache readback failed: {error}");
    }
    let quarantined_route_classes = inspection
        .configs
        .iter()
        .flat_map(|config| {
            config
                .decisions
                .iter()
                .filter(|decision| decision.runtime_quarantined)
                .map(|decision| {
                    (
                        config.config_digest.clone(),
                        config.host_identity.clone(),
                        decision.workload.clone(),
                    )
                })
        })
        .collect::<BTreeSet<_>>();
    let measured_still_quarantined = measured_route_classes
        .intersection(&quarantined_route_classes)
        .count();
    if measured_still_quarantined > 0 {
        anyhow::bail!(
            "autoroute calibration published timing evidence, but {measured_still_quarantined} route class(es) measured by this command remain runtime-quarantined; repair the runtime-health artifact and rerun calibration"
        );
    }
    if let Some(path) = args.measurement_receipts.as_deref() {
        write_measurement_receipts(path, &measured_route_classes)?;
    }
    let mut one_shot_gpu = 0usize;
    let mut daemon_gpu = 0usize;
    let mut vyre_gpu_receipts = 0usize;
    for config in &inspection.configs {
        for decision in &config.decisions {
            if keyhog_scanner::hw_probe::parse_backend_str(&decision.backend)
                .is_some_and(|backend| backend.is_gpu())
            {
                one_shot_gpu += 1;
            }
            if keyhog_scanner::hw_probe::parse_backend_str(&decision.daemon_backend)
                .is_some_and(|backend| backend.is_gpu())
            {
                daemon_gpu += 1;
            }
            vyre_gpu_receipts += decision
                .candidate_receipts
                .iter()
                .filter(|receipt| {
                    keyhog_scanner::hw_probe::parse_backend_str(&receipt.backend)
                        .is_some_and(|backend| backend.is_gpu())
                })
                .count();
        }
    }
    println!(
        "{check} ran {green}{total}{reset} workload {probe_word} across {green}{passes}{reset} scan {policy_word}; retained {green}{measured_point_count}{reset} measured {point_word} in {green}{measured_unique_decisions}{reset} route {class_word}; cache contains {green}{persisted_decisions}{reset} route {decision_word} \u{2192} {dim}{cache}{reset}",
        check = crate::style::pass("\u{2713}", &p),
        green = p.green,
        reset = p.reset,
        dim = p.dim,
        probe_word = if total == 1 { "probe" } else { "probes" },
        decision_word = if persisted_decisions == 1 {
            "decision"
        } else {
            "decisions"
        },
        class_word = if measured_unique_decisions == 1 {
            "class"
        } else {
            "classes"
        },
        point_word = if measured_point_count == 1 {
            "point"
        } else {
            "points"
        },
        passes = policy_flags.len(),
        policy_word = if policy_flags.len() == 1 { "policy" } else { "policies" },
        cache = cache_note,
    );
    println!(
        "  cache route summary: one-shot GPU {one_shot_gpu}/{persisted_decisions}, daemon GPU {daemon_gpu}/{persisted_decisions}; VYRE GPU execution-plan receipts {vyre_gpu_receipts}"
    );
    if !quarantined_route_classes.is_empty() {
        eprintln!(
            "warning: {} unrelated route class(es) in the shared cache remain runtime-quarantined; inspect them with `keyhog backend --autoroute --verbose`",
            quarantined_route_classes.len()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn calibration_summary_counts(
    persisted_route_classes: &BTreeSet<(String, String, String)>,
    measured_route_classes: &BTreeSet<(String, String, String)>,
) -> Result<(usize, usize)> {
    if let Some((config_digest, host_identity, workload)) = measured_route_classes
        .difference(persisted_route_classes)
        .next()
    {
        anyhow::bail!(
            "autoroute calibration measured route class [{workload}] for config {config_digest} on host identity {host_identity}, but final cache readback did not contain it"
        );
    }
    Ok((persisted_route_classes.len(), measured_route_classes.len()))
}

fn calibration_point_summary_count(
    persisted_points: &BTreeSet<crate::orchestrator::AutorouteMeasurementReceipt>,
    measured_points: &BTreeSet<crate::orchestrator::AutorouteMeasurementReceipt>,
) -> Result<usize> {
    if let Some(missing) = measured_points.difference(persisted_points).next() {
        anyhow::bail!(
            "autoroute calibration measured shape {} for route class [{}], config {}, host {}, but final cache readback did not retain that measurement point",
            missing.measurement_shape_digest,
            missing.workload,
            missing.config_digest,
            missing.host_identity,
        );
    }
    Ok(measured_points.len())
}

/// Argv for one calibration pass.
///
/// `include_gpu` admits GPU candidates through `--autoroute-gpu`, which is
/// deliberately outside `autoroute_config_digest` so a calibrated decision
/// serves the later scan that does not repeat the flag. Its absence must stay
/// equally invisible to that digest, so a host without an eligible GPU drops
/// the flag instead of passing `--no-gpu`.
///
/// `--no-gpu` resolves `gpu_runtime_policy = Disabled`, and that policy IS
/// hashed: it changes which backends a scan may use. Passing it here wrote
/// every measured decision under a config digest no ordinary scan requests. On
/// a host with no eligible GPU that was every decision in the cache: a
/// completed install persisted 635 decisions across four policies, and the very
/// next `keyhog scan` reported "7 calibrated config(s), none matching config
/// digest" and exited 2.
///
/// `no_config` is the same reasoning applied to `.keyhog.toml`: the digest
/// hashes the resolved configuration, so calibration resolves the repository
/// config exactly when the scans it serves will. Only a caller that wants the
/// compiled-in host baseline, such as an installer running from whatever
/// directory the install was started in, passes it.
fn calibration_scan_args(
    autoroute_cache: Option<&Path>,
    policy: Option<&str>,
    include_gpu: bool,
    no_config: bool,
) -> Result<ScanArgs> {
    let mut argv = vec![
        OsString::from("keyhog-scan"),
        OsString::from("--autoroute-calibrate"),
    ];
    if no_config {
        argv.push(OsString::from("--no-config"));
    }
    if include_gpu {
        argv.push(OsString::from("--autoroute-gpu"));
    }
    if let Some(cache) = autoroute_cache {
        argv.push(OsString::from("--autoroute-cache"));
        argv.push(cache.as_os_str().to_owned());
    }
    if let Some(policy) = policy {
        argv.push(OsString::from(policy));
    }
    ScanArgs::try_parse_from(argv).context("parsing the internal calibration scan policy")
}

/// One policy-local sweep. The compiled scanner and every acquired backend peer
/// stay alive across all representative workloads in this policy.
struct ProbeSweep<'a> {
    orchestrator: &'a mut ScanOrchestrator,
    workspace: &'a Path,
    policy_label: &'a str,
    total: usize,
    quiet: bool,
    palette: &'a Palette,
}

impl ProbeSweep<'_> {
    /// Materialize one representative through its canonical source and run it
    /// through the same measured router used by `keyhog scan` calibration.
    fn run_probe(&mut self, workload: &Workload, idx: usize) -> Result<()> {
        let p = self.palette;
        let label = workload.label();
        if !self.quiet {
            print!(
                "  [{idx}/{total}] {tag} {label} {dim}({policy_label}){reset} ",
                total = self.total,
                tag = crate::style::info("calibrating", p),
                policy_label = self.policy_label,
                dim = p.dim,
                reset = p.reset,
            );
            // LAW10: no runtime effect (a progress-line flush error is cosmetic; stdout flushes at exit).
            std::io::stdout().flush().ok();
        }

        let probe = materialize_probe(self.workspace, idx, workload)
            .with_context(|| format!("creating {label} calibration probe"))?;
        let sources = probe
            .into_sources(self.orchestrator)
            .with_context(|| format!("building {label} calibration source"))?;
        if let Err(error) = self.orchestrator.scan_sources(sources, false, None, None) {
            if !self.quiet {
                println!("{}", crate::style::fail("FAIL", p));
            }
            return Err(error).with_context(|| format!("{label} ({})", self.policy_label));
        }
        if !self.quiet {
            println!("{}", crate::style::pass("ok", p));
        }
        Ok(())
    }
}

enum MaterializedProbe {
    Stdin(Vec<u8>),
    Filesystem(PathBuf),
    SourceClass(CalibrationSource),
}

struct CalibrationSource {
    name: &'static str,
    chunk: Chunk,
}

impl Source for CalibrationSource {
    fn name(&self) -> &str {
        self.name
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        Box::new(std::iter::once(Ok(self.chunk.clone())))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn chunk_identities_are_contiguous(&self) -> bool {
        true
    }
}

impl MaterializedProbe {
    fn into_sources(self, orchestrator: &ScanOrchestrator) -> Result<Vec<Box<dyn Source>>> {
        match self {
            Self::Stdin(bytes) => Ok(vec![Box::new(
                keyhog_sources::BufferedStdinSource::new(bytes)
                    .with_limits(orchestrator.effective_config.source_limits),
            )]),
            Self::SourceClass(source) => Ok(vec![Box::new(source)]),
            Self::Filesystem(path) => {
                let mut source_args = orchestrator.args().clone();
                source_args.input.clear();
                source_args.path = Some(path);
                source_args.stdin = false;
                crate::sources::build_sources(
                    &source_args,
                    &orchestrator.effective_config,
                    Vec::new(),
                    None,
                )
            }
        }
    }
}

/// Materialize a representative once. Filesystem inputs still pass through
/// [`keyhog_sources::FilesystemSource`], including archive extraction. Stdin
/// uses [`keyhog_sources::BufferedStdinSource`], the canonical stdin decoder
/// and metadata owner for already acquired bytes.
fn materialize_probe(
    workspace: &Path,
    idx: usize,
    workload: &Workload,
) -> Result<MaterializedProbe> {
    match workload {
        Workload::Stdin { bytes, .. } => {
            Ok(MaterializedProbe::Stdin(plain_calibration_bytes(*bytes)))
        }
        Workload::File {
            bytes,
            decode_heavy,
            ..
        } => {
            let path = workspace.join(format!("file-{idx}.txt"));
            let content = if *decode_heavy {
                calibration_bytes(DECODE_HEAVY_SEED, *bytes)
            } else {
                plain_calibration_bytes(*bytes)
            };
            std::fs::write(&path, content)
                .with_context(|| format!("writing file probe {}", path.display()))?;
            Ok(MaterializedProbe::Filesystem(path))
        }
        Workload::Tree { files, kib, .. } => {
            let tree = workspace.join(format!("tree-{idx}"));
            std::fs::create_dir_all(&tree)
                .with_context(|| format!("creating tree probe {}", tree.display()))?;
            for file_idx in 0..*files {
                let path = tree.join(format!("file-{file_idx}.txt"));
                std::fs::write(&path, plain_calibration_bytes(kib * 1024))
                    .with_context(|| format!("writing tree probe {}", path.display()))?;
            }
            Ok(MaterializedProbe::Filesystem(tree))
        }
        Workload::SourceClass {
            source_class,
            bytes,
            has_full_size,
            ..
        } => {
            let data = plain_calibration_bytes(*bytes);
            Ok(MaterializedProbe::SourceClass(CalibrationSource {
                name: source_class,
                chunk: Chunk {
                    data: String::from_utf8(data)
                        .context("calibration source bytes are UTF-8")?
                        .into(),
                    metadata: ChunkMetadata {
                        source_type: (*source_class).into(),
                        path: Some(format!("calibration://{source_class}").into()),
                        size_bytes: has_full_size.then_some(*bytes as u64),
                        ..Default::default()
                    },
                },
            }))
        }
        Workload::Tar { members, kib, .. } => {
            let path = workspace.join(format!("archive-{idx}.tar"));
            let file = std::fs::File::create(&path)
                .with_context(|| format!("creating tar probe {}", path.display()))?;
            let mut archive = tar::Builder::new(file);
            for member_idx in 0..*members {
                let content = plain_calibration_bytes(kib * 1024);
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o600);
                header.set_cksum();
                archive
                    .append_data(
                        &mut header,
                        format!("member-{member_idx}.txt"),
                        content.as_slice(),
                    )
                    .with_context(|| format!("writing tar member {member_idx}"))?;
            }
            archive
                .finish()
                .with_context(|| format!("finishing tar probe {}", path.display()))?;
            Ok(MaterializedProbe::Filesystem(path))
        }
    }
}

#[cfg(test)]
mod tests;
