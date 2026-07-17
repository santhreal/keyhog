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

use crate::args::{CalibrateAutorouteArgs, ScanArgs};
use crate::orchestrator::ScanOrchestrator;
use crate::style::Palette;
use anyhow::{Context, Result};
use clap::Parser;
use keyhog_core::Source;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

/// This binary's own scan-policy preset flags, swept in addition to the default
/// policy. Each resolves a distinct autoroute config digest, so each needs its
/// own calibrated decisions or a `keyhog scan <preset>` fails closed (exit 2).
/// Keep in sync with the `--fast` / `--deep` / `--precision` flags in
/// `args::scan`; the `every_documented_preset_resolves` e2e gate fails if a
/// preset is missing a calibrated decision.
const SCAN_POLICY_PRESETS: &[&str] = &["--fast", "--deep", "--precision"];

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
}

impl Workload {
    fn label(&self) -> &str {
        match self {
            Workload::Stdin { label, .. } | Workload::File { label, .. } => label,
            Workload::Tree { label, .. } | Workload::Tar { label, .. } => label.as_str(),
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
            label: "decode-heavy 256 KiB workload",
            bytes: 256 * 1024,
            decode_heavy: true,
        },
    ];
    workloads.extend(
        (1..=crate::orchestrator_config::FUSED_BATCH_DEFAULT).map(|files| Workload::Tree {
            label: format!("{files} x 4 KiB files workload"),
            files,
            kib: 4,
        }),
    );
    workloads.extend(
        (1..=crate::orchestrator_config::FUSED_BATCH_DEFAULT).map(|members| Workload::Tar {
            label: format!("{members} x 4 KiB tar members workload"),
            members,
            kib: 4,
        }),
    );
    workloads
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
    let cache_path =
        crate::autoroute_cache_path::resolve_autoroute_cache_path(args.autoroute_cache.as_deref())
            .map_err(anyhow::Error::msg)?;
    let workspace = tempfile::Builder::new()
        .prefix("keyhog-autoroute-prime-")
        .tempdir()
        .context("could not create the autoroute calibration workspace")?;

    let workloads = core_workload_plan();
    // Default policy first (no preset flag), then each preset.
    let policy_flags: Vec<Option<&str>> = std::iter::once(None)
        .chain(SCAN_POLICY_PRESETS.iter().copied().map(Some))
        .collect();
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
    let measured_route_classes = Arc::new(Mutex::new(BTreeSet::new()));
    for policy in &policy_flags {
        let policy_label = policy.unwrap_or("default policy"); // LAW10: documented default label only; it does not select a fallback backend
        let scan_args = calibration_scan_args(args.autoroute_cache.as_deref(), *policy)
            .with_context(|| format!("constructing {policy_label} calibration runtime"))?;
        let mut orchestrator = ScanOrchestrator::new(scan_args)
            .with_context(|| format!("initializing {policy_label} calibration runtime"))?;
        orchestrator
            .observe_autoroute_calibration_measurements(Arc::clone(&measured_route_classes))
            .with_context(|| format!("observing {policy_label} calibration route receipts"))?;
        orchestrator
            .prepare_autoroute_calibration_gpu_artifact()
            .with_context(|| format!("preparing {policy_label} shared GPU calibration artifact"))?;
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
            if let Err(error) = sweep.run_probe(workload, idx) {
                failed += 1;
                // The probe already printed its FAIL line; surface the cause
                // loudly (Law 10) rather than swallowing it behind the counter.
                eprintln!("    {} {error:#}", crate::style::fail("reason:", &p));
            }
        }
    }

    if failed > 0 {
        anyhow::bail!(
            "autoroute calibration failed for {failed}/{total} workload probes; \
             persisted routing was not updated for every required bucket"
        );
    }

    let inspection = crate::orchestrator::inspect_autoroute_cache(cache_path.as_deref());
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
        crate::orchestrator::AutorouteReadiness::Ready => {}
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
    let measured_route_classes = measured_route_classes
        .lock()
        .map_err(|_| {
            anyhow::anyhow!(
                "autoroute measured-route observer lock was poisoned, so the calibration summary cannot be trusted; rerun `keyhog calibrate-autoroute`"
            )
        })?;
    let persisted_route_classes = inspection
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
        .collect::<BTreeSet<_>>();
    let (persisted_decisions, measured_unique_decisions) =
        calibration_summary_counts(&persisted_route_classes, &measured_route_classes)?;
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
        "{check} ran {green}{total}{reset} workload {probe_word} across {green}{passes}{reset} scan {policy_word}; measured {green}{measured_unique_decisions}{reset} unique route {class_word}; cache contains {green}{persisted_decisions}{reset} route {decision_word} \u{2192} {dim}{cache}{reset}",
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
        passes = policy_flags.len(),
        policy_word = if policy_flags.len() == 1 { "policy" } else { "policies" },
        cache = cache_note,
    );
    println!(
        "  cache route summary: one-shot GPU {one_shot_gpu}/{persisted_decisions}, daemon GPU {daemon_gpu}/{persisted_decisions}; VYRE GPU execution-plan receipts {vyre_gpu_receipts}"
    );
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

fn calibration_scan_args(autoroute_cache: Option<&str>, policy: Option<&str>) -> Result<ScanArgs> {
    let mut argv = vec![
        OsString::from("keyhog-scan"),
        OsString::from("--autoroute-calibrate"),
        OsString::from("--autoroute-gpu"),
        OsString::from("--no-config"),
    ];
    if let Some(cache) = autoroute_cache {
        argv.push(OsString::from("--autoroute-cache"));
        argv.push(OsString::from(cache));
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
}

impl MaterializedProbe {
    fn into_sources(self, orchestrator: &ScanOrchestrator) -> Result<Vec<Box<dyn Source>>> {
        match self {
            Self::Stdin(bytes) => Ok(vec![Box::new(
                keyhog_sources::BufferedStdinSource::new(bytes)
                    .with_limits(orchestrator.effective_config.source_limits),
            )]),
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
