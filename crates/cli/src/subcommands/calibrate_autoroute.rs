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
//! Each probe is a real child `keyhog scan --autoroute-calibrate` process
//! the same invocation the installer spawned, so calibration behavior is
//! unchanged byte for byte; only the loop moved from shell into Rust. Because
//! it runs in the same build whose presets it sweeps, every preset flag below
//! always exists (the installer has to grep `scan --help` because it may drive
//! an older released binary; this command never does).

use crate::args::CalibrateAutorouteArgs;
use crate::style::Palette;
use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

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

/// One calibration workload: how to materialize the probe and feed it to the
/// child scan.
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
            label: "8 MiB workload",
            bytes: 8 * 1024 * 1024,
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
    let exe = std::env::current_exe()
        .context("could not resolve the running keyhog binary to spawn calibration probes")?;
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

    let sweep = ProbeSweep {
        exe: &exe,
        workspace: workspace.path(),
        autoroute_cache: args.autoroute_cache.as_deref(),
        total,
        quiet: args.quiet,
        palette: &p,
    };
    let mut idx = 0usize;
    let mut failed = 0usize;
    for policy in &policy_flags {
        for workload in &workloads {
            idx += 1;
            if let Err(error) = sweep.run_probe(workload, *policy, idx) {
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

    let cache_note = match args.autoroute_cache.as_deref() {
        Some(path) => path.to_string(),
        None => "the default autoroute cache".to_string(),
    };
    println!(
        "{check} calibrated {green}{total}{reset} workload {bucket_word} across {green}{passes}{reset} scan {policy_word} \u{2192} {dim}{cache}{reset}",
        check = crate::style::pass("\u{2713}", &p),
        green = p.green,
        reset = p.reset,
        dim = p.dim,
        bucket_word = if total == 1 { "bucket" } else { "buckets" },
        passes = policy_flags.len(),
        policy_word = if policy_flags.len() == 1 { "policy" } else { "policies" },
        cache = cache_note,
    );
    Ok(ExitCode::SUCCESS)
}

/// The sweep-wide invariants every probe shares: the binary under calibration,
/// the probe workspace, the cache override, and the presentation context.
/// Per-probe variation (workload, policy, index) stays a method argument.
struct ProbeSweep<'a> {
    exe: &'a Path,
    workspace: &'a Path,
    autoroute_cache: Option<&'a str>,
    total: usize,
    quiet: bool,
    palette: &'a Palette,
}

impl ProbeSweep<'_> {
    /// Materialize one probe and run a child `keyhog scan --autoroute-calibrate`
    /// against it. Returns `Err` (with the child's first stderr line) if the
    /// probe could not be created or the scan exited non-zero.
    fn run_probe(&self, workload: &Workload, policy: Option<&str>, idx: usize) -> Result<()> {
        let p = self.palette;
        let label = workload.label();
        // LAW10: reporting_only (display label for the default (no-flag) policy).
        let policy_label = policy.unwrap_or("default policy");
        if !self.quiet {
            print!(
                "  [{idx}/{total}] {tag} {label} {dim}({policy_label}){reset} ",
                total = self.total,
                tag = crate::style::info("calibrating", p),
                dim = p.dim,
                reset = p.reset,
            );
            // LAW10: no runtime effect (a progress-line flush error is cosmetic; stdout flushes at exit).
            std::io::stdout().flush().ok();
        }

        let out = self.workspace.join(format!("probe-{idx}.json"));
        let mut cmd = Command::new(self.exe);
        cmd.arg("scan")
            .arg("--autoroute-calibrate")
            // Autoroute calibration measures every eligible backend. GPU is a
            // peer candidate, not an opt-in route that normal scans can never
            // discover.
            .arg("--autoroute-gpu")
            .arg("--no-config");
        if let Some(cache) = self.autoroute_cache {
            cmd.arg("--autoroute-cache").arg(cache);
        }
        // The probe target (positional path, or `--stdin` + piped file) is added
        // by `materialize_probe`; the returned handle, if any, becomes the child
        // stdin.
        let stdin_handle = materialize_probe(self.workspace, idx, workload, &mut cmd)
            .with_context(|| format!("creating {label} calibration probe"))?;
        if let Some(flag) = policy {
            cmd.arg(flag);
        }
        cmd.arg("--format").arg("json").arg("-o").arg(&out);
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::piped());
        match stdin_handle {
            Some(file) => {
                cmd.stdin(Stdio::from(file));
            }
            None => {
                cmd.stdin(Stdio::null());
            }
        }

        let output = cmd
            .output()
            .with_context(|| format!("spawning {label} calibration probe"))?;
        if output.status.success() {
            if !self.quiet {
                println!("{}", crate::style::pass("ok", p));
            }
            Ok(())
        } else {
            if !self.quiet {
                println!("{}", crate::style::fail("FAIL", p));
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            let reason = stderr
                .lines()
                .find(|line| !line.trim().is_empty())
                // LAW10: reporting-only error-message string; placeholder for a child that wrote no stderr.
                .unwrap_or("no error output");
            anyhow::bail!("{label} ({policy_label}): {reason}");
        }
    }
}

/// Write the probe for `workload` under `workspace` and add its target to `cmd`.
/// Returns an open stdin file for stdin workloads (the caller wires it to the
/// child), or `None` for path / tree workloads (added as a positional arg).
fn materialize_probe(
    workspace: &Path,
    idx: usize,
    workload: &Workload,
    cmd: &mut Command,
) -> Result<Option<std::fs::File>> {
    match workload {
        Workload::Stdin { bytes, .. } => {
            let path = workspace.join(format!("stdin-{idx}.bin"));
            std::fs::write(&path, plain_calibration_bytes(*bytes))
                .with_context(|| format!("writing stdin probe {}", path.display()))?;
            cmd.arg("--stdin");
            let file = std::fs::File::open(&path)
                .with_context(|| format!("opening stdin probe {}", path.display()))?;
            Ok(Some(file))
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
            cmd.arg(&path);
            Ok(None)
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
            cmd.arg(&tree);
            Ok(None)
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
            cmd.arg(&path);
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests;
