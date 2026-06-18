//! Main scan run loop: hardening, sources, baseline, reporting, exit codes.

use super::allowlist::{load_allowlist, load_rule_suppressor};
use super::reporting::{dump_dogfood_trace, report_completion_summary, report_skip_summary};
use super::ScanOrchestrator;
use crate::baseline::Baseline;
use crate::orchestrator_config::print_effective_config_if_requested;
use anyhow::Result;
use keyhog_core::{VerificationResult, VerifiedFinding};
use std::io::IsTerminal;
use std::time::Instant;

pub const EXIT_LIVE_CREDENTIALS: u8 = 10;
pub const EXIT_SCANNER_PANIC: u8 = 11;
/// Documented "configuration problem" exit code (see docs/src/reference/exit-codes.md).
/// Returned when `KEYHOG_REQUIRE_GPU=1` is set but no usable GPU is present, so the
/// require-GPU contract fails closed instead of silently degrading to CPU.
pub const EXIT_REQUIRE_GPU_UNMET: u8 = 2;
/// Returned when the scan produced no data because every source failed to read
/// (e.g. `--git-history` / `--git-diff` on a non-repo or bad ref, an
/// unreachable remote). User-error class (2): the caller named a source we
/// could not read. We fail closed rather than report "clean" + exit 0, which
/// would tell a CI gate the tree is clean when nothing was scanned
/// (KH-GAP-096).
pub const EXIT_SOURCE_FAILED: u8 = 2;

impl ScanOrchestrator {
    pub async fn run(self) -> Result<std::process::ExitCode> {
        let start = Instant::now();
        let stderr_is_tty = std::io::stderr().is_terminal();
        let show_progress = self.args.progress || stderr_is_tty;
        let progress_ansi = stderr_is_tty && std::env::var_os("NO_COLOR").is_none();

        if self.args.dogfood {
            keyhog_scanner::telemetry::enable_dogfood();
        }

        if let Some(backend) = self.args.backend.as_deref() {
            unsafe {
                std::env::set_var("KEYHOG_BACKEND", backend);
            }
        }

        if print_effective_config_if_requested(&self.effective_config) {
            return Ok(std::process::ExitCode::SUCCESS);
        }

        let hardening = keyhog_core::hardening::apply_default_protections();
        if !hardening.failures.is_empty() {
            tracing::warn!(
                failures = ?hardening.failures,
                "default hardening protections did not fully apply"
            );
        }

        if self.args.lockdown {
            #[cfg(feature = "verify")]
            if self.args.verify {
                anyhow::bail!(
                    "lockdown mode forbids --verify (would send credentials \
                     to outbound HTTPS endpoints). Drop --verify or drop --lockdown."
                );
            }

            if self.args.show_secrets {
                anyhow::bail!(
                    "lockdown mode forbids --show-secrets (would print plaintext credentials \
                     to stdout/stderr). Drop --show-secrets or drop --lockdown."
                );
            }

            let lockdown = keyhog_core::hardening::apply_protections_with_persistence_paths(
                true,
                self.lockdown_persistence_cache_paths(),
            );
            if !lockdown.failures.is_empty() {
                anyhow::bail!(
                    "lockdown mode requested but protections failed to apply: {:?}",
                    lockdown.failures
                );
            }
            tracing::info!(
                mlocked = lockdown.mlocked,
                "lockdown mode active: mlocked + coredump-blocked + cache-free"
            );
            eprintln!("🔒 LOCKDOWN MODE: no findings cache on disk, mlocked, no live verifier");

            if self.args.no_default_excludes {
                anyhow::bail!(
                    "lockdown mode forbids --no-default-excludes (would scan untrusted \
                     lock files / minified bundles / vendor dirs that are common \
                     credential-leak vectors)."
                );
            }
            if self.args.no_unicode_norm {
                anyhow::bail!(
                    "lockdown mode forbids --no-unicode-norm (would let homoglyph \
                     attackers hide secrets behind visually identical Unicode)."
                );
            }
            if self.args.no_decode {
                anyhow::bail!(
                    "lockdown mode forbids --no-decode (encoded secrets like \
                     base64('AKIA…') would slip through entirely)."
                );
            }
            if self.args.no_entropy {
                anyhow::bail!(
                    "lockdown mode forbids --no-entropy (entropy detection is the \
                     only catch for novel / unknown high-entropy secrets)."
                );
            }
            if self.args.no_ml {
                anyhow::bail!(
                    "lockdown mode forbids --no-ml (ML confidence gating reduces \
                     false-negative rate on hand-crafted near-misses)."
                );
            }
            if self.args.fast {
                anyhow::bail!(
                    "lockdown mode forbids --fast (it disables decode + entropy + ML \
                     simultaneously, the largest detection blind spot we ship)."
                );
            }
        }

        let hw = keyhog_scanner::hw_probe::probe_hardware();
        let preferred_backend = self.scanner.preferred_backend_label();
        tracing::info!(
            backend = preferred_backend,
            gpu_available = hw.gpu_available,
            gpu_software = hw.gpu_is_software,
            hyperscan = hw.hyperscan_available,
            avx512 = hw.has_avx512,
            avx2 = hw.has_avx2,
            neon = hw.has_neon,
            "scan backend selected"
        );
        if show_progress {
            let _ = keyhog_core::banner::print_banner(
                &mut std::io::stderr(),
                progress_ansi,
                true,
                self.detectors.len(),
            );
            let gpu_label = self.scanner.gpu_backend_label().unwrap_or("none");
            eprintln!(
                "⚡ {} | backend={preferred_backend} | gpu={gpu_label}",
                keyhog_scanner::hw_probe::startup_banner(
                    hw,
                    self.detectors.len(),
                    self.scanner.pattern_count(),
                )
            );
        }

        // Require-GPU preflight, independent of backend routing. When
        // KEYHOG_REQUIRE_GPU=1 and no usable GPU adapter is present (or the GPU
        // self-test fails), fail closed with the documented exit code 2 BEFORE
        // we warm a backend or scan a byte. This is the no-GPU path the flag
        // exists for: the scanner library's hard-fail only lives inside the
        // GPU-selected dispatch paths, which a no-GPU host never reaches
        // (routing degrades to SimdCpu). Routing the failure through the CLI
        // ExitCode here - rather than a scanner-lib process::exit - keeps the
        // exit contract in the CLI layer.
        if let Err(diagnostic) = keyhog_scanner::gpu::require_gpu_preflight() {
            eprintln!("keyhog: {diagnostic}");
            return Ok(std::process::ExitCode::from(EXIT_REQUIRE_GPU_UNMET));
        }

        let preferred = self.scanner.select_backend_for_file(0);
        let warm_started = Instant::now();
        let warmed = self.scanner.warm_backend(preferred);
        let warm_ms = warm_started.elapsed().as_millis();
        tracing::debug!(
            target: "keyhog::routing",
            backend = preferred.label(),
            warmed,
            elapsed_ms = warm_ms as u64,
            "backend warmed"
        );

        if self.args.benchmark {
            let results = crate::benchmark::run_benchmark(&self)?;
            let baseline_mb = results
                .iter()
                .map(|r| r.mb_per_sec)
                .fold(f64::INFINITY, f64::min)
                .max(f64::EPSILON);
            for result in &results {
                let speedup = result.mb_per_sec / baseline_mb;
                eprintln!(
                    "benchmark | backend={:<14} | throughput={:>8.2} MiB/s | speedup={:>5.2}× | findings={:>4} | bytes={}",
                    result.backend.label(),
                    result.mb_per_sec,
                    speedup,
                    result.findings,
                    result.bytes_scanned
                );
            }
            if let Some(fastest) = results
                .iter()
                .max_by(|a, b| a.mb_per_sec.total_cmp(&b.mb_per_sec))
            {
                eprintln!(
                    "benchmark winner: {} at {:.2} MiB/s",
                    fastest.backend.label(),
                    fastest.mb_per_sec
                );
            }
            return Ok(std::process::ExitCode::SUCCESS);
        }

        let allowlist = load_allowlist(self.args.path.as_deref())?;
        let merkle = self.build_merkle_index();

        let sources = crate::sources::build_sources(
            &self.args,
            allowlist.ignored_paths.clone(),
            merkle.clone(),
        )?;
        if sources.is_empty() {
            anyhow::bail!(
                "no input source specified. Use --path, --stdin, --git, --git-diff, --git-history, --github-org, --s3-bucket, or --docker-image"
            );
        }

        let all_matches = self.scan_sources(sources, show_progress, merkle);
        let filtered = self.filter_and_resolve(all_matches, &allowlist);
        let findings_pre_rules = self.finalize(filtered).await?;

        let rule_suppressor = load_rule_suppressor(self.args.path.as_deref())?;
        let pre_rule_count = findings_pre_rules.len();
        let hide_client_safe = self.args.hide_client_safe;
        let mut client_safe_dropped = 0usize;
        let findings: Vec<VerifiedFinding> = findings_pre_rules
            .into_iter()
            .filter(|f| {
                if rule_suppressor.matches(f) {
                    return false;
                }
                if hide_client_safe && f.severity == keyhog_core::Severity::ClientSafe {
                    client_safe_dropped += 1;
                    return false;
                }
                true
            })
            .collect();

        // KH-GAP-096: if a requested source failed ENTIRELY — produced zero
        // chunks AND errored (e.g. --git-history / --git-diff on a non-repo or
        // bad ref, --github-org with a bad token, an unreachable --url) — and
        // there are no findings, the requested scan never ran. Do NOT fall
        // through to "no findings, all clean" + exit 0: a CI gate would read
        // that as a clean tree when nothing was scanned. Fail closed with a
        // diagnostic. A partial failure (some files unreadable in a tree that
        // still produced chunks) does NOT trip this — that source produced
        // data, so FAILED_SOURCES stays 0 — nor does a failed source that runs
        // alongside another source which DID surface findings (exit 1 wins).
        if findings.is_empty()
            && crate::FAILED_SOURCES.load(std::sync::atomic::Ordering::Relaxed) > 0
        {
            eprintln!(
                "error: a requested scan source failed to read and produced no data (see the \
                 warnings above). Not reporting \"clean\": that scan did not run. Check the \
                 repository path, ref, token, or URL and re-run."
            );
            return Ok(std::process::ExitCode::from(EXIT_SOURCE_FAILED));
        }

        if show_progress && !rule_suppressor.is_empty() {
            let dropped = pre_rule_count - findings.len() - client_safe_dropped;
            if dropped > 0 {
                eprintln!(
                    "\n  Suppressed {} finding(s) via .keyhogignore.toml ({} rule(s) loaded)",
                    dropped,
                    rule_suppressor.len()
                );
            }
        }
        if show_progress && client_safe_dropped > 0 {
            eprintln!(
                "\n  Suppressed {} client-safe finding(s) via --hide-client-safe (public-by-design keys)",
                client_safe_dropped
            );
        }

        if let Some(ref path) = self.args.create_baseline {
            let baseline = Baseline::from_findings(&findings);
            baseline.save(path)?;
            if show_progress {
                eprintln!(
                    "\n📝 Baseline created with {} entries at {}",
                    baseline.entries.len(),
                    path.display()
                );
            }
            return Ok(std::process::ExitCode::SUCCESS);
        }

        let (report_findings, has_new_entries) = if let Some(ref path) = self.args.update_baseline {
            let mut baseline = if path.exists() {
                Baseline::load(path)?
            } else {
                Baseline::empty()
            };
            let new_findings = baseline.filter_new(&findings);
            let had_new = !new_findings.is_empty();
            baseline.merge(&findings);
            baseline.save(path)?;
            if show_progress {
                eprintln!(
                    "\n📝 Baseline updated: added {} new entries at {}",
                    new_findings.len(),
                    path.display()
                );
            }
            (new_findings, had_new)
        } else if let Some(ref path) = self.args.baseline {
            let baseline = Baseline::load(path)?;
            let filtered_findings = baseline.filter_new(&findings);
            let suppressed_count = findings.len() - filtered_findings.len();
            let has_new = !filtered_findings.is_empty();
            if show_progress && suppressed_count > 0 {
                eprintln!("\n  Suppressed {} baseline finding(s)", suppressed_count);
            }
            (filtered_findings, has_new)
        } else {
            let has_findings = !findings.is_empty();
            (findings, has_findings)
        };

        let has_live_credentials = report_findings
            .iter()
            .any(|f| matches!(f.verification, VerificationResult::Live));

        // `--stream`: emit one redacted `[stream]` preview per REPORTED finding.
        // Wired to the resolved report stream (post filter_and_resolve /
        // suppression / --min-confidence / baseline) rather than the raw scanner
        // matches, so a streamed line always corresponds to a finding the report
        // and exit code agree on. (AUD-testing_dogfood-1: the old wiring streamed
        // raw matches the report later dropped, lying about the result.)
        if self.args.stream {
            super::reporting::stream_report_previews(&report_findings);
        }

        crate::reporting::report_findings(&report_findings, &self.args)?;

        let elapsed = start.elapsed().as_secs_f64();
        if show_progress {
            report_completion_summary(report_findings.len(), elapsed, progress_ansi);
        } else {
            report_skip_summary(false);
        }
        dump_dogfood_trace();

        tracing::info!(
            "Done in {:.1}s. {} findings",
            elapsed,
            report_findings.len()
        );

        let scanner_panicked = crate::SCANNER_PANICKED.load(std::sync::atomic::Ordering::Relaxed);
        Ok(if has_live_credentials {
            std::process::ExitCode::from(EXIT_LIVE_CREDENTIALS)
        } else if scanner_panicked {
            std::process::ExitCode::from(EXIT_SCANNER_PANIC)
        } else if has_new_entries {
            std::process::ExitCode::from(1)
        } else {
            std::process::ExitCode::SUCCESS
        })
    }
}
