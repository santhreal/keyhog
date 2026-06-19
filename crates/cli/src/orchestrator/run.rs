//! Main scan run loop: hardening, sources, baseline, reporting, exit codes.

use super::allowlist::{load_allowlist, load_rule_suppressor};
use super::reporting::{dump_dogfood_trace, report_completion_summary, report_skip_summary};
use super::ScanOrchestrator;
use crate::baseline::Baseline;
use crate::exit_codes::{
    EXIT_FINDINGS, EXIT_LIVE_CREDENTIALS, EXIT_REQUIRE_GPU_UNMET, EXIT_SCANNER_PANIC,
    EXIT_SOURCE_FAILED,
};
use crate::style;
use anyhow::Result;
use keyhog_core::{VerificationResult, VerifiedFinding};
use std::io::IsTerminal;
use std::time::Instant;

impl ScanOrchestrator {
    pub async fn run(self) -> Result<std::process::ExitCode> {
        let start = Instant::now();
        let wall_start = chrono::Utc::now();
        let stderr_is_tty = std::io::stderr().is_terminal();
        let show_progress = self.args.progress || stderr_is_tty;
        let progress_ansi = stderr_is_tty && std::env::var_os("NO_COLOR").is_none();

        if self.args.dogfood {
            keyhog_scanner::telemetry::enable_dogfood();
        }

        let hardening = keyhog_core::apply_protections(false);
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

            let lockdown = keyhog_core::apply_protections_with_persistence_paths(
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
            let palette = style::for_stderr();
            eprintln!(
                "{} LOCKDOWN MODE: no findings cache on disk, mlocked, no live verifier",
                style::info("INFO", &palette)
            );

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
        let scanner_status = self.scanner.runtime_status();
        let preferred_backend = scanner_status.preferred_backend;
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
            if let Err(error) = crate::write_banner(
                &mut std::io::stderr(),
                progress_ansi,
                true,
                self.detectors.len(),
            ) {
                tracing::debug!(%error, "banner write error");
            }
            let gpu_label = scanner_status.gpu_backend.unwrap_or("none"); // LAW10: absent name/label => display default; reporting-only, recall-safe
            eprintln!(
                "⚡ {} | backend={preferred_backend} | gpu={gpu_label}",
                keyhog_scanner::hw_probe::startup_banner(
                    hw,
                    self.detectors.len(),
                    scanner_status.pattern_count,
                )
            );
        }

        // Require-GPU preflight, independent of backend routing. When
        // `--require-gpu` is resolved and no usable GPU adapter is present (or
        // the GPU self-test fails), fail closed with the dedicated scan exit
        // code BEFORE warming a backend or scanning a byte. Routing the failure
        // through the CLI ExitCode here - rather than a scanner-lib
        // process::exit - keeps the exit contract in the CLI layer.
        if let Err(diagnostic) = keyhog_scanner::gpu::require_gpu_preflight() {
            eprintln!("keyhog: {diagnostic}");
            return Ok(std::process::ExitCode::from(EXIT_REQUIRE_GPU_UNMET));
        }

        let calibration_mode = self.effective_config.autoroute_calibration;
        if calibration_mode {
            tracing::debug!(
                target: "keyhog::routing",
                "backend prewarm skipped during autoroute calibration"
            );
        } else {
            let preferred = match self.effective_config.backend_override {
                Some(backend) => backend,
                None => {
                    keyhog_scanner::hw_probe::select_backend(hw, 0, scanner_status.pattern_count)
                }
            };
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
        }

        if self.args.benchmark {
            // Name the GPU that produced the GPU row so the operator can tell
            // which adapter the throughput figures came from.
            eprintln!("benchmark | gpu={}", crate::benchmark::format_gpu_summary());
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

        let allowlist =
            load_allowlist(self.args.path.as_deref(), &self.effective_config.allowlist)?;
        let merkle = self.build_merkle_index();

        let sources = crate::sources::build_sources(
            &self.args,
            allowlist.ignored_paths.clone(),
            merkle.clone(),
        )?;
        if sources.is_empty() {
            anyhow::bail!(
                "no input source specified. Use --path, --stdin, --git, --git-diff, --git-history, --github-org, --gitlab-group, --bitbucket-workspace, --s3-bucket, --gcs-bucket, --azure-container-url, or --docker-image"
            );
        }

        let all_matches = self.scan_sources(sources, show_progress, merkle)?;
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

        if show_progress {
            let dropped = pre_rule_count - findings.len() - client_safe_dropped;
            if dropped > 0 {
                eprintln!(
                    "\n  Suppressed {} finding(s) via .keyhogignore.toml",
                    dropped
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

        let report_metadata =
            crate::reporting::ReportMetadata::from_scan_times(wall_start, chrono::Utc::now());
        crate::reporting::report_findings_with_metadata(
            &report_findings,
            &self.args,
            &report_metadata,
        )?;

        let elapsed = start.elapsed().as_secs_f64();
        if show_progress {
            report_completion_summary(
                report_findings.len(),
                elapsed,
                progress_ansi,
                self.effective_config.backend_override,
            );
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
            std::process::ExitCode::from(EXIT_FINDINGS)
        } else {
            std::process::ExitCode::SUCCESS
        })
    }
}
