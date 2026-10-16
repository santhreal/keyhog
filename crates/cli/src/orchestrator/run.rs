//! Main scan run loop: hardening, sources, baseline, reporting, exit codes.

use super::allowlist::{load_allowlist, load_rule_suppressor};
use super::reporting::{
    dump_dogfood_trace, report_autoroute_cache_summary, report_compiled_cache_summary,
    report_completion_summary, report_scanner_materialization_summary, report_skip_summary,
    TickerGuard,
};
use super::ScanOrchestrator;
use crate::baseline::Baseline;
use crate::exit_codes::{
    EXIT_FINDINGS, EXIT_LIVE_CREDENTIALS, EXIT_REQUIRE_GPU_UNMET, EXIT_SCANNER_PANIC,
    EXIT_SOURCE_FAILED, EXIT_SUCCESS, EXIT_SYSTEM_ERROR,
};
use crate::style;
use anyhow::Result;
use keyhog_core::{VerificationResult, VerifiedFinding};
use sha2::{Digest, Sha256};
use std::io::{IsTerminal, Read};
use std::time::Instant;

pub(super) use super::profile_report::profiler_build_identity;
pub(crate) use super::profile_report::render_daemon_request_profile;
use super::profile_report::{
    profiler_cache_identities, profiler_cache_transitions, profiler_config_identity,
    profiler_detector_identity, profiler_outcome_identity, OperatorProfile,
};

#[cfg(feature = "mimalloc")]
pub(super) fn release_current_allocator_arena() {
    extern "C" {
        fn mi_collect(force: bool);
    }

    // Referencing the Rust allocator crate keeps its native link metadata in
    // library-test binaries too; the production binary already references this
    // type through its global allocator declaration.
    let allocator_link = mimalloc::MiMalloc;
    std::hint::black_box(&allocator_link);
    // SAFETY: the mimalloc feature links the process allocator that exports
    // `mi_collect`; the function has no pointer arguments or preconditions.
    unsafe { mi_collect(true) };
}

#[cfg(feature = "mimalloc")]
pub(super) fn release_allocator_arenas_after_construction() {
    // Regex and matcher compilation runs on Rayon workers. Collect each
    // thread-local mimalloc heap, then the caller heap, so compiler pages do
    // not remain resident throughout a tiny scan.
    rayon::broadcast(|_| release_current_allocator_arena());
    release_current_allocator_arena();
}

#[cfg(all(not(feature = "mimalloc"), target_os = "linux", target_env = "gnu"))]
pub(super) fn release_current_allocator_arena() {
    // SAFETY: glibc's process-wide trim takes no pointers and tolerates
    // concurrent allocator users.
    let _ = unsafe { libc::malloc_trim(0) }; // LAW10: allocator trimming is a best-effort memory optimization with no effect on scan findings or error semantics.
}

#[cfg(all(not(feature = "mimalloc"), target_os = "linux", target_env = "gnu"))]
pub(super) fn release_allocator_arenas_after_construction() {
    release_current_allocator_arena();
}

#[cfg(not(any(feature = "mimalloc", all(target_os = "linux", target_env = "gnu"))))]
pub(super) fn release_current_allocator_arena() {}

#[cfg(not(any(feature = "mimalloc", all(target_os = "linux", target_env = "gnu"))))]
pub(super) fn release_allocator_arenas_after_construction() {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct ScanOutcome {
    pub(super) autoroute_calibration: bool,
    pub(super) scanner_panicked: bool,
    pub(super) has_live_credentials: bool,
    pub(super) has_blocking_findings: bool,
    pub(super) incremental_cache_failed: bool,
    pub(super) source_coverage_incomplete: bool,
    /// A requested source produced ZERO chunks and errored: not a gap in the
    /// coverage of input we read, but input we never read at all. Tracked
    /// separately from `source_coverage_incomplete` so the exit code cannot
    /// depend on whether that total failure also happened to raise a
    /// FAIL-class coverage gap.
    pub(super) total_source_failure: bool,
    /// The autoroute decision cache could not be written. Never discards
    /// findings; it exists so `--autoroute-calibrate` cannot report success
    /// when persisting that decision WAS the requested operation.
    pub(super) autoroute_persist_failed: bool,
}

/// Resolve scan terminal state with reliability failures ahead of findings.
///
/// A panic outranks everything: the run's state is unreliable. Then findings,
/// because the caller has actionable credential evidence to preserve, and that
/// includes a CALIBRATING run. Calibration is a side effect of a scan, not a
/// different operation, so it must not mask the scan's verdict. It used to
/// return success unconditionally, which made
/// `keyhog scan --autoroute-calibrate <tree> && echo clean` print "clean" on a
/// tree with leaks: the report named the credential and the exit code said
/// nothing was wrong. That is the documented first-run command in our own
/// installers, so the one scan most likely to be wired into a gate was the one
/// that could not fail it.
///
/// Below findings, calibration is still allowed to report success on an
/// incomplete sample, because its workload is a deliberately partial
/// measurement rather than a claim about the tree. What it may NOT do is
/// report success when persisting the decision failed, since that was the
/// requested operation.
pub(super) fn resolve_scan_exit(outcome: ScanOutcome) -> u8 {
    if outcome.scanner_panicked {
        EXIT_SCANNER_PANIC
    } else if outcome.has_live_credentials {
        EXIT_LIVE_CREDENTIALS
    } else if outcome.has_blocking_findings {
        EXIT_FINDINGS
    } else if outcome.autoroute_calibration {
        if outcome.autoroute_persist_failed {
            EXIT_SYSTEM_ERROR
        } else {
            EXIT_SUCCESS
        }
    } else if outcome.incremental_cache_failed || outcome.autoroute_persist_failed {
        EXIT_SYSTEM_ERROR
    } else if outcome.source_coverage_incomplete || outcome.total_source_failure {
        EXIT_SOURCE_FAILED
    } else {
        EXIT_SUCCESS
    }
}


impl ScanOrchestrator {
    pub async fn run(mut self) -> Result<std::process::ExitCode> {
        crate::reset_scan_runtime_state();
        super::workflow_state::reset_workflow_state();
        // `--no-default-excludes` disables EVERY default exclusion, not just the
        // walker's. The vendored/minified path suppression used to survive the
        // flag, so the walker read `app.min.js` and reported its bytes as
        // scanned while the scanner threw away the `sk_live_` key inside it. The
        // flag now means what it says. This must run after
        // `reset_scan_runtime_state`, which restores the default.
        keyhog_scanner::telemetry::set_vendored_path_suppression(!self.args.no_default_excludes);
        let start = Instant::now();
        let wall_start = chrono::Utc::now();
        let stderr_is_tty = std::io::stderr().is_terminal();
        // `--no-color` forces plain output everywhere in the scan path; it
        // rides the same `NO_COLOR` convention the palette helpers already read
        // so a single env set covers the report formatter, the ticker, and the
        // diagnostic palette without threading a flag through every call.
        if self.args.no_color {
            std::env::set_var("NO_COLOR", "1");
        }
        let no_color = self.args.no_color || crate::style::no_color_requested();
        // Fold the `NO_COLOR` env convention into the flag so the stdout report
        // formatter (which honors `args.no_color`) also drops color on a TTY
        // when the operator set `NO_COLOR`, matching the ticker/palette.
        self.args.no_color = no_color;
        // `--quiet` suppresses the interactive chrome (banner / ticker /
        // completion summary) while leaving coverage FAIL/WARN and fatal errors
        // intact, so a quiet scan is never mistaken for a clean one.
        let show_progress = !self.args.quiet && (self.args.progress || stderr_is_tty);
        let progress_ansi = stderr_is_tty && !no_color;

        if self.args.dogfood {
            keyhog_scanner::telemetry::enable_dogfood();
        }

        let hardening = keyhog_core::apply_protections(false);
        let mut protection_state = if hardening.failures.is_empty() {
            "default-applied"
        } else {
            "default-degraded"
        };
        if !hardening.failures.is_empty() {
            tracing::warn!(
                failures = ?hardening.failures,
                "default hardening protections did not fully apply"
            );
        }

        if self.args.lockdown {
            #[cfg(feature = "verify")]
            if self.effective_config.report.verify {
                anyhow::bail!(
                    "lockdown mode forbids --verify (would send credentials \
                     to outbound HTTPS endpoints). Drop --verify or drop --lockdown."
                );
            }

            if self.effective_config.report.show_secrets {
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
            protection_state = "lockdown-applied";
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
        #[cfg(feature = "verify")]
        if self.effective_config.verify.oob.enabled {
            keyhog_verifier::oob::prewarm_key_generation();
        }

        let hw = keyhog_scanner::hw_probe::probe_hardware();
        let scanner_status = self.scanner.runtime_status();
        let backend_policy = if self.effective_config.autoroute_calibration {
            "calibrate"
        } else if let Some(backend) = self.effective_config.backend_override {
            backend.label()
        } else {
            "auto:persisted-per-workload"
        };
        tracing::info!(
            backend_policy,
            gpu_available = hw.gpu_available,
            gpu_software = hw.gpu_is_software,
            hyperscan = hw.hyperscan_available,
            avx512 = hw.has_avx512,
            avx2 = hw.has_avx2,
            neon = hw.has_neon,
            "scan backend policy configured"
        );
        if show_progress {
            if let Err(error) =
                crate::write_banner(&mut std::io::stderr(), progress_ansi, self.detector_count)
            {
                tracing::debug!(%error, "banner write error");
            }
            let gpu_candidates = self.scanner.gpu_backend_candidates();
            let gpu_label = gpu_candidates
                .iter()
                .filter(|candidate| candidate.is_eligible())
                .map(|candidate| candidate.backend.label())
                .collect::<Vec<_>>()
                .join(",");
            let gpu_label = if gpu_label.is_empty() {
                "none"
            } else {
                gpu_label.as_str()
            };
            eprintln!(
                "⚡ {} | backend={backend_policy} | gpu={gpu_label}",
                keyhog_scanner::hw_probe::startup_banner(
                    hw,
                    self.detector_count,
                    scanner_status.pattern_count,
                )
            );
            for candidate in gpu_candidates
                .iter()
                .filter(|candidate| !candidate.is_eligible())
            {
                if let Some(error) = candidate.acquisition_error.as_deref() {
                    eprintln!(
                        "gpu candidate unavailable | backend={} | error={error}",
                        candidate.backend.label()
                    );
                } else if candidate.available {
                    eprintln!(
                        "gpu candidate ineligible | backend={} | software={} | complete_identity={}",
                        candidate.backend.label(),
                        candidate.is_software,
                        candidate.has_complete_identity(),
                    );
                }
            }
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

        // A backend owns no work until the first real batch. Eagerly warming an
        // explicit diagnostic override compiled every lazy regex and
        // deserialized every native SIMD database even for empty or rejected
        // inputs. Dispatch performs the same fail-closed initialization once it
        // has bytes, so keep zero-byte scans free of backend runtime state.
        tracing::debug!(
            target: "keyhog::routing",
            calibration_mode = self.effective_config.autoroute_calibration,
            explicit_backend = ?self.effective_config.backend_override,
            "backend materialization awaits the first real batch"
        );

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

        let config_digest =
            crate::orchestrator_config::autoroute_config_digest(&self.effective_config);
        let mut profile_identity = keyhog_profile::RunIdentity::new(
            env!("CARGO_PKG_VERSION"),
            self.detector_corpus_digest.clone(),
            format!("{config_digest:016x}"),
            "pending",
            "runtime-batches",
            backend_policy,
        );
        profile_identity.backend_selected =
            Some(self.effective_config.backend_override.map_or_else(
                || "autoroute-per-workload".to_owned(),
                |backend| backend.label().to_owned(),
            ));
        profile_identity.scanner_threads = rayon::current_num_threads();
        profile_identity.reader_threads = self.effective_config.reader_threads;
        let profile_enabled =
            self.effective_config.scanner.profile || self.args.profile_out.is_some();
        let detector_identity = profile_enabled.then(|| profiler_detector_identity(&self));
        let config_identity =
            profile_enabled.then(|| profiler_config_identity(&self, protection_state));
        let source_identity =
            profile_enabled.then(|| crate::sources::profiling_source_identity(&self.args, &[]));
        let early_profile_session = self.early_profile_session.take();
        let early_profile_build = self.early_profile_build.take();
        let mut operator_profile = OperatorProfile::start(
            profile_enabled,
            early_profile_session,
            early_profile_build,
            profile_identity,
            detector_identity,
            config_identity,
            source_identity,
            self.args.profile_out.clone(),
        )?;
        operator_profile.transition(keyhog_profile::RunState::Acquiring);

        let (allowlist, incremental_cache_path, merkle, merkle_status, sources) = {
            let _profile_span = keyhog_profile::span(keyhog_profile::Stage::SourceAcquire);
            let allowlist =
                load_allowlist(self.args.path.as_deref(), &self.effective_config.allowlist)?;
            let incremental_cache_path = self.incremental_cache_path()?;
            let (merkle, merkle_status) =
                self.build_merkle_index(incremental_cache_path.as_deref());
            let sources = crate::sources::build_sources(
                &self.args,
                &self.effective_config,
                allowlist.ignored_paths.as_ref().to_vec(),
                merkle.clone(),
            )?;
            (
                allowlist,
                incremental_cache_path,
                merkle,
                merkle_status,
                sources,
            )
        };
        operator_profile.set_cache_identities(
            profiler_cache_identities(&self, merkle_status.as_ref()),
            profiler_cache_transitions(&self, merkle_status.as_ref()),
        );
        if sources.is_empty() {
            anyhow::bail!(
                "no input source specified. Use --path, --stdin, --git, --git-diff, --git-history, --github-org, --gitlab-group, --bitbucket-workspace, --s3-bucket, --gcs-bucket, --azure-container-url, or --docker-image"
            );
        }
        operator_profile.set_source_identity(crate::sources::profiling_source_identity(
            &self.args, &sources,
        ));
        if let Some(identity) = operator_profile.identity_mut() {
            identity.source_kind = sources
                .iter()
                .map(|source| source.name())
                .collect::<Vec<_>>()
                .join("+");
            let mut workload_adapters = sources
                .iter()
                .map(|source| source.name())
                .collect::<Vec<_>>();
            workload_adapters.sort_unstable();
            workload_adapters.dedup();
            identity.workload_class = workload_adapters.join("+");
            identity.cache_state = match merkle_status.as_ref() {
                None => keyhog_profile::CacheState::Disabled,
                Some(keyhog_core::MerkleLoadStatus::Missing { .. }) => {
                    keyhog_profile::CacheState::Cold
                }
                Some(keyhog_core::MerkleLoadStatus::Loaded { .. }) => {
                    keyhog_profile::CacheState::Warm
                }
                // Failed load: evidence exists and the cache is rebuilt, so
                // the run is cold, never `unknown`.
                Some(_) => keyhog_profile::CacheState::Cold,
            };
        }

        operator_profile.transition(keyhog_profile::RunState::Scanning);
        let all_matches = {
            let _profile_span = keyhog_profile::span(keyhog_profile::Stage::ScanPipeline);
            self.scan_sources(sources, show_progress, merkle, incremental_cache_path)?
        };
        operator_profile.transition(keyhog_profile::RunState::Resolving);
        let filtered = {
            let _profile_span = keyhog_profile::span(keyhog_profile::Stage::Suppression);
            self.filter_and_resolve(all_matches, &allowlist)?
        };
        operator_profile.transition(keyhog_profile::RunState::Verifying);
        let mut findings = {
            let _profile_span = keyhog_profile::span(keyhog_profile::Stage::LiveVerification);
            self.finalize(filtered).await?
        };
        operator_profile.transition(keyhog_profile::RunState::Reporting);

        let _suppression_span = keyhog_profile::span(keyhog_profile::Stage::Suppression);
        let rule_suppressor = load_rule_suppressor(self.args.path.as_deref())?;
        let pre_rule_count = findings.len();
        let hide_client_safe = self.effective_config.report.hide_client_safe;
        let mut client_safe_dropped = 0usize;
        findings.retain(|f| {
            if rule_suppressor.matches(f) {
                return false;
            }
            if hide_client_safe && f.severity == keyhog_core::Severity::ClientSafe {
                client_safe_dropped += 1;
                return false;
            }
            true
        });
        drop(_suppression_span);

        // KH-GAP-096: a requested source that failed ENTIRELY, producing zero
        // chunks AND erroring (e.g. --git-history / --git-diff on a non-repo or
        // bad ref, --github-org with a bad token, an unreachable --url, or a
        // tree whose every entry was unreadable or over a cap), means the scan
        // did not cover what was asked of it. That must NOT read as "no
        // findings, all clean" + exit 0: a CI gate would take it for a clean
        // tree when nothing was examined.
        //
        // It must equally NOT discard the run. This used to return here, ahead
        // of report emission, so `-o out.json` produced NO FILE AT ALL: not an
        // empty envelope, not a gap row, nothing. Our loudest failure was the
        // only one with no machine-readable output, so a CI job could not tell
        // "we could not scan your input" from "the tool never ran", and the
        // shipped generic-shell and Drone recipes pre-seeded an empty envelope
        // purely to work around it. The verdict belongs in the exit code; the
        // reason belongs in the report. Both are now always produced.
        //
        // A partial failure (some entries unreadable in a tree that still
        // produced chunks) does not set FAILED_SOURCES at all, and a failed
        // source running alongside one that DID surface findings still exits 1,
        // because `resolve_scan_exit` ranks findings above coverage.
        let total_source_failure =
            crate::FAILED_SOURCES.load(std::sync::atomic::Ordering::Relaxed) > 0;
        if total_source_failure && findings.is_empty() {
            eprintln!(
                "error: a requested scan source failed to read and produced no data (see the \
                 warnings above). Not reporting \"clean\": that scan did not run. A report is \
                 still written, stating what was not covered and why. Check the repository \
                 path, ref, token, or URL and re-run."
            );
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

        // Reliability outcomes gate baseline mutation (KH-504 / KH-1352).
        // Panic, incremental-cache failure, FAIL-class coverage gaps, or a
        // source that produced nothing at all must not mint a "successful"
        // baseline. Deliberate WARN skips (binary, over-max-size) do not
        // poison baseline writes.
        let scanner_panicked = crate::SCANNER_PANICKED.load(std::sync::atomic::Ordering::Relaxed);
        let incremental_cache_failed =
            crate::INCREMENTAL_CACHE_ERRORS.load(std::sync::atomic::Ordering::Relaxed) > 0;
        let source_coverage_incomplete = source_coverage_incomplete();
        let baseline_coverage_failed = baseline_coverage_untrustworthy();
        let autoroute_persist_failed =
            crate::AUTOROUTE_PERSIST_ERRORS.load(std::sync::atomic::Ordering::Relaxed) > 0;
        let baseline_untrustworthy = scanner_panicked
            || incremental_cache_failed
            || baseline_coverage_failed
            || total_source_failure;

        if let Some(path) = &self.args.create_baseline {
            if baseline_untrustworthy {
                let exit = resolve_scan_exit(ScanOutcome {
                    autoroute_calibration: false,
                    scanner_panicked,
                    has_live_credentials: false,
                    has_blocking_findings: false,
                    incremental_cache_failed,
                    source_coverage_incomplete: baseline_coverage_failed,
                    total_source_failure,
                    autoroute_persist_failed,
                });
                eprintln!(
                    "error: refusing --create-baseline: scan is untrustworthy \
                     (panic={}, coverage_failed={}, incremental_cache_failed={}). \
                     Prior baseline left unchanged.",
                    scanner_panicked, baseline_coverage_failed, incremental_cache_failed
                );
                for (reason, count) in crate::reporting::coverage_gap_summary(
                    &crate::reporting::CoverageCounts::current(),
                ) {
                    if count > 0 {
                        eprintln!("  coverage gap: {count} {reason}");
                    }
                }
                operator_profile.finish_recorded(
                    exit,
                    &findings,
                    None,
                    scanner_panicked,
                    true,
                    self.effective_config.report.verify,
                );
                return Ok(std::process::ExitCode::from(exit));
            }
            let baseline = Baseline::from_findings(&findings);
            baseline.save(path)?;
            if show_progress {
                eprintln!(
                    "\n📝 Baseline created with {} entries at {}",
                    baseline.entries.len(),
                    path.display()
                );
            }
            // Snapshot still writes even with findings (exit 0), but Live must
            // not collapse to green: CI that combines --create-baseline --verify
            // needs exit 10 (KH-1439).
            let has_live = findings
                .iter()
                .any(|f| matches!(f.verification, VerificationResult::Live));
            if has_live {
                operator_profile.finish_recorded(
                    EXIT_LIVE_CREDENTIALS,
                    &findings,
                    Some(path),
                    scanner_panicked,
                    false,
                    self.effective_config.report.verify,
                );
                return Ok(std::process::ExitCode::from(EXIT_LIVE_CREDENTIALS));
            }
            operator_profile.finish_recorded(
                EXIT_SUCCESS,
                &findings,
                Some(path),
                scanner_panicked,
                false,
                self.effective_config.report.verify,
            );
            return Ok(std::process::ExitCode::SUCCESS);
        }

        let report_findings = if let Some(path) = &self.args.update_baseline {
            if baseline_untrustworthy {
                let exit = resolve_scan_exit(ScanOutcome {
                    autoroute_calibration: false,
                    scanner_panicked,
                    has_live_credentials: false,
                    has_blocking_findings: false,
                    incremental_cache_failed,
                    source_coverage_incomplete: baseline_coverage_failed,
                    total_source_failure,
                    autoroute_persist_failed,
                });
                eprintln!(
                    "error: refusing --update-baseline: scan is untrustworthy \
                     (panic={}, coverage_failed={}, incremental_cache_failed={}). \
                     Prior baseline left byte-identical.",
                    scanner_panicked, baseline_coverage_failed, incremental_cache_failed
                );
                for (reason, count) in crate::reporting::coverage_gap_summary(
                    &crate::reporting::CoverageCounts::current(),
                ) {
                    if count > 0 {
                        eprintln!("  coverage gap: {count} {reason}");
                    }
                }
                operator_profile.finish_recorded(
                    exit,
                    &findings,
                    None,
                    scanner_panicked,
                    true,
                    self.effective_config.report.verify,
                );
                return Ok(std::process::ExitCode::from(exit));
            }
            let mut baseline = if path.exists() {
                Baseline::load(path)?
            } else {
                Baseline::empty()
            };
            let keep = baseline.new_finding_mask(&findings);
            let new_count = keep.iter().filter(|keep| **keep).count();
            baseline.merge(&findings);
            baseline.save(path)?;
            if show_progress {
                eprintln!(
                    "\n📝 Baseline updated: added {} new entries at {}",
                    new_count,
                    path.display()
                );
            }
            Baseline::retain_mask(&mut findings, &keep);
            findings
        } else if let Some(path) = &self.args.baseline {
            let baseline = Baseline::load(path)?;
            let pre_baseline_count = findings.len();
            baseline.retain_new(&mut findings);
            let suppressed_count = pre_baseline_count - findings.len();
            if show_progress && suppressed_count > 0 {
                eprintln!("\n  Suppressed {} baseline finding(s)", suppressed_count);
            }
            findings
        } else {
            findings
        };

        let exit_class = scan_exit_code(
            &report_findings,
            self.effective_config.report.evidence_policy.is_paranoid(),
        );
        let has_live_credentials = exit_class == EXIT_LIVE_CREDENTIALS;
        let has_blocking_findings = exit_class == EXIT_FINDINGS;

        // `--stream`: emit one redacted `[stream]` preview per REPORTED finding.
        // Wired to the resolved report stream (post filter_and_resolve /
        // suppression / --min-confidence / baseline) rather than the raw scanner
        // matches, so a streamed line always corresponds to a finding the report
        // and exit code agree on. (AUD-testing_dogfood-1: the old wiring streamed
        // raw matches the report later dropped, lying about the result.)
        if self.args.stream {
            super::reporting::stream_report_previews(&report_findings);
        }

        let report_finished_at = chrono::Utc::now();
        let report_metadata = crate::reporting::report_metadata_from_scan_run_with_corpus(
            &self.args,
            wall_start,
            report_finished_at,
            start.elapsed().as_millis(),
            crate::SCANNED_CHUNKS.load(std::sync::atomic::Ordering::Relaxed),
            crate::SCANNED_BYTES.load(std::sync::atomic::Ordering::Relaxed),
            self.detector_count,
            &self.detector_corpus_digest,
            &self.detector_corpus_provenance,
            Some(crate::orchestrator_config::autoroute_config_digest(
                &self.effective_config,
            )),
        );
        let show_reporting_progress = show_progress
            && !self.args.stream
            && (self.args.output.is_some() || !std::io::stdout().is_terminal());
        let report_finding_count = report_findings.len();
        let reporting_progress = show_reporting_progress.then(|| {
            TickerGuard::spawn("reporting", move |done, started| {
                super::reporting::reporting_ticker(done, started, report_finding_count)
            })
        });
        let report_result = {
            let _profile_span = keyhog_profile::span(keyhog_profile::Stage::Reporting);
            crate::reporting::report_findings_with_metadata(
                &report_findings,
                &self.args,
                &report_metadata,
            )
        };
        if let Some(guard) = reporting_progress {
            guard.stop();
        }
        if let Err(error) = report_result {
            // Exit 3, not 13, and say so. "We could not scan your input" and
            // "we scanned it and could not write the answer down" need opposite
            // responses (fix the input versus fix the output path), and after
            // the always-emit change they would otherwise share one signature:
            // non-zero exit, no report on disk. The exit code separates them;
            // this line names the path so an operator does not have to infer it.
            match self.args.output.as_deref() {
                Some(path) => eprintln!(
                    "error: the scan completed but its report could not be written to {}: \
                     {error}. The findings above were produced and then lost at the output \
                     step; this is an output-path failure, not a coverage failure.",
                    path.display()
                ),
                None => eprintln!(
                    "error: the scan completed but its report could not be emitted: {error}. \
                     This is an output failure, not a coverage failure."
                ),
            }
            let coverage_counts = crate::reporting::CoverageCounts::current();
            let mut outcome = profiler_outcome_identity(
                EXIT_SYSTEM_ERROR,
                &report_findings,
                None,
                scanner_panicked,
                crate::INCREMENTAL_CACHE_ERRORS.load(std::sync::atomic::Ordering::Relaxed),
                &coverage_counts,
            );
            outcome.coverage = keyhog_profile::CoverageStateV2::Failed;
            outcome.status = keyhog_profile::RunState::Failed;
            outcome.error_count = keyhog_profile::Evidence::recorded(1);
            let outcome_status = outcome.status;
            operator_profile.set_outcome(outcome);
            operator_profile
                .set_verification(self.effective_config.report.verify, &report_findings);
            operator_profile.finish(outcome_status);
            return Err(error);
        }

        let elapsed = start.elapsed().as_secs_f64();
        if show_progress {
            report_completion_summary(
                &report_findings,
                elapsed,
                progress_ansi,
                self.effective_config.backend_override,
            );
        } else {
            report_skip_summary(false);
        }
        // Scanner materialization, cache state, and autoroute state are status,
        // not decoration: a piped `--format json -o <file>` run is exactly the
        // shape CI and installers use, and it is where "did this scan use the
        // installed generation" has to be answerable. Only `--quiet` silences
        // them.
        if !self.args.quiet {
            report_scanner_materialization_summary(
                progress_ansi,
                self.scanner_materialization.as_ref(),
            );
            report_compiled_cache_summary(progress_ansi, &self);
        }
        report_autoroute_cache_summary(
            show_progress && progress_ansi,
            self.effective_config.backend_override.is_some(),
        );
        dump_dogfood_trace();

        tracing::info!(
            "Done in {:.1}s. {} findings",
            elapsed,
            report_findings.len()
        );

        let exit = resolve_scan_exit(ScanOutcome {
            autoroute_calibration: self.args.autoroute_calibrate,
            scanner_panicked,
            has_live_credentials,
            has_blocking_findings,
            incremental_cache_failed,
            source_coverage_incomplete,
            total_source_failure,
            autoroute_persist_failed,
        });
        crate::action_report::write_scan_receipt(
            &self.args,
            report_findings.len(),
            exit,
            report_metadata.scan_status,
        )?;
        // The total-source-failure case already printed its own, more specific
        // diagnostic before the report was written, so do not restate it.
        if exit == EXIT_SOURCE_FAILED && !total_source_failure {
            eprintln!(
                "error: input coverage was incomplete (see coverage warnings above). Not \
                 reporting \"clean\": some requested bytes were not scanned."
            );
        }
        let coverage_counts = crate::reporting::CoverageCounts::current();
        let outcome = profiler_outcome_identity(
            exit,
            &report_findings,
            self.args.output.as_deref(),
            scanner_panicked,
            crate::INCREMENTAL_CACHE_ERRORS.load(std::sync::atomic::Ordering::Relaxed),
            &coverage_counts,
        );
        let outcome_status = outcome.status;
        operator_profile.set_outcome(outcome);
        operator_profile.set_verification(self.effective_config.report.verify, &report_findings);
        {
            let _profile_span = keyhog_profile::span(keyhog_profile::Stage::Teardown);
            drop(self.scanner);
        }
        operator_profile.finish(outcome_status);
        Ok(std::process::ExitCode::from(exit))
    }
}

/// Pure exit-code mapping for the reported finding set.
///
/// Live verification takes precedence and returns
/// [`EXIT_LIVE_CREDENTIALS`] (10). Otherwise, confirmed and likely evidence
/// return [`EXIT_FINDINGS`] (1) under the default policy. Review evidence
/// remains visible but returns [`EXIT_SUCCESS`] (0), unless `paranoid` is true.
///
/// Verification states other than `Live` do not independently change the exit
/// code. Their scanner evidence still applies, so a dead or skipped finding can
/// block when its tier is confirmed or likely.
///
/// Keeping this mapping pure gives daemon and one-shot reporting one
/// definitional source for identical exit semantics.
pub(crate) fn scan_exit_code(findings: &[VerifiedFinding], paranoid: bool) -> u8 {
    if findings
        .iter()
        .any(|finding| matches!(finding.verification, VerificationResult::Live))
    {
        EXIT_LIVE_CREDENTIALS
    } else if findings
        .iter()
        .any(|finding| finding.evidence.tier().blocks(paranoid))
    {
        EXIT_FINDINGS
    } else {
        EXIT_SUCCESS
    }
}

/// Incomplete exit 13 and baseline refusal share the CoverageGapKind FAIL set
/// (KH-1347 / KH-1352). WARN skips (binary, over-max-size, deliberate exclude,
/// advisory scanner truncations) must not flip a clean scan to exit 13.
fn source_coverage_incomplete() -> bool {
    fail_class_coverage_gaps() > 0
}

fn baseline_coverage_untrustworthy() -> bool {
    fail_class_coverage_gaps() > 0
}

fn fail_class_coverage_gaps() -> usize {
    // Single owner: CoverageGapKind severity table via CoverageCounts (KH-1410).
    crate::reporting::CoverageCounts::current().fail_class_total()
}
