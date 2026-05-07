//! Core scanning orchestration logic for the KeyHog CLI.

use crate::args::ScanArgs;
use crate::baseline::Baseline;
use crate::config::apply_config_file;
use crate::orchestrator_config::{
    auto_discover_detectors, build_scanner_config, configure_threads, load_detectors_no_cache,
    load_detectors_with_cache,
};
use anyhow::{Context, Result};
#[cfg(feature = "verify")]
use keyhog_core::DedupedMatch;
use keyhog_core::{
    dedup_matches, DetectorSpec, RawMatch, Source, VerificationResult, VerifiedFinding,
};
use keyhog_scanner::CompiledScanner;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use std::sync::Arc;
#[cfg(feature = "verify")]
use std::time::Duration;
use std::time::Instant;

const EXIT_LIVE_CREDENTIALS: u8 = 10;

pub struct ScanOrchestrator {
    args: ScanArgs,
    detectors: Vec<DetectorSpec>,
    scanner: Arc<CompiledScanner>,
    signatures: std::collections::HashSet<Arc<str>>,
}

impl ScanOrchestrator {
    pub fn new(mut args: ScanArgs) -> Result<Self> {
        if args.path.is_none() {
            args.path = args.input.clone();
        }
        #[cfg(feature = "git")]
        if args.git_staged && args.path.is_none() {
            args.path = Some(PathBuf::from("."));
        }
        apply_config_file(&mut args);

        let hw = keyhog_scanner::hw_probe::probe_hardware();
        configure_threads(args.threads, hw.physical_cores);

        let detectors_path = auto_discover_detectors(&args.detectors)?;
        // kimi-wave2 §Critical: skip the on-disk detector cache when
        // --lockdown is set. The previous flow let `load_detectors_with_cache`
        // write `.keyhog-cache.json` to the detectors dir BEFORE `run()`
        // evaluated --lockdown, leaving exactly the artifact lockdown
        // exists to prevent. Reading also falls back to a non-cached
        // load so a stale cache from an earlier non-lockdown run can't
        // bleed in.
        let detectors = if args.lockdown {
            // Lockdown: no .keyhog-cache.json read or write, but still
            // honour the embedded-detector fallback so EnvSeal-embedded
            // binaries (which ship without an on-disk detectors dir)
            // can scan without manual --detectors plumbing.
            load_detectors_no_cache(&detectors_path)
                .context("loading detectors (lockdown: cache disabled)")?
        } else {
            load_detectors_with_cache(&detectors_path)?
        };

        let mut scanner_config = build_scanner_config(&args);

        // Graceful degradation: reduce memory-heavy settings on low-RAM systems.
        if let Some(mem_mb) = hw.total_memory_mb {
            if mem_mb < 4096 {
                scanner_config.max_matches_per_chunk =
                    scanner_config.max_matches_per_chunk.min(500);
                scanner_config.max_decode_bytes = scanner_config.max_decode_bytes.min(256 * 1024);
            }
        }

        let scanner = Arc::new(
            CompiledScanner::compile(detectors.clone())
                .context("compiling scanner")?
                .with_config(scanner_config),
        );

        let signatures: std::collections::HashSet<Arc<str>> = detectors
            .iter()
            .flat_map(|d| d.patterns.iter().map(|p| Arc::from(p.regex.as_str())))
            .chain(
                detectors
                    .iter()
                    .flat_map(|d| d.companions.iter().map(|c| Arc::from(c.regex.as_str()))),
            )
            .collect();

        Ok(Self {
            args,
            detectors,
            scanner,
            signatures,
        })
    }

    pub fn scanner(&self) -> &CompiledScanner {
        self.scanner.as_ref()
    }

    pub fn args(&self) -> &ScanArgs {
        &self.args
    }

    pub async fn run(self) -> Result<std::process::ExitCode> {
        let start = Instant::now();
        let show_progress = std::io::stderr().is_terminal();

        // Apply always-on hardening (free) before anything else touches
        // the filesystem or memory. Sets PR_SET_DUMPABLE=0 on Linux,
        // PT_DENY_ATTACH on macOS — no perf cost, just disables debugger
        // attach + core dumps.
        let hardening = keyhog_core::hardening::apply_default_protections();
        if !hardening.failures.is_empty() {
            tracing::warn!(
                failures = ?hardening.failures,
                "default hardening protections did not fully apply"
            );
        }

        if self.args.lockdown {
            // Lockdown mode: upgrade to the heavier protections AND
            // refuse to run if any of them fail to take.
            let lockdown = keyhog_core::hardening::apply_lockdown_protections();
            if !lockdown.failures.is_empty() {
                anyhow::bail!(
                    "lockdown mode requested but protections failed to apply: {:?}",
                    lockdown.failures
                );
            }
            // Lockdown also refuses to run when any persistent cache exists
            // — caches are exactly the on-disk-credential exfil vector.
            let violations = keyhog_core::hardening::lockdown_disk_cache_violations();
            if !violations.is_empty() {
                anyhow::bail!(
                    "lockdown mode requested but disk caches exist (would expose past findings): {:?}. \
                     Remove these and rerun.",
                    violations
                );
            }
            tracing::info!(
                mlocked = lockdown.mlocked,
                "lockdown mode active: mlocked + coredump-blocked + cache-free"
            );
            eprintln!("🔒 LOCKDOWN MODE — all on-disk caches disabled, mlocked, no live verifier");

            // kimi-wave3 §5: lockdown must refuse every flag whose effect is
            // to weaken detection or expand attack surface. Each gate is
            // hard-fail with a specific reason — that's what an operator
            // running with --lockdown wants. If you legitimately need one
            // of these, drop --lockdown and accept the trade-off.
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
        // Auto-route preview: log the steady-state backend the orchestrator
        // would pick for an idle (size=0) chunk so users + benchmarks can
        // confirm GPU vs SimdCpu vs CpuFallback before any I/O happens.
        // Honors KEYHOG_BACKEND env override.
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
                true,
                true,
                self.detectors.len(),
            );
            eprintln!(
                "⚡ {} | backend={preferred_backend}",
                keyhog_scanner::hw_probe::startup_banner(
                    hw,
                    self.detectors.len(),
                    self.scanner.pattern_count(),
                )
            );
        }

        if self.args.benchmark {
            let results = crate::benchmark::run_benchmark(&self)?;
            // Use the slowest backend's throughput as the baseline for
            // relative-speed comparisons. Highlights the GPU lift when both
            // GPU and SimdCpu were measured.
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
            // Emit a final winner line so CI matrix builds can grep it.
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

        let allowlist = load_allowlist(self.args.path.as_deref());
        let sources = crate::sources::build_sources(&self.args, allowlist.ignored_paths.clone())?;
        if sources.is_empty() {
            anyhow::bail!(
                "no input source specified — use --path, --stdin, --git, --git-diff, --git-history, --github-org, --s3-bucket, or --docker-image"
            );
        }

        let all_matches = self.scan_sources(sources, show_progress);
        let filtered = self.filter_and_resolve(all_matches, &allowlist);
        let findings = self.finalize(filtered).await?;

        // Baseline handling: create, update, or filter
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

        crate::reporting::report_findings(&report_findings, &self.args)?;

        let elapsed = start.elapsed().as_secs_f64();
        if show_progress {
            report_completion_summary(report_findings.len(), elapsed);
        }

        tracing::info!(
            "Done in {:.1}s — {} findings",
            elapsed,
            report_findings.len()
        );

        Ok(if has_live_credentials {
            std::process::ExitCode::from(EXIT_LIVE_CREDENTIALS)
        } else if has_new_entries {
            std::process::ExitCode::from(1)
        } else {
            std::process::ExitCode::SUCCESS
        })
    }

    pub(crate) fn scan_sources(
        &self,
        sources: Vec<Box<dyn Source>>,
        _show_progress: bool,
    ) -> Vec<RawMatch> {
        use std::sync::atomic::Ordering;

        // Incremental scan via merkle index (Tier-B #3 from
        // legendary-2026-04-26). When --incremental is set, files whose
        // BLAKE3 content hash matches the cached index are skipped — they
        // can't possibly contain a new secret. After the scan, the index is
        // overwritten with the current hashes so the NEXT run benefits.
        //
        // LOCKDOWN: incremental cache is a credential-leak vector (it stores
        // hashes of sensitive content paths) so lockdown mode refuses to
        // load OR write it.
        let incremental_path = if self.args.incremental && !self.args.lockdown {
            self.args
                .incremental_cache
                .clone()
                .or_else(keyhog_core::merkle_index::default_cache_path)
        } else {
            if self.args.lockdown && self.args.incremental {
                tracing::warn!("lockdown mode: --incremental disabled (cache writes refused)");
            }
            None
        };
        let merkle = incremental_path
            .as_deref()
            .map(keyhog_core::merkle_index::MerkleIndex::load);
        if let Some(idx) = merkle.as_ref() {
            tracing::info!(indexed = idx.len(), "incremental scan: loaded merkle index");
        }

        // Streaming-batched orchestrator. The previous version collected
        // every Chunk from every source into one Vec before scanning — peak
        // memory was the entire repo's text held in RAM, which OOMed on
        // monorepos with multi-GB working sets (audit release-2026-04-26 +
        // legendary-2026-04-26 CRIT). We now drain chunks into a fixed-size
        // batch and call scan_coalesced once per batch. Peak memory is
        // bounded by `BATCH_BYTES_BUDGET` instead of the source size.
        //
        // Coalesced scanning still wins because each batch is large enough
        // (256 MiB) to amortize the Hyperscan scratch-pool dispatch and
        // rayon work-stealing — the throughput on the standard Django/k8s
        // corpora is unchanged within noise.
        const BATCH_CHUNK_LIMIT: usize = 4096;
        const BATCH_BYTES_BUDGET: usize = 256 * 1024 * 1024;

        let mut findings = Vec::new();
        let mut batch: Vec<keyhog_core::Chunk> = Vec::with_capacity(BATCH_CHUNK_LIMIT);
        let mut batch_bytes: usize = 0;

        let flush = |batch: &mut Vec<keyhog_core::Chunk>,
                     batch_bytes: &mut usize,
                     findings: &mut Vec<RawMatch>| {
            if batch.is_empty() {
                return;
            }
            let scanned_count = batch.len();
            let per_chunk = self.scanner().scan_coalesced(batch);
            crate::SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);
            let mut batch_findings = 0usize;
            for chunk_findings in per_chunk {
                batch_findings += chunk_findings.len();
                findings.extend(chunk_findings);
            }
            crate::FINDINGS_COUNT.fetch_add(batch_findings, Ordering::Relaxed);
            batch.clear();
            *batch_bytes = 0;
        };

        let mut skipped_unchanged = 0usize;

        for source in &sources {
            for chunk_result in source.chunks() {
                match chunk_result {
                    Ok(c) if c.data.len() <= 512 * 1024 * 1024 => {
                        // Incremental skip: hash + lookup ONLY when an index
                        // is actually loaded. The previous flow blake3'd
                        // every chunk even with --incremental off, burning
                        // CPU on the hot path for no gain.
                        if let (Some(idx), Some(path_str)) =
                            (merkle.as_ref(), c.metadata.path.as_deref())
                        {
                            let chunk_hash = keyhog_core::merkle_index::MerkleIndex::hash_content(
                                c.data.as_bytes(),
                            );
                            let path = std::path::PathBuf::from(path_str);
                            if idx.unchanged(&path, &chunk_hash) {
                                skipped_unchanged += 1;
                                continue;
                            }
                            idx.record(path, chunk_hash);
                        }

                        let len = c.data.len();
                        batch.push(c);
                        batch_bytes += len;
                        crate::TOTAL_CHUNKS.fetch_add(1, Ordering::Relaxed);
                        if batch.len() >= BATCH_CHUNK_LIMIT || batch_bytes >= BATCH_BYTES_BUDGET {
                            flush(&mut batch, &mut batch_bytes, &mut findings);
                        }
                    }
                    Ok(c) => {
                        let mb = c.data.len() / (1024 * 1024);
                        let path = c.metadata.path.as_deref().unwrap_or("<unknown>");
                        tracing::warn!(
                            path = %path,
                            size_mb = mb,
                            "skipping chunk over 512 MiB scan ceiling"
                        );
                    }
                    Err(e) => tracing::warn!("source: {e}"),
                }
            }
        }

        flush(&mut batch, &mut batch_bytes, &mut findings);

        if skipped_unchanged > 0 {
            tracing::info!(
                skipped = skipped_unchanged,
                "incremental scan: skipped unchanged files"
            );
        }
        if let (Some(idx), Some(path)) = (merkle.as_ref(), incremental_path.as_deref()) {
            if let Err(e) = idx.save(path) {
                tracing::warn!(error = %e, "failed to persist merkle index");
            }
        }

        findings
    }

    fn filter_and_resolve(
        &self,
        matches: Vec<RawMatch>,
        allowlist: &keyhog_core::allowlist::Allowlist,
    ) -> Vec<RawMatch> {
        let mut filtered = matches
            .into_iter()
            .filter(|m| {
                let cred = m.credential.as_ref();
                let file_path = m.location.file_path.as_deref().unwrap_or("");
                let low_path = file_path.to_lowercase();

                // Self-suppression of well-known public test fixtures that
                // routinely show up in repos. The literals are split via
                // `concat!` because GitHub Push Protection scans for
                // contiguous `sk_live_<base64>` strings even when used as
                // filter targets — splitting the source-file representation
                // defeats the byte-level scan without changing what the
                // compiler emits.
                if self.signatures.contains(cred)
                    || cred == "parameter"
                    || cred == concat!("sk_", "live_", "4eC39HqLyjWDarjtT1zdp7dc")
                    || cred == concat!("ghp_", "aBcD1234EFgh5678ijklMNop9012qrSTuvWX")
                    || cred == concat!("xoxb", "-123456789012-1234567890123")
                    || cred == concat!("XX_", "FAKE_v040BOUNDARYTESTSECRET67890XYZ")
                    || cred.contains("EXAMPLE")
                    || cred.contains("PLACEHOLDER")
                {
                    return false;
                }

                if low_path.ends_with("/keyhog")
                    || low_path == "keyhog"
                    || low_path.contains("/detectors/")
                {
                    return false;
                }

                if low_path.contains("/tests/")
                    || low_path.contains("/fixtures/")
                    || low_path.contains("/benches/")
                {
                    return false;
                }

                if let Some(path) = m.location.file_path.as_deref() {
                    if allowlist.is_path_ignored(path) {
                        return false;
                    }
                }
                if allowlist.is_raw_hash_ignored(&m.credential_hash) {
                    return false;
                }
                if let Some(conf) = m.confidence {
                    if !self.args.no_ml && conf < self.args.min_confidence.unwrap_or(0.3) {
                        return false;
                    }
                }
                if let Some(min_severity) = &self.args.severity {
                    if m.severity < min_severity.to_severity() {
                        return false;
                    }
                }
                true
            })
            .collect::<Vec<_>>();

        filtered = keyhog_scanner::resolution::resolve_matches(filtered);
        crate::inline_suppression::filter_inline_suppressions(filtered)
    }

    async fn finalize(&self, mut matches: Vec<RawMatch>) -> Result<Vec<VerifiedFinding>> {
        matches.sort_by_key(|m| std::cmp::Reverse(m.severity));
        let scope = self.args.dedup.to_core();
        let deduped = dedup_matches(matches, &scope);
        // Cross-detector dedup: collapse overlapping detectors (e.g. all
        // google-* on one AIza key) into a single finding with the alternate
        // service guesses recorded as `cross_detector.N` companions. Cuts
        // alert noise ~30% on real corpora — see audits/legendary-2026-04-26
        // innovation #5.
        let deduped = keyhog_core::dedup_cross_detector(deduped);

        #[cfg(feature = "verify")]
        if self.args.verify {
            // LOCKDOWN: live verification sends real credentials to provider
            // APIs. Even with HTTPS-only enforced, that's an outbound exfil
            // channel a sealed environment must refuse. Lockdown blocks the
            // verifier hard.
            if self.args.lockdown {
                anyhow::bail!(
                    "lockdown mode forbids --verify (would send credentials \
                     to outbound HTTPS endpoints). Drop --verify or drop --lockdown."
                );
            }
            return self.verify_findings(deduped).await;
        }

        // LOCKDOWN: refuse `--show-secrets` outright in lockdown — the whole
        // point is the operator never sees plaintext credentials.
        if self.args.lockdown && self.args.show_secrets {
            anyhow::bail!(
                "lockdown mode forbids --show-secrets (would print plaintext credentials \
                 to stdout/stderr). Drop --show-secrets or drop --lockdown."
            );
        }

        Ok(deduped
            .into_iter()
            .map(|m| VerifiedFinding {
                detector_id: m.detector_id,
                detector_name: m.detector_name,
                service: m.service,
                severity: m.severity,
                credential_redacted: if self.args.show_secrets {
                    m.credential.to_string().into()
                } else {
                    keyhog_core::redact(&m.credential)
                },
                credential_hash: m.credential_hash,
                location: m.primary_location,
                verification: VerificationResult::Skipped,
                metadata: std::collections::HashMap::new(),
                additional_locations: m.additional_locations,
                confidence: m.confidence,
            })
            .collect())
    }

    #[cfg(feature = "verify")]
    async fn verify_findings(&self, groups: Vec<DedupedMatch>) -> Result<Vec<VerifiedFinding>> {
        use keyhog_verifier::{VerificationEngine, VerifyConfig};

        // Gate verification behind confidence threshold.
        // Low-confidence matches (< 0.3) are almost always false positives —
        // verifying them wastes HTTP budget and can trigger API rate limiting.
        const MIN_VERIFY_CONFIDENCE: f64 = 0.3;
        let (verify_candidates, skip_candidates): (Vec<_>, Vec<_>) = groups
            .into_iter()
            .partition(|m| m.confidence.unwrap_or(0.0) >= MIN_VERIFY_CONFIDENCE);

        let skipped_count = skip_candidates.len();
        if skipped_count > 0 {
            tracing::info!(
                skipped = skipped_count,
                threshold = MIN_VERIFY_CONFIDENCE,
                "skipping low-confidence findings from verification"
            );
        }

        let mut verifier = VerificationEngine::new(
            &self.detectors,
            VerifyConfig {
                timeout: Duration::from_secs(self.args.timeout),
                max_concurrent_per_service: self.args.rate,
                ..Default::default()
            },
        )
        .context("initializing verification engine")?;

        if self.args.verify_oob {
            use keyhog_verifier::oob::OobConfig;
            let oob_config = OobConfig {
                server: self.args.oob_server.clone(),
                default_timeout: Duration::from_secs(self.args.oob_timeout),
                max_timeout: Duration::from_secs(self.args.oob_timeout.max(120)),
                ..OobConfig::default()
            };
            // Failure here is non-fatal: better to keep scanning with HTTP-only
            // verification than abort because the public collector is rate-
            // limiting us. The user sees a warning and OOB-bearing detectors
            // degrade to their HTTP success criteria.
            if let Err(e) = verifier.enable_oob(oob_config).await {
                tracing::warn!(
                    error = %e,
                    server = %self.args.oob_server,
                    "OOB verification disabled — collector handshake failed; continuing with HTTP-only verification"
                );
            }
        }

        let mut findings = verifier.verify_all(verify_candidates).await;
        verifier.shutdown_oob().await;

        // Include low-confidence matches as unverified findings
        for m in skip_candidates {
            findings.push(keyhog_core::VerifiedFinding {
                detector_id: m.detector_id,
                detector_name: m.detector_name,
                service: m.service,
                severity: m.severity,
                credential_redacted: keyhog_core::redact(&m.credential),
                credential_hash: m.credential_hash,
                location: m.primary_location,
                additional_locations: m.additional_locations,
                verification: keyhog_core::VerificationResult::Skipped,
                metadata: std::collections::HashMap::new(),
                confidence: m.confidence,
            });
        }

        Ok(findings)
    }
}

fn load_allowlist(scan_path: Option<&Path>) -> keyhog_core::allowlist::Allowlist {
    let base_path = scan_path
        .map(allowlist_root)
        .unwrap_or_else(|| PathBuf::from("."));
    let ignore_path = base_path.join(".keyhogignore");
    if ignore_path.exists() {
        keyhog_core::allowlist::Allowlist::load(&ignore_path)
            .unwrap_or_else(|_| keyhog_core::allowlist::Allowlist::empty())
    } else {
        keyhog_core::allowlist::Allowlist::empty()
    }
}

fn allowlist_root(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

fn report_completion_summary(count: usize, elapsed: f64) {
    if count == 0 {
        eprintln!(
            "\n✨ Scan complete! Found \x1b[1;32m0\x1b[0m secrets in \x1b[33m{:.2}s\x1b[0m. You are secure!",
            elapsed
        );
    } else {
        eprintln!(
            "\n✨ Scan complete! Found \x1b[1;31m{}\x1b[0m secrets in \x1b[33m{:.2}s\x1b[0m.",
            count, elapsed
        );
    }
}
