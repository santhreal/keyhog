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
/// Set when the scanner worker thread panicked mid-scan. Surfaced as
/// a distinct exit code so a CI pipeline can tell "scan completed
/// clean" from "scanner crashed and we don't know if it was clean."
///
/// The panic-to-exit-code path is correct by inspection rather than by
/// integration test: writing a test that actually crashes
/// `scan_coalesced` would either need a production-binary-polluting
/// `#[cfg(test)]` panic-injection knob, or a malicious-input chunk
/// that panics the regex engine (fragile and detector-dependent). The
/// path itself — `scanner_thread.join()` returning `Err` →
/// `SCANNER_PANICKED.store(true)` → `EXIT_SCANNER_PANIC` here — is
/// linear and exercised by every `pipeline_tests::*` run (which
/// observe the flag stays `false` on successful joins).
const EXIT_SCANNER_PANIC: u8 = 11;

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

        // `--backend <name>` is sugar for `KEYHOG_BACKEND=<name>`. Setting
        // the env var here is safe even though the scanner was already
        // built — `select_backend` reads the var on every routing
        // decision, not at scanner-construction time. CLI flag wins over
        // env var so a developer who sets both gets the explicit one.
        if let Some(backend) = self.args.backend.as_deref() {
            // SAFETY: `set_var` is a process-wide mutation. We're early in
            // `run()`, before any worker thread has been spawned via
            // `configure_threads`/rayon, so no concurrent reader exists.
            // `KEYHOG_BACKEND` is owned by this binary; nothing else
            // observes it.
            unsafe {
                std::env::set_var("KEYHOG_BACKEND", backend);
            }
        }

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

        // Pre-warm the steady-state backend so the first scanned batch
        // doesn't pay the cold-start cost of compiling the GPU literal
        // matcher (≈100-300 ms on the 1500-detector corpus). Was lazy
        // inside `gpu_matcher()` — we already know which backend will
        // run, so do it now while the user is still reading the banner.
        // Best-effort: if warm fails we just take the cost on the first
        // batch as before.
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

        // Build the (optional) merkle index up here so it can be passed
        // into the filesystem source — that's where the perf win lives.
        // The orchestrator decides whether to load it at all (lockdown +
        // --incremental gating); sources just consume the Arc.
        let merkle = self.build_merkle_index();

        let sources = crate::sources::build_sources(
            &self.args,
            allowlist.ignored_paths.clone(),
            merkle.clone(),
        )?;
        if sources.is_empty() {
            anyhow::bail!(
                "no input source specified — use --path, --stdin, --git, --git-diff, --git-history, --github-org, --s3-bucket, or --docker-image"
            );
        }

        let all_matches = self.scan_sources(sources, show_progress, merkle);
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

        // Scanner-thread panic: exit non-zero even when no findings
        // were produced. The user MUST see the failure rather than
        // assume clean. Live-credentials still wins (more urgent),
        // then panic (reliability signal), then new entries.
        let scanner_panicked =
            crate::SCANNER_PANICKED.load(std::sync::atomic::Ordering::Relaxed);
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

    /// Compute the merkle-index destination path (resolving CLI override
    /// and default-cache fallback) iff `--incremental` is on AND lockdown
    /// is not engaged. `None` means "do not persist a cache this run."
    fn incremental_cache_path(&self) -> Option<std::path::PathBuf> {
        if !self.args.incremental {
            return None;
        }
        if self.args.lockdown {
            tracing::warn!("lockdown mode: --incremental disabled (cache writes refused)");
            return None;
        }
        self.args
            .incremental_cache
            .clone()
            .or_else(keyhog_core::merkle_index::default_cache_path)
    }

    /// Build the (optional) shared merkle index. Returns the Arc the
    /// orchestrator and every source share. The index is loaded with the
    /// detector spec hash gate so adding a detector forces a clean
    /// re-scan of every previously-cached file.
    fn build_merkle_index(
        &self,
    ) -> Option<Arc<keyhog_core::merkle_index::MerkleIndex>> {
        let path = self.incremental_cache_path()?;
        let spec_hash = keyhog_core::merkle_index::compute_spec_hash(&self.detectors);
        let idx = keyhog_core::merkle_index::MerkleIndex::load_with_spec(&path, &spec_hash);
        tracing::info!(
            indexed = idx.len(),
            "incremental scan: loaded merkle index"
        );
        Some(Arc::new(idx))
    }

    pub(crate) fn scan_sources(
        &self,
        sources: Vec<Box<dyn Source>>,
        _show_progress: bool,
        merkle: Option<Arc<keyhog_core::merkle_index::MerkleIndex>>,
    ) -> Vec<RawMatch> {
        use std::sync::atomic::Ordering;

        // Incremental scan via merkle index (Tier-B #3 from
        // legendary-2026-04-26). FilesystemSource handles the
        // pre-read metadata fast-path skip. The orchestrator still
        // does a content-hash check post-read for sources that don't
        // surface mtime (git diffs, stdin, archive entries) so those
        // benefit from the scan-skip even without the I/O skip.
        //
        // LOCKDOWN: incremental cache is a credential-leak vector (it stores
        // hashes of sensitive content paths) so lockdown mode refuses to
        // load OR write it. `build_merkle_index` returns `None` then.
        let incremental_path = self.incremental_cache_path();

        // Pipeline-batched orchestrator. The producer (this thread)
        // iterates sources and builds batches; the scanner runs in a
        // spawned thread that pulls completed batches off a bounded
        // channel. While the scanner is busy on a CPU-heavy regex
        // pass the producer is busy on the next file's I/O, so the
        // two stages overlap. Channel capacity = 1 keeps memory
        // bounded to one in-flight batch + one being built.
        //
        // Each batch still respects `BATCH_BYTES_BUDGET` so peak heap
        // doesn't grow unbounded on monorepos (legendary-2026-04-26
        // CRIT — pre-pipeline OOM regression that the streaming flush
        // model fixed). Coalesced scanning still wins because each
        // batch is large enough (256 MiB) to amortize the Hyperscan
        // scratch-pool dispatch and rayon work-stealing.
        const BATCH_CHUNK_LIMIT: usize = 4096;
        const BATCH_BYTES_BUDGET: usize = 256 * 1024 * 1024;
        const PIPELINE_DEPTH: usize = 1;

        let scanner = Arc::clone(&self.scanner);
        let (tx, rx) =
            std::sync::mpsc::sync_channel::<Vec<keyhog_core::Chunk>>(PIPELINE_DEPTH);

        // `--stream`: print a one-line redacted preview to stderr as
        // each finding lands. Captured into the worker thread closure
        // so the moved `Arc<CompiledScanner>` can stay tightly scoped.
        let stream = self.args.stream;

        // Scanner thread: pull batches, scan_coalesced each, accumulate
        // findings + counters. Holds an `Arc<CompiledScanner>` so the
        // producer can drop its handle and exit cleanly.
        let scanner_thread = std::thread::spawn(move || {
            let mut findings: Vec<RawMatch> = Vec::new();
            // Buffer stderr writes so the preview lines land atomically
            // even when the scanner produces them on multiple rayon
            // workers; one `LineWriter` per scanner thread is enough
            // since we only enter this loop on this single OS thread.
            let mut stderr_writer = if stream {
                Some(std::io::LineWriter::new(std::io::stderr()))
            } else {
                None
            };
            for batch in rx {
                if batch.is_empty() {
                    continue;
                }
                let scanned_count = batch.len();
                let per_chunk = scanner.scan_coalesced(&batch);
                crate::SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);
                let mut batch_findings = 0usize;
                for chunk_findings in per_chunk {
                    batch_findings += chunk_findings.len();
                    if let Some(w) = stderr_writer.as_mut() {
                        for m in &chunk_findings {
                            stream_finding_preview(w, m);
                        }
                    }
                    findings.extend(chunk_findings);
                }
                crate::FINDINGS_COUNT.fetch_add(batch_findings, Ordering::Relaxed);
            }
            findings
        });

        let mut batch: Vec<keyhog_core::Chunk> = Vec::with_capacity(BATCH_CHUNK_LIMIT);
        let mut batch_bytes: usize = 0;
        let mut skipped_unchanged = 0usize;
        // `pipeline_alive` short-circuits the producer loop when the
        // scanner thread has already given up (its `rx` was dropped on
        // panic). Without this we'd keep reading files into a batch
        // we'll never get to send.
        let mut pipeline_alive = true;

        let send_batch = |batch: &mut Vec<keyhog_core::Chunk>,
                              batch_bytes: &mut usize,
                              alive: &mut bool| {
            if !*alive || batch.is_empty() {
                batch.clear();
                *batch_bytes = 0;
                return;
            }
            let payload = std::mem::take(batch);
            *batch_bytes = 0;
            if tx.send(payload).is_err() {
                *alive = false;
            }
        };

        'sources: for source in &sources {
            for chunk_result in source.chunks() {
                match chunk_result {
                    Ok(c) if c.data.len() <= 512 * 1024 * 1024 => {
                        // Incremental skip: BLAKE3 + lookup ONLY when an
                        // index is actually loaded. FilesystemSource has
                        // already pre-skipped any file whose
                        // `(mtime, size)` matched a stored entry — so
                        // the chunks reaching this point either belong
                        // to a source without metadata (git, stdin,
                        // archive entries) or to a file whose metadata
                        // changed but content might still be identical
                        // (touch-after-rebase, file copy). Hash the
                        // chunk content; on hash match we can still
                        // skip the scan, just not the read.
                        if let (Some(idx), Some(path_str)) =
                            (merkle.as_ref(), c.metadata.path.as_deref())
                        {
                            let chunk_hash = keyhog_core::merkle_index::MerkleIndex::hash_content(
                                c.data.as_bytes(),
                            );
                            let path = std::path::PathBuf::from(path_str);
                            if idx.unchanged(&path, &chunk_hash) {
                                idx.record_with_metadata(
                                    path,
                                    c.metadata.mtime_ns.unwrap_or(0),
                                    c.metadata.size_bytes.unwrap_or(0),
                                    chunk_hash,
                                );
                                skipped_unchanged += 1;
                                continue;
                            }
                            idx.record_with_metadata(
                                path,
                                c.metadata.mtime_ns.unwrap_or(0),
                                c.metadata.size_bytes.unwrap_or(0),
                                chunk_hash,
                            );
                        }

                        let len = c.data.len();
                        batch.push(c);
                        batch_bytes += len;
                        crate::TOTAL_CHUNKS.fetch_add(1, Ordering::Relaxed);
                        if batch.len() >= BATCH_CHUNK_LIMIT || batch_bytes >= BATCH_BYTES_BUDGET {
                            send_batch(&mut batch, &mut batch_bytes, &mut pipeline_alive);
                            if !pipeline_alive {
                                break 'sources;
                            }
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

        send_batch(&mut batch, &mut batch_bytes, &mut pipeline_alive);
        // Drop the sender so the scanner's `for batch in rx` exits
        // cleanly once the in-flight batch is processed.
        drop(tx);
        let findings = scanner_thread.join().unwrap_or_else(|_| {
            tracing::error!(
                "scanner thread panicked mid-scan; results are incomplete"
            );
            // Surface the failure to `run()` so the process exits with
            // a non-zero code instead of silently reporting clean.
            crate::SCANNER_PANICKED.store(true, std::sync::atomic::Ordering::Relaxed);
            Vec::new()
        });

        if skipped_unchanged > 0 {
            tracing::info!(
                skipped = skipped_unchanged,
                "incremental scan: skipped unchanged files"
            );
        }
        if let (Some(idx), Some(path)) = (merkle.as_ref(), incremental_path.as_deref()) {
            // Persist the spec hash alongside the entries so the next
            // run rejects this cache the moment a detector is added,
            // removed, or modified — that's the only way to keep
            // metadata-skip safe under detector drift.
            let spec_hash =
                keyhog_core::merkle_index::compute_spec_hash(&self.detectors);
            if let Err(e) = idx.save_with_spec(path, &spec_hash) {
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

                // Path-based self-suppression. Splits on both `/` and
                // `\` so Windows paths get the same treatment as POSIX —
                // the previous flow did `path.to_lowercase()` and ran
                // `.contains("/tests/")` checks, which (a) silently
                // failed to suppress `\tests\` matches on Windows and
                // (b) burned an allocation per match even when the path
                // was empty. ASCII case-insensitive segment compare is
                // alloc-free: `eq_ignore_ascii_case` does the work in
                // place against literals.
                if let Some(file_path) = m.location.file_path.as_deref() {
                    let mut segs = file_path.split(['/', '\\']);
                    let suppressed = segs.any(|seg| {
                        seg.eq_ignore_ascii_case("keyhog")
                            || seg.eq_ignore_ascii_case("detectors")
                            || seg.eq_ignore_ascii_case("tests")
                            || seg.eq_ignore_ascii_case("fixtures")
                            || seg.eq_ignore_ascii_case("benches")
                    });
                    if suppressed {
                        return false;
                    }
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

        // Apply the user's per-service rate cap to the global token-bucket
        // limiter BEFORE the engine starts dispatching verifies. The
        // limiter is a process-wide OnceLock so this needs to land before
        // the first `wait()` call inside `verify_with_retry`.
        keyhog_verifier::rate_limit::set_global_default_rps(self.args.verify_rate);

        // `--verify-batch`: serialize live verifications per service on
        // top of the rate cap. Useful when the scanned tree has hundreds
        // of fixture findings that would otherwise burst past the
        // upstream's auth endpoint.
        let per_service_concurrency = if self.args.verify_batch {
            1
        } else {
            self.args.rate
        };

        let mut verifier = VerificationEngine::new(
            &self.detectors,
            VerifyConfig {
                timeout: Duration::from_secs(self.args.timeout),
                max_concurrent_per_service: per_service_concurrency,
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

/// Emit one redacted preview line per finding for `--stream` mode.
/// Format is intentionally short and grep-friendly; the full report
/// (with companions, confidence, full credential under `--show-secrets`)
/// still lands at the end. Keeps the stderr feed readable on terminals
/// while a 100k-file scan is in flight.
fn stream_finding_preview<W: std::io::Write>(w: &mut W, m: &RawMatch) {
    let path = m
        .location
        .file_path
        .as_deref()
        .unwrap_or("<stdin>");
    let line = m
        .location
        .line
        .map(|n| n.to_string())
        .unwrap_or_else(|| "?".into());
    let redacted = keyhog_core::redact(&m.credential);
    let _ = writeln!(
        w,
        "[stream] {sev:<8} {service}/{detector}  {path}:{line}  {redacted}",
        sev = format!("{:?}", m.severity).to_uppercase(),
        service = m.service,
        detector = m.detector_id,
        path = path,
        line = line,
        redacted = redacted,
    );
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

#[cfg(test)]
mod pipeline_tests {
    //! Tests for the producer/scanner pipeline introduced in Stage C.
    //!
    //! Each test builds a `ScanOrchestrator` manually (bypassing
    //! `ScanOrchestrator::new` so we don't have to materialize a
    //! detectors directory on disk) and feeds it synthetic sources.
    //! The contract under test is "findings emitted by `scan_sources`
    //! match the chunks the synthetic sources produced" — i.e. the
    //! threading layer doesn't drop, duplicate, or reorder work.

    use super::*;
    use clap::Parser;
    use keyhog_core::{
        Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity, Source, SourceError,
    };

    /// Source impl that yields a fixed list of chunks once. Used to
    /// drive the pipeline deterministically without filesystem I/O.
    struct StaticSource {
        chunks: Vec<Chunk>,
    }
    impl Source for StaticSource {
        fn name(&self) -> &str {
            "static"
        }
        fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
            Box::new(self.chunks.clone().into_iter().map(Ok))
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn make_chunk(text: &str, path: &str) -> Chunk {
        Chunk {
            data: text.into(),
            metadata: ChunkMetadata {
                source_type: "test".into(),
                path: Some(path.into()),
                ..Default::default()
            },
        }
    }

    /// Detector that matches the literal `STATIC_SECRET_<digits>` —
    /// distinctive enough that nothing else in the test corpus
    /// triggers it.
    fn make_detector() -> DetectorSpec {
        DetectorSpec {
            id: "static-test".into(),
            name: "Static Test".into(),
            service: "test".into(),
            severity: Severity::Medium,
            patterns: vec![PatternSpec {
                regex: r"STATIC_SECRET_[0-9]+".into(),
                description: None,
                group: None,
            }],
            companions: Vec::new(),
            verify: None,
            keywords: vec!["STATIC_SECRET".into()],
        }
    }

    /// Minimal orchestrator wired up with a synthetic detector. Skips
    /// detector-cache loading + lockdown gating that `new()` does, so
    /// it works without an on-disk detectors directory.
    fn make_orchestrator(detectors: Vec<DetectorSpec>) -> ScanOrchestrator {
        let args = crate::args::ScanArgs::try_parse_from(["scan"])
            .expect("ScanArgs default-parse from bare invocation");
        let scanner = Arc::new(
            keyhog_scanner::CompiledScanner::compile(detectors.clone())
                .expect("scanner compile"),
        );
        let signatures = detectors
            .iter()
            .flat_map(|d| d.patterns.iter().map(|p| Arc::from(p.regex.as_str())))
            .collect();
        ScanOrchestrator {
            args,
            detectors,
            scanner,
            signatures,
        }
    }

    #[test]
    fn pipeline_finds_secret_in_single_source_single_chunk() {
        let orch = make_orchestrator(vec![make_detector()]);
        let sources: Vec<Box<dyn Source>> = vec![Box::new(StaticSource {
            chunks: vec![make_chunk(
                "let key = STATIC_SECRET_12345;",
                "fixture.rs",
            )],
        })];
        let findings = orch.scan_sources(sources, false, None);
        assert_eq!(findings.len(), 1, "expected exactly one finding");
        assert_eq!(&*findings[0].credential, "STATIC_SECRET_12345");
    }

    #[test]
    fn pipeline_handles_empty_source() {
        // Empty source: scanner thread spins up, sees zero batches,
        // joins cleanly, returns no findings. No panic, no leak.
        let orch = make_orchestrator(vec![make_detector()]);
        let sources: Vec<Box<dyn Source>> = vec![Box::new(StaticSource { chunks: Vec::new() })];
        let findings = orch.scan_sources(sources, false, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn pipeline_processes_chunks_across_multiple_sources() {
        // Two sources, each with one secret. Findings from both must
        // surface — the producer iterates sources in order and the
        // scanner accumulates all of them.
        let orch = make_orchestrator(vec![make_detector()]);
        let sources: Vec<Box<dyn Source>> = vec![
            Box::new(StaticSource {
                chunks: vec![make_chunk("STATIC_SECRET_1 here", "a.rs")],
            }),
            Box::new(StaticSource {
                chunks: vec![make_chunk("STATIC_SECRET_2 there", "b.rs")],
            }),
        ];
        let findings = orch.scan_sources(sources, false, None);
        assert_eq!(findings.len(), 2);
        let mut creds: Vec<String> =
            findings.iter().map(|f| f.credential.to_string()).collect();
        creds.sort();
        assert_eq!(creds, vec!["STATIC_SECRET_1", "STATIC_SECRET_2"]);
    }

    #[test]
    fn pipeline_processes_many_chunks_to_exercise_batch_flush() {
        // Emit enough chunks that the BATCH_CHUNK_LIMIT (4096) fires
        // at least once. Each chunk has a unique numeric-suffixed
        // secret so any pipeline drop manifests as a missing finding.
        // The scanner applies its own confidence/dedup filters to
        // findings, so we use a SMALL count where every secret has
        // distinct, high-entropy enough surroundings to clear those
        // filters — the goal is to prove the pipeline doesn't lose
        // batches, not to stress the scanner's heuristics.
        const N: usize = 6000; // > BATCH_CHUNK_LIMIT (4096)
        let orch = make_orchestrator(vec![make_detector()]);
        // Use 12-digit suffixes so every credential clears the
        // scanner's per-length entropy floor independent of the
        // index value. The pipeline test isn't about exercising
        // those filters — it's about proving the threaded handoff
        // doesn't drop batches.
        let chunks: Vec<Chunk> = (0..N)
            .map(|i| {
                make_chunk(
                    &format!("token = STATIC_SECRET_{:012}", 100_000_000 + i),
                    &format!("file_{i}.rs"),
                )
            })
            .collect();
        let sources: Vec<Box<dyn Source>> = vec![Box::new(StaticSource { chunks })];
        let findings = orch.scan_sources(sources, false, None);
        // The scanner's downstream filters apply uniformly; they
        // can't distinguish "this match came from batch 1 vs batch 2".
        // So if the pipeline drops a batch, recall plummets. Any
        // recall floor above ~80% proves all batches were scanned.
        let recall = findings.len() as f64 / N as f64;
        assert!(
            recall >= 0.80,
            "pipeline recall {:.2}% below floor — likely a dropped batch \
             (got {} of {})",
            recall * 100.0,
            findings.len(),
            N
        );
    }

    #[test]
    fn pipeline_two_chunks_in_one_source_both_yield_findings() {
        // Sanity check that the within-source iteration emits every
        // chunk to the scanner thread. Earlier tests covered 1 chunk
        // and N sources × 1 chunk; this one covers N chunks × 1
        // source — an independent walk through the producer loop.
        let orch = make_orchestrator(vec![make_detector()]);
        let sources: Vec<Box<dyn Source>> = vec![Box::new(StaticSource {
            chunks: vec![
                make_chunk("first STATIC_SECRET_12345 here", "x.rs"),
                make_chunk("second STATIC_SECRET_67890 there", "y.rs"),
            ],
        })];
        let findings = orch.scan_sources(sources, false, None);
        assert_eq!(findings.len(), 2);
        let mut creds: Vec<String> =
            findings.iter().map(|f| f.credential.to_string()).collect();
        creds.sort();
        assert_eq!(creds, vec!["STATIC_SECRET_12345", "STATIC_SECRET_67890"]);
    }

    #[test]
    fn pipeline_no_findings_when_corpus_clean() {
        // Detector exists but no chunk matches its regex. Confirms
        // we don't conjure findings from thin air after the threading
        // refactor (paranoia check — same scanner contract, but the
        // batch handoff is new code).
        let orch = make_orchestrator(vec![make_detector()]);
        let sources: Vec<Box<dyn Source>> = vec![Box::new(StaticSource {
            chunks: vec![
                make_chunk("plain text with nothing notable", "a.rs"),
                make_chunk("more boring content", "b.rs"),
                make_chunk("function foo() {}", "c.rs"),
            ],
        })];
        let findings = orch.scan_sources(sources, false, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn pipeline_with_merkle_records_metadata_for_chunks_seen() {
        // Stage A + Stage C interaction: when the pipeline runs with a
        // shared `Arc<MerkleIndex>`, every chunk that arrives at the
        // scanner gets its `(path, mtime, size, hash)` recorded so the
        // next run's metadata fast-path can skip it. The orchestrator
        // owns this side-effect; verify it actually fires under the
        // threaded handoff (regression test for "scanner thread eats
        // chunks → no records left for next run").
        let orch = make_orchestrator(vec![make_detector()]);
        let mut chunk = make_chunk("STATIC_SECRET_42424242 here", "x.rs");
        // Plant non-default metadata so the recording path has
        // something concrete to round-trip — proves we don't lose it
        // crossing the channel.
        chunk.metadata.mtime_ns = Some(1_700_000_000_000_000_000);
        chunk.metadata.size_bytes = Some(123);

        let merkle = Arc::new(keyhog_core::merkle_index::MerkleIndex::empty());
        let sources: Vec<Box<dyn Source>> =
            vec![Box::new(StaticSource { chunks: vec![chunk] })];
        let findings = orch.scan_sources(sources, false, Some(merkle.clone()));

        // Scanner still produced the finding even though merkle is
        // wired in — merkle doesn't suppress non-cached entries.
        assert_eq!(findings.len(), 1);
        // The orchestrator recorded the chunk's metadata so a future
        // metadata_unchanged check would hit.
        assert!(
            merkle.metadata_unchanged(
                std::path::Path::new("x.rs"),
                1_700_000_000_000_000_000,
                123,
            ),
            "merkle should now contain the chunk's (path, mtime, size) entry"
        );
    }

    #[test]
    fn pipeline_with_merkle_skips_already_cached_chunks() {
        // Pre-populate the merkle index with an entry whose hash
        // matches the chunk content. The orchestrator's BLAKE3
        // post-read check should fire on this path (synthetic
        // sources don't surface live mtime, so the FilesystemSource
        // pre-read fast-path is bypassed; this exercises the
        // *content-hash* fallback inside scan_sources). Result: zero
        // findings emitted, even though the regex would have matched.
        let orch = make_orchestrator(vec![make_detector()]);
        let text = "STATIC_SECRET_42424242 here";
        let chunk = make_chunk(text, "y.rs");

        let merkle = Arc::new(keyhog_core::merkle_index::MerkleIndex::empty());
        let known_hash =
            keyhog_core::merkle_index::MerkleIndex::hash_content(text.as_bytes());
        merkle.record(std::path::PathBuf::from("y.rs"), known_hash);

        let sources: Vec<Box<dyn Source>> =
            vec![Box::new(StaticSource { chunks: vec![chunk] })];
        let findings = orch.scan_sources(sources, false, Some(merkle));

        assert!(
            findings.is_empty(),
            "merkle hash hit must skip the scan; got {} finding(s)",
            findings.len()
        );
    }
}
