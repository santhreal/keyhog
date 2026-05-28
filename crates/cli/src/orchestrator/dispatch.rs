//! Scan dispatch: producer/scanner pipeline and backend routing.

use super::reporting::stream_finding_preview;
use super::ScanOrchestrator;
use keyhog_core::{RawMatch, Source};
use std::sync::Arc;
use std::time::Instant;

/// Returns the backend the user explicitly forced via `KEYHOG_BACKEND`
/// or `--backend <name>`.
///
/// Thin re-export over `keyhog_scanner::hw_probe::forced_backend_from_env`
/// so the orchestrator and the scanner agree on the parsed override
/// set (including aliases like `literal-set` and `regex-nfa`). The
/// previous hand-rolled match here drifted from the scanner-side
/// match table; consolidating means new aliases only need to land in
/// one place.
pub fn explicit_backend_override() -> Option<keyhog_scanner::hw_probe::ScanBackend> {
    // Use the uncached parser. This is called once per scan startup, not
    // per-file, so the per-file cache that `forced_backend_from_env` shares
    // with `select_backend` is unnecessary here - and using it would have a
    // subtle side effect: integration tests that flip `KEYHOG_BACKEND`
    // between cases in a single test binary would all observe the first
    // value the cache locked in.
    keyhog_scanner::hw_probe::forced_backend_from_env_uncached()
}

impl ScanOrchestrator {
    pub(crate) fn scan_sources(
        &self,
        sources: Vec<Box<dyn Source>>,
        show_progress: bool,
        merkle: Option<Arc<keyhog_core::merkle_index::MerkleIndex>>,
    ) -> Vec<RawMatch> {
        use std::sync::atomic::Ordering;

        keyhog_sources::reset_skipped_over_max_size();

        let progress_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let progress_handle = if show_progress && !self.args.stream {
            let done = Arc::clone(&progress_done);
            let started_t = Instant::now();
            Some(std::thread::spawn(move || {
                super::reporting::progress_ticker(done, started_t)
            }))
        } else {
            None
        };

        let incremental_path = self.incremental_cache_path();

        const BATCH_CHUNK_LIMIT: usize = 4096;
        // Bytes budget per coalesced batch. Sized to match the
        // engine's `megascan_input_len()` (the pre-compiled
        // `RulePipeline` input cap) so the GPU dispatch never
        // auto-degrades to literal-set on oversized batches and we
        // capture every regex-NFA win. The engine sizes its cap by
        // VRAM (1 GiB on RTX 4090/5090, 256 MiB default), so the
        // orchestrator inherits that scaling automatically.
        //
        // Clamped so worst-case resident memory (`pipeline_depth ×
        // batch_bytes_budget`) stays under 1/8 of system RAM. On a
        // 16 GiB CI runner with a hypothetical 24+ GiB-VRAM card,
        // the engine's 1 GiB cap × depth 3 would otherwise float
        // toward 3 GiB resident which earlyoom flags before the
        // scanner gets useful work done. Safer to cap the batch
        // (still well over the dispatch breakeven for any card big
        // enough to want the bigger buffer) than to break the
        // memory-safety invariant.
        let batch_bytes_budget: usize = {
            let engine_cap = keyhog_scanner::engine::megascan_input_len();
            let total_ram_bytes = keyhog_scanner::hw_probe::probe_hardware()
                .total_memory_mb
                .map(|mb| (mb as usize) * 1024 * 1024)
                .unwrap_or(0);
            // Pipeline depth here is still being computed below, so
            // assume the max (3) for the headroom clamp. Worst case
            // is the orchestrator picking depth=1 and only using a
            // third of the headroom - safe in the under-direction.
            let headroom_cap = total_ram_bytes / (8 * 3);
            if headroom_cap == 0 {
                engine_cap
            } else {
                engine_cap.min(headroom_cap)
            }
        };
        // Producer/scanner pipeline depth. Each in-flight batch holds up
        // to `batch_bytes_budget` (256 MiB default, up to 1 GiB on
        // big-VRAM cards) of coalesced chunks, so the worst-case
        // resident memory floor is depth * batch_bytes_budget. Higher
        // depth lets the reader prefetch the next batch while the
        // scanner is still grinding the previous one - critical at
        // multi-TB scale where IO and GPU dispatch take similar wall-
        // clock time and depth=1 leaves whichever finishes first
        // idling. The previous fixed depth=1 fully serialized the two
        // sides; on a 96 GB workstation reading 5 TB of source, that
        // costs roughly half of total throughput.
        //
        // Adaptive by total system memory:
        //   - >= 32 GiB: depth 3 (~3x readahead).
        //   - >= 16 GiB: depth 2.
        //   -  < 16 GiB: depth 1 (the safe original behavior, since
        //                 jumping to a multi-batch peak on a small host
        //                 risks earlyoom).
        //
        // The peak resident is now `depth × batch_bytes_budget`, where
        // batch_bytes_budget is itself capped at RAM/24 above, so even
        // depth=3 cannot push us past 1/8 of system RAM.
        let pipeline_depth: usize = {
            let caps = keyhog_scanner::hw_probe::probe_hardware();
            match caps.total_memory_mb {
                Some(mb) if mb >= 32 * 1024 => 3,
                Some(mb) if mb >= 16 * 1024 => 2,
                _ => 1,
            }
        };

        let scanner = Arc::clone(&self.scanner);
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<keyhog_core::Chunk>>(pipeline_depth);

        tracing::debug!(
            target: "keyhog::routing",
            pipeline_depth,
            batch_bytes_budget,
            batch_chunk_limit = BATCH_CHUNK_LIMIT,
            "scan dispatch pipeline sized"
        );

        let stream = self.args.stream;

        let scanner_thread = std::thread::spawn(move || {
            let mut findings: Vec<RawMatch> = Vec::new();
            let mut stderr_writer = if stream {
                Some(std::io::LineWriter::new(std::io::stderr()))
            } else {
                None
            };

            let mut prev_phase2: Option<(std::thread::JoinHandle<Vec<Vec<RawMatch>>>, usize)> =
                None;

            let drain_prev =
                |prev: Option<(std::thread::JoinHandle<Vec<Vec<RawMatch>>>, usize)>,
                 findings: &mut Vec<RawMatch>,
                 stderr_writer: &mut Option<std::io::LineWriter<std::io::Stderr>>| {
                    if let Some((handle, scanned_count)) = prev {
                        let per_chunk = handle.join().unwrap_or_else(|e| {
                            std::panic::resume_unwind(e);
                        });
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
                };

            for batch in rx {
                if batch.is_empty() {
                    continue;
                }
                let scanned_count = batch.len();
                let explicit_backend = explicit_backend_override();
                match explicit_backend {
                    Some(keyhog_scanner::hw_probe::ScanBackend::Gpu) => {
                        let batch_bytes: u64 = batch.iter().map(|c| c.data.len() as u64).sum();
                        tracing::debug!(
                            target: "keyhog::routing",
                            backend = "gpu",
                            batch_bytes,
                            chunks = scanned_count,
                            "batch dispatched (explicit gpu, pipelined)",
                        );
                        match scanner.scan_coalesced_gpu_phase1(&batch) {
                            keyhog_scanner::GpuPhase1Output::Done(per_chunk) => {
                                drain_prev(prev_phase2.take(), &mut findings, &mut stderr_writer);
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
                            keyhog_scanner::GpuPhase1Output::Hits(per_chunk_hits) => {
                                drain_prev(prev_phase2.take(), &mut findings, &mut stderr_writer);
                                let scanner_clone = Arc::clone(&scanner);
                                let batch_owned = batch;
                                let handle = std::thread::spawn(move || {
                                    scanner_clone
                                        .scan_coalesced_gpu_phase2(&batch_owned, per_chunk_hits)
                                });
                                prev_phase2 = Some((handle, scanned_count));
                            }
                        }
                    }
                    Some(backend @ keyhog_scanner::hw_probe::ScanBackend::MegaScan) => {
                        drain_prev(prev_phase2.take(), &mut findings, &mut stderr_writer);
                        let batch_bytes: u64 = batch.iter().map(|c| c.data.len() as u64).sum();
                        tracing::debug!(
                            target: "keyhog::routing",
                            backend = backend.label(),
                            batch_bytes,
                            chunks = scanned_count,
                            "batch dispatched (explicit megascan, sync)",
                        );
                        let per_chunk = scanner.scan_chunks_with_backend(&batch, backend);
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
                    _ => {
                        drain_prev(prev_phase2.take(), &mut findings, &mut stderr_writer);
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
                }
            }
            drain_prev(prev_phase2.take(), &mut findings, &mut stderr_writer);
            findings
        });

        let mut batch: Vec<keyhog_core::Chunk> = Vec::with_capacity(BATCH_CHUNK_LIMIT);
        let mut batch_bytes: usize = 0;
        let mut skipped_unchanged = 0usize;
        let mut pipeline_alive = true;

        let send_batch =
            |batch: &mut Vec<keyhog_core::Chunk>, batch_bytes: &mut usize, alive: &mut bool| {
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
                        if batch.len() >= BATCH_CHUNK_LIMIT || batch_bytes >= batch_bytes_budget {
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
        drop(tx);
        let findings = scanner_thread.join().unwrap_or_else(|_| {
            tracing::error!("scanner thread panicked mid-scan; results are incomplete");
            crate::SCANNER_PANICKED.store(true, std::sync::atomic::Ordering::Relaxed);
            Vec::new()
        });

        progress_done.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = progress_handle {
            let _ = h.join();
        }

        if skipped_unchanged > 0 {
            tracing::info!(
                skipped = skipped_unchanged,
                "incremental scan: skipped unchanged files"
            );
        }
        if let (Some(idx), Some(path)) = (merkle.as_ref(), incremental_path.as_deref()) {
            let spec_hash = keyhog_core::merkle_index::compute_spec_hash(&self.detectors);
            if let Err(e) = idx.save_with_spec(path, &spec_hash) {
                tracing::warn!(error = %e, "failed to persist merkle index");
            }
        }

        findings
    }
}
