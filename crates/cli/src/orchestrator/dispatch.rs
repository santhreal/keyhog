//! Scan dispatch: producer/scanner pipeline and backend routing.

use super::reporting::stream_finding_preview;
use super::ScanOrchestrator;
use keyhog_core::{RawMatch, Source};
use std::sync::Arc;
use std::time::Instant;

/// Returns the backend the user explicitly forced via `KEYHOG_BACKEND`
/// or `--backend <name>`.
pub fn explicit_backend_override() -> Option<keyhog_scanner::hw_probe::ScanBackend> {
    let raw = std::env::var("KEYHOG_BACKEND").ok()?;
    use keyhog_scanner::hw_probe::ScanBackend;
    match raw.trim().to_ascii_lowercase().as_str() {
        "gpu" | "gpu-zero-copy" | "literal-set" => Some(ScanBackend::Gpu),
        "mega-scan" | "gpu-mega-scan" | "regex-nfa" | "rule-pipeline" => {
            Some(ScanBackend::MegaScan)
        }
        "simd" | "simd-regex" | "hyperscan" => Some(ScanBackend::SimdCpu),
        "cpu" | "cpu-fallback" | "scalar" => Some(ScanBackend::CpuFallback),
        _ => None,
    }
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
        const BATCH_BYTES_BUDGET: usize = 256 * 1024 * 1024;
        const PIPELINE_DEPTH: usize = 1;

        let scanner = Arc::clone(&self.scanner);
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<keyhog_core::Chunk>>(PIPELINE_DEPTH);

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
