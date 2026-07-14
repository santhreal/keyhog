//! Built-in benchmark corpus and reporting for backend throughput checks.

use crate::orchestrator::ScanOrchestrator;
use anyhow::Result;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{probe_hardware, ScanBackend};
use std::time::Instant;

// Total ~96 MiB. `keyhog scan --benchmark` compares explicit backend rows;
// default auto-routing is driven by persisted calibration evidence, not this
// synthetic corpus size. Kept below the large-file scan ceiling so CI remains
// bounded.
const BENCHMARK_CHUNKS: usize = 768;
const BENCHMARK_CHUNK_BYTES: usize = 128 * 1024;

pub(crate) struct BackendBenchmark {
    pub backend: ScanBackend,
    pub mb_per_sec: f64,
    pub findings: usize,
    pub bytes_scanned: usize,
}

/// Format a one-line GPU summary string for hardware-aware reporting.
///
/// The shipping startup banner is built by the CLI banner writer
/// plus `keyhog_scanner::hw_probe::startup_banner` (see `orchestrator/run.rs`);
/// there is intentionally no second `startup_summary` banner builder here. This
/// helper renders just the GPU portion (adapter name + VRAM, or `unavailable`)
/// and is emitted as the `benchmark | gpu=…` header of `keyhog scan --benchmark`
/// (`orchestrator/run.rs`), so the operator can see which adapter produced the
/// GPU throughput row.
pub(crate) fn format_gpu_summary() -> String {
    let hw = probe_hardware();
    match (&hw.gpu_name, hw.gpu_vram_mb) {
        (Some(name), Some(vram_mb)) => format!("{} ({}GB)", name, (vram_mb / 1024).max(1)),
        (Some(name), None) => name.clone(),
        _ => "unavailable".to_string(),
    }
}

pub(crate) fn run_benchmark(orchestrator: &ScanOrchestrator) -> Result<Vec<BackendBenchmark>> {
    let corpus = build_benchmark_corpus();
    let total_bytes: usize = corpus.iter().map(|chunk| chunk.data.len()).sum();
    let hw = probe_hardware();
    let mut backends = vec![ScanBackend::CpuFallback];

    if hw.has_avx512 || hw.has_avx2 || hw.has_neon {
        backends.push(ScanBackend::SimdCpu);
    }
    backends.extend(
        orchestrator
            .scanner()
            .gpu_backend_candidates()
            .into_iter()
            .filter(|candidate| candidate.is_eligible())
            .map(|candidate| candidate.backend),
    );

    let mut results = Vec::new();
    for backend in backends {
        orchestrator.scanner().warm_backend(backend);
        let started = Instant::now();
        let findings = orchestrator
            .scanner()
            .scan_chunks_with_backend(&corpus, backend)
            .into_iter()
            .map(|matches| matches.len())
            .sum();
        let elapsed = started.elapsed().as_secs_f64().max(f64::EPSILON);
        results.push(BackendBenchmark {
            backend,
            mb_per_sec: (total_bytes as f64 / 1024.0 / 1024.0) / elapsed,
            findings,
            bytes_scanned: total_bytes,
        });
    }

    Ok(results)
}

fn build_benchmark_corpus() -> Vec<Chunk> {
    let mut chunks = Vec::with_capacity(BENCHMARK_CHUNKS);
    for index in 0..BENCHMARK_CHUNKS {
        let mut data = String::with_capacity(BENCHMARK_CHUNK_BYTES + 512);
        // Realistic source-code shape: short tokens, natural language
        // comments, low-entropy variable names. The previous fixture
        // used 36-char alphanumeric filler which triggered the entropy
        // detector on every line, making the benchmark dominated by
        // per-chunk extraction cost rather than the
        // literal-set-vs-Hyperscan crossover this is meant to measure.
        // The ~70-char average line below mirrors the line-length
        // distribution of typical TypeScript/Go/Rust source.
        let template = concat!(
            "// process inbound webhook from upstream provider\n",
            "fn handle_request(req: &Request) -> Result<Response, Error> {\n",
            "    let payload = serde_json::from_slice(&req.body)?;\n",
            "    log::info!(\"received webhook for tenant: {}\", payload.tenant_id);\n",
            "    let user = users.lookup(payload.user_id).await?;\n",
            "    if !user.has_capability(Capability::Webhook) {\n",
            "        return Ok(Response::forbidden());\n",
            "    }\n",
            "    let normalized = normalize(payload.event)?;\n",
            "    queue.publish(normalized).await?;\n",
            "    Ok(Response::ok())\n",
            "}\n\n",
        );
        while data.len() < BENCHMARK_CHUNK_BYTES {
            data.push_str(template);
        }

        let suffix = format!(
            "// configuration constants\n\
             export const GITHUB_TOKEN_{index} = \"ghp_ABCDEF1234567890ABCDEF1234567890AB\";\n\
             export const STRIPE_SECRET_{index} = \"sk_live_1234567890abcdefghijklmnopqrstuv\";\n\
             export const AWS_KEY_{index} = \"AKIA1234567890ABCD\";\n"
        );
        data.push_str(&suffix);

        chunks.push(Chunk {
            data: data.into(),
            metadata: ChunkMetadata {
                base_offset: 0,
                base_line: 0,
                source_type: "benchmark".into(),
                path: Some(format!("benchmark/corpus-{index}.txt").into()),
                commit: None,
                author: None,
                date: None,
                mtime_ns: None,
                size_bytes: None,
                decoded_span: None,
            },
        });
    }
    chunks
}
