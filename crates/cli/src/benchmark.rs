//! Built-in benchmark corpus and reporting for backend throughput checks.

use crate::orchestrator::ScanOrchestrator;
use anyhow::Result;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_profile::{decision_timer, Stage};
use keyhog_scanner::{probe_hardware, ScanBackend};

// Total ~96 MiB. `keyhog scan --benchmark` compares explicit backend rows;
// default auto-routing is driven by persisted calibration evidence, not this
// synthetic corpus size. Kept below the large-file scan ceiling so CI remains
// bounded.
const BENCHMARK_CHUNKS: usize = 768;
const BENCHMARK_CHUNK_BYTES: usize = 128 * 1024;

/// Stable source-code seed for the bounded synthetic throughput benchmark.
pub(crate) const BENCHMARK_SOURCE_TEMPLATE: &str = concat!(
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
        // The row's MB/s is a number this function consumes, so it takes the
        // profiler's decision timer rather than a private `Instant`: same clock,
        // and the interval also lands in the profile when one is running, so the
        // printed throughput and the profiled throughput cannot disagree.
        let timer = decision_timer(Stage::BackendDispatch);
        let findings = orchestrator
            .scanner()
            .scan_chunks_with_backend(&corpus, backend)?
            .into_iter()
            .map(|matches| matches.len())
            .sum();
        let elapsed = timer.finish().as_secs_f64().max(f64::EPSILON);
        results.push(BackendBenchmark {
            backend,
            mb_per_sec: (total_bytes as f64 / 1024.0 / 1024.0) / elapsed,
            findings,
            bytes_scanned: total_bytes,
        });
    }

    Ok(results)
}

pub(crate) fn build_benchmark_chunk(index: usize) -> Chunk {
    let mut data = String::with_capacity(BENCHMARK_CHUNK_BYTES + 512);
    // Realistic source-code shape: short tokens, natural language
    // comments, low-entropy variable names. The previous fixture
    // used 36-char alphanumeric filler which triggered the entropy
    // detector on every line, making the benchmark dominated by
    // per-chunk extraction cost rather than the
    // literal-set-vs-Hyperscan crossover this is meant to measure.
    // The ~70-char average line below mirrors the line-length
    // distribution of typical TypeScript/Go/Rust source.
    let template = BENCHMARK_SOURCE_TEMPLATE;
    while data.len() < BENCHMARK_CHUNK_BYTES {
        data.push_str(template);
    }

    let gh_token = format!("ghp_{}{}", "ABCDEF1234567890", "ABCDEF1234567890ABCD");
    let stripe_secret = format!("sk_live_{}{}", "1234567890", "abcdefghijklmnopqrstuv");
    let aws_key = format!("AKIA{}{}", "Q7XR2M4P", "LZ9WVB3T");
    let suffix = format!(
        "// configuration constants\n\
         export const GITHUB_TOKEN_{index} = \"{gh_token}\";\n\
         export const STRIPE_SECRET_{index} = \"{stripe_secret}\";\n\
         export const AWS_KEY_{index} = \"{aws_key}\";\n"
    );
    data.push_str(&suffix);

    Chunk {
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
    }
}

pub(crate) fn build_benchmark_corpus() -> Vec<Chunk> {
    let mut chunks = Vec::with_capacity(BENCHMARK_CHUNKS);
    for index in 0..BENCHMARK_CHUNKS {
        chunks.push(build_benchmark_chunk(index));
    }
    chunks
}
