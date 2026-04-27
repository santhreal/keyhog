//! Built-in benchmark corpus and reporting for backend throughput checks.

use crate::orchestrator::ScanOrchestrator;
use anyhow::Result;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{probe_hardware, ScanBackend};
use std::time::Instant;

// Total ≈ 96 MiB. Above the 64 MiB GPU_MIN_BYTES routing threshold so the
// `keyhog scan --benchmark` results compare GPU and SimdCpu under conditions
// where auto-routing would actually pick GPU. Below the 256 MiB
// GPU_BYTES_BREAKEVEN_SOLO cap to keep CI run-time reasonable.
const BENCHMARK_CHUNKS: usize = 768;
const BENCHMARK_CHUNK_BYTES: usize = 128 * 1024;

pub struct BackendBenchmark {
    pub backend: ScanBackend,
    pub mb_per_sec: f64,
    pub findings: usize,
    pub bytes_scanned: usize,
}

pub fn startup_summary(detector_count: usize, backend_label: &str) -> String {
    let gpu = format_gpu_summary();
    format!(
        "KeyHog v{} | GPU: {} | Backend: {} | {} detectors",
        env!("CARGO_PKG_VERSION"),
        gpu,
        backend_label,
        detector_count
    )
}

pub fn format_gpu_summary() -> String {
    let hw = probe_hardware();
    match (&hw.gpu_name, hw.gpu_vram_mb) {
        (Some(name), Some(vram_mb)) => format!("{} ({}GB)", name, (vram_mb / 1024).max(1)),
        (Some(name), None) => name.clone(),
        _ => "unavailable".to_string(),
    }
}

pub fn run_benchmark(orchestrator: &ScanOrchestrator) -> Result<Vec<BackendBenchmark>> {
    let corpus = build_benchmark_corpus();
    let total_bytes: usize = corpus.iter().map(|chunk| chunk.data.len()).sum();
    let hw = probe_hardware();
    let mut backends = vec![ScanBackend::CpuFallback];

    if hw.has_avx512 || hw.has_avx2 || hw.has_neon {
        backends.push(ScanBackend::SimdCpu);
    }
    if hw.gpu_available {
        backends.push(ScanBackend::Gpu);
    }

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
        while data.len() < BENCHMARK_CHUNK_BYTES {
            data.push_str("const filler = \"abcdefghijklmnopqrstuvwxyz0123456789\";\n");
            data.push_str("let config_value = \"no_secret_here_but_realistic_code_shape\";\n");
        }

        let suffix = format!(
            "export const GITHUB_TOKEN_{index} = \"ghp_ABCDEF1234567890ABCDEF1234567890AB\";\n\
             export const STRIPE_SECRET_{index} = \"sk_live_1234567890abcdefghijklmnopqrstuv\";\n\
             export const AWS_KEY_{index} = \"AKIA1234567890ABCD\";\n"
        );
        data.push_str(&suffix);

        chunks.push(Chunk {
            data,
            metadata: ChunkMetadata {
                source_type: "benchmark".to_string(),
                path: Some(format!("benchmark/corpus-{index}.txt")),
                commit: None,
                author: None,
                date: None,
            },
        });
    }
    chunks
}
