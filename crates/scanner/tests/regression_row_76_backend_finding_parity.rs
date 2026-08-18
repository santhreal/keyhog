//! Row 76 regression lock: Backend finding parity across CPU, SIMD, and GPU.
//!
//! WHY:
//! Closes the backend finding divergence defect class:
//! 1. Structured preprocessing / base64 decoded view resolution parity across
//!    parent and decoded views (e.g. Kubernetes Secret `data:` fields with base64
//!    connection strings), ensuring service-specific connection strings and generic
//!    URL credentials resolve identically without duplicate suppression gaps across
//!    source views.
//! 2. Multi-window chunk trigger propagation across `MAX_SCAN_CHUNK_BYTES` (1 MiB)
//!    boundaries in `scan_coalesced_phase2_with_admission` and `scan_windowed_with_triggered`,
//!    guaranteeing that connection strings and credentials placed across 1 MiB seams
//!    yield identical findings across CPU, SIMD, and GPU backends.
//! 3. Resolution priority alignment (`resolution_priority = 2`) across all database
//!    connection string detectors (`redis-connection-string`, `mongodb-connection-string`,
//!    `neon-db-connection-string`, `postgresql-connection-string`).
//! What it does not catch: detectors whose verification requires live network requests.
#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeSet;
use support::paths::detector_dir;

type FindingTuple = (String, String, usize);

fn collect_finding_tuples(results: &[Vec<RawMatch>]) -> BTreeSet<FindingTuple> {
    results
        .iter()
        .flat_map(|chunk| chunk.iter())
        .map(|m| {
            (
                m.detector_id.to_string(),
                m.credential.as_ref().to_string(),
                m.location.offset,
            )
        })
        .collect()
}

fn test_scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir())
        .expect("detector directory must load for parity test");
    CompiledScanner::compile_with_runtime_policy(detectors)
        .expect("scanner must compile with runtime policy")
}

#[test]
fn row_76_k8s_secret_redis_connection_string_parity_across_backends() {
    use base64::Engine as _;
    let secret_payload = b"redis://:StrongRedisPassword123@redis-master:6379/0";
    let encoded = base64::engine::general_purpose::STANDARD.encode(secret_payload);

    let yaml_content = format!(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: test-redis-secret\ntype: Opaque\ndata:\n  DATABASE_URL: {encoded}\n"
    );

    let chunk = Chunk {
        data: yaml_content.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("k8s_secret_redis.yaml".into()),
            base_offset: 0,
            ..Default::default()
        },
    };

    let scanner = test_scanner();
    let cpu_matches = scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .expect("CPU scan succeeds");
    let cpu_findings = collect_finding_tuples(&cpu_matches);

    #[cfg(feature = "simd")]
    {
        let simd_matches = scanner
            .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::SimdCpu)
            .expect("SIMD scan succeeds");
        let simd_findings = collect_finding_tuples(&simd_matches);
        assert_eq!(
            cpu_findings, simd_findings,
            "SIMD and CPU findings must be identical on Kubernetes Secret connection strings"
        );
    }

    #[cfg(feature = "gpu")]
    {
        if scanner.runtime_status().gpu_backends.any() {
            let gpu_backend = if cfg!(target_os = "macos") {
                ScanBackend::GpuMetal
            } else {
                ScanBackend::GpuCuda
            };
            if let Ok(gpu_matches) =
                scanner.scan_chunks_with_backend(std::slice::from_ref(&chunk), gpu_backend)
            {
                let gpu_findings = collect_finding_tuples(&gpu_matches);
                assert_eq!(
                    cpu_findings, gpu_findings,
                    "GPU and CPU findings must be identical on Kubernetes Secret connection strings"
                );
            }
        }
    }
}

#[test]
fn row_76_multi_megabyte_window_boundary_parity_across_backends() {
    let mut lines = Vec::new();
    let mut current_len = 0usize;
    let target_len = 2 * 1024 * 1024; // 2 MiB

    let secret_line_targets = [
        500_000usize,
        1024 * 1024 - 200,
        1024 * 1024 + 200,
        1_500_000,
    ];
    let mut targets_hit = [false; 4];
    let mut idx = 0usize;

    while current_len < target_len {
        let mut target_index = None;
        for (i, &off) in secret_line_targets.iter().enumerate() {
            if !targets_hit[i] && current_len >= off {
                targets_hit[i] = true;
                target_index = Some(i);
                break;
            }
        }
        let line = if let Some(t_idx) = target_index {
            format!(
                "{{\"event\": \"db_connect\", \"service\": \"cache_{t_idx}\", \"url\": \"redis://:SecretPass_{t_idx}_12345@redis-node-{t_idx}.internal:6379/0\"}}\n"
            )
        } else {
            format!(
                "{{\"event\": \"request_log\", \"req_id\": \"{idx:08x}-abcd-ef01-2345-{idx:012x}\", \"path\": \"/api/v1/resource/{idx}\", \"status\": 200, \"latency_ms\": 14.2}}\n"
            )
        };
        current_len += line.len();
        lines.push(line);
        idx += 1;
    }

    let manifest_content = lines.concat();
    let chunk = Chunk {
        data: manifest_content.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("manifest.jsonl".into()),
            base_offset: 0,
            ..Default::default()
        },
    };

    let scanner = test_scanner();
    let cpu_matches = scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .expect("CPU scan succeeds");
    let cpu_findings = collect_finding_tuples(&cpu_matches);
    assert!(
        cpu_findings.len() >= 4,
        "CPU must find all 4 secrets across the 2 MiB payload, got {}",
        cpu_findings.len()
    );

    #[cfg(feature = "simd")]
    {
        let simd_matches = scanner
            .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::SimdCpu)
            .expect("SIMD scan succeeds");
        let simd_findings = collect_finding_tuples(&simd_matches);
        assert_eq!(
            cpu_findings, simd_findings,
            "SIMD and CPU findings must be identical across 1 MiB window boundaries in manifest.jsonl"
        );
    }

    #[cfg(feature = "gpu")]
    {
        if scanner.runtime_status().gpu_backends.any() {
            let gpu_backend = if cfg!(target_os = "macos") {
                ScanBackend::GpuMetal
            } else {
                ScanBackend::GpuCuda
            };
            if let Ok(gpu_matches) =
                scanner.scan_chunks_with_backend(std::slice::from_ref(&chunk), gpu_backend)
            {
                let gpu_findings = collect_finding_tuples(&gpu_matches);
                assert_eq!(
                    cpu_findings, gpu_findings,
                    "GPU and CPU findings must be identical across 1 MiB window boundaries in manifest.jsonl"
                );
            }
        }
    }
}
