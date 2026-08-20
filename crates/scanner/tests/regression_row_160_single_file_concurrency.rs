//! WHY: Closes the defect class where single large file scanning was serialized
//! across cores or produced non-deterministic findings and missed credentials at
//! chunk seam boundaries (Row 160).
//!
//! What this does NOT catch: OS-level kernel mmap page eviction under memory exhaustion.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::pipeline::{
    compute_line_offsets, deduplicate_partition_matches, partition_chunk,
    partition_chunk_for_workers, scan_chunk_partitioned,
};
use keyhog_scanner::testing::{
    partition_chunk as testing_partition_chunk,
    partition_chunk_for_workers as testing_partition_for_workers,
};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

fn sample_scanner() -> CompiledScanner {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");

    let detectors = keyhog_core::load_detectors(&d).expect("must load embedded detector corpus");
    CompiledScanner::compile(detectors).expect("must compile scanner")
}

#[test]
fn row_160_large_chunk_subdivision_preserves_metadata_and_lines() {
    let lines: Vec<String> = (0..5000).map(|i| format!("line_{i}: value_{i}")).collect();
    let body = lines.join("\n");
    let base_offset = 100_000usize;
    let base_line = 500usize;

    let chunk = Chunk {
        data: body.clone().into(),
        metadata: ChunkMetadata {
            path: Some("src/large_file.txt".into()),
            source_type: "filesystem/windowed".into(),
            base_offset,
            base_line,
            commit: None,
            author: None,
            date: None,
            mtime_ns: Some(1_700_000_000),
            size_bytes: Some(body.len() as u64),
            decoded_span: None,
        },
    };

    let target_window = 16 * 1024;
    let overlap = 4 * 1024;
    let sub_chunks = partition_chunk(&chunk, target_window, overlap);

    assert!(
        sub_chunks.len() > 1,
        "must partition large chunk into multiple sub-chunks"
    );

    let line_offsets = compute_line_offsets(&body);
    for sub in &sub_chunks {
        assert_eq!(sub.metadata.path.as_deref(), Some("src/large_file.txt"));
        assert_eq!(sub.metadata.source_type.as_ref(), "filesystem/windowed");
        assert_eq!(sub.metadata.mtime_ns, Some(1_700_000_000));
        assert!(sub.metadata.base_offset >= base_offset);
        assert!(sub.metadata.base_line >= base_line);

        let local_start = sub.metadata.base_offset - base_offset;
        let expected_newlines = line_offsets
            .partition_point(|&lo| lo <= local_start)
            .saturating_sub(1);
        assert_eq!(
            sub.metadata.base_line,
            base_line + expected_newlines,
            "base_line must match exact newline count preceding sub-chunk start"
        );
    }
}

#[test]
fn row_160_partition_for_workers_scales_and_bounds() {
    let chunk_size = 512 * 1024;
    let body = "A".repeat(chunk_size);
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata::default(),
    };

    // 1 worker should return single chunk
    let single = partition_chunk_for_workers(&chunk, 1, 64 * 1024, 16 * 1024);
    assert_eq!(single.len(), 1);

    // 4 workers should yield partitions
    let four = partition_chunk_for_workers(&chunk, 4, 64 * 1024, 16 * 1024);
    assert!(
        four.len() >= 4,
        "must partition for 4 workers, got {}",
        four.len()
    );

    // 8 workers should yield more partitions
    let eight = partition_chunk_for_workers(&chunk, 8, 32 * 1024, 8 * 1024);
    assert!(
        eight.len() >= 8,
        "must partition for 8 workers, got {}",
        eight.len()
    );
}

#[test]
fn row_160_seam_straddling_secret_detected_across_boundaries() {
    let scanner = sample_scanner();
    let secret = concat!("AK", "IAQYLPMN5HFIQR7XYZ");

    let pad_before = "x\n".repeat(128 * 1024);
    let pad_after = "y\n".repeat(128 * 1024);

    // Embed the secret precisely where a window boundary would fall
    let mut full_text = pad_before.clone();
    let _secret_start = full_text.len();
    full_text.push_str(secret);
    full_text.push_str(";\n");
    full_text.push_str(&pad_after);

    let chunk = Chunk {
        data: full_text.into(),
        metadata: ChunkMetadata {
            path: Some("config/secrets.env".into()),
            source_type: "filesystem/windowed".into(),
            base_offset: 0,
            base_line: 1,
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
            decoded_span: None,
        },
    };

    // Sequential scan
    let seq_matches = scanner
        .scan_with_backend(&chunk, keyhog_scanner::ScanBackend::CpuFallback)
        .expect("sequential scan must succeed");

    // Partitioned scan with 4 workers
    let par_matches = scan_chunk_partitioned(
        &scanner,
        &chunk,
        keyhog_scanner::ScanBackend::CpuFallback,
        4,
    )
    .expect("partitioned scan must succeed");

    assert!(
        !seq_matches.is_empty(),
        "sequential scan must detect secret"
    );
    assert!(
        !par_matches.is_empty(),
        "partitioned parallel scan must detect secret"
    );

    let seq_found = seq_matches.iter().any(|m| m.credential.as_str() == secret);
    let par_found = par_matches.iter().any(|m| m.credential.as_str() == secret);

    assert!(seq_found, "secret must be found in sequential scan");
    assert!(
        par_found,
        "secret must be found across partitioned chunk seam"
    );

    // Parity: matches must be identical
    assert_eq!(seq_matches.len(), par_matches.len(), "finding count parity");
    for (seq_m, par_m) in seq_matches.iter().zip(par_matches.iter()) {
        assert_eq!(seq_m.detector_id, par_m.detector_id);
        assert_eq!(seq_m.credential.as_str(), par_m.credential.as_str());
        assert_eq!(seq_m.location.offset, par_m.location.offset);
        assert_eq!(seq_m.location.line, par_m.location.line);
    }
}

#[test]
fn row_160_parallel_scan_parity_and_determinism() {
    let scanner = sample_scanner();

    let mut body = String::new();
    body.push_str("// Header comments and setup\n");
    for i in 0..6000 {
        if i % 1000 == 500 {
            body.push_str(&format!("aws_key_{i} = \"AKIAQYLPMN5HFIQR{i:04}\";\n"));
        } else {
            body.push_str(&format!(
                "const CONFIG_ENTRY_{i}: &str = \"standard_non_secret_value_{i}\";\n"
            ));
        }
    }

    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            path: Some("src/services/auth.rs".into()),
            source_type: "filesystem/windowed".into(),
            base_offset: 2048,
            base_line: 10,
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
            decoded_span: None,
        },
    };

    let baseline = scanner
        .scan_with_backend(&chunk, keyhog_scanner::ScanBackend::CpuFallback)
        .expect("baseline scan");

    for worker_count in [2, 4, 8, 16] {
        let parallel = scanner
            .scan_chunk_partitioned(
                &chunk,
                keyhog_scanner::ScanBackend::CpuFallback,
                worker_count,
            )
            .expect("partitioned scan");

        assert_eq!(
            baseline.len(),
            parallel.len(),
            "worker_count {worker_count} match count parity"
        );

        for (b, p) in baseline.iter().zip(parallel.iter()) {
            assert_eq!(b.detector_id, p.detector_id, "detector id parity");
            assert_eq!(
                b.credential.as_str(),
                p.credential.as_str(),
                "credential parity"
            );
            assert_eq!(b.location.offset, p.location.offset, "offset parity");
            assert_eq!(b.location.line, p.location.line, "line parity");
        }
    }
}

#[test]
fn row_160_adversarial_multibyte_utf8_boundary_alignment() {
    // String with 3-byte and 4-byte UTF-8 codepoints
    let multibyte_block = "🦀 🌲 🌟 🔑 🚀 — \u{200B}\u{FEFF} ".repeat(2000);
    let chunk = Chunk {
        data: multibyte_block.into(),
        metadata: ChunkMetadata::default(),
    };

    // Subdivide with small window sizes to force boundaries near multibyte sequences
    for window_size in [128, 256, 512, 1024] {
        let sub_chunks = testing_partition_chunk(&chunk, window_size, window_size / 2);
        for sub in &sub_chunks {
            // Must be valid UTF-8 string without panics or corrupt boundaries
            assert!(!sub.data.is_empty());
            assert!(std::str::from_utf8(sub.data.as_bytes()).is_ok());
        }
    }
}

#[test]
fn row_160_empty_and_small_chunk_no_op_invariants() {
    let empty_chunk = Chunk {
        data: "".into(),
        metadata: ChunkMetadata::default(),
    };
    assert_eq!(partition_chunk(&empty_chunk, 1024, 256).len(), 1);

    let small_chunk = Chunk {
        data: "small text".into(),
        metadata: ChunkMetadata::default(),
    };
    assert_eq!(partition_chunk(&small_chunk, 1024, 256).len(), 1);
    assert_eq!(
        testing_partition_for_workers(&small_chunk, 8, 1024, 256).len(),
        1
    );
}

#[test]
fn row_160_deduplicate_partition_matches_orders_and_dedups() {
    use keyhog_core::{CredentialHash, EvidenceVerdict, MatchLocation, RawMatch, Severity};
    let make_match = |offset: usize, line: usize, secret: &str| RawMatch {
        detector_id: "aws-access-key".into(),
        detector_name: "AWS Access Key".into(),
        service: "aws".into(),
        severity: Severity::High,
        credential: secret.into(),
        credential_hash: CredentialHash::ZERO,
        companions: std::collections::HashMap::new(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some("file.txt".into()),
            line: Some(line),
            offset,
            commit: None,
            author: None,
            date: None,
        },
        entropy: Some(4.2),
        confidence: Some(0.9),
        evidence: EvidenceVerdict::review_unattributed(),
    };

    let m1 = make_match(100, 10, "AKIAQYLPMN5HFIQR0001");
    let m2 = make_match(100, 10, "AKIAQYLPMN5HFIQR0001"); // duplicate
    let m3 = make_match(200, 20, "AKIAQYLPMN5HFIQR0002");
    let m0 = make_match(50, 5, "AKIAQYLPMN5HFIQR0000"); // earlier offset

    // Shuffled input order
    let deduped =
        deduplicate_partition_matches(vec![m3.clone(), m1.clone(), m2.clone(), m0.clone()]);
    assert_eq!(deduped.len(), 3, "must deduplicate identical finding");
    assert_eq!(deduped[0].location.offset, 50);
    assert_eq!(deduped[1].location.offset, 100);
    assert_eq!(deduped[2].location.offset, 200);
}
#[test]
fn row_160_partition_bounds_prevent_triple_scanning() {
    let chunk_size = 2 * 1024 * 1024;
    let body = "A".repeat(chunk_size);
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata::default(),
    };

    for worker_count in [2, 4, 8, 16, 32, 64] {
        let partitions = partition_chunk_for_workers(
            &chunk,
            worker_count,
            keyhog_scanner::pipeline::DEFAULT_MIN_PARTITION_CHUNK_BYTES,
            keyhog_scanner::pipeline::DEFAULT_PARTITION_OVERLAP_BYTES,
        );
        // Verify that for all partitions k and k+2, partition k end <= partition k+2 start
        // proving no byte is scanned by 3 or more workers.
        for i in 0..partitions.len().saturating_sub(2) {
            let p0_end = partitions[i].metadata.base_offset + partitions[i].data.len();
            let p2_start = partitions[i + 2].metadata.base_offset;
            assert!(
                p0_end <= p2_start,
                "worker_count {worker_count}: partition {i} end ({p0_end}) must not overlap partition {} start ({p2_start})",
                i + 2
            );
        }
    }
}

#[test]
fn row_160_subchunk_metadata_clears_decoded_span_and_updates_size() {
    let body = "A\n".repeat(200_000);
    let chunk = Chunk {
        data: body.clone().into(),
        metadata: ChunkMetadata {
            path: Some("file.bin".into()),
            source_type: "filesystem".into(),
            base_offset: 1000,
            base_line: 50,
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: Some(body.len() as u64),
            decoded_span: Some((10, 500)),
        },
    };
    let partitions = partition_chunk(&chunk, 64 * 1024, 16 * 1024);
    assert!(partitions.len() > 1);
    for p in &partitions {
        assert_eq!(p.metadata.size_bytes, Some(p.data.len() as u64));
        assert_eq!(p.metadata.decoded_span, None);
    }
}
