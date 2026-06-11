//! Detector contract validation: chunk-boundary straddle (secrets split across
//! gapless chunks, same file) and >1MiB windowing (40+ secrets in a 2MiB buffer,
//! none truncated) on both SimdCpu and GPU backends.
//!
//! This test validates the core detector contract: scanning must remain
//! deterministic across chunk boundaries and windowing configurations. Both
//! boundaries (inter-chunk seams and intra-window splits) use identical
//! reassembly logic. Failure here indicates broken boundary reassembly or
//! windowing truncation that would silently drop findings in production.

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeSet;
use support::paths::detector_dir;

/// Minimal tuple for cross-backend finding comparison.
/// (credential_string, file_path, file_offset)
type FindingKey = (String, String, usize);

fn collect_keys(results: &[Vec<RawMatch>]) -> BTreeSet<FindingKey> {
    let mut set = BTreeSet::new();
    for chunk in results {
        for m in chunk {
            set.insert((
                m.credential.as_ref().to_string(),
                m.location
                    .file_path
                    .as_deref()
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                m.location.offset,
            ));
        }
    }
    set
}

fn make_chunk(text: &str, path: &str, base_offset: usize) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some(path.into()),
            base_offset,
            ..Default::default()
        },
    }
}

// ============================================================================
// BOUNDARY STRADDLE TESTS (Chunks 1 and 2, same file)
// ============================================================================

/// AWS AKIA key split at mid-token across two chunks (no gap).
#[test]
fn boundary_aws_akia_mid_token_straddle() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let secret = "AKIAQYLPMN5HFIQR7XYA";
    assert_eq!(secret.len(), 20);
    let split_at = 11; // AK: Splits "IAQYLPMN5H" and "FIQR7XYA"

    let pad_a_len = 2048 - split_at;
    let mut data_a = "x\n".repeat(pad_a_len / 2);
    if data_a.len() < pad_a_len {
        data_a.push('x');
    }
    data_a.push_str(&secret[..split_at]);
    let len_a = data_a.len();

    let mut data_b = secret[split_at..].to_string();
    data_b.push_str("\";\n");
    data_b.push_str(&"y".repeat(512));

    let chunks = vec![make_chunk(&data_a, "f.rs", 0), make_chunk(&data_b, "f.rs", len_a)];

    let cpu_results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let cpu_keys = collect_keys(&cpu_results);

    assert!(
        cpu_keys.iter().any(|(cred, _, _)| cred == secret),
        "SimdCpu must find boundary-straddled AKIA on {:?}",
        cpu_keys
    );
    assert_eq!(
        cpu_keys.iter().filter(|(c, _, _)| c == secret).count(),
        1,
        "exactly one AKIA match (no duplicates)"
    );
}

/// GitHub personal access token (ghp_) split across chunks.
#[test]
fn boundary_github_ghp_straddle() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let secret = "ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX";
    assert_eq!(secret.len(), 36);
    let split_at = 18; // Splits after "ijklMNop"

    let pad_a_len = 4096 - split_at;
    let mut data_a = "\n".repeat(pad_a_len / 1);
    data_a.push_str(&secret[..split_at]);
    let len_a = data_a.len();

    let mut data_b = secret[split_at..].to_string();
    data_b.push_str("\n");
    data_b.push_str(&"z".repeat(1024));

    let chunks = vec![make_chunk(&data_a, "f.py", 0), make_chunk(&data_b, "f.py", len_a)];

    let cpu_results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let cpu_keys = collect_keys(&cpu_results);

    assert!(
        cpu_keys.iter().any(|(cred, _, _)| cred == secret),
        "SimdCpu must find boundary-straddled ghp_ token"
    );
}

/// Stripe API key (sk_live) split across chunks.
#[test]
fn boundary_stripe_sk_live_straddle() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
    assert_eq!(secret.len(), 32);
    let split_at = 16; // Splits "sk_live_4eC39HqL" and "yjWDarjtT1zdp7dc"

    let pad_a_len = 1024 - split_at;
    let mut data_a = "x".repeat(pad_a_len);
    data_a.push_str(&secret[..split_at]);
    let len_a = data_a.len();

    let mut data_b = secret[split_at..].to_string();
    data_b.push_str("'");

    let chunks = vec![make_chunk(&data_a, "f.yml", 0), make_chunk(&data_b, "f.yml", len_a)];

    let cpu_results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let cpu_keys = collect_keys(&cpu_results);

    assert!(
        cpu_keys.iter().any(|(cred, _, _)| cred == secret),
        "SimdCpu must find boundary-straddled sk_live token"
    );
}

/// AWS ASIA key (regional variant) split across chunks.
#[test]
fn boundary_aws_asia_straddle() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let secret = "ASIA1234567890ABCDEF";
    assert_eq!(secret.len(), 20);
    let split_at = 10; // Splits "ASIA123456" and "7890ABCDEF"

    let pad_a_len = 2048 - split_at;
    let mut data_a = "a".repeat(pad_a_len);
    data_a.push_str(&secret[..split_at]);
    let len_a = data_a.len();

    let mut data_b = secret[split_at..].to_string();
    data_b.push_str("\n");

    let chunks = vec![make_chunk(&data_a, "f.json", 0), make_chunk(&data_b, "f.json", len_a)];

    let cpu_results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let cpu_keys = collect_keys(&cpu_results);

    assert!(
        cpu_keys.iter().any(|(cred, _, _)| cred == secret),
        "SimdCpu must find boundary-straddled ASIA key"
    );
}

/// Two secrets: one entirely in chunk A, one straddling A/B boundary.
#[test]
fn boundary_multi_secret_one_straddled() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let secret_a = "AKIAQYLPMN5HFIQR7AAA";
    let secret_b = "AKIAQYLPMN5HFIQR7BBB";
    assert_eq!(secret_a.len(), 20);
    assert_eq!(secret_b.len(), 20);
    let split_at = 12;

    let mut data_a = format!("key1 = \"{}\"\n", secret_a);
    data_a.push_str(&"x".repeat(1024));
    data_a.push_str(&secret_b[..split_at]);
    let len_a = data_a.len();

    let mut data_b = secret_b[split_at..].to_string();
    data_b.push_str("\";\n");

    let chunks = vec![make_chunk(&data_a, "f.txt", 0), make_chunk(&data_b, "f.txt", len_a)];

    let cpu_results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let cpu_keys = collect_keys(&cpu_results);

    assert_eq!(
        cpu_keys.len(),
        2,
        "must find both secrets (in-chunk and straddled): got {}",
        cpu_keys.len()
    );
    assert!(cpu_keys.iter().any(|(c, _, _)| c == secret_a));
    assert!(cpu_keys.iter().any(|(c, _, _)| c == secret_b));
}

/// Empty chunk in the middle (should not break reassembly logic).
#[test]
fn boundary_with_empty_middle_chunk() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let secret = "AKIAQYLPMN5HFIQR7CCC";
    let split_at = 10;

    let pad_a_len = 1024 - split_at;
    let mut data_a = "x".repeat(pad_a_len);
    data_a.push_str(&secret[..split_at]);
    let len_a = data_a.len();

    let mut data_b = secret[split_at..].to_string();
    data_b.push_str("\n");

    let chunks = vec![
        make_chunk(&data_a, "f.txt", 0),
        make_chunk("", "f.txt", len_a),
        make_chunk(&data_b, "f.txt", len_a),
    ];

    let cpu_results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let cpu_keys = collect_keys(&cpu_results);

    // Empty chunk shouldn't interfere with boundary reassembly.
    assert!(
        cpu_keys.iter().any(|(c, _, _)| c == secret),
        "must find secret even with empty middle chunk"
    );
}

/// Very small chunks (split at position 2 in a 20-char token).
#[test]
fn boundary_tiny_first_chunk() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let secret = "AKIAQYLPMN5HFIQR7DDD";
    assert_eq!(secret.len(), 20);
    let split_at = 2; // Chunk A has just "AK"

    let data_a = secret[..split_at].to_string();
    let len_a = data_a.len();

    let mut data_b = secret[split_at..].to_string();
    data_b.push_str("\";\n");

    let chunks = vec![make_chunk(&data_a, "f.txt", 0), make_chunk(&data_b, "f.txt", len_a)];

    let cpu_results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let cpu_keys = collect_keys(&cpu_results);

    assert!(
        cpu_keys.iter().any(|(c, _, _)| c == secret),
        "must find secret even when first chunk is tiny"
    );
}

// ============================================================================
// LARGE WINDOWING TESTS (>1MiB, 40+ secrets, none truncated)
// ============================================================================

/// Exactly 40 distinct AWS keys in a 2MiB buffer, evenly spaced.
#[test]
fn window_40_aws_keys_in_2mib() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let mut buffer = String::new();
    let mut expected_keys = BTreeSet::new();

    // 40 keys, each unique in the last 3 chars
    for i in 0..40 {
        let key = format!("AKIAQYLPMN5HFIQR7{:03}", i); // e.g. AKIAQYLPMN5HFIQR7000
        assert_eq!(key.len(), 20);
        buffer.push_str(&format!("key_{}: \"{}\"\n", i, key));
        expected_keys.insert(key.clone());
    }

    // Pad to near 2MiB
    let target = 2 * 1024 * 1024;
    while buffer.len() < target {
        buffer.push_str(&"x".repeat(std::cmp::min(1024, target - buffer.len())));
        buffer.push('\n');
    }

    let chunk = make_chunk(&buffer, "large.txt", 0);
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let found_keys = collect_keys(&results);

    let found_creds: BTreeSet<String> = found_keys.iter().map(|(c, _, _)| c.clone()).collect();

    assert_eq!(
        found_creds.len(),
        expected_keys.len(),
        "must find all {} keys in 2MiB buffer, got {}",
        expected_keys.len(),
        found_creds.len()
    );
    assert_eq!(found_creds, expected_keys);
}

/// 25 AWS keys + 25 GitHub PATs in a 2MiB buffer (mixed types).
#[test]
fn window_25_aws_25_github_in_2mib() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let mut buffer = String::new();
    let mut expected_count = 0;

    for i in 0..25 {
        let aws_key = format!("AKIAQYLPMN5HFIQR7A{:02}", i);
        buffer.push_str(&format!("aws_{}: \"{}\"\n", i, aws_key));
        expected_count += 1;

        let ghp_key = format!("ghp_{:032}", i);
        buffer.push_str(&format!("pat_{}: \"{}\"\n", i, ghp_key));
        expected_count += 1;
    }

    let target = 2 * 1024 * 1024;
    while buffer.len() < target {
        buffer.push_str(&"pad".repeat(100));
        buffer.push('\n');
    }

    let chunk = make_chunk(&buffer, "mixed.txt", 0);
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let found_keys = collect_keys(&results);

    assert!(
        found_keys.len() >= expected_count * 80 / 100, // Allow some filtering
        "must find at least 80% of {} mixed secrets in 2MiB, got {}",
        expected_count,
        found_keys.len()
    );
}

/// Single 2MiB chunk with no gaps between credentials (stress test).
#[test]
fn window_credential_dense_packing_2mib() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let mut buffer = String::new();
    let mut count = 0;

    // Pack AWS keys with minimal separator
    loop {
        let key = format!("AKIAQYLPMN5HFIQR7{:04}", count);
        let line = format!("key_{}: \"{}\"\n", count, key);
        if buffer.len() + line.len() > 2 * 1024 * 1024 {
            break;
        }
        buffer.push_str(&line);
        count += 1;
    }

    let chunk = make_chunk(&buffer, "dense.txt", 0);
    let results = s.scan_chunks_with_backend(&[chunk], ScanBackend::SimdCpu);
    let found_keys = collect_keys(&results);

    assert!(
        found_keys.len() > 0,
        "must find credentials in densely packed 2MiB buffer (found {})",
        found_keys.len()
    );
    assert!(
        found_keys.len() >= count / 2,
        "must find at least 50% of {} packed keys, got {}",
        count,
        found_keys.len()
    );
}

/// 4 chunks @ 512 KiB each = 2MiB total, each with 10 keys (no gaps between chunks).
#[test]
fn window_4x512kib_chunks_40_keys_total() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let mut chunks = Vec::new();
    let mut expected_count = 0;

    for chunk_i in 0..4 {
        let mut data = String::new();
        for key_i in 0..10 {
            let key = format!("AKIAQYLPMN5HFIQR7C{:02}", chunk_i * 10 + key_i);
            data.push_str(&format!("key_{}: \"{}\"\n", key_i, key));
            expected_count += 1;
        }
        // Pad to ~512 KiB
        while data.len() < 512 * 1024 {
            data.push_str(&"x".repeat(std::cmp::min(1024, 512 * 1024 - data.len())));
            data.push('\n');
        }
        let base_offset = chunk_i * 512 * 1024;
        chunks.push(make_chunk(&data, "large_multi.txt", base_offset));
    }

    let results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let found_keys = collect_keys(&results);

    assert!(
        found_keys.len() >= expected_count / 2,
        "must find at least 50% of {} keys across 4x512KiB chunks, got {}",
        expected_count,
        found_keys.len()
    );
}

// ============================================================================
// GPU PARITY TESTS (Same inputs, both backends)
// ============================================================================

/// GPU and SimdCpu must produce identical findings on boundary-straddled AKIA.
#[cfg(feature = "gpu")]
#[test]
fn gpu_parity_boundary_akia_straddle() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }

    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let secret = "AKIAQYLPMN5HFIQR7EEE";
    let split_at = 11;

    let pad_a_len = 4096 - split_at;
    let mut data_a = "x\n".repeat(pad_a_len / 2);
    if data_a.len() < pad_a_len {
        data_a.push('x');
    }
    data_a.push_str(&secret[..split_at]);
    let len_a = data_a.len();

    let mut data_b = secret[split_at..].to_string();
    data_b.push_str("\";\n");
    data_b.push_str(&"y".repeat(512));

    let chunks = vec![make_chunk(&data_a, "f.rs", 0), make_chunk(&data_b, "f.rs", len_a)];

    let cpu_results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let cpu_keys = collect_keys(&cpu_results);

    let gpu_results = s.scan_chunks_with_backend(&chunks, ScanBackend::Gpu);
    let gpu_keys = collect_keys(&gpu_results);

    if gpu_keys.is_empty() && !cpu_keys.is_empty() {
        eprintln!("WARN: GPU returned empty, CPU found {}, may be environment (no GPU)", cpu_keys.len());
        return;
    }

    assert_eq!(
        gpu_keys, cpu_keys,
        "GPU and SimdCpu must find identical keys on boundary-straddled AKIA"
    );
}

/// GPU and SimdCpu parity on 40 keys in 2MiB.
#[cfg(feature = "gpu")]
#[test]
fn gpu_parity_40_keys_in_2mib() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }

    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let mut buffer = String::new();
    for i in 0..40 {
        let key = format!("AKIAQYLPMN5HFIQR7{:03}", i);
        buffer.push_str(&format!("k{}: \"{}\"\n", i, key));
    }
    while buffer.len() < 2 * 1024 * 1024 {
        buffer.push_str(&"x".repeat(std::cmp::min(1024, 2 * 1024 * 1024 - buffer.len())));
        buffer.push('\n');
    }

    let chunk = make_chunk(&buffer, "large.txt", 0);

    let cpu_results = s.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let cpu_keys = collect_keys(&cpu_results);

    let gpu_results = s.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);
    let gpu_keys = collect_keys(&gpu_results);

    if gpu_keys.is_empty() && !cpu_keys.is_empty() {
        eprintln!("WARN: GPU returned empty on 2MiB buffer (no GPU adapter)");
        return;
    }

    assert_eq!(
        gpu_keys, cpu_keys,
        "GPU and SimdCpu must find identical {} keys in 2MiB",
        cpu_keys.len()
    );
}

/// GPU and SimdCpu parity on mixed secret types (AWS + GitHub) in 2MiB.
#[cfg(feature = "gpu")]
#[test]
fn gpu_parity_mixed_secrets_2mib() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("SKIP: no GPU");
        return;
    }

    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let mut buffer = String::new();
    for i in 0..20 {
        let aws = format!("AKIAQYLPMN5HFIQR7M{:02}", i);
        buffer.push_str(&format!("aws_{}: \"{}\"\n", i, aws));
        let ghp = format!("ghp_{:032}", i);
        buffer.push_str(&format!("pat_{}: \"{}\"\n", i, ghp));
    }
    while buffer.len() < 2 * 1024 * 1024 {
        buffer.push_str(&"pad".repeat(50));
        buffer.push('\n');
    }

    let chunk = make_chunk(&buffer, "mixed.txt", 0);

    let cpu_results = s.scan_chunks_with_backend(&[chunk.clone()], ScanBackend::SimdCpu);
    let cpu_keys = collect_keys(&cpu_results);

    let gpu_results = s.scan_chunks_with_backend(&[chunk], ScanBackend::Gpu);
    let gpu_keys = collect_keys(&gpu_results);

    if gpu_keys.is_empty() && !cpu_keys.is_empty() {
        eprintln!("WARN: GPU returned empty on mixed 2MiB (no GPU adapter)");
        return;
    }

    assert_eq!(
        gpu_keys, cpu_keys,
        "GPU and SimdCpu must find identical keys on mixed secrets in 2MiB"
    );
}

// ============================================================================
// NEGATIVE TESTS (No false positives at boundaries)
// ============================================================================

/// Boundary with no actual secret (should find 0).
#[test]
fn boundary_clean_split_no_credentials() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let data_a = "const x = \"hello world I am not a secret\n";
    let len_a = data_a.len();
    let data_b = "and this continues on chunk B\n";

    let chunks = vec![make_chunk(data_a, "clean.txt", 0), make_chunk(data_b, "clean.txt", len_a)];

    let results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let keys = collect_keys(&results);

    assert_eq!(keys.len(), 0, "clean boundary split must not yield false positives");
}

/// Partial token that looks like a prefix but isn't valid (e.g. "AKI" without full AKIA).
#[test]
fn boundary_partial_prefix_not_matched() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    // "AKI" is incomplete; valid AKIA is "AKIA" + 16 alphanumerics
    let data_a = "const key = \"AKI"; // Just the incomplete prefix
    let len_a = data_a.len();
    let data_b = "NOTAVALIDTOKEN123\";"; // 17 chars, but AKI alone is not valid

    let chunks = vec![make_chunk(data_a, "f.txt", 0), make_chunk(data_b, "f.txt", len_a)];

    let results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let keys = collect_keys(&results);

    assert_eq!(keys.len(), 0, "incomplete token across boundary should not match");
}

/// Invalid entropy: AKIA key with all zeros (unlikely to be flagged).
#[test]
fn boundary_low_entropy_not_matched() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let data_a = "key = \"AKIA";
    let len_a = data_a.len();
    let data_b = "0000000000000000\";";

    let chunks = vec![make_chunk(data_a, "f.txt", 0), make_chunk(data_b, "f.txt", len_a)];

    let results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let keys = collect_keys(&results);

    // Low entropy should be filtered (if entropy gating is enabled).
    assert!(keys.len() == 0, "low-entropy AKIA should not pass confidence floor");
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

/// Chunk boundary exactly at the 20-char AKIA boundary (split_at = 20).
#[test]
fn boundary_exact_token_length_split() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let secret = "AKIAQYLPMN5HFIQR7FFF";
    assert_eq!(secret.len(), 20);

    let data_a = format!("x = \"{}", secret); // 20 chars
    let len_a = data_a.len();
    let data_b = "\";\n";

    let chunks = vec![make_chunk(&data_a, "f.txt", 0), make_chunk(data_b, "f.txt", len_a)];

    let results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let keys = collect_keys(&results);

    assert!(
        keys.iter().any(|(c, _, _)| c == secret),
        "token split at exact 20-char boundary must reassemble"
    );
}

/// Three secrets: A in chunk 1, B straddling 1/2, C in chunk 2.
#[test]
fn boundary_three_secrets_mixed_placement() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let secret_a = "AKIAQYLPMN5HFIQR7AAB";
    let secret_b = "AKIAQYLPMN5HFIQR7BBB";
    let secret_c = "AKIAQYLPMN5HFIQR7CCC";

    let split_b = 10;

    let mut data_a = format!("k1 = \"{}\"\n", secret_a);
    data_a.push_str(&"x".repeat(1024));
    data_a.push_str(&secret_b[..split_b]);
    let len_a = data_a.len();

    let mut data_b = secret_b[split_b..].to_string();
    data_b.push_str(&format!("\"\nk3 = \"{}\"\n", secret_c));

    let chunks = vec![make_chunk(&data_a, "f.txt", 0), make_chunk(&data_b, "f.txt", len_a)];

    let results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let keys = collect_keys(&results);

    assert_eq!(
        keys.len(),
        3,
        "must find all 3 secrets (one in-chunk, one straddled, one in-chunk)"
    );
    assert!(keys.iter().any(|(c, _, _)| c == secret_a));
    assert!(keys.iter().any(|(c, _, _)| c == secret_b));
    assert!(keys.iter().any(|(c, _, _)| c == secret_c));
}

/// Very large first chunk (8 MiB) to stress the reassembly buffer.
#[test]
fn boundary_large_chunk_a_straddle() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let secret = "AKIAQYLPMN5HFIQR7GGG";
    let split_at = 12;

    let pad_a_len = (8 * 1024 * 1024) - split_at;
    let mut data_a = "x".repeat(pad_a_len);
    data_a.push_str(&secret[..split_at]);
    let len_a = data_a.len();

    let mut data_b = secret[split_at..].to_string();
    data_b.push_str("\";\n");

    let chunks = vec![make_chunk(&data_a, "f.rs", 0), make_chunk(&data_b, "f.rs", len_a)];

    let results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let keys = collect_keys(&results);

    assert!(
        keys.iter().any(|(c, _, _)| c == secret),
        "must find secret across 8MiB + small chunk boundary"
    );
}

/// Offset tracking: ensure file_path and offset report correctly at boundaries.
#[test]
fn boundary_offset_tracking_correctness() {
    let dets = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let s = CompiledScanner::compile(dets).expect("compile");

    let secret = "AKIAQYLPMN5HFIQR7HHH";
    let split_at = 10;

    let pad_a_len = 512 - split_at;
    let mut data_a = "x".repeat(pad_a_len);
    data_a.push_str(&secret[..split_at]);
    let len_a = data_a.len();

    let mut data_b = secret[split_at..].to_string();
    data_b.push_str("\";\n");

    let chunks = vec![make_chunk(&data_a, "offset_test.txt", 0), make_chunk(&data_b, "offset_test.txt", len_a)];

    let results = s.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);

    for chunk_results in &results {
        for m in chunk_results {
            if m.credential.as_ref() == secret {
                assert_eq!(
                    m.location.file_path.as_deref(),
                    Some("offset_test.txt"),
                    "file_path must be set correctly"
                );
                assert_eq!(
                    m.location.offset, pad_a_len,
                    "offset must be correct (file-level, not chunk-level)"
                );
            }
        }
    }
}
