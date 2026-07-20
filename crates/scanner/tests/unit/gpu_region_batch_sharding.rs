use super::*;
#[cfg(feature = "simd")]
use hyperscan::{Block as BlockMode, BlockDatabase, Builder, Matching, Pattern, PatternFlags};

#[cfg(feature = "simd")]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Hit {
    chunk: usize,
    start: usize,
    end: usize,
}

fn chunk_with_hits(len: usize, uppercase: bool) -> keyhog_core::Chunk {
    assert!(len >= 16);
    let mut bytes = vec![b'x'; len];
    let token = if uppercase { b"SECRET" } else { b"secret" };
    bytes[1..7].copy_from_slice(token);
    bytes[len - 7..len - 1].copy_from_slice(token);
    keyhog_core::Chunk::from(String::from_utf8(bytes).expect("ASCII fixture"))
}

#[cfg(feature = "simd")]
fn cpu_hits(chunks: &[keyhog_core::Chunk]) -> Vec<Hit> {
    let regex = regex::bytes::Regex::new("(?i)secret").expect("CPU regex");
    chunks
        .iter()
        .enumerate()
        .flat_map(|(chunk, value)| {
            regex
                .find_iter(value.data.as_bytes())
                .map(move |found| Hit {
                    chunk,
                    start: found.start(),
                    end: found.end(),
                })
        })
        .collect()
}

#[cfg(feature = "simd")]
fn hyperscan_hits(chunks: &[keyhog_core::Chunk]) -> Vec<Hit> {
    let flags = PatternFlags::CASELESS | PatternFlags::SOM_LEFTMOST;
    let pattern = Pattern::with_flags("secret", flags).expect("Hyperscan pattern");
    let database: BlockDatabase = Builder::build::<BlockMode>(&pattern).expect("Hyperscan DB");
    let scratch = database.alloc_scratch().expect("Hyperscan scratch");
    let mut hits = Vec::new();
    for (chunk, value) in chunks.iter().enumerate() {
        database
            .scan(
                value.data.as_bytes(),
                &scratch,
                |_id, start, end, _flags| {
                    hits.push(Hit {
                        chunk,
                        start: start as usize,
                        end: end as usize,
                    });
                    Matching::Continue
                },
            )
            .expect("Hyperscan scan");
    }
    hits
}

#[cfg(feature = "simd")]
fn sharded_gpu_semantics_hits(
    chunks: &[keyhog_core::Chunk],
    byte_limit: usize,
) -> (Vec<Hit>, RegionPresenceBatchSummary, Vec<&'static str>) {
    let regex = regex::bytes::Regex::new("(?i)secret").expect("case-insensitive GPU oracle");
    let mut hits = Vec::new();
    let mut backend_ids = Vec::new();
    let selected_backend = "gpu-cuda";
    let summary = for_each_region_presence_batch_with_limit(
        chunks,
        byte_limit,
        |haystack, region_starts, _mode, shard| {
            backend_ids.push(selected_backend);
            assert!(haystack.len() <= byte_limit);
            assert_eq!(region_starts.len(), shard.chunks.len());
            for (row, &start) in region_starts.iter().enumerate() {
                let start = start as usize;
                let end = region_starts
                    .get(row + 1)
                    .map_or(haystack.len(), |next| *next as usize - 1);
                for found in regex.find_iter(&haystack[start..end]) {
                    hits.push(Hit {
                        chunk: shard.chunks.start + row,
                        start: found.start(),
                        end: found.end(),
                    });
                }
            }
            Ok(())
        },
    )
    .expect("bounded sharded GPU input");
    (hits, summary, backend_ids)
}

#[cfg(feature = "simd")]
fn assert_backend_parity(chunks: &[keyhog_core::Chunk], byte_limit: usize, dispatches: usize) {
    let cpu = cpu_hits(chunks);
    let hyperscan = hyperscan_hits(chunks);
    let (gpu, summary, backend_ids) = sharded_gpu_semantics_hits(chunks, byte_limit);

    assert_eq!(hyperscan, cpu, "Hyperscan must match the CPU oracle");
    assert_eq!(gpu, cpu, "sharded GPU rows changed order or multiplicity");
    assert_eq!(summary.dispatches, dispatches);
    assert!(summary.max_dispatch_bytes <= byte_limit);
    assert_eq!(backend_ids, vec!["gpu-cuda"; dispatches]);
}

fn canonicalize_production_results(results: &mut [Vec<keyhog_core::RawMatch>]) {
    for row in results {
        row.sort_unstable();
    }
}

#[test]
fn single_chunk_keeps_the_borrowed_raw_fast_path_regardless_of_case() {
    let chunks = [chunk_with_hits(32, true)];
    let source = chunks[0].data.as_bytes().as_ptr();
    let mut observed = std::ptr::null();
    let summary =
        for_each_region_presence_batch_with_limit(&chunks, 64, |haystack, starts, mode, shard| {
            observed = haystack.as_ptr();
            assert_eq!(starts, &[0]);
            assert_eq!(mode, RegionPresenceBatchMode::BorrowedSingleChunk);
            assert_eq!(shard.chunks, 0..1);
            Ok(())
        })
        .expect("borrowed bounded batch");

    assert_eq!(observed, source);
    assert_eq!(summary.dispatches, 1);
    assert_eq!(summary.mode, RegionPresenceBatchMode::BorrowedSingleChunk);
}

#[test]
fn backend_limits_keep_wgpu_inside_its_portable_grid() {
    assert_eq!(
        region_presence_batch_byte_limit("wgpu"),
        WGPU_BYTE_SCAN_DISPATCH_LIMIT
    );
    assert_eq!(
        region_presence_batch_byte_limit("cuda"),
        REGION_PRESENCE_BATCH_BYTE_LIMIT.min(crate::gpu_input_budget::gpu_batch_input_limit())
    );
    assert_eq!(WGPU_BYTE_SCAN_DISPATCH_LIMIT, 8_388_480);
    assert_eq!(
        region_presence_batch_byte_limit_for_input_budget("cuda", 128 * 1024 * 1024),
        128 * 1024 * 1024,
        "CUDA dispatches must honor the live low-VRAM batch budget below VYRE's hard ceiling"
    );
    assert_eq!(
        region_presence_batch_byte_limit_for_input_budget("wgpu", 128 * 1024 * 1024),
        WGPU_BYTE_SCAN_DISPATCH_LIMIT,
        "WGPU's portable grid ceiling remains stricter than the low-VRAM budget"
    );

    let exact = [
        WGPU_BYTE_SCAN_DISPATCH_LIMIT / 2,
        WGPU_BYTE_SCAN_DISPATCH_LIMIT / 2 - 1,
    ];
    let exact: Vec<_> = region_presence_shards_with_limit(
        exact.len(),
        |index| exact[index],
        WGPU_BYTE_SCAN_DISPATCH_LIMIT,
    )
    .expect("exact WGPU grid limit")
    .collect::<Result<_, _>>()
    .expect("exact WGPU grid limit must fit one dispatch");
    assert_eq!(exact.len(), 1);
    assert_eq!(exact[0].coalesced_bytes, WGPU_BYTE_SCAN_DISPATCH_LIMIT);

    let plus_one = [
        WGPU_BYTE_SCAN_DISPATCH_LIMIT / 2,
        WGPU_BYTE_SCAN_DISPATCH_LIMIT / 2,
    ];
    let plus_one: Vec<_> = region_presence_shards_with_limit(
        plus_one.len(),
        |index| plus_one[index],
        WGPU_BYTE_SCAN_DISPATCH_LIMIT,
    )
    .expect("WGPU plus-one shard iterator")
    .collect::<Result<_, _>>()
    .expect("WGPU plus-one chunks each fit separately");
    assert_eq!(plus_one.len(), 2);
    assert!(plus_one
        .iter()
        .all(|shard| shard.coalesced_bytes <= WGPU_BYTE_SCAN_DISPATCH_LIMIT));
}

#[test]
fn production_wgpu_shards_the_8mib_overlapped_workload_with_cpu_parity() {
    use super::super::gpu_region_dispatch::{
        reset_test_window_reduction_allocations, test_window_reduction_allocations,
    };
    use crate::{CompiledScanner, ScanBackend};
    use keyhog_core::{ChunkMetadata, DetectorSpec, PatternSpec, Severity};

    const CHUNK_BYTES: usize = 3_145_770;
    const TOKEN: &str = "KHGPUWG_0123456789abcdefghijklmn";

    let detector = DetectorSpec {
        id: "gpu-wgpu-sharding".into(),
        name: "GPU WGPU sharding".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "KHGPUWG_[A-Za-z0-9]{24}".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        keywords: vec!["KHGPUWG".into()],
        match_confidence: keyhog_core::detector_spec_by_id("datadog-api-key")
            .and_then(|embedded| embedded.match_confidence),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let scanner = CompiledScanner::compile(vec![detector]).expect("compile WGPU shard scanner");
    if !crate::hw_probe::probe_hardware().gpu_available {
        eprintln!("GPU parity fixture requires a physical GPU");
        return;
    }
    let wgpu = scanner
        .gpu_backend_candidates()
        .into_iter()
        .find(|candidate| candidate.backend == ScanBackend::GpuWgpu)
        .expect("compiled scanner must report WGPU");
    assert!(
        wgpu.available,
        "RTX host must acquire WGPU: {}",
        wgpu.acquisition_error.as_deref().unwrap_or("no diagnostic")
    );
    assert_eq!(wgpu.driver_id, Some("wgpu"));

    let chunks: Vec<_> = (0..3)
        .map(|index| {
            let mut data = String::with_capacity(CHUNK_BYTES);
            data.push_str(&"x".repeat(1024 + index));
            data.push_str(TOKEN);
            data.push_str(&"x".repeat(CHUNK_BYTES - data.len()));
            keyhog_core::Chunk {
                data: data.into(),
                metadata: ChunkMetadata {
                    path: Some(format!("wgpu-shard-{index}.txt").into()),
                    ..ChunkMetadata::default()
                },
            }
        })
        .collect();
    let coalesced_bytes = region_presence_batch_len(&chunks).expect("coalesced byte count");
    assert_eq!(coalesced_bytes, 9_437_312);
    assert!(coalesced_bytes > WGPU_BYTE_SCAN_DISPATCH_LIMIT);
    let shards: Vec<_> = region_presence_shards(&chunks, region_presence_batch_byte_limit("wgpu"))
        .expect("WGPU shard iterator")
        .collect::<Result<_, _>>()
        .expect("WGPU chunks fit the portable dispatch ceiling");
    assert_eq!(shards.len(), 2);
    assert!(shards
        .iter()
        .all(|shard| shard.coalesced_bytes <= WGPU_BYTE_SCAN_DISPATCH_LIMIT));

    let mut cpu = scanner.scan_coalesced_with_backend(&chunks, ScanBackend::CpuFallback);
    reset_test_window_reduction_allocations();
    let mut gpu = scanner.scan_coalesced_with_backend(&chunks, ScanBackend::GpuWgpu);
    assert_eq!(
        test_window_reduction_allocations(),
        0,
        "ordinary chunk-boundary shards must retain streaming trigger derivation"
    );
    canonicalize_production_results(&mut cpu);
    canonicalize_production_results(&mut gpu);
    assert_eq!(
        cpu.iter().map(Vec::len).sum::<usize>(),
        3,
        "fixture must produce one finding per chunk"
    );
    assert_eq!(
        gpu, cpu,
        "sharded production WGPU findings diverged from CPU"
    );
}

#[test]
fn production_cuda_windows_seam_tail_and_mixed_rows_with_cpu_parity() {
    use super::super::gpu_region_dispatch::{
        reset_test_window_reduction_allocations, test_window_reduction_allocations,
    };
    use crate::{CompiledScanner, ScanBackend};
    use keyhog_core::{DetectorSpec, PatternSpec, Severity};

    const LIMIT: usize = 64;
    const SEAM: &str = "KHCUDAX_A1b2C3d4";
    const TAIL: &str = "KHCUDAX_Z9y8X7w6";
    let detector = DetectorSpec {
        id: "gpu-cuda-windowing".into(),
        name: "GPU CUDA windowing".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "KHCUDAX_[A-Za-z0-9]{8}".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        keywords: vec!["KHCUDAX_".into()],
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let scanner = CompiledScanner::compile(vec![detector]).expect("compile CUDA window scanner");
    let cuda = scanner
        .gpu_backend_candidates()
        .into_iter()
        .find(|candidate| candidate.backend == ScanBackend::GpuCuda)
        .expect("compiled scanner must report CUDA");
    if !cuda.available {
        let caps = crate::hw_probe::probe_hardware();
        let cuda_capable = cuda.device_identity.is_some()
            || caps
                .gpu_name
                .as_deref()
                .is_some_and(|name| name.to_ascii_lowercase().contains("nvidia"));
        assert!(
            !cuda_capable,
            "CUDA-capable host failed to acquire CUDA: {}",
            cuda.acquisition_error.as_deref().unwrap_or("no diagnostic")
        );
        eprintln!(
            "CUDA parity fixture skipped because the CUDA peer is ineligible: {}",
            cuda.acquisition_error.as_deref().unwrap_or("no diagnostic")
        );
        return;
    }

    let mut oversized = "x".repeat(160);
    oversized.replace_range(61..61 + SEAM.len(), SEAM);
    oversized.replace_range(160 - TAIL.len()..160, TAIL);
    let chunks = vec![
        keyhog_core::Chunk::from("KHCUDAX_Q1w2E3r4!"),
        keyhog_core::Chunk::from(oversized),
        keyhog_core::Chunk::from("KHCUDAX_T5y6U7i8!"),
    ];
    let mut cpu = scanner.scan_coalesced_with_backend(&chunks, ScanBackend::CpuFallback);
    reset_test_window_reduction_allocations();
    let mut cuda = with_test_region_presence_byte_limit(LIMIT, || {
        scanner.scan_coalesced_with_backend(&chunks, ScanBackend::GpuCuda)
    });
    assert_eq!(
        test_window_reduction_allocations(),
        1,
        "only the one oversized logical row may allocate a reduction bitmap"
    );
    canonicalize_production_results(&mut cpu);
    canonicalize_production_results(&mut cuda);
    assert_eq!(cpu.iter().map(Vec::len).sum::<usize>(), 4);
    assert_eq!(cuda, cpu, "windowed production CUDA findings diverged");
}

#[test]
fn phase2_shard_merge_preserves_row_proofs_and_match_multiplicity() {
    use super::super::gpu_region_dispatch::append_phase2_gpu_admission;
    use super::super::phase2_gpu_dfa::Phase2GpuDfaAdmission;

    let mut merged = Phase2GpuDfaAdmission {
        admitted: Vec::new(),
        complete: Vec::new(),
        matches_seen: 0,
    };
    append_phase2_gpu_admission(
        &mut merged,
        Phase2GpuDfaAdmission {
            admitted: vec![true, false],
            complete: vec![true, true],
            matches_seen: 3,
        },
        2,
    )
    .expect("first phase-2 shard");
    append_phase2_gpu_admission(
        &mut merged,
        Phase2GpuDfaAdmission {
            admitted: vec![false, true, true],
            complete: vec![false, true, false],
            matches_seen: 4,
        },
        3,
    )
    .expect("second phase-2 shard");

    assert_eq!(merged.admitted, [true, false, false, true, true]);
    assert_eq!(merged.complete, [true, true, false, true, false]);
    assert_eq!(merged.matches_seen, 7);
}

#[test]
#[cfg(feature = "simd")]
fn ceiling_edges_and_multi_shard_preserve_cpu_hyperscan_parity() {
    const LIMIT: usize = 64;

    let boundary_minus_one = [chunk_with_hits(31, false), chunk_with_hits(31, true)];
    assert_eq!(
        region_presence_batch_len(&boundary_minus_one).unwrap(),
        LIMIT - 1
    );
    assert_backend_parity(&boundary_minus_one, LIMIT, 1);

    let exact_boundary = [chunk_with_hits(31, true), chunk_with_hits(32, false)];
    assert_eq!(region_presence_batch_len(&exact_boundary).unwrap(), LIMIT);
    assert_backend_parity(&exact_boundary, LIMIT, 1);

    let boundary_plus_one = [chunk_with_hits(31, false), chunk_with_hits(33, true)];
    assert_eq!(
        region_presence_batch_len(&boundary_plus_one).unwrap(),
        LIMIT + 1
    );
    assert_backend_parity(&boundary_plus_one, LIMIT, 2);

    let multi_shard: Vec<_> = (0..7)
        .map(|idx| chunk_with_hits(23, idx % 2 == 0))
        .collect();
    assert_backend_parity(&multi_shard, LIMIT, 4);
}

#[test]
fn phase2_chunk_sharder_rejects_one_oversized_chunk() {
    let chunks = [chunk_with_hits(65, false)];
    let mut callbacks = 0usize;
    let error = for_each_region_presence_batch_with_limit(
        &chunks,
        64,
        |_haystack, _region_starts, _mode, _shard| {
            callbacks += 1;
            Ok(())
        },
    )
    .expect_err("a chunk without a safe split boundary must fail");

    assert_eq!(callbacks, 0);
    assert!(error.contains("chunk 0") && error.contains("no safe chunk boundary"));
}

#[test]
fn oversized_literal_presence_windows_are_bounded_and_overlap_seams() {
    const LIMIT: usize = 64;
    const LITERAL_LEN: usize = 6;
    let mut bytes = vec![b'x'; 72];
    bytes[61..67].copy_from_slice(b"SECRET");
    let mut ranges = Vec::new();
    let mut found = false;
    let summary = for_each_region_presence_window(&bytes, LIMIT, LITERAL_LEN, |window, range| {
        assert!(window.len() <= LIMIT);
        ranges.push(range);
        found |= window
            .windows(LITERAL_LEN)
            .any(|candidate| candidate.eq_ignore_ascii_case(b"secret"));
        Ok(())
    })
    .expect("oversized literal-presence windows");

    assert!(
        found,
        "the case-insensitive seam literal must survive raw physical windowing"
    );
    assert_eq!(ranges, [0..64, 59..72]);
    assert_eq!(summary.dispatches, 2);
    assert_eq!(summary.coalesced_bytes, 77);
    assert_eq!(summary.max_dispatch_bytes, LIMIT);
    assert_eq!(summary.mode, RegionPresenceBatchMode::Windowed);
}

#[test]
fn literal_presence_windows_cover_the_tail_and_reject_impossible_overlap() {
    let bytes = vec![b'x'; 129];
    let ranges = for_each_region_presence_window(&bytes, 64, 1, |_window, _range| Ok(()))
        .expect("one-byte literal windows");
    assert_eq!(ranges.dispatches, 3);
    assert_eq!(ranges.coalesced_bytes, bytes.len());

    let exact = for_each_region_presence_window(&bytes[..64], 64, 64, |window, range| {
        assert_eq!(window.len(), 64);
        assert_eq!(range, 0..64);
        Ok(())
    })
    .expect("literal equal to the dispatch ceiling remains representable");
    assert_eq!(exact.dispatches, 1);

    let error = for_each_region_presence_window(&bytes, 64, 65, |_window, _range| Ok(()))
        .expect_err("literal longer than the dispatch ceiling must fail");
    assert!(error.contains("longest compiled GPU literal is 65 byte(s)"));
    let error = validate_region_presence_request_plan(&[chunk_with_hits(65, false)], 64, 65)
        .expect_err("request preflight must preserve actionable literal bounds");
    assert!(
        error.contains("literal is 65 byte(s)")
            && error.contains("64-byte dispatch ceiling")
            && error.contains("Fix:"),
        "unexpected preflight diagnostic: {error}"
    );

    let pathological = vec![b'x'; 64 + MAX_REGION_PRESENCE_REQUEST_DISPATCHES];
    let error = for_each_region_presence_window(&pathological, 64, 64, |_window, _range| Ok(()))
        .expect_err("one-byte window progress must have a bounded dispatch count");
    assert!(error.contains("above the request safety limit of 4096"));
}

#[test]
fn request_plan_caps_many_individually_valid_oversized_chunks() {
    let chunks = (0..(MAX_REGION_PRESENCE_REQUEST_DISPATCHES / 2 + 1))
        .map(|_| chunk_with_hits(65, false))
        .collect::<Vec<_>>();
    let error = validate_region_presence_request_plan(&chunks, 64, 1)
        .expect_err("request-wide dispatch amplification must fail before execution");
    assert!(
        error.contains("request needs 4098 dispatches")
            && error.contains("request safety limit of 4096"),
        "unexpected request-plan error: {error}"
    );
}

#[test]
fn window_plan_contains_every_literal_interval_across_ten_thousand_cases() {
    const LIMIT: usize = 64;
    for case in 0usize..10_000 {
        let literal_len = 1 + case % 32;
        let source_len = LIMIT + 1 + (case.wrapping_mul(37) % 257);
        let start = case.wrapping_mul(97) % (source_len - literal_len + 1);
        let end = start + literal_len;
        let literal = vec![b'a'; literal_len];
        let absent = vec![b'z'; literal_len];
        let mut source = vec![b'x'; source_len];
        for (offset, byte) in source[start..end].iter_mut().enumerate() {
            *byte = if offset % 2 == 0 { b'A' } else { b'a' };
        }
        let scalar = [literal.as_slice(), absent.as_slice()].map(|needle| {
            source
                .windows(needle.len())
                .any(|candidate| candidate.eq_ignore_ascii_case(needle))
        });
        let mut reduced = [false; 2];
        let mut ranges = Vec::new();
        for_each_region_presence_window(&source, LIMIT, literal_len, |window, range| {
            ranges.push(range);
            for (bit, needle) in [literal.as_slice(), absent.as_slice()]
                .into_iter()
                .enumerate()
            {
                reduced[bit] |= window
                    .windows(needle.len())
                    .any(|candidate| candidate.eq_ignore_ascii_case(needle));
            }
            Ok(())
        })
        .expect("valid physical window plan");
        assert!(
            ranges
                .iter()
                .any(|range| range.start <= start && range.end >= end),
            "case {case}: literal interval {start}..{end} was not contained in {ranges:?}"
        );
        assert!(ranges.iter().all(|range| range.len() <= LIMIT));
        assert_eq!(
            reduced, scalar,
            "case {case}: OR-reduced raw window presence diverged from case-insensitive scalar presence"
        );
    }
}

#[test]
fn shard_iteration_is_lazy() {
    let calls = std::cell::Cell::new(0usize);
    let lengths = [40usize, 40, 40];
    let mut shards = region_presence_shards_with_limit(
        lengths.len(),
        |index| {
            calls.set(calls.get() + 1);
            lengths[index]
        },
        64,
    )
    .expect("valid shard limit");

    assert_eq!(calls.get(), 0, "construction must not inspect every chunk");
    assert_eq!(shards.next().transpose().unwrap().unwrap().chunks, 0..1);
    assert!(calls.get() < lengths.len());
    assert_eq!(shards.next().transpose().unwrap().unwrap().chunks, 1..2);
    assert_eq!(shards.next().transpose().unwrap().unwrap().chunks, 2..3);
    assert!(shards.next().is_none());
}

#[test]
fn lazy_shard_error_is_yielded_once_then_fused() {
    let lengths = [16usize, 65, 16];
    let mut shards = region_presence_shards_with_limit(lengths.len(), |index| lengths[index], 64)
        .expect("valid shard limit");

    assert_eq!(shards.next().transpose().unwrap().unwrap().chunks, 0..1);
    let error = shards
        .next()
        .expect("oversized shard result")
        .expect_err("oversized chunk must fail");
    assert!(error.contains("chunk 1") && error.contains("no safe chunk boundary"));
    assert!(shards.next().is_none());
    assert!(shards.next().is_none());
}
