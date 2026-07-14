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
fn sharded_gpu_view_hits(
    chunks: &[keyhog_core::Chunk],
    byte_limit: usize,
) -> (Vec<Hit>, RegionPresenceBatchSummary, Vec<&'static str>) {
    let regex = regex::bytes::Regex::new("secret").expect("folded GPU-view regex");
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
    .expect("bounded sharded GPU view");
    (hits, summary, backend_ids)
}

#[cfg(feature = "simd")]
fn assert_backend_parity(chunks: &[keyhog_core::Chunk], byte_limit: usize, dispatches: usize) {
    let cpu = cpu_hits(chunks);
    let hyperscan = hyperscan_hits(chunks);
    let (gpu, summary, backend_ids) = sharded_gpu_view_hits(chunks, byte_limit);

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
fn single_lowercase_chunk_keeps_the_borrowed_fast_path() {
    let chunks = [chunk_with_hits(32, false)];
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
        REGION_PRESENCE_BATCH_BYTE_LIMIT
    );
    assert_eq!(WGPU_BYTE_SCAN_DISPATCH_LIMIT, 8_388_480);

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
            client_safe: false,
        }],
        keywords: vec!["KHGPUWG".into()],
        ..DetectorSpec::default()
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
        wgpu.acquired,
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
    let mut gpu = scanner.scan_coalesced_with_backend(&chunks, ScanBackend::GpuWgpu);
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
fn phase2_shard_merge_preserves_rows_marks_and_match_multiplicity() {
    use super::super::gpu_region_dispatch::append_phase2_gpu_admission;
    use super::super::phase2_gpu_dfa::Phase2GpuDfaAdmission;

    let mut merged = Phase2GpuDfaAdmission {
        admitted: Vec::new(),
        complete: true,
        matches_seen: 0,
        marked: Vec::new(),
    };
    append_phase2_gpu_admission(
        &mut merged,
        Phase2GpuDfaAdmission {
            admitted: vec![true, false],
            complete: true,
            matches_seen: 3,
            marked: vec![vec![7, 9], Vec::new()],
        },
        2,
    )
    .expect("first phase-2 shard");
    append_phase2_gpu_admission(
        &mut merged,
        Phase2GpuDfaAdmission {
            admitted: vec![false, true, true],
            complete: false,
            matches_seen: 4,
            marked: vec![Vec::new(), vec![2], vec![2, 8]],
        },
        3,
    )
    .expect("second phase-2 shard");

    assert_eq!(merged.admitted, [true, false, false, true, true]);
    assert_eq!(
        merged.marked,
        [vec![7, 9], vec![], vec![], vec![2], vec![2, 8]]
    );
    assert_eq!(merged.matches_seen, 7);
    assert!(!merged.complete);
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
fn one_oversized_chunk_fails_without_switching_backend() {
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
