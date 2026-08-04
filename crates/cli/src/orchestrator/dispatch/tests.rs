//! Unit tests for `orchestrator::dispatch` derived constants and the
//! `is_gpu_backend` predicate. Housed in a sibling `tests.rs` module (rather
//! than an inline `#[cfg(test)] mod {}` block) so the `no_inline_tests_in_src`
//! gate stays green while these still reach the parent module via `use super::*`.

use super::*;
use clap::Parser;
use keyhog_core::{DetectorSpec, PatternSpec, Severity};

struct StaticSource {
    name: &'static str,
    chunks: Vec<Chunk>,
}

impl Source for StaticSource {
    fn name(&self) -> &str {
        self.name
    }

    fn chunks(
        &self,
    ) -> Box<dyn Iterator<Item = std::result::Result<Chunk, keyhog_core::SourceError>> + '_> {
        Box::new(self.chunks.clone().into_iter().map(Ok))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn source_chunk(source_type: &str, body: &str) -> Chunk {
    Chunk {
        data: body.into(),
        metadata: keyhog_core::ChunkMetadata {
            source_type: source_type.into(),
            size_bytes: Some(body.len() as u64),
            ..Default::default()
        },
    }
}

fn routed_chunk(source_type: &str, path: &str, body: &str, full_size: bool) -> Chunk {
    let mut chunk = source_chunk(source_type, body);
    chunk.metadata.path = Some(path.into());
    chunk.metadata.size_bytes = full_size.then_some(body.len() as u64);
    chunk
}

/// The MiB scan-ceiling used in operator skip messages is DERIVED from the
/// byte constant, so the two can never drift apart. Pins both the value (512)
/// and the exact byte<->MiB relationship the derivation relies on.
#[test]
fn coalesced_scan_ceiling_mb_is_derived_from_bytes() {
    assert_eq!(COALESCED_CHUNK_SCAN_CEILING_MB, 512);
    assert_eq!(
        COALESCED_CHUNK_SCAN_CEILING_MB * 1024 * 1024,
        COALESCED_CHUNK_SCAN_CEILING_BYTES
    );
}

/// `is_gpu_backend` is the single owner of the "does this backend run on the
/// GPU" predicate that the coalesced worker's `ran_on_gpu` flag consumes.
/// Pin its verdict for every routable backend so an inline `matches!` copy
/// cannot silently reintroduce a divergent classification.
#[test]
fn is_gpu_backend_classifies_every_routable_backend() {
    assert!(is_gpu_backend(ScanBackend::GpuCuda));
    assert!(is_gpu_backend(ScanBackend::GpuWgpu));
    assert!(!is_gpu_backend(ScanBackend::SimdCpu));
    assert!(!is_gpu_backend(ScanBackend::CpuFallback));
}

#[test]
fn coalesced_producer_never_mixes_distinct_sources_in_one_autoroute_batch() {
    let sources: Vec<Box<dyn Source>> = vec![
        Box::new(StaticSource {
            name: "filesystem",
            chunks: vec![
                source_chunk("filesystem", "one"),
                source_chunk("filesystem", "two"),
            ],
        }),
        Box::new(StaticSource {
            name: "web",
            chunks: vec![source_chunk("web", "three"), source_chunk("web", "four")],
        }),
    ];
    let plan = CoalescedPipelinePlan {
        batch_chunk_limit: 16,
        batch_bytes_budget: usize::MAX,
        pipeline_depth: 4,
    };
    let (tx, rx) = std::sync::mpsc::sync_channel(4);

    CoalescedBatchProducer::new(tx, plan, None).produce_sources(&sources);
    let batches: Vec<Vec<Chunk>> = rx.into_iter().collect();

    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0].len(), 2);
    assert_eq!(batches[1].len(), 2);
    assert!(batches[0]
        .iter()
        .all(|chunk| chunk.metadata.source_type.as_ref() == "filesystem"));
    assert!(batches[1]
        .iter()
        .all(|chunk| chunk.metadata.source_type.as_ref() == "web"));
}

#[test]
fn route_class_split_separates_distinct_filesystem_provenance() {
    let full = routed_chunk("filesystem", "plain.txt", "plain", true);
    let extracted = routed_chunk("filesystem:archive", "bundle.zip/item.txt", "inner", false);

    assert!(should_split_for_route_class(&[full], &extracted, true));
}

#[test]
fn route_class_split_preserves_same_identity_boundary_closure() {
    let full = routed_chunk("filesystem", "window.txt", "left", true);
    let mut transformed = routed_chunk("filesystem", "window.txt", "right", false);
    transformed.metadata.base_offset = full.data.len();

    assert!(!should_split_for_route_class(&[full], &transformed, true));
}

#[test]
fn route_class_split_requires_a_contiguous_identity_source_contract() {
    let full = routed_chunk("git-diff", "tracked.rs", "tracked", true);
    let payload = routed_chunk("git-diff", "patch.diff", "patch", false);

    assert!(!should_split_for_route_class(&[full], &payload, false));
}

#[test]
fn coalesced_producer_separates_real_files_and_extracted_tar_members() {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::write(root.path().join("a.txt"), "plain-source-body").expect("write plain file");
    let tar_path = root.path().join("b.tar");
    let tar_file = std::fs::File::create(&tar_path).expect("create tar");
    let mut archive = tar::Builder::new(tar_file);
    let member = b"archive-member-body";
    let mut header = tar::Header::new_gnu();
    header.set_size(member.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    archive
        .append_data(&mut header, "member.txt", member.as_slice())
        .expect("append tar member");
    archive.finish().expect("finish tar");

    let sources: Vec<Box<dyn Source>> = vec![Box::new(
        keyhog_sources::FilesystemSource::new(root.path().to_path_buf())
            .with_default_excludes(false),
    )];
    let plan = CoalescedPipelinePlan {
        batch_chunk_limit: 16,
        batch_bytes_budget: usize::MAX,
        pipeline_depth: 4,
    };
    let (tx, rx) = std::sync::mpsc::sync_channel(4);

    CoalescedBatchProducer::new(tx, plan, None).produce_sources(&sources);
    let batches: Vec<Vec<Chunk>> = rx.into_iter().collect();

    assert_eq!(
        batches.len(),
        2,
        "plain and extracted payload classes split"
    );
    assert_eq!(batches.iter().map(Vec::len).sum::<usize>(), 2);
    assert!(batches.iter().all(|batch| {
        let class = backend::source_route_class(&batch[0]);
        batch
            .iter()
            .all(|chunk| backend::source_route_class(chunk) == class)
    }));
    let bodies: Vec<&str> = batches
        .iter()
        .flat_map(|batch| batch.iter().map(|chunk| chunk.data.as_ref()))
        .collect();
    assert_eq!(bodies, ["plain-source-body", "archive-member-body"]);
}

#[test]
fn coalesced_producer_reserves_region_separators_before_crossing_the_byte_cap() {
    let sources: Vec<Box<dyn Source>> = vec![Box::new(StaticSource {
        name: "filesystem",
        chunks: vec![
            source_chunk("filesystem", "one"),
            source_chunk("filesystem", "two"),
            source_chunk("filesystem", "x"),
        ],
    })];
    let plan = CoalescedPipelinePlan {
        batch_chunk_limit: 16,
        batch_bytes_budget: 8,
        pipeline_depth: 2,
    };
    let (tx, rx) = std::sync::mpsc::sync_channel(2);

    CoalescedBatchProducer::new(tx, plan, None).produce_sources(&sources);
    let batches: Vec<Vec<Chunk>> = rx.into_iter().collect();

    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0].len(), 2);
    assert_eq!(batches[0][0].data.as_ref(), "one");
    assert_eq!(batches[0][1].data.as_ref(), "two");
    assert_eq!(batches[1].len(), 1);
    assert_eq!(batches[1][0].data.as_ref(), "x");
}

#[test]
fn autoroute_calibration_leaves_incremental_cache_bytes_unchanged() {
    let detector = DetectorSpec {
        id: "incremental-finalize-test".into(),
        name: "Incremental Finalize Test".into(),
        service: "test".into(),
        severity: Severity::Medium,
        patterns: vec![PatternSpec {
            regex: r"STATIC_SECRET_[0-9]+".into(),
            ..Default::default()
        }],
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let scanner =
        Arc::new(CompiledScanner::compile(vec![detector.clone()]).expect("compile test detector"));
    let signatures = [Arc::<str>::from(r"STATIC_SECRET_[0-9]+")]
        .into_iter()
        .collect();
    let args = crate::args::ScanArgs::try_parse_from(["scan"]).expect("parse scan args");
    let mut orchestrator = ScanOrchestrator::from_parts_for_test(
        args,
        vec![detector],
        scanner,
        signatures,
        crate::test_fixture_suppressions::TestFixtureSuppressions::bundled(),
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let cache = dir.path().join("incremental.json");
    let index = Arc::new(keyhog_core::MerkleIndex::default());
    assert!(!index.record_chunk_at_offset_and_check_unchanged("seed.rs".into(), 0, 1, 4, b"seed",));
    index
        .save_with_spec(&cache, &orchestrator.detector_spec_hash)
        .expect("seed incremental cache");
    let seeded_bytes = std::fs::read(&cache).expect("read seeded cache");

    assert!(!index.record_chunk_at_offset_and_check_unchanged("new.rs".into(), 0, 2, 3, b"new",));
    orchestrator.effective_config.autoroute_calibration = true;
    orchestrator.finalize_incremental(Some(&index), Some(&cache), 0, &[]);
    assert_eq!(
        std::fs::read(&cache).expect("read cache after calibration"),
        seeded_bytes,
        "calibration must not persist in-memory incremental updates"
    );

    orchestrator.effective_config.autoroute_calibration = false;
    orchestrator.finalize_incremental(Some(&index), Some(&cache), 0, &[]);
    assert_ne!(
        std::fs::read(&cache).expect("read cache after ordinary scan"),
        seeded_bytes,
        "ordinary scans must persist in-memory incremental updates"
    );
    let reloaded =
        keyhog_core::MerkleIndex::load_with_spec_report(&cache, &orchestrator.detector_spec_hash)
            .into_index();
    assert!(reloaded.record_chunk_at_offset_and_check_unchanged("new.rs".into(), 0, 2, 3, b"new",));
}

/// Regression for KH-1409: admission identity recovery must drive the same
/// counted complete-after-recovery report metadata as an exact backend rescan,
/// while terminal text names admission recovery rather than a backend fault.
#[test]
fn admission_recovery_receipt_is_counted_in_json_and_terminal_status() {
    use crate::testing::{CliTestApi, API};
    use keyhog_core::ScanCompletionStatus;

    let guard = API.scan_runtime_guard_for_test();
    API.reset_scan_runtime_state_for_test(&guard);
    let receipt = keyhog_scanner::BackendRecoveryReceipt::new(
        ScanBackend::CpuFallback,
        ScanBackend::CpuFallback,
        vec![keyhog_scanner::RecoveredInputRange::new(0, 0, 17)],
        "phase-one admission plan identity mismatch; discarded the untrusted plan and recomputed exact admission"
            .to_string(),
    );
    let summary = completed_recovery_summary(&receipt);
    let json = serde_json::to_value(&summary).expect("recovery summary serializes");
    assert_eq!(json["events"], 1);
    assert_eq!(json["recovered_ranges"], 1);
    assert_eq!(json["recovered_chunks"], 1);
    assert_eq!(json["recovered_bytes"], 17);
    assert_eq!(
        json["reason"],
        "phase-one admission plan identity mismatch; discarded the untrusted plan and recomputed exact admission"
    );
    assert_eq!(
        json["repair_command"],
        "rerun the scan; report persistent admission-plan identity mismatches"
    );

    let terminal = completed_recovery_terminal_message(&receipt);
    assert!(terminal.contains("phase-one admission plan identity mismatch"));
    assert!(terminal.contains("recovered 1 exact range(s)"));
    assert!(terminal.contains("17 byte(s)"));
    assert!(terminal.contains("scan coverage is complete"));
    assert!(!terminal.contains("backend CPU fallback faulted"));
    assert!(!terminal.contains("calibrate-autoroute"));

    record_completed_backend_recovery(&receipt);
    record_completed_backend_recovery(&receipt);
    let snapshot = API.scan_runtime_snapshot(&guard);
    assert_eq!(snapshot.backend_recovery_events, 2);
    assert_eq!(snapshot.backend_recovered_chunks, 2);
    assert_eq!(snapshot.backend_recovered_bytes, 34);
    let summaries = API.backend_recovery_summaries_for_test(&guard);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].events, 2);
    assert_eq!(summaries[0].recovered_ranges, 2);
    assert_eq!(summaries[0].recovered_chunks, 2);
    assert_eq!(summaries[0].recovered_bytes, 34);

    let cli = crate::args::Cli::parse_from(["keyhog", "scan", "."]);
    let crate::args::Command::Scan(args) = cli.command.expect("scan command parsed") else {
        panic!("expected scan command");
    };
    let now = chrono::Utc::now();
    let metadata =
        crate::reporting::report_metadata_from_scan_run(&args, now, now, 0, 1, 17, 1, None);
    assert_eq!(
        metadata.scan_status,
        ScanCompletionStatus::CompleteAfterRecovery
    );
    assert_eq!(metadata.backend_recoveries.len(), 1);
    assert_eq!(metadata.backend_recoveries[0].events, 2);
    let metadata_json =
        serde_json::to_value(&metadata).expect("report metadata serializes to JSON");
    assert_eq!(metadata_json["scan_status"], "complete_after_recovery");
    assert_eq!(metadata_json["backend_recoveries"][0]["events"], 2);
    assert_eq!(
        metadata_json["backend_recoveries"][0]["reason"],
        "phase-one admission plan identity mismatch; discarded the untrusted plan and recomputed exact admission"
    );
    API.reset_scan_runtime_state_for_test(&guard);
}

// ── incremental batch-split state ───────────────────────────────────────────
//
// `BatchRouteState` replaced a predicate that rescanned the whole accumulating
// batch and hashed every chunk's source class on every call. At the coalesced
// pipeline's 4,096-chunk limit that was 8.4 million source-class hashes per
// batch and 9.4 s of the 10.2 s a 15,002-file scan took, which is also why an
// explicit GPU backend measured slower than CPU. The incremental state must
// decide EXACTLY what the reference decided; these tests are the proof.

/// Replay one chunk sequence through both predicates and report the first
/// position where they disagree. The reference is fed the real accumulated
/// batch, the incremental state is pushed and cleared in lockstep, so this is a
/// true differential over the same inputs a producer would see.
fn differential_split_disagreement(chunks: &[Chunk], contiguous: bool) -> Option<usize> {
    let mut batch: Vec<Chunk> = Vec::new();
    let mut state = BatchRouteState::default();
    for (index, chunk) in chunks.iter().enumerate() {
        let reference = should_split_for_route_class(&batch, chunk, contiguous);
        let incremental = state.should_split_before(chunk, contiguous);
        if reference != incremental {
            return Some(index);
        }
        if reference {
            batch.clear();
            state.clear();
        }
        batch.push(chunk.clone());
        state.push(chunk);
    }
    None
}

/// The two predicates agree on every sequence that exercises a distinct split
/// reason: a uniform run, a class change, a class change back, a repeat of an
/// identity already in the batch, and a mixed batch that can never split.
#[test]
fn incremental_split_state_matches_the_reference_predicate() {
    let plain = |name: &str| routed_chunk("filesystem", name, "body", true);
    let extracted = |name: &str| routed_chunk("filesystem/tar", name, "body", true);
    let sizeless = |name: &str| routed_chunk("filesystem", name, "body", false);

    let cases: Vec<(&str, Vec<Chunk>)> = vec![
        ("empty", vec![]),
        ("single", vec![plain("a")]),
        ("uniform run", vec![plain("a"), plain("b"), plain("c")]),
        (
            "class change",
            vec![plain("a"), plain("b"), extracted("c"), extracted("d")],
        ),
        (
            "class change back",
            vec![plain("a"), extracted("b"), plain("c"), extracted("d")],
        ),
        (
            "repeat identity across a class change",
            vec![plain("a"), plain("b"), extracted("a")],
        ),
        (
            "size-provenance change only",
            vec![plain("a"), sizeless("b"), plain("c")],
        ),
        (
            "alternating identities and classes",
            vec![
                plain("a"),
                extracted("a"),
                plain("a"),
                extracted("b"),
                plain("b"),
            ],
        ),
    ];

    for (label, chunks) in cases {
        for contiguous in [true, false] {
            assert_eq!(
                differential_split_disagreement(&chunks, contiguous),
                None,
                "{label} (contiguous={contiguous}) disagreed with the reference predicate"
            );
        }
    }
}

/// A long deterministic sequence over a small alphabet of classes and paths.
/// Short hand-written cases cannot reach the states a real 4,096-chunk batch
/// visits; this walks 600 chunks through repeated splits and resets.
#[test]
fn incremental_split_state_matches_the_reference_over_a_long_sequence() {
    let mut chunks = Vec::with_capacity(600);
    for index in 0..600usize {
        let source_type = match index % 3 {
            0 => "filesystem",
            1 => "filesystem/tar",
            _ => "git",
        };
        let path = format!("p{}", index % 7);
        let full_size = index % 5 != 0;
        chunks.push(routed_chunk(source_type, &path, "body", full_size));
    }
    assert_eq!(
        differential_split_disagreement(&chunks, true),
        None,
        "the incremental state diverged from the reference on a long mixed sequence"
    );
}

/// Clearing must reset the class AND the identity set. A stale identity would
/// suppress a legitimate split; a stale class would invent one.
///
/// Chunk identity is `(source_type, path)`, so the case where identity actually
/// suppresses a split is a route-class change that keeps the source type: the
/// same file seen once with a known size and once without.
#[test]
fn clearing_the_state_forgets_both_the_class_and_the_identities() {
    let sized = routed_chunk("filesystem", "same", "body", true);
    let sizeless = routed_chunk("filesystem", "same", "body", false);
    assert_ne!(
        backend::source_route_class(&sized),
        backend::source_route_class(&sizeless),
        "the fixture must differ in route class or it proves nothing"
    );

    let mut state = BatchRouteState::default();
    state.push(&sized);
    assert!(
        !state.should_split_before(&sizeless, true),
        "an identity already in the batch must suppress the split"
    );

    state.clear();
    assert!(
        !state.should_split_before(&sizeless, true),
        "an empty batch can never split"
    );

    let other = routed_chunk("filesystem", "other", "body", true);
    state.push(&other);
    assert!(
        state.should_split_before(&sizeless, true),
        "after a clear, a new batch with a different class and identity must split"
    );
}

/// A batch whose classes are already mixed can never split, and one more chunk
/// must not un-mix it. The reference reaches this through an `any` over the
/// batch; the incremental state has to latch it.
#[test]
fn a_mixed_batch_stays_unsplittable() {
    let mut state = BatchRouteState::default();
    state.push(&routed_chunk("filesystem", "a", "body", true));
    state.push(&routed_chunk("filesystem/tar", "b", "body", true));
    let probe = routed_chunk("git", "c", "body", true);
    assert!(!state.should_split_before(&probe, true));
    state.push(&routed_chunk("filesystem", "d", "body", true));
    assert!(
        !state.should_split_before(&probe, true),
        "a chunk matching the FIRST class must not clear the mixed latch"
    );
}

/// A non-contiguous source never splits, whatever the classes are. This is the
/// guard that keeps identity-based splitting sound for sources that interleave
/// chunk identities.
#[test]
fn a_non_contiguous_source_never_splits() {
    let mut state = BatchRouteState::default();
    state.push(&routed_chunk("filesystem", "a", "body", true));
    assert!(!state.should_split_before(&routed_chunk("git", "b", "body", true), false));
}
