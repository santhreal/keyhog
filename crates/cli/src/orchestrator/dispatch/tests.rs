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
    assert!(!index.record_chunk_at_offset_and_check_unchanged(
        "seed.rs".into(),
        0,
        1,
        2,
        4,
        b"seed",
    ));
    index
        .save_with_spec(&cache, &orchestrator.detector_spec_hash)
        .expect("seed incremental cache");
    let seeded_bytes = std::fs::read(&cache).expect("read seeded cache");

    assert!(!index.record_chunk_at_offset_and_check_unchanged("new.rs".into(), 0, 2, 3, 3, b"new",));
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
    assert!(reloaded.record_chunk_at_offset_and_check_unchanged(
        "new.rs".into(),
        0,
        2,
        3,
        3,
        b"new",
    ));
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

/// WHY: a scanner-thread panic invalidates scan completeness even when the
/// source layer recorded no coverage gap. Report metadata must carry `partial`
/// so the exit-11 Action receipt remains representable and fail closed.
#[test]
fn scanner_panic_marks_report_metadata_partial_without_a_source_gap() {
    use crate::testing::{CliTestApi, API};
    use keyhog_core::ScanCompletionStatus;

    let guard = API.scan_runtime_guard_for_test();
    API.reset_scan_runtime_state_for_test(&guard);
    let _ = crate::record_scanner_panic(); // LAW10: synthetic test-only fault event; reporting-only, recall-safe

    let cli = crate::args::Cli::parse_from(["keyhog", "scan", "."]);
    let crate::args::Command::Scan(args) = cli.command.expect("scan command parsed") else {
        panic!("expected scan command");
    };
    let now = chrono::Utc::now();
    let metadata =
        crate::reporting::report_metadata_from_scan_run(&args, now, now, 0, 0, 0, 1, None);

    assert_eq!(metadata.scan_status, ScanCompletionStatus::Partial);
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

// --- Parallel coalesced consumer -------------------------------------------
//
// The consumer bridges the batch channel onto the global pool, so two pieces
// of shared state decide whether a scan is trustworthy: the slot holding the
// scan's terminal routing error, and the iterator that feeds batches to the
// pool. Both are reachable from several threads and both fail quietly if they
// are wrong, so they are pinned here rather than only through an end-to-end
// report comparison.

/// A routing failure recorded before a panic must survive the panic.
///
/// `Mutex::lock` returns `Err` once a holder panics. Treating that as "no
/// error recorded" would let `run` return `Ok` with whatever findings the
/// surviving batches produced, reporting a partial scan as a clean one. That
/// is the exact failure mode the fail-closed contract exists to prevent.
#[test]
fn a_recorded_routing_error_survives_a_poisoned_slot() {
    let slot: std::sync::Mutex<Option<AutorouteRoutingError>> = std::sync::Mutex::new(None);
    *first_routing_error(&slot) = Some(AutorouteRoutingError::unsupported_backend(
        ScanBackend::GpuMetal,
    ));

    let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = slot.lock().expect("uncontended lock");
        panic!("holder panics while the error is recorded");
    }));
    assert!(poison.is_err(), "the test must actually poison the mutex");
    assert!(
        slot.is_poisoned(),
        "the slot must be poisoned for this contract"
    );

    assert!(
        first_routing_error(&slot).is_some(),
        "a poisoned slot must still surrender the recorded routing error"
    );
}

/// An empty slot reads as empty, so a clean scan is never failed by accident.
#[test]
fn an_untouched_routing_slot_reports_no_error() {
    let slot: std::sync::Mutex<Option<AutorouteRoutingError>> = std::sync::Mutex::new(None);
    assert!(first_routing_error(&slot).is_none());
}

/// The bridge must deliver every batch exactly once and in channel order.
///
/// `par_bridge` scans batches out of order, but it can only do that with
/// batches the iterator actually yields. A bridge that dropped, duplicated, or
/// reordered items would silently change recall, and the timing instrumentation
/// wrapped around `next` is exactly the kind of code that invites such a bug.
#[test]
fn the_timed_bridge_yields_every_batch_once_in_order() {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<Chunk>>();
    let sent: Vec<Vec<Chunk>> = (0..5)
        .map(|index| {
            vec![routed_chunk(
                "filesystem",
                &format!("f{index}"),
                "body",
                true,
            )]
        })
        .collect();
    for batch in &sent {
        tx.send(batch.clone()).expect("send batch");
    }
    drop(tx);

    let bridge = TimedBatches {
        batches: rx.into_iter(),
    };
    let received: Vec<Arc<str>> = bridge
        .map(|batch| {
            batch[0]
                .metadata
                .path
                .clone()
                .expect("fixture chunks carry a path")
        })
        .collect();

    let expected: Vec<Arc<str>> = sent
        .iter()
        .map(|batch| batch[0].metadata.path.clone().expect("fixture path"))
        .collect();
    assert_eq!(received, expected, "every batch, once, in channel order");
}

/// The bridge charges the time it spends waiting, including the final blocking
/// read that ends the stream.
///
/// `Stage::ScannerQueueWait` is how you tell a starved consumer from a slow
/// one. If the instrumentation only counted immediate reads it would report
/// zero wait on exactly the workloads where the producer is the bottleneck,
/// which is when the number matters. The bridge used to carry a private
/// `AtomicU64` timing this same interval one line below the span; the span is
/// now the only clock, so this test reads the profiler.
#[test]
fn the_timed_bridge_charges_time_spent_waiting_for_a_batch() {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<Chunk>>();
    let sender = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(40));
        let _ = tx.send(vec![routed_chunk("filesystem", "slow", "body", true)]);
        // LAW10: test-only producer may observe a closed consumer after assertion failure; no production result is suppressed.
    });

    let identity = keyhog_profile::RunIdentity::new(
        "0.5.80",
        "detectors",
        "config",
        "filesystem",
        "timed-bridge",
        "scalar",
    );
    let _session = keyhog_profile::Session::start(identity).expect("start profile");
    keyhog_profile::set_detail(keyhog_profile::Detail::Stages);
    keyhog_profile::reset();
    let batches: Vec<Vec<Chunk>> = TimedBatches {
        batches: rx.into_iter(),
    }
    .collect();
    sender.join().expect("sender thread");
    let waited_ns: u64 = keyhog_profile::take_stage_measurements()
        .into_iter()
        .filter(|row| row.stage == keyhog_profile::Stage::ScannerQueueWait)
        .map(|row| row.elapsed_ns)
        .sum();
    keyhog_profile::set_detail(keyhog_profile::Detail::Off);

    assert_eq!(batches.len(), 1);
    let waited = std::time::Duration::from_nanos(waited_ns);
    assert!(
        waited >= std::time::Duration::from_millis(30),
        "a 40 ms producer stall must be charged as scanner-queue wait, saw {waited:?}"
    );
}

/// Scanner setup is demand-driven at the production batch boundary. A clean
/// file starts both the fused and coalesced scanner path on its cold scan, then
/// its trusted Merkle metadata hit closes acquisition without starting either
/// path on the warm scan. This covers cold and all-unchanged variants;
/// backend-specific route parity remains covered by the scanner suites.
#[test]
fn incremental_scanner_dispatch_starts_only_for_nonempty_production_batches() {
    let detector = DetectorSpec {
        id: "deferred-dispatch-test".into(),
        name: "Deferred Dispatch Test".into(),
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
    orchestrator.effective_config.backend_override = Some(ScanBackend::CpuFallback);

    for coalesced in [false, true] {
        orchestrator.effective_config.batch_pipeline = coalesced;
        let source = tempfile::tempdir().expect("source root");
        std::fs::write(
            source.path().join("clean.txt"),
            "ordinary source without credentials\n",
        )
        .expect("write clean source");
        let merkle = Arc::new(keyhog_core::MerkleIndex::default());

        let cold_sources: Vec<Box<dyn Source>> = vec![Box::new(
            keyhog_sources::FilesystemSource::new(source.path().to_path_buf())
                .with_default_excludes(false)
                .with_merkle_skip(Arc::clone(&merkle)),
        )];
        orchestrator
            .scanner_dispatch_starts
            .store(0, Ordering::Relaxed);
        let cold_findings = orchestrator
            .scan_sources(cold_sources, false, Some(Arc::clone(&merkle)), None)
            .expect("cold source scan");
        assert!(cold_findings.is_empty());
        assert_eq!(
            orchestrator.scanner_dispatch_starts.load(Ordering::Relaxed),
            1,
            "cold {} path did not start scanner dispatch exactly once",
            if coalesced { "coalesced" } else { "fused" }
        );

        let warm_sources: Vec<Box<dyn Source>> = vec![Box::new(
            keyhog_sources::FilesystemSource::new(source.path().to_path_buf())
                .with_default_excludes(false)
                .with_merkle_skip(Arc::clone(&merkle)),
        )];
        orchestrator
            .scanner_dispatch_starts
            .store(0, Ordering::Relaxed);
        let warm_findings = orchestrator
            .scan_sources(warm_sources, false, Some(Arc::clone(&merkle)), None)
            .expect("warm all-unchanged source scan");
        assert!(warm_findings.is_empty());
        assert_eq!(
            orchestrator.scanner_dispatch_starts.load(Ordering::Relaxed),
            0,
            "warm all-unchanged {} path started scanner dispatch",
            if coalesced { "coalesced" } else { "fused" }
        );
    }
}

/// An explicit backend needs no lock, and the same batch must resolve to the
/// same backend however many threads ask at once.
///
/// Putting the measured router behind a mutex made it easy to accidentally
/// serialise the explicit path too, or to let selection depend on call order.
/// Either would turn `--backend cpu` into a throughput cliff or a nondeterministic
/// route, so both are pinned.
#[test]
fn explicit_routing_is_lock_free_and_order_independent() {
    let router = CoalescedBatchRouter::Explicit(ScanBackend::CpuFallback);
    let scanner = Arc::new(
        CompiledScanner::compile(vec![DetectorSpec {
            id: "explicit-route-test".into(),
            name: "Explicit Route Test".into(),
            service: "test".into(),
            severity: Severity::Medium,
            patterns: vec![PatternSpec {
                regex: r"STATIC_SECRET_[0-9]+".into(),
                ..Default::default()
            }],
            ..keyhog_scanner::testing::named_detector_fixture_defaults()
        }])
        .expect("compile test detector"),
    );
    let batch = vec![routed_chunk("filesystem", "a", "body", true)];

    let chosen: Vec<ScanBackend> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    router
                        .choose_with_plan(scanner.as_ref(), &batch)
                        .expect("explicit routing never fails")
                        .backend
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("join"))
            .collect()
    });

    assert_eq!(chosen.len(), 8);
    assert!(
        chosen
            .iter()
            .all(|backend| *backend == ScanBackend::CpuFallback),
        "an explicit backend must be returned to every concurrent caller"
    );
}
