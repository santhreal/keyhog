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
