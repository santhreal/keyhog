//! Unit tests for `orchestrator::dispatch` derived constants and the
//! `is_gpu_backend` predicate. Housed in a sibling `tests.rs` module (rather
//! than an inline `#[cfg(test)] mod {}` block) so the `no_inline_tests_in_src`
//! gate stays green while these still reach the parent module via `use super::*`.

use super::*;

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
    assert!(is_gpu_backend(ScanBackend::Gpu));
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
