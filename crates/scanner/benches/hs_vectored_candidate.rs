//! Benchmark-only Hyperscan vectored candidate for same-source chunk batches.
//!
//! This does not participate in production routing. It compares one vectored
//! scan per source with a block-mode reference over the identical virtual byte
//! stream. Contiguous data parts may form a match across buffer boundaries.
//! Separator parts represent omitted source ranges, and matches touching them
//! are discarded by canonical regex extraction before logical offsets are
//! mapped back to source offsets. Both Hyperscan databases use production
//! phase-1 flags: CASELESS and SINGLEMATCH, without SOM.
//!
//! Run the default 7, 8, and 9 MiB sweep with:
//! `cargo bench -p keyhog-scanner --bench hs_vectored_candidate`.
//! `KH_HS_VECTOR_SIZES_MIB` accepts a comma-separated MiB list and
//! `KH_HS_VECTOR_ITERS` controls the steady-state sample count.

use hyperscan::{
    Block, BlockDatabase, Builder, Matching, Pattern, PatternFlags, Patterns, Serialized, Vectored,
    VectoredDatabase,
};
use keyhog_core::load_detectors;
use std::collections::HashSet;
use std::env;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const SHARD_PATTERNS: usize = 320;
const MAX_HS_PATTERN_LEN: usize = 500;
const DEFAULT_ITERS: usize = 7;
const DEFAULT_SIZES_MIB: &[usize] = &[7, 8, 9];
const GAP_SEPARATOR: &[u8] = b"\n\0KEYHOG_SOURCE_GAP\0\n";
const SOURCE_GAP_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Finding {
    pattern_id: usize,
    source_id: usize,
    from: usize,
    to: usize,
}

#[derive(Debug, Eq, PartialEq)]
struct ScanOutcome {
    triggers: Vec<Vec<usize>>,
    findings: Vec<Finding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PartKind {
    Data {
        source_id: usize,
        source_offset: usize,
    },
    Separator,
}

#[derive(Debug)]
struct Part {
    bytes: Vec<u8>,
    kind: PartKind,
}

#[derive(Debug)]
struct SourceBatch {
    source_id: usize,
    parts: Vec<Part>,
}

impl SourceBatch {
    fn logical_len(&self) -> usize {
        self.parts.iter().map(|part| part.bytes.len()).sum()
    }

    fn buffers(&self) -> impl Iterator<Item = &[u8]> {
        self.parts.iter().map(|part| part.bytes.as_slice())
    }

    fn materialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.logical_len());
        for part in &self.parts {
            bytes.extend_from_slice(&part.bytes);
        }
        bytes
    }

    fn map_span(&self, from: usize, to: usize) -> Option<(usize, usize)> {
        if from >= to || to > self.logical_len() {
            return None;
        }

        let mut logical_start = 0usize;
        let mut source_start = None;
        let mut expected_source = None;
        for part in &self.parts {
            let logical_end = logical_start.checked_add(part.bytes.len())?;
            let overlap_start = from.max(logical_start);
            let overlap_end = to.min(logical_end);
            if overlap_start < overlap_end {
                let PartKind::Data {
                    source_id,
                    source_offset,
                } = part.kind
                else {
                    return None;
                };
                if source_id != self.source_id {
                    return None;
                }
                let local_start = overlap_start - logical_start;
                let local_end = overlap_end - logical_start;
                let mapped_start = source_offset.checked_add(local_start)?;
                let mapped_end = source_offset.checked_add(local_end)?;
                if let Some(expected) = expected_source {
                    if mapped_start != expected {
                        return None;
                    }
                } else {
                    source_start = Some(mapped_start);
                }
                expected_source = Some(mapped_end);
            }
            logical_start = logical_end;
        }
        Some((source_start?, expected_source?))
    }
}

#[derive(Default)]
struct CompileStats {
    block: Duration,
    vectored: Duration,
    prepare_rejected: usize,
    both_rejected: usize,
    block_only: usize,
    vectored_only: usize,
}

struct DatabaseShard {
    block: BlockDatabase,
    vectored: VectoredDatabase,
}

struct CatalogPattern {
    hyperscan: Pattern,
    canonical: regex::Regex,
}

fn detectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors")
}

fn compile_catalog_pattern(
    id: usize,
    expression: &str,
) -> Result<CatalogPattern, Box<dyn std::error::Error>> {
    let flags = PatternFlags::CASELESS | PatternFlags::SINGLEMATCH;
    let mut hyperscan = Pattern::with_flags(expression, flags)?;
    hyperscan.id = Some(id);
    let canonical = regex::RegexBuilder::new(expression)
        .case_insensitive(true)
        .build()?;
    Ok(CatalogPattern {
        hyperscan,
        canonical,
    })
}

fn catalog_patterns() -> Result<(Vec<CatalogPattern>, usize), Box<dyn std::error::Error>> {
    let detectors = load_detectors(&detectors_dir())?;
    let mut seen = HashSet::new();
    let mut patterns = Vec::new();
    let mut rejected = 0usize;
    for detector in detectors {
        for spec in detector.patterns {
            if !seen.insert(spec.regex.clone()) {
                continue;
            }
            if spec.regex.len() > MAX_HS_PATTERN_LEN {
                rejected += 1;
                continue;
            }
            match compile_catalog_pattern(patterns.len(), &spec.regex) {
                Ok(pattern) => {
                    patterns.push(pattern);
                }
                Err(_) => rejected += 1,
            }
        }
    }
    Ok((patterns, rejected))
}

fn build_pair(patterns: &[Pattern], stats: &mut CompileStats) -> Vec<DatabaseShard> {
    let block_start = Instant::now();
    let block = Builder::build::<Block>(&Patterns(patterns.to_vec()));
    stats.block += block_start.elapsed();

    let vectored_start = Instant::now();
    let vectored = Builder::build::<Vectored>(&Patterns(patterns.to_vec()));
    stats.vectored += vectored_start.elapsed();

    match (block, vectored) {
        (Ok(block), Ok(vectored)) => vec![DatabaseShard { block, vectored }],
        (block, vectored) if patterns.len() > 1 => {
            drop(block);
            drop(vectored);
            let middle = patterns.len() / 2;
            let mut left = build_pair(&patterns[..middle], stats);
            left.extend(build_pair(&patterns[middle..], stats));
            left
        }
        (Err(_), Err(_)) => {
            stats.both_rejected += 1;
            Vec::new()
        }
        (Ok(_), Err(_)) => {
            stats.block_only += 1;
            Vec::new()
        }
        (Err(_), Ok(_)) => {
            stats.vectored_only += 1;
            Vec::new()
        }
    }
}

fn compile_catalog(
) -> Result<(Vec<CatalogPattern>, Vec<DatabaseShard>, CompileStats), Box<dyn std::error::Error>> {
    let (catalog, prepare_rejected) = catalog_patterns()?;
    let patterns: Vec<Pattern> = catalog
        .iter()
        .map(|pattern| pattern.hyperscan.clone())
        .collect();
    let mut stats = CompileStats {
        prepare_rejected,
        ..CompileStats::default()
    };
    let mut shards = Vec::new();
    for patterns in patterns.chunks(SHARD_PATTERNS) {
        shards.extend(build_pair(patterns, &mut stats));
    }
    Ok((catalog, shards, stats))
}

fn canonical_outcome(
    catalog: &[CatalogPattern],
    batches: &[SourceBatch],
    materialized: &[Vec<u8>],
    mut triggers: Vec<Vec<usize>>,
) -> ScanOutcome {
    let mut findings = Vec::new();
    for ids in &mut triggers {
        ids.sort_unstable();
        ids.dedup();
    }
    for ((batch, bytes), ids) in batches.iter().zip(materialized).zip(&triggers) {
        let text = std::str::from_utf8(bytes).expect("benchmark input must remain valid UTF-8");
        for &pattern_id in ids {
            for matched in catalog[pattern_id].canonical.find_iter(text) {
                if let Some((source_from, source_to)) =
                    batch.map_span(matched.start(), matched.end())
                {
                    findings.push(Finding {
                        pattern_id,
                        source_id: batch.source_id,
                        from: source_from,
                        to: source_to,
                    });
                }
            }
        }
    }
    findings.sort_unstable();
    findings.dedup();
    ScanOutcome { triggers, findings }
}

fn scan_block(
    catalog: &[CatalogPattern],
    shards: &[DatabaseShard],
    batches: &[SourceBatch],
) -> Result<ScanOutcome, Box<dyn std::error::Error>> {
    let materialized: Vec<Vec<u8>> = batches.iter().map(SourceBatch::materialize).collect();
    let mut triggers = vec![Vec::new(); batches.len()];
    for shard in shards {
        let scratch = shard.block.alloc_scratch()?;
        for (ids, bytes) in triggers.iter_mut().zip(&materialized) {
            shard
                .block
                .scan(bytes, &scratch, |id, _from, _to, _flags| {
                    ids.push(id as usize);
                    Matching::Continue
                })?;
        }
    }
    Ok(canonical_outcome(catalog, batches, &materialized, triggers))
}

fn scan_vectored(
    catalog: &[CatalogPattern],
    shards: &[DatabaseShard],
    batches: &[SourceBatch],
) -> Result<ScanOutcome, Box<dyn std::error::Error>> {
    let materialized: Vec<Vec<u8>> = batches.iter().map(SourceBatch::materialize).collect();
    let mut triggers = vec![Vec::new(); batches.len()];
    for shard in shards {
        let scratch = shard.vectored.alloc_scratch()?;
        for (batch, ids) in batches.iter().zip(&mut triggers) {
            shard
                .vectored
                .scan(batch.buffers(), &scratch, |id, _from, _to, _flags| {
                    ids.push(id as usize);
                    Matching::Continue
                })?;
        }
    }
    Ok(canonical_outcome(catalog, batches, &materialized, triggers))
}

fn correctness_gate() -> Result<(), Box<dyn std::error::Error>> {
    let expressions = [
        "KH_BOUNDARY_[A-Z]{8}",
        "KH_EMPTY_[A-Z]{8}",
        "KH_GAP_[A-Z]{8}",
        "KH_FILE_[A-Z]{8}",
        "KH_SEP_[A-Z]{8}",
    ];
    let catalog: Vec<CatalogPattern> = expressions
        .iter()
        .enumerate()
        .map(|(id, expression)| {
            compile_catalog_pattern(id, expression).expect("fixed correctness pattern must compile")
        })
        .collect();
    let patterns: Vec<Pattern> = catalog
        .iter()
        .map(|pattern| pattern.hyperscan.clone())
        .collect();
    let mut stats = CompileStats::default();
    let shards = build_pair(&patterns, &mut stats);
    assert_eq!(shards.len(), 1, "correctness patterns must form one shard");

    let contiguous = b"aaKH_BOUNDARY_ABCDEFGHzzKH_EMPTY_ABCDEFGHend";
    let boundary_start = 2usize;
    let empty_start = contiguous
        .windows(b"KH_EMPTY_ABCDEFGH".len())
        .position(|window| window == b"KH_EMPTY_ABCDEFGH")
        .expect("fixed empty-buffer fixture");
    let batches = vec![
        SourceBatch {
            source_id: 0,
            parts: vec![
                Part {
                    bytes: contiguous[..9].to_vec(),
                    kind: PartKind::Data {
                        source_id: 0,
                        source_offset: 0,
                    },
                },
                Part {
                    bytes: contiguous[9..30].to_vec(),
                    kind: PartKind::Data {
                        source_id: 0,
                        source_offset: 9,
                    },
                },
                Part {
                    bytes: Vec::new(),
                    kind: PartKind::Data {
                        source_id: 0,
                        source_offset: 30,
                    },
                },
                Part {
                    bytes: contiguous[30..].to_vec(),
                    kind: PartKind::Data {
                        source_id: 0,
                        source_offset: 30,
                    },
                },
            ],
        },
        SourceBatch {
            source_id: 1,
            parts: vec![
                Part {
                    bytes: b"KH_GAP_".to_vec(),
                    kind: PartKind::Data {
                        source_id: 1,
                        source_offset: 0,
                    },
                },
                Part {
                    bytes: b"KH_SEP_ABCDEFGH".to_vec(),
                    kind: PartKind::Separator,
                },
                Part {
                    bytes: b"ABCDEFGH".to_vec(),
                    kind: PartKind::Data {
                        source_id: 1,
                        source_offset: 4096,
                    },
                },
            ],
        },
        SourceBatch {
            source_id: 2,
            parts: vec![Part {
                bytes: b"prefix KH_FILE_".to_vec(),
                kind: PartKind::Data {
                    source_id: 2,
                    source_offset: 0,
                },
            }],
        },
        SourceBatch {
            source_id: 3,
            parts: vec![Part {
                bytes: b"ABCDEFGH suffix".to_vec(),
                kind: PartKind::Data {
                    source_id: 3,
                    source_offset: 0,
                },
            }],
        },
    ];
    let expected = vec![
        Finding {
            pattern_id: 0,
            source_id: 0,
            from: boundary_start,
            to: boundary_start + b"KH_BOUNDARY_ABCDEFGH".len(),
        },
        Finding {
            pattern_id: 1,
            source_id: 0,
            from: empty_start,
            to: empty_start + b"KH_EMPTY_ABCDEFGH".len(),
        },
    ];
    let block = scan_block(&catalog, &shards, &batches)?;
    let vectored = scan_vectored(&catalog, &shards, &batches)?;
    assert_eq!(
        block, vectored,
        "vectored trigger or finding parity changed"
    );
    assert_eq!(block.findings, expected, "canonical exact spans changed");
    assert_eq!(
        block.triggers[0],
        vec![0, 1],
        "cross-buffer triggers changed"
    );
    assert_eq!(
        block.triggers[1],
        vec![4],
        "gap or separator trigger semantics changed"
    );
    assert!(
        block.triggers[2].is_empty() && block.triggers[3].is_empty(),
        "independent sources formed a cross-file trigger"
    );
    Ok(())
}

fn source_payload(size: usize) -> Vec<u8> {
    const FILLER: &[u8] = b"fn process_record(input: &Record) -> usize { input.fields.len() }\n";
    const SECRET: &[u8] = b"const token = \"sk_live_0123456789abcdefghijklmnopqrstuv\";\n";
    let mut bytes = Vec::with_capacity(size + FILLER.len());
    let mut since_secret = 0usize;
    while bytes.len() < size {
        if since_secret >= 64 * KIB {
            bytes.extend_from_slice(SECRET);
            since_secret = 0;
        } else {
            bytes.extend_from_slice(FILLER);
            since_secret += FILLER.len();
        }
    }
    bytes.truncate(size);
    bytes
}

fn large_batch(size: usize) -> SourceBatch {
    let source = source_payload(size);
    let mut parts = Vec::new();
    let mut offset = 0usize;
    let mut chunk_index = 0usize;
    let mut source_gap = 0usize;
    while offset < source.len() {
        let end = (offset + 64 * KIB).min(source.len());
        let split = offset + (end - offset) / 2;
        parts.push(Part {
            bytes: source[offset..split].to_vec(),
            kind: PartKind::Data {
                source_id: 0,
                source_offset: offset + source_gap,
            },
        });
        if chunk_index % 5 == 2 {
            parts.push(Part {
                bytes: GAP_SEPARATOR.to_vec(),
                kind: PartKind::Separator,
            });
        } else {
            parts.push(Part {
                bytes: Vec::new(),
                kind: PartKind::Data {
                    source_id: 0,
                    source_offset: split + source_gap,
                },
            });
        }
        parts.push(Part {
            bytes: source[split..end].to_vec(),
            kind: PartKind::Data {
                source_id: 0,
                source_offset: if chunk_index % 5 == 2 {
                    split + source_gap + SOURCE_GAP_BYTES
                } else {
                    split + source_gap
                },
            },
        });
        if chunk_index % 5 == 2 {
            source_gap += SOURCE_GAP_BYTES;
        }
        offset = end;
        chunk_index += 1;
    }
    SourceBatch {
        source_id: 0,
        parts,
    }
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn measure(
    catalog: &[CatalogPattern],
    shards: &[DatabaseShard],
    batches: &[SourceBatch],
    iters: usize,
    vectored: bool,
) -> Result<(Duration, ScanOutcome), Box<dyn std::error::Error>> {
    let expected = if vectored {
        scan_vectored(catalog, shards, batches)?
    } else {
        scan_block(catalog, shards, batches)?
    };
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let started = Instant::now();
        let outcome = if vectored {
            scan_vectored(catalog, shards, batches)?
        } else {
            scan_block(catalog, shards, batches)?
        };
        samples.push(started.elapsed());
        assert_eq!(outcome, expected, "benchmark scan became nondeterministic");
        std::hint::black_box(outcome);
    }
    Ok((median(samples), expected))
}

fn report_cache_cost(shards: &[DatabaseShard]) -> Result<(), Box<dyn std::error::Error>> {
    let serialize_block_started = Instant::now();
    let block_bytes: Vec<Vec<u8>> = shards
        .iter()
        .map(|shard| shard.block.serialize().map(|bytes| bytes.to_vec()))
        .collect::<Result<_, _>>()?;
    let serialize_block = serialize_block_started.elapsed();

    let serialize_vectored_started = Instant::now();
    let vectored_bytes: Vec<Vec<u8>> = shards
        .iter()
        .map(|shard| shard.vectored.serialize().map(|bytes| bytes.to_vec()))
        .collect::<Result<_, _>>()?;
    let serialize_vectored = serialize_vectored_started.elapsed();

    let deserialize_block_started = Instant::now();
    let block_cached: Vec<BlockDatabase> = block_bytes
        .iter()
        .map(|bytes| bytes.as_slice().deserialize::<Block>())
        .collect::<Result<_, _>>()?;
    let deserialize_block = deserialize_block_started.elapsed();

    let deserialize_vectored_started = Instant::now();
    let vectored_cached: Vec<VectoredDatabase> = vectored_bytes
        .iter()
        .map(|bytes| bytes.as_slice().deserialize::<Vectored>())
        .collect::<Result<_, _>>()?;
    let deserialize_vectored = deserialize_vectored_started.elapsed();
    std::hint::black_box((block_cached, vectored_cached));

    println!(
        "cache block: bytes={} serialize={:?} deserialize={:?}",
        block_bytes.iter().map(Vec::len).sum::<usize>(),
        serialize_block,
        deserialize_block
    );
    println!(
        "cache vectored: bytes={} serialize={:?} deserialize={:?}",
        vectored_bytes.iter().map(Vec::len).sum::<usize>(),
        serialize_vectored,
        deserialize_vectored
    );
    Ok(())
}

fn env_positive_usize(name: &str, default: usize) -> Result<usize, io::Error> {
    let Some(raw) = env::var_os(name) else {
        return Ok(default);
    };
    let raw = raw.into_string().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} is not Unicode"),
        )
    })?;
    let value = raw.parse::<usize>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name}={raw:?} must be a positive integer: {error}"),
        )
    })?;
    if value == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be greater than zero"),
        ));
    }
    Ok(value)
}

fn env_sizes() -> Result<Vec<usize>, io::Error> {
    let Some(raw) = env::var_os("KH_HS_VECTOR_SIZES_MIB") else {
        return Ok(DEFAULT_SIZES_MIB.to_vec());
    };
    let raw = raw.into_string().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "KH_HS_VECTOR_SIZES_MIB is not Unicode",
        )
    })?;
    let mut sizes = Vec::new();
    for item in raw.split(',') {
        let size = item.trim().parse::<usize>().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("KH_HS_VECTOR_SIZES_MIB contains {item:?}: {error}"),
            )
        })?;
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "KH_HS_VECTOR_SIZES_MIB values must be greater than zero",
            ));
        }
        sizes.push(size);
    }
    if sizes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "KH_HS_VECTOR_SIZES_MIB must contain at least one size",
        ));
    }
    Ok(sizes)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    correctness_gate()?;
    let iters = env_positive_usize("KH_HS_VECTOR_ITERS", DEFAULT_ITERS)?;
    let sizes = env_sizes()?;
    let (catalog, shards, stats) = compile_catalog()?;
    assert_eq!(
        stats.block_only, 0,
        "vectored mode rejected {} pattern(s) accepted by block mode; candidate cannot match the canonical Hyperscan pattern set",
        stats.block_only
    );
    assert!(
        shards.len() > 1,
        "catalog must exercise Hyperscan shard fanout"
    );
    println!("=== benchmark-only Hyperscan vectored candidate ===");
    println!(
        "patterns_prepared={} prepare_rejected={} both_modes_rejected={} block_only={} vectored_only={} shards={} paired_probe_block_compile={:?} paired_probe_vectored_compile={:?}",
        catalog.len(),
        stats.prepare_rejected,
        stats.both_rejected,
        stats.block_only,
        stats.vectored_only,
        shards.len(),
        stats.block,
        stats.vectored
    );
    report_cache_cost(&shards)?;
    println!("size | parts | findings | block median | vectored median | vectored/block");
    for size_mib in sizes {
        let size = size_mib.checked_mul(MIB).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "benchmark size overflows usize",
            )
        })?;
        let batch = large_batch(size);
        let parts = batch.parts.len();
        let batches = [batch];
        let (block, canonical) = measure(&catalog, &shards, &batches, iters, false)?;
        let (vectored, candidate) = measure(&catalog, &shards, &batches, iters, true)?;
        assert_eq!(
            candidate, canonical,
            "vectored candidate changed canonical findings at {size_mib} MiB"
        );
        let ratio = vectored.as_secs_f64() / block.as_secs_f64();
        println!(
            "{size_mib:>4} | {parts:>5} | {:>8} | {:>12?} | {:>15?} | {ratio:>14.3}",
            canonical.findings.len(),
            block,
            vectored
        );
    }
    println!("candidate remains benchmark-only; this run does not modify autoroute");
    Ok(())
}
