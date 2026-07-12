//! Cross-chunk window-boundary secret reassembly.
//!
//! When a single file is too large for one scan window (the FilesystemSource
//! splits files >64 MiB into overlapping mmap windows), a secret that
//! straddles a window boundary may be split across two adjacent chunks.
//! In-chunk scanning misses it. The overlap region the FilesystemSource
//! provides catches secrets shorter than the overlap; for the rare longer
//! secret (or for sources that produce gapless contiguous chunks without
//! overlap), this module synthesises a thin boundary buffer from the tail
//! of chunk A and the head of chunk B, scans it, and reports any matches
//! that genuinely straddle the seam.
//!
//! For bounded detector regexes, the boundary buffer width is derived from the
//! scanner's compiled pattern sources. If an active generation path is unbounded
//! for this pair (an unbounded detector regex or entropy fallback), the scanner
//! uses the full adjacent chunks instead of pretending a fixed seam width is a
//! guarantee.

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use regex_syntax::ast::{Ast, RepetitionKind, RepetitionRange};

use super::{absolute_line, absolute_offset, floor_char_boundary, CompiledScanner};
use crate::types::CompiledPattern;

/// Cross-seam reassembly cap for the unbounded / entropy boundary context.
///
/// When an active generator has no finite match width (an unbounded detector
/// regex, or entropy on a non-source path) the seam buffer would otherwise
/// splice ALL of chunk A onto ALL of chunk B and full-rescan a ~2x-chunk buffer
/// for EVERY adjacent pair — O(pairs x chunk_bytes) plus large transient
/// allocations on a many-chunk gapless producer. A straddling secret only needs
/// a bounded reassembly window: any credential/line longer than this on one
/// side is already visible whole inside that chunk's own in-chunk scan. Sized
/// at the FilesystemSource window overlap so the seam covers exactly the
/// straddle range the overlap design already assumes catchable.
pub(crate) const MAX_BOUNDARY_SEAM_BYTES: usize = crate::types::WINDOW_OVERLAP_BYTES;

/// Scanner-derived cross-seam context requirement for compiled detector regexes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BoundaryContextBytes {
    /// Every compiled detector regex has a finite maximum match width.
    Bounded(usize),
    /// At least one active detector regex can match an arbitrary-width span.
    FullAdjacentChunks,
}

pub(crate) fn derive_pattern_boundary_context<'a>(
    patterns: impl IntoIterator<Item = &'a CompiledPattern>,
) -> BoundaryContextBytes {
    let mut max_bound = 0usize;
    for pattern in patterns {
        let Some(bound) = regex_match_byte_upper_bound(pattern.regex.as_str()) else {
            return BoundaryContextBytes::FullAdjacentChunks;
        };
        max_bound = max_bound.max(bound);
    }
    BoundaryContextBytes::Bounded(max_bound)
}

pub(crate) fn regex_match_byte_upper_bound(source: &str) -> Option<usize> {
    let ast = match regex_syntax::ast::parse::Parser::new().parse(source) {
        Ok(ast) => ast,
        Err(_) => return None, // LAW10: regex bound parse failure => full adjacent-pair seam scan, recall-preserving
    };
    ast_match_byte_upper_bound(&ast)
}

fn ast_match_byte_upper_bound(ast: &Ast) -> Option<usize> {
    match ast {
        Ast::Empty(_) | Ast::Flags(_) | Ast::Assertion(_) => Some(0),
        Ast::Literal(literal) => Some(literal.c.len_utf8()),
        Ast::Dot(_) | Ast::ClassUnicode(_) | Ast::ClassPerl(_) | Ast::ClassBracketed(_) => Some(4),
        Ast::Group(group) => ast_match_byte_upper_bound(&group.ast),
        Ast::Alternation(alternation) => {
            let mut max_bound = 0usize;
            for ast in &alternation.asts {
                max_bound = max_bound.max(ast_match_byte_upper_bound(ast)?);
            }
            Some(max_bound)
        }
        Ast::Concat(concat) => {
            let mut total = 0usize;
            for ast in &concat.asts {
                total = total.saturating_add(ast_match_byte_upper_bound(ast)?);
            }
            Some(total)
        }
        Ast::Repetition(repetition) => {
            let inner = ast_match_byte_upper_bound(&repetition.ast)?;
            let max_repetitions = match repetition.op.kind {
                RepetitionKind::ZeroOrOne => 1,
                RepetitionKind::ZeroOrMore | RepetitionKind::OneOrMore => return None,
                RepetitionKind::Range(RepetitionRange::Exactly(n)) => n,
                RepetitionKind::Range(RepetitionRange::Bounded(_, n)) => n,
                RepetitionKind::Range(RepetitionRange::AtLeast(_)) => return None,
            };
            Some(inner.saturating_mul(max_repetitions as usize))
        }
    }
}

/// For each pair of adjacent chunks belonging to the same file, scan a
/// synthetic boundary buffer and append any straddle matches to the
/// per-chunk results vector for the right-hand chunk.
///
/// "Adjacent" means: same `(source_type, path)` and `b.base_offset`
/// equals `a.base_offset + a.data.len()` exactly (gapless, no overlap).
/// Overlapping chunks are intentionally skipped - the overlap region
/// already gives the in-chunk scan everything it needs to catch secrets
/// up to `overlap` bytes long, and any secret longer than that would
/// also be visible inside the right-hand chunk on its own.
///
/// Mutates `per_chunk_results` in place. Boundary findings are dedup'd
/// against (offset, credential_hash) entries already in the chunks'
/// own results so the same secret isn't reported twice.
pub(crate) fn scan_chunk_boundaries(
    scanner: &CompiledScanner,
    chunks: &[Chunk],
    per_chunk_results: &mut [Vec<RawMatch>],
) {
    if chunks.len() < 2 {
        return;
    }
    if chunks.len() != per_chunk_results.len() {
        crate::telemetry::record_boundary_result_cardinality_mismatch();
        return;
    }

    // Group chunk indices by (source_type, path). Indices, not refs,
    // because we need to mutate `per_chunk_results[bi]` later.
    use std::collections::HashMap;
    let mut groups: HashMap<(&str, &str), Vec<usize>> = HashMap::new();
    for (i, c) in chunks.iter().enumerate() {
        let Some(path) = c.metadata.path.as_deref() else {
            continue;
        };
        groups
            .entry((c.metadata.source_type.as_ref(), path))
            .or_default()
            .push(i);
    }

    for (_, mut indices) in groups {
        if indices.len() < 2 {
            continue;
        }
        // Sort by base_offset so window k+1 always sits to the right
        // of window k. Producers (FilesystemSource) emit in order
        // already, but a multi-source pipeline could re-order.
        indices.sort_by_key(|&i| chunks[i].metadata.base_offset);

        for w in indices.windows(2) {
            let (ai, bi) = (w[0], w[1]);
            scan_one_pair(scanner, &chunks[ai], &chunks[bi], ai, bi, per_chunk_results);
        }
    }
}

fn scan_one_pair(
    scanner: &CompiledScanner,
    a: &Chunk,
    b: &Chunk,
    ai: usize,
    bi: usize,
    per_chunk_results: &mut [Vec<RawMatch>],
) {
    if ai >= per_chunk_results.len() || bi >= per_chunk_results.len() {
        crate::telemetry::record_boundary_result_cardinality_mismatch();
        return;
    }

    let a_bytes = a.data.as_ref().as_bytes();
    let b_bytes = b.data.as_ref().as_bytes();
    let a_end = a.metadata.base_offset.saturating_add(a_bytes.len());

    // Only contiguous-with-no-overlap pairs need the boundary buffer.
    // - Overlap: chunk B already contains the seam region; in-chunk
    //   scan handles it.
    // - Gap: data between chunks isn't available to reassemble.
    if a_end != b.metadata.base_offset {
        return;
    }

    if a_bytes.is_empty() || b_bytes.is_empty() {
        return;
    }

    let path = b.metadata.path.as_deref().or(a.metadata.path.as_deref());
    let context = boundary_context_for_pair(scanner, path);

    // Pull the trailing slice of A and the leading slice of B, snapped to UTF-8
    // boundaries since `Chunk.data` is `&str`-shaped (we splice bytes back into
    // a String below). For unbounded active generators, use the whole adjacent
    // pair and scan the synthetic buffer as one unit below.
    let context_bytes = match context {
        BoundaryContextBytes::Bounded(bytes) => bytes,
        BoundaryContextBytes::FullAdjacentChunks => MAX_BOUNDARY_SEAM_BYTES,
    };
    let tail_start = a_bytes.len().saturating_sub(context_bytes);
    let tail_start = floor_char_boundary(a.data.as_ref(), tail_start);
    let tail = &a.data.as_ref()[tail_start..];

    let head_end = b_bytes.len().min(context_bytes);
    let head_end = floor_char_boundary(b.data.as_ref(), head_end);
    let head = &b.data.as_ref()[..head_end];

    if tail.is_empty() || head.is_empty() {
        return;
    }

    // Build the synthetic boundary chunk. file-level base_offset =
    // start position of the tail in the original file, so any match
    // offset inside the boundary buffer round-trips back to the
    // correct file coordinate via the standard
    // `local_offset + base_offset` reporting path.
    //
    // Caller-supplied chunk metadata sets `base_offset`; a malformed source
    // reporting one near `usize::MAX` would misattribute the finding. The shared
    // `absolute_offset` guard skips this (impossible-on-real-input) case.
    let Some(boundary_base_offset) = absolute_offset(a.metadata.base_offset, tail_start) else {
        return;
    };
    let mut buf = String::with_capacity(tail.len() + head.len());
    buf.push_str(tail);
    let seam_local = buf.len();
    buf.push_str(head);

    // Absolute base line of the seam buffer: lines before chunk A's start
    // plus the lines in A that precede `tail_start` (where the buffer
    // begins). `..b.metadata.clone()` would wrongly inherit B's base line,
    // but the seam buffer starts inside A's tail, so derive it from A. This
    // is the line analog of `boundary_base_offset = a.base_offset + tail_start`.
    let boundary_base_line = absolute_line(
        a.metadata.base_line,
        memchr::memchr_iter(b'\n', &a_bytes[..tail_start]).count(),
    );
    let boundary_chunk = Chunk {
        data: buf.into(),
        metadata: ChunkMetadata {
            base_offset: boundary_base_offset,
            base_line: boundary_base_line,
            ..b.metadata.clone()
        },
    };

    let boundary_matches = scan_boundary_chunk_whole(scanner, &boundary_chunk);
    let Some(seam_file_offset) = absolute_offset(boundary_base_offset, seam_local) else {
        return;
    };

    for m in boundary_matches {
        // Accept any match from the boundary buffer that is not already
        // covered by in-chunk scanning of either A or B.  The previous
        // "straddle" check (`credential.start < seam && credential.end >
        // seam`) was too strict: for context-anchored detectors
        // (e.g. `HEROKU_API_KEY=<uuid>`, `DD_API_KEY=<hex32>`) the regex
        // anchor prefix can be split across the seam while the captured
        // credential group lives entirely in B's region.  In that case
        // `credential.start >= seam_file_offset`, the straddle check fired
        // false, and the finding was silently dropped — a recall loss.
        //
        // The straddle check's original purpose (avoid double-counting
        // matches already visible inside chunk A or B on their own) is
        // fully served by the `already_seen` dedup below: for any match
        // entirely within A's tail or B's head the in-chunk scanner
        // already produced it at the identical (offset, detector_id,
        // credential_hash) triple, and `already_seen` suppresses the
        // duplicate.  No extra position filter is needed.
        //
        // We retain a single exclusion: matches whose credential ends at
        // or before the seam are fully inside A's contribution to the
        // buffer and would have been caught by A's own in-chunk scan.
        // While `already_seen` would suppress them too, the early
        // continue keeps the dedup loop tight.
        let start = m.location.offset;
        let end = start.saturating_add(m.credential.as_ref().len());
        if end <= seam_file_offset {
            // Entirely inside A's tail region – A's own in-chunk scan has
            // this; skip without consulting `already_seen`.
            continue;
        }

        // Defensive dedup: if the per-chunk scan already produced an
        // identical (offset, detector_id, credential_hash) triple (e.g.
        // an overlap case slipped through), don't double-count.
        //
        // The key MUST include detector_id. Two distinct detectors can
        // legitimately match the same bytes at the same offset (e.g. a
        // generic `shopify-access-token` and the specific
        // `shopify-admin-api-token` both claim `shpat_<32hex>`). The
        // plain per-chunk scan reports BOTH; a (offset, hash)-only key
        // would push the first boundary match then suppress every other
        // detector's match of the same span as "already seen", making
        // the boundary path drop findings the in-chunk path keeps.
        // Order-dependent and silent. detector_id in the key restores
        // parity with the in-chunk scan.
        let already_seen = per_chunk_results[ai]
            .iter()
            .chain(per_chunk_results[bi].iter())
            .any(|x| {
                x.location.offset == m.location.offset
                    && x.detector_id == m.detector_id
                    && x.credential_hash == m.credential_hash
            });
        if already_seen {
            continue;
        }

        per_chunk_results[bi].push(m);
    }
}

fn boundary_context_for_pair(
    scanner: &CompiledScanner,
    path: Option<&str>,
) -> BoundaryContextBytes {
    if matches!(
        scanner.pattern_boundary_context,
        BoundaryContextBytes::FullAdjacentChunks
    ) {
        return BoundaryContextBytes::FullAdjacentChunks;
    }

    if scanner.config.entropy_enabled
        && crate::entropy::is_entropy_appropriate(path, scanner.config.entropy_in_source_files)
    {
        return BoundaryContextBytes::FullAdjacentChunks;
    }

    scanner.pattern_boundary_context
}

fn scan_boundary_chunk_whole(scanner: &CompiledScanner, chunk: &Chunk) -> Vec<RawMatch> {
    // Boundary reassembly is a shared correctness tail, not a second routing
    // decision. Choosing from live hardware here let an explicit batch backend
    // silently change at the seam and made results depend on host state. Keep
    // the small synthetic buffer on the deterministic reference backend; the
    // CLI's persisted router remains the sole owner of workload routing.
    let mut matches = scanner.scan_inner(chunk, crate::hw_probe::ScanBackend::CpuFallback, None);
    scanner.post_process_matches(chunk, &mut matches, None);
    matches
}
