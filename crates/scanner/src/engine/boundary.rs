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
//! The boundary buffer is bounded (`MAX_BOUNDARY` bytes per side) so the
//! cost is independent of chunk size: at most ~2 KiB of data per pair of
//! adjacent chunks. With N chunks per file, that's `(N-1) * 2 KiB` of
//! boundary data - negligible next to the per-chunk scan cost.

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use regex_syntax::ast::{Ast, RepetitionKind, RepetitionRange};

use super::{floor_char_boundary, CompiledScanner};

/// How much of each chunk's edge to include in a boundary buffer.
///
/// Picked to comfortably cover every secret shape in the embedded
/// detector corpus (longest is the JWT shape at ~600 chars; everything
/// else is < 200). 1024 bytes per side gives a 2 KiB boundary buffer
/// that fits any realistic credential plus surrounding keyword context.
const MAX_BOUNDARY: usize = 1024;

pub(crate) fn regex_match_byte_upper_bound(source: &str) -> Option<usize> {
    let ast = match regex_syntax::ast::parse::Parser::new().parse(source) {
        Ok(ast) => ast,
        Err(_) => return None,
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
pub fn scan_chunk_boundaries(
    scanner: &CompiledScanner,
    chunks: &[Chunk],
    per_chunk_results: &mut [Vec<RawMatch>],
) {
    if chunks.len() < 2 {
        return;
    }
    debug_assert_eq!(chunks.len(), per_chunk_results.len());

    // Group chunk indices by (source_type, path). Indices, not refs,
    // because we need to mutate `per_chunk_results[bi]` later.
    use std::collections::HashMap;
    let mut groups: HashMap<(&str, &str), Vec<usize>> = HashMap::new();
    for (i, c) in chunks.iter().enumerate() {
        let Some(path) = c.metadata.path.as_deref() else {
            continue;
        };
        groups
            .entry((c.metadata.source_type.as_str(), path))
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
    // kimi-engine audit: in release builds only a debug_assert protects
    // the `per_chunk_results[ai]` / `[bi]` accesses below. Verify here
    // and bail silently rather than panicking on a slice mismatch.
    if ai >= per_chunk_results.len() || bi >= per_chunk_results.len() {
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

    // Pull the trailing slice of A and the leading slice of B, snapped to
    // UTF-8 boundaries since `Chunk.data` is `&str`-shaped (we splice
    // bytes back into a String below).
    let tail_start = a_bytes.len().saturating_sub(MAX_BOUNDARY);
    let tail_start = floor_char_boundary(a.data.as_ref(), tail_start);
    let tail = &a.data.as_ref()[tail_start..];

    let head_end = b_bytes.len().min(MAX_BOUNDARY);
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
    // kimi-engine audit: caller-supplied chunk metadata sets
    // `base_offset`. A malformed source that reports `base_offset`
    // near `usize::MAX` would overflow the additions below - debug
    // panic, release wrap to a bogus offset that misattributes the
    // finding. checked_add + early return keeps the scan moving and
    // simply skips the (impossible-on-real-input) boundary case.
    let Some(boundary_base_offset) = a.metadata.base_offset.checked_add(tail_start) else {
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
    let boundary_base_line = a
        .metadata
        .base_line
        .saturating_add(memchr::memchr_iter(b'\n', &a_bytes[..tail_start]).count());
    let boundary_chunk = Chunk {
        data: buf.into(),
        metadata: ChunkMetadata {
            base_offset: boundary_base_offset,
            base_line: boundary_base_line,
            ..b.metadata.clone()
        },
    };

    let boundary_matches = scanner.scan(&boundary_chunk);
    let Some(seam_file_offset) = boundary_base_offset.checked_add(seam_local) else {
        return;
    };

    for m in boundary_matches {
        // Keep only matches that genuinely straddle the seam - i.e. the
        // match starts in A's tail (file_offset < seam) and ends in
        // B's head (file_offset + len > seam). Anything fully on one
        // side is already covered by that chunk's own scan.
        let start = m.location.offset;
        let end = start.saturating_add(m.credential.as_ref().len());
        if !(start < seam_file_offset && end > seam_file_offset) {
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
