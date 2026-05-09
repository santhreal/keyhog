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
//! boundary data — negligible next to the per-chunk scan cost.

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};

use super::CompiledScanner;

/// How much of each chunk's edge to include in a boundary buffer.
///
/// Picked to comfortably cover every secret shape in the embedded
/// detector corpus (longest is the JWT shape at ~600 chars; everything
/// else is < 200). 1024 bytes per side gives a 2 KiB boundary buffer
/// that fits any realistic credential plus surrounding keyword context.
const MAX_BOUNDARY: usize = 1024;

/// For each pair of adjacent chunks belonging to the same file, scan a
/// synthetic boundary buffer and append any straddle matches to the
/// per-chunk results vector for the right-hand chunk.
///
/// "Adjacent" means: same `(source_type, path)` and `b.base_offset`
/// equals `a.base_offset + a.data.len()` exactly (gapless, no overlap).
/// Overlapping chunks are intentionally skipped — the overlap region
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
    let boundary_base_offset = a.metadata.base_offset + tail_start;
    let mut buf = String::with_capacity(tail.len() + head.len());
    buf.push_str(tail);
    let seam_local = buf.len();
    buf.push_str(head);

    let boundary_chunk = Chunk {
        data: buf.into(),
        metadata: ChunkMetadata {
            base_offset: boundary_base_offset,
            ..b.metadata.clone()
        },
    };

    let boundary_matches = scanner.scan(&boundary_chunk);
    let seam_file_offset = boundary_base_offset + seam_local;

    for m in boundary_matches {
        // Keep only matches that genuinely straddle the seam — i.e. the
        // match starts in A's tail (file_offset < seam) and ends in
        // B's head (file_offset + len > seam). Anything fully on one
        // side is already covered by that chunk's own scan.
        let start = m.location.offset;
        let end = start.saturating_add(m.credential.as_ref().len());
        if !(start < seam_file_offset && end > seam_file_offset) {
            continue;
        }

        // Defensive dedup: if the per-chunk scan already produced an
        // identical (offset, credential_hash) pair (e.g. an overlap
        // case slipped through), don't double-count.
        let already_seen = per_chunk_results[ai]
            .iter()
            .chain(per_chunk_results[bi].iter())
            .any(|x| x.location.offset == m.location.offset && x.credential_hash == m.credential_hash);
        if already_seen {
            continue;
        }

        per_chunk_results[bi].push(m);
    }
}

/// Floor `index` down to the nearest UTF-8 character boundary in `text`.
/// Mirrors the unstable std `str::floor_char_boundary`.
fn floor_char_boundary(text: &str, index: usize) -> usize {
    let mut i = index.min(text.len());
    while i > 0 && !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CompiledScanner;
    use keyhog_core::{DetectorSpec, PatternSpec, Severity};

    fn make_chunk(data: String, base_offset: usize, path: &str) -> Chunk {
        Chunk {
            data: data.into(),
            metadata: ChunkMetadata {
                source_type: "test".into(),
                path: Some(path.into()),
                base_offset,
                ..Default::default()
            },
        }
    }

    fn straddle_detector() -> DetectorSpec {
        DetectorSpec {
            id: "straddle-test".into(),
            name: "Straddle Test".into(),
            service: "test".into(),
            severity: Severity::Medium,
            patterns: vec![PatternSpec {
                regex: r"STRADDLE_[A-Z0-9]{20}".into(),
                description: None,
                group: None,
            }],
            companions: Vec::new(),
            verify: None,
            keywords: vec!["STRADDLE".into()],
        }
    }

    #[test]
    fn boundary_reassembles_secret_split_across_two_contiguous_chunks() {
        let scanner = CompiledScanner::compile(vec![straddle_detector()]).unwrap();
        let secret = "STRADDLE_ABCDEFGHIJKLMNOPQRST"; // 29 chars total
        let split_at = 14; // first 14 chars in chunk A, rest in chunk B
        let pad = "x".repeat(2000);
        let mut a_data = pad.clone();
        a_data.push_str(&secret[..split_at]);
        let a_len = a_data.len();
        let mut b_data = secret[split_at..].to_string();
        b_data.push_str(&pad);

        let chunks = vec![
            make_chunk(a_data, 0, "file.txt"),
            make_chunk(b_data, a_len, "file.txt"),
        ];
        let mut per_chunk: Vec<Vec<RawMatch>> = vec![Vec::new(), Vec::new()];

        scan_chunk_boundaries(&scanner, &chunks, &mut per_chunk);

        // Match should land in chunk B's bucket (right-hand-side).
        let total: usize = per_chunk.iter().map(|v| v.len()).sum();
        assert_eq!(total, 1, "expected exactly one straddle match, got {total}");
        let m = &per_chunk[1][0];
        assert_eq!(m.credential.as_ref(), secret);
        assert_eq!(m.location.offset, pad.len());
    }

    #[test]
    fn boundary_skips_chunks_with_overlap() {
        // Overlap means the in-chunk scan already covers the seam.
        // Boundary helper must not fire here — that would double-count.
        let scanner = CompiledScanner::compile(vec![straddle_detector()]).unwrap();
        let secret = "STRADDLE_ABCDEFGHIJKLMNOPQRST";
        let pad = "x".repeat(100);

        let mut a_data = pad.clone();
        a_data.push_str(secret);
        let a_len = a_data.len();
        let mut b_data = secret.to_string();
        b_data.push_str(&pad);

        // B starts BEFORE A ends → 29-byte overlap
        let chunks = vec![
            make_chunk(a_data, 0, "file.txt"),
            make_chunk(b_data, a_len - secret.len(), "file.txt"),
        ];
        let mut per_chunk: Vec<Vec<RawMatch>> = vec![Vec::new(), Vec::new()];

        scan_chunk_boundaries(&scanner, &chunks, &mut per_chunk);
        let total: usize = per_chunk.iter().map(|v| v.len()).sum();
        assert_eq!(total, 0, "overlap case must skip boundary scan");
    }

    #[test]
    fn boundary_skips_chunks_with_gap() {
        // Missing data between chunks — can't reassemble what isn't there.
        let scanner = CompiledScanner::compile(vec![straddle_detector()]).unwrap();
        let chunks = vec![
            make_chunk("padding".into(), 0, "file.txt"),
            make_chunk("more padding".into(), 1000, "file.txt"),
        ];
        let mut per_chunk: Vec<Vec<RawMatch>> = vec![Vec::new(), Vec::new()];
        scan_chunk_boundaries(&scanner, &chunks, &mut per_chunk);
        assert!(per_chunk.iter().all(|v| v.is_empty()));
    }

    #[test]
    fn boundary_ignores_chunks_with_different_paths() {
        let scanner = CompiledScanner::compile(vec![straddle_detector()]).unwrap();
        let secret = "STRADDLE_ABCDEFGHIJKLMNOPQRST";
        let split = 14;
        let mut a_data = String::from("xxx");
        a_data.push_str(&secret[..split]);
        let a_len = a_data.len();
        let mut b_data = secret[split..].to_string();
        b_data.push_str("xxx");

        let chunks = vec![
            make_chunk(a_data, 0, "alice.txt"),
            make_chunk(b_data, a_len, "bob.txt"),
        ];
        let mut per_chunk: Vec<Vec<RawMatch>> = vec![Vec::new(), Vec::new()];
        scan_chunk_boundaries(&scanner, &chunks, &mut per_chunk);
        assert!(per_chunk.iter().all(|v| v.is_empty()));
    }

    #[test]
    fn boundary_dedups_against_existing_match() {
        // Pre-populate chunk B's results with an identical (offset, hash)
        // entry; the boundary scan must NOT add it again.
        let scanner = CompiledScanner::compile(vec![straddle_detector()]).unwrap();
        let secret = "STRADDLE_ABCDEFGHIJKLMNOPQRST";
        let split = 14;
        let pad = "x".repeat(50);
        let mut a_data = pad.clone();
        a_data.push_str(&secret[..split]);
        let a_len = a_data.len();
        let mut b_data = secret[split..].to_string();
        b_data.push_str(&pad);

        let chunks = vec![
            make_chunk(a_data, 0, "file.txt"),
            make_chunk(b_data, a_len, "file.txt"),
        ];

        // Run boundary once to learn the canonical match shape.
        let mut probe: Vec<Vec<RawMatch>> = vec![Vec::new(), Vec::new()];
        scan_chunk_boundaries(&scanner, &chunks, &mut probe);
        assert_eq!(probe[1].len(), 1);
        let canonical = probe[1][0].clone();

        // Pre-seed chunk B with that canonical match, then re-run.
        let mut per_chunk: Vec<Vec<RawMatch>> = vec![Vec::new(), vec![canonical]];
        scan_chunk_boundaries(&scanner, &chunks, &mut per_chunk);
        assert_eq!(per_chunk[1].len(), 1, "dedup must keep just the seeded match");
    }

    #[test]
    fn boundary_handles_single_chunk() {
        // No pairs to consider — must return cleanly without panicking.
        let scanner = CompiledScanner::compile(vec![straddle_detector()]).unwrap();
        let chunks = vec![make_chunk("alone".into(), 0, "file.txt")];
        let mut per_chunk: Vec<Vec<RawMatch>> = vec![Vec::new()];
        scan_chunk_boundaries(&scanner, &chunks, &mut per_chunk);
        assert!(per_chunk[0].is_empty());
    }
}
