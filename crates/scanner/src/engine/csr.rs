//! `CsrU32`: compressed-sparse-row index table, extracted from `engine/mod.rs`
//! (Law 5, 500-LOC ceiling). A flattened, `u32`-narrowed replacement for the
//! `Vec<Vec<usize>>` detector-side index maps. Re-exported `pub(crate)` from
//! `mod.rs` so the `CompiledScanner` field types and builders resolve
//! `super::CsrU32` unchanged. Pure move, no behaviour change.

/// Compressed-sparse-row (CSR) index table: a flattened replacement for a
/// `Vec<Vec<usize>>` whose rows are pattern/literal indices.
///
/// The detector-side index maps (`prefix_propagation`, `same_prefix_patterns`,
/// `phase2_keyword_to_patterns`, and the SIMD prefilter's index map) are each
/// indexed parallel to the ~1000+ AC literals / phase-2 patterns. Stored as
/// `Vec<Vec<usize>>` that is ~1000+ separate heap allocations per table, each
/// inner `Vec` carrying a 24-byte (ptr+len+cap) header plus capacity slack -
/// even for the overwhelmingly common empty or single-element row. That
/// fragments the heap, forces pointer-chasing on the hot lookup path (every
/// row a separate cacheline), and wastes 8-byte `usize` where the values are
/// corpus-bounded indices that fit in `u32`.
///
/// CSR collapses each table to exactly two allocations: `data` holds every
/// row concatenated, and `offsets` (length `n + 1`) records where each row
/// starts, so `row(i) == &data[offsets[i]..offsets[i + 1]]`. Empty rows cost
/// zero data bytes instead of a header, element width halves to `u32`, and
/// lookups are contiguous. Builders emit flat `(row, value)` pairs so the
/// production construction path never allocates temporary per-row vectors.
/// Reads go through [`CsrU32::get`], mirroring the slice API the old table exposed.
#[derive(Clone, Debug, Default)]
pub(crate) struct CsrU32 {
    /// All rows concatenated, in row order.
    data: Box<[u32]>,
    /// `offsets[i]..offsets[i + 1]` is the slice of `data` for row `i`.
    /// Always non-empty once built: a table of `n` rows has `n + 1` offsets.
    offsets: Box<[u32]>,
}

impl CsrU32 {
    /// Build from flat `(row, value)` pairs without allocating one vector per
    /// logical row. Pair order within each row is preserved.
    pub(crate) fn from_pairs(
        row_count: usize,
        pairs: impl IntoIterator<Item = (usize, usize)>,
    ) -> Self {
        assert!(
            row_count <= u32::MAX as usize,
            "CSR row count exceeds the u32 offset representation"
        );
        let mut pairs = pairs
            .into_iter()
            .map(|(row, value)| {
                assert!(row < row_count, "CSR pair row {row} exceeds {row_count}");
                assert!(
                    value <= u32::MAX as usize,
                    "CSR value exceeds the u32 representation"
                );
                (row, value as u32)
            })
            .collect::<Vec<_>>();
        pairs.sort_by_key(|(row, _)| *row);

        let mut data = Vec::with_capacity(pairs.len());
        let mut offsets = Vec::with_capacity(row_count + 1);
        offsets.push(0);
        let mut cursor = 0;
        for row in 0..row_count {
            while cursor < pairs.len() && pairs[cursor].0 == row {
                data.push(pairs[cursor].1);
                cursor += 1;
            }
            offsets.push(data.len() as u32);
        }
        debug_assert_eq!(cursor, pairs.len());
        Self {
            data: data.into_boxed_slice(),
            offsets: offsets.into_boxed_slice(),
        }
    }

    /// Row `i` as a contiguous slice, or `None` when `i` is out of range.
    /// Replaces `Vec::get(i) -> Option<&Vec<usize>>` on the hot lookup path.
    #[inline]
    pub(crate) fn get(&self, i: usize) -> Option<&[u32]> {
        let start = *self.offsets.get(i)? as usize;
        let end = *self.offsets.get(i + 1)? as usize;
        Some(&self.data[start..end])
    }

    /// Number of logical rows in the table.
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    /// Whether the table has no logical rows.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate logical rows without exposing the offset representation.
    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = &[u32]> {
        (0..self.len()).map(|index| &self[index])
    }

    pub(crate) fn storage_lengths(&self) -> (usize, usize) {
        (self.data.len(), self.offsets.len())
    }
}

impl std::ops::Index<usize> for CsrU32 {
    type Output = [u32];

    #[inline]
    fn index(&self, i: usize) -> &[u32] {
        let start = self.offsets[i] as usize;
        let end = self.offsets[i + 1] as usize;
        &self.data[start..end]
    }
}
