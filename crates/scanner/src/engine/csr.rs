//! `CsrU32`: compressed-sparse-row index table, extracted from `engine/mod.rs`
//! (Law 5, 500-LOC ceiling). A flattened, `u32`-narrowed replacement for the
//! `Vec<Vec<usize>>` detector-side index maps. Re-exported `pub(crate)` from
//! `mod.rs` so the `CompiledScanner` field types and builders resolve
//! `super::CsrU32` unchanged. Pure move, no behaviour change.

/// Compressed-sparse-row (CSR) index table: a flattened replacement for a
/// `Vec<Vec<usize>>` whose rows are pattern/literal indices.
///
/// The detector-side index maps (`prefix_propagation`, `same_prefix_patterns`,
/// `phase2_keyword_to_patterns`, and the simd `hs_index_map`) are each
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
/// lookups are contiguous. Build it once from the existing
/// `Vec<Vec<usize>>`-producing builders via `From` (or directly with
/// `from_rows`); reads go through [`CsrU32::get`], mirroring the slice/`Vec`
/// API the old field type exposed.
#[derive(Clone, Debug, Default)]
pub(crate) struct CsrU32 {
    /// All rows concatenated, in row order.
    data: Vec<u32>,
    /// `offsets[i]..offsets[i + 1]` is the slice of `data` for row `i`.
    /// Always non-empty once built: a table of `n` rows has `n + 1` offsets.
    offsets: Vec<u32>,
}

impl CsrU32 {
    /// Build a CSR table from per-row index lists in a single pass.
    ///
    /// Accepts any iterator of rows so the existing builders can feed their
    /// `Vec<Vec<usize>>` (or borrowed slices) straight in without an
    /// intermediate allocation. Values are narrowed to `u32`; a corpus index
    /// can never exceed the pattern count, which is far below `u32::MAX`.
    pub(crate) fn from_rows<R, I>(rows: R) -> Self
    where
        R: IntoIterator<Item = I>,
        I: IntoIterator<Item = usize>,
    {
        let mut data = Vec::new();
        let mut offsets = vec![0u32];
        for row in rows {
            for v in row {
                data.push(v as u32);
            }
            offsets.push(data.len() as u32);
        }
        Self { data, offsets }
    }

    /// Row `i` as a contiguous slice, or `None` when `i` is out of range.
    /// Replaces `Vec::get(i) -> Option<&Vec<usize>>` on the hot lookup path.
    #[inline]
    pub(crate) fn get(&self, i: usize) -> Option<&[u32]> {
        let start = *self.offsets.get(i)? as usize;
        let end = *self.offsets.get(i + 1)? as usize;
        Some(&self.data[start..end])
    }
}

impl From<Vec<Vec<usize>>> for CsrU32 {
    fn from(rows: Vec<Vec<usize>>) -> Self {
        Self::from_rows(rows)
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
