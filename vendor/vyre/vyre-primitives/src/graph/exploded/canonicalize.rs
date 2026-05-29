/// Sort each CSR row in place after validating row ranges.
pub fn canonicalize_csr_within_rows_in_place(
    row_ptr: &[u32],
    col_idx: &mut [u32],
) -> Result<(), String> {
    for window in row_ptr.windows(2) {
        let start = window[0] as usize;
        let end = window[1] as usize;
        if start > end || end > col_idx.len() {
            return Err(format!(
                "Fix: exploded IFDS CSR row range {start}..{end} exceeds col_idx.len()={}.",
                col_idx.len()
            ));
        }
        col_idx[start..end].sort_unstable();
    }
    Ok(())
}

/// Return a row-canonical CSR copy.
#[must_use]
pub fn canonicalize_csr_within_rows(row_ptr: &[u32], col_idx: &[u32]) -> (Vec<u32>, Vec<u32>) {
    let mut canonical_col = col_idx.to_vec();
    if canonicalize_csr_within_rows_in_place(row_ptr, &mut canonical_col).is_err() {
        canonical_col.copy_from_slice(col_idx);
    }
    (row_ptr.to_vec(), canonical_col)
}
