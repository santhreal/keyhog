//! Geometry helpers shared by the plain and bias-fused tiled matmul
//! variants.

use vyre::ir::Expr;

use crate::tensor_ref::TensorRefError;

#[derive(Copy, Clone)]
pub(super) struct MatrixShape {
    pub(super) m: u32,
    pub(super) k: u32,
    pub(super) n: u32,
}

#[derive(Copy, Clone)]
pub(super) struct TileShape {
    pub(super) k_tile: u32,
    pub(super) out_rows: u32,
    pub(super) out_cols: u32,
    pub(super) lanes: u32,
    pub(super) a_values: u32,
    pub(super) b_values: u32,
}

pub(super) fn output_tile_shape(workgroup: [u32; 3]) -> Result<(u32, u32, u32), TensorRefError> {
    let out_cols = workgroup[0].max(1);
    let out_rows = workgroup[1].max(1).saturating_mul(workgroup[2].max(1));
    let lanes =
        out_cols
            .checked_mul(out_rows)
            .ok_or_else(|| TensorRefError::ElementCountOverflow {
                name: "matmul_workgroup".to_string(),
                shape: vec![out_rows, out_cols],
            })?;
    Ok((out_cols, out_rows, lanes))
}

pub(super) fn padded_tile_lane_count(
    m: u32,
    n: u32,
    out_rows: u32,
    out_cols: u32,
    lanes: u32,
) -> Result<u32, TensorRefError> {
    let row_tiles = m.div_ceil(out_rows);
    let col_tiles = n.div_ceil(out_cols);
    row_tiles
        .checked_mul(col_tiles)
        .and_then(|tiles| tiles.checked_mul(lanes))
        .ok_or_else(|| TensorRefError::ElementCountOverflow {
            name: "matmul_tiled_launch_lanes".to_string(),
            shape: vec![row_tiles, col_tiles, lanes],
        })
}

pub(super) fn in_output_bounds(row: Expr, col: Expr, shape: MatrixShape) -> Expr {
    Expr::and(
        Expr::lt(row, Expr::u32(shape.m)),
        Expr::lt(col, Expr::u32(shape.n)),
    )
}
