//! Plain (no-bias) cooperative tiled matmul builder + Cat-A wrapper.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Program};
use vyre_foundation::ir::model::expr::GeneratorRef;
use vyre_primitives::math::semiring_gemm::OP_ID as SEMIRING_GEMM_OP_ID;

use crate::builder::{check_tensors, BuildOptions};
use crate::region::{wrap, wrap_child};
use crate::tensor_ref::{TensorRef, TensorRefError};

use super::body::cooperative_matmul_body;
use super::shape::{output_tile_shape, padded_tile_lane_count, MatrixShape, TileShape};

pub(super) const OP_ID: &str = "vyre-libs::math::matmul_tiled";

/// Typed Cat-A builder for [`matmul_tiled`].
#[derive(Debug, Clone)]
pub struct MatmulTiled {
    a: TensorRef,
    b: TensorRef,
    out: TensorRef,
    tile: u32,
    options: BuildOptions,
}

impl MatmulTiled {
    /// Start a builder. `tile` splits the k axis for register-reuse.
    #[must_use]
    pub fn new(a: TensorRef, b: TensorRef, out: TensorRef, tile: u32) -> Self {
        Self {
            a,
            b,
            out,
            tile,
            options: BuildOptions::default(),
        }
    }

    /// Override workgroup size.
    #[must_use]
    pub fn with_workgroup_size(mut self, size: [u32; 3]) -> Self {
        self.options = self.options.with_workgroup_size(size);
        self
    }

    /// Override region generator name.
    #[must_use]
    pub fn with_region_generator(mut self, name: &'static str) -> Self {
        self.options = self.options.with_region_generator(name);
        self
    }

    /// Stamp tenant id.
    #[must_use]
    pub fn with_tenant_id(mut self, tenant_id: u32) -> Self {
        self.options = self.options.with_tenant_id(tenant_id);
        self
    }

    /// Validate + materialize.
    ///
    /// # Errors
    ///
    /// Same shape-coherence + name-uniqueness errors as [`super::super::Matmul`].
    pub fn build(self) -> Result<Program, TensorRefError> {
        check_tensors(
            OP_ID,
            &[
                (&self.a, DataType::U32),
                (&self.b, DataType::U32),
                (&self.out, DataType::U32),
            ],
        )?;
        if self.tile == 0 {
            return Err(TensorRefError::ShapeMismatch {
                name: "tile".into(),
                found: vec![0],
                expected: vec![1],
                op: OP_ID,
            });
        }
        if self.a.shape.len() != 2 || self.b.shape.len() != 2 || self.out.shape.len() != 2 {
            return Err(TensorRefError::ShapeMismatch {
                name: "a/b/out".into(),
                found: vec![],
                expected: vec![0, 0],
                op: OP_ID,
            });
        }
        let m = self.a.shape[0];
        let k = self.a.shape[1];
        let n = self.b.shape[1];
        if self.b.shape[0] != k {
            return Err(TensorRefError::ShapeMismatch {
                name: self.b.name.as_str().to_string(),
                found: self.b.shape.to_vec(),
                expected: vec![k, n],
                op: OP_ID,
            });
        }
        if self.out.shape.as_ref() != [m, n] {
            return Err(TensorRefError::ShapeMismatch {
                name: self.out.name.as_str().to_string(),
                found: self.out.shape.to_vec(),
                expected: vec![m, n],
                op: OP_ID,
            });
        }
        let program = matmul_tiled_program(
            self.a.name_str(),
            self.b.name_str(),
            self.out.name_str(),
            m,
            k,
            n,
            self.tile,
            self.options.workgroup_size.unwrap_or([16, 16, 1]),
            self.options.region_generator.unwrap_or(OP_ID),
        )?;
        Ok(program)
    }
}

/// Back-compat wrapper; panics on contract violation.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn matmul_tiled(a: &str, b: &str, out: &str, m: u32, k: u32, n: u32, tile: u32) -> Program {
    MatmulTiled::new(
        TensorRef::u32_2d(a, m, k),
        TensorRef::u32_2d(b, k, n),
        TensorRef::u32_2d(out, m, n),
        tile,
    )
    .build()
    .unwrap_or_else(|err| {
        crate::builder::invalid_output_program(OP_ID, out, DataType::U32, format!("Fix: {err}"))
    })
}

#[allow(clippy::too_many_arguments)]
fn matmul_tiled_program(
    a: &str,
    b: &str,
    out: &str,
    m: u32,
    k: u32,
    n: u32,
    tile: u32,
    workgroup: [u32; 3],
    generator: &'static str,
) -> Result<Program, TensorRefError> {
    if tile == 0 {
        return Err(TensorRefError::ShapeMismatch {
            name: "tile".into(),
            found: vec![0],
            expected: vec![1],
            op: OP_ID,
        });
    }
    let (out_tile_cols, out_tile_rows, lane_count) = output_tile_shape(workgroup)?;
    let a_tile_count =
        out_tile_rows
            .checked_mul(tile)
            .ok_or_else(|| TensorRefError::ElementCountOverflow {
                name: "matmul_a_tile".to_string(),
                shape: vec![out_tile_rows, tile],
            })?;
    let b_tile_count =
        tile.checked_mul(out_tile_cols)
            .ok_or_else(|| TensorRefError::ElementCountOverflow {
                name: "matmul_b_tile".to_string(),
                shape: vec![tile, out_tile_cols],
            })?;
    let a_count = m
        .checked_mul(k)
        .ok_or_else(|| TensorRefError::ElementCountOverflow {
            name: a.to_string(),
            shape: vec![m, k],
        })?;
    let b_count = k
        .checked_mul(n)
        .ok_or_else(|| TensorRefError::ElementCountOverflow {
            name: b.to_string(),
            shape: vec![k, n],
        })?;
    let out_count = m
        .checked_mul(n)
        .ok_or_else(|| TensorRefError::ElementCountOverflow {
            name: out.to_string(),
            shape: vec![m, n],
        })?;
    let padded_out_count = padded_tile_lane_count(m, n, out_tile_rows, out_tile_cols, lane_count)?;

    let body = vec![wrap_child(
        SEMIRING_GEMM_OP_ID,
        GeneratorRef {
            name: generator.to_string(),
        },
        cooperative_matmul_body(
            a,
            b,
            None,
            out,
            MatrixShape { m, k, n },
            TileShape {
                k_tile: tile,
                out_rows: out_tile_rows,
                out_cols: out_tile_cols,
                lanes: lane_count,
                a_values: a_tile_count,
                b_values: b_tile_count,
            },
        ),
    )];

    Ok(Program::wrapped(
        vec![
            BufferDecl::storage(a, 0, BufferAccess::ReadOnly, DataType::U32).with_count(a_count),
            BufferDecl::storage(b, 1, BufferAccess::ReadOnly, DataType::U32).with_count(b_count),
            BufferDecl::workgroup("matmul_a_tile", a_tile_count, DataType::U32),
            BufferDecl::workgroup("matmul_b_tile", b_tile_count, DataType::U32),
            BufferDecl::output(out, 2, DataType::U32)
                .with_count(padded_out_count)
                .with_output_byte_range(0..((out_count as usize) * core::mem::size_of::<u32>())),
        ],
        [lane_count, 1, 1],
        vec![wrap(generator, body, None)],
    ))
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::math::matmul_tiled",
        build: || matmul_tiled("a", "b", "out", 2, 2, 2, 2),
        // V7-TEST-001: deterministic fixture — 2x2 * 2x2 = 2x2.
        //   A = [[1, 2], [3, 4]], B = [[5, 6], [7, 8]]
        //   out[row*2+col] = sum_k A[row*2+k] * B[k*2+col]
        //   out[0] = 1*5 + 2*7 = 19
        //   out[1] = 1*6 + 2*8 = 22
        //   out[2] = 3*5 + 4*7 = 43
        //   out[3] = 3*6 + 4*8 = 50
        test_inputs: Some(|| {

            vec![vec![
                crate::test_support::byte_pack::u32_bytes(&[1, 2, 3, 4]),
                crate::test_support::byte_pack::u32_bytes(&[5, 6, 7, 8]),
                vec![0u8; 4 * 4],
            ]]
        }),
        expected_output: Some(|| {

            vec![vec![crate::test_support::byte_pack::u32_bytes(&[19, 22, 43, 50])]]
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_reference::value::Value;

    fn decode_u32_words(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks_exact(core::mem::size_of::<u32>())
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect()
    }

    fn output_zero_bytes(program: &Program) -> Vec<u8> {
        let output = program
            .buffers()
            .iter()
            .find(|buffer| buffer.is_output())
            .expect("Fix: tiled matmul test program must declare an output buffer.");
        vec![0u8; (output.count() as usize) * core::mem::size_of::<u32>()]
    }

    fn run_program(program: &Program, inputs: Vec<Vec<u8>>) -> Vec<u32> {
        let values = inputs.into_iter().map(Value::from).collect::<Vec<_>>();
        let outputs = vyre_reference::reference_eval(program, &values)
            .expect("Fix: tiled matmul must execute in the reference interpreter.");
        decode_u32_words(&outputs[0].to_bytes())
    }

    fn expected_matmul(a: &[u32], b: &[u32], m: u32, k: u32, n: u32) -> Vec<u32> {
        let mut out = Vec::with_capacity((m * n) as usize);
        for row in 0..m {
            for col in 0..n {
                let mut acc = 0u32;
                for kk in 0..k {
                    let av = a[(row * k + kk) as usize];
                    let bv = b[(kk * n + col) as usize];
                    acc = acc.wrapping_add(av.wrapping_mul(bv));
                }
                out.push(acc);
            }
        }
        out
    }

    fn pseudo_random_words(count: usize, seed: &mut u32) -> Vec<u32> {
        (0..count)
            .map(|_| {
                *seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *seed
            })
            .collect()
    }

    #[test]
    fn matmul_tiled_rejects_zero_tile_without_panic() {
        let error = MatmulTiled::new(
            TensorRef::u32_2d("a", 2, 2),
            TensorRef::u32_2d("b", 2, 2),
            TensorRef::u32_2d("out", 2, 2),
            0,
        )
        .build()
        .expect_err("zero tile must be a build error");

        assert!(
            error.to_string().contains("tile"),
            "zero-tile error must identify the invalid tile dimension: {error}"
        );
    }

    #[test]
    fn cooperative_matmul_tiled_matches_reference_on_edge_tiles() {
        let (m, k, n, tile) = (17_u32, 19_u32, 13_u32, 8_u32);
        let mut seed = 0xA5A5_0131;
        let a = pseudo_random_words((m * k) as usize, &mut seed);
        let b = pseudo_random_words((k * n) as usize, &mut seed);
        let program = MatmulTiled::new(
            TensorRef::u32_2d("a", m, k),
            TensorRef::u32_2d("b", k, n),
            TensorRef::u32_2d("out", m, n),
            tile,
        )
        .with_workgroup_size([8, 8, 1])
        .build()
        .expect("Fix: edge-tiled matmul dimensions are valid.");

        let actual = run_program(
            &program,
            vec![
                crate::test_support::byte_pack::u32_bytes(&a),
                crate::test_support::byte_pack::u32_bytes(&b),
                output_zero_bytes(&program),
            ],
        );
        assert_eq!(actual, expected_matmul(&a, &b, m, k, n));
    }
}
