//! Bias-fused cooperative tiled matmul builder + Cat-A wrapper.

use vyre::ir::{BufferAccess, BufferDecl, DataType, Program};
use vyre_foundation::ir::model::expr::GeneratorRef;
use vyre_primitives::math::semiring_gemm::OP_ID as SEMIRING_GEMM_OP_ID;

use crate::builder::{check_tensors, BuildOptions};
use crate::region::{wrap, wrap_child};
use crate::tensor_ref::{TensorRef, TensorRefError};

use super::body::cooperative_matmul_body;
use super::mma_body::cooperative_matmul_body_mma;
use super::shape::{output_tile_shape, padded_tile_lane_count, MatrixShape, TileShape};

const OP_ID_BIAS: &str = "vyre-libs::math::matmul_bias_tiled";

/// Typed Cat-A builder for [`matmul_bias_tiled`].
#[derive(Debug, Clone)]
pub struct MatmulBiasTiled {
    a: TensorRef,
    b: TensorRef,
    bias: TensorRef,
    out: TensorRef,
    tile: u32,
    options: BuildOptions,
}

impl MatmulBiasTiled {
    /// Start a builder. `tile` splits the k axis for register-reuse.
    #[must_use]
    pub fn new(a: TensorRef, b: TensorRef, bias: TensorRef, out: TensorRef, tile: u32) -> Self {
        Self {
            a,
            b,
            bias,
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
    /// Same shape-coherence + name-uniqueness errors as [`super::super::MatmulBias`].
    pub fn build(self) -> Result<Program, TensorRefError> {
        let dtype = self.a.dtype.clone();
        check_tensors(
            OP_ID_BIAS,
            &[
                (&self.a, dtype.clone()),
                (&self.b, dtype.clone()),
                (&self.bias, dtype.clone()),
                (&self.out, dtype.clone()),
            ],
        )?;
        if self.tile == 0 {
            return Err(TensorRefError::ShapeMismatch {
                name: "tile".into(),
                found: vec![0],
                expected: vec![1],
                op: OP_ID_BIAS,
            });
        }
        if self.a.shape.len() != 2
            || self.b.shape.len() != 2
            || self.bias.shape.len() != 1
            || self.out.shape.len() != 2
        {
            return Err(TensorRefError::ShapeMismatch {
                name: "a/b/bias/out".into(),
                found: vec![],
                expected: vec![0, 0],
                op: OP_ID_BIAS,
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
                op: OP_ID_BIAS,
            });
        }
        if self.bias.shape[0] != n {
            return Err(TensorRefError::ShapeMismatch {
                name: self.bias.name.as_str().to_string(),
                found: self.bias.shape.to_vec(),
                expected: vec![n],
                op: OP_ID_BIAS,
            });
        }
        if self.out.shape.as_ref() != [m, n] {
            return Err(TensorRefError::ShapeMismatch {
                name: self.out.name.as_str().to_string(),
                found: self.out.shape.to_vec(),
                expected: vec![m, n],
                op: OP_ID_BIAS,
            });
        }
        let program = matmul_bias_tiled_program(
            self.a.name_str(),
            self.b.name_str(),
            self.bias.name_str(),
            self.out.name_str(),
            m,
            k,
            n,
            self.tile,
            self.options.workgroup_size.unwrap_or([16, 16, 1]),
            self.options.region_generator.unwrap_or(OP_ID_BIAS),
            dtype,
            "matmul_a_tile",
            "matmul_b_tile",
        )?;
        Ok(program)
    }
}

/// Back-compat wrapper; panics on contract violation.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn matmul_bias_tiled(
    a: &str,
    b: &str,
    bias: &str,
    out: &str,
    m: u32,
    k: u32,
    n: u32,
    tile: u32,
) -> Program {
    MatmulBiasTiled::new(
        TensorRef::u32_2d(a, m, k),
        TensorRef::u32_2d(b, k, n),
        TensorRef::u32_1d(bias, n),
        TensorRef::u32_2d(out, m, n),
        tile,
    )
    .build()
    .unwrap_or_else(|err| {
        crate::builder::invalid_output_program(
            OP_ID_BIAS,
            out,
            DataType::U32,
            format!("Fix: {err}"),
        )
    })
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
fn matmul_bias_tiled_program(
    a: &str,
    b: &str,
    bias: &str,
    out: &str,
    m: u32,
    k: u32,
    n: u32,
    tile: u32,
    workgroup: [u32; 3],
    generator: &'static str,
    dtype: DataType,
    a_tile_name: &str,
    b_tile_name: &str,
) -> Result<Program, TensorRefError> {
    if tile == 0 {
        return Err(TensorRefError::ShapeMismatch {
            name: "tile".into(),
            found: vec![0],
            expected: vec![1],
            op: OP_ID_BIAS,
        });
    }
    // MMA fast path: M16N8K16 fragment with F16 inputs.
    let use_mma = dtype == DataType::F16 && tile == 16 && m % 16 == 0 && n % 8 == 0;

    let (a_tile_count, b_tile_count, padded_out_count, dispatch_wg, kernel_body) = if use_mma {
        // Force a flat 32-thread workgroup; each lane contributes MMA fragment work.
        let mma_wg = [32, 1, 1];
        let mma_out_rows = 16u32;
        let mma_out_cols = 8u32;
        let mma_lanes = 32u32;
        let mma_a_tile =
            mma_out_rows
                .checked_mul(tile)
                .ok_or_else(|| TensorRefError::ElementCountOverflow {
                    name: "matmul_bias_a_tile".to_string(),
                    shape: vec![mma_out_rows, tile],
                })?;
        let mma_b_tile =
            tile.checked_mul(mma_out_cols)
                .ok_or_else(|| TensorRefError::ElementCountOverflow {
                    name: "matmul_bias_b_tile".to_string(),
                    shape: vec![tile, mma_out_cols],
                })?;
        let out_count = m
            .checked_mul(n)
            .ok_or_else(|| TensorRefError::ElementCountOverflow {
                name: out.to_string(),
                shape: vec![m, n],
            })?;
        let body_nodes = cooperative_matmul_body_mma(
            a,
            b,
            Some(bias),
            out,
            MatrixShape { m, k, n },
            TileShape {
                k_tile: tile,
                out_rows: mma_out_rows,
                out_cols: mma_out_cols,
                x_lanes: mma_lanes,
                y_lanes: 1,
                lanes: mma_lanes,
                a_values: mma_a_tile,
                b_values: mma_b_tile,
            },
            dtype.clone(),
            a_tile_name,
            b_tile_name,
        );
        (mma_a_tile, mma_b_tile, out_count, mma_wg, body_nodes)
    } else {
        let (out_tile_cols, out_tile_rows, lane_count) = output_tile_shape(workgroup)?;
        let a_tile_count = out_tile_rows.checked_mul(tile).ok_or_else(|| {
            TensorRefError::ElementCountOverflow {
                name: "matmul_bias_a_tile".to_string(),
                shape: vec![out_tile_rows, tile],
            }
        })?;
        let b_tile_count = tile.checked_mul(out_tile_cols).ok_or_else(|| {
            TensorRefError::ElementCountOverflow {
                name: "matmul_bias_b_tile".to_string(),
                shape: vec![tile, out_tile_cols],
            }
        })?;
        let padded_out_count =
            padded_tile_lane_count(m, n, out_tile_rows, out_tile_cols, lane_count)?;
        let flat_workgroup = [lane_count, 1, 1];
        let body_nodes = cooperative_matmul_body(
            a,
            b,
            Some(bias),
            out,
            MatrixShape { m, k, n },
            TileShape {
                k_tile: tile,
                out_rows: out_tile_rows,
                out_cols: out_tile_cols,
                x_lanes: lane_count,
                y_lanes: 1,
                lanes: lane_count,
                a_values: a_tile_count,
                b_values: b_tile_count,
            },
        );
        (
            a_tile_count,
            b_tile_count,
            padded_out_count,
            flat_workgroup,
            body_nodes,
        )
    };

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
    let logical_out_count =
        m.checked_mul(n)
            .ok_or_else(|| TensorRefError::ElementCountOverflow {
                name: out.to_string(),
                shape: vec![m, n],
            })?;
    let element_size = dtype
        .size_bytes()
        .ok_or_else(|| TensorRefError::ElementCountOverflow {
            name: out.to_string(),
            shape: vec![m, n],
        })?;
    let logical_output_bytes = (logical_out_count as usize)
        .checked_mul(element_size)
        .ok_or_else(|| TensorRefError::ElementCountOverflow {
            name: out.to_string(),
            shape: vec![m, n],
        })?;
    let body = vec![wrap_child(
        SEMIRING_GEMM_OP_ID,
        GeneratorRef {
            name: generator.to_string(),
        },
        kernel_body,
    )];

    Ok(Program::wrapped(
        vec![
            BufferDecl::storage(a, 0, BufferAccess::ReadOnly, dtype.clone()).with_count(a_count),
            BufferDecl::storage(b, 1, BufferAccess::ReadOnly, dtype.clone()).with_count(b_count),
            BufferDecl::storage(bias, 2, BufferAccess::ReadOnly, dtype.clone()).with_count(n),
            BufferDecl::workgroup(a_tile_name, a_tile_count, dtype.clone()),
            BufferDecl::workgroup(b_tile_name, b_tile_count, dtype.clone()),
            BufferDecl::output(out, 3, dtype)
                .with_count(padded_out_count)
                .with_output_byte_range(0..logical_output_bytes),
        ],
        dispatch_wg,
        vec![wrap(generator, body, None)],
    ))
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::math::matmul_bias_tiled",
        build: || matmul_bias_tiled("a", "b", "bias", "out", 2, 2, 2, 2),
        test_inputs: Some(|| {

            vec![vec![
                crate::test_support::byte_pack::u32_bytes(&[1, 2, 3, 4]),
                crate::test_support::byte_pack::u32_bytes(&[5, 6, 7, 8]),
                crate::test_support::byte_pack::u32_bytes(&[10, 20]),
            ]]
        }),
        expected_output: Some(|| {

            // out[0] = 19 + 10 = 29
            // out[1] = 22 + 20 = 42
            // out[2] = 43 + 10 = 53
            // out[3] = 50 + 20 = 70
            vec![vec![crate::test_support::byte_pack::u32_bytes(&[29, 42, 53, 70])]]
        }),
        category: Some("math"),
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

    fn expected_bias_matmul(
        a: &[u32],
        b: &[u32],
        bias: &[u32],
        m: u32,
        k: u32,
        n: u32,
    ) -> Vec<u32> {
        let mut out = Vec::with_capacity((m * n) as usize);
        for row in 0..m {
            for col in 0..n {
                let mut acc = bias[col as usize];
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
    fn matmul_bias_tiled_rejects_zero_tile_without_panic() {
        let error = MatmulBiasTiled::new(
            TensorRef::u32_2d("a", 2, 2),
            TensorRef::u32_2d("b", 2, 2),
            TensorRef::u32_1d("bias", 2),
            TensorRef::u32_2d("out", 2, 2),
            0,
        )
        .build()
        .expect_err("zero tile must be a build error");

        assert!(
            error.to_string().contains("tile"),
            "zero-tile bias error must identify the invalid tile dimension: {error}"
        );
    }

    #[test]
    fn cooperative_matmul_bias_tiled_matches_reference_on_edge_tiles() {
        let (m, k, n, tile) = (17_u32, 19_u32, 13_u32, 8_u32);
        let mut seed = 0x5A5A_0717;
        let a = pseudo_random_words((m * k) as usize, &mut seed);
        let b = pseudo_random_words((k * n) as usize, &mut seed);
        let bias = pseudo_random_words(n as usize, &mut seed);
        let program = MatmulBiasTiled::new(
            TensorRef::u32_2d("a", m, k),
            TensorRef::u32_2d("b", k, n),
            TensorRef::u32_1d("bias", n),
            TensorRef::u32_2d("out", m, n),
            tile,
        )
        .with_workgroup_size([8, 8, 1])
        .build()
        .expect("Fix: edge-tiled matmul+bias dimensions are valid.");

        let actual = run_program(
            &program,
            vec![
                crate::test_support::byte_pack::u32_bytes(&a),
                crate::test_support::byte_pack::u32_bytes(&b),
                crate::test_support::byte_pack::u32_bytes(&bias),
                output_zero_bytes(&program),
            ],
        );
        let expected = expected_bias_matmul(&a, &b, &bias, m, k, n);
        assert_eq!(&actual[..expected.len()], expected.as_slice());
    }

    #[test]
    fn matmul_bias_tiled_mma_path_uses_workgroup_tile_coordinates() {
        let program = MatmulBiasTiled::new(
            TensorRef::f16_2d("a", 32, 16),
            TensorRef::f16_2d("b", 16, 16),
            TensorRef::f16_1d("bias", 16),
            TensorRef::f16_2d("out", 32, 16),
            16,
        )
        .build()
        .expect("Fix: F16 M16N8K16 bias tiled matmul dimensions are valid.");
        let debug = format!("{:?}", program.entry());

        assert!(
            debug.contains("tile_row_base"),
            "MMA bias tiled matmul must include workgroup row offset in output coordinates"
        );
        assert!(
            debug.contains("tile_col_base"),
            "MMA bias tiled matmul must include workgroup column offset in output coordinates"
        );
        assert_eq!(
            program.workgroup_size(),
            [32, 1, 1],
            "MMA bias tiled matmul must force the 32-lane M16N8K16 workgroup"
        );
    }
}
