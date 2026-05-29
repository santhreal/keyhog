//! Tensor-core path selection for tiled matmul.

use vyre::ir::DataType;

use super::shape::MatrixShape;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum MatmulKernelPath {
    Cooperative,
    TensorCoreM16N8K16,
}

pub(crate) fn select_matmul_kernel(
    dtype: &DataType,
    shape: MatrixShape,
    tile: u32,
) -> MatmulKernelPath {
    if *dtype == DataType::F16
        && tile == 16
        && shape.m % 16 == 0
        && shape.n % 8 == 0
        && shape.k % 16 == 0
    {
        return MatmulKernelPath::TensorCoreM16N8K16;
    }
    MatmulKernelPath::Cooperative
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tensor_core_policy_only_accepts_full_m16n8k16_tiles() {
        let mut cases = 0usize;
        for m in [1, 15, 16, 31, 32] {
            for k in [1, 15, 16, 17, 32] {
                for n in [1, 7, 8, 9, 16] {
                    for tile in [1, 8, 16, 32] {
                        let path =
                            select_matmul_kernel(&DataType::F16, MatrixShape { m, k, n }, tile);
                        let expected_mma = tile == 16 && m % 16 == 0 && n % 8 == 0 && k % 16 == 0;
                        assert_eq!(
                            path == MatmulKernelPath::TensorCoreM16N8K16,
                            expected_mma,
                            "m={m} k={k} n={n} tile={tile}"
                        );
                        cases += 1;
                    }
                }
            }
        }
        assert_eq!(cases, 500);
    }
}
