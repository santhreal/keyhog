//! Live CUDA parity for packed INT4 quantized primitives.

use vyre_driver::DispatchConfig;
use vyre_driver_cuda::CudaBackend;

fn pack_i4x8(values: &[i32]) -> Vec<u32> {
    let mut out = vec![0_u32; values.len().div_ceil(8)];
    for (index, &value) in values.iter().enumerate() {
        let clamped = value.clamp(-8, 7);
        let nibble = (clamped as i8 as u8) & 0x0f;
        let word = index / 8;
        let shift = (index % 8) * 4;
        out[word] |= u32::from(nibble) << shift;
    }
    out
}

fn extract_i4(packed: &[u32], lane: usize) -> i32 {
    let word = packed.get(lane / 8).copied().unwrap_or(0);
    let nibble = ((word >> ((lane % 8) * 4)) & 0x0f) as i32;
    if nibble & 0x8 == 0 {
        nibble
    } else {
        nibble - 16
    }
}

fn dot_scaled_oracle(
    lhs_packed: &[u32],
    rhs_packed: &[u32],
    lhs_scale: f32,
    rhs_scale: f32,
    lane_count: u32,
) -> f32 {
    let mut acc = 0.0_f32;
    for lane in 0..lane_count as usize {
        acc += extract_i4(lhs_packed, lane) as f32 * extract_i4(rhs_packed, lane) as f32;
    }
    acc * lhs_scale * rhs_scale
}

fn dot_i32_oracle(lhs_packed: &[u32], rhs_packed: &[u32], lane_count: u32) -> i32 {
    let mut acc = 0_i32;
    for lane in 0..lane_count as usize {
        acc += extract_i4(lhs_packed, lane) * extract_i4(rhs_packed, lane);
    }
    acc
}

fn pack_i4_matrix_rows(rows: &[Vec<i32>]) -> Vec<u32> {
    let cols = rows.first().map_or(0, Vec::len);
    let words_per_row = cols.div_ceil(8);
    let mut out = Vec::with_capacity(rows.len() * words_per_row);
    for row in rows {
        let mut packed = pack_i4x8(row);
        packed.resize(words_per_row, 0);
        out.extend_from_slice(&packed);
    }
    out
}

fn matvec_scaled_oracle(
    weights_packed: &[u32],
    x: &[f32],
    scales: &[f32],
    rows: u32,
    cols: u32,
) -> Vec<f32> {
    let words_per_row = (cols as usize).div_ceil(8);
    let mut out = vec![0.0_f32; rows as usize];
    for row in 0..rows as usize {
        let mut acc = 0.0_f32;
        let row_words = &weights_packed[row * words_per_row..];
        for col in 0..cols as usize {
            acc += extract_i4(row_words, col) as f32 * x[col];
        }
        out[row] = acc * scales[row];
    }
    out
}

fn batched_matvec_scaled_oracle(
    weights_packed: &[u32],
    x_batches: &[f32],
    scales: &[f32],
    batch: u32,
    rows: u32,
    cols: u32,
) -> Vec<f32> {
    let mut out = Vec::with_capacity((batch * rows) as usize);
    for batch_index in 0..batch as usize {
        let x_start = batch_index * cols as usize;
        let x_end = x_start + cols as usize;
        out.extend(matvec_scaled_oracle(
            weights_packed,
            &x_batches[x_start..x_end],
            scales,
            rows,
            cols,
        ));
    }
    out
}

fn batched_packed_matmul_scaled_oracle(
    weights_packed: &[u32],
    activation_batches_packed: &[u32],
    row_scales: &[f32],
    batch_scales: &[f32],
    batch: u32,
    rows: u32,
    cols: u32,
) -> Vec<f32> {
    let words_per_row = (cols as usize).div_ceil(8);
    let mut out = vec![0.0_f32; (batch * rows) as usize];
    for batch_index in 0..batch as usize {
        let activation_words = &activation_batches_packed[batch_index * words_per_row..];
        for row in 0..rows as usize {
            let weight_words = &weights_packed[row * words_per_row..];
            let mut acc = 0.0_f32;
            for col in 0..cols as usize {
                acc +=
                    extract_i4(weight_words, col) as f32 * extract_i4(activation_words, col) as f32;
            }
            out[batch_index * rows as usize + row] =
                acc * row_scales[row] * batch_scales[batch_index];
        }
    }
    out
}

fn batched_packed_matmul_top1_scaled_oracle(
    weights_packed: &[u32],
    activation_batches_packed: &[u32],
    row_scales: &[f32],
    batch_scales: &[f32],
    batch: u32,
    rows: u32,
    cols: u32,
) -> (Vec<f32>, Vec<u32>) {
    let logits = batched_packed_matmul_scaled_oracle(
        weights_packed,
        activation_batches_packed,
        row_scales,
        batch_scales,
        batch,
        rows,
        cols,
    );
    let mut scores = vec![f32::MIN; batch as usize];
    let mut indices = vec![0_u32; batch as usize];
    for batch_index in 0..batch as usize {
        let row_start = batch_index * rows as usize;
        for row in 0..rows as usize {
            let score = logits[row_start + row];
            if score > scores[batch_index] {
                scores[batch_index] = score;
                indices[batch_index] = row as u32;
            }
        }
    }
    (scores, indices)
}

fn pack_u32(words: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 4);
    for word in words {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

fn pack_f32(words: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(words.len() * 4);
    for word in words {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

fn read_f32(bytes: &[u8]) -> f32 {
    f32::from_le_bytes(
        bytes
            .get(0..4)
            .expect("Fix: CUDA INT4 scaled dot must emit one f32.")
            .try_into()
            .expect("Fix: f32 CUDA output must be exactly four bytes."),
    )
}

fn read_i32(bytes: &[u8]) -> i32 {
    i32::from_le_bytes(
        bytes
            .get(0..4)
            .expect("Fix: CUDA INT4 dot must emit one i32.")
            .try_into()
            .expect("Fix: i32 CUDA output must be exactly four bytes."),
    )
}

fn read_f32_vec(bytes: &[u8], count: usize) -> Vec<f32> {
    bytes
        .chunks_exact(4)
        .take(count)
        .map(|chunk| f32::from_le_bytes(chunk.try_into().expect("Fix: f32 chunk is four bytes.")))
        .collect()
}

fn generated_i4_values(len: usize, seed: u32) -> Vec<i32> {
    let mut state = seed ^ 0x9E37_79B9;
    (0..len)
        .map(|index| {
            state = state
                .wrapping_mul(1_664_525)
                .wrapping_add(1_013_904_223)
                .rotate_left((index % 17) as u32);
            ((state >> 28) as i32) - 8
        })
        .collect()
}

fn generated_f32_values(len: usize, seed: u32) -> Vec<f32> {
    let mut state = seed ^ 0xA5A5_5A5A;
    (0..len)
        .map(|index| {
            state = state
                .wrapping_mul(747_796_405)
                .wrapping_add(2_891_336_453)
                .rotate_right((index % 11) as u32);
            (((state >> 27) & 0x1f) as f32 - 16.0) * 0.0625
        })
        .collect()
}

fn generated_positive_scales(len: usize, seed: u32) -> Vec<f32> {
    (0..len)
        .map(|index| 0.0625_f32 * (1 + ((seed as usize + index * 3) % 13)) as f32)
        .collect()
}

fn generated_i4_rows(rows: u32, cols: u32, seed: u32) -> Vec<Vec<i32>> {
    (0..rows)
        .map(|row| generated_i4_values(cols as usize, seed.wrapping_add(row * 97)))
        .collect()
}

fn f32_bits(values: &[f32]) -> Vec<u32> {
    values.iter().map(|value| value.to_bits()).collect()
}

#[test]
fn cuda_dispatch_matches_packed_int4_dot_i32_oracle() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let lhs_pattern = [-8, -3, -1, 0, 1, 3, 7, 6, 5, 4, 2, -2, -4, -6, -7, -5];
    let rhs_pattern = [7, 5, 3, 1, -1, -3, -5, -7, 6, 4, 2, 0, -2, -4, -6, -8];

    for lane_count in [1_u32, 7, 8, 9, 16, 31, 32, 33, 65] {
        let lhs = lhs_pattern
            .iter()
            .copied()
            .cycle()
            .take(lane_count as usize)
            .collect::<Vec<_>>();
        let rhs = rhs_pattern
            .iter()
            .copied()
            .cycle()
            .take(lane_count as usize)
            .collect::<Vec<_>>();
        let lhs_packed = pack_i4x8(&lhs);
        let rhs_packed = pack_i4x8(&rhs);
        let program = vyre_primitives::math::quantized::i4x8_dot_i32(
            "lhs", "rhs", "out", lane_count,
        );
        let outputs = backend
            .dispatch(
                &program,
                &[pack_u32(&lhs_packed), pack_u32(&rhs_packed)],
                &DispatchConfig::default(),
            )
            .expect("Fix: CUDA must execute packed INT4 dot without CPU fallback.");
        let expected = dot_i32_oracle(&lhs_packed, &rhs_packed, lane_count);
        let actual = read_i32(&outputs[0]);

        assert_eq!(actual, expected, "lane_count={lane_count}");
    }
}

#[test]
fn cuda_dispatch_matches_packed_int4_scaled_dot_oracle() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let lhs_pattern = [-8, -3, -1, 0, 1, 3, 7, 6, 5, 4, 2, -2, -4, -6, -7, -5];
    let rhs_pattern = [7, 5, 3, 1, -1, -3, -5, -7, 6, 4, 2, 0, -2, -4, -6, -8];

    for lane_count in [1_u32, 7, 8, 9, 16, 31, 32, 33, 65] {
        let lhs = lhs_pattern
            .iter()
            .copied()
            .cycle()
            .take(lane_count as usize)
            .collect::<Vec<_>>();
        let rhs = rhs_pattern
            .iter()
            .copied()
            .cycle()
            .take(lane_count as usize)
            .collect::<Vec<_>>();
        let lhs_packed = pack_i4x8(&lhs);
        let rhs_packed = pack_i4x8(&rhs);
        let lhs_scale = 0.125_f32 + (lane_count % 4) as f32 * 0.0625;
        let rhs_scale = 0.25_f32 + (lane_count % 3) as f32 * 0.125;
        let program = vyre_primitives::math::quantized::i4x8_dot_f32_scaled(
            "lhs",
            "rhs",
            "lhs_scale",
            "rhs_scale",
            "out",
            lane_count,
        );
        let outputs = backend
            .dispatch(
                &program,
                &[
                    pack_u32(&lhs_packed),
                    pack_u32(&rhs_packed),
                    pack_f32(&[lhs_scale]),
                    pack_f32(&[rhs_scale]),
                ],
                &DispatchConfig::default(),
            )
            .expect("Fix: CUDA must execute fused packed INT4 scaled dot without CPU fallback.");
        let expected =
            dot_scaled_oracle(&lhs_packed, &rhs_packed, lhs_scale, rhs_scale, lane_count);
        let actual = read_f32(&outputs[0]);

        assert_eq!(
            actual.to_bits(),
            expected.to_bits(),
            "lane_count={lane_count}"
        );
    }
}

#[test]
fn cuda_dispatch_matches_packed_int4_scaled_matvec_oracle() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let pattern = [-8, -3, -1, 0, 1, 3, 7, 6, 5, 4, 2, -2, -4, -6, -7, -5];

    for (rows, cols) in [
        (1_u32, 1_u32),
        (2, 7),
        (3, 8),
        (4, 9),
        (5, 17),
        (6, 33),
        (7, 65),
    ] {
        let weights = (0..rows as usize)
            .map(|row| {
                pattern
                    .iter()
                    .copied()
                    .cycle()
                    .skip(row * 3)
                    .take(cols as usize)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let x = (0..cols)
            .map(|col| (col % 13) as f32 * 0.125 - 0.75)
            .collect::<Vec<_>>();
        let scales = (0..rows)
            .map(|row| 0.125_f32 + row as f32 * 0.0625)
            .collect::<Vec<_>>();
        let weights_packed = pack_i4_matrix_rows(&weights);
        let program = vyre_primitives::math::quantized::i4x8_matvec_f32_scaled(
            "weights", "x", "scales", "out", rows, cols,
        );
        let outputs = backend
            .dispatch(
                &program,
                &[pack_u32(&weights_packed), pack_f32(&x), pack_f32(&scales)],
                &DispatchConfig::default(),
            )
            .expect("Fix: CUDA must execute fused packed INT4 scaled matvec without CPU fallback.");
        let expected = matvec_scaled_oracle(&weights_packed, &x, &scales, rows, cols);
        let actual = read_f32_vec(&outputs[0], rows as usize);

        assert_eq!(
            actual.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
            expected.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
            "rows={rows} cols={cols}"
        );
    }
}

#[test]
fn cuda_dispatch_matches_packed_int4_batched_scaled_matvec_oracle() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let pattern = [-8, -3, -1, 0, 1, 3, 7, 6, 5, 4, 2, -2, -4, -6, -7, -5];

    for (batch, rows, cols) in [
        (1_u32, 1_u32, 1_u32),
        (2, 2, 7),
        (3, 3, 8),
        (4, 4, 9),
        (5, 5, 17),
        (6, 6, 33),
        (3, 7, 65),
    ] {
        let weights = (0..rows as usize)
            .map(|row| {
                pattern
                    .iter()
                    .copied()
                    .cycle()
                    .skip(row * 5)
                    .take(cols as usize)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let x_batches = (0..batch * cols)
            .map(|index| (index % 17) as f32 * 0.0625 - 0.5)
            .collect::<Vec<_>>();
        let scales = (0..rows)
            .map(|row| 0.125_f32 + row as f32 * 0.0625)
            .collect::<Vec<_>>();
        let weights_packed = pack_i4_matrix_rows(&weights);
        let program = vyre_primitives::math::quantized::i4x8_batched_matvec_f32_scaled(
            "weights", "x", "scales", "out", batch, rows, cols,
        );
        let outputs = backend
            .dispatch(
                &program,
                &[
                    pack_u32(&weights_packed),
                    pack_f32(&x_batches),
                    pack_f32(&scales),
                ],
                &DispatchConfig::default(),
            )
            .expect(
                "Fix: CUDA must execute batched fused packed INT4 scaled matvec without CPU fallback.",
            );
        let expected =
            batched_matvec_scaled_oracle(&weights_packed, &x_batches, &scales, batch, rows, cols);
        let actual = read_f32_vec(&outputs[0], (batch * rows) as usize);

        assert_eq!(
            actual.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
            expected.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
            "batch={batch} rows={rows} cols={cols}"
        );
    }
}

#[test]

fn cuda_dispatch_matches_packed_int4_batched_scaled_matmul_oracle() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let weight_pattern = [-8, -3, -1, 0, 1, 3, 7, 6, 5, 4, 2, -2, -4, -6, -7, -5];
    let activation_pattern = [7, 5, 3, 1, -1, -3, -5, -7, 6, 4, 2, 0, -2, -4, -6, -8];

    for (batch, rows, cols) in [
        (1_u32, 1_u32, 1_u32),
        (2, 2, 7),
        (3, 3, 8),
        (4, 4, 9),
        (5, 5, 17),
        (6, 6, 33),
        (3, 7, 65),
    ] {
        let weights = (0..rows as usize)
            .map(|row| {
                weight_pattern
                    .iter()
                    .copied()
                    .cycle()
                    .skip(row * 5)
                    .take(cols as usize)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let activation_batches = (0..batch as usize)
            .map(|batch_index| {
                activation_pattern
                    .iter()
                    .copied()
                    .cycle()
                    .skip(batch_index * 7)
                    .take(cols as usize)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let row_scales = (0..rows)
            .map(|row| 0.125_f32 + row as f32 * 0.0625)
            .collect::<Vec<_>>();
        let batch_scales = (0..batch)
            .map(|batch_index| 0.25_f32 + batch_index as f32 * 0.03125)
            .collect::<Vec<_>>();
        let weights_packed = pack_i4_matrix_rows(&weights);
        let activation_batches_packed = pack_i4_matrix_rows(&activation_batches);
        let program = vyre_primitives::math::quantized::i4x8_batched_matmul_f32_scaled(
            "weights",
            "activations",
            "row_scales",
            "batch_scales",
            "out",
            batch,
            rows,
            cols,
        );
        let outputs = backend
            .dispatch(
                &program,
                &[
                    pack_u32(&weights_packed),
                    pack_u32(&activation_batches_packed),
                    pack_f32(&row_scales),
                    pack_f32(&batch_scales),
                ],
                &DispatchConfig::default(),
            )
            .expect(
                "Fix: CUDA must execute packed-activation batched INT4 matmul without CPU fallback.",
            );
        let expected = batched_packed_matmul_scaled_oracle(
            &weights_packed,
            &activation_batches_packed,
            &row_scales,
            &batch_scales,
            batch,
            rows,
            cols,
        );
        let actual = read_f32_vec(&outputs[0], (batch * rows) as usize);

        assert_eq!(
            actual.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
            expected.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
            "batch={batch} rows={rows} cols={cols}"
        );
    }
}

#[test]
fn cuda_dispatch_matches_packed_int4_batched_scaled_matmul_top1_oracle() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");
    let weight_pattern = [-8, -3, -1, 0, 1, 3, 7, 6, 5, 4, 2, -2, -4, -6, -7, -5];
    let activation_pattern = [7, 5, 3, 1, -1, -3, -5, -7, 6, 4, 2, 0, -2, -4, -6, -8];

    for (batch, rows, cols) in [
        (1_u32, 1_u32, 1_u32),
        (2, 2, 7),
        (3, 3, 8),
        (4, 4, 9),
        (5, 5, 17),
        (6, 6, 33),
        (3, 7, 65),
    ] {
        let weights = (0..rows as usize)
            .map(|row| {
                weight_pattern
                    .iter()
                    .copied()
                    .cycle()
                    .skip(row * 5)
                    .take(cols as usize)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let activation_batches = (0..batch as usize)
            .map(|batch_index| {
                activation_pattern
                    .iter()
                    .copied()
                    .cycle()
                    .skip(batch_index * 7)
                    .take(cols as usize)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let row_scales = (0..rows)
            .map(|row| 0.125_f32 + row as f32 * 0.0625)
            .collect::<Vec<_>>();
        let batch_scales = (0..batch)
            .map(|batch_index| 0.25_f32 + batch_index as f32 * 0.03125)
            .collect::<Vec<_>>();
        let weights_packed = pack_i4_matrix_rows(&weights);
        let activation_batches_packed = pack_i4_matrix_rows(&activation_batches);
        let program = vyre_primitives::math::quantized::i4x8_batched_matmul_top1_f32_scaled(
            "weights",
            "activations",
            "row_scales",
            "batch_scales",
            "out",
            batch,
            rows,
            cols,
        );
        let outputs = backend
            .dispatch(
                &program,
                &[
                    pack_u32(&weights_packed),
                    pack_u32(&activation_batches_packed),
                    pack_f32(&row_scales),
                    pack_f32(&batch_scales),
                ],
                &DispatchConfig::default(),
            )
            .expect(
                "Fix: CUDA must execute packed-activation INT4 top1 routing without CPU fallback.",
            );
        let (expected_scores, expected_indices) = batched_packed_matmul_top1_scaled_oracle(
            &weights_packed,
            &activation_batches_packed,
            &row_scales,
            &batch_scales,
            batch,
            rows,
            cols,
        );
        let actual_packed = read_f32_vec(&outputs[0], (batch * 2) as usize);
        let actual_scores = actual_packed[..batch as usize].to_vec();
        let actual_indices = actual_packed[batch as usize..]
            .iter()
            .map(|index| *index as u32)
            .collect::<Vec<_>>();

        assert_eq!(
            actual_scores
                .iter()
                .map(|v| v.to_bits())
                .collect::<Vec<_>>(),
            expected_scores
                .iter()
                .map(|v| v.to_bits())
                .collect::<Vec<_>>(),
            "batch={batch} rows={rows} cols={cols}"
        );
        assert_eq!(
            actual_indices, expected_indices,
            "batch={batch} rows={rows} cols={cols}"
        );
    }
}

#[test]
fn generated_cuda_int4_release_parity_sweeps_boundary_shapes() {
    let backend =
        CudaBackend::acquire().expect("Fix: CUDA backend acquire failed on a GPU-required host.");

    for seed in 0_u32..8 {
        for lane_count in [1_u32, 2, 7, 8, 9, 15, 16, 31, 32, 33, 65, 96] {
            let lhs = generated_i4_values(lane_count as usize, seed.wrapping_mul(17) + 1);
            let rhs = generated_i4_values(lane_count as usize, seed.wrapping_mul(31) + 7);
            let lhs_packed = pack_i4x8(&lhs);
            let rhs_packed = pack_i4x8(&rhs);

            let dot_program = vyre_primitives::math::quantized::i4x8_dot_i32(
                "lhs", "rhs", "out", lane_count,
            );
            let dot_outputs = backend
                .dispatch(
                    &dot_program,
                    &[pack_u32(&lhs_packed), pack_u32(&rhs_packed)],
                    &DispatchConfig::default(),
                )
                .expect("Fix: generated CUDA INT4 i32 dot parity must dispatch on live GPU.");
            let dot_actual = read_i32(&dot_outputs[0]);
            let dot_expected = dot_i32_oracle(&lhs_packed, &rhs_packed, lane_count);
            assert_eq!(
                dot_actual, dot_expected,
                "generated i32 dot seed={seed} lane_count={lane_count}"
            );

            let lhs_scale = 0.0625_f32 * (1 + (seed % 7)) as f32;
            let rhs_scale = 0.03125_f32 * (1 + (lane_count % 9)) as f32;
            let program = vyre_primitives::math::quantized::i4x8_dot_f32_scaled(
                "lhs",
                "rhs",
                "lhs_scale",
                "rhs_scale",
                "out",
                lane_count,
            );
            let outputs = backend
                .dispatch(
                    &program,
                    &[
                        pack_u32(&lhs_packed),
                        pack_u32(&rhs_packed),
                        pack_f32(&[lhs_scale]),
                        pack_f32(&[rhs_scale]),
                    ],
                    &DispatchConfig::default(),
                )
                .expect("Fix: generated CUDA INT4 dot parity must dispatch on live GPU.");
            let actual = read_f32(&outputs[0]);
            let expected =
                dot_scaled_oracle(&lhs_packed, &rhs_packed, lhs_scale, rhs_scale, lane_count);
            assert_eq!(
                actual.to_bits(),
                expected.to_bits(),
                "generated dot seed={seed} lane_count={lane_count}"
            );
        }
    }

    for seed in 0_u32..6 {
        for (rows, cols) in [
            (1_u32, 1_u32),
            (2, 7),
            (3, 8),
            (4, 9),
            (5, 17),
            (6, 33),
            (3, 64),
            (7, 65),
        ] {
            let weights = generated_i4_rows(rows, cols, seed.wrapping_mul(101) + 11);
            let x = generated_f32_values(cols as usize, seed.wrapping_mul(109) + rows + cols);
            let scales = generated_positive_scales(rows as usize, seed + rows * 13 + cols);
            let weights_packed = pack_i4_matrix_rows(&weights);
            let program = vyre_primitives::math::quantized::i4x8_matvec_f32_scaled(
                "weights", "x", "scales", "out", rows, cols,
            );
            let outputs = backend
                .dispatch(
                    &program,
                    &[pack_u32(&weights_packed), pack_f32(&x), pack_f32(&scales)],
                    &DispatchConfig::default(),
                )
                .expect("Fix: generated CUDA INT4 matvec parity must dispatch on live GPU.");
            let actual = read_f32_vec(&outputs[0], rows as usize);
            let expected = matvec_scaled_oracle(&weights_packed, &x, &scales, rows, cols);
            assert_eq!(
                f32_bits(&actual),
                f32_bits(&expected),
                "generated matvec seed={seed} rows={rows} cols={cols}"
            );
        }
    }

    for seed in 0_u32..5 {
        for (batch, rows, cols) in [
            (1_u32, 1_u32, 1_u32),
            (2, 2, 7),
            (3, 3, 8),
            (4, 4, 9),
            (5, 5, 17),
            (3, 6, 33),
            (2, 7, 65),
        ] {
            let weights = generated_i4_rows(rows, cols, seed.wrapping_mul(127) + 19);
            let x_batches =
                generated_f32_values((batch * cols) as usize, seed.wrapping_mul(131) + 23);
            let scales = generated_positive_scales(rows as usize, seed + 29);
            let weights_packed = pack_i4_matrix_rows(&weights);
            let program = vyre_primitives::math::quantized::i4x8_batched_matvec_f32_scaled(
                "weights", "x", "scales", "out", batch, rows, cols,
            );
            let outputs = backend
                .dispatch(
                    &program,
                    &[
                        pack_u32(&weights_packed),
                        pack_f32(&x_batches),
                        pack_f32(&scales),
                    ],
                    &DispatchConfig::default(),
                )
                .expect("Fix: generated CUDA INT4 batched matvec parity must dispatch.");
            let actual = read_f32_vec(&outputs[0], (batch * rows) as usize);
            let expected = batched_matvec_scaled_oracle(
                &weights_packed,
                &x_batches,
                &scales,
                batch,
                rows,
                cols,
            );
            assert_eq!(
                f32_bits(&actual),
                f32_bits(&expected),
                "generated batched matvec seed={seed} batch={batch} rows={rows} cols={cols}"
            );
        }
    }

    for seed in 0_u32..5 {
        for (batch, rows, cols) in [
            (1_u32, 1_u32, 1_u32),
            (2, 2, 7),
            (3, 3, 8),
            (4, 4, 9),
            (5, 5, 17),
            (3, 6, 33),
            (2, 7, 65),
        ] {
            let weights = generated_i4_rows(rows, cols, seed.wrapping_mul(149) + 31);
            let activations = generated_i4_rows(batch, cols, seed.wrapping_mul(151) + 37);
            let row_scales = generated_positive_scales(rows as usize, seed + 41);
            let batch_scales = generated_positive_scales(batch as usize, seed + 43);
            let weights_packed = pack_i4_matrix_rows(&weights);
            let activations_packed = pack_i4_matrix_rows(&activations);
            let program = vyre_primitives::math::quantized::i4x8_batched_matmul_f32_scaled(
                "weights",
                "activations",
                "row_scales",
                "batch_scales",
                "out",
                batch,
                rows,
                cols,
            );
            let outputs = backend
                .dispatch(
                    &program,
                    &[
                        pack_u32(&weights_packed),
                        pack_u32(&activations_packed),
                        pack_f32(&row_scales),
                        pack_f32(&batch_scales),
                    ],
                    &DispatchConfig::default(),
                )
                .expect("Fix: generated CUDA INT4 batched matmul parity must dispatch.");
            let actual = read_f32_vec(&outputs[0], (batch * rows) as usize);
            let expected = batched_packed_matmul_scaled_oracle(
                &weights_packed,
                &activations_packed,
                &row_scales,
                &batch_scales,
                batch,
                rows,
                cols,
            );
            assert_eq!(
                f32_bits(&actual),
                f32_bits(&expected),
                "generated batched matmul seed={seed} batch={batch} rows={rows} cols={cols}"
            );

            let top1_program =
                vyre_primitives::math::quantized::i4x8_batched_matmul_top1_f32_scaled(
                    "weights",
                    "activations",
                    "row_scales",
                    "batch_scales",
                    "out",
                    batch,
                    rows,
                    cols,
                );
            let top1_outputs = backend
                .dispatch(
                    &top1_program,
                    &[
                        pack_u32(&weights_packed),
                        pack_u32(&activations_packed),
                        pack_f32(&row_scales),
                        pack_f32(&batch_scales),
                    ],
                    &DispatchConfig::default(),
                )
                .expect("Fix: generated CUDA INT4 top1 parity must dispatch.");
            let (expected_scores, expected_indices) = batched_packed_matmul_top1_scaled_oracle(
                &weights_packed,
                &activations_packed,
                &row_scales,
                &batch_scales,
                batch,
                rows,
                cols,
            );
            let actual_packed = read_f32_vec(&top1_outputs[0], (batch * 2) as usize);
            let actual_scores = actual_packed[..batch as usize].to_vec();
            let actual_indices = actual_packed[batch as usize..]
                .iter()
                .map(|index| *index as u32)
                .collect::<Vec<_>>();
            assert_eq!(
                f32_bits(&actual_scores),
                f32_bits(&expected_scores),
                "generated top1 score seed={seed} batch={batch} rows={rows} cols={cols}"
            );
            assert_eq!(
                actual_indices, expected_indices,
                "generated top1 index seed={seed} batch={batch} rows={rows} cols={cols}"
            );
        }
    }
}

