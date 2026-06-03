//! Unit tests for packed INT4 quantized primitives.

use super::*;

#[test]
fn packed_word_count_rounds_up_to_eight_lanes() {
    let cases = [
        (0, 0),
        (1, 1),
        (7, 1),
        (8, 1),
        (9, 2),
        (15, 2),
        (16, 2),
        (17, 3),
    ];
    for (lanes, words) in cases {
        assert_eq!(i4_packed_words(lanes), words, "lanes={lanes}");
    }
}

#[test]
fn pack_unpack_preserves_signed_i4_domain() {
    let values = [-8, -7, -1, 0, 1, 2, 6, 7];
    let packed = pack_i4x8_cpu(&values);
    assert_eq!(packed, vec![0x7621_0F98]);
    assert_eq!(unpack_i4x8_cpu(&packed, values.len() as u32), values);
}

#[test]
fn pack_saturates_out_of_domain_values() {
    let values = [-32, -9, -8, 7, 8, 31];
    let packed = pack_i4x8_cpu(&values);
    assert_eq!(
        unpack_i4x8_cpu(&packed, values.len() as u32),
        [-8, -8, -8, 7, 7, 7]
    );
}

#[test]
fn generated_pack_unpack_round_trip_all_offsets() {
    let pattern = [-8, -3, -1, 0, 1, 3, 7, 6, 5, 4, 2, -2, -4, -6, -7, -5];
    for len in 0..=256 {
        let values = pattern
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect::<Vec<_>>();
        let packed = pack_i4x8_cpu(&values);
        let unpacked = unpack_i4x8_cpu(&packed, len as u32);
        assert_eq!(unpacked, values, "len={len}");
        assert_eq!(packed.len(), i4_packed_words(len as u32) as usize);
    }
}

#[test]
fn pack_unpack_into_reuses_capacity_and_truncates_stale_tail() {
    let mut packed = Vec::with_capacity(4);
    packed.extend_from_slice(&[0xFFFF_FFFF, 0xAAAA_AAAA, 0x5555_5555, 0]);
    let packed_capacity = packed.capacity();

    try_pack_i4x8_cpu_into(&[-8, -1, 0, 7, 8, -9, 3, -2, 1], &mut packed)
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - pack_i4x8 CPU oracle should reuse caller-owned packed storage");

    assert_eq!(packed.len(), 2);
    assert_eq!(packed.capacity(), packed_capacity);

    try_pack_i4x8_cpu_into(&[7], &mut packed)
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - pack_i4x8 CPU oracle should truncate stale packed words");

    assert_eq!(packed, vec![7]);
    assert_eq!(packed.capacity(), packed_capacity);

    let mut lanes = Vec::with_capacity(16);
    lanes.extend_from_slice(&[99; 16]);
    let lanes_capacity = lanes.capacity();

    try_unpack_i4x8_cpu_into(&packed, 1, &mut lanes)
        .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - unpack_i4x8 CPU oracle should reuse caller-owned lane storage");

    assert_eq!(lanes, vec![7]);
    assert_eq!(lanes.capacity(), lanes_capacity);
}

#[test]
fn unpack_missing_words_zero_fills_missing_lanes() {
    assert_eq!(unpack_i4x8_cpu(&[], 4), vec![0, 0, 0, 0]);
    assert_eq!(unpack_i4x8_cpu(&[0xF], 4), vec![-1, 0, 0, 0]);
}

#[test]
fn unpack_program_layout_matches_packed_shape() {
    let program = unpack_i4x8("packed", "lanes", 17);
    assert_eq!(program.workgroup_size, [256, 1, 1]);
    assert_eq!(program.buffers[0].name(), "packed");
    assert_eq!(program.buffers[0].count(), 3);
    assert_eq!(program.buffers[1].name(), "lanes");
    assert_eq!(program.buffers[1].count(), 17);
}

#[test]
fn unpack_zero_lanes_traps() {
    assert!(unpack_i4x8("packed", "lanes", 0).stats().trap());
}

#[test]
fn dot_cpu_matches_unpacked_reference() {
    let lhs = [-8, -4, -1, 0, 1, 2, 6, 7, 5, -7, 3, -3];
    let rhs = [7, -2, -1, 4, -8, 6, 2, 1, -5, 3, -4, 2];
    let lhs_packed = pack_i4x8_cpu(&lhs);
    let rhs_packed = pack_i4x8_cpu(&rhs);
    let expected = lhs
        .iter()
        .zip(rhs.iter())
        .fold(0i32, |acc, (&lhs, &rhs)| acc + lhs * rhs);

    assert_eq!(
        i4x8_dot_i32_cpu(&lhs_packed, &rhs_packed, lhs.len() as u32),
        expected
    );
}

#[test]
fn dot_cpu_missing_words_contribute_zero_lanes() {
    let lhs = pack_i4x8_cpu(&[7, -8, 3, -2]);

    assert_eq!(i4x8_dot_i32_cpu(&lhs, &[], 4), 0);
}

#[test]
fn generated_dot_matches_unpack_then_dot_for_all_offsets() {
    let lhs_pattern = [-8, -3, -1, 0, 1, 3, 7, 6, 5, 4, 2, -2, -4, -6, -7, -5];
    let rhs_pattern = [7, 5, 3, 1, -1, -3, -5, -7, 6, 4, 2, 0, -2, -4, -6, -8];
    for len in 0..=256 {
        let lhs = lhs_pattern
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect::<Vec<_>>();
        let rhs = rhs_pattern
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect::<Vec<_>>();
        let lhs_packed = pack_i4x8_cpu(&lhs);
        let rhs_packed = pack_i4x8_cpu(&rhs);
        let unpacked_lhs = unpack_i4x8_cpu(&lhs_packed, len as u32);
        let unpacked_rhs = unpack_i4x8_cpu(&rhs_packed, len as u32);
        let expected = unpacked_lhs
            .iter()
            .zip(unpacked_rhs.iter())
            .fold(0i32, |acc, (&lhs, &rhs)| {
                acc.wrapping_add(lhs.wrapping_mul(rhs))
            });

        assert_eq!(
            i4x8_dot_i32_cpu(&lhs_packed, &rhs_packed, len as u32),
            expected,
            "len={len}"
        );
    }
}

#[test]
fn scaled_dot_cpu_matches_dequantized_reference() {
    let lhs = [-8, -4, -1, 0, 1, 2, 6, 7, 5, -7, 3, -3];
    let rhs = [7, -2, -1, 4, -8, 6, 2, 1, -5, 3, -4, 2];
    let lhs_scale = 0.25_f32;
    let rhs_scale = 0.5_f32;
    let lhs_packed = pack_i4x8_cpu(&lhs);
    let rhs_packed = pack_i4x8_cpu(&rhs);
    let expected = lhs
        .iter()
        .zip(rhs.iter())
        .fold(0.0_f32, |acc, (&lhs, &rhs)| {
            acc + (lhs as f32 * lhs_scale) * (rhs as f32 * rhs_scale)
        });
    let actual = i4x8_dot_f32_scaled_cpu(
        &lhs_packed,
        &rhs_packed,
        lhs_scale,
        rhs_scale,
        lhs.len() as u32,
    );

    assert!(
        (actual - expected).abs() <= 0.000_001,
        "actual={actual} expected={expected}"
    );
}

#[test]
fn generated_scaled_dot_matches_i32_dot_scale_product() {
    let lhs_pattern = [-8, -3, -1, 0, 1, 3, 7, 6, 5, 4, 2, -2, -4, -6, -7, -5];
    let rhs_pattern = [7, 5, 3, 1, -1, -3, -5, -7, 6, 4, 2, 0, -2, -4, -6, -8];
    for len in 0..=256 {
        let lhs = lhs_pattern
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect::<Vec<_>>();
        let rhs = rhs_pattern
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect::<Vec<_>>();
        let lhs_packed = pack_i4x8_cpu(&lhs);
        let rhs_packed = pack_i4x8_cpu(&rhs);
        let lhs_scale = 0.125_f32 + (len % 7) as f32 * 0.03125;
        let rhs_scale = 0.25_f32 + (len % 5) as f32 * 0.0625;
        let expected =
            i4x8_dot_i32_cpu(&lhs_packed, &rhs_packed, len as u32) as f32 * lhs_scale * rhs_scale;

        assert_eq!(
            i4x8_dot_f32_scaled_cpu(&lhs_packed, &rhs_packed, lhs_scale, rhs_scale, len as u32)
                .to_bits(),
            expected.to_bits(),
            "len={len}"
        );
    }
}

fn pack_i4_matrix_rows(rows: &[Vec<i32>]) -> Vec<u32> {
    let cols = rows.first().map_or(0, Vec::len) as u32;
    let words_per_row = i4_packed_words(cols) as usize;
    let mut out = Vec::with_capacity(rows.len() * words_per_row);
    for row in rows {
        let mut packed = pack_i4x8_cpu(row);
        packed.resize(words_per_row, 0);
        out.extend_from_slice(&packed);
    }
    out
}

#[test]
fn matvec_cpu_matches_dequantized_reference() {
    let weights = vec![
        vec![-8, -4, -1, 0, 1, 2, 6, 7, 5],
        vec![7, 5, 3, 1, -1, -3, -5, -7, 6],
        vec![0, 1, 0, -1, 2, -2, 3, -3, 4],
    ];
    let x = [0.5_f32, -1.0, 2.0, 0.25, -0.5, 1.5, -2.0, 3.0, 0.75];
    let scales = [0.125_f32, 0.25, 0.5];
    let packed = pack_i4_matrix_rows(&weights);
    let actual = i4x8_matvec_f32_scaled_cpu(&packed, &x, &scales, 3, 9);
    let expected = weights
        .iter()
        .zip(scales)
        .map(|(row, scale)| {
            row.iter()
                .zip(x)
                .fold(0.0_f32, |acc, (&w, x)| acc + w as f32 * x)
                * scale
        })
        .collect::<Vec<_>>();

    assert_eq!(
        actual.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
        expected.iter().map(|v| v.to_bits()).collect::<Vec<_>>()
    );
}

#[test]
fn generated_matvec_matches_dequantized_reference_across_pack_boundaries() {
    let pattern = [-8, -3, -1, 0, 1, 3, 7, 6, 5, 4, 2, -2, -4, -6, -7, -5];
    for rows in 1..=8_u32 {
        for cols in [1_u32, 7, 8, 9, 16, 17, 31, 32, 33, 65] {
            let weights = (0..rows as usize)
                .map(|row| {
                    pattern
                        .iter()
                        .copied()
                        .cycle()
                        .skip(row)
                        .take(cols as usize)
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let x = (0..cols)
                .map(|col| (col % 11) as f32 * 0.125 - 0.5)
                .collect::<Vec<_>>();
            let scales = (0..rows)
                .map(|row| 0.125_f32 + row as f32 * 0.0625)
                .collect::<Vec<_>>();
            let packed = pack_i4_matrix_rows(&weights);
            let actual = i4x8_matvec_f32_scaled_cpu(&packed, &x, &scales, rows, cols);
            let expected = weights
                .iter()
                .zip(scales.iter().copied())
                .map(|(row, scale)| {
                    row.iter()
                        .zip(x.iter().copied())
                        .fold(0.0_f32, |acc, (&w, x)| acc + w as f32 * x)
                        * scale
                })
                .collect::<Vec<_>>();

            assert_eq!(
                actual.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
                expected.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
                "rows={rows} cols={cols}"
            );
        }
    }
}

#[test]
fn batched_matvec_cpu_matches_repeated_matvec_reference() {
    let weights = vec![
        vec![1, 2, 3, 4, -1, -2, -3, -4, 5],
        vec![4, 3, 2, 1, -4, -3, -2, -1, -5],
        vec![-8, -7, -6, -5, -4, -3, -2, -1, 0],
    ];
    let x_batches = [
        1.0_f32, -0.5, 0.25, 2.0, -1.5, 0.75, 1.25, -2.0, 0.5, -1.0, 0.5, -0.25, -2.0, 1.5, -0.75,
        -1.25, 2.0, -0.5,
    ];
    let scales = [0.5_f32, 0.25, 0.125];
    let packed = pack_i4_matrix_rows(&weights);
    let actual = i4x8_batched_matvec_f32_scaled_cpu(&packed, &x_batches, &scales, 2, 3, 9);
    let mut expected = Vec::new();
    for x in x_batches.chunks_exact(9) {
        expected.extend(i4x8_matvec_f32_scaled_cpu(&packed, x, &scales, 3, 9));
    }

    assert_eq!(
        actual.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
        expected.iter().map(|v| v.to_bits()).collect::<Vec<_>>()
    );
}

#[test]
fn generated_batched_matvec_matches_repeated_matvec_across_pack_boundaries() {
    let pattern = [-8, -3, -1, 0, 1, 3, 7, 6, 5, 4, 2, -2, -4, -6, -7, -5];
    for batch in 1..=4_u32 {
        for rows in 1..=5_u32 {
            for cols in [1_u32, 7, 8, 9, 16, 17, 31, 32, 33] {
                let weights = (0..rows as usize)
                    .map(|row| {
                        pattern
                            .iter()
                            .copied()
                            .cycle()
                            .skip(row * 2)
                            .take(cols as usize)
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                let x_batches = (0..batch * cols)
                    .map(|index| (index % 13) as f32 * 0.125 - 0.75)
                    .collect::<Vec<_>>();
                let scales = (0..rows)
                    .map(|row| 0.125_f32 + row as f32 * 0.0625)
                    .collect::<Vec<_>>();
                let packed = pack_i4_matrix_rows(&weights);
                let actual = i4x8_batched_matvec_f32_scaled_cpu(
                    &packed, &x_batches, &scales, batch, rows, cols,
                );
                let mut expected = Vec::new();
                for x in x_batches.chunks_exact(cols as usize) {
                    expected.extend(i4x8_matvec_f32_scaled_cpu(&packed, x, &scales, rows, cols));
                }

                assert_eq!(
                    actual.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
                    expected.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
                    "batch={batch} rows={rows} cols={cols}"
                );
            }
        }
    }
}

#[test]
fn batched_matmul_cpu_matches_dequantized_reference() {
    let weights = vec![
        vec![1, 2, 3, 4, -1, -2, -3, -4, 5],
        vec![4, 3, 2, 1, -4, -3, -2, -1, -5],
        vec![-8, -7, -6, -5, -4, -3, -2, -1, 0],
    ];
    let activations = vec![
        vec![1, -1, 2, -2, 3, -3, 4, -4, 5],
        vec![-5, 4, -4, 3, -3, 2, -2, 1, -1],
    ];
    let row_scales = [0.5_f32, 0.25, 0.125];
    let batch_scales = [0.25_f32, 0.5];
    let weights_packed = pack_i4_matrix_rows(&weights);
    let activations_packed = pack_i4_matrix_rows(&activations);
    let actual = i4x8_batched_matmul_f32_scaled_cpu(
        &weights_packed,
        &activations_packed,
        &row_scales,
        &batch_scales,
        2,
        3,
        9,
    );
    let expected = activations
        .iter()
        .zip(batch_scales)
        .flat_map(|(activation, batch_scale)| {
            weights.iter().zip(row_scales).map(move |(row, row_scale)| {
                row.iter()
                    .zip(activation)
                    .fold(0.0_f32, |acc, (&w, &x)| acc + w as f32 * x as f32)
                    * row_scale
                    * batch_scale
            })
        })
        .collect::<Vec<_>>();

    assert_eq!(
        actual.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
        expected.iter().map(|v| v.to_bits()).collect::<Vec<_>>()
    );
}

#[test]
fn batched_matmul_top1_cpu_matches_full_matmul_argmax() {
    let weights = vec![
        vec![1, 2, 3, 4, -1, -2, -3, -4, 5],
        vec![4, 3, 2, 1, -4, -3, -2, -1, -5],
        vec![-8, -7, -6, -5, -4, -3, -2, -1, 0],
    ];
    let activations = vec![
        vec![1, -1, 2, -2, 3, -3, 4, -4, 5],
        vec![-5, 4, -4, 3, -3, 2, -2, 1, -1],
    ];
    let row_scales = [0.5_f32, 0.25, 0.125];
    let batch_scales = [0.75_f32, 0.375];
    let weights_packed = pack_i4_matrix_rows(&weights);
    let activations_packed = pack_i4_matrix_rows(&activations);
    let logits = i4x8_batched_matmul_f32_scaled_cpu(
        &weights_packed,
        &activations_packed,
        &row_scales,
        &batch_scales,
        activations.len() as u32,
        weights.len() as u32,
        weights[0].len() as u32,
    );
    let (scores, indices) = i4x8_batched_matmul_top1_f32_scaled_cpu(
        &weights_packed,
        &activations_packed,
        &row_scales,
        &batch_scales,
        activations.len() as u32,
        weights.len() as u32,
        weights[0].len() as u32,
    );

    for batch_index in 0..activations.len() {
        let row_start = batch_index * weights.len();
        let (expected_index, expected_score) = (0..weights.len())
            .map(|row| (row as u32, logits[row_start + row]))
            .max_by(|(_, lhs), (_, rhs)| lhs.total_cmp(rhs))
            .expect("Fix: top1 test requires at least one row.");
        assert_eq!(indices[batch_index], expected_index);
        assert_eq!(scores[batch_index].to_bits(), expected_score.to_bits());
    }
}

#[test]

fn generated_batched_matmul_matches_dequantized_reference_across_pack_boundaries() {
    let pattern = [-8, -3, -1, 0, 1, 3, 7, 6, 5, 4, 2, -2, -4, -6, -7, -5];
    for batch in 1..=4_u32 {
        for rows in 1..=5_u32 {
            for cols in [1_u32, 7, 8, 9, 16, 17, 31, 32, 33] {
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
                let activations = (0..batch as usize)
                    .map(|batch_index| {
                        pattern
                            .iter()
                            .copied()
                            .cycle()
                            .skip(batch_index * 5 + 1)
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
                let activations_packed = pack_i4_matrix_rows(&activations);
                let actual = i4x8_batched_matmul_f32_scaled_cpu(
                    &weights_packed,
                    &activations_packed,
                    &row_scales,
                    &batch_scales,
                    batch,
                    rows,
                    cols,
                );
                let expected = activations
                    .iter()
                    .zip(batch_scales.iter().copied())
                    .flat_map(|(activation, batch_scale)| {
                        weights.iter().zip(row_scales.iter().copied()).map(
                            move |(row, row_scale)| {
                                row.iter()
                                    .zip(activation)
                                    .fold(0.0_f32, |acc, (&w, &x)| acc + w as f32 * x as f32)
                                    * row_scale
                                    * batch_scale
                            },
                        )
                    })
                    .collect::<Vec<_>>();

                assert_eq!(
                    actual.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
                    expected.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
                    "batch={batch} rows={rows} cols={cols}"
                );
            }
        }
    }
}

#[test]
fn generated_batched_matmul_top1_matches_full_matmul_across_pack_boundaries() {
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
        let activations = (0..batch as usize)
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
        let activations_packed = pack_i4_matrix_rows(&activations);
        let logits = i4x8_batched_matmul_f32_scaled_cpu(
            &weights_packed,
            &activations_packed,
            &row_scales,
            &batch_scales,
            batch,
            rows,
            cols,
        );
        let (scores, indices) = i4x8_batched_matmul_top1_f32_scaled_cpu(
            &weights_packed,
            &activations_packed,
            &row_scales,
            &batch_scales,
            batch,
            rows,
            cols,
        );

        for batch_index in 0..batch as usize {
            let row_start = batch_index * rows as usize;
            let (expected_index, expected_score) = (0..rows as usize)
                .map(|row| (row as u32, logits[row_start + row]))
                .max_by(|(_, lhs), (_, rhs)| lhs.total_cmp(rhs))
                .expect("Fix: top1 generated test requires at least one row.");
            assert_eq!(
                indices[batch_index], expected_index,
                "batch={batch} rows={rows} cols={cols} batch_index={batch_index}"
            );
            assert_eq!(
                scores[batch_index].to_bits(),
                expected_score.to_bits(),
                "batch={batch} rows={rows} cols={cols} batch_index={batch_index}"
            );
        }
    }
}

#[test]
fn dot_program_layout_matches_packed_shape() {
    let program = i4x8_dot_i32("lhs", "rhs", "out", 65);
    assert_eq!(program.workgroup_size, [1, 1, 1]);
    assert_eq!(program.buffers[0].name(), "lhs");
    assert_eq!(program.buffers[0].count(), 9);
    assert_eq!(program.buffers[1].name(), "rhs");
    assert_eq!(program.buffers[1].count(), 9);
    assert_eq!(program.buffers[2].name(), "out");
    assert_eq!(program.buffers[2].count(), 1);
}

#[test]
fn scaled_dot_program_layout_matches_fused_packed_shape() {
    let program = i4x8_dot_f32_scaled("lhs", "rhs", "lhs_scale", "rhs_scale", "out", 65);
    assert_eq!(program.workgroup_size, [1, 1, 1]);
    assert_eq!(program.buffers[0].name(), "lhs");
    assert_eq!(program.buffers[0].count(), 9);
    assert_eq!(program.buffers[1].name(), "rhs");
    assert_eq!(program.buffers[1].count(), 9);
    assert_eq!(program.buffers[2].name(), "lhs_scale");
    assert_eq!(program.buffers[2].count(), 1);
    assert_eq!(program.buffers[3].name(), "rhs_scale");
    assert_eq!(program.buffers[3].count(), 1);
    assert_eq!(program.buffers[4].name(), "out");
    assert_eq!(program.buffers[4].count(), 1);
}

#[test]
fn matvec_program_layout_matches_row_major_packed_shape() {
    let program = i4x8_matvec_f32_scaled("weights", "x", "scales", "out", 3, 65);
    assert_eq!(program.workgroup_size, [64, 1, 1]);
    assert_eq!(program.buffers[0].name(), "weights");
    assert_eq!(program.buffers[0].count(), 27);
    assert_eq!(program.buffers[1].name(), "x");
    assert_eq!(program.buffers[1].count(), 65);
    assert_eq!(program.buffers[2].name(), "scales");
    assert_eq!(program.buffers[2].count(), 3);
    assert_eq!(program.buffers[3].name(), "out");
    assert_eq!(program.buffers[3].count(), 3);
}

#[test]
fn batched_matvec_program_layout_matches_reused_weights_shape() {
    let program = i4x8_batched_matvec_f32_scaled("weights", "x", "scales", "out", 4, 3, 65);
    assert_eq!(program.workgroup_size, [64, 1, 1]);
    assert_eq!(program.buffers[0].name(), "weights");
    assert_eq!(program.buffers[0].count(), 27);
    assert_eq!(program.buffers[1].name(), "x");
    assert_eq!(program.buffers[1].count(), 260);
    assert_eq!(program.buffers[2].name(), "scales");
    assert_eq!(program.buffers[2].count(), 3);
    assert_eq!(program.buffers[3].name(), "out");
    assert_eq!(program.buffers[3].count(), 12);
}

#[test]
fn batched_matmul_program_layout_matches_packed_activation_shape() {
    let program = i4x8_batched_matmul_f32_scaled(
        "weights",
        "activations",
        "row_scales",
        "batch_scales",
        "out",
        4,
        3,
        65,
    );
    assert_eq!(program.workgroup_size, [64, 1, 1]);
    assert_eq!(program.buffers[0].name(), "weights");
    assert_eq!(program.buffers[0].count(), 27);
    assert_eq!(program.buffers[1].name(), "activations");
    assert_eq!(program.buffers[1].count(), 36);
    assert_eq!(program.buffers[2].name(), "row_scales");
    assert_eq!(program.buffers[2].count(), 3);
    assert_eq!(program.buffers[3].name(), "batch_scales");
    assert_eq!(program.buffers[3].count(), 4);
    assert_eq!(program.buffers[4].name(), "out");
    assert_eq!(program.buffers[4].count(), 12);
}

#[test]
fn batched_matmul_top1_program_layout_matches_packed_activation_shape() {
    let program = i4x8_batched_matmul_top1_f32_scaled(
        "weights",
        "activations",
        "row_scales",
        "batch_scales",
        "out",
        4,
        3,
        65,
    );

    assert_eq!(program.workgroup_size, [64, 1, 1]);
    assert_eq!(program.buffers[0].name(), "weights");
    assert_eq!(program.buffers[0].count(), 27);
    assert_eq!(program.buffers[1].name(), "activations");
    assert_eq!(program.buffers[1].count(), 36);
    assert_eq!(program.buffers[2].name(), "row_scales");
    assert_eq!(program.buffers[2].count(), 3);
    assert_eq!(program.buffers[3].name(), "batch_scales");
    assert_eq!(program.buffers[3].count(), 4);
    assert_eq!(program.buffers[4].name(), "out");
    assert_eq!(program.buffers[4].count(), 8);
}

#[test]
fn dot_zero_lanes_traps() {
    assert!(i4x8_dot_i32("lhs", "rhs", "out", 0).stats().trap());
}

#[test]
fn scaled_dot_zero_lanes_traps() {
    assert!(
        i4x8_dot_f32_scaled("lhs", "rhs", "lhs_scale", "rhs_scale", "out", 0)
            .stats()
            .trap()
    );
}

#[test]
fn matvec_zero_shape_traps() {
    assert!(
        i4x8_matvec_f32_scaled("weights", "x", "scales", "out", 0, 8)
            .stats()
            .trap()
    );
    assert!(
        i4x8_matvec_f32_scaled("weights", "x", "scales", "out", 4, 0)
            .stats()
            .trap()
    );
}

#[test]
fn batched_matvec_zero_shape_traps() {
    assert!(
        i4x8_batched_matvec_f32_scaled("weights", "x", "scales", "out", 0, 4, 8)
            .stats()
            .trap()
    );
    assert!(
        i4x8_batched_matvec_f32_scaled("weights", "x", "scales", "out", 2, 0, 8)
            .stats()
            .trap()
    );
    assert!(
        i4x8_batched_matvec_f32_scaled("weights", "x", "scales", "out", 2, 4, 0)
            .stats()
            .trap()
    );
}

#[test]
fn batched_matmul_zero_shape_traps() {
    assert!(i4x8_batched_matmul_f32_scaled(
        "weights",
        "activations",
        "row_scales",
        "batch_scales",
        "out",
        0,
        4,
        8
    )
    .stats()
    .trap());
    assert!(i4x8_batched_matmul_f32_scaled(
        "weights",
        "activations",
        "row_scales",
        "batch_scales",
        "out",
        2,
        0,
        8
    )
    .stats()
    .trap());
    assert!(i4x8_batched_matmul_f32_scaled(
        "weights",
        "activations",
        "row_scales",
        "batch_scales",
        "out",
        2,
        4,
        0
    )
    .stats()
    .trap());
}

#[test]
fn batched_matmul_top1_zero_shape_traps() {
    assert!(i4x8_batched_matmul_top1_f32_scaled(
        "weights",
        "activations",
        "row_scales",
        "batch_scales",
        "out",
        0,
        4,
        8
    )
    .stats()
    .trap());
    assert!(i4x8_batched_matmul_top1_f32_scaled(
        "weights",
        "activations",
        "row_scales",
        "batch_scales",
        "out",
        2,
        0,
        8
    )
    .stats()
    .trap());
    assert!(i4x8_batched_matmul_top1_f32_scaled(
        "weights",
        "activations",
        "row_scales",
        "batch_scales",
        "out",
        2,
        4,
        0
    )
    .stats()
    .trap());
}
