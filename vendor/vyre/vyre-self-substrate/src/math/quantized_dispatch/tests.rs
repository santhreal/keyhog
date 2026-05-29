use super::*;

struct QuantizedDispatcher;

impl OptimizerDispatcher for QuantizedDispatcher {
    fn dispatch(
        &self,
        _program: &Program,
        inputs: &[Vec<u8>],
        grid_override: Option<[u32; 3]>,
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        assert_eq!(grid_override, Some([1, 1, 1]));
        assert_eq!(inputs.len(), 2);
        let packed = crate::hardware::dispatch_buffers::read_u32s(&inputs[0]);
        let lane_count = inputs[1].len() / std::mem::size_of::<i32>();
        let mut out = Vec::new();
        unpack_i4x8_cpu_into(&packed, lane_count as u32, &mut out);
        Ok(vec![vyre_primitives::wire::pack_i32_slice(&out)])
    }
}

struct QuantizedDotDispatcher;

impl OptimizerDispatcher for QuantizedDotDispatcher {
    fn dispatch(
        &self,
        _program: &Program,
        inputs: &[Vec<u8>],
        grid_override: Option<[u32; 3]>,
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        assert_eq!(grid_override, Some([1, 1, 1]));
        assert_eq!(inputs.len(), 5);
        let lhs = crate::hardware::dispatch_buffers::read_u32s(&inputs[0]);
        let rhs = crate::hardware::dispatch_buffers::read_u32s(&inputs[1]);
        let lhs_scale = crate::hardware::dispatch_buffers::read_f32s(&inputs[2])[0];
        let rhs_scale = crate::hardware::dispatch_buffers::read_f32s(&inputs[3])[0];
        let lane_count = (inputs[4].len() / std::mem::size_of::<f32>()) as u32;
        assert_eq!(
            lane_count, 1,
            "Fix: dot output slot must reserve exactly one f32 word."
        );
        let logical_lane_count = (lhs.len() as u32 - 1) * 8
            + if lhs.last().copied().unwrap_or(0) == 0 {
                8
            } else {
                8
            };
        let lane_count = logical_lane_count.min((lhs.len() as u32) * 8);
        let out = i4x8_dot_f32_scaled_cpu(&lhs, &rhs, lhs_scale, rhs_scale, lane_count);
        Ok(vec![vyre_primitives::wire::pack_f32_slice(&[out])])
    }
}

struct MalformedDotDispatcher {
    outputs: Vec<Vec<u8>>,
}

impl OptimizerDispatcher for MalformedDotDispatcher {
    fn dispatch(
        &self,
        _program: &Program,
        _inputs: &[Vec<u8>],
        _grid_override: Option<[u32; 3]>,
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        Ok(self.outputs.clone())
    }
}

struct QuantizedMatvecDispatcher;

impl OptimizerDispatcher for QuantizedMatvecDispatcher {
    fn dispatch(
        &self,
        _program: &Program,
        inputs: &[Vec<u8>],
        grid_override: Option<[u32; 3]>,
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        assert_eq!(inputs.len(), 4);
        let weights = crate::hardware::dispatch_buffers::read_u32s(&inputs[0]);
        let x = crate::hardware::dispatch_buffers::read_f32s(&inputs[1]);
        let row_scales = crate::hardware::dispatch_buffers::read_f32s(&inputs[2]);
        let rows = row_scales.len() as u32;
        let cols = x.len() as u32;
        assert_eq!(grid_override, Some([rows, 1, 1]));
        assert_eq!(
            inputs[3].len(),
            row_scales.len() * std::mem::size_of::<f32>(),
            "Fix: matvec output slot must reserve exactly one f32 per row."
        );
        let out = i4x8_matvec_f32_scaled_cpu(&weights, &x, &row_scales, rows, cols);
        Ok(vec![vyre_primitives::wire::pack_f32_slice(&out)])
    }
}

struct QuantizedBatchedMatvecDispatcher;

impl OptimizerDispatcher for QuantizedBatchedMatvecDispatcher {
    fn dispatch(
        &self,
        _program: &Program,
        inputs: &[Vec<u8>],
        grid_override: Option<[u32; 3]>,
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        assert_eq!(inputs.len(), 4);
        let weights = crate::hardware::dispatch_buffers::read_u32s(&inputs[0]);
        let x_batches = crate::hardware::dispatch_buffers::read_f32s(&inputs[1]);
        let row_scales = crate::hardware::dispatch_buffers::read_f32s(&inputs[2]);
        let Some([rows, batch, 1]) = grid_override else {
            panic!("Fix: batched matvec dispatch must launch with [rows, batch, 1].");
        };
        let cols = x_batches
            .len()
            .checked_div(batch as usize)
            .expect("Fix: fake batched matvec dispatcher requires nonzero batch")
            as u32;
        assert_eq!(rows as usize, row_scales.len());
        assert_eq!(
            inputs[3].len(),
            batch as usize * rows as usize * std::mem::size_of::<f32>(),
            "Fix: batched matvec output slot must reserve exactly one f32 per batch row."
        );
        let out = i4x8_batched_matvec_f32_scaled_cpu(
            &weights,
            &x_batches,
            &row_scales,
            batch,
            rows,
            cols,
        );
        Ok(vec![vyre_primitives::wire::pack_f32_slice(&out)])
    }
}

struct QuantizedBatchedMatmulDispatcher;

impl OptimizerDispatcher for QuantizedBatchedMatmulDispatcher {
    fn dispatch(
        &self,
        _program: &Program,
        inputs: &[Vec<u8>],
        grid_override: Option<[u32; 3]>,
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        assert_eq!(inputs.len(), 5);
        let weights = crate::hardware::dispatch_buffers::read_u32s(&inputs[0]);
        let activations = crate::hardware::dispatch_buffers::read_u32s(&inputs[1]);
        let row_scales = crate::hardware::dispatch_buffers::read_f32s(&inputs[2]);
        let batch_scales = crate::hardware::dispatch_buffers::read_f32s(&inputs[3]);
        let rows = row_scales.len() as u32;
        let batch = batch_scales.len() as u32;
        let Some([grid_x, 1, 1]) = grid_override else {
            panic!(
                "Fix: batched matmul dispatch must launch one-dimensional 64-wide workgroup grid."
            );
        };
        assert_eq!(grid_x, ceil_div_u32(batch * rows, 64));
        assert_eq!(
            inputs[4].len(),
            batch as usize * rows as usize * std::mem::size_of::<f32>(),
            "Fix: batched matmul output slot must reserve exactly one f32 per batch row."
        );
        let words_per_activation = activations.len() / batch as usize;
        let cols = (words_per_activation as u32) * 8;
        let out = i4x8_batched_matmul_f32_scaled_cpu(
            &weights,
            &activations,
            &row_scales,
            &batch_scales,
            batch,
            rows,
            cols,
        );
        Ok(vec![vyre_primitives::wire::pack_f32_slice(&out)])
    }
}

struct QuantizedBatchedMatmulTop1Dispatcher;

impl OptimizerDispatcher for QuantizedBatchedMatmulTop1Dispatcher {
    fn dispatch(
        &self,
        _program: &Program,
        inputs: &[Vec<u8>],
        grid_override: Option<[u32; 3]>,
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        assert_eq!(inputs.len(), 6);
        let weights = crate::hardware::dispatch_buffers::read_u32s(&inputs[0]);
        let activations = crate::hardware::dispatch_buffers::read_u32s(&inputs[1]);
        let row_scales = crate::hardware::dispatch_buffers::read_f32s(&inputs[2]);
        let batch_scales = crate::hardware::dispatch_buffers::read_f32s(&inputs[3]);
        let rows = row_scales.len() as u32;
        let batch = batch_scales.len() as u32;
        assert_eq!(grid_override, Some([ceil_div_u32(batch, 64), 1, 1]));
        assert_eq!(
            inputs[4].len(),
            batch as usize * std::mem::size_of::<f32>(),
            "Fix: top-1 score output slot must reserve exactly one f32 per batch."
        );
        assert_eq!(
            inputs[5].len(),
            batch as usize * std::mem::size_of::<u32>(),
            "Fix: top-1 index output slot must reserve exactly one u32 per batch."
        );
        let words_per_activation = activations.len() / batch as usize;
        let cols = (words_per_activation as u32) * 8;
        let (scores, indices) = i4x8_batched_matmul_top1_f32_scaled_cpu(
            &weights,
            &activations,
            &row_scales,
            &batch_scales,
            batch,
            rows,
            cols,
        );
        Ok(vec![
            vyre_primitives::wire::pack_f32_slice(&scores),
            vyre_primitives::wire::pack_u32_slice(&indices),
        ])
    }
}

fn pack_i4_rows(rows: &[&[i32]]) -> Vec<u32> {
    let mut packed = Vec::new();
    for row in rows {
        packed.extend(pack_i4x8_cpu(row));
    }
    packed
}

#[test]
fn unpack_i4x8_via_dispatches_signed_boundaries() {
    let values = [-8, -7, -1, 0, 1, 2, 6, 7, -3, 4, 5, -5, -6, 3, -2, 0, 7];
    let packed = pack_i4x8_cpu(&values);

    let out = unpack_i4x8_via(&QuantizedDispatcher, &packed, values.len() as u32)
        .expect("Fix: CUDA parity tests require backend dispatch; skip test if GPU unavailable, do not panic - fake dispatcher unpacks signed INT4 lanes");

    assert_eq!(out, values);
}

#[test]
fn unpack_i4x8_via_reuses_scratch_and_output() {
    let values = [-8, -1, 0, 7, 3, -3, 6, -6];
    let packed = pack_i4x8_cpu(&values);
    let mut scratch = QuantizedUnpackGpuScratch {
        inputs: vec![Vec::with_capacity(64), Vec::with_capacity(64)],
        program_cache: ProgramCache::default(),
    };
    let mut out = Vec::with_capacity(16);
    let input_ptrs = scratch.inputs.iter().map(Vec::as_ptr).collect::<Vec<_>>();
    let out_ptr = out.as_ptr();

    unpack_i4x8_via_with_scratch_into(
        &QuantizedDispatcher,
        &packed,
        values.len() as u32,
        &mut scratch,
        &mut out,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - first unpack succeeds");
    assert_eq!(
            scratch.program_cache.builds(),
            1,
            "Fix: first quantized dispatch should build exactly one shape-specialized primitive Program."
        );
    unpack_i4x8_via_with_scratch_into(
        &QuantizedDispatcher,
        &packed,
        values.len() as u32,
        &mut scratch,
        &mut out,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - second unpack reuses buffers");
    assert_eq!(
            scratch.program_cache.builds(),
            1,
            "Fix: repeated quantized dispatch with the same lane shape must reuse the primitive Program."
        );

    assert_eq!(out, values);
    for (before, after) in input_ptrs
        .iter()
        .zip(scratch.inputs.iter().map(Vec::as_ptr))
    {
        assert_eq!(*before, after);
    }
    assert_eq!(out.as_ptr(), out_ptr);
}

#[test]
fn unpack_i4x8_via_rebuilds_cached_program_only_on_lane_shape_change() {
    let values8 = [-8, -1, 0, 7, 3, -3, 6, -6];
    let values9 = [-8, -1, 0, 7, 3, -3, 6, -6, 2];
    let packed8 = pack_i4x8_cpu(&values8);
    let packed9 = pack_i4x8_cpu(&values9);
    let mut scratch = QuantizedUnpackGpuScratch::default();
    let mut out = Vec::new();

    unpack_i4x8_via_with_scratch_into(
        &QuantizedDispatcher,
        &packed8,
        values8.len() as u32,
        &mut scratch,
        &mut out,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - first shape succeeds");
    unpack_i4x8_via_with_scratch_into(
        &QuantizedDispatcher,
        &packed8,
        values8.len() as u32,
        &mut scratch,
        &mut out,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - same shape succeeds");
    unpack_i4x8_via_with_scratch_into(
        &QuantizedDispatcher,
        &packed9,
        values9.len() as u32,
        &mut scratch,
        &mut out,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - changed shape succeeds");

    assert_eq!(out, values9);
    assert_eq!(
            scratch.program_cache.builds(),
            2,
            "Fix: quantized dispatch should rebuild the primitive Program only when lane_count changes."
        );
}

#[test]
fn unpack_i4x8_via_rejects_shape_errors_before_dispatch() {
    let err =
        unpack_i4x8_via(&QuantizedDispatcher, &[], 1).expect_err("missing packed word must fail");
    assert!(err.to_string().contains("packed_words.len()"));

    let err = unpack_i4x8_via(&QuantizedDispatcher, &[0], 0).expect_err("zero lanes must fail");
    assert!(err.to_string().contains("lane_count > 0"));
}

#[test]
fn i4x8_dot_f32_scaled_via_dispatches_signed_boundary_accumulators() {
    let lhs_values = [-8, -7, -1, 0, 1, 2, 6, 7];
    let rhs_values = [7, 6, 2, 1, 0, -1, -7, -8];
    let lhs = pack_i4x8_cpu(&lhs_values);
    let rhs = pack_i4x8_cpu(&rhs_values);
    let lhs_scale = 0.125;
    let rhs_scale = 0.25;

    let out = i4x8_dot_f32_scaled_via(
        &QuantizedDotDispatcher,
        &lhs,
        &rhs,
        lhs_scale,
        rhs_scale,
        lhs_values.len() as u32,
    )
    .expect("Fix: CUDA parity tests require backend dispatch; skip test if GPU unavailable, do not panic - fake dispatcher computes scaled INT4 dot");
    let expected =
        i4x8_dot_f32_scaled_cpu(&lhs, &rhs, lhs_scale, rhs_scale, lhs_values.len() as u32);

    assert_eq!(out.to_bits(), expected.to_bits());
}

#[test]
fn i4x8_dot_f32_scaled_via_reuses_cached_program_for_same_lane_shape() {
    let lhs8 = pack_i4x8_cpu(&[-8, -1, 0, 7, 3, -3, 6, -6]);
    let rhs8 = pack_i4x8_cpu(&[7, 1, -1, -8, 2, -2, 5, -5]);
    let lhs9 = pack_i4x8_cpu(&[-8, -1, 0, 7, 3, -3, 6, -6, 4]);
    let rhs9 = pack_i4x8_cpu(&[7, 1, -1, -8, 2, -2, 5, -5, 3]);
    let mut scratch = QuantizedDotGpuScratch::default();
    let mut out = Vec::with_capacity(1);

    i4x8_dot_f32_scaled_via_with_scratch_into(
        &QuantizedDotDispatcher,
        &lhs8,
        &rhs8,
        0.5,
        0.25,
        8,
        &mut scratch,
        &mut out,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - first dot shape succeeds");
    i4x8_dot_f32_scaled_via_with_scratch_into(
        &QuantizedDotDispatcher,
        &lhs8,
        &rhs8,
        0.25,
        0.5,
        8,
        &mut scratch,
        &mut out,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - same dot shape succeeds");
    assert_eq!(
        scratch.program_cache.builds(),
        1,
        "Fix: repeated same-shape INT4 dot dispatch must reuse the primitive Program."
    );

    i4x8_dot_f32_scaled_via_with_scratch_into(
        &QuantizedDotDispatcher,
        &lhs9,
        &rhs9,
        0.25,
        0.5,
        9,
        &mut scratch,
        &mut out,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - changed dot shape succeeds");
    assert_eq!(
        scratch.program_cache.builds(),
        2,
        "Fix: INT4 dot dispatch should rebuild the primitive Program only when lane_count changes."
    );
}

#[test]
fn generated_i4x8_dot_hot_warm_cache_survives_alternating_shapes() {
    let mut scratch = QuantizedDotGpuScratch::default();
    let mut out = Vec::with_capacity(1);

    for seed in 0..8192u32 {
        let lane_count = if seed % 2 == 0 { 8 } else { 16 };
        let lhs_values = generated_i4_values(lane_count as usize, seed ^ 0x9e37_79b9);
        let rhs_values = generated_i4_values(lane_count as usize, seed ^ 0x85eb_ca6b);
        let lhs = pack_i4x8_cpu(&lhs_values);
        let rhs = pack_i4x8_cpu(&rhs_values);
        let lhs_scale = 0.03125 * f32::from((seed % 7) as u8 + 1);
        let rhs_scale = 0.015625 * f32::from((seed % 5) as u8 + 1);

        i4x8_dot_f32_scaled_via_with_scratch_into(
            &QuantizedDotDispatcher,
            &lhs,
            &rhs,
            lhs_scale,
            rhs_scale,
            lane_count,
            &mut scratch,
            &mut out,
        )
        .expect("Fix: CUDA parity tests require backend dispatch; skip test if GPU unavailable, do not panic - generated alternating INT4 dot dispatch should succeed");

        let expected = i4x8_dot_f32_scaled_cpu(&lhs, &rhs, lhs_scale, rhs_scale, lane_count);
        assert_eq!(
            out[0].to_bits(),
            expected.to_bits(),
            "seed={seed} lane_count={lane_count}"
        );
    }

    assert_eq!(
            scratch.program_cache.builds(),
            2,
            "Fix: alternating two INT4 dot lane shapes must stay in the hot/warm ProgramCache instead of rebuilding every dispatch."
        );
}

#[test]

fn i4x8_dot_f32_scaled_via_rejects_bad_shape_before_dispatch() {
    let err = i4x8_dot_f32_scaled_via(&QuantizedDotDispatcher, &[0], &[0], 1.0, 1.0, 0)
        .expect_err("zero lanes must fail");
    assert!(err.to_string().contains("lane_count > 0"));

    let err = i4x8_dot_f32_scaled_via(&QuantizedDotDispatcher, &[], &[0], 1.0, 1.0, 8)
        .expect_err("missing lhs packed word must fail");
    assert!(err.to_string().contains("packed lengths"));
}

#[test]
fn i4x8_dot_f32_scaled_via_rejects_malformed_backend_outputs() {
    let lhs = pack_i4x8_cpu(&[-1, 2, 3, -4, 5, -6, 7, -8]);
    let rhs = pack_i4x8_cpu(&[7, -6, 5, -4, 3, -2, 1, 0]);
    let no_outputs = MalformedDotDispatcher { outputs: vec![] };
    let err = i4x8_dot_f32_scaled_via(&no_outputs, &lhs, &rhs, 1.0, 1.0, 8)
        .expect_err("missing output must fail");
    assert!(err.to_string().contains("exactly one output"));

    let short_output = MalformedDotDispatcher {
        outputs: vec![vec![0; 3]],
    };
    let err = i4x8_dot_f32_scaled_via(&short_output, &lhs, &rhs, 1.0, 1.0, 8)
        .expect_err("short output must fail");
    assert!(err.to_string().contains("expected 4 output bytes"));
}

#[test]
fn i4x8_matvec_f32_scaled_via_dispatches_signed_boundary_rows() {
    let rows = 3_u32;
    let cols = 9_u32;
    let row0 = [-8, -7, -1, 0, 1, 2, 6, 7, -3];
    let row1 = [7, 6, 2, 1, 0, -1, -7, -8, 3];
    let row2 = [-4, 5, -6, 4, -2, 3, -5, 2, 1];
    let mut weights = Vec::new();
    for row in [&row0[..], &row1[..], &row2[..]] {
        weights.extend(pack_i4x8_cpu(row));
    }
    let x = [0.5, -1.0, 2.0, -0.25, 0.75, -1.5, 1.25, 0.125, -0.875];
    let row_scales = [0.125, 0.25, 0.5];

    let out = i4x8_matvec_f32_scaled_via(
        &QuantizedMatvecDispatcher,
        &weights,
        &x,
        &row_scales,
        rows,
        cols,
    )
    .expect("Fix: CUDA parity tests require backend dispatch; skip test if GPU unavailable, do not panic - fake dispatcher computes scaled INT4 matvec");
    let expected = i4x8_matvec_f32_scaled_cpu(&weights, &x, &row_scales, rows, cols);

    assert_eq!(out.len(), rows as usize);
    for (actual, expected) in out.iter().zip(expected.iter()) {
        assert_eq!(actual.to_bits(), expected.to_bits());
    }
}

#[test]
fn i4x8_matvec_f32_scaled_via_reuses_cached_program_for_same_shape() {
    let rows = 2_u32;
    let cols = 8_u32;
    let weights = pack_i4x8_cpu(&[-8, -1, 0, 7, 3, -3, 6, -6, 7, 1, -1, -8, 2, -2, 5, -5]);
    let x = [1.0, -1.0, 0.5, 0.25, -0.75, 1.5, -0.5, 2.0];
    let row_scales = [0.25, 0.5];
    let mut changed_weights = Vec::new();
    changed_weights.extend(pack_i4x8_cpu(&[-8, -1, 0, 7, 3, -3, 6, -6, 4]));
    changed_weights.extend(pack_i4x8_cpu(&[7, 1, -1, -8, 2, -2, 5, -5, 3]));
    let changed_x = [1.0, -1.0, 0.5, 0.25, -0.75, 1.5, -0.5, 2.0, 0.125];
    let mut scratch = QuantizedMatvecGpuScratch::default();
    let mut out = Vec::new();

    i4x8_matvec_f32_scaled_via_with_scratch_into(
        &QuantizedMatvecDispatcher,
        &weights,
        &x,
        &row_scales,
        rows,
        cols,
        &mut scratch,
        &mut out,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - first matvec shape succeeds");
    i4x8_matvec_f32_scaled_via_with_scratch_into(
        &QuantizedMatvecDispatcher,
        &weights,
        &x,
        &row_scales,
        rows,
        cols,
        &mut scratch,
        &mut out,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - same matvec shape succeeds");
    assert_eq!(
        scratch.program_cache.builds(),
        1,
        "Fix: repeated same-shape INT4 matvec dispatch must reuse the primitive Program."
    );

    i4x8_matvec_f32_scaled_via_with_scratch_into(
        &QuantizedMatvecDispatcher,
        &changed_weights,
        &changed_x,
        &row_scales,
        rows,
        9,
        &mut scratch,
        &mut out,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - changed matvec shape succeeds");
    assert_eq!(
            scratch.program_cache.builds(),
            2,
            "Fix: INT4 matvec dispatch should rebuild the primitive Program only when rows/cols changes."
        );
}

#[test]
fn i4x8_matvec_f32_scaled_via_rejects_shape_errors_before_dispatch() {
    let weights = pack_i4x8_cpu(&[-1, 2, 3, -4, 5, -6, 7, -8]);
    let x = [1.0; 8];
    let row_scales = [0.5];

    let err =
        i4x8_matvec_f32_scaled_via(&QuantizedMatvecDispatcher, &weights, &x, &row_scales, 0, 8)
            .expect_err("zero rows must fail");
    assert!(err.to_string().contains("rows > 0 and cols > 0"));

    let err = i4x8_matvec_f32_scaled_via(&QuantizedMatvecDispatcher, &[], &x, &row_scales, 1, 8)
        .expect_err("missing weights must fail");
    assert!(err.to_string().contains("weights_packed.len()"));

    let err = i4x8_matvec_f32_scaled_via(
        &QuantizedMatvecDispatcher,
        &weights,
        &x[..7],
        &row_scales,
        1,
        8,
    )
    .expect_err("short x must fail");
    assert!(err.to_string().contains("x.len() == cols"));

    let err = i4x8_matvec_f32_scaled_via(&QuantizedMatvecDispatcher, &weights, &x, &[], 1, 8)
        .expect_err("missing scale must fail");
    assert!(err.to_string().contains("row_scales.len() == rows"));
}

#[test]
fn i4x8_matvec_f32_scaled_via_rejects_malformed_backend_outputs() {
    let weights = pack_i4x8_cpu(&[-1, 2, 3, -4, 5, -6, 7, -8]);
    let x = [1.0; 8];
    let row_scales = [0.5];
    let no_outputs = MalformedDotDispatcher { outputs: vec![] };
    let err = i4x8_matvec_f32_scaled_via(&no_outputs, &weights, &x, &row_scales, 1, 8)
        .expect_err("missing output must fail");
    assert!(err.to_string().contains("exactly one output"));

    let trailing_output = MalformedDotDispatcher {
        outputs: vec![vec![0; 8]],
    };
    let err = i4x8_matvec_f32_scaled_via(&trailing_output, &weights, &x, &row_scales, 1, 8)
        .expect_err("trailing output bytes must fail");
    assert!(err.to_string().contains("expected 4 output bytes"));
}

#[test]
fn i4x8_batched_matvec_f32_scaled_via_dispatches_boundary_batches() {
    let batch = 2_u32;
    let rows = 3_u32;
    let cols = 9_u32;
    let mut weights = Vec::new();
    for row in [
        &[-8, -7, -1, 0, 1, 2, 6, 7, -3][..],
        &[7, 6, 2, 1, 0, -1, -7, -8, 3][..],
        &[-4, 5, -6, 4, -2, 3, -5, 2, 1][..],
    ] {
        weights.extend(pack_i4x8_cpu(row));
    }
    let x_batches = [
        0.5, -1.0, 2.0, -0.25, 0.75, -1.5, 1.25, 0.125, -0.875, -0.25, 0.5, -0.75, 1.0, -1.25, 1.5,
        -1.75, 2.0, -2.25,
    ];
    let row_scales = [0.125, 0.25, 0.5];

    let out = i4x8_batched_matvec_f32_scaled_via(
        &QuantizedBatchedMatvecDispatcher,
        &weights,
        &x_batches,
        &row_scales,
        batch,
        rows,
        cols,
    )
    .expect("Fix: CUDA parity tests require backend dispatch; skip test if GPU unavailable, do not panic - fake dispatcher computes batched scaled INT4 matvec");
    let expected =
        i4x8_batched_matvec_f32_scaled_cpu(&weights, &x_batches, &row_scales, batch, rows, cols);

    assert_eq!(out.len(), (batch * rows) as usize);
    for (actual, expected) in out.iter().zip(expected.iter()) {
        assert_eq!(actual.to_bits(), expected.to_bits());
    }
}

#[test]
fn i4x8_batched_matvec_f32_scaled_via_reuses_cached_program_for_same_shape() {
    let batch = 2_u32;
    let rows = 2_u32;
    let cols = 8_u32;
    let weights = pack_i4x8_cpu(&[-8, -1, 0, 7, 3, -3, 6, -6, 7, 1, -1, -8, 2, -2, 5, -5]);
    let x_batches = [
        1.0, -1.0, 0.5, 0.25, -0.75, 1.5, -0.5, 2.0, -0.125, 0.25, -0.5, 0.75, -1.0, 1.25, -1.5,
        1.75,
    ];
    let row_scales = [0.25, 0.5];
    let changed_x_batches = [
        1.0, -1.0, 0.5, 0.25, -0.75, 1.5, -0.5, 2.0, -0.125, 0.25, -0.5, 0.75, -1.0, 1.25, -1.5,
        1.75, 0.375, -0.625, 0.875, -1.125, 1.375, -1.625, 1.875, -2.125,
    ];
    let mut scratch = QuantizedBatchedMatvecGpuScratch::default();
    let mut out = Vec::new();

    i4x8_batched_matvec_f32_scaled_via_with_scratch_into(
        &QuantizedBatchedMatvecDispatcher,
        &weights,
        &x_batches,
        &row_scales,
        batch,
        rows,
        cols,
        &mut scratch,
        &mut out,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - first batched matvec shape succeeds");
    i4x8_batched_matvec_f32_scaled_via_with_scratch_into(
        &QuantizedBatchedMatvecDispatcher,
        &weights,
        &x_batches,
        &row_scales,
        batch,
        rows,
        cols,
        &mut scratch,
        &mut out,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - same batched matvec shape succeeds");
    assert_eq!(
        scratch.program_cache.builds(),
        1,
        "Fix: repeated same-shape INT4 batched matvec dispatch must reuse the primitive Program."
    );

    i4x8_batched_matvec_f32_scaled_via_with_scratch_into(
        &QuantizedBatchedMatvecDispatcher,
        &weights,
        &changed_x_batches,
        &row_scales,
        3,
        rows,
        cols,
        &mut scratch,
        &mut out,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - changed batched matvec shape succeeds");
    assert_eq!(
            scratch.program_cache.builds(),
            2,
            "Fix: INT4 batched matvec dispatch should rebuild the primitive Program only when batch/rows/cols changes."
        );
}

#[test]
fn i4x8_batched_matvec_f32_scaled_via_rejects_shape_errors_before_dispatch() {
    let weights = pack_i4x8_cpu(&[-1, 2, 3, -4, 5, -6, 7, -8]);
    let x_batches = [1.0; 16];
    let row_scales = [0.5];

    let err = i4x8_batched_matvec_f32_scaled_via(
        &QuantizedBatchedMatvecDispatcher,
        &weights,
        &x_batches,
        &row_scales,
        0,
        1,
        8,
    )
    .expect_err("zero batch must fail");
    assert!(err.to_string().contains("batch > 0"));

    let err = i4x8_batched_matvec_f32_scaled_via(
        &QuantizedBatchedMatvecDispatcher,
        &[],
        &x_batches,
        &row_scales,
        2,
        1,
        8,
    )
    .expect_err("missing weights must fail");
    assert!(err.to_string().contains("weights_packed.len()"));

    let err = i4x8_batched_matvec_f32_scaled_via(
        &QuantizedBatchedMatvecDispatcher,
        &weights,
        &x_batches[..15],
        &row_scales,
        2,
        1,
        8,
    )
    .expect_err("short x batch must fail");
    assert!(err.to_string().contains("x_batches.len() == batch*cols"));

    let err = i4x8_batched_matvec_f32_scaled_via(
        &QuantizedBatchedMatvecDispatcher,
        &weights,
        &x_batches,
        &[],
        2,
        1,
        8,
    )
    .expect_err("missing scale must fail");
    assert!(err.to_string().contains("row_scales.len() == rows"));
}

#[test]
fn i4x8_batched_matvec_f32_scaled_via_rejects_malformed_backend_outputs() {
    let weights = pack_i4x8_cpu(&[-1, 2, 3, -4, 5, -6, 7, -8]);
    let x_batches = [1.0; 16];
    let row_scales = [0.5];
    let no_outputs = MalformedDotDispatcher { outputs: vec![] };
    let err =
        i4x8_batched_matvec_f32_scaled_via(&no_outputs, &weights, &x_batches, &row_scales, 2, 1, 8)
            .expect_err("missing output must fail");
    assert!(err.to_string().contains("exactly one output"));

    let trailing_output = MalformedDotDispatcher {
        outputs: vec![vec![0; 12]],
    };
    let err = i4x8_batched_matvec_f32_scaled_via(
        &trailing_output,
        &weights,
        &x_batches,
        &row_scales,
        2,
        1,
        8,
    )
    .expect_err("trailing output bytes must fail");
    assert!(err.to_string().contains("expected 8 output bytes"));
}

#[test]
fn i4x8_batched_matmul_f32_scaled_via_dispatches_boundary_batches() {
    let batch = 2_u32;
    let rows = 3_u32;
    let cols = 9_u32;
    let weights = pack_i4_rows(&[
        &[-8, -7, -1, 0, 1, 2, 6, 7, -3],
        &[7, 6, 2, 1, 0, -1, -7, -8, 3],
        &[-4, 5, -6, 4, -2, 3, -5, 2, 1],
    ]);
    let activations = pack_i4_rows(&[
        &[7, 5, 3, 1, -1, -3, -5, -7, 6],
        &[-8, -6, -4, -2, 0, 2, 4, 6, 7],
    ]);
    let row_scales = [0.125, 0.25, 0.5];
    let batch_scales = [0.25, 0.375];

    let out = i4x8_batched_matmul_f32_scaled_via(
        &QuantizedBatchedMatmulDispatcher,
        &weights,
        &activations,
        &row_scales,
        &batch_scales,
        batch,
        rows,
        cols,
    )
    .expect("Fix: CUDA parity tests require backend dispatch; skip test if GPU unavailable, do not panic - fake dispatcher computes batched scaled INT4 matmul");
    let expected = i4x8_batched_matmul_f32_scaled_cpu(
        &weights,
        &activations,
        &row_scales,
        &batch_scales,
        batch,
        rows,
        cols,
    );

    assert_eq!(out.len(), (batch * rows) as usize);
    for (actual, expected) in out.iter().zip(expected.iter()) {
        assert_eq!(actual.to_bits(), expected.to_bits());
    }
}

#[test]
fn i4x8_batched_matmul_f32_scaled_via_reuses_cached_program_for_same_shape() {
    let batch = 2_u32;
    let rows = 2_u32;
    let cols = 8_u32;
    let weights = pack_i4_rows(&[&[-8, -1, 0, 7, 3, -3, 6, -6], &[7, 1, -1, -8, 2, -2, 5, -5]]);
    let activations = pack_i4_rows(&[&[7, 5, 3, 1, -1, -3, -5, -7], &[-8, -6, -4, -2, 0, 2, 4, 6]]);
    let changed_activations = pack_i4_rows(&[
        &[7, 5, 3, 1, -1, -3, -5, -7],
        &[-8, -6, -4, -2, 0, 2, 4, 6],
        &[1, -1, 2, -2, 3, -3, 4, -4],
    ]);
    let row_scales = [0.25, 0.5];
    let batch_scales = [0.125, 0.375, 0.625];
    let mut scratch = QuantizedBatchedMatmulGpuScratch::default();
    let mut out = Vec::new();

    i4x8_batched_matmul_f32_scaled_via_with_scratch_into(
        &QuantizedBatchedMatmulDispatcher,
        &weights,
        &activations,
        &row_scales,
        &batch_scales[..2],
        batch,
        rows,
        cols,
        &mut scratch,
        &mut out,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - first batched matmul shape succeeds");
    i4x8_batched_matmul_f32_scaled_via_with_scratch_into(
        &QuantizedBatchedMatmulDispatcher,
        &weights,
        &activations,
        &row_scales,
        &batch_scales[..2],
        batch,
        rows,
        cols,
        &mut scratch,
        &mut out,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - same batched matmul shape succeeds");
    assert_eq!(
        scratch.program_cache.builds(),
        1,
        "Fix: repeated same-shape INT4 batched matmul dispatch must reuse the primitive Program."
    );

    i4x8_batched_matmul_f32_scaled_via_with_scratch_into(
        &QuantizedBatchedMatmulDispatcher,
        &weights,
        &changed_activations,
        &row_scales,
        &batch_scales,
        3,
        rows,
        cols,
        &mut scratch,
        &mut out,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - changed batched matmul shape succeeds");
    assert_eq!(
            scratch.program_cache.builds(),
            2,
            "Fix: INT4 batched matmul dispatch should rebuild the primitive Program only when batch/rows/cols changes."
        );
}

#[test]

fn i4x8_batched_matmul_f32_scaled_via_rejects_shape_errors_before_dispatch() {
    let weights = pack_i4_rows(&[&[-1, 2, 3, -4, 5, -6, 7, -8]]);
    let activations = pack_i4_rows(&[&[7, 5, 3, 1, -1, -3, -5, -7], &[-8, -6, -4, -2, 0, 2, 4, 6]]);
    let row_scales = [0.5];
    let batch_scales = [0.25, 0.375];

    let err = i4x8_batched_matmul_f32_scaled_via(
        &QuantizedBatchedMatmulDispatcher,
        &weights,
        &activations,
        &row_scales,
        &batch_scales,
        0,
        1,
        8,
    )
    .expect_err("zero batch must fail");
    assert!(err.to_string().contains("batch > 0"));

    let err = i4x8_batched_matmul_f32_scaled_via(
        &QuantizedBatchedMatmulDispatcher,
        &[],
        &activations,
        &row_scales,
        &batch_scales,
        2,
        1,
        8,
    )
    .expect_err("missing weights must fail");
    assert!(err.to_string().contains("weights_packed.len()"));

    let err = i4x8_batched_matmul_f32_scaled_via(
        &QuantizedBatchedMatmulDispatcher,
        &weights,
        &activations[..1],
        &row_scales,
        &batch_scales,
        2,
        1,
        8,
    )
    .expect_err("short activations must fail");
    assert!(err.to_string().contains("activation_batches_packed.len()"));

    let err = i4x8_batched_matmul_f32_scaled_via(
        &QuantizedBatchedMatmulDispatcher,
        &weights,
        &activations,
        &[],
        &batch_scales,
        2,
        1,
        8,
    )
    .expect_err("missing row scale must fail");
    assert!(err.to_string().contains("row_scales.len() == rows"));

    let err = i4x8_batched_matmul_f32_scaled_via(
        &QuantizedBatchedMatmulDispatcher,
        &weights,
        &activations,
        &row_scales,
        &batch_scales[..1],
        2,
        1,
        8,
    )
    .expect_err("missing batch scale must fail");
    assert!(err.to_string().contains("batch_scales.len() == batch"));
}

#[test]
fn i4x8_batched_matmul_f32_scaled_via_rejects_malformed_backend_outputs() {
    let weights = pack_i4_rows(&[&[-1, 2, 3, -4, 5, -6, 7, -8]]);
    let activations = pack_i4_rows(&[&[7, 5, 3, 1, -1, -3, -5, -7], &[-8, -6, -4, -2, 0, 2, 4, 6]]);
    let row_scales = [0.5];
    let batch_scales = [0.25, 0.375];
    let no_outputs = MalformedDotDispatcher { outputs: vec![] };
    let err = i4x8_batched_matmul_f32_scaled_via(
        &no_outputs,
        &weights,
        &activations,
        &row_scales,
        &batch_scales,
        2,
        1,
        8,
    )
    .expect_err("missing output must fail");
    assert!(err.to_string().contains("exactly one output"));

    let trailing_output = MalformedDotDispatcher {
        outputs: vec![vec![0; 12]],
    };
    let err = i4x8_batched_matmul_f32_scaled_via(
        &trailing_output,
        &weights,
        &activations,
        &row_scales,
        &batch_scales,
        2,
        1,
        8,
    )
    .expect_err("trailing output bytes must fail");
    assert!(err.to_string().contains("expected 8 output bytes"));
}

#[test]
fn i4x8_batched_matmul_top1_f32_scaled_via_dispatches_boundary_batches() {
    let batch = 3_u32;
    let rows = 4_u32;
    let cols = 8_u32;
    let weights = pack_i4_rows(&[
        &[-8, -7, -1, 0, 1, 2, 6, 7],
        &[7, 6, 2, 1, 0, -1, -7, -8],
        &[-4, 5, -6, 4, -2, 3, -5, 2],
        &[3, -3, 4, -4, 5, -5, 6, -6],
    ]);
    let activations = pack_i4_rows(&[
        &[7, 5, 3, 1, -1, -3, -5, -7],
        &[-8, -6, -4, -2, 0, 2, 4, 6],
        &[1, -1, 2, -2, 3, -3, 4, -4],
    ]);
    let row_scales = [0.125, 0.25, 0.5, 0.75];
    let batch_scales = [0.25, 0.375, 0.625];

    let (scores, indices) = i4x8_batched_matmul_top1_f32_scaled_via(
        &QuantizedBatchedMatmulTop1Dispatcher,
        &weights,
        &activations,
        &row_scales,
        &batch_scales,
        batch,
        rows,
        cols,
    )
    .expect("Fix: CUDA parity tests require backend dispatch; skip test if GPU unavailable, do not panic - fake dispatcher computes top-1 packed INT4 routing");
    let (expected_scores, expected_indices) = i4x8_batched_matmul_top1_f32_scaled_cpu(
        &weights,
        &activations,
        &row_scales,
        &batch_scales,
        batch,
        rows,
        cols,
    );

    assert_eq!(
        scores
            .iter()
            .map(|value| value.to_bits())
            .collect::<Vec<_>>(),
        expected_scores
            .iter()
            .map(|value| value.to_bits())
            .collect::<Vec<_>>()
    );
    assert_eq!(indices, expected_indices);
}

#[test]
fn i4x8_batched_matmul_top1_f32_scaled_via_reuses_cached_program_for_same_shape() {
    let batch = 2_u32;
    let rows = 3_u32;
    let cols = 8_u32;
    let weights = pack_i4_rows(&[
        &[-8, -1, 0, 7, 3, -3, 6, -6],
        &[7, 1, -1, -8, 2, -2, 5, -5],
        &[3, -3, 4, -4, 5, -5, 6, -6],
    ]);
    let activations = pack_i4_rows(&[&[7, 5, 3, 1, -1, -3, -5, -7], &[-8, -6, -4, -2, 0, 2, 4, 6]]);
    let changed_activations = pack_i4_rows(&[
        &[7, 5, 3, 1, -1, -3, -5, -7],
        &[-8, -6, -4, -2, 0, 2, 4, 6],
        &[1, -1, 2, -2, 3, -3, 4, -4],
    ]);
    let row_scales = [0.25, 0.5, 0.75];
    let batch_scales = [0.125, 0.375, 0.625];
    let mut scratch = QuantizedBatchedMatmulTop1GpuScratch::default();
    let mut scores = Vec::new();
    let mut indices = Vec::new();

    i4x8_batched_matmul_top1_f32_scaled_via_with_scratch_into(
        &QuantizedBatchedMatmulTop1Dispatcher,
        &weights,
        &activations,
        &row_scales,
        &batch_scales[..2],
        batch,
        rows,
        cols,
        &mut scratch,
        &mut scores,
        &mut indices,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - first top-1 shape succeeds");
    i4x8_batched_matmul_top1_f32_scaled_via_with_scratch_into(
        &QuantizedBatchedMatmulTop1Dispatcher,
        &weights,
        &activations,
        &row_scales,
        &batch_scales[..2],
        batch,
        rows,
        cols,
        &mut scratch,
        &mut scores,
        &mut indices,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - same top-1 shape succeeds");
    assert_eq!(
        scratch.program_cache.builds(),
        1,
        "Fix: repeated same-shape INT4 top-1 dispatch must reuse the primitive Program."
    );

    i4x8_batched_matmul_top1_f32_scaled_via_with_scratch_into(
        &QuantizedBatchedMatmulTop1Dispatcher,
        &weights,
        &changed_activations,
        &row_scales,
        &batch_scales,
        3,
        rows,
        cols,
        &mut scratch,
        &mut scores,
        &mut indices,
    )
    .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - changed top-1 shape succeeds");
    assert_eq!(
            scratch.program_cache.builds(),
            2,
            "Fix: INT4 top-1 dispatch should rebuild the primitive Program only when batch/rows/cols changes."
        );
}

#[test]
fn i4x8_batched_matmul_top1_f32_scaled_via_rejects_shape_errors_before_dispatch() {
    let weights = pack_i4_rows(&[&[-1, 2, 3, -4, 5, -6, 7, -8]]);
    let activations = pack_i4_rows(&[&[7, 5, 3, 1, -1, -3, -5, -7], &[-8, -6, -4, -2, 0, 2, 4, 6]]);
    let row_scales = [0.5];
    let batch_scales = [0.25, 0.375];

    let err = i4x8_batched_matmul_top1_f32_scaled_via(
        &QuantizedBatchedMatmulTop1Dispatcher,
        &weights,
        &activations,
        &row_scales,
        &batch_scales,
        0,
        1,
        8,
    )
    .expect_err("zero batch must fail");
    assert!(err.to_string().contains("batch > 0"));

    let err = i4x8_batched_matmul_top1_f32_scaled_via(
        &QuantizedBatchedMatmulTop1Dispatcher,
        &[],
        &activations,
        &row_scales,
        &batch_scales,
        2,
        1,
        8,
    )
    .expect_err("missing weights must fail");
    assert!(err.to_string().contains("weights_packed.len()"));

    let err = i4x8_batched_matmul_top1_f32_scaled_via(
        &QuantizedBatchedMatmulTop1Dispatcher,
        &weights,
        &activations[..1],
        &row_scales,
        &batch_scales,
        2,
        1,
        8,
    )
    .expect_err("short activations must fail");
    assert!(err.to_string().contains("activation_batches_packed.len()"));

    let err = i4x8_batched_matmul_top1_f32_scaled_via(
        &QuantizedBatchedMatmulTop1Dispatcher,
        &weights,
        &activations,
        &[],
        &batch_scales,
        2,
        1,
        8,
    )
    .expect_err("missing row scale must fail");
    assert!(err.to_string().contains("row_scales.len() == rows"));

    let err = i4x8_batched_matmul_top1_f32_scaled_via(
        &QuantizedBatchedMatmulTop1Dispatcher,
        &weights,
        &activations,
        &row_scales,
        &batch_scales[..1],
        2,
        1,
        8,
    )
    .expect_err("missing batch scale must fail");
    assert!(err.to_string().contains("batch_scales.len() == batch"));
}

#[test]
fn i4x8_batched_matmul_top1_f32_scaled_via_rejects_malformed_backend_outputs() {
    let weights = pack_i4_rows(&[&[-1, 2, 3, -4, 5, -6, 7, -8]]);
    let activations = pack_i4_rows(&[&[7, 5, 3, 1, -1, -3, -5, -7], &[-8, -6, -4, -2, 0, 2, 4, 6]]);
    let row_scales = [0.5];
    let batch_scales = [0.25, 0.375];
    let no_outputs = MalformedDotDispatcher { outputs: vec![] };
    let err = i4x8_batched_matmul_top1_f32_scaled_via(
        &no_outputs,
        &weights,
        &activations,
        &row_scales,
        &batch_scales,
        2,
        1,
        8,
    )
    .expect_err("missing outputs must fail");
    assert!(err.to_string().contains("exactly two output buffers"));

    let one_output = MalformedDotDispatcher {
        outputs: vec![vec![0; 8]],
    };
    let err = i4x8_batched_matmul_top1_f32_scaled_via(
        &one_output,
        &weights,
        &activations,
        &row_scales,
        &batch_scales,
        2,
        1,
        8,
    )
    .expect_err("one output must fail");
    assert!(err.to_string().contains("exactly two output buffers"));

    let trailing_index_output = MalformedDotDispatcher {
        outputs: vec![vec![0; 8], vec![0; 12]],
    };
    let err = i4x8_batched_matmul_top1_f32_scaled_via(
        &trailing_index_output,
        &weights,
        &activations,
        &row_scales,
        &batch_scales,
        2,
        1,
        8,
    )
    .expect_err("trailing index output bytes must fail");
    assert!(err.to_string().contains("expected 8 output bytes"));
}
fn generated_i4_values(len: usize, seed: u32) -> Vec<i32> {
    (0..len)
        .map(|idx| {
            let mixed = (idx as u32)
                .wrapping_mul(17)
                .wrapping_add(seed.wrapping_mul(31))
                .wrapping_add((idx as u32 ^ seed).rotate_left((idx % 5) as u32));
            (mixed % 16) as i32 - 8
        })
        .collect()
}

fn generated_f32_values(len: usize, seed: u32) -> Vec<f32> {
    (0..len)
        .map(|idx| {
            let signed = ((idx as i32 * 13 + seed as i32 * 7) % 17) - 8;
            signed as f32 * 0.125
        })
        .collect()
}

fn generated_weight_rows(rows: u32, cols: u32, seed: u32) -> Vec<Vec<i32>> {
    (0..rows)
        .map(|row| generated_i4_values(cols as usize, seed.wrapping_add(row * 19)))
        .collect()
}

fn generated_activation_rows(batch: u32, cols: u32, seed: u32) -> Vec<Vec<i32>> {
    (0..batch)
        .map(|batch_idx| generated_i4_values(cols as usize, seed.wrapping_add(batch_idx * 23)))
        .collect()
}

fn pack_owned_i4_rows(rows: &[Vec<i32>]) -> Vec<u32> {
    let refs = rows.iter().map(Vec::as_slice).collect::<Vec<_>>();
    pack_i4_rows(&refs)
}

#[test]
fn generated_quantized_wrappers_match_oracles_across_boundary_shapes() {
    for (case_idx, lane_count) in [1_u32, 7, 8, 9, 15, 16, 31, 32, 33, 65]
        .iter()
        .copied()
        .enumerate()
    {
        let lhs_values = generated_i4_values(lane_count as usize, case_idx as u32 + 1);
        let rhs_values = generated_i4_values(lane_count as usize, case_idx as u32 + 101);
        let lhs = pack_i4x8_cpu(&lhs_values);
        let rhs = pack_i4x8_cpu(&rhs_values);
        let lhs_scale = 0.125 + case_idx as f32 * 0.03125;
        let rhs_scale = 0.25 + case_idx as f32 * 0.015625;
        let actual = i4x8_dot_f32_scaled_via(
            &QuantizedDotDispatcher,
            &lhs,
            &rhs,
            lhs_scale,
            rhs_scale,
            lane_count,
        )
        .expect("Fix: CUDA parity tests require backend dispatch; skip test if GPU unavailable, do not panic - generated INT4 dot dispatch should match oracle");
        let expected = i4x8_dot_f32_scaled_cpu(&lhs, &rhs, lhs_scale, rhs_scale, lane_count);
        assert_eq!(
            actual.to_bits(),
            expected.to_bits(),
            "dot lane_count={lane_count}"
        );
    }

    for (case_idx, (rows, cols)) in [(1_u32, 1_u32), (2, 7), (3, 8), (4, 9), (5, 17), (3, 33)]
        .iter()
        .copied()
        .enumerate()
    {
        let row_values = generated_weight_rows(rows, cols, 200 + case_idx as u32);
        let weights = pack_owned_i4_rows(&row_values);
        let x = generated_f32_values(cols as usize, 300 + case_idx as u32);
        let row_scales = generated_f32_values(rows as usize, 400 + case_idx as u32)
            .into_iter()
            .map(|value| value.abs() + 0.125)
            .collect::<Vec<_>>();
        let actual = i4x8_matvec_f32_scaled_via(
            &QuantizedMatvecDispatcher,
            &weights,
            &x,
            &row_scales,
            rows,
            cols,
        )
        .expect("Fix: CUDA parity tests require backend dispatch; skip test if GPU unavailable, do not panic - generated INT4 matvec dispatch should match oracle");
        let expected = i4x8_matvec_f32_scaled_cpu(&weights, &x, &row_scales, rows, cols);
        assert_eq!(
            actual
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>(),
            "matvec rows={rows} cols={cols}"
        );
    }

    for (case_idx, (batch, rows, cols)) in [
        (1_u32, 1_u32, 1_u32),
        (2, 2, 7),
        (3, 3, 8),
        (4, 4, 9),
        (5, 3, 17),
        (3, 5, 33),
    ]
    .iter()
    .copied()
    .enumerate()
    {
        let row_values = generated_weight_rows(rows, cols, 500 + case_idx as u32);
        let weights = pack_owned_i4_rows(&row_values);
        let x_batches = generated_f32_values((batch * cols) as usize, 600 + case_idx as u32);
        let row_scales = generated_f32_values(rows as usize, 700 + case_idx as u32)
            .into_iter()
            .map(|value| value.abs() + 0.125)
            .collect::<Vec<_>>();
        let actual = i4x8_batched_matvec_f32_scaled_via(
            &QuantizedBatchedMatvecDispatcher,
            &weights,
            &x_batches,
            &row_scales,
            batch,
            rows,
            cols,
        )
        .expect("Fix: CUDA parity tests require backend dispatch; skip test if GPU unavailable, do not panic - generated INT4 batched matvec dispatch should match oracle");
        let expected = i4x8_batched_matvec_f32_scaled_cpu(
            &weights,
            &x_batches,
            &row_scales,
            batch,
            rows,
            cols,
        );
        assert_eq!(
            actual
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>(),
            "batched matvec batch={batch} rows={rows} cols={cols}"
        );
    }

    for (case_idx, (batch, rows, cols)) in [
        (1_u32, 1_u32, 1_u32),
        (2, 2, 7),
        (3, 3, 8),
        (4, 4, 9),
        (5, 5, 17),
        (3, 7, 33),
    ]
    .iter()
    .copied()
    .enumerate()
    {
        let weight_rows = generated_weight_rows(rows, cols, 800 + case_idx as u32);
        let activation_rows = generated_activation_rows(batch, cols, 900 + case_idx as u32);
        let weights = pack_owned_i4_rows(&weight_rows);
        let activations = pack_owned_i4_rows(&activation_rows);
        let row_scales = generated_f32_values(rows as usize, 1000 + case_idx as u32)
            .into_iter()
            .map(|value| value.abs() + 0.125)
            .collect::<Vec<_>>();
        let batch_scales = generated_f32_values(batch as usize, 1100 + case_idx as u32)
            .into_iter()
            .map(|value| value.abs() + 0.25)
            .collect::<Vec<_>>();

        let actual = i4x8_batched_matmul_f32_scaled_via(
            &QuantizedBatchedMatmulDispatcher,
            &weights,
            &activations,
            &row_scales,
            &batch_scales,
            batch,
            rows,
            cols,
        )
        .expect("Fix: CUDA parity tests require backend dispatch; skip test if GPU unavailable, do not panic - generated INT4 batched matmul dispatch should match oracle");
        let expected = i4x8_batched_matmul_f32_scaled_cpu(
            &weights,
            &activations,
            &row_scales,
            &batch_scales,
            batch,
            rows,
            cols,
        );
        assert_eq!(
            actual
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>(),
            "batched matmul batch={batch} rows={rows} cols={cols}"
        );

        let (scores, indices) = i4x8_batched_matmul_top1_f32_scaled_via(
            &QuantizedBatchedMatmulTop1Dispatcher,
            &weights,
            &activations,
            &row_scales,
            &batch_scales,
            batch,
            rows,
            cols,
        )
        .expect("Fix: CUDA parity tests require backend dispatch; skip test if GPU unavailable, do not panic - generated INT4 top-1 dispatch should match oracle");
        let (expected_scores, expected_indices) = i4x8_batched_matmul_top1_f32_scaled_cpu(
            &weights,
            &activations,
            &row_scales,
            &batch_scales,
            batch,
            rows,
            cols,
        );
        assert_eq!(
            scores
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>(),
            expected_scores
                .iter()
                .map(|value| value.to_bits())
                .collect::<Vec<_>>(),
            "top1 scores batch={batch} rows={rows} cols={cols}"
        );
        assert_eq!(
            indices, expected_indices,
            "top1 indices batch={batch} rows={rows} cols={cols}"
        );
    }
}

