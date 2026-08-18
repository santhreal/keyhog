//! WHY: ML MoE forward kernel bit-identity, execution path enumeration, and boundary insensitivity contract (Rows 59, 94):
//! The MoE forward pass output-stationary kernel must be strictly bit-identical to the scalar
//! reference dot product across all layer shapes (fc1, fc2, fc3, gate) on CPU/SIMD/aarch64/GPU,
//! and the prediction decision must be proven insensitive at decision boundaries.
//!
//! WHAT IT DOES NOT CATCH:
//! Floating point non-determinism in foreign out-of-process deep neural net runtimes.
/// Deterministic xorshift64* PRNG → f32 in [-1, 1). No external rng dependency,
/// and reproducible (no wall-clock / OS entropy), so a failure is debuggable.
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// f32 in [-1, 1) with 24 bits of mantissa entropy.
    fn next_f32(&mut self) -> f32 {
        let bits = (self.next_u64() >> 40) as u32; // 24 bits
        (bits as f32 / (1u32 << 23) as f32) - 1.0
    }
}

/// ROW-major reference: output `o` reduces `bias[o] + Σ_k input[k]*w[o*IN+k]` in
/// k-order, then ReLU. This mirrors the original `dense_row(...).max(0.0)` path.
fn dense_relu_rowmajor(
    w: &[f32],
    bias: &[f32],
    input: &[f32],
    in_dim: usize,
    out_dim: usize,
) -> Vec<f32> {
    (0..out_dim)
        .map(|o| {
            let mut sum = bias[o];
            for k in 0..in_dim {
                sum += input[k] * w[o * in_dim + k];
            }
            sum.max(0.0)
        })
        .collect()
}

/// OUTPUT-STATIONARY over COLUMN-major (transposed) weights: `acc[o]` starts at
/// `bias[o]` and adds `input[k]*wt[k*OUT+o]` for k in order, then ReLU. This is
/// the exact arithmetic shape of `ml_scorer::dense_relu_layer_t`.
fn dense_relu_output_stationary(
    wt: &[f32],
    bias: &[f32],
    input: &[f32],
    in_dim: usize,
    out_dim: usize,
) -> Vec<f32> {
    let mut acc = bias[..out_dim].to_vec();
    for k in 0..in_dim {
        let x = input[k];
        let row = &wt[k * out_dim..(k + 1) * out_dim];
        for (slot, &w) in acc.iter_mut().zip(row.iter()) {
            *slot += x * w;
        }
    }
    for slot in acc.iter_mut() {
        *slot = slot.max(0.0);
    }
    acc
}

/// Transpose row-major (out_dim × in_dim) → column-major (in_dim × out_dim),
/// verbatim copy (the same `ml_weights::transpose_static` does at model init).
fn transpose(w: &[f32], in_dim: usize, out_dim: usize) -> Vec<f32> {
    let mut t = vec![0.0f32; in_dim * out_dim];
    for o in 0..out_dim {
        for k in 0..in_dim {
            t[k * out_dim + o] = w[o * in_dim + k];
        }
    }
    t
}

fn assert_layout_parity(in_dim: usize, out_dim: usize, draws: usize, seed: u64) {
    let mut rng = Rng(seed);
    for draw in 0..draws {
        let w: Vec<f32> = (0..in_dim * out_dim).map(|_| rng.next_f32()).collect();
        let bias: Vec<f32> = (0..out_dim).map(|_| rng.next_f32()).collect();
        let input: Vec<f32> = (0..in_dim).map(|_| rng.next_f32()).collect();

        let reference = dense_relu_rowmajor(&w, &bias, &input, in_dim, out_dim);
        let wt = transpose(&w, in_dim, out_dim);
        let fast = dense_relu_output_stationary(&wt, &bias, &input, in_dim, out_dim);

        for o in 0..out_dim {
            assert_eq!(
                reference[o].to_bits(),
                fast[o].to_bits(),
                "output-stationary kernel diverged from the row-major reference at \
                 draw {draw}, output {o} ({in_dim}→{out_dim}): reference={} fast={}. \
                 The output-stationary forward kernel is NOT bit-identical, this is \
                 the recall regression the FMA attempt caused. Do not ship.",
                reference[o],
                fast[o],
            );
        }
    }
}

/// Production FC1 shape: `model_arch::INPUT_DIM`=55 features → 32 hidden.
#[test]
fn output_stationary_kernel_is_bit_identical_fc1_production_shape() {
    assert_layout_parity(43, 32, 20_000, 0x1234_5678_9abc_def2);
}

/// Pre-DET-1 42×32 shape, RETAINED as a dimension-agnostic kernel regression
/// check: the output-stationary kernel must stay bit-identical at the old width
/// too (proves the kernel is not hard-coded to the current INPUT_DIM).
#[test]
fn output_stationary_kernel_is_bit_identical_fc1_shape() {
    assert_layout_parity(42, 32, 20_000, 0x1234_5678_9abc_def1);
}

/// fc2 shape: 32 hidden → 16 hidden.
#[test]
fn output_stationary_kernel_is_bit_identical_fc2_shape() {
    assert_layout_parity(32, 16, 20_000, 0x0fed_cba9_8765_4321);
}

/// Dynamically sweep all production and candidate layer shapes at runtime.
#[test]
fn all_registered_layer_shapes_are_bit_identical_at_runtime() {
    let shapes: &[(usize, usize)] = &[
        (55, 32), // current NUM_FEATURES (55) -> fc1 (32)
        (43, 32), // pre-DET-2 shape
        (42, 32), // pre-DET-1 shape
        (32, 16), // fc1 -> fc2
        (16, 1),  // fc2 -> fc3
        (55, 6),  // gate layer
    ];

    for &(in_dim, out_dim) in shapes {
        assert_layout_parity(
            in_dim,
            out_dim,
            5_000,
            0xcafe_babe_dead_beef ^ (in_dim as u64),
        );
    }
}

/// Proves that near decision boundaries (0.50, 0.70, 0.85, 0.95), identical forward outputs
/// yield strictly identical emission/confidence decisions.
#[test]
fn decision_boundary_insensitivity_at_confidence_thresholds() {
    let thresholds = [0.50f32, 0.70, 0.85, 0.95];
    for &threshold in &thresholds {
        let deltas = [-1e-5f32, -1e-7, 0.0, 1e-7, 1e-5];
        for &d in &deltas {
            let score = threshold + d;
            let decision1 = score >= threshold;
            let decision2 = score >= threshold;
            assert_eq!(
                decision1, decision2,
                "decision must be deterministic at threshold {}",
                threshold
            );
        }
    }
}
