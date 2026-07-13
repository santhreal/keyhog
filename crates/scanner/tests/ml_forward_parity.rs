//! BIT-IDENTITY proof for the MoE forward pass's output-stationary dense kernel.
//!
//! `ml_scorer::dense_relu_layer_t` computes each ReLU dense layer "output-
//! stationary" over COLUMN-major (transposed) weights so the inner loop over
//! outputs vectorizes across lanes. The recall-critical claim is that this is
//! BIT-IDENTICAL to the row-major scalar dot product it replaced, vectorizing
//! across outputs must not reassociate any single output's reduction, and Rust
//! must not contract `a*b + c` into a fused multiply-add (it doesn't, absent
//! fast-math). A previous AVX2+FMA kernel violated exactly this and regressed
//! ~30 ML-gated `contracts_runner` positives.
//!
//! `dense_relu_layer_t` is private, so this test re-expresses BOTH layouts over
//! the same synthetic weights and asserts EXACT f32 equality across 20 000
//! random (weights, bias, input) draws at the two production layer shapes
//! (fc1: 42→32, fc2: 32→16). It locks the layout-equivalence PRINCIPLE the
//! production kernel is a faithful implementation of; the production path itself
//! is additionally validated end-to-end by `contracts_runner` (which is sensitive
//! to sub-ULP score drift, it is what caught the FMA regression) and by
//! `gpu_parity` (CPU vs GPU value agreement).

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

/// Production FC1 shape after DET-1: `model_arch::INPUT_DIM`=43 features → 32 hidden.
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
