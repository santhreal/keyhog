//! DET-11 contract guard (always-on, feature-independent).
//!
//! The GPU MoE shader output activation MUST be the same rational sigmoid the
//! CPU MoE uses (`ml_scorer::sigmoid`: `0.5 + 0.5*x/(1+|x|)`, clamped at +/-6),
//! NOT the true logistic `1/(1+exp(-x))`. The two diverge by ~0.05 in the
//! mid-range, far wider than the near-floor band, so a shader using the
//! logistic systematically flips findings between the GPU and the benched
//! CPU/SIMD path (the swing that forced `KEYHOG_NO_GPU=1` to be pinned).
//!
//! This reads the shader SOURCE rather than the `gpu`-gated `MOE_SHADER`
//! constant so it runs in every CI config (the in-crate gpu module only
//! compiles under `--features gpu`, which CI does not always enable). The
//! end-to-end numeric check is `crates/cli/tests/gpu_simd_parity.rs` on GPU
//! hardware.

fn shader_src() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/gpu_shader.rs"
    ))
    .expect("read gpu_shader.rs")
}

#[test]
fn gpu_shader_uses_cpu_rational_sigmoid_not_logistic() {
    let src = shader_src();
    assert!(
        src.contains("0.5 + 0.5 * score_logit / (1.0 + abs(score_logit))"),
        "GPU MoE shader output activation must be the CPU rational sigmoid \
         (DET-11); otherwise the GPU path diverges from the benched CPU path"
    );
    assert!(
        !src.contains("1.0 / (1.0 + exp(-score_logit))"),
        "GPU MoE shader must NOT use the true logistic activation: it diverges \
         from the CPU rational sigmoid by ~0.05 and flips findings (DET-11)"
    );
}

#[test]
fn rational_and_logistic_sigmoids_diverge_beyond_floor_band() {
    // Replicates `ml_scorer::sigmoid` (private), the shape the shader must
    // mirror. If this divergence ever shrinks below the floor band the bug
    // class changed; revisit DET-11.
    fn cpu_sigmoid(x: f32) -> f32 {
        if x <= -6.0 {
            0.0
        } else if x >= 6.0 {
            1.0
        } else {
            0.5 + 0.5 * x / (1.0 + x.abs())
        }
    }
    fn logistic(x: f32) -> f32 {
        1.0 / (1.0 + (-x).exp())
    }
    let mut max_gap = 0.0f32;
    let mut x = -6.0f32;
    while x <= 6.0 {
        max_gap = max_gap.max((cpu_sigmoid(x) - logistic(x)).abs());
        x += 0.01;
    }
    assert!(
        max_gap > 0.04,
        "rational vs logistic sigmoid should diverge by >0.04 (~0.05); got {max_gap}"
    );
}
