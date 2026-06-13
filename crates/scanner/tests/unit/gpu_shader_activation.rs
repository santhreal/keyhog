const GPU_SHADER: &str = include_str!("../../src/gpu/gpu_shader.rs");

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

#[test]
fn rational_and_logistic_sigmoids_diverge_beyond_floor_band() {
    let mut max_gap = 0.0f32;
    let mut x = -6.0f32;
    while x <= 6.0 {
        max_gap = max_gap.max((cpu_sigmoid(x) - logistic(x)).abs());
        x += 0.01;
    }
    assert!(
        max_gap > 0.04,
        "expected rational and logistic activations to diverge by >0.04; got {max_gap}"
    );
}

#[test]
fn shader_uses_cpu_rational_sigmoid_not_logistic() {
    assert!(
        GPU_SHADER.contains("0.5 + 0.5 * score_logit / (1.0 + abs(score_logit))"),
        "MoE shader output activation must match the CPU rational sigmoid"
    );
    assert!(
        !GPU_SHADER.contains("1.0 / (1.0 + exp(-score_logit))"),
        "MoE shader must not use the true logistic activation"
    );
}
