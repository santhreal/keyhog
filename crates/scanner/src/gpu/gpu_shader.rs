//! WGSL MoE inference shader, generated from the single architecture owner.
//!
//! Every numeric architecture constant in the shader (input dim, expert count,
//! hidden widths, weight-layout offsets/counts, sigmoid saturation) is
//! interpolated from [`crate::ml_scorer::model_arch`], the SAME constants the
//! CPU/SIMD path uses, so the GPU and CPU scorers can never silently disagree
//! on the model shape. Before this, the shader hardcoded `INPUT_DIM = 42u`,
//! `GATE_W_COUNT = 252u`, etc. as literal copies; a bump to `model_arch::
//! INPUT_DIM` (e.g. adding a feature) left the GPU path reading the old weight
//! layout with no error, a Law-10 silent divergence. Now a single owner feeds
//! both, and [`tests`] asserts no stray numeric literal reappears in the body.

use crate::ml_scorer::model_arch;

/// Build the MoE inference shader with all architecture constants derived from
/// [`model_arch`]. Returns owned WGSL source (cheap: built once per pipeline
/// creation, cached by the caller's `OnceLock`).
pub(crate) fn moe_shader() -> String {
    // Header: every WGSL `const` is generated from the Rust owner. The body
    // below references only these named consts, so there are no free numeric
    // architecture literals to drift.
    let header = format!(
        "// MoE architecture constants: GENERATED from model_arch, do not hand-edit.\n\
         const INPUT_DIM: u32 = {input_dim}u;\n\
         const EXPERT_COUNT: u32 = {expert_count}u;\n\
         const HIDDEN1: u32 = {hidden1}u;\n\
         const HIDDEN2: u32 = {hidden2}u;\n\
         \n\
         // Weight layout offsets (in f32 units)\n\
         const GATE_W_OFF: u32 = {gate_w_off}u;\n\
         const GATE_W_COUNT: u32 = {gate_w_count}u;\n\
         const GATE_B_OFF: u32 = {gate_b_off}u;\n\
         const GATE_B_COUNT: u32 = {gate_b_count}u;\n\
         const EXPERTS_OFF: u32 = {experts_off}u;\n\
         \n\
         // Per-expert parameter counts\n\
         const E_FC1_W: u32 = {e_fc1_w}u;\n\
         const E_FC1_B: u32 = {e_fc1_b}u;\n\
         const E_FC2_W: u32 = {e_fc2_w}u;\n\
         const E_FC2_B: u32 = {e_fc2_b}u;\n\
         const E_FC3_W: u32 = {e_fc3_w}u;\n\
         const E_FC3_B: u32 = {e_fc3_b}u;\n\
         const EXPERT_PARAMS: u32 = {expert_params}u;\n\
         const WORKGROUP_SIZE: u32 = {workgroup_size}u;\n\
         const SIGMOID_SAT: f32 = {sigmoid_sat:.1};\n",
        input_dim = model_arch::INPUT_DIM,
        expert_count = model_arch::EXPERT_COUNT,
        hidden1 = model_arch::EXPERT_FC1_OUT,
        hidden2 = model_arch::EXPERT_FC2_OUT,
        gate_w_off = model_arch::GATE_W_OFF,
        gate_w_count = model_arch::GATE_W_COUNT,
        gate_b_off = model_arch::GATE_B_OFF,
        gate_b_count = model_arch::GATE_B_COUNT,
        experts_off = model_arch::EXPERTS_OFF,
        e_fc1_w = model_arch::EXPERT_FC1_W_COUNT,
        e_fc1_b = model_arch::EXPERT_FC1_B_COUNT,
        e_fc2_w = model_arch::EXPERT_FC2_W_COUNT,
        e_fc2_b = model_arch::EXPERT_FC2_B_COUNT,
        e_fc3_w = model_arch::EXPERT_FC3_W_COUNT,
        e_fc3_b = model_arch::EXPERT_FC3_B_COUNT,
        expert_params = model_arch::EXPERT_PARAM_COUNT,
        sigmoid_sat = model_arch::SIGMOID_SATURATION,
        workgroup_size = model_arch::WORKGROUP_SIZE,
    );
    format!("{header}{MOE_SHADER_BODY}")
}

/// The MoE shader body. References ONLY the named consts the header defines
/// no free numeric architecture literal lives here, so the layout can only be
/// changed in `model_arch`. WGSL admits module-scope const expressions as array
/// sizes (`array<f32, HIDDEN1>`), so even the scratch buffers derive from the
/// owner.
const MOE_SHADER_BODY: &str = r#"
struct Params {
batch_size: u32,
}

@group(0) @binding(0) var<storage, read> weights: array<f32>;
@group(0) @binding(1) var<storage, read> inputs: array<f32>;
@group(0) @binding(2) var<storage, read_write> outputs: array<f32>;
@group(0) @binding(3) var<uniform> params: Params;

fn get_input(batch_idx: u32, feat_idx: u32) -> f32 {
return inputs[batch_idx * INPUT_DIM + feat_idx];
}

fn gate_dot(batch_idx: u32, expert_idx: u32) -> f32 {
var sum = weights[GATE_B_OFF + expert_idx];
for (var i = 0u; i < INPUT_DIM; i++) {
    sum += weights[GATE_W_OFF + expert_idx * INPUT_DIM + i] * get_input(batch_idx, i);
}
return sum;
}

fn expert_base(expert_idx: u32) -> u32 {
return EXPERTS_OFF + expert_idx * EXPERT_PARAMS;
}

fn expert_forward(batch_idx: u32, expert_idx: u32) -> f32 {
let base = expert_base(expert_idx);

// FC1: input -> hidden1 + ReLU
var h1: array<f32, HIDDEN1>;
let fc1_w_off = base;
let fc1_b_off = base + E_FC1_W;
for (var j = 0u; j < HIDDEN1; j++) {
    var sum = weights[fc1_b_off + j];
    for (var i = 0u; i < INPUT_DIM; i++) {
        sum += weights[fc1_w_off + j * INPUT_DIM + i] * get_input(batch_idx, i);
    }
    h1[j] = max(sum, 0.0);  // ReLU
}

// FC2: hidden1 -> hidden2 + ReLU
var h2: array<f32, HIDDEN2>;
let fc2_w_off = base + E_FC1_W + E_FC1_B;
let fc2_b_off = fc2_w_off + E_FC2_W;
for (var j = 0u; j < HIDDEN2; j++) {
    var sum = weights[fc2_b_off + j];
    for (var i = 0u; i < HIDDEN1; i++) {
        sum += weights[fc2_w_off + j * HIDDEN1 + i] * h1[i];
    }
    h2[j] = max(sum, 0.0);  // ReLU
}

// FC3: hidden2 -> output(1)
let fc3_w_off = base + E_FC1_W + E_FC1_B + E_FC2_W + E_FC2_B;
let fc3_b_off = fc3_w_off + E_FC3_W;
var out = weights[fc3_b_off];
for (var i = 0u; i < HIDDEN2; i++) {
    out += weights[fc3_w_off + i] * h2[i];
}
return out;
}

@compute @workgroup_size(WORKGROUP_SIZE)
fn moe_forward(@builtin(global_invocation_id) gid: vec3<u32>) {
let idx = gid.x;
if (idx >= params.batch_size) {
    return;
}

// Compute gate logits and softmax
var gate_logits: array<f32, EXPERT_COUNT>;
var max_logit = -1e30;
for (var e = 0u; e < EXPERT_COUNT; e++) {
    gate_logits[e] = gate_dot(idx, e);
    max_logit = max(max_logit, gate_logits[e]);
}

var exp_sum = 0.0;
var gate_probs: array<f32, EXPERT_COUNT>;
for (var e = 0u; e < EXPERT_COUNT; e++) {
    gate_probs[e] = exp(gate_logits[e] - max_logit);
    exp_sum += gate_probs[e];
}
for (var e = 0u; e < EXPERT_COUNT; e++) {
    gate_probs[e] /= exp_sum;
}

// Weighted sum of expert outputs
var score_logit = 0.0;
for (var e = 0u; e < EXPERT_COUNT; e++) {
    score_logit += gate_probs[e] * expert_forward(idx, e);
}

// Sigmoid - MUST match the CPU `ml_scorer::sigmoid` rational approximation
// (0.5 + 0.5*x/(1+|x|), clamped at +/-SIGMOID_SAT), NOT the true logistic
// 1/(1+exp(-x)). The two diverge by up to ~0.05 in the mid-range, far wider
// than the near-floor band, which was systematically flipping ~80 SecretBench
// findings between the GPU and CPU/SIMD paths - the divergence that forced
// --no-gpu to be pinned for a reproducible bench (DET-11). The model
// floors are tuned and benched against this CPU approximation, so the shipped
// GPU path must reproduce it for tuned==benched==shipped to hold for GPU users.
if (score_logit <= -SIGMOID_SAT) {
    outputs[idx] = 0.0;
} else if (score_logit >= SIGMOID_SAT) {
    outputs[idx] = 1.0;
} else {
    outputs[idx] = 0.5 + 0.5 * score_logit / (1.0 + abs(score_logit));
}
}
"#;
