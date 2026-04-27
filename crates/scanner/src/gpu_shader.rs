pub(crate) const MOE_SHADER: &str = r#"
// MoE architecture constants
const INPUT_DIM: u32 = 41u;
const EXPERT_COUNT: u32 = 6u;
const HIDDEN1: u32 = 32u;
const HIDDEN2: u32 = 16u;

// Weight layout offsets (in f32 units)
const GATE_W_OFF: u32 = 0u;
const GATE_W_COUNT: u32 = 246u;  // 41 * 6
const GATE_B_OFF: u32 = 246u;
const GATE_B_COUNT: u32 = 6u;
const EXPERTS_OFF: u32 = 252u;

// Per-expert parameter counts
const E_FC1_W: u32 = 1312u;  // 41 * 32
const E_FC1_B: u32 = 32u;
const E_FC2_W: u32 = 512u;   // 32 * 16
const E_FC2_B: u32 = 16u;
const E_FC3_W: u32 = 16u;
const E_FC3_B: u32 = 1u;
const EXPERT_PARAMS: u32 = 1889u;  // sum of above

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

// FC1: input(41) -> hidden1(32) + ReLU
var h1: array<f32, 32>;
let fc1_w_off = base;
let fc1_b_off = base + E_FC1_W;
for (var j = 0u; j < HIDDEN1; j++) {
    var sum = weights[fc1_b_off + j];
    for (var i = 0u; i < INPUT_DIM; i++) {
        sum += weights[fc1_w_off + j * INPUT_DIM + i] * get_input(batch_idx, i);
    }
    h1[j] = max(sum, 0.0);  // ReLU
}

// FC2: hidden1(32) -> hidden2(16) + ReLU
var h2: array<f32, 16>;
let fc2_w_off = base + E_FC1_W + E_FC1_B;
let fc2_b_off = fc2_w_off + E_FC2_W;
for (var j = 0u; j < HIDDEN2; j++) {
    var sum = weights[fc2_b_off + j];
    for (var i = 0u; i < HIDDEN1; i++) {
        sum += weights[fc2_w_off + j * HIDDEN1 + i] * h1[i];
    }
    h2[j] = max(sum, 0.0);  // ReLU
}

// FC3: hidden2(16) -> output(1)
let fc3_w_off = base + E_FC1_W + E_FC1_B + E_FC2_W + E_FC2_B;
let fc3_b_off = fc3_w_off + E_FC3_W;
var out = weights[fc3_b_off];
for (var i = 0u; i < HIDDEN2; i++) {
    out += weights[fc3_w_off + i] * h2[i];
}
return out;
}

@compute @workgroup_size(64)
fn moe_forward(@builtin(global_invocation_id) gid: vec3<u32>) {
let idx = gid.x;
if (idx >= params.batch_size) {
    return;
}

// Compute gate logits and softmax
var gate_logits: array<f32, 6>;
var max_logit = -1e30;
for (var e = 0u; e < EXPERT_COUNT; e++) {
    gate_logits[e] = gate_dot(idx, e);
    max_logit = max(max_logit, gate_logits[e]);
}

var exp_sum = 0.0;
var gate_probs: array<f32, 6>;
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

// Sigmoid
outputs[idx] = 1.0 / (1.0 + exp(-score_logit));
}
"#;
