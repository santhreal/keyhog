//! Single owner of the MoE model architecture.
//!
//! Every layer dimension, derived parameter count, flat weight-buffer offset,
//! and the sigmoid clamp lives here ONCE. Four sites previously kept their own
//! copies of these numbers:
//!   - `ml_weights.rs`  — flat `weights.bin` buffer layout (counts + offsets),
//!   - `ml_scorer.rs`   — const-generic dense-layer widths + sigmoid clamp,
//!   - `ml_features.rs` — `NUM_FEATURES` (the input width),
//!   - `gpu/gpu_shader.rs` — the WGSL `const` block + layout offsets (string
//!     literals).
//! They now IMPORT these consts. The WGSL literals (which must stay literals for
//! the shader source) are pinned to these values by
//! `tests/ml_model_arch_wgsl_parity.rs`, which fails the moment either side is
//! retuned without the other.
//!
//! Architecture: gate `Linear(INPUT_DIM, EXPERT_COUNT)` -> Softmax; `EXPERT_COUNT`
//! experts of `Linear(INPUT_DIM, FC1)` -> ReLU -> `Linear(FC1, FC2)` -> ReLU ->
//! `Linear(FC2, 1)`; gate-weighted logit sum -> rational Sigmoid. Changing any
//! primitive below requires a matching `weights.bin` retrain — the buffer-size
//! check in `ml_weights::parse_weights` fails closed on any stride mismatch.

/// Feature-vector dimensionality = gate/expert input width. Feature 41 is the
/// decode-structure verdict (base64/hex -> magic-bytes/protobuf); feature 42 is
/// the keyword-specificity verdict (context names a specific service, DET-1,
/// see `service_vocab.rs`); layout in `ml_features.rs`.
///
/// 42 -> 43 (2026-07-08, DET-1). Any bump here REQUIRES a matching
/// `weights.bin` + `model_card.json` retrain (`FEATURES=43
/// ml/retrain_loop.sh --write --verify`); `ml_weights::parse_weights` fails
/// closed on the stride mismatch until they land, and the generated WGSL
/// shader + GPU host buffers derive from this const so the GPU path can never
/// lag the CPU layout.
pub(crate) const INPUT_DIM: usize = 43;

/// Mixture-of-experts specialist count (grid-searched over {4, 6, 8, 12}).
pub(crate) const EXPERT_COUNT: usize = 6;

/// Expert first hidden width: `Linear(INPUT_DIM, EXPERT_FC1_OUT)` -> ReLU.
pub(crate) const EXPERT_FC1_OUT: usize = 32;

/// Expert second hidden width: `Linear(EXPERT_FC1_OUT, EXPERT_FC2_OUT)` -> ReLU.
pub(crate) const EXPERT_FC2_OUT: usize = 16;

/// Expert output width: `Linear(EXPERT_FC2_OUT, 1)` — a single logit per expert.
pub(crate) const EXPERT_FC3_OUT: usize = 1;

/// Symmetric saturation bound for the fast rational sigmoid: outside
/// `[-SIGMOID_SATURATION, SIGMOID_SATURATION]` the output clamps to `0.0` / `1.0`.
/// The CPU forward pass is the parity reference for every confidence floor AND
/// the GPU shader, so this owns the clamp for both paths.
pub(crate) const SIGMOID_SATURATION: f32 = 6.0;

/// GPU compute workgroup size (threads per workgroup) for the MoE inference
/// shader. SINGLE OWNER shared by BOTH the WGSL `@workgroup_size(WORKGROUP_SIZE)`
/// attribute (interpolated into the generated shader header) AND the host-side
/// dispatch `(batch_size).div_ceil(WORKGROUP_SIZE)` in `gpu::backend`. Before this
/// each side carried a free literal `64`; changing one without the other silently
/// under- or over-dispatches the batch (partial/duplicate scoring). One owner, so
/// they cannot drift; `wgsl_literals_match_rust_owner` pins the shader copy to it.
pub(crate) const WORKGROUP_SIZE: usize = 64;

// --- Derived per-layer element counts (f32 values) ---
pub(crate) const GATE_W_COUNT: usize = INPUT_DIM * EXPERT_COUNT;
pub(crate) const GATE_B_COUNT: usize = EXPERT_COUNT;
pub(crate) const EXPERT_FC1_W_COUNT: usize = INPUT_DIM * EXPERT_FC1_OUT;
pub(crate) const EXPERT_FC1_B_COUNT: usize = EXPERT_FC1_OUT;
pub(crate) const EXPERT_FC2_W_COUNT: usize = EXPERT_FC1_OUT * EXPERT_FC2_OUT;
pub(crate) const EXPERT_FC2_B_COUNT: usize = EXPERT_FC2_OUT;
pub(crate) const EXPERT_FC3_W_COUNT: usize = EXPERT_FC2_OUT * EXPERT_FC3_OUT;
pub(crate) const EXPERT_FC3_B_COUNT: usize = EXPERT_FC3_OUT;

/// f32 values in one contiguous expert block (fc1/fc2/fc3 weights + biases).
pub(crate) const EXPERT_PARAM_COUNT: usize = EXPERT_FC1_W_COUNT
    + EXPERT_FC1_B_COUNT
    + EXPERT_FC2_W_COUNT
    + EXPERT_FC2_B_COUNT
    + EXPERT_FC3_W_COUNT
    + EXPERT_FC3_B_COUNT;

// --- Flat little-endian `weights.bin` offsets (f32 units) ---
// Layout: gate weights, gate bias, then EXPERT_COUNT contiguous expert blocks.
pub(crate) const GATE_W_OFF: usize = 0;
pub(crate) const GATE_B_OFF: usize = GATE_W_OFF + GATE_W_COUNT;
pub(crate) const EXPERTS_OFF: usize = GATE_B_OFF + GATE_B_COUNT;

/// Total f32 count in `weights.bin` — the buffer-size contract `parse_weights`
/// enforces.
pub(crate) const TOTAL_F32_COUNT: usize = EXPERTS_OFF + EXPERT_COUNT * EXPERT_PARAM_COUNT;
