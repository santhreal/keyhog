//! Exact fixed-point confidence scoring on an acquired VYRE backend.

use super::quantized::{
    model, AcceleratedCandidateScore, QuantizedConfidenceError, QuantizedFeatureRow,
    MAX_CANDIDATES_PER_BATCH, SCALE,
};
use crate::ml_scorer::model_arch::{
    EXPERTS_OFF, EXPERT_COUNT, EXPERT_FC1_B_COUNT, EXPERT_FC1_OUT, EXPERT_FC1_W_COUNT,
    EXPERT_FC2_B_COUNT, EXPERT_FC2_OUT, EXPERT_FC2_W_COUNT, EXPERT_FC3_W_COUNT, EXPERT_PARAM_COUNT,
    GATE_B_OFF, GATE_W_OFF, INPUT_DIM, TOTAL_F32_COUNT,
};
use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock, Mutex};
use vyre::backend::PendingDispatch;
use vyre::ir::{BufferDecl, DataType, Expr, Node, Program};
use vyre::{DispatchConfig, VyreBackend};
use zeroize::Zeroizing;

const WORKGROUP_X: u32 = 64;
const MAX_ACTIVATION: i32 = i16::MAX as i32;
const SIGMOID_SATURATION: i32 = 6 * SCALE;
const GATE_DECAY: i32 = 8 * SCALE;
const CANDIDATE_ID_SLOT: usize = 0;
const SCORE_SLOT: usize = 1;
const GATE_SLOT: usize = 2;
const H1_SLOT: usize = GATE_SLOT + EXPERT_COUNT;
const H2_SLOT: usize = H1_SLOT + EXPERT_FC1_OUT;
const EXPERT_LOGIT_SLOT: usize = H2_SLOT + EXPERT_FC2_OUT;
const ACCUMULATOR_SLOT: usize = EXPERT_LOGIT_SLOT + EXPERT_COUNT;
pub(crate) const RESULT_STRIDE: usize = ACCUMULATOR_SLOT + 1;

static PARAMETER_BYTES: LazyLock<Result<Box<[u8]>, QuantizedConfidenceError>> =
    LazyLock::new(|| {
        let params = model()?.parameters();
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(params.len() * std::mem::size_of::<i32>())
            .map_err(|_| {
                QuantizedConfidenceError::BackendFailure(
                    "parameter staging allocation failed".into(),
                )
            })?;
        for &parameter in params {
            bytes.extend_from_slice(&i32::from(parameter).to_le_bytes());
        }
        Ok(bytes.into_boxed_slice())
    });

static PROGRAMS: LazyLock<Mutex<BTreeMap<usize, Arc<Program>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// Signed-Q7 dimensions bound every caller strictly inside the `i32` range.
fn bounded_add(left: Expr, right: Expr) -> Expr {
    Expr::add(left, right)
}

fn validate_i32_arithmetic_bounds() -> Result<(), QuantizedConfidenceError> {
    let parameter_bound = model()?
        .parameters()
        .iter()
        .map(|&parameter| i64::from(parameter).abs())
        .max()
        .unwrap_or(0);
    let activation_bound = i64::from(i16::MAX) + 1;
    let dense_terms = INPUT_DIM.max(EXPERT_FC1_OUT).max(EXPERT_FC2_OUT) as i64;
    let dense = dense_terms * activation_bound * parameter_bound
        + i64::from(SCALE) * parameter_bound
        + i64::from(SCALE / 2);
    let weighted = EXPERT_COUNT as i64 * activation_bound * i64::from(SCALE)
        + EXPERT_COUNT as i64 * i64::from(SCALE / 2);
    let sigmoid = i64::from(SCALE + 2 * SIGMOID_SATURATION) * i64::from(u16::MAX)
        + i64::from(SCALE + SIGMOID_SATURATION);
    if dense.max(weighted).max(sigmoid) > i64::from(i32::MAX) {
        return Err(QuantizedConfidenceError::BackendFailure(format!(
            "signed-Q7 model parameter magnitude {parameter_bound} exceeds the VYRE i32 arithmetic bound"
        )));
    }
    Ok(())
}

fn round_div_ties_away(numerator: Expr, denominator: Expr) -> Expr {
    let half = Expr::div(denominator.clone(), Expr::i32(2));
    let adjusted = Expr::select(
        Expr::ge(numerator.clone(), Expr::i32(0)),
        bounded_add(numerator.clone(), half.clone()),
        bounded_add(numerator, Expr::sub(Expr::i32(0), half)),
    );
    Expr::div(adjusted, denominator)
}

fn clamp_i16(value: Expr) -> Expr {
    Expr::min(
        Expr::max(value, Expr::i32(i16::MIN as i32)),
        Expr::i32(i16::MAX as i32),
    )
}

fn result_index(result_base: &Expr, slot: usize) -> Expr {
    Expr::add(result_base.clone(), Expr::u32(slot as u32))
}

fn result_value(result_base: &Expr, slot: usize) -> Expr {
    Expr::load("results", result_index(result_base, slot))
}

fn indexed(base: Expr, offset: Expr) -> Expr {
    Expr::add(base, offset)
}

fn dense_loop_body(
    result_base: &Expr,
    output_slot: Expr,
    input_buffer: &'static str,
    input_base: Expr,
    input_count: usize,
    weight_base: Expr,
    bias_index: Expr,
    relu: bool,
    column_var: &'static str,
) -> Vec<Node> {
    let accumulator = result_index(result_base, ACCUMULATOR_SLOT);
    let column = Expr::var(column_var);
    let product = Expr::mul(
        Expr::load(input_buffer, indexed(input_base.clone(), column.clone())),
        Expr::load("params", indexed(weight_base, column)),
    );
    let mut value = clamp_i16(round_div_ties_away(
        result_value(result_base, ACCUMULATOR_SLOT),
        Expr::i32(SCALE),
    ));
    if relu {
        value = Expr::min(Expr::max(value, Expr::i32(0)), Expr::i32(MAX_ACTIVATION));
    }
    vec![
        Node::store(
            "results",
            accumulator.clone(),
            Expr::mul(Expr::load("params", bias_index), Expr::i32(SCALE)),
        ),
        Node::loop_for(
            column_var,
            Expr::u32(0),
            Expr::u32(input_count as u32),
            vec![Node::store(
                "results",
                accumulator,
                bounded_add(result_value(result_base, ACCUMULATOR_SLOT), product),
            )],
        ),
        Node::store("results", indexed(result_base.clone(), output_slot), value),
    ]
}

pub(crate) fn build_program(capacity: usize) -> Result<Program, QuantizedConfidenceError> {
    validate_i32_arithmetic_bounds()?;
    let row_count = capacity.checked_mul(INPUT_DIM).ok_or_else(|| {
        QuantizedConfidenceError::BackendFailure("feature buffer size overflow".into())
    })?;
    let row_count = u32::try_from(row_count).map_err(|_| {
        QuantizedConfidenceError::BackendFailure("feature buffer exceeds VYRE count ABI".into())
    })?;
    let capacity_u32 = u32::try_from(capacity).map_err(|_| {
        QuantizedConfidenceError::BackendFailure("candidate capacity exceeds VYRE count ABI".into())
    })?;
    let output_count = capacity
        .checked_mul(RESULT_STRIDE)
        .and_then(|count| u32::try_from(count).ok())
        .ok_or_else(|| {
            QuantizedConfidenceError::BackendFailure("score output count overflow".into())
        })?;
    let parameter_count = u32::try_from(TOTAL_F32_COUNT).map_err(|_| {
        QuantizedConfidenceError::BackendFailure("parameter buffer exceeds VYRE count ABI".into())
    })?;

    let gid = Expr::gid_x();
    let row_base = Expr::mul(gid.clone(), Expr::u32(INPUT_DIM as u32));
    let result_base = Expr::mul(gid.clone(), Expr::u32(RESULT_STRIDE as u32));
    let mut body = Vec::new();

    let gate = Expr::var("gate");
    body.push(Node::loop_for(
        "gate",
        Expr::u32(0),
        Expr::u32(EXPERT_COUNT as u32),
        dense_loop_body(
            &result_base,
            indexed(Expr::u32(GATE_SLOT as u32), gate.clone()),
            "rows",
            row_base.clone(),
            INPUT_DIM,
            indexed(
                Expr::u32(GATE_W_OFF as u32),
                Expr::mul(gate.clone(), Expr::u32(INPUT_DIM as u32)),
            ),
            indexed(Expr::u32(GATE_B_OFF as u32), gate),
            false,
            "gate_column",
        ),
    ));

    let expert = Expr::var("expert");
    let expert_base = indexed(
        Expr::u32(EXPERTS_OFF as u32),
        Expr::mul(expert.clone(), Expr::u32(EXPERT_PARAM_COUNT as u32)),
    );
    let fc1_row = Expr::var("fc1_row");
    let fc1_bias_base = indexed(expert_base.clone(), Expr::u32(EXPERT_FC1_W_COUNT as u32));
    let fc1_loop = Node::loop_for(
        "fc1_row",
        Expr::u32(0),
        Expr::u32(EXPERT_FC1_OUT as u32),
        dense_loop_body(
            &result_base,
            indexed(Expr::u32(H1_SLOT as u32), fc1_row.clone()),
            "rows",
            row_base,
            INPUT_DIM,
            indexed(
                expert_base.clone(),
                Expr::mul(fc1_row.clone(), Expr::u32(INPUT_DIM as u32)),
            ),
            indexed(fc1_bias_base.clone(), fc1_row),
            true,
            "fc1_column",
        ),
    );

    let fc2_weights_base = indexed(fc1_bias_base, Expr::u32(EXPERT_FC1_B_COUNT as u32));
    let fc2_bias_base = indexed(
        fc2_weights_base.clone(),
        Expr::u32(EXPERT_FC2_W_COUNT as u32),
    );
    let fc2_row = Expr::var("fc2_row");
    let fc2_loop = Node::loop_for(
        "fc2_row",
        Expr::u32(0),
        Expr::u32(EXPERT_FC2_OUT as u32),
        dense_loop_body(
            &result_base,
            indexed(Expr::u32(H2_SLOT as u32), fc2_row.clone()),
            "results",
            result_index(&result_base, H1_SLOT),
            EXPERT_FC1_OUT,
            indexed(
                fc2_weights_base.clone(),
                Expr::mul(fc2_row.clone(), Expr::u32(EXPERT_FC1_OUT as u32)),
            ),
            indexed(fc2_bias_base.clone(), fc2_row),
            true,
            "fc2_column",
        ),
    );

    let fc3_weights_base = indexed(fc2_bias_base, Expr::u32(EXPERT_FC2_B_COUNT as u32));
    let mut expert_body = vec![fc1_loop, fc2_loop];
    expert_body.extend(dense_loop_body(
        &result_base,
        indexed(Expr::u32(EXPERT_LOGIT_SLOT as u32), expert),
        "results",
        result_index(&result_base, H2_SLOT),
        EXPERT_FC2_OUT,
        fc3_weights_base.clone(),
        indexed(fc3_weights_base, Expr::u32(EXPERT_FC3_W_COUNT as u32)),
        false,
        "fc3_column",
    ));
    body.push(Node::loop_for(
        "expert",
        Expr::u32(0),
        Expr::u32(EXPERT_COUNT as u32),
        expert_body,
    ));

    let gate_max_slot = H1_SLOT;
    let weighted_sum_slot = H1_SLOT + 1;
    let weight_sum_slot = H1_SLOT + 2;
    let mixed_logit_slot = H1_SLOT + 3;
    body.push(Node::store(
        "results",
        result_index(&result_base, gate_max_slot),
        result_value(&result_base, GATE_SLOT),
    ));
    let mix_gate = Expr::var("mix_gate");
    body.push(Node::loop_for(
        "mix_gate",
        Expr::u32(1),
        Expr::u32(EXPERT_COUNT as u32),
        vec![Node::store(
            "results",
            result_index(&result_base, gate_max_slot),
            Expr::max(
                result_value(&result_base, gate_max_slot),
                Expr::load(
                    "results",
                    indexed(
                        result_base.clone(),
                        indexed(Expr::u32(GATE_SLOT as u32), mix_gate),
                    ),
                ),
            ),
        )],
    ));
    body.push(Node::store(
        "results",
        result_index(&result_base, weighted_sum_slot),
        Expr::i32(0),
    ));
    body.push(Node::store(
        "results",
        result_index(&result_base, weight_sum_slot),
        Expr::i32(0),
    ));
    let mix_expert = Expr::var("mix_expert");
    let gate_logit = Expr::load(
        "results",
        indexed(
            result_base.clone(),
            indexed(Expr::u32(GATE_SLOT as u32), mix_expert.clone()),
        ),
    );
    let expert_logit = Expr::load(
        "results",
        indexed(
            result_base.clone(),
            indexed(Expr::u32(EXPERT_LOGIT_SLOT as u32), mix_expert.clone()),
        ),
    );
    let delta = Expr::sub(result_value(&result_base, gate_max_slot), gate_logit);
    let weight = Expr::max(
        Expr::div(
            Expr::i32(SCALE * GATE_DECAY),
            bounded_add(Expr::i32(GATE_DECAY), delta),
        ),
        Expr::i32(1),
    );
    body.push(Node::loop_for(
        "mix_expert",
        Expr::u32(0),
        Expr::u32(EXPERT_COUNT as u32),
        vec![
            Node::store(
                "results",
                result_index(&result_base, weighted_sum_slot),
                bounded_add(
                    result_value(&result_base, weighted_sum_slot),
                    Expr::mul(expert_logit, weight.clone()),
                ),
            ),
            Node::store(
                "results",
                result_index(&result_base, weight_sum_slot),
                bounded_add(result_value(&result_base, weight_sum_slot), weight),
            ),
        ],
    ));
    body.push(Node::store(
        "results",
        result_index(&result_base, mixed_logit_slot),
        round_div_ties_away(
            result_value(&result_base, weighted_sum_slot),
            Expr::max(result_value(&result_base, weight_sum_slot), Expr::i32(1)),
        ),
    ));

    let logit = result_value(&result_base, mixed_logit_slot);
    let bounded_logit = Expr::min(
        Expr::max(logit.clone(), Expr::i32(-SIGMOID_SATURATION)),
        Expr::i32(SIGMOID_SATURATION),
    );
    let magnitude = Expr::select(
        Expr::lt(bounded_logit.clone(), Expr::i32(0)),
        Expr::sub(Expr::i32(0), bounded_logit.clone()),
        bounded_logit.clone(),
    );
    let base = bounded_add(Expr::i32(SCALE), magnitude);
    let numerator = Expr::select(
        Expr::lt(bounded_logit.clone(), Expr::i32(0)),
        Expr::i32(SCALE),
        bounded_add(Expr::i32(SCALE), Expr::mul(bounded_logit, Expr::i32(2))),
    );
    let scaled = Expr::mul(numerator, Expr::i32(i32::from(u16::MAX)));
    let sigmoid = round_div_ties_away(scaled, Expr::mul(base, Expr::i32(2)));
    let score = Expr::select(
        Expr::le(logit.clone(), Expr::i32(-SIGMOID_SATURATION)),
        Expr::i32(0),
        Expr::select(
            Expr::ge(logit, Expr::i32(SIGMOID_SATURATION)),
            Expr::i32(i32::from(u16::MAX)),
            Expr::min(
                Expr::max(sigmoid, Expr::i32(0)),
                Expr::i32(i32::from(u16::MAX)),
            ),
        ),
    );
    body.push(Node::store(
        "results",
        result_index(&result_base, CANDIDATE_ID_SLOT),
        Expr::cast(DataType::I32, gid),
    ));
    body.push(Node::store(
        "results",
        result_index(&result_base, SCORE_SLOT),
        score,
    ));

    Ok(Program::wrapped(
        vec![
            BufferDecl::read("rows", 0, DataType::I32).with_count(row_count),
            BufferDecl::read("params", 1, DataType::I32).with_count(parameter_count),
            BufferDecl::output("results", 2, DataType::I32).with_count(output_count),
        ],
        [WORKGROUP_X, 1, 1],
        vec![Node::if_then(
            Expr::lt(Expr::gid_x(), Expr::u32(capacity_u32)),
            body,
        )],
    ))
}

fn program_for_capacity(capacity: usize) -> Result<Arc<Program>, QuantizedConfidenceError> {
    if let Some(program) = PROGRAMS
        .lock()
        .map_err(|_| {
            QuantizedConfidenceError::BackendFailure("program cache lock is poisoned".into())
        })?
        .get(&capacity)
        .cloned()
    {
        return Ok(program);
    }
    let program = Arc::new(build_program(capacity)?);
    let mut programs = PROGRAMS.lock().map_err(|_| {
        QuantizedConfidenceError::BackendFailure("program cache lock is poisoned".into())
    })?;
    Ok(programs.entry(capacity).or_insert(program).clone())
}

#[must_use = "pending quantized scores must be retired before staged candidate data is released"]
pub(crate) struct PendingQuantizedScores {
    pending: Option<Box<dyn PendingDispatch>>,
    // Keep borrowed program and input storage alive until the backend fence retires.
    _program: Option<Arc<Program>>,
    _row_bytes: Zeroizing<Vec<u8>>,
    candidate_count: usize,
    capacity: usize,
}

impl PendingQuantizedScores {
    pub(crate) fn await_scores(
        mut self,
    ) -> Result<Vec<AcceleratedCandidateScore>, QuantizedConfidenceError> {
        let Some(pending) = self.pending.take() else {
            return Ok(Vec::new());
        };
        let mut outputs = pending
            .await_result()
            .map_err(|error| QuantizedConfidenceError::BackendFailure(error.to_string()))?;
        let result = decode_outputs(&outputs, self.candidate_count, self.capacity);
        for output in &mut outputs {
            output.fill(0);
        }
        result
    }
}

impl Drop for PendingQuantizedScores {
    fn drop(&mut self) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        match pending.await_result() {
            Ok(mut outputs) => {
                for output in &mut outputs {
                    output.fill(0);
                }
            }
            Err(error) => {
                tracing::error!(
                    target: "keyhog::gpu",
                    %error,
                    "abandoned quantized confidence dispatch retirement failed"
                );
            }
        }
    }
}

pub(crate) fn decode_outputs(
    outputs: &[Vec<u8>],
    candidate_count: usize,
    capacity: usize,
) -> Result<Vec<AcceleratedCandidateScore>, QuantizedConfidenceError> {
    let expected_bytes = capacity
        .checked_mul(RESULT_STRIDE)
        .and_then(|values| values.checked_mul(std::mem::size_of::<i32>()))
        .ok_or_else(|| {
            QuantizedConfidenceError::BackendFailure("score output layout overflow".into())
        })?;
    if candidate_count > capacity || outputs.len() != 1 || outputs[0].len() != expected_bytes {
        return Err(QuantizedConfidenceError::BackendFailure(
            "VYRE quantized scorer returned an invalid output layout".into(),
        ));
    }
    let mut scored = Vec::new();
    scored
        .try_reserve_exact(candidate_count)
        .map_err(|_| QuantizedConfidenceError::BackendFailure("score allocation failed".into()))?;
    for candidate in 0..candidate_count {
        let offset = candidate * RESULT_STRIDE * std::mem::size_of::<i32>();
        let candidate_id = u32::from_le_bytes([
            outputs[0][offset],
            outputs[0][offset + 1],
            outputs[0][offset + 2],
            outputs[0][offset + 3],
        ]);
        let score_offset = offset + SCORE_SLOT * std::mem::size_of::<i32>();
        let score = u32::from_le_bytes([
            outputs[0][score_offset],
            outputs[0][score_offset + 1],
            outputs[0][score_offset + 2],
            outputs[0][score_offset + 3],
        ]);
        let score = u16::try_from(score).map_err(|_| {
            QuantizedConfidenceError::BackendFailure("VYRE quantized score exceeds u16".into())
        })?;
        scored.push(AcceleratedCandidateScore {
            candidate_id,
            score: super::quantized::QuantizedScore(score),
        });
    }
    Ok(scored)
}

pub(crate) fn submit_rows(
    backend: &dyn VyreBackend,
    rows: &[QuantizedFeatureRow],
    timeout: Option<std::time::Duration>,
) -> Result<PendingQuantizedScores, QuantizedConfidenceError> {
    if rows.len() > MAX_CANDIDATES_PER_BATCH {
        return Err(QuantizedConfidenceError::BatchTooLarge {
            candidates: rows.len(),
            maximum: MAX_CANDIDATES_PER_BATCH,
        });
    }
    if rows.is_empty() {
        return Ok(PendingQuantizedScores {
            pending: None,
            _program: None,
            _row_bytes: Zeroizing::new(Vec::new()),
            candidate_count: 0,
            capacity: 0,
        });
    }
    if timeout.is_some_and(|timeout| timeout.is_zero()) {
        return Err(QuantizedConfidenceError::BackendFailure(
            "scan deadline elapsed before quantized confidence dispatch".into(),
        ));
    }
    let capacity = rows.len().next_power_of_two();
    let program = program_for_capacity(capacity)?;
    let row_elements = capacity.checked_mul(INPUT_DIM).ok_or_else(|| {
        QuantizedConfidenceError::BackendFailure("feature buffer size overflow".into())
    })?;
    let mut row_bytes = Zeroizing::new(Vec::new());
    row_bytes
        .try_reserve_exact(row_elements * std::mem::size_of::<i32>())
        .map_err(|_| {
            QuantizedConfidenceError::BackendFailure("feature staging allocation failed".into())
        })?;
    for row in rows {
        for &value in &row.0 {
            row_bytes.extend_from_slice(&i32::from(value).to_le_bytes());
        }
    }
    row_bytes.resize(row_elements * std::mem::size_of::<i32>(), 0);
    let parameter_bytes = PARAMETER_BYTES.as_ref().map_err(|error| {
        QuantizedConfidenceError::BackendFailure(format!(
            "embedded parameter staging failed: {error}"
        ))
    })?;
    let mut config = DispatchConfig::default();
    config.grid_override = Some([(capacity as u32).div_ceil(WORKGROUP_X), 1, 1]);
    config.workgroup_override = Some([WORKGROUP_X, 1, 1]);
    config.timeout = timeout;
    config.max_output_bytes = capacity
        .checked_mul(RESULT_STRIDE)
        .and_then(|values| values.checked_mul(std::mem::size_of::<i32>()))
        .ok_or_else(|| {
            QuantizedConfidenceError::BackendFailure("score output size overflow".into())
        })?
        .into();
    let pending = backend
        .dispatch_borrowed_async(&program, &[row_bytes.as_slice(), parameter_bytes], &config)
        .map_err(|error| QuantizedConfidenceError::BackendFailure(error.to_string()))?;
    Ok(PendingQuantizedScores {
        pending: Some(pending),
        _program: Some(program),
        _row_bytes: row_bytes,
        candidate_count: rows.len(),
        capacity,
    })
}
