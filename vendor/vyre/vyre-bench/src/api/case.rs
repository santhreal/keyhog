use std::sync::Arc;

use serde::{Deserialize, Serialize};
use vyre::{DispatchConfig, VyreBackend};
use vyre_driver::CompiledPipeline;
pub use vyre_spec::DeterminismClass;

use super::metric::BenchMetrics;
use super::suite::SuiteKind;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BenchId(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BenchLayer {
    Foundation,
    Reference,
    Runtime,
    Libs,
    Backend,
    Conform,
    Competition,
    Honest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkloadClass {
    Micro,
    Macro,
    Adversarial,
    Honest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchMetadata {
    pub id: BenchId,
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub layer: BenchLayer,
    pub workload: WorkloadClass,
    pub determinism: DeterminismClass,
    pub owner_crate: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BaselineClass {
    CpuSota,
    GpuSota,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineTarget {
    pub name: String,
    pub crate_name: String,
    pub class: BaselineClass,
    pub min_speedup_x: f64,
    pub backend_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceContract {
    pub primitive: String,
    pub baselines: Vec<BaselineTarget>,
}

impl PerformanceContract {
    pub fn cpu_sota_min_speedup(
        primitive: impl Into<String>,
        crate_name: impl Into<String>,
        baseline: impl Into<String>,
        min_speedup_x: f64,
    ) -> Self {
        Self {
            primitive: primitive.into(),
            baselines: vec![BaselineTarget {
                name: baseline.into(),
                crate_name: crate_name.into(),
                class: BaselineClass::CpuSota,
                min_speedup_x,
                backend_ids: vec!["cuda".to_string()],
            }],
        }
    }

    pub fn cpu_sota_100x(
        primitive: impl Into<String>,
        crate_name: impl Into<String>,
        baseline: impl Into<String>,
    ) -> Self {
        Self::cpu_sota_min_speedup(primitive, crate_name, baseline, 100.0)
    }

    pub fn cpu_sota_10x(
        primitive: impl Into<String>,
        crate_name: impl Into<String>,
        baseline: impl Into<String>,
    ) -> Self {
        Self::cpu_sota_min_speedup(primitive, crate_name, baseline, 10.0)
    }

    pub fn cpu_sota_3x(
        primitive: impl Into<String>,
        crate_name: impl Into<String>,
        baseline: impl Into<String>,
    ) -> Self {
        Self::cpu_sota_min_speedup(primitive, crate_name, baseline, 3.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceEvaluation {
    pub speedup_x: Option<f64>,
    pub contract_passed: bool,
    pub violations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchRequirements {
    pub needs_gpu: bool,
    pub needs_network: bool,
    pub min_vram_bytes: Option<u64>,
    pub min_input_bytes: Option<u64>,
    pub feature_set: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Correctness {
    Exact,
    Toleranced {
        ulp_budget: u32,
        max_observed_ulp: u32,
    },
    Certificate {
        digest: [u8; 32],
    },
    Invalid {
        reason: String,
    },
}

pub struct ScratchPool {
    pub buffer: Vec<u8>,
}

pub struct OptimizerPipeline {}

pub struct CpuReference {}

impl CpuReference {
    pub fn dispatch(
        &self,
        prog: &vyre::ir::Program,
        inputs: &[Vec<u8>],
        _config: &vyre::DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, String> {
        let ref_inputs: Vec<vyre_reference::value::Value> = inputs
            .iter()
            .map(|b| vyre_reference::value::Value::Bytes(std::sync::Arc::from(b.clone())))
            .collect();
        vyre_reference::reference_eval(prog, &ref_inputs)
            .map(|values| values.iter().map(|v| v.to_bytes()).collect())
            .map_err(|e| format!("{:?}", e))
    }
}

pub struct BenchContext {
    pub backends: Vec<Box<dyn VyreBackend>>,
    pub preferred_backend: Arc<dyn VyreBackend>,
    pub compiled_pipeline: Option<Arc<dyn CompiledPipeline>>,
    pub compiled_program_fingerprint: Option<[u8; 32]>,
    pub reference: CpuReference,
    pub optimizer: OptimizerPipeline,
    pub scratch: ScratchPool,
    pub rng: rand::rngs::StdRng,
    pub dispatch_config: DispatchConfig,
    pub evolve_candidate: Option<vyre::ir::Program>,
    pub include_baseline_outputs: bool,
}

impl BenchContext {
    pub fn dispatch(
        &self,
        prog: &vyre::ir::Program,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, vyre_driver::BackendError> {
        let mut inferred_config;
        let config = if config.grid_override.is_none() {
            inferred_config = config.clone();
            inferred_config.grid_override = Some(vyre_driver::program_walks::infer_dispatch_grid(
                prog, inputs, config,
            )?);
            &inferred_config
        } else {
            config
        };
        vyre_driver::validate_program_for_backend(self.preferred_backend.as_ref(), prog, config)?;
        if self
            .compiled_program_fingerprint
            .is_some_and(|fingerprint| fingerprint == prog.fingerprint())
        {
            let pipeline = self.compiled_pipeline.as_ref().ok_or_else(|| {
                vyre_driver::BackendError::new(
                    "compiled program fingerprint was set without a compiled pipeline. Fix: keep BenchContext compiled pipeline state coherent.",
                )
            })?;
            let borrowed_inputs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
            pipeline.dispatch_borrowed(&borrowed_inputs, config)
        } else {
            let borrowed_inputs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
            self.preferred_backend
                .dispatch_borrowed(prog, &borrowed_inputs, config)
        }
    }

    pub fn dispatch_timed(
        &self,
        prog: &vyre::ir::Program,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<vyre_driver::TimedDispatchResult, vyre_driver::BackendError> {
        let mut inferred_config;
        let config = if config.grid_override.is_none() {
            inferred_config = config.clone();
            inferred_config.grid_override = Some(vyre_driver::program_walks::infer_dispatch_grid(
                prog, inputs, config,
            )?);
            &inferred_config
        } else {
            config
        };
        vyre_driver::validate_program_for_backend(self.preferred_backend.as_ref(), prog, config)?;
        let borrowed_inputs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
        if self
            .compiled_program_fingerprint
            .is_some_and(|fingerprint| fingerprint == prog.fingerprint())
        {
            let pipeline = self.compiled_pipeline.as_ref().ok_or_else(|| {
                vyre_driver::BackendError::new(
                    "compiled program fingerprint was set without a compiled pipeline. Fix: keep BenchContext compiled pipeline state coherent.",
                )
            })?;
            pipeline.dispatch_borrowed_timed(&borrowed_inputs, config)
        } else {
            self.preferred_backend
                .dispatch_borrowed_timed(prog, &borrowed_inputs, config)
        }
    }
}

pub type PreparedCase = Box<dyn std::any::Any>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchRun {
    pub metrics: BenchMetrics,
    pub baseline_metrics: Option<BenchMetrics>,
    pub outputs: Vec<Vec<u8>>,
    pub baseline_outputs: Option<Vec<Vec<u8>>>,
}

impl BenchRun {
    pub fn verify_exact_outputs(&self) -> Result<Correctness, BenchError> {
        let baseline = self.baseline_outputs.as_ref().ok_or_else(|| {
            BenchError::CorrectnessViolation(
                "benchmark did not capture a baseline output; cannot claim exact correctness"
                    .to_string(),
            )
        })?;
        if self.outputs == *baseline {
            return Ok(Correctness::Exact);
        }
        Err(BenchError::CorrectnessViolation(first_output_difference(
            &self.outputs,
            baseline,
        )))
    }
}

pub fn prepared_program(prepared: &PreparedCase) -> Result<&vyre::ir::Program, BenchError> {
    prepared.downcast_ref::<vyre::ir::Program>().ok_or_else(|| {
        BenchError::ExecutionFailed(
            "prepared benchmark payload was not a vyre::ir::Program".to_string(),
        )
    })
}

fn first_output_difference(outputs: &[Vec<u8>], baseline: &[Vec<u8>]) -> String {
    if outputs.len() != baseline.len() {
        return format!(
            "output count mismatch: backend returned {}, baseline returned {}",
            outputs.len(),
            baseline.len()
        );
    }
    for (buffer_index, (actual, expected)) in outputs.iter().zip(baseline).enumerate() {
        if actual.len() != expected.len() {
            return format!(
                "output buffer {buffer_index} length mismatch: backend returned {} bytes, baseline returned {} bytes",
                actual.len(),
                expected.len()
            );
        }
        if let Some(byte_index) = actual
            .iter()
            .zip(expected)
            .position(|(actual_byte, expected_byte)| actual_byte != expected_byte)
        {
            let window_end = actual.len().min(byte_index.saturating_add(16));
            return format!(
                "output buffer {buffer_index} differs at byte {byte_index}: backend=0x{:02x}, baseline=0x{:02x}, backend_window={:02x?}, baseline_window={:02x?}",
                actual[byte_index],
                expected[byte_index],
                &actual[byte_index..window_end],
                &expected[byte_index..window_end]
            );
        }
    }
    "backend output differs from baseline".to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum BenchError {
    #[error("Environment invalid: {0}")]
    EnvironmentInvalid(String),
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
    #[error("GPU probe failed for GPU-required benchmark: {0}. Fix: run `nvidia-smi`, verify CUDA/WGPU backend acquisition, and rerun the benchmark.")]
    GpuProbeFailed(String),
    #[error("Backend failed: {0}")]
    BackendFailed(String),
    #[error("Correctness violation: {0}")]
    CorrectnessViolation(String),
}

pub trait BenchCase: Send + Sync {
    fn id(&self) -> BenchId;
    fn metadata(&self) -> BenchMetadata;
    fn suites(&self) -> &'static [SuiteKind] {
        &[]
    }
    fn active_in_suite(&self, suite: SuiteKind) -> bool {
        let suites = self.suites();
        suites.is_empty() || suites.contains(&suite)
    }
    fn requirements(&self) -> BenchRequirements;
    fn performance_contract(&self) -> Option<PerformanceContract> {
        None
    }
    fn prepare(&self, ctx: &mut BenchContext) -> Result<PreparedCase, BenchError>;
    fn program<'a>(&self, prepared: &'a PreparedCase) -> Option<&'a vyre::ir::Program> {
        prepared_program(prepared).ok()
    }
    fn run(
        &self,
        ctx: &mut BenchContext,
        prepared: &mut PreparedCase,
    ) -> Result<BenchRun, BenchError>;
    fn verify(&self, ctx: &mut BenchContext, run: &BenchRun) -> Result<Correctness, BenchError>;
    fn bytes_touched(&self, prepared: &PreparedCase) -> (u64, u64) {
        prepared_program(prepared)
            .map(static_program_bytes_touched)
            .unwrap_or((0, 0))
    }
}

fn static_program_bytes_touched(program: &vyre::ir::Program) -> (u64, u64) {
    let mut read_bytes = 0_u64;
    let mut write_bytes = 0_u64;
    for buffer in program.buffers() {
        let bytes = buffer
            .element()
            .size_bytes()
            .map(|element_bytes| (element_bytes as u64).saturating_mul(u64::from(buffer.count())))
            .unwrap_or(0);
        match buffer.access() {
            vyre::ir::BufferAccess::ReadOnly | vyre::ir::BufferAccess::Uniform => {
                read_bytes = read_bytes.saturating_add(bytes);
            }
            vyre::ir::BufferAccess::ReadWrite => {
                read_bytes = read_bytes.saturating_add(bytes);
                write_bytes = write_bytes.saturating_add(bytes);
            }
            vyre::ir::BufferAccess::WriteOnly => {
                write_bytes = write_bytes.saturating_add(bytes);
            }
            vyre::ir::BufferAccess::Workgroup => {}
            _ => {}
        }
    }
    (read_bytes, write_bytes)
}
