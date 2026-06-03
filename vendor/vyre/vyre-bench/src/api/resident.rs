use std::sync::Arc;
use std::time::Instant;

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre::{DispatchConfig, VyreBackend};
use vyre_driver::{BackendError, CompiledPipeline, Resource, TimedDispatchResult};

use crate::api::case::{BenchContext, BenchError};

/// Prepared resident input buffers for a benchmark case.
///
/// This owns GPU-resident resources and frees them on drop. Benchmark cases use
/// it to keep setup traffic out of measured samples while preserving an exact
/// host-buffer fallback on backends that do not support residency.
pub struct ResidentInputSet {
    backend: Arc<dyn VyreBackend>,
    resources: Vec<Resource>,
    cleanup_label: &'static str,
}

/// Rotating pool of resident input-buffer sets for persistent benchmarks.
///
/// Persistent megakernel-style cases dispatch compiled handles repeatedly. A
/// single resident set can create false dependencies between measured samples;
/// a small rotating pool lets the benchmark keep host uploads outside the hot
/// path until the pool wraps.
pub struct ResidentInputPool {
    backend: Arc<dyn VyreBackend>,
    sets: Vec<Vec<Resource>>,
    next_set: usize,
    cleanup_label: &'static str,
}

/// Timed dispatch result plus whether the measured run used resident inputs.
pub struct ResidentDispatch {
    pub timed: TimedDispatchResult,
    pub resident_used: bool,
}

/// Host-transfer accounting for a dispatch sample.
pub struct TransferAccounting {
    pub bytes_touched: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

/// Sum encoded benchmark input bytes once during preparation.
pub fn input_bytes_total(inputs: &[Vec<u8>]) -> u64 {
    inputs.iter().map(Vec::len).sum::<usize>() as u64
}

/// Build a one-lane resident reset program for sparse-output `u32` counters.
pub fn u32_counter_reset_program(buffer_name: &str) -> Program {
    let idx = Expr::InvocationId { axis: 0 };
    Program::wrapped(
        vec![
            BufferDecl::storage(buffer_name, 0, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
        ],
        [1, 1, 1],
        vec![Node::if_then(
            Expr::eq(idx, Expr::u32(0)),
            vec![Node::store(buffer_name, Expr::u32(0), Expr::u32(0))],
        )],
    )
}

/// Account resident samples as output-only host traffic and fallback samples as full round trips.
pub fn transfer_accounting(
    input_bytes_total: u64,
    output_bytes_total: u64,
    resident_used: bool,
) -> TransferAccounting {
    let bytes_read = if resident_used { 0 } else { input_bytes_total };
    TransferAccounting {
        bytes_touched: bytes_read.saturating_add(output_bytes_total),
        bytes_read,
        bytes_written: output_bytes_total,
    }
}

/// Dispatch a compiled pipeline through a resident pool when present, otherwise through borrowed host input.
pub fn dispatch_compiled_timed(
    compiled: &dyn CompiledPipeline,
    resident: Option<&mut ResidentInputPool>,
    inputs: &[Vec<u8>],
    config: &DispatchConfig,
) -> Result<ResidentDispatch, BenchError> {
    if let Some(resident) = resident {
        let resources = resident.next_set(inputs)?;
        let started = Instant::now();
        let outputs = compiled
            .dispatch_persistent_handles(resources, config)
            .map_err(|error| BenchError::BackendFailed(error.to_string()))?;
        return Ok(ResidentDispatch {
            timed: TimedDispatchResult {
                outputs,
                wall_ns: u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
                device_ns: None,
                enqueue_ns: None,
                wait_ns: None,
            },
            resident_used: true,
        });
    }

    let input_refs = inputs.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let timed = compiled
        .dispatch_borrowed_timed(&input_refs, config)
        .map_err(|error| BenchError::BackendFailed(error.to_string()))?;
    Ok(ResidentDispatch {
        timed,
        resident_used: false,
    })
}

/// Dispatch an IR program through resident resources when present, otherwise through the benchmark backend.
pub fn dispatch_program_timed(
    ctx: &BenchContext,
    program: &vyre::ir::Program,
    resident: Option<&ResidentInputSet>,
    inputs: &[Vec<u8>],
    config: &DispatchConfig,
) -> Result<ResidentDispatch, BenchError> {
    if let Some(resident) = resident {
        let timed = resident
            .dispatch_timed(program, config)
            .map_err(|error| BenchError::BackendFailed(error.to_string()))?;
        return Ok(ResidentDispatch {
            timed,
            resident_used: true,
        });
    }

    let timed = ctx
        .dispatch_timed(program, inputs, config)
        .map_err(|error| BenchError::BackendFailed(error.to_string()))?;
    Ok(ResidentDispatch {
        timed,
        resident_used: false,
    })
}

impl ResidentInputSet {
    /// Upload every benchmark input as a resident resource.
    ///
    /// Unsupported resident allocation returns `Ok(None)` so callers can use
    /// the normal host-buffer path. Any other backend error is a benchmark
    /// failure because partial residency would corrupt the measured workload.
    pub fn upload_optional(
        ctx: &BenchContext,
        inputs: &[Vec<u8>],
        cleanup_label: &'static str,
    ) -> Result<Option<Self>, BenchError> {
        match Self::upload(ctx, inputs, cleanup_label) {
            Ok(resident) => Ok(Some(resident)),
            Err(BackendError::UnsupportedFeature { name, .. })
                if name == "resident buffer allocation" =>
            {
                Ok(None)
            }
            Err(error) => Err(BenchError::BackendFailed(error.to_string())),
        }
    }

    /// Upload benchmark inputs and append zero-filled resident output buffers.
    ///
    /// Use this for sparse-output benchmarks where the kernel writes into a
    /// storage/output resource that should not be re-uploaded every measured
    /// sample. The input resources keep their original indices and zero outputs
    /// are appended in `output_sizes` order.
    pub fn upload_with_zeroed_outputs_optional(
        ctx: &BenchContext,
        inputs: &[Vec<u8>],
        output_sizes: &[usize],
        cleanup_label: &'static str,
    ) -> Result<Option<Self>, BenchError> {
        match Self::upload_with_zeroed_outputs(ctx, inputs, output_sizes, cleanup_label) {
            Ok(resident) => Ok(Some(resident)),
            Err(BackendError::UnsupportedFeature { name, .. })
                if name == "resident buffer allocation" =>
            {
                Ok(None)
            }
            Err(error) => Err(BenchError::BackendFailed(error.to_string())),
        }
    }

    /// Dispatch against the uploaded resident resources.
    pub fn dispatch_timed(
        &self,
        program: &vyre::ir::Program,
        config: &DispatchConfig,
    ) -> Result<TimedDispatchResult, BackendError> {
        self.backend
            .dispatch_resident_timed(program, &self.resources, config)
    }

    /// Re-upload a small payload into an existing resident resource.
    pub fn upload_resource(
        &self,
        index: usize,
        payload: &[u8],
        context: &str,
    ) -> Result<(), BenchError> {
        let resource = self.resources.get(index).ok_or_else(|| {
            BenchError::ExecutionFailed(format!(
                "{context} resident resources missing reset resource at index {index}"
            ))
        })?;
        self.backend
            .upload_resident(resource, payload)
            .map_err(|error| BenchError::BackendFailed(error.to_string()))
    }

    /// Clone resident resource handles in caller-requested binding order.
    pub fn resources_for_indices(
        &self,
        indices: &[usize],
        context: &str,
    ) -> Result<Vec<Resource>, BenchError> {
        indices
            .iter()
            .map(|&index| {
                self.resources.get(index).cloned().ok_or_else(|| {
                    BenchError::ExecutionFailed(format!(
                        "{context} resident resources missing resource at index {index}"
                    ))
                })
            })
            .collect()
    }

    fn upload(
        ctx: &BenchContext,
        inputs: &[Vec<u8>],
        cleanup_label: &'static str,
    ) -> Result<Self, BackendError> {
        Self::upload_with_zeroed_outputs(ctx, inputs, &[], cleanup_label)
    }

    fn upload_with_zeroed_outputs(
        ctx: &BenchContext,
        inputs: &[Vec<u8>],
        output_sizes: &[usize],
        cleanup_label: &'static str,
    ) -> Result<Self, BackendError> {
        let backend = Arc::clone(&ctx.preferred_backend);
        let mut resources = Vec::with_capacity(resident_set_resource_count(inputs, output_sizes));
        let mut zero_scratch = Vec::new();
        let result = allocate_and_upload_resident_set(
            backend.as_ref(),
            &mut resources,
            inputs,
            output_sizes,
            &mut zero_scratch,
        );

        if let Err(error) = result {
            for resource in resources {
                if let Err(cleanup_error) = backend.free_resident(resource) {
                    eprintln!("{cleanup_label} resident rollback cleanup failed: {cleanup_error}");
                }
            }
            return Err(error);
        }

        Ok(Self {
            backend,
            resources,
            cleanup_label,
        })
    }
}

impl Drop for ResidentInputSet {
    fn drop(&mut self) {
        for resource in self.resources.drain(..) {
            if let Err(error) = self.backend.free_resident(resource) {
                eprintln!("{} resident cleanup failed: {error}", self.cleanup_label);
            }
        }
    }
}

impl ResidentInputPool {
    /// Upload `set_count` copies of `inputs` and return `None` when residency is unsupported.
    pub fn upload_optional(
        ctx: &BenchContext,
        inputs: &[Vec<u8>],
        set_count: usize,
        cleanup_label: &'static str,
    ) -> Result<Option<Self>, BenchError> {
        match Self::upload(ctx, inputs, set_count, cleanup_label) {
            Ok(pool) => Ok(Some(pool)),
            Err(BackendError::UnsupportedFeature { name, .. })
                if name == "resident buffer allocation" =>
            {
                Ok(None)
            }
            Err(error) => Err(BenchError::BackendFailed(error.to_string())),
        }
    }

    /// Return the next resident input set, re-uploading when the pool wraps.
    pub fn next_set<'a>(&'a mut self, inputs: &[Vec<u8>]) -> Result<&'a [Resource], BenchError> {
        if self.sets.is_empty() {
            return Err(BenchError::ExecutionFailed(format!(
                "{} resident pool is empty",
                self.cleanup_label
            )));
        }
        let index = self.next_set % self.sets.len();
        if self.sets[index].len() != inputs.len() {
            return Err(BenchError::ExecutionFailed(format!(
                "{} resident pool input count changed: pool has {}, caller passed {}",
                self.cleanup_label,
                self.sets[index].len(),
                inputs.len()
            )));
        }
        if self.next_set >= self.sets.len() {
            upload_resident_inputs(self.backend.as_ref(), &self.sets[index], inputs)
                .map_err(|error| BenchError::BackendFailed(error.to_string()))?;
        }
        self.next_set = self.next_set.saturating_add(1);
        Ok(&self.sets[index])
    }

    fn upload(
        ctx: &BenchContext,
        inputs: &[Vec<u8>],
        set_count: usize,
        cleanup_label: &'static str,
    ) -> Result<Self, BackendError> {
        if set_count == 0 {
            return Ok(Self {
                backend: Arc::clone(&ctx.preferred_backend),
                sets: Vec::new(),
                next_set: 0,
                cleanup_label,
            });
        }

        let backend = Arc::clone(&ctx.preferred_backend);
        let mut sets = Vec::with_capacity(set_count);
        let mut zero_scratch = Vec::new();
        let result = (|| {
            for _ in 0..set_count {
                sets.push(Vec::with_capacity(resident_set_resource_count(inputs, &[])));
                let resource_index = sets.len() - 1;
                allocate_and_upload_resident_set(
                    backend.as_ref(),
                    &mut sets[resource_index],
                    inputs,
                    &[],
                    &mut zero_scratch,
                )?;
            }
            Ok(())
        })();

        if let Err(error) = result {
            for set in sets {
                for resource in set {
                    if let Err(cleanup_error) = backend.free_resident(resource) {
                        eprintln!(
                            "{cleanup_label} resident pool rollback cleanup failed: {cleanup_error}"
                        );
                    }
                }
            }
            return Err(error);
        }

        Ok(Self {
            backend,
            sets,
            next_set: 0,
            cleanup_label,
        })
    }
}

impl Drop for ResidentInputPool {
    fn drop(&mut self) {
        for set in self.sets.drain(..) {
            for resource in set {
                if let Err(error) = self.backend.free_resident(resource) {
                    eprintln!(
                        "{} resident pool cleanup failed: {error}",
                        self.cleanup_label
                    );
                }
            }
        }
    }
}

fn allocate_and_upload_resident_set(
    backend: &dyn VyreBackend,
    resources: &mut Vec<Resource>,
    inputs: &[Vec<u8>],
    output_sizes: &[usize],
    zero_scratch: &mut Vec<u8>,
) -> Result<(), BackendError> {
    let start = resources.len();
    for input in inputs {
        resources.push(backend.allocate_resident(input.len())?);
    }
    for &output_size in output_sizes {
        resources.push(backend.allocate_resident(output_size)?);
    }
    if let Some(max_output_size) = output_sizes.iter().copied().max() {
        if zero_scratch.len() < max_output_size {
            zero_scratch.resize(max_output_size, 0);
        }
    }

    let mut uploads = Vec::with_capacity(non_empty_upload_count(inputs, output_sizes));
    for (resource, input) in resources[start..start + inputs.len()]
        .iter()
        .zip(inputs.iter())
    {
        if !input.is_empty() {
            uploads.push((resource, input.as_slice()));
        }
    }
    let output_start = start + inputs.len();
    for (resource, &output_size) in resources[output_start..].iter().zip(output_sizes.iter()) {
        if output_size != 0 {
            uploads.push((resource, &zero_scratch[..output_size]));
        }
    }
    if !uploads.is_empty() {
        backend.upload_resident_many(&uploads)?;
    }
    Ok(())
}

fn upload_resident_inputs(
    backend: &dyn VyreBackend,
    resources: &[Resource],
    inputs: &[Vec<u8>],
) -> Result<(), BackendError> {
    let mut uploads = Vec::with_capacity(non_empty_upload_count(inputs, &[]));
    for (resource, input) in resources.iter().zip(inputs.iter()) {
        if !input.is_empty() {
            uploads.push((resource, input.as_slice()));
        }
    }
    if !uploads.is_empty() {
        backend.upload_resident_many(&uploads)?;
    }
    Ok(())
}

fn non_empty_upload_count(inputs: &[Vec<u8>], output_sizes: &[usize]) -> usize {
    inputs.iter().filter(|input| !input.is_empty()).count()
        + output_sizes
            .iter()
            .filter(|&&output_size| output_size != 0)
            .count()
}

fn resident_set_resource_count(inputs: &[Vec<u8>], output_sizes: &[usize]) -> usize {
    inputs.len().saturating_add(output_sizes.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_bytes_total_sums_encoded_buffers_once() {
        let inputs = vec![vec![0; 3], vec![0; 5], Vec::new(), vec![0; 7]];

        assert_eq!(input_bytes_total(&inputs), 15);
    }

    #[test]
    fn resident_batch_upload_count_skips_empty_resources() {
        let inputs = vec![vec![1; 3], Vec::new(), vec![2; 1]];
        let output_sizes = [0, 8, 16, 0];

        assert_eq!(
            non_empty_upload_count(&inputs, &output_sizes),
            4,
            "resident benchmark setup must batch only non-empty staged payloads"
        );
        assert_eq!(
            resident_set_resource_count(&inputs, &output_sizes),
            7,
            "resident benchmark setup must still allocate empty ABI resources"
        );
    }

    #[test]
    fn resident_batch_upload_count_matches_generated_staging_layouts() {
        for case in 0..4096usize {
            let input_count = case % 9;
            let output_count = (case / 7) % 9;
            let inputs = (0..input_count)
                .map(|index| {
                    let len = (case.wrapping_mul(17).wrapping_add(index * 5)) % 13;
                    vec![index as u8; len]
                })
                .collect::<Vec<_>>();
            let output_sizes = (0..output_count)
                .map(|index| (case.wrapping_mul(11).wrapping_add(index * 3)) % 17)
                .collect::<Vec<_>>();
            let expected_uploads = inputs.iter().filter(|input| !input.is_empty()).count()
                + output_sizes.iter().filter(|&&size| size != 0).count();

            assert_eq!(
                non_empty_upload_count(&inputs, &output_sizes),
                expected_uploads,
                "case {case} must count exactly the non-empty resident staging payloads"
            );
            assert_eq!(
                resident_set_resource_count(&inputs, &output_sizes),
                input_count + output_count,
                "case {case} must allocate every ABI resource even when no upload is needed"
            );
        }
    }

    #[test]
    fn transfer_accounting_counts_resident_samples_as_output_only() {
        let accounting = transfer_accounting(4096, 128, true);

        assert_eq!(accounting.bytes_read, 0);
        assert_eq!(accounting.bytes_written, 128);
        assert_eq!(accounting.bytes_touched, 128);
    }

    #[test]
    fn transfer_accounting_counts_host_fallback_as_full_roundtrip() {
        let accounting = transfer_accounting(4096, 128, false);

        assert_eq!(accounting.bytes_read, 4096);
        assert_eq!(accounting.bytes_written, 128);
        assert_eq!(accounting.bytes_touched, 4224);
    }

    #[test]
    fn transfer_accounting_saturates_touched_bytes() {
        let accounting = transfer_accounting(u64::MAX, 4096, false);

        assert_eq!(accounting.bytes_read, u64::MAX);
        assert_eq!(accounting.bytes_written, 4096);
        assert_eq!(accounting.bytes_touched, u64::MAX);
    }

    #[test]
    fn u32_counter_reset_program_targets_single_read_write_word() {
        let program = u32_counter_reset_program("counter");

        assert_eq!(program.workgroup_size(), [1, 1, 1]);
        assert_eq!(program.buffers().len(), 1);
        assert_eq!(program.buffers()[0].name.as_ref(), "counter");
        assert_eq!(program.buffers()[0].binding, 0);
        assert_eq!(program.buffers()[0].access, BufferAccess::ReadWrite);
        assert_eq!(program.buffers()[0].count, 1);
    }
}
