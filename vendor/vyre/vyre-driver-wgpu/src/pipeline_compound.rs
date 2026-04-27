//! Compound command-buffer dispatch for pipeline mode (Innovation I.14).

use crate::buffer::GpuBufferHandle;
use crate::pipeline::{DispatchItem, OutputLayout, WgpuPipeline};
use crate::pipeline_persistent::usage_for_binding;
use vyre_driver::{BackendError, DispatchConfig, Resource};

impl WgpuPipeline {
    /// Batch several inputs for this same compiled program into one GPU
    /// submission.
    pub fn dispatch_coalesced(
        &self,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<Vec<u8>>>, BackendError> {
        let requests = inputs
            .iter()
            .map(|input| (self, Resource::Borrowed(input.clone())))
            .collect::<Vec<_>>();
        Self::dispatch_compound_v2(&requests, config)
    }

    /// Optimized substrate-neutral compound dispatch (V7-PERF-021).
    pub fn dispatch_compound_v2(
        requests: &[(&WgpuPipeline, Resource)],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<Vec<u8>>>, BackendError> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }
        let (device, queue) = &*requests[0].0.device_queue;
        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("vyre compound dispatch v2"),
        });
        let mut live = Vec::with_capacity(requests.len());
        for (pipeline, resource) in requests {
            if pipeline.device_queue.0 != *device {
                return Err(BackendError::new(
                    "cross-device compound dispatch is unsupported",
                ));
            }
            live.push(pipeline.record_compound_dispatch_v2(
                device,
                &mut encoder,
                resource,
                config,
            )?);
        }
        let submission = queue.submit(std::iter::once(encoder.finish()));
        let outputs = live
            .into_iter()
            .map(|resources| resources.read(device, submission.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        enforce_compound_output_budget(config, &outputs)?;
        Ok(outputs)
    }

    fn record_compound_dispatch_v2(
        &self,
        device: &wgpu::Device,
        encoder: &mut wgpu::CommandEncoder,
        resource: &Resource,
        config: &DispatchConfig,
    ) -> Result<PipelineDispatchReadback, BackendError> {
        let workgroup_count = self
            .output_word_count
            .div_ceil(self.workgroup_size as usize)
            .max(1)
            .try_into()
            .unwrap_or(u32::MAX);
        let workgroups = config.grid_override.unwrap_or([workgroup_count, 1, 1]);

        let (input_handles, output_handles) = match resource {
            Resource::Borrowed(bytes) => self.legacy_handles_from_inputs(&[bytes])?,
            Resource::Resident(id) => self.handles_from_resident_resource(*id)?,
        };

        self.record_persistent_item(
            device,
            encoder,
            &DispatchItem {
                inputs: &input_handles,
                outputs: &output_handles,
                params: None,
                workgroups,
            },
        )?;

        let readback_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("vyre readback"),
            size: self.output.copy_size as u64,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });

        let output = output_handles
            .first()
            .ok_or_else(|| BackendError::new("no output"))?;
        encoder.copy_buffer_to_buffer(
            output.buffer(),
            self.output.copy_offset as u64,
            &readback_buffer,
            0,
            self.output.copy_size as u64,
        );

        Ok(PipelineDispatchReadback {
            readback_buffer,
            output: self.output,
            _input_handles: input_handles,
            _output_handles: output_handles,
        })
    }

    fn handles_from_resident_resource(
        &self,
        id: u64,
    ) -> Result<(Vec<GpuBufferHandle>, Vec<GpuBufferHandle>), BackendError> {
        let input_count = self
            .buffer_bindings
            .iter()
            .filter(|info| info.kind != vyre::ir::MemoryKind::Shared && !info.is_output)
            .count();
        if input_count != 1 {
            return Err(BackendError::new(format!(
                "Resident Resource can bind exactly one non-output buffer, but this pipeline declares {input_count}. Fix: call dispatch_persistent with the full input handle list for multi-input resident dispatch."
            )));
        }
        let input = GpuBufferHandle::from_resident_id(id).ok_or_else(|| {
            BackendError::new(format!(
                "Resident Resource id {id} is not live in the wgpu resident registry. Fix: keep the GpuBufferHandle alive until compound dispatch completes."
            ))
        })?;
        let mut outputs = Vec::new();
        for info in self.buffer_bindings.iter() {
            if info.kind == vyre::ir::MemoryKind::Shared || !info.is_output {
                continue;
            }
            let output = self.output_binding(info.binding)?;
            let output_bytes = output.word_count.checked_mul(4).ok_or_else(|| {
                BackendError::new(format!(
                    "compound resident output `{}` size overflows usize. Fix: reduce its element count.",
                    output.name
                ))
            })?;
            outputs.push(
                self.persistent_pool
                    .acquire(output_bytes as u64, usage_for_binding(info)?)?,
            );
        }
        Ok((vec![input], outputs))
    }

    /// Legacy compatibility shim.
    pub fn dispatch_compound(
        requests: &[(&WgpuPipeline, &[u8])],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<Vec<u8>>>, BackendError> {
        let v2_reqs: Vec<_> = requests
            .iter()
            .map(|(p, i)| (*p, Resource::Borrowed(i.to_vec())))
            .collect();
        Self::dispatch_compound_v2(&v2_reqs, config)
    }
}

fn enforce_compound_output_budget(
    config: &DispatchConfig,
    outputs: &[Vec<Vec<u8>>],
) -> Result<(), BackendError> {
    let Some(limit) = config.max_output_bytes else {
        return Ok(());
    };
    let actual = outputs.iter().try_fold(0usize, |sum, dispatch_outputs| {
        dispatch_outputs.iter().try_fold(sum, |inner_sum, output| {
            inner_sum.checked_add(output.len()).ok_or_else(|| {
                BackendError::new(
                    "compound readback size overflows usize. Fix: split the Program output before dispatch.",
                )
            })
        })
    })?;
    if actual > limit {
        return Err(BackendError::new(format!(
            "compound readback size {actual} exceeds DispatchConfig.max_output_bytes {limit}. Fix: narrow BufferDecl::output_byte_range or raise max_output_bytes."
        )));
    }
    Ok(())
}

struct PipelineDispatchReadback {
    readback_buffer: wgpu::Buffer,
    output: OutputLayout,
    _input_handles: Vec<GpuBufferHandle>,
    _output_handles: Vec<GpuBufferHandle>,
}

impl PipelineDispatchReadback {
    fn read(
        self,
        device: &wgpu::Device,
        submission: wgpu::SubmissionIndex,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        let slice = self.readback_buffer.slice(..);
        let (sender, receiver) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |res| {
            if let Err(error) = sender.send(res) {
                tracing::error!(
                    ?error,
                    "compound pipeline readback map_async result was lost because the receiver dropped"
                );
            }
        });
        match device.poll(wgpu::Maintain::wait_for(submission)) {
            wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {}
        }
        receiver
            .recv()
            .map_err(|_| BackendError::new("channel closed"))?
            .map_err(|e| BackendError::new(format!("{:?}", e)))?;

        let mapped = slice.get_mapped_range();
        let end = self.output.trim_start + self.output.read_size;
        let res = mapped[self.output.trim_start..end].to_vec();
        drop(mapped);
        self.readback_buffer.unmap();
        Ok(vec![res])
    }
}
