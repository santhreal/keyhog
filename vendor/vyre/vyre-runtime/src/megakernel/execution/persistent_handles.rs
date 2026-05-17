use super::{
    nanos_u64, Megakernel, MegakernelBatchDispatchOutput, MegakernelDispatchOutput,
    MegakernelDispatchStats, MegakernelResidentHandles,
};
use crate::PipelineError;
use smallvec::SmallVec;
use std::time::Instant;
use vyre_driver::backend::Resource;

impl Megakernel {
    /// Dispatch using backend-resident handles for all megakernel ABI buffers.
    ///
    /// This path never falls back to host byte buffers. If the compiled backend
    /// pipeline does not implement resident handles, the backend's structured
    /// unsupported-feature error is returned.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when the backend rejects persistent handles,
    /// dispatch fails, or device-loss recovery cannot rebuild the pipeline.
    pub fn dispatch_persistent_handles(
        &self,
        handles: MegakernelResidentHandles,
    ) -> Result<Vec<Vec<u8>>, PipelineError> {
        Ok(self.dispatch_persistent_handles_observed(handles)?.buffers)
    }

    /// Dispatch using backend-resident handles and return instrumentation.
    ///
    /// # Errors
    ///
    /// See [`Megakernel::dispatch_persistent_handles`].
    pub fn dispatch_persistent_handles_observed(
        &self,
        handles: MegakernelResidentHandles,
    ) -> Result<MegakernelDispatchOutput, PipelineError> {
        if self.has_grid_sync && !self.backend.supports_grid_sync() {
            return Err(PipelineError::Backend(
                "persistent-handle dispatch cannot split GridSync barriers without backend-resident segment threading. Fix: use a backend with native grid sync or dispatch borrowed buffers through the grid-sync splitter."
                    .to_string(),
            ));
        }
        let resources = handles.resources();
        let config = self.launch_geometry().dispatch_config(None);
        let started = Instant::now();
        let mut recovered = false;
        let outputs = match self.dispatch_persistent_handles_once(&resources, &config) {
            Ok(outputs) => outputs,
            Err(error) if self.recovery_policy.allows_retry(&error) => {
                self.recover_after_device_loss()?;
                recovered = true;
                self.dispatch_persistent_handles_once(&resources, &config)?
            }
            Err(error) => return Err(error.into()),
        };
        let latency_ns = nanos_u64(started.elapsed().as_nanos());
        let output_bytes = outputs
            .iter()
            .map(|buffer| buffer.len() as u64)
            .fold(0_u64, u64::saturating_add);
        let output_buffers = u32::try_from(outputs.len()).unwrap_or(u32::MAX);
        Ok(MegakernelDispatchOutput {
            buffers: outputs,
            stats: MegakernelDispatchStats {
                input_bytes: 0,
                output_bytes,
                latency_ns,
                output_buffers,
                recovered_after_device_loss: recovered,
            },
        })
    }

    /// Dispatch several resident megakernel submissions through the compiled
    /// backend batch contract.
    ///
    /// This is the many-small-launch path: callers keep every ABI buffer
    /// resident, then submit a slice of handle tuples so native backends can
    /// record one command buffer or replay one graph batch instead of paying a
    /// host submission per item.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when the backend rejects persistent handles,
    /// any item fails, or device-loss recovery cannot rebuild the pipeline.
    pub fn dispatch_persistent_handles_many_observed(
        &self,
        handles: &[MegakernelResidentHandles],
    ) -> Result<MegakernelBatchDispatchOutput, PipelineError> {
        if handles.is_empty() {
            return Ok(MegakernelBatchDispatchOutput {
                batches: Vec::new(),
                stats: MegakernelDispatchStats {
                    input_bytes: 0,
                    output_bytes: 0,
                    latency_ns: 0,
                    output_buffers: 0,
                    recovered_after_device_loss: false,
                },
            });
        }
        if self.has_grid_sync && !self.backend.supports_grid_sync() {
            return Err(PipelineError::Backend(
                "batched persistent-handle dispatch cannot split GridSync barriers without backend-resident segment threading. Fix: use a backend with native grid sync or dispatch borrowed buffers through the grid-sync splitter."
                    .to_string(),
            ));
        }

        let resources: SmallVec<[[Resource; 4]; 16]> =
            handles.iter().map(|handles| handles.resources()).collect();
        let resource_refs: SmallVec<[&[Resource]; 16]> = resources
            .iter()
            .map(|resources| resources.as_slice())
            .collect();
        let config = self.launch_geometry().dispatch_config(None);
        let started = Instant::now();
        let mut recovered = false;
        let batches = match self.dispatch_persistent_handles_batched_once(&resource_refs, &config) {
            Ok(outputs) => outputs,
            Err(error) if self.recovery_policy.allows_retry(&error) => {
                self.recover_after_device_loss()?;
                recovered = true;
                self.dispatch_persistent_handles_batched_once(&resource_refs, &config)?
            }
            Err(error) => return Err(error.into()),
        };
        let latency_ns = nanos_u64(started.elapsed().as_nanos());
        let output_bytes = batches
            .iter()
            .flatten()
            .map(|buffer| buffer.len() as u64)
            .fold(0_u64, u64::saturating_add);
        let output_buffers =
            u32::try_from(batches.iter().map(Vec::len).sum::<usize>()).unwrap_or(u32::MAX);
        Ok(MegakernelBatchDispatchOutput {
            batches,
            stats: MegakernelDispatchStats {
                input_bytes: 0,
                output_bytes,
                latency_ns,
                output_buffers,
                recovered_after_device_loss: recovered,
            },
        })
    }
}
