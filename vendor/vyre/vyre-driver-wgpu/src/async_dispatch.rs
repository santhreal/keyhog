use std::sync::Arc;
use std::time::{Duration, Instant};
use vyre_foundation::ir::Program;

use crate::{PredictedProgram, WgpuBackend};

enum WgpuPendingKind {
    Ready(Vec<Vec<u8>>),
    Readback(crate::engine::record_and_readback::WgpuPendingReadback),
}

pub(crate) struct WgpuPendingDispatch {
    kind: WgpuPendingKind,
    started: Instant,
    timeout: Option<Duration>,
    prefetch: Option<PipelinePrefetch>,
}

impl vyre_driver::backend::private::Sealed for WgpuPendingDispatch {}

impl WgpuPendingDispatch {
    pub(crate) fn await_owned(
        self,
    ) -> Result<vyre_driver::OutputBuffers, vyre_driver::BackendError> {
        let Self {
            kind,
            started,
            timeout,
            prefetch,
        } = self;
        run_prefetch(prefetch);
        let outputs = match kind {
            WgpuPendingKind::Ready(outputs) => outputs,
            WgpuPendingKind::Readback(pending) => pending.await_result()?,
        };
        if let Some(deadline) = timeout {
            let elapsed = started.elapsed();
            if elapsed > deadline {
                return Err(vyre_driver::BackendError::new(format!(
                    "dispatch exceeded configured timeout: took {elapsed:?}, budget {deadline:?}. \
                     Fix: raise DispatchConfig.timeout or split the program into smaller chunks."
                )));
            }
        }
        Ok(outputs)
    }

    pub(crate) fn await_into(
        self,
        outputs: &mut vyre_driver::OutputBuffers,
    ) -> Result<(), vyre_driver::BackendError> {
        let Self {
            kind,
            started,
            timeout,
            prefetch,
        } = self;
        run_prefetch(prefetch);
        match kind {
            WgpuPendingKind::Ready(ready) => {
                outputs.clear();
                outputs.extend(ready);
                Ok(())
            }
            WgpuPendingKind::Readback(pending) => pending.await_into(outputs),
        }?;
        if let Some(deadline) = timeout {
            let elapsed = started.elapsed();
            if elapsed > deadline {
                return Err(vyre_driver::BackendError::new(format!(
                    "dispatch exceeded configured timeout: took {elapsed:?}, budget {deadline:?}. \
                     Fix: raise DispatchConfig.timeout or split the program into smaller chunks."
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn await_mapped_outputs<F>(
        self,
        mut visitor: F,
    ) -> Result<(), vyre_driver::BackendError>
    where
        F: FnMut(usize, &[u8]) -> Result<(), vyre_driver::BackendError>,
    {
        let Self {
            kind,
            started,
            timeout,
            prefetch,
        } = self;
        run_prefetch(prefetch);
        match kind {
            WgpuPendingKind::Ready(ready) => {
                for (index, output) in ready.iter().enumerate() {
                    visitor(index, output)?;
                }
                Ok(())
            }
            WgpuPendingKind::Readback(pending) => pending.await_mapped_outputs(visitor),
        }?;
        Self::enforce_timeout(started, timeout)
    }

    fn is_ready_inner(&self) -> bool {
        match &self.kind {
            WgpuPendingKind::Ready(_) => true,
            WgpuPendingKind::Readback(pending) => pending.is_ready(),
        }
    }

    fn enforce_timeout(
        started: Instant,
        timeout: Option<Duration>,
    ) -> Result<(), vyre_driver::BackendError> {
        if let Some(deadline) = timeout {
            let elapsed = started.elapsed();
            if elapsed > deadline {
                return Err(vyre_driver::BackendError::new(format!(
                    "dispatch exceeded configured timeout: took {elapsed:?}, budget {deadline:?}. \
                     Fix: raise DispatchConfig.timeout or split the program into smaller chunks."
                )));
            }
        }
        Ok(())
    }
}

impl vyre_driver::PendingDispatch for WgpuPendingDispatch {
    fn is_ready(&self) -> bool {
        self.is_ready_inner()
    }

    fn await_result(self: Box<Self>) -> Result<Vec<Vec<u8>>, vyre_driver::BackendError> {
        (*self).await_owned()
    }
}

impl WgpuBackend {
    /// GPU staging consumes these slices directly; backing memory must stay valid until the
    /// pending dispatch completes. The `VyreBackend::dispatch_async` implementation forwards here
    /// after collecting `Vec::as_slice` views into a `SmallVec`—no clone of input payloads.
    pub(crate) fn dispatch_borrowed_async(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &vyre_driver::DispatchConfig,
    ) -> Result<WgpuPendingDispatch, vyre_driver::BackendError> {
        let started = Instant::now();
        self.enforce_config_caps(config)?;
        self.validate_with_cache(program)?;
        self.dispatch_borrowed_async_validated(program, inputs, config, started)
    }

    fn dispatch_borrowed_async_validated(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &vyre_driver::DispatchConfig,
        started: Instant,
    ) -> Result<WgpuPendingDispatch, vyre_driver::BackendError> {
        self.enforce_config_caps(config)?;
        if program.is_explicit_noop() {
            return Ok(WgpuPendingDispatch {
                kind: WgpuPendingKind::Ready(Vec::new()),
                started,
                timeout: config.timeout,
                prefetch: None,
            });
        }

        let pipeline = crate::pipeline::WgpuPipeline::compile_with_device_queue(
            program,
            config,
            self.adapter_info.clone(),
            self.enabled_features,
            self.current_device_queue(),
            self.dispatch_arena_snapshot(),
            self.current_persistent_pool(),
            self.pipeline_cache.clone(),
            self.bind_group_layout_cache.clone(),
        )?;

        if let Some(deadline) = config.timeout {
            let elapsed = started.elapsed();
            if elapsed > deadline {
                return Err(vyre_driver::BackendError::new(format!(
                    "dispatch cancelled after DispatchConfig.timeout before GPU submission: took {elapsed:?}, budget {deadline:?}. \
                     Fix: raise DispatchConfig.timeout or split the program into smaller chunks."
                )));
            }
        }

        let workgroup_count = pipeline.workgroups_for_dispatch(config)?;
        let dispatch_arena = self.dispatch_arena_snapshot();
        let pending = crate::engine::record_and_readback::record_and_submit_async(
            crate::engine::record_and_readback::RecordAndReadback::for_dispatch(
                &pipeline,
                &dispatch_arena,
                inputs,
                workgroup_count,
                config,
                timestamp_profile_requested(config),
                crate::engine::record_and_readback::DispatchLabels {
                    readback: "vyre dispatch_async readback",
                    bind_group: "vyre dispatch_async bind group",
                    encoder: "vyre dispatch_async",
                    compute: "vyre dispatch_async compute",
                },
            ),
        )?;
        Ok(WgpuPendingDispatch {
            kind: WgpuPendingKind::Readback(pending),
            started,
            timeout: config.timeout,
            prefetch: self.next_shape_prefetch(program, config)?,
        })
    }
}

struct PipelinePrefetch {
    backend: WgpuBackend,
    program: Arc<Program>,
    config: vyre_driver::DispatchConfig,
}

impl PipelinePrefetch {
    fn run(self) {
        if let Err(error) = crate::pipeline::WgpuPipeline::compile_with_device_queue(
            &self.program,
            &self.config,
            self.backend.adapter_info.clone(),
            self.backend.enabled_features,
            self.backend.current_device_queue(),
            self.backend.dispatch_arena_snapshot(),
            self.backend.current_persistent_pool(),
            self.backend.pipeline_cache.clone(),
            self.backend.bind_group_layout_cache.clone(),
        ) {
            tracing::debug!(
                target: "vyre.wgpu.pipeline.prefetch",
                error = %error,
                "predicted pipeline prefetch failed"
            );
        }
    }
}

fn run_prefetch(prefetch: Option<PipelinePrefetch>) {
    if let Some(prefetch) = prefetch {
        prefetch.run();
    }
}

impl WgpuBackend {
    fn next_shape_prefetch(
        &self,
        program: &Program,
        config: &vyre_driver::DispatchConfig,
    ) -> Result<Option<PipelinePrefetch>, vyre_driver::BackendError> {
        let fingerprint = vyre_driver::program_vsa_fingerprint_words(program);
        self.predicted_programs
            .entry(fingerprint)
            .and_modify(|cached| cached.config = config.clone())
            .or_insert_with(|| PredictedProgram {
                program: Arc::new(program.clone()),
                config: config.clone(),
            });

        let predicted = {
            let mut history = self.shape_history.lock().map_err(|_| {
                vyre_driver::BackendError::new(
                    "wgpu shape-prediction history lock was poisoned. Fix: abort the current backend instance and reacquire the GPU backend.",
                )
            })?;
            history.record(fingerprint);
            history.predict_next()
        };

        let Some(predicted) = predicted else {
            return Ok(None);
        };
        Ok(self
            .predicted_programs
            .get(&predicted)
            .map(|cached| PipelinePrefetch {
                backend: self.clone(),
                program: Arc::clone(&cached.program),
                config: cached.config.clone(),
            }))
    }
}

pub(crate) fn timestamp_profile_requested(config: &vyre_driver::DispatchConfig) -> bool {
    matches!(
        config.profile.as_deref(),
        Some("gpu-timestamps" | "wgpu-timestamps" | "timestamps")
    ) || std::env::var_os("VYRE_WGPU_TIMESTAMPS").is_some()
}
