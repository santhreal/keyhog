use smallvec::SmallVec;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use vyre_foundation::ir::Program;

use crate::WgpuBackend;

enum WgpuPendingKind {
    Ready(Vec<Vec<u8>>),
    Readback(crate::engine::record_and_readback::WgpuPendingReadback),
    Deferred(Box<DeferredDispatch>),
}

pub(crate) struct WgpuPendingDispatch {
    kind: WgpuPendingKind,
    started: Instant,
    timeout: Option<Duration>,
}

impl vyre_driver::backend::private::Sealed for WgpuPendingDispatch {}

impl WgpuPendingDispatch {
    pub(crate) fn await_owned(self) -> Result<Vec<Vec<u8>>, vyre::BackendError> {
        let result = match self.kind {
            WgpuPendingKind::Ready(outputs) => Ok(outputs),
            WgpuPendingKind::Readback(pending) => pending.await_result(),
            WgpuPendingKind::Deferred(deferred) => deferred.await_result()?.await_owned(),
        }?;
        if let Some(deadline) = self.timeout {
            let elapsed = self.started.elapsed();
            if elapsed > deadline {
                return Err(vyre::BackendError::new(format!(
                    "dispatch exceeded configured timeout: took {elapsed:?}, budget {deadline:?}. \
                     Fix: raise DispatchConfig.timeout or split the program into smaller chunks."
                )));
            }
        }
        Ok(result)
    }

    fn is_ready_inner(&self) -> bool {
        match &self.kind {
            WgpuPendingKind::Ready(_) => true,
            WgpuPendingKind::Readback(pending) => pending.is_ready(),
            WgpuPendingKind::Deferred(deferred) => deferred.is_ready(),
        }
    }
}

impl vyre_driver::PendingDispatch for WgpuPendingDispatch {
    fn is_ready(&self) -> bool {
        self.is_ready_inner()
    }

    fn await_result(self: Box<Self>) -> Result<Vec<Vec<u8>>, vyre::BackendError> {
        (*self).await_owned()
    }
}

type AsyncDispatchResult = Result<WgpuPendingDispatch, vyre::BackendError>;
type AsyncDispatchTask = Box<dyn FnOnce() -> AsyncDispatchResult + Send + 'static>;

struct AsyncDispatchJob {
    task: AsyncDispatchTask,
    response: crossbeam_channel::Sender<AsyncDispatchResult>,
}

struct AsyncDispatchPool {
    sender: crossbeam_channel::Sender<AsyncDispatchJob>,
}

impl AsyncDispatchPool {
    fn global() -> Result<&'static Self, vyre::BackendError> {
        static POOL: LazyLock<Result<AsyncDispatchPool, vyre::BackendError>> =
            LazyLock::new(AsyncDispatchPool::new);
        POOL.as_ref()
            .map_err(|error| vyre::BackendError::new(error.to_string()))
    }

    fn new() -> Result<Self, vyre::BackendError> {
        const QUEUE_CAPACITY: usize = 1024;
        let (sender, receiver) = crossbeam_channel::bounded::<AsyncDispatchJob>(QUEUE_CAPACITY);
        let workers = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .clamp(1, 32);
        for index in 0..workers {
            let receiver = receiver.clone();
            std::thread::Builder::new()
                .name(format!("vyre-wgpu-dispatch-async-{index}"))
                .spawn(move || {
                    while let Ok(job) = receiver.recv() {
                        let result =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(job.task))
                                .unwrap_or_else(|_| {
                                    Err(vyre::BackendError::new(
                                        "wgpu async dispatch worker panicked. Fix: inspect the Program, GPU driver logs, and worker-pool invariants.",
                                    ))
                                });
                        if let Err(error) = job.response.send(result) {
                            tracing::error!(
                                ?error,
                                "wgpu async dispatch result was lost because the receiver dropped"
                            );
                        }
                    }
                })
                .map_err(|error| {
                    vyre::BackendError::new(format!(
                        "failed to spawn wgpu async dispatch worker {index}: {error}. Fix: reduce process thread count or increase system nproc limit."
                    ))
                })?;
        }
        Ok(Self { sender })
    }

    fn submit(&self, task: AsyncDispatchTask) -> Result<DeferredDispatch, vyre::BackendError> {
        let (response, receiver) = crossbeam_channel::bounded(1);
        let job = AsyncDispatchJob { task, response };
        self.sender.try_send(job).map_err(|error| {
            vyre::BackendError::new(format!(
                "wgpu async dispatch queue is full or closed: {error}. Fix: await existing PendingDispatch handles or increase caller-side backpressure."
            ))
        })?;
        Ok(DeferredDispatch {
            receiver,
            cached: Mutex::new(None),
        })
    }
}

struct DeferredDispatch {
    receiver: crossbeam_channel::Receiver<AsyncDispatchResult>,
    cached: Mutex<Option<AsyncDispatchResult>>,
}

impl DeferredDispatch {
    fn is_ready(&self) -> bool {
        let mut cached = match self.cached.lock() {
            Ok(guard) => guard,
            Err(error) => error.into_inner(),
        };
        if cached.is_none() {
            match self.receiver.try_recv() {
                Ok(result) => *cached = Some(result),
                Err(crossbeam_channel::TryRecvError::Empty) => return false,
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    *cached = Some(Err(vyre::BackendError::new(
                        "wgpu async dispatch worker ended before returning a pending readback. Fix: inspect worker-pool lifecycle and GPU driver logs.",
                    )));
                }
            }
        }
        match cached.as_ref() {
            Some(Ok(pending)) => pending.is_ready_inner(),
            Some(Err(_)) => true,
            None => false,
        }
    }

    fn await_result(self) -> AsyncDispatchResult {
        if let Some(result) = self
            .cached
            .into_inner()
            .unwrap_or_else(|error| error.into_inner())
        {
            return result;
        }
        self.receiver.recv().map_err(|error| {
            vyre::BackendError::new(format!(
                "wgpu async dispatch worker ended before returning a result: {error}. Fix: inspect worker-pool lifecycle and GPU driver logs."
            ))
        })?
    }
}

impl WgpuBackend {
    pub(crate) fn dispatch_owned_async(
        &self,
        program: Program,
        inputs: Vec<Vec<u8>>,
        config: vyre::DispatchConfig,
        started: Instant,
    ) -> Result<WgpuPendingDispatch, vyre::BackendError> {
        self.validate_with_cache(&program)?;
        if program.is_explicit_noop() {
            return Ok(WgpuPendingDispatch {
                kind: WgpuPendingKind::Ready(Vec::new()),
                started,
                timeout: config.timeout,
            });
        }

        let backend = self.clone();
        let timeout = config.timeout;
        let deferred = AsyncDispatchPool::global()?.submit(Box::new(move || {
            let borrowed: SmallVec<[&[u8]; 8]> = inputs.iter().map(Vec::as_slice).collect();
            backend.dispatch_borrowed_async(&program, &borrowed, &config)
        }))?;
        Ok(WgpuPendingDispatch {
            kind: WgpuPendingKind::Deferred(Box::new(deferred)),
            started,
            timeout,
        })
    }

    pub(crate) fn dispatch_borrowed_async(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &vyre::DispatchConfig,
    ) -> Result<WgpuPendingDispatch, vyre::BackendError> {
        let started = Instant::now();
        self.validate_with_cache(program)?;
        if program.is_explicit_noop() {
            return Ok(WgpuPendingDispatch {
                kind: WgpuPendingKind::Ready(Vec::new()),
                started,
                timeout: config.timeout,
            });
        }

        let pipeline = crate::pipeline::WgpuPipeline::compile_with_device_queue(
            program,
            config,
            self.adapter_info.clone(),
            self.enabled_features,
            self.current_device_queue(),
            self.dispatch_arena.clone(),
            self.current_persistent_pool(),
            self.pipeline_cache.clone(),
        )?;

        if let Some(deadline) = config.timeout {
            let elapsed = started.elapsed();
            if elapsed > deadline {
                return Err(vyre::BackendError::new(format!(
                    "dispatch cancelled after DispatchConfig.timeout before GPU submission: took {elapsed:?}, budget {deadline:?}. \
                     Fix: raise DispatchConfig.timeout or split the program into smaller chunks."
                )));
            }
        }

        let workgroup_count = if let Some(grid) = config.grid_override {
            grid
        } else {
            let count = pipeline
                .output_word_count
                .div_ceil(pipeline.workgroup_size as usize)
                .max(1)
                .try_into()
                .unwrap_or(u32::MAX);
            [count, 1, 1]
        };
        let pending = crate::engine::record_and_readback::record_and_submit_async(
            crate::engine::record_and_readback::RecordAndReadback {
                device_queue: &pipeline.device_queue,
                pool: self.dispatch_arena.pool(),
                pipeline: &pipeline.pipeline,
                bind_group_layouts: &pipeline.bind_group_layouts,
                buffer_bindings: &pipeline.buffer_bindings,
                inputs,
                output_bindings: &pipeline.output_bindings,
                trap_tags: &pipeline.trap_tags,
                workgroup_count,
                indirect: pipeline.indirect.as_ref(),
                labels: crate::engine::record_and_readback::DispatchLabels {
                    readback: "vyre dispatch_async readback",
                    bind_group: "vyre dispatch_async bind group",
                    encoder: "vyre dispatch_async",
                    compute: "vyre dispatch_async compute",
                },
                iterations: config.fixpoint_iterations.unwrap_or(1).max(1),
            },
        )?;
        Ok(WgpuPendingDispatch {
            kind: WgpuPendingKind::Readback(pending),
            started,
            timeout: config.timeout,
        })
    }
}
