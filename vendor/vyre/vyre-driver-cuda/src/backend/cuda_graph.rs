#![allow(unsafe_code)]
//! cudaGraph capture-and-replay path for repeat-shape Programs.
//!
//! Op id: `vyre-driver-cuda::cuda_graph`. Soundness: `Exact` over the
//! captured launch sequence. Cost-direction: read-only at the wire layer
//! (does not mutate Program); host-side dispatch overhead is amortized by
//! replacing repeated launch construction with a cached `CUgraphExec`.
//!
//! ## Why
//!
//! Latency-bound kernels can spend more time in host launch setup than in
//! device execution. cudaGraph captures the full launch sequence (memcpy +
//! kernel launch + readback) into a graph object once; subsequent dispatches
//! replay the cached executable graph with `cuGraphLaunch`.
//!
//! ## Constraints
//!
//! - **No allocation during capture.** `cuMemAlloc_v2` returns
//!   `CUDA_ERROR_STREAM_CAPTURE_UNSUPPORTED` while a stream is in capture
//!   mode. `record_cuda_graph` allocates ALL device buffers BEFORE
//!   `cuStreamBeginCapture_v2` and stores them in `CachedCudaGraph`.
//! - **Host pointers must persist.** The captured `cuMemcpyHtoDAsync_v2`
//!   records the host source pointer; the cached graph reuses the SAME
//!   pointer on every replay. `CachedCudaGraph` owns the input host buffers
//!   so callers can write new bytes into them without changing the address.
//! - **Shape-bound.** A cached graph captures one specific input/output
//!   byte layout. Calling `dispatch_via_cuda_graph` with mismatched input
//!   sizes returns `BackendError::InvalidProgram` — the caller must record
//!   a fresh graph for each shape.
//!
//! ## Lifecycle
//!
//! ```text
//! CachedCudaGraph::record  ──► CUgraph ──► CUgraphExec ──► live
//!                               │
//!                               ▼
//!                        owns input/output device pointers
//!                        owns input/output host buffers
//!                        owns dedicated CUstream
//!                        owns CUfunction (via module_cache)
//!                               │
//! CachedCudaGraph::drop ──► cuGraphExecDestroy ──► cuGraphDestroy
//!                       ──► cuStreamDestroy_v2
//!                       ──► cuMemFree_v2 for each device buffer

use std::ptr::NonNull;
use std::sync::Arc;

use cudarc::driver::sys::{CUgraphExec_st, CUgraph_st, CUstream_st};
use smallvec::SmallVec;
use vyre_driver::binding::BindingRole;
use vyre_driver::{BackendError, DispatchConfig};
use vyre_foundation::ir::Program;

use super::allocations::{cuda_check, PinnedHostAllocation, PinnedHostAllocationPool};
use super::dispatch::CudaBackend;
use super::output_range::cuda_output_readback;
use super::plan::CudaDispatchPlan;

fn log_cuda_drop_result(op: &str, result: cudarc::driver::sys::CUresult) {
    if result != cudarc::driver::sys::CUresult::CUDA_SUCCESS {
        eprintln!(
            "Fix: {op} failed while releasing CUDA graph resources with {result:?}; ensure graph work has completed before resource drop."
        );
    }
}

/// CUDA driver constant: stream-capture-mode thread-local. Only the calling
/// thread's cuda calls are forbidden during capture (alloc-class operations
/// fail with `CUDA_ERROR_STREAM_CAPTURE_UNSUPPORTED`); other threads remain
/// free to allocate / launch. The alternative `GLOBAL` (value 0) blocks
/// alloc on every thread, which makes parallel test execution impossible
/// and would also stall any concurrent caller of `CudaBackend`.
/// Mirrors `CU_STREAM_CAPTURE_MODE_THREAD_LOCAL` from `cuda.h`.
const CU_STREAM_CAPTURE_MODE_THREAD_LOCAL: u32 = 1;

struct DevicePtrGuard {
    ptr: u64,
}

impl DevicePtrGuard {
    fn new(ptr: u64) -> Self {
        Self { ptr }
    }

    fn ptr(&self) -> u64 {
        self.ptr
    }

    fn into_raw(mut self) -> u64 {
        let ptr = self.ptr;
        self.ptr = 0;
        ptr
    }
}

impl Drop for DevicePtrGuard {
    fn drop(&mut self) {
        if self.ptr != 0 {
            unsafe {
                log_cuda_drop_result(
                    "cuMemFree_v2",
                    cudarc::driver::sys::cuMemFree_v2(self.ptr),
                );
            }
        }
    }
}

struct StreamGuard {
    stream: NonNull<CUstream_st>,
}

impl StreamGuard {
    fn new(stream: NonNull<CUstream_st>) -> Self {
        Self { stream }
    }

    fn ptr(&self) -> NonNull<CUstream_st> {
        self.stream
    }

    fn into_raw(mut self) -> NonNull<CUstream_st> {
        let stream = self.stream;
        self.stream = NonNull::dangling();
        stream
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        if self.stream != NonNull::dangling() {
            unsafe {
                log_cuda_drop_result(
                    "cuStreamDestroy_v2",
                    cudarc::driver::sys::cuStreamDestroy_v2(self.stream.as_ptr()),
                );
            }
        }
    }
}

struct CaptureGuard {
    stream: NonNull<CUstream_st>,
    active: bool,
}

impl CaptureGuard {
    fn armed(stream: NonNull<CUstream_st>) -> Self {
        Self {
            stream,
            active: true,
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                let mut graph_ptr: cudarc::driver::sys::CUgraph = std::ptr::null_mut();
                if cudarc::driver::sys::cuStreamEndCapture(self.stream.as_ptr(), &mut graph_ptr)
                    == cudarc::driver::sys::CUresult::CUDA_SUCCESS
                    && !graph_ptr.is_null()
                {
                    log_cuda_drop_result(
                        "cuGraphDestroy",
                        cudarc::driver::sys::cuGraphDestroy(graph_ptr),
                    );
                }
            }
        }
    }
}

struct GraphGuard {
    graph: NonNull<CUgraph_st>,
}

impl GraphGuard {
    fn new(graph: NonNull<CUgraph_st>) -> Self {
        Self { graph }
    }

    fn ptr(&self) -> NonNull<CUgraph_st> {
        self.graph
    }

    fn into_raw(mut self) -> NonNull<CUgraph_st> {
        let graph = self.graph;
        self.graph = NonNull::dangling();
        graph
    }
}

impl Drop for GraphGuard {
    fn drop(&mut self) {
        if self.graph != NonNull::dangling() {
            unsafe {
                log_cuda_drop_result(
                    "cuGraphDestroy",
                    cudarc::driver::sys::cuGraphDestroy(self.graph.as_ptr()),
                );
            }
        }
    }
}

struct GraphExecGuard {
    graph_exec: NonNull<CUgraphExec_st>,
}

impl GraphExecGuard {
    fn new(graph_exec: NonNull<CUgraphExec_st>) -> Self {
        Self { graph_exec }
    }

    fn into_raw(mut self) -> NonNull<CUgraphExec_st> {
        let graph_exec = self.graph_exec;
        self.graph_exec = NonNull::dangling();
        graph_exec
    }
}

impl Drop for GraphExecGuard {
    fn drop(&mut self) {
        if self.graph_exec != NonNull::dangling() {
            unsafe {
                log_cuda_drop_result(
                    "cuGraphExecDestroy",
                    cudarc::driver::sys::cuGraphExecDestroy(self.graph_exec.as_ptr()),
                );
            }
        }
    }
}

fn cuda_graph_binding_capacities(prepared: &CudaDispatchPlan) -> (usize, usize) {
    let mut input_capacity = 0usize;
    let mut output_capacity = 0usize;
    for binding in &prepared.bindings.bindings {
        if binding.role == BindingRole::Shared {
            continue;
        }
        if binding.input_index.is_some() {
            input_capacity = input_capacity.saturating_add(1);
        }
        if binding.output_index.is_some() {
            output_capacity = output_capacity.saturating_add(1);
        }
    }
    (input_capacity, output_capacity)
}

struct GraphHostBuffers {
    pool: Arc<PinnedHostAllocationPool>,
    input: SmallVec<[PinnedHostAllocation; 8]>,
    output: SmallVec<[PinnedHostAllocation; 8]>,
}

impl GraphHostBuffers {
    fn with_capacity(
        pool: Arc<PinnedHostAllocationPool>,
        input_capacity: usize,
        output_capacity: usize,
    ) -> Self {
        Self {
            pool,
            input: SmallVec::with_capacity(input_capacity),
            output: SmallVec::with_capacity(output_capacity),
        }
    }

    fn push_input(&mut self, bytes: &[u8]) -> Result<(), BackendError> {
        let mut allocation = self.pool.acquire(bytes.len())?;
        allocation.copy_from_slice(bytes);
        self.input.push(allocation);
        Ok(())
    }

    fn push_output(&mut self, byte_len: usize) -> Result<(), BackendError> {
        self.output.push(self.pool.acquire(byte_len)?);
        Ok(())
    }

    fn into_raw(
        mut self,
    ) -> (
        SmallVec<[PinnedHostAllocation; 8]>,
        SmallVec<[PinnedHostAllocation; 8]>,
    ) {
        let input = std::mem::take(&mut self.input);
        let output = std::mem::take(&mut self.output);
        (input, output)
    }
}

impl Drop for GraphHostBuffers {
    fn drop(&mut self) {
        for allocation in self.input.drain(..).chain(self.output.drain(..)) {
            self.pool.release(allocation);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::cuda_graph_binding_capacities;
    use crate::backend::CudaDispatchPlan;
    use smallvec::smallvec;
    use std::sync::Arc;
    use vyre_driver::binding::{Binding, BindingPlan, BindingRole};
    use vyre_driver::LaunchPlan;

    #[test]
    fn cuda_graph_binding_capacities_count_only_runtime_buffers() {
        let plan = CudaDispatchPlan {
            bindings: BindingPlan {
                bindings: vec![
                    Binding {
                        name: Arc::from("input"),
                        binding: 0,
                        buffer_index: 0,
                        role: BindingRole::Input,
                        element_size: 4,
                        preferred_alignment: 4,
                        element_count: 16,
                        static_byte_len: Some(64),
                        input_index: Some(0),
                        output_index: None,
                    },
                    Binding {
                        name: Arc::from("shared"),
                        binding: 1,
                        buffer_index: 1,
                        role: BindingRole::Shared,
                        element_size: 4,
                        preferred_alignment: 4,
                        element_count: 16,
                        static_byte_len: Some(64),
                        input_index: None,
                        output_index: None,
                    },
                    Binding {
                        name: Arc::from("output"),
                        binding: 2,
                        buffer_index: 2,
                        role: BindingRole::Output,
                        element_size: 4,
                        preferred_alignment: 4,
                        element_count: 16,
                        static_byte_len: Some(64),
                        input_index: None,
                        output_index: Some(0),
                    },
                ],
                input_indices: vec![0],
                output_indices: vec![2],
                shared_indices: vec![1],
            },
            output_binding_indices: smallvec![2],
            launch: LaunchPlan::new(),
            cooperative: false,
            fixpoint_iterations: 1,
        };

        assert_eq!(cuda_graph_binding_capacities(&plan), (1, 1));
    }

    #[test]
    fn cuda_graph_binding_capacities_count_input_output_twice() {
        let plan = CudaDispatchPlan {
            bindings: BindingPlan {
                bindings: vec![Binding {
                    name: Arc::from("state"),
                    binding: 0,
                    buffer_index: 0,
                    role: BindingRole::InputOutput,
                    element_size: 4,
                    preferred_alignment: 4,
                    element_count: 16,
                    static_byte_len: Some(64),
                    input_index: Some(0),
                    output_index: Some(0),
                }],
                input_indices: vec![0],
                output_indices: vec![0],
                shared_indices: vec![],
            },
            output_binding_indices: smallvec![0],
            launch: LaunchPlan::new(),
            cooperative: false,
            fixpoint_iterations: 1,
        };

        assert_eq!(cuda_graph_binding_capacities(&plan), (1, 1));
    }
}

/// A pre-recorded CUDA graph wrapping one full Program-dispatch sequence
/// (input HtoD memcpy + kernel launch + output DtoH memcpy). Hold on to this
/// across many `dispatch_via_cuda_graph` calls to amortize launch overhead.
///
/// `CachedCudaGraph` owns:
///   - The captured `CUgraph` and instantiated `CUgraphExec`.
///   - A dedicated `CUstream` used for capture + replay.
///   - Device pointers for every input + output buffer.
///   - Host buffers for every input (so callers write new bytes into the
///     same address the captured memcpy reads from) and every output (so
///     readback target stays stable across replays).
///
/// On drop, all CUDA resources are released in the right order.
#[derive(Debug)]
pub struct CachedCudaGraph {
    /// Backend reference — keeps the CUDA context alive for the cached
    /// graph's lifetime.
    pub(crate) backend: CudaBackend,
    /// Captured graph (owned). Destroyed in `drop`.
    pub(crate) graph: NonNull<CUgraph_st>,
    /// Instantiated graph executable (owned). Destroyed in `drop` BEFORE
    /// `graph`.
    pub(crate) graph_exec: NonNull<CUgraphExec_st>,
    /// Dedicated stream used for capture + replay (owned). Destroyed in
    /// `drop` AFTER graph + graph_exec.
    pub(crate) stream: NonNull<CUstream_st>,
    /// Per-input host buffers. Callers write new input bytes here before
    /// each replay; the captured memcpy reads from these addresses.
    pub(crate) input_host_bufs: SmallVec<[PinnedHostAllocation; 8]>,
    /// Per-input device pointers (allocated via `cuMemAlloc_v2`). Freed in
    /// `drop`.
    pub(crate) input_device_ptrs: SmallVec<[u64; 8]>,
    /// Per-output device pointers (allocated via `cuMemAlloc_v2`). Freed
    /// in `drop`.
    pub(crate) output_device_ptrs: SmallVec<[u64; 8]>,
    /// Per-output pinned host buffers. The captured DtoH memcpy writes into
    /// these stable addresses on every replay.
    pub(crate) output_host_bufs: SmallVec<[PinnedHostAllocation; 8]>,
    /// Exact byte lengths for each output. Pinned allocations are bucketed and
    /// can be larger than the logical output buffer.
    pub(crate) output_lens: SmallVec<[usize; 8]>,
    /// Expected input byte lengths. `dispatch_via_cuda_graph` validates
    /// the caller's input sizes match these — a mismatch means the graph
    /// is wrong-shape for the input and must be re-recorded.
    pub(crate) expected_input_lens: SmallVec<[usize; 8]>,
    /// Param-buffer device pointer (single allocation; freed in `drop`).
    /// The kernel reads launch parameters (workgroup-related constants)
    /// from this buffer.
    pub(crate) params_device_ptr: u64,
}

// SAFETY: `CachedCudaGraph` holds raw CUDA resource pointers (graph,
// graph_exec, stream, device pointers). All access goes through cudarc FFI
// calls that are documented thread-safe per the CUDA Driver API
// (`cuGraphLaunch`, `cuStreamSynchronize`, etc.). The pinned host buffers
// are mutated only through `&mut self`.
unsafe impl Send for CachedCudaGraph {}

impl Drop for CachedCudaGraph {
    fn drop(&mut self) {
        if let Err(error) = self.backend.warmup() {
            eprintln!(
                "Fix: CUDA backend warmup failed before graph resource drop: {error}. Cleanup will continue, but the CUDA context may be unhealthy."
            );
        }
        // SAFETY: every pointer was obtained via the corresponding cuda
        // create-call inside `CudaBackend::record_cuda_graph`. The order is
        // graph_exec → graph → stream → device buffers. Errors are logged
        // (best-effort) since drop cannot return them.
        unsafe {
            log_cuda_drop_result(
                "cuGraphExecDestroy",
                cudarc::driver::sys::cuGraphExecDestroy(self.graph_exec.as_ptr()),
            );
            log_cuda_drop_result(
                "cuGraphDestroy",
                cudarc::driver::sys::cuGraphDestroy(self.graph.as_ptr()),
            );
            log_cuda_drop_result(
                "cuStreamDestroy_v2",
                cudarc::driver::sys::cuStreamDestroy_v2(self.stream.as_ptr()),
            );
            for ptr in self
                .input_device_ptrs
                .iter()
                .chain(self.output_device_ptrs.iter())
            {
                if *ptr != 0 {
                    log_cuda_drop_result("cuMemFree_v2", cudarc::driver::sys::cuMemFree_v2(*ptr));
                }
            }
            if self.params_device_ptr != 0 {
                log_cuda_drop_result(
                    "cuMemFree_v2",
                    cudarc::driver::sys::cuMemFree_v2(self.params_device_ptr),
                );
            }
        }
        for allocation in self
            .input_host_bufs
            .drain(..)
            .chain(self.output_host_bufs.drain(..))
        {
            self.backend.host_pool.release(allocation);
        }
    }
}

impl CudaBackend {
    /// Record one full Program dispatch into a CUDA graph for fast replay.
    ///
    /// Allocates all device + host buffers, captures the dispatch sequence
    /// (HtoD memcpy → kernel launch → DtoH memcpy), and instantiates the
    /// captured graph. The returned `CachedCudaGraph` is a handle the
    /// caller drives via `dispatch_via_cuda_graph`.
    ///
    /// `sample_inputs` is used only to determine the input byte-layout
    /// shape captured into the graph; the caller passes the actual
    /// per-dispatch bytes via `dispatch_via_cuda_graph`. The bytes in
    /// `sample_inputs` are also copied into the cached host buffers as the
    /// initial state.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when device allocation fails, the kernel
    /// cannot be compiled or loaded, or the CUDA driver rejects any of the
    /// graph capture / instantiate operations.
    pub fn record_cuda_graph(
        &self,
        program: &Program,
        sample_inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<CachedCudaGraph, BackendError> {
        let sample_refs: SmallVec<[&[u8]; 8]> = sample_inputs.iter().map(Vec::as_slice).collect();
        self.record_cuda_graph_borrowed(program, &sample_refs, config)
    }

    /// Record one full Program dispatch into a CUDA graph using borrowed
    /// sample inputs.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when device allocation fails, the kernel
    /// cannot be compiled or loaded, or the CUDA driver rejects graph capture.
    pub fn record_cuda_graph_borrowed(
        &self,
        program: &Program,
        sample_inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<CachedCudaGraph, BackendError> {
        let _capture_serial = self.graph_capture_lock.lock().map_err(|_| {
            BackendError::DispatchFailed {
                code: None,
                message: "cuda graph capture lock poisoned. Fix: recreate CudaBackend after a panic during graph recording.".to_string(),
            }
        })?;
        self.warmup()?;

        // Compile + prepare. This lifts the program into PTX, computes the
        // binding plan, validates the program. All allocations / launches
        // below assume this succeeded.
        let prepared = self.prepare_host_dispatch(program, sample_inputs, config)?;
        let ptx_src = self.ptx_for_program_cached(program, config)?;
        let module_key = self.module_cache_key(&ptx_src);
        let func = self.module_for_ptx_with_key(&ptx_src, module_key)?;

        // Allocate all device buffers BEFORE capture. cuMemAlloc returns
        // CUDA_ERROR_STREAM_CAPTURE_UNSUPPORTED inside capture; allocating
        // up front is the only way to make capture work.
        let (input_capacity, output_capacity) = cuda_graph_binding_capacities(&prepared);
        let mut input_device_ptrs = SmallVec::<[DevicePtrGuard; 8]>::with_capacity(input_capacity);
        let mut output_device_ptrs =
            SmallVec::<[DevicePtrGuard; 8]>::with_capacity(output_capacity);
        let mut readback_device_ptrs = SmallVec::<[u64; 8]>::with_capacity(output_capacity);
        let mut host_buffers = GraphHostBuffers::with_capacity(
            Arc::clone(&self.host_pool),
            input_capacity,
            output_capacity,
        );
        let mut expected_input_lens = SmallVec::<[usize; 8]>::with_capacity(input_capacity);
        let mut output_lens = SmallVec::<[usize; 8]>::with_capacity(output_capacity);

        // Walk binding plan in order, allocating + classifying input vs output.
        for binding in &prepared.bindings.bindings {
            if binding.role == BindingRole::Shared {
                continue;
            }
            let byte_len = match binding.input_index {
                Some(input_index) => sample_inputs[input_index].len(),
                None => binding
                    .static_byte_len
                    .ok_or_else(|| BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: CUDA-graph output `{}` needs a static byte length to be \
                             cached. Set BufferDecl::with_count or output_byte_range before \
                             recording.",
                            binding.name
                        ),
                    })?,
            };
            let mut device_ptr: u64 = 0;
            // SAFETY: byte_len > 0 enforced by allocate-before-capture invariant.
            // cuMemAlloc returns ENOMEM if it can't satisfy; cuda_check converts.
            unsafe {
                cuda_check(
                    cudarc::driver::sys::cuMemAlloc_v2(&mut device_ptr, byte_len.max(1)),
                    "cuMemAlloc_v2 (cuda_graph input/output buffer)",
                )?;
            }
            if let Some(input_index) = binding.input_index {
                expected_input_lens.push(sample_inputs[input_index].len());
                host_buffers.push_input(sample_inputs[input_index])?;
                input_device_ptrs.push(DevicePtrGuard::new(device_ptr));
            } else {
                output_device_ptrs.push(DevicePtrGuard::new(device_ptr));
            }
            if binding.output_index.is_some() {
                let readback =
                    cuda_output_readback(&program.buffers()[binding.buffer_index], byte_len)?;
                host_buffers.push_output(readback.byte_len)?;
                output_lens.push(readback.byte_len);
                readback_device_ptrs.push(device_ptr.saturating_add(readback.device_offset as u64));
            }
        }

        // Allocate the param buffer separately (one per cached graph).
        let param_bytes = prepared.launch.param_words.len() * std::mem::size_of::<u32>();
        let mut params_device_ptr: u64 = 0;
        // SAFETY: param_bytes is u32-aligned and non-zero per launch plan invariants.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuMemAlloc_v2(&mut params_device_ptr, param_bytes.max(1)),
                "cuMemAlloc_v2 (cuda_graph param buffer)",
            )?;
        }
        let params_device_ptr = DevicePtrGuard::new(params_device_ptr);

        // Create dedicated stream for capture + replay.
        let mut stream_ptr: cudarc::driver::sys::CUstream = std::ptr::null_mut();
        // SAFETY: stream_ptr is a valid out-pointer; cuStreamCreate takes 0 flags.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuStreamCreate(&mut stream_ptr, 0),
                "cuStreamCreate (cuda_graph dedicated stream)",
            )?;
        }
        let stream = NonNull::new(stream_ptr).ok_or_else(|| BackendError::DispatchFailed {
            code: None,
            message: "cuStreamCreate returned a null stream after reporting success. Fix: update the CUDA driver or disable CUDA graph capture for this device.".to_string(),
        })?;
        let stream = StreamGuard::new(stream);
        unsafe {
            // Upload the param words once; the kernel reads them on every replay.
            // The async copy targets the dedicated stream so recording cannot
            // create an implicit dependency on CUDA's legacy default stream.
            cuda_check(
                cudarc::driver::sys::cuMemcpyHtoDAsync_v2(
                    params_device_ptr.ptr(),
                    prepared.launch.param_words.as_ptr().cast(),
                    param_bytes,
                    stream.ptr().as_ptr(),
                ),
                "cuMemcpyHtoDAsync_v2 (cuda_graph param init)",
            )?;
            cuda_check(
                cudarc::driver::sys::cuStreamSynchronize(stream.ptr().as_ptr()),
                "cuStreamSynchronize (cuda_graph param init)",
            )?;
        }

        // Begin capture. Every cuda call on `stream` from here until end
        // capture is recorded into the graph.
        // SAFETY: stream is freshly created; capture mode is the constant defined above.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuStreamBeginCapture_v2(
                    stream.ptr().as_ptr(),
                    std::mem::transmute::<u32, cudarc::driver::sys::CUstreamCaptureMode>(
                        CU_STREAM_CAPTURE_MODE_THREAD_LOCAL,
                    ),
                ),
                "cuStreamBeginCapture_v2",
            )?;
        }
        let mut capture_guard = CaptureGuard::armed(stream.ptr());

        // Record HtoD memcpys for each input.
        for ((host_buf, input_len), device_ptr) in host_buffers
            .input
            .iter()
            .zip(expected_input_lens.iter())
            .zip(input_device_ptrs.iter())
        {
            // SAFETY: host_buf.as_ptr() is stable for the lifetime of CachedCudaGraph
            // (the Vec is owned by CachedCudaGraph and never reallocated — capacity is
            // set at construction). device_ptr was allocated above. Both pointers
            // outlive the captured graph.
            unsafe {
                cuda_check(
                    cudarc::driver::sys::cuMemcpyHtoDAsync_v2(
                        device_ptr.ptr(),
                        host_buf.as_ptr(),
                        *input_len,
                        stream.ptr().as_ptr(),
                    ),
                    "cuMemcpyHtoDAsync_v2 (capture input)",
                )?;
            }
        }

        // Record kernel launch. Build kernel_args mirroring the production
        // launch_module path: per-buffer u64 ptr-of-ptr, then param ptr.
        let mut all_ptrs = SmallVec::<[u64; 16]>::with_capacity(
            input_device_ptrs
                .len()
                .saturating_add(output_device_ptrs.len()),
        );
        let mut input_iter = input_device_ptrs.iter();
        let mut output_iter = output_device_ptrs.iter();
        for binding in &prepared.bindings.bindings {
            if binding.role == BindingRole::Shared {
                continue;
            }
            let ptr = if binding.input_index.is_some() {
                input_iter
                    .next()
                    .ok_or_else(|| BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: CUDA graph capture binding plan expected an input pointer for `{}` but none was allocated.",
                            binding.name
                        ),
                    })?
                    .ptr()
            } else {
                output_iter
                    .next()
                    .ok_or_else(|| BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: CUDA graph capture binding plan expected an output pointer for `{}` but none was allocated.",
                            binding.name
                        ),
                    })?
                    .ptr()
            };
            all_ptrs.push(ptr);
        }
        let mut kernel_args: SmallVec<[*mut std::ffi::c_void; 16]> =
            SmallVec::with_capacity(all_ptrs.len() + 1);
        for ptr in &mut all_ptrs {
            if *ptr == 0 {
                return Err(BackendError::InvalidProgram {
                    fix: "Fix: CUDA graph capture resolved a null kernel argument; graph launch arguments must preserve the lowered descriptor order."
                        .to_string(),
                });
            }
            kernel_args.push(ptr as *mut _ as *mut std::ffi::c_void);
        }
        let mut params_ref = params_device_ptr.ptr();
        kernel_args.push(&mut params_ref as *mut _ as *mut std::ffi::c_void);

        for _ in 0..prepared.fixpoint_iterations {
            // SAFETY: launch geometry validated by prepare. kernel_args pointers
            // are stable until the cuLaunchKernel call returns; capture records
            // by value.
            unsafe {
                cuda_check(
                    cudarc::driver::sys::cuLaunchKernel(
                        func,
                        prepared.launch.grid[0],
                        prepared.launch.grid[1],
                        prepared.launch.grid[2],
                        prepared.launch.workgroup[0],
                        prepared.launch.workgroup[1],
                        prepared.launch.workgroup[2],
                        0,
                        stream.ptr().as_ptr(),
                        kernel_args.as_mut_ptr(),
                        std::ptr::null_mut(),
                    ),
                    "cuLaunchKernel (capture)",
                )?;
            }
        }

        // Record DtoH memcpys for each output.
        for ((host_buf, output_len), device_ptr) in host_buffers
            .output
            .iter_mut()
            .zip(output_lens.iter())
            .zip(readback_device_ptrs.iter())
        {
            if *output_len == 0 {
                continue;
            }
            // SAFETY: same as input memcpy — pointers stable for graph lifetime.
            unsafe {
                cuda_check(
                    cudarc::driver::sys::cuMemcpyDtoHAsync_v2(
                        host_buf.as_mut_ptr(),
                        *device_ptr,
                        *output_len,
                        stream.ptr().as_ptr(),
                    ),
                    "cuMemcpyDtoHAsync_v2 (capture output)",
                )?;
            }
        }

        // End capture and instantiate.
        let mut graph_ptr: cudarc::driver::sys::CUgraph = std::ptr::null_mut();
        // SAFETY: stream is in capture mode (we started it above).
        let end_capture_status = unsafe {
            cudarc::driver::sys::cuStreamEndCapture(stream.ptr().as_ptr(), &mut graph_ptr)
        };
        capture_guard.disarm();
        if end_capture_status != cudarc::driver::sys::CUresult::CUDA_SUCCESS && !graph_ptr.is_null()
        {
            unsafe {
                log_cuda_drop_result(
                    "cuGraphDestroy",
                    cudarc::driver::sys::cuGraphDestroy(graph_ptr),
                );
            }
        }
        cuda_check(end_capture_status, "cuStreamEndCapture")?;
        let graph = NonNull::new(graph_ptr).ok_or_else(|| BackendError::DispatchFailed {
            code: None,
            message: "cuStreamEndCapture returned a null graph after reporting success. Fix: update the CUDA driver or disable CUDA graph capture for this device.".to_string(),
        })?;
        let graph = GraphGuard::new(graph);

        let mut graph_exec_ptr: cudarc::driver::sys::CUgraphExec = std::ptr::null_mut();
        // SAFETY: graph is the freshly captured graph; flags = 0 selects default execution.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuGraphInstantiateWithFlags(
                    &mut graph_exec_ptr,
                    graph.ptr().as_ptr(),
                    0,
                ),
                "cuGraphInstantiateWithFlags",
            )?;
        }
        let graph_exec = NonNull::new(graph_exec_ptr).ok_or_else(|| {
            BackendError::DispatchFailed {
                code: None,
                message: "cuGraphInstantiateWithFlags returned a null executable graph after reporting success. Fix: update the CUDA driver or disable CUDA graph capture for this device.".to_string(),
            }
        })?;
        let graph_exec = GraphExecGuard::new(graph_exec);

        let input_device_ptrs: SmallVec<[u64; 8]> = input_device_ptrs
            .into_iter()
            .map(DevicePtrGuard::into_raw)
            .collect();
        let output_device_ptrs: SmallVec<[u64; 8]> = output_device_ptrs
            .into_iter()
            .map(DevicePtrGuard::into_raw)
            .collect();
        let (input_host_bufs, output_host_bufs) = host_buffers.into_raw();

        Ok(CachedCudaGraph {
            backend: self.clone(),
            graph: graph.into_raw(),
            graph_exec: graph_exec.into_raw(),
            stream: stream.into_raw(),
            input_host_bufs,
            input_device_ptrs,
            output_device_ptrs,
            output_host_bufs,
            output_lens,
            expected_input_lens,
            params_device_ptr: params_device_ptr.into_raw(),
        })
    }
}
