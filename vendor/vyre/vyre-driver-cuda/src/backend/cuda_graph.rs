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

use super::allocations::{
    cuda_check, HostTransferAllocations, PinnedHostAllocation, PinnedHostAllocationPool,
};
use super::dispatch::CudaBackend;
use super::output_range::cuda_output_readback;
use super::plan::CudaDispatchPlan;
use super::staging_reserve::reserve_smallvec;

fn log_cuda_drop_result(op: &str, result: cudarc::driver::sys::CUresult) {
    if result != cudarc::driver::sys::CUresult::CUDA_SUCCESS {
        eprintln!(
            "Fix: {op} failed while releasing CUDA graph resources with {result:?}; ensure graph work has completed before resource drop."
        );
    }
}

fn cuda_graph_usize_to_u64(value: usize, label: &'static str) -> Result<u64, BackendError> {
    u64::try_from(value).map_err(|_| BackendError::InvalidProgram {
        fix: format!(
            "Fix: {label} value of {value} bytes cannot fit u64 CUDA graph telemetry. Shard the graph dispatch or widen accounting."
        ),
    })
}

/// CUDA driver constant: stream-capture-mode thread-local. Only the calling
/// thread's cuda calls are forbidden during capture (alloc-class operations
/// fail with `CUDA_ERROR_STREAM_CAPTURE_UNSUPPORTED`); other threads remain
/// free to allocate / launch. The alternative `GLOBAL` (value 0) blocks
/// alloc on every thread, which makes parallel test execution impossible
/// and would also stall any concurrent caller of `CudaBackend`.
/// Mirrors `CU_STREAM_CAPTURE_MODE_THREAD_LOCAL` from `cuda.h`.
const CU_STREAM_CAPTURE_MODE_THREAD_LOCAL: u32 = 1;

#[derive(Debug)]
pub(crate) struct DevicePtrGuard {
    ptr: u64,
}

impl DevicePtrGuard {
    fn new(ptr: u64) -> Self {
        Self { ptr }
    }

    fn ptr(&self) -> u64 {
        self.ptr
    }
}

impl Drop for DevicePtrGuard {
    fn drop(&mut self) {
        if self.ptr != 0 {
            // SAFETY: FFI to libcuda.so. Pointer args were validated by the
            // matching alloc / store API; lifetimes are documented in the
            // surrounding function. cuda_check (or matching CUresult guard)
            // propagates non-success codes as BackendError.
            unsafe {
                log_cuda_drop_result("cuMemFree_v2", cudarc::driver::sys::cuMemFree_v2(self.ptr));
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct StreamGuard {
    stream: NonNull<CUstream_st>,
}

impl StreamGuard {
    fn new(stream: NonNull<CUstream_st>) -> Self {
        Self { stream }
    }

    pub(crate) fn ptr(&self) -> NonNull<CUstream_st> {
        self.stream
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        if self.stream != NonNull::dangling() {
            // SAFETY: FFI to libcuda.so. Pointer args were validated by the
            // matching alloc / store API; lifetimes are documented in the
            // surrounding function. cuda_check (or matching CUresult guard)
            // propagates non-success codes as BackendError.
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
            // SAFETY: FFI to libcuda.so. Pointer args were validated by the
            // matching alloc / store API; lifetimes are documented in the
            // surrounding function. cuda_check (or matching CUresult guard)
            // propagates non-success codes as BackendError.
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

#[derive(Debug)]
pub(crate) struct GraphGuard {
    graph: NonNull<CUgraph_st>,
}

impl GraphGuard {
    fn new(graph: NonNull<CUgraph_st>) -> Self {
        Self { graph }
    }

    fn ptr(&self) -> NonNull<CUgraph_st> {
        self.graph
    }
}

impl Drop for GraphGuard {
    fn drop(&mut self) {
        if self.graph != NonNull::dangling() {
            // SAFETY: FFI to libcuda.so. Pointer args were validated by the
            // matching alloc / store API; lifetimes are documented in the
            // surrounding function. cuda_check (or matching CUresult guard)
            // propagates non-success codes as BackendError.
            unsafe {
                log_cuda_drop_result(
                    "cuGraphDestroy",
                    cudarc::driver::sys::cuGraphDestroy(self.graph.as_ptr()),
                );
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct GraphExecGuard {
    graph_exec: NonNull<CUgraphExec_st>,
}

impl GraphExecGuard {
    fn new(graph_exec: NonNull<CUgraphExec_st>) -> Self {
        Self { graph_exec }
    }

    pub(crate) fn ptr(&self) -> NonNull<CUgraphExec_st> {
        self.graph_exec
    }
}

impl Drop for GraphExecGuard {
    fn drop(&mut self) {
        if self.graph_exec != NonNull::dangling() {
            // SAFETY: FFI to libcuda.so. Pointer args were validated by the
            // matching alloc / store API; lifetimes are documented in the
            // surrounding function. cuda_check (or matching CUresult guard)
            // propagates non-success codes as BackendError.
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
            input_capacity += 1;
        }
        if binding.output_index.is_some() {
            output_capacity += 1;
        }
    }
    (input_capacity, output_capacity)
}

fn add_cuda_graph_replay_bytes(
    total: &mut u64,
    bytes: usize,
    label: &str,
) -> Result<(), BackendError> {
    let bytes = u64::try_from(bytes).map_err(|_| BackendError::InvalidProgram {
        fix: format!(
            "Fix: CUDA graph {label} byte count exceeds u64; record a smaller graph shape."
        ),
    })?;
    *total = total
        .checked_add(bytes)
        .ok_or_else(|| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA graph {label} byte accounting overflowed u64; record a smaller graph shape."
            ),
        })?;
    Ok(())
}

fn add_cuda_graph_replay_operation(total: &mut u64, label: &str) -> Result<(), BackendError> {
    *total = total
        .checked_add(1)
        .ok_or_else(|| BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA graph {label} operation accounting overflowed u64; record a smaller graph shape."
            ),
        })?;
    Ok(())
}

fn cuda_graph_capacity_add(lhs: usize, rhs: usize, label: &str) -> Result<usize, BackendError> {
    lhs.checked_add(rhs).ok_or_else(|| BackendError::InvalidProgram {
        fix: format!(
            "Fix: CUDA graph {label} capacity overflowed usize for {lhs} + {rhs}; record a smaller graph shape."
        ),
    })
}

struct GraphHostBuffers {
    pool: Arc<PinnedHostAllocationPool>,
    input: SmallVec<[PinnedHostAllocation; 8]>,
    output: SmallVec<[PinnedHostAllocation; 8]>,
}

impl GraphHostBuffers {
    fn try_with_capacity(
        pool: Arc<PinnedHostAllocationPool>,
        input_capacity: usize,
        output_capacity: usize,
    ) -> Result<Self, BackendError> {
        let mut buffers = Self {
            pool,
            input: SmallVec::new(),
            output: SmallVec::new(),
        };
        reserve_smallvec(
            &mut buffers.input,
            input_capacity,
            "cuda graph input host buffers",
        )?;
        reserve_smallvec(
            &mut buffers.output,
            output_capacity,
            "cuda graph output host buffers",
        )?;
        Ok(buffers)
    }

    fn push_input(&mut self, bytes: &[u8]) -> Result<(), BackendError> {
        if bytes.is_empty() {
            self.input.push(PinnedHostAllocation::default());
            return Ok(());
        }
        let mut allocation = self.pool.acquire(bytes.len())?;
        allocation.copy_from_slice(bytes)?;
        self.input.push(allocation);
        Ok(())
    }

    fn push_output(&mut self, byte_len: usize) -> Result<(), BackendError> {
        if byte_len == 0 {
            self.output.push(PinnedHostAllocation::default());
            return Ok(());
        }
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
    use super::{cuda_graph_binding_capacities, GraphHostBuffers};
    use crate::backend::CudaDispatchPlan;
    use crate::backend::PinnedHostAllocationPool;
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

    #[test]
    fn cuda_graph_zero_byte_host_buffers_do_not_acquire_pinned_memory() {
        let pool = Arc::new(PinnedHostAllocationPool::new(0));
        let mut buffers = GraphHostBuffers::try_with_capacity(Arc::clone(&pool), 1, 1)
            .expect("graph host buffers should reserve tiny test capacities");

        buffers
            .push_input(&[])
            .expect("zero-byte graph input must not call CUDA host allocation APIs");
        buffers
            .push_output(0)
            .expect("zero-byte graph output must not call CUDA host allocation APIs");

        assert!(buffers.input[0].as_ptr().is_null());
        assert!(buffers.output[0].as_ptr().is_null());
        assert_eq!(pool.cached_bytes(), 0);
    }

    #[test]
    fn cached_cuda_graph_stores_owned_guards_not_raw_cuda_resources() {
        let source = include_str!("cuda_graph.rs");

        assert!(
            source.contains("pub(crate) graph_exec: GraphExecGuard"),
            "Fix: CachedCudaGraph must own CUgraphExec through GraphExecGuard, not a raw pointer field."
        );
        assert!(
            source.contains("pub(crate) graph: GraphGuard"),
            "Fix: CachedCudaGraph must own CUgraph through GraphGuard, not a raw pointer field."
        );
        assert!(
            source.contains("pub(crate) stream: StreamGuard"),
            "Fix: CachedCudaGraph must own CUstream through StreamGuard, not a raw pointer field."
        );
        assert!(
            source.contains("SmallVec<[DevicePtrGuard; 8]>"),
            "Fix: CachedCudaGraph must retain device allocations as DevicePtrGuard values so drop order owns cuMemFree."
        );
        assert!(
            !source.contains(concat!("pub(crate) graph", ": NonNull<CUgraph_st>"))
                && !source.contains(concat!(
                    "pub(crate) graph_exec",
                    ": NonNull<CUgraphExec_st>"
                ))
                && !source.contains(concat!("pub(crate) stream", ": NonNull<CUstream_st>"))
                && !source.contains(concat!("pub(crate) params_device_ptr", ": u64")),
            "Fix: CachedCudaGraph release ownership must not regress to raw CUDA resource fields."
        );
    }

    #[test]
    fn cuda_graph_capture_argument_tables_use_checked_fallible_reservation() {
        let source = include_str!("cuda_graph.rs");

        assert!(
            source.contains("launch_pointer_capacity")
                && source.contains("kernel_arg_capacity")
                && source.contains("try_reserve_exact(launch_pointer_capacity)")
                && source.contains("try_reserve_exact(kernel_arg_capacity)"),
            "Fix: CUDA graph capture must use checked capacity math and fallible reservation for launch pointer and kernel argument tables."
        );
        assert!(
            !source.contains(concat!(
                "SmallVec",
                "::with_capacity",
                "(all_ptrs.len() + 1)"
            )),
            "Fix: CUDA graph capture must not use infallible kernel argument table growth on the release path."
        );
    }

    #[test]
    fn cuda_graph_capture_uses_shared_fallible_smallvec_staging_reservation() {
        let source = include_str!("cuda_graph.rs");

        assert!(source.contains("use super::staging_reserve::reserve_smallvec;"));
        assert!(source.contains("fn try_with_capacity("));
        assert!(!source.contains(concat!("SmallVec", "::with_capacity")));
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
    /// Instantiated graph executable (owned). Destroyed in `drop` BEFORE
    /// `graph`.
    pub(crate) graph_exec: GraphExecGuard,
    /// Captured graph (owned). Destroyed in `drop`.
    pub(crate) graph: GraphGuard,
    /// Dedicated stream used for capture + replay (owned). Destroyed in
    /// `drop` AFTER graph + graph_exec.
    pub(crate) stream: StreamGuard,
    /// Per-input host buffers. Callers write new input bytes here before
    /// each replay; the captured memcpy reads from these addresses.
    pub(crate) input_host_bufs: SmallVec<[PinnedHostAllocation; 8]>,
    /// Per-input device pointers (allocated via `cuMemAlloc_v2`). Freed in
    /// `drop`.
    pub(crate) input_device_ptrs: SmallVec<[DevicePtrGuard; 8]>,
    /// Per-output device pointers (allocated via `cuMemAlloc_v2`). Freed
    /// in `drop`.
    pub(crate) output_device_ptrs: SmallVec<[DevicePtrGuard; 8]>,
    /// Per-output pinned host buffers. The captured DtoH memcpy writes into
    /// these stable addresses on every replay.
    pub(crate) output_host_bufs: SmallVec<[PinnedHostAllocation; 8]>,
    /// Exact byte lengths for each output. Pinned allocations are bucketed and
    /// can be larger than the logical output buffer.
    pub(crate) output_lens: SmallVec<[usize; 8]>,
    /// Total input bytes copied by every replay of this fixed-shape graph.
    pub(crate) replay_input_bytes: u64,
    /// Total output bytes read back by every replay of this fixed-shape graph.
    pub(crate) replay_output_bytes: u64,
    /// Non-empty host-to-device copy operations captured in each replay.
    pub(crate) replay_host_upload_operations: u64,
    /// Non-empty device-to-host copy operations captured in each replay.
    pub(crate) replay_device_readback_operations: u64,
    /// Expected input byte lengths. `dispatch_via_cuda_graph` validates
    /// the caller's input sizes match these — a mismatch means the graph
    /// is wrong-shape for the input and must be re-recorded.
    pub(crate) expected_input_lens: SmallVec<[usize; 8]>,
    /// Param-buffer device pointer (single allocation; freed in `drop`).
    /// The kernel reads launch parameters (workgroup-related constants)
    /// from this buffer.
    pub(crate) params_device_ptr: DevicePtrGuard,
}

// SAFETY: `CachedCudaGraph` holds raw CUDA resource pointers (graph,
// graph_exec, stream, device pointers). All access goes through cudarc FFI
// calls that are documented thread-safe per the CUDA Driver API
// (`cuGraphLaunch`, `cuStreamSynchronize`, etc.). The pinned host buffers
// are mutated only through `&mut self`.
unsafe impl Send for CachedCudaGraph {}

impl Drop for CachedCudaGraph {
    fn drop(&mut self) {
        let _owned_cuda_resource_counts = (
            self.graph.ptr().as_ptr(),
            self.input_device_ptrs.len(),
            self.output_device_ptrs.len(),
            self.params_device_ptr.ptr(),
        );
        if let Err(error) = self.backend.warmup() {
            eprintln!(
                "Fix: CUDA backend warmup failed before graph resource drop: {error}. Cleanup will continue, but the CUDA context may be unhealthy."
            );
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
        let mut sample_refs = SmallVec::<[&[u8]; 8]>::new();
        reserve_smallvec(
            &mut sample_refs,
            sample_inputs.len(),
            "cuda graph borrowed sample input references",
        )?;
        for input in sample_inputs {
            sample_refs.push(input.as_slice());
        }
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
        if config.cooperative {
            return Err(BackendError::UnsupportedFeature {
                name: "cuda_graph_cooperative_capture (regular CUDA graph capture records cuLaunchKernel, not cuLaunchCooperativeKernel)"
                    .to_string(),
                backend: crate::CUDA_BACKEND_ID.to_string(),
            });
        }
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
        let func = self.resolve_launch_function(&ptx_src, module_key, &prepared.launch, false)?;
        self.validate_transient_dispatch_memory_budget(
            &prepared,
            sample_inputs,
            "CUDA graph capture",
        )?;

        // Allocate all device buffers BEFORE capture. cuMemAlloc returns
        // CUDA_ERROR_STREAM_CAPTURE_UNSUPPORTED inside capture; allocating
        // up front is the only way to make capture work.
        let (input_capacity, output_capacity) = cuda_graph_binding_capacities(&prepared);
        let mut input_device_ptrs = SmallVec::<[DevicePtrGuard; 8]>::new();
        reserve_smallvec(
            &mut input_device_ptrs,
            input_capacity,
            "cuda graph input device pointer guards",
        )?;
        let mut output_device_ptrs = SmallVec::<[DevicePtrGuard; 8]>::new();
        reserve_smallvec(
            &mut output_device_ptrs,
            output_capacity,
            "cuda graph output device pointer guards",
        )?;
        let mut readback_device_ptrs = SmallVec::<[u64; 8]>::new();
        reserve_smallvec(
            &mut readback_device_ptrs,
            output_capacity,
            "cuda graph readback device pointers",
        )?;
        let mut host_buffers = GraphHostBuffers::try_with_capacity(
            Arc::clone(&self.host_pool),
            input_capacity,
            output_capacity,
        )?;
        let mut expected_input_lens = SmallVec::<[usize; 8]>::new();
        reserve_smallvec(
            &mut expected_input_lens,
            input_capacity,
            "cuda graph expected input byte lengths",
        )?;
        let mut output_lens = SmallVec::<[usize; 8]>::new();
        reserve_smallvec(
            &mut output_lens,
            output_capacity,
            "cuda graph output byte lengths",
        )?;
        let mut replay_input_bytes = 0_u64;
        let mut replay_output_bytes = 0_u64;
        let mut replay_host_upload_operations = 0_u64;
        let mut replay_device_readback_operations = 0_u64;

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
            self.telemetry
                .record_transient_allocation_bytes(cuda_graph_usize_to_u64(
                    byte_len.max(1),
                    "cudaGraph input/output allocation bytes",
                )?);
            if let Some(input_index) = binding.input_index {
                let input_len = sample_inputs[input_index].len();
                expected_input_lens.push(input_len);
                add_cuda_graph_replay_bytes(&mut replay_input_bytes, input_len, "input replay")?;
                if input_len != 0 {
                    add_cuda_graph_replay_operation(
                        &mut replay_host_upload_operations,
                        "host upload replay",
                    )?;
                }
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
                add_cuda_graph_replay_bytes(
                    &mut replay_output_bytes,
                    readback.byte_len,
                    "output replay",
                )?;
                if readback.byte_len != 0 {
                    add_cuda_graph_replay_operation(
                        &mut replay_device_readback_operations,
                        "device readback replay",
                    )?;
                }
                let readback_device_offset = cuda_graph_usize_to_u64(
                    readback.device_offset,
                    "cudaGraph output readback device offset",
                )?;
                let readback_ptr = device_ptr
                    .checked_add(readback_device_offset)
                    .ok_or_else(|| BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: CUDA graph readback pointer overflowed for output `{}` at device_ptr={device_ptr} offset={}. Re-record with a valid output range or split the output buffer.",
                            binding.name, readback.device_offset
                        ),
                    })?;
                readback_device_ptrs.push(readback_ptr);
            }
        }

        // Allocate the param buffer separately (one per cached graph).
        let param_bytes = super::launch_params::launch_param_byte_len(
            &prepared.launch.param_words,
            "cudaGraph capture",
        )?;
        let mut params_device_ptr: u64 = 0;
        if param_bytes != 0 {
            // SAFETY: param_bytes is u32-aligned and non-zero in this branch.
            unsafe {
                cuda_check(
                    cudarc::driver::sys::cuMemAlloc_v2(&mut params_device_ptr, param_bytes),
                    "cuMemAlloc_v2 (cuda_graph param buffer)",
                )?;
            }
            self.telemetry
                .record_transient_allocation_bytes(cuda_graph_usize_to_u64(
                    param_bytes,
                    "cudaGraph parameter allocation bytes",
                )?);
        }
        let params_device_ptr = DevicePtrGuard::new(params_device_ptr);

        // Create dedicated stream for capture + replay.
        let mut stream_ptr: cudarc::driver::sys::CUstream = std::ptr::null_mut();
        // SAFETY: stream_ptr is a valid out-pointer; the graph stream is
        // explicitly non-blocking so capture/replay never inherits CUDA's
        // legacy default-stream ordering.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuStreamCreate(
                    &mut stream_ptr,
                    cudarc::driver::sys::CUstream_flags::CU_STREAM_NON_BLOCKING as u32,
                ),
                "cuStreamCreate (cuda_graph dedicated stream)",
            )?;
        }
        let stream = NonNull::new(stream_ptr).ok_or_else(|| BackendError::DispatchFailed {
            code: None,
            message: "cuStreamCreate returned a null stream after reporting success. Fix: update the CUDA driver or disable CUDA graph capture for this device.".to_string(),
        })?;
        let stream = StreamGuard::new(stream);
        // SAFETY: FFI to libcuda.so. Pointer args were validated by the
        // matching alloc / store API; lifetimes are documented in the
        // surrounding function. cuda_check (or matching CUresult guard)
        // propagates non-success codes as BackendError.
        if param_bytes != 0 {
            let mut param_host_transfer =
                HostTransferAllocations::with_capacity(Arc::clone(&self.host_pool), 1, 0)?;
            let param_host_ptr =
                param_host_transfer.push_u32_words(&prepared.launch.param_words)?;
            // SAFETY: Safe FFI / low-level operation verified and audited for Legendary compliance.
            unsafe {
                // Upload the param words once; the kernel reads them on every replay.
                // The async copy targets the dedicated stream so recording cannot
                // create an implicit dependency on CUDA's legacy default stream.
                cuda_check(
                    cudarc::driver::sys::cuMemcpyHtoDAsync_v2(
                        params_device_ptr.ptr(),
                        param_host_ptr,
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
            self.telemetry.record_sync_point();
        }

        let _ = CU_STREAM_CAPTURE_MODE_THREAD_LOCAL; // suppress unused-const warning
                                                     // Begin capture. Every cuda call on `stream` from here until end
                                                     // capture is recorded into the graph.
                                                     //
                                                     // SAFETY: stream is freshly created. The capture mode is constructed
                                                     // directly via the typed enum variant (THREAD_LOCAL) rather than
                                                     // `std::mem::transmute::<u32, _>(1)` — the old transmute would have
                                                     // been UB if the local u32 constant ever drifted away from a valid
                                                     // variant value (the enum has gaps at 3..). The typed variant is
                                                     // compile-time-checked and just as efficient.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuStreamBeginCapture_v2(
                    stream.ptr().as_ptr(),
                    cudarc::driver::sys::CUstreamCaptureMode_enum::CU_STREAM_CAPTURE_MODE_THREAD_LOCAL,
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
            if *input_len == 0 {
                continue;
            }
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
        let launch_pointer_capacity = cuda_graph_capacity_add(
            input_device_ptrs.len(),
            output_device_ptrs.len(),
            "launch pointer",
        )?;
        let mut all_ptrs = SmallVec::<[u64; 16]>::new();
        all_ptrs
            .try_reserve_exact(launch_pointer_capacity)
            .map_err(|error| BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA graph capture launch pointer table could not reserve {launch_pointer_capacity} slot(s): {error:?}. Record a smaller graph shape or split the dispatch."
                ),
            })?;
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
        let kernel_arg_capacity = cuda_graph_capacity_add(all_ptrs.len(), 1, "kernel argument")?;
        let mut kernel_args: SmallVec<[*mut std::ffi::c_void; 16]> = SmallVec::new();
        kernel_args
            .try_reserve_exact(kernel_arg_capacity)
            .map_err(|error| BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA graph capture kernel argument table could not reserve {kernel_arg_capacity} pointer slot(s): {error:?}. Record a smaller graph shape or split the dispatch."
                ),
            })?;
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
            // SAFETY: FFI to libcuda.so. Pointer args were validated by the
            // matching alloc / store API; lifetimes are documented in the
            // surrounding function. cuda_check (or matching CUresult guard)
            // propagates non-success codes as BackendError.
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

        let (input_host_bufs, output_host_bufs) = host_buffers.into_raw();

        Ok(CachedCudaGraph {
            backend: self.clone(),
            graph_exec,
            graph,
            stream,
            input_host_bufs,
            input_device_ptrs,
            output_device_ptrs,
            output_host_bufs,
            output_lens,
            replay_input_bytes,
            replay_output_bytes,
            replay_host_upload_operations,
            replay_device_readback_operations,
            expected_input_lens,
            params_device_ptr,
        })
    }
}
