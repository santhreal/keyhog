use super::*;
use crate::megakernel::readback::MegakernelReadback;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use vyre_driver::backend::OutputBuffers;
use vyre_foundation::ir::{Ident, Node};
use vyre_foundation::memory_model::MemoryOrdering;

#[derive(Default)]
struct GridSyncBackend {
    segment_lengths: Mutex<Vec<usize>>,
}

impl vyre_driver::backend::private::Sealed for GridSyncBackend {}

impl VyreBackend for GridSyncBackend {
    fn id(&self) -> &'static str {
        "grid-sync-recording"
    }

    fn dispatch(
        &self,
        _program: &Program,
        inputs: &[Vec<u8>],
        _config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, vyre_driver::BackendError> {
        Ok(inputs.to_vec())
    }

    fn dispatch_borrowed(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        _config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, vyre_driver::BackendError> {
        let entry = program.entry();
        let segment_len = match entry {
            [Node::Region { body, .. }] => body.len(),
            other => other.len(),
        };
        self.segment_lengths
            .lock()
            .expect("Fix: grid-sync recording mutex must not be poisoned")
            .push(segment_len);
        Ok(inputs.iter().map(|input| input.to_vec()).collect())
    }
}

#[derive(Default)]
struct PersistentHandleBackend {
    calls: Arc<Mutex<Vec<[u64; 4]>>>,
    row_batch_calls: Arc<AtomicUsize>,
}

impl vyre_driver::backend::private::Sealed for PersistentHandleBackend {}

impl VyreBackend for PersistentHandleBackend {
    fn id(&self) -> &'static str {
        "persistent-handle-recording"
    }

    fn dispatch(
        &self,
        _program: &Program,
        _inputs: &[Vec<u8>],
        _config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, vyre_driver::BackendError> {
        Err(vyre_driver::BackendError::new(
                "host-byte dispatch should not run. Fix: route resident handles through dispatch_persistent_handles.",
            ))
    }

    fn compile_native(
        &self,
        _program: &Program,
        _config: &DispatchConfig,
    ) -> Result<Option<Arc<dyn CompiledPipeline>>, vyre_driver::BackendError> {
        Ok(Some(Arc::new(PersistentHandlePipeline {
            calls: Arc::clone(&self.calls),
            row_batch_calls: Arc::clone(&self.row_batch_calls),
        })))
    }
}

struct PersistentHandlePipeline {
    calls: Arc<Mutex<Vec<[u64; 4]>>>,
    row_batch_calls: Arc<AtomicUsize>,
}

impl vyre_driver::backend::private::Sealed for PersistentHandlePipeline {}

impl CompiledPipeline for PersistentHandlePipeline {
    fn id(&self) -> &str {
        "persistent-handle-recording:pipeline"
    }

    fn dispatch(
        &self,
        _inputs: &[Vec<u8>],
        _config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, vyre_driver::BackendError> {
        Err(vyre_driver::BackendError::new(
            "host-byte compiled dispatch should not run. Fix: use persistent handles.",
        ))
    }

    fn dispatch_persistent_handles(
        &self,
        inputs: &[Resource],
        _config: &DispatchConfig,
    ) -> Result<OutputBuffers, vyre_driver::BackendError> {
        let handles: Vec<u64> = inputs
            .iter()
            .map(|resource| match resource {
                Resource::Resident(handle) => *handle,
                Resource::Borrowed(_) => 0,
            })
            .collect();
        let handles: [u64; 4] = handles.try_into().map_err(|_| {
                vyre_driver::BackendError::new(
                    "persistent handle ABI requires exactly four resources. Fix: pass control, ring, debug_log, and io_queue handles.",
                )
            })?;
        self.calls
            .lock()
            .expect("Fix: persistent-handle recording mutex must not be poisoned")
            .push(handles);
        Ok(vec![vec![1, 2, 3, 4]])
    }

    fn dispatch_persistent_handles_into(
        &self,
        inputs: &[Resource],
        _config: &DispatchConfig,
        outputs: &mut OutputBuffers,
    ) -> Result<(), vyre_driver::BackendError> {
        let handles: Vec<u64> = inputs
            .iter()
            .map(|resource| match resource {
                Resource::Resident(handle) => *handle,
                Resource::Borrowed(_) => 0,
            })
            .collect();
        let handles: [u64; 4] = handles.try_into().map_err(|_| {
            vyre_driver::BackendError::new(
                "persistent handle ABI requires exactly four resources. Fix: pass control, ring, debug_log, and io_queue handles.",
            )
        })?;
        self.calls
            .lock()
            .expect("Fix: persistent-handle recording mutex must not be poisoned")
            .push(handles);
        if outputs.is_empty() {
            outputs.push(Vec::new());
        } else {
            outputs.truncate(1);
        }
        outputs[0].clear();
        outputs[0].extend_from_slice(&[1, 2, 3, 4]);
        Ok(())
    }

    fn dispatch_persistent_handles_batched(
        &self,
        batches: &[&[Resource]],
        _config: &DispatchConfig,
    ) -> Result<Vec<OutputBuffers>, vyre_driver::BackendError> {
        let mut outputs = Vec::with_capacity(batches.len());
        for (index, inputs) in batches.iter().enumerate() {
            let handles: Vec<u64> = inputs
                .iter()
                .map(|resource| match resource {
                    Resource::Resident(handle) => *handle,
                    Resource::Borrowed(_) => 0,
                })
                .collect();
            let handles: [u64; 4] = handles.try_into().map_err(|_| {
                    vyre_driver::BackendError::new(
                        "batched persistent handle ABI requires exactly four resources. Fix: pass control, ring, debug_log, and io_queue handles.",
                    )
                })?;
            self.calls
                .lock()
                .expect("Fix: persistent-handle recording mutex must not be poisoned")
                .push(handles);
            outputs.push(vec![vec![u8::try_from(index).unwrap_or(u8::MAX)]]);
        }
        Ok(outputs)
    }

    fn dispatch_persistent_handles_batched_into(
        &self,
        batches: &[&[Resource]],
        _config: &DispatchConfig,
        outputs: &mut Vec<OutputBuffers>,
    ) -> Result<(), vyre_driver::BackendError> {
        if outputs.len() < batches.len() {
            outputs.resize_with(batches.len(), Vec::new);
        } else {
            outputs.truncate(batches.len());
        }
        for (index, (inputs, row)) in batches.iter().zip(outputs.iter_mut()).enumerate() {
            let handles: Vec<u64> = inputs
                .iter()
                .map(|resource| match resource {
                    Resource::Resident(handle) => *handle,
                    Resource::Borrowed(_) => 0,
                })
                .collect();
            let handles: [u64; 4] = handles.try_into().map_err(|_| {
                vyre_driver::BackendError::new(
                    "batched persistent handle ABI requires exactly four resources. Fix: pass control, ring, debug_log, and io_queue handles.",
                )
            })?;
            self.calls
                .lock()
                .expect("Fix: persistent-handle recording mutex must not be poisoned")
                .push(handles);
            if row.is_empty() {
                row.push(Vec::new());
            } else {
                row.truncate(1);
            }
            row[0].clear();
            row[0].push(u8::try_from(index).unwrap_or(u8::MAX));
        }
        Ok(())
    }

    fn dispatch_persistent_handle_rows_into(
        &self,
        rows: &[[Resource; 4]],
        _config: &DispatchConfig,
        outputs: &mut Vec<OutputBuffers>,
    ) -> Result<(), vyre_driver::BackendError> {
        self.row_batch_calls.fetch_add(1, Ordering::SeqCst);
        if outputs.len() < rows.len() {
            outputs.resize_with(rows.len(), Vec::new);
        } else {
            outputs.truncate(rows.len());
        }
        for (index, (inputs, row)) in rows.iter().zip(outputs.iter_mut()).enumerate() {
            let handles = std::array::from_fn(|index| match &inputs[index] {
                Resource::Resident(handle) => *handle,
                Resource::Borrowed(_) => 0,
            });
            self.calls
                .lock()
                .expect("Fix: persistent-handle recording mutex must not be poisoned")
                .push(handles);
            if row.is_empty() {
                row.push(Vec::new());
            } else {
                row.truncate(1);
            }
            row[0].clear();
            row[0].push(u8::try_from(index).unwrap_or(u8::MAX));
        }
        Ok(())
    }
}

struct EchoPipeline;

impl vyre_driver::backend::private::Sealed for EchoPipeline {}

impl CompiledPipeline for EchoPipeline {
    fn id(&self) -> &str {
        "echo:pipeline"
    }

    fn dispatch(
        &self,
        inputs: &[Vec<u8>],
        _config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, vyre_driver::BackendError> {
        Ok(inputs.to_vec())
    }

    fn dispatch_borrowed(
        &self,
        inputs: &[&[u8]],
        _config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, vyre_driver::BackendError> {
        Ok(inputs.iter().map(|input| input.to_vec()).collect())
    }
}

struct EchoBackend;

impl vyre_driver::backend::private::Sealed for EchoBackend {}

impl VyreBackend for EchoBackend {
    fn id(&self) -> &'static str {
        "echo"
    }

    fn dispatch(
        &self,
        _program: &Program,
        inputs: &[Vec<u8>],
        _config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, vyre_driver::BackendError> {
        Ok(inputs.to_vec())
    }

    fn compile_native(
        &self,
        _program: &Program,
        _config: &DispatchConfig,
    ) -> Result<Option<Arc<dyn CompiledPipeline>>, vyre_driver::BackendError> {
        Ok(Some(Arc::new(EchoPipeline)))
    }
}

struct RecoveringBackend {
    dispatch_calls: Arc<AtomicUsize>,
    expected_outputs_addr: usize,
    expected_slot_addr: usize,
}

impl vyre_driver::backend::private::Sealed for RecoveringBackend {}

impl VyreBackend for RecoveringBackend {
    fn id(&self) -> &'static str {
        "recovering"
    }

    fn dispatch(
        &self,
        _program: &Program,
        _inputs: &[Vec<u8>],
        _config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, vyre_driver::BackendError> {
        Err(vyre_driver::BackendError::new(
            "host-byte dispatch should not run. Fix: compile_native must provide the recovering pipeline.",
        ))
    }

    fn compile_native(
        &self,
        _program: &Program,
        _config: &DispatchConfig,
    ) -> Result<Option<Arc<dyn CompiledPipeline>>, vyre_driver::BackendError> {
        Ok(Some(Arc::new(RecoveringPipeline {
            dispatch_calls: Arc::clone(&self.dispatch_calls),
            expected_outputs_addr: self.expected_outputs_addr,
            expected_slot_addr: self.expected_slot_addr,
        })))
    }
}

struct RecoveringPipeline {
    dispatch_calls: Arc<AtomicUsize>,
    expected_outputs_addr: usize,
    expected_slot_addr: usize,
}

impl vyre_driver::backend::private::Sealed for RecoveringPipeline {}

impl CompiledPipeline for RecoveringPipeline {
    fn id(&self) -> &str {
        "recovering:pipeline"
    }

    fn dispatch(
        &self,
        _inputs: &[Vec<u8>],
        _config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, vyre_driver::BackendError> {
        Err(vyre_driver::BackendError::new(
            "host-byte compiled dispatch should not run. Fix: dispatch_borrowed_into must be used.",
        ))
    }

    fn dispatch_borrowed_into(
        &self,
        _inputs: &[&[u8]],
        _config: &DispatchConfig,
        outputs: &mut OutputBuffers,
    ) -> Result<(), vyre_driver::BackendError> {
        let call = self.dispatch_calls.fetch_add(1, Ordering::SeqCst);
        if call == 0 {
            return Err(vyre_driver::BackendError::new(
                "device lost during test dispatch. Fix: recover and retry without discarding caller-owned output storage.",
            ));
        }
        assert_eq!(outputs.as_ptr() as usize, self.expected_outputs_addr);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].as_ptr() as usize, self.expected_slot_addr);
        outputs[0].clear();
        outputs[0].extend_from_slice(&[9, 8, 7, 6]);
        Ok(())
    }
}

fn grid_sync_program() -> Program {
    let base = super::super::builder::build_program_sharded_slots(1, 1, &[]);
    base.with_rewritten_entry(vec![Node::Region {
        generator: Ident::from("grid_sync_test"),
        source_region: None,
        body: Arc::new(vec![
            Node::Barrier {
                ordering: MemoryOrdering::GridSync,
            },
            Node::Return,
            Node::Barrier {
                ordering: MemoryOrdering::GridSync,
            },
            Node::Return,
        ]),
    }])
}

#[test]
fn borrowed_dispatch_uses_grid_sync_splitter_when_backend_lacks_native_barrier() {
    let backend = Arc::new(GridSyncBackend::default());
    let kernel = Megakernel::compile_bootstrap(backend.clone(), 1, 1, grid_sync_program())
        .expect("Fix: grid-sync test megakernel must compile");
    let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
    let ring = Megakernel::try_encode_empty_ring(1).unwrap();
    let debug = Megakernel::try_encode_empty_debug_log(protocol::debug::RECORD_CAPACITY).unwrap();
    let io_queue = io::try_encode_empty_io_queue(io::IO_SLOT_COUNT).unwrap();

    kernel
        .dispatch_with_io_queue_borrowed(&control, &ring, &debug, &io_queue)
        .expect("Fix: grid-sync split dispatch must succeed through borrowed buffers");

    let segment_lengths = backend
        .segment_lengths
        .lock()
        .expect("Fix: grid-sync recording mutex must not be poisoned")
        .clone();
    assert_eq!(segment_lengths, vec![0, 1, 1]);
}

#[test]
fn persistent_handle_dispatch_never_reenters_host_byte_path() {
    let backend = Arc::new(PersistentHandleBackend::default());
    let calls = Arc::clone(&backend.calls);
    let kernel = Megakernel::bootstrap_sharded(backend, 1, 1, Vec::new())
        .expect("Fix: persistent-handle backend must bootstrap");

    let output = kernel
        .dispatch_persistent_handles_observed(MegakernelResidentHandles::new(11, 12, 13, 14))
        .expect("Fix: persistent-handle dispatch must call the compiled pipeline handle API");

    assert_eq!(output.buffers, vec![vec![1, 2, 3, 4]]);
    assert_eq!(output.stats.input_bytes, 0);
    assert_eq!(output.stats.readback_bytes, 4);
    assert_eq!(output.stats.bytes_moved, 4);
    assert_eq!(output.stats.resident_resource_rows, 1);
    assert_eq!(output.stats.resident_resource_handles, 4);
    assert_eq!(
        output.stats.device_allocation_bytes, 0,
        "Fix: resident-handle dispatch must not report fresh host-visible device allocation"
    );
    assert_eq!(
        output.stats.device_allocation_events, 0,
        "Fix: resident-handle dispatch must not report fresh host-visible device allocation events"
    );
    assert_eq!(
        calls
            .lock()
            .expect("Fix: persistent-handle recording mutex must not be poisoned")
            .as_slice(),
        &[[11, 12, 13, 14]]
    );
}

#[test]
fn persistent_handle_dispatch_into_reuses_caller_output_storage() {
    let backend = Arc::new(PersistentHandleBackend::default());
    let kernel = Megakernel::bootstrap_sharded(backend, 1, 1, Vec::new())
        .expect("Fix: persistent-handle backend must bootstrap");
    let mut outputs = vec![Vec::with_capacity(16)];
    let output_shell = outputs.as_ptr() as usize;
    let first_slot = outputs[0].as_ptr() as usize;

    let stats = kernel
        .dispatch_persistent_handles_into(
            MegakernelResidentHandles::new(11, 12, 13, 14),
            &mut outputs,
        )
        .expect("Fix: persistent-handle dispatch_into must call the compiled pipeline handle API");

    assert_eq!(outputs, vec![vec![1, 2, 3, 4]]);
    assert_eq!(outputs.as_ptr() as usize, output_shell);
    assert_eq!(outputs[0].as_ptr() as usize, first_slot);
    assert_eq!(stats.input_bytes, 0);
    assert_eq!(stats.output_bytes, 4);
    assert_eq!(stats.readback_bytes, 4);
    assert_eq!(stats.bytes_moved, 4);
    assert_eq!(stats.resident_resource_rows, 1);
    assert_eq!(stats.resident_resource_handles, 4);
    assert_eq!(stats.device_allocation_bytes, 0);
    assert_eq!(stats.device_allocation_events, 0);
}

#[test]
fn persistent_handle_observed_preallocates_abi_output_shell() {
    let backend = Arc::new(PersistentHandleBackend::default());
    let kernel = Megakernel::bootstrap_sharded(backend, 1, 1, Vec::new())
        .expect("Fix: persistent-handle backend must bootstrap");

    let observed = kernel
        .dispatch_persistent_handles_observed(MegakernelResidentHandles::new(11, 12, 13, 14))
        .expect(
            "Fix: observed persistent-handle dispatch must call the compiled pipeline handle API",
        );

    assert_eq!(observed.buffers, vec![vec![1, 2, 3, 4]]);
    assert!(
        observed.buffers.capacity() >= MegakernelResidentHandles::ABI_RESOURCE_COUNT,
        "Fix: observed persistent-handle dispatch must preallocate the megakernel ABI output shell."
    );
    assert_eq!(observed.stats.output_bytes, 4);
    assert_eq!(observed.stats.output_buffers, 1);
}

#[test]
fn persistent_handle_many_dispatch_uses_backend_batch_contract_once() {
    let backend = Arc::new(PersistentHandleBackend::default());
    let calls = Arc::clone(&backend.calls);
    let row_batch_calls = Arc::clone(&backend.row_batch_calls);
    let kernel = Megakernel::bootstrap_sharded(backend, 1, 1, Vec::new())
        .expect("Fix: persistent-handle backend must bootstrap");

    let output = kernel
        .dispatch_persistent_handles_many_observed(&[
            MegakernelResidentHandles::new(21, 22, 23, 24),
            MegakernelResidentHandles::new(31, 32, 33, 34),
        ])
        .expect("Fix: batched persistent-handle dispatch must use the compiled pipeline batch API");

    assert_eq!(output.batches, vec![vec![vec![0]], vec![vec![1]]]);
    assert_eq!(output.stats.input_bytes, 0);
    assert_eq!(output.stats.readback_bytes, 2);
    assert_eq!(output.stats.bytes_moved, 2);
    assert_eq!(output.stats.resident_resource_rows, 2);
    assert_eq!(output.stats.resident_resource_handles, 8);
    assert_eq!(
        output.stats.device_allocation_bytes, 0,
        "Fix: batched resident-handle dispatch must not report fresh host-visible device allocation"
    );
    assert_eq!(output.stats.device_allocation_events, 0);
    assert_eq!(output.stats.output_buffers, 2);
    assert_eq!(
        calls
            .lock()
            .expect("Fix: persistent-handle recording mutex must not be poisoned")
            .as_slice(),
        &[[21, 22, 23, 24], [31, 32, 33, 34]]
    );
    assert_eq!(
        row_batch_calls.load(Ordering::SeqCst),
        1,
        "Fix: megakernel resident batches must use fixed ABI resource rows directly, not rebuild transient &[Resource] slice lists"
    );
}

#[test]
fn persistent_handle_many_into_reuses_nested_output_storage() {
    let backend = Arc::new(PersistentHandleBackend::default());
    let kernel = Megakernel::bootstrap_sharded(backend, 1, 1, Vec::new())
        .expect("Fix: persistent-handle backend must bootstrap");
    let mut batches = vec![vec![Vec::with_capacity(8)], vec![Vec::with_capacity(8)]];
    let outer_ptr = batches.as_ptr() as usize;
    let first_row_ptr = batches[0].as_ptr() as usize;
    let second_row_ptr = batches[1].as_ptr() as usize;
    let first_slot_ptr = batches[0][0].as_ptr() as usize;
    let second_slot_ptr = batches[1][0].as_ptr() as usize;

    let stats = kernel
        .dispatch_persistent_handles_many_into(
            &[
                MegakernelResidentHandles::new(21, 22, 23, 24),
                MegakernelResidentHandles::new(31, 32, 33, 34),
            ],
            &mut batches,
        )
        .expect("Fix: batched persistent-handle dispatch must fill caller-owned output storage");

    assert_eq!(batches, vec![vec![vec![0]], vec![vec![1]]]);
    assert_eq!(batches.as_ptr() as usize, outer_ptr);
    assert_eq!(batches[0].as_ptr() as usize, first_row_ptr);
    assert_eq!(batches[1].as_ptr() as usize, second_row_ptr);
    assert_eq!(batches[0][0].as_ptr() as usize, first_slot_ptr);
    assert_eq!(batches[1][0].as_ptr() as usize, second_slot_ptr);
    assert_eq!(stats.output_buffers, 2);
    assert_eq!(stats.resident_resource_rows, 2);
    assert_eq!(stats.resident_resource_handles, 8);
    assert_eq!(stats.device_allocation_events, 0);
}

#[test]
fn persistent_handle_many_scratch_reuses_resource_rows_and_outputs() {
    let backend = Arc::new(PersistentHandleBackend::default());
    let row_batch_calls = Arc::clone(&backend.row_batch_calls);
    let kernel = Megakernel::bootstrap_sharded(backend, 1, 1, Vec::new())
        .expect("Fix: persistent-handle backend must bootstrap");
    let mut scratch = MegakernelResidentBatchScratch::with_capacity(2, 1);

    let first_stats = kernel
        .dispatch_persistent_handles_many_with_scratch(
            &[
                MegakernelResidentHandles::new(21, 22, 23, 24),
                MegakernelResidentHandles::new(31, 32, 33, 34),
            ],
            &mut scratch,
        )
        .expect("Fix: scratch-backed batched persistent dispatch must run");
    let resource_ptr = scratch.resources.as_ptr() as usize;
    let resource_capacity = scratch.resource_capacity();
    let batch_ptr = scratch.batches.as_ptr() as usize;
    let first_row_ptr = scratch.batches[0].as_ptr() as usize;
    let second_row_ptr = scratch.batches[1].as_ptr() as usize;
    let first_slot_ptr = scratch.batches[0][0].as_ptr() as usize;
    let second_slot_ptr = scratch.batches[1][0].as_ptr() as usize;

    let second_stats = kernel
        .dispatch_persistent_handles_many_with_scratch(
            &[
                MegakernelResidentHandles::new(41, 42, 43, 44),
                MegakernelResidentHandles::new(51, 52, 53, 54),
            ],
            &mut scratch,
        )
        .expect("Fix: second scratch-backed dispatch must reuse retained storage");

    assert_eq!(scratch.batches(), &[vec![vec![0]], vec![vec![1]]]);
    assert_eq!(first_stats.output_buffers, 2);
    assert_eq!(second_stats.output_buffers, 2);
    assert_eq!(first_stats.resident_resource_rows, 2);
    assert_eq!(second_stats.resident_resource_rows, 2);
    assert_eq!(first_stats.resident_resource_handles, 8);
    assert_eq!(second_stats.resident_resource_handles, 8);
    assert_eq!(scratch.resources.as_ptr() as usize, resource_ptr);
    assert_eq!(scratch.resource_capacity(), resource_capacity);
    assert_eq!(scratch.batches.as_ptr() as usize, batch_ptr);
    assert_eq!(scratch.batches[0].as_ptr() as usize, first_row_ptr);
    assert_eq!(scratch.batches[1].as_ptr() as usize, second_row_ptr);
    assert_eq!(scratch.batches[0][0].as_ptr() as usize, first_slot_ptr);
    assert_eq!(scratch.batches[1][0].as_ptr() as usize, second_slot_ptr);
    assert_eq!(
        row_batch_calls.load(Ordering::SeqCst),
        2,
        "Fix: scratch-backed resident batches must keep using fixed resource rows across repeated submissions"
    );
}

#[test]
fn resident_batch_scratch_clear_retains_nested_allocations_but_hides_logical_batches() {
    let mut scratch = MegakernelResidentBatchScratch::with_capacity(2, 1);
    scratch.batches[0][0].extend_from_slice(&[1, 2, 3]);
    scratch.batches[1][0].extend_from_slice(&[4, 5, 6]);
    scratch.active_batches = 2;
    let batch_ptr = scratch.batches.as_ptr() as usize;
    let first_row_ptr = scratch.batches[0].as_ptr() as usize;
    let second_row_ptr = scratch.batches[1].as_ptr() as usize;
    let first_slot_ptr = scratch.batches[0][0].as_ptr() as usize;
    let second_slot_ptr = scratch.batches[1][0].as_ptr() as usize;

    scratch.clear();

    assert!(scratch.batches().is_empty());
    assert_eq!(scratch.batches.as_ptr() as usize, batch_ptr);
    assert_eq!(scratch.batches[0].as_ptr() as usize, first_row_ptr);
    assert_eq!(scratch.batches[1].as_ptr() as usize, second_row_ptr);
    assert_eq!(scratch.batches[0][0].as_ptr() as usize, first_slot_ptr);
    assert_eq!(scratch.batches[1][0].as_ptr() as usize, second_slot_ptr);
    assert!(scratch.batches.iter().flatten().all(Vec::is_empty));
}

#[test]
fn readback_borrowed_into_decodes_into_caller_storage() {
    let backend = Arc::new(EchoBackend);
    let kernel = Megakernel::bootstrap_sharded(backend, 1, 1, Vec::new())
        .expect("Fix: echo backend must compile megakernel");
    let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
    let ring = Megakernel::try_encode_empty_ring(1).unwrap();
    let debug = Megakernel::try_encode_empty_debug_log(protocol::debug::RECORD_CAPACITY).unwrap();
    let io_queue = io::try_encode_empty_io_queue(io::IO_SLOT_COUNT).unwrap();
    let mut readback = MegakernelReadback::default();
    let mut outputs = Vec::with_capacity(4);

    let stats = kernel
        .dispatch_with_io_queue_readback_borrowed_into(
            &control,
            &ring,
            &debug,
            &io_queue,
            &mut readback,
            &mut outputs,
        )
        .expect("Fix: readback into caller storage must decode echoed ABI buffers");

    assert_eq!(outputs.len(), 4);
    assert!(
        outputs.iter().all(Vec::is_empty),
        "Fix: readback decode must leave reusable output slots empty after swapping bytes into MegakernelReadback."
    );
    assert!(
        outputs.capacity() >= 4,
        "Fix: readback decode must preserve caller output-vector capacity across dispatches."
    );
    assert_eq!(stats.output_buffers, 4);
    assert_eq!(stats.readback_bytes, stats.output_bytes);
    assert_eq!(
        stats.bytes_moved,
        stats.input_bytes.saturating_add(stats.readback_bytes)
    );
    assert_eq!(
        stats.device_allocation_bytes,
        stats.input_bytes.saturating_add(stats.output_bytes)
    );
    assert_eq!(stats.device_allocation_events, 8);
    assert_eq!(stats.kernel_launches, 1);
    assert_eq!(stats.sync_points, 1);
    assert_eq!(readback.control_bytes, control);
    assert_eq!(readback.ring_bytes, ring);
    assert_eq!(readback.debug_log_bytes, debug);
    assert_eq!(readback.io_queue_bytes, io_queue);
}

#[test]
fn readback_owned_into_uses_caller_storage() {
    let backend = Arc::new(EchoBackend);
    let kernel = Megakernel::bootstrap_sharded(backend, 1, 1, Vec::new())
        .expect("Fix: echo backend must compile megakernel");
    let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
    let ring = Megakernel::try_encode_empty_ring(1).unwrap();
    let debug = Megakernel::try_encode_empty_debug_log(protocol::debug::RECORD_CAPACITY).unwrap();
    let io_queue = io::try_encode_empty_io_queue(io::IO_SLOT_COUNT).unwrap();
    let mut readback = MegakernelReadback::default();
    let mut outputs = Vec::with_capacity(4);

    let stats = kernel
        .dispatch_with_io_queue_readback_into(
            control.clone(),
            ring.clone(),
            debug.clone(),
            io_queue.clone(),
            &mut readback,
            &mut outputs,
        )
        .expect("Fix: owned readback-into dispatch must decode echoed ABI buffers");

    assert_eq!(outputs.len(), 4);
    assert!(
        outputs.iter().all(Vec::is_empty),
        "Fix: owned readback-into dispatch must leave caller output slots reusable after decode."
    );
    assert!(
        outputs.capacity() >= 4,
        "Fix: owned readback-into dispatch must preserve caller output-vector capacity."
    );
    assert_eq!(stats.output_buffers, 4);
    assert_eq!(stats.kernel_launches, 1);
    assert_eq!(stats.sync_points, 1);
    assert_eq!(readback.control_bytes, control);
    assert_eq!(readback.ring_bytes, ring);
    assert_eq!(readback.debug_log_bytes, debug);
    assert_eq!(readback.io_queue_bytes, io_queue);
}

#[test]
fn recovery_retry_preserves_caller_output_slots() {
    let mut outputs = vec![Vec::with_capacity(8)];
    let outputs_addr = outputs.as_ptr() as usize;
    let slot_addr = outputs[0].as_ptr() as usize;
    let dispatch_calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(RecoveringBackend {
        dispatch_calls: Arc::clone(&dispatch_calls),
        expected_outputs_addr: outputs_addr,
        expected_slot_addr: slot_addr,
    });
    let kernel = Megakernel::bootstrap_sharded(backend, 1, 1, Vec::new())
        .expect("Fix: recovering backend must compile megakernel");
    let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
    let ring = Megakernel::try_encode_empty_ring(1).unwrap();
    let debug = Megakernel::try_encode_empty_debug_log(protocol::debug::RECORD_CAPACITY).unwrap();
    let io_queue = io::try_encode_empty_io_queue(io::IO_SLOT_COUNT).unwrap();

    let stats = kernel
        .dispatch_with_io_queue_borrowed_into(&control, &ring, &debug, &io_queue, &mut outputs)
        .expect("Fix: recovery retry must reuse caller-owned output storage");

    assert!(stats.recovered_after_device_loss);
    assert_eq!(dispatch_calls.load(Ordering::SeqCst), 2);
    assert_eq!(outputs, vec![vec![9, 8, 7, 6]]);
    assert_eq!(outputs.as_ptr() as usize, outputs_addr);
    assert_eq!(outputs[0].as_ptr() as usize, slot_addr);
}
