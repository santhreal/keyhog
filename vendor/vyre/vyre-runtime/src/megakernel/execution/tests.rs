use super::*;
use crate::megakernel::readback::MegakernelReadback;
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
        })))
    }
}

struct PersistentHandlePipeline {
    calls: Arc<Mutex<Vec<[u64; 4]>>>,
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
    assert_eq!(
        calls
            .lock()
            .expect("Fix: persistent-handle recording mutex must not be poisoned")
            .as_slice(),
        &[[11, 12, 13, 14]]
    );
}

#[test]
fn persistent_handle_many_dispatch_uses_backend_batch_contract_once() {
    let backend = Arc::new(PersistentHandleBackend::default());
    let calls = Arc::clone(&backend.calls);
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
    assert_eq!(output.stats.output_buffers, 2);
    assert_eq!(
        calls
            .lock()
            .expect("Fix: persistent-handle recording mutex must not be poisoned")
            .as_slice(),
        &[[21, 22, 23, 24], [31, 32, 33, 34]]
    );
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

    assert!(outputs.is_empty());
    assert!(
        outputs.capacity() >= 4,
        "Fix: readback decode must preserve caller output-vector capacity across dispatches."
    );
    assert_eq!(stats.output_buffers, 4);
    assert_eq!(readback.control_bytes, control);
    assert_eq!(readback.ring_bytes, ring);
    assert_eq!(readback.debug_log_bytes, debug);
    assert_eq!(readback.io_queue_bytes, io_queue);
}
