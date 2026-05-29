use super::*;
use crate::optimizer::dispatcher::{
    DispatchError, OptimizerDispatcher, ResidentDispatchStep, ResidentReadRange,
};
use std::cell::{Cell, RefCell};
use vyre_foundation::ir::Program;

#[derive(Default)]
struct RecordingResidentDispatcher {
    next_handle: Cell<u64>,
    allocs: RefCell<Vec<usize>>,
    uploads: RefCell<Vec<Vec<u8>>>,
    sequence_upload_handles: RefCell<Vec<Vec<u64>>>,
    sequence_step_handles: RefCell<Vec<Vec<Vec<u64>>>>,
    freed: RefCell<Vec<u64>>,
}

impl OptimizerDispatcher for RecordingResidentDispatcher {
    fn dispatch(
        &self,
        _program: &Program,
        _inputs: &[Vec<u8>],
        _grid_override: Option<[u32; 3]>,
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        Err(DispatchError::Rejected(
            "Fix: resident queue tests should not use non-resident dispatch.".to_string(),
        ))
    }

    fn alloc_resident(&self, byte_len: usize) -> Result<u64, DispatchError> {
        self.allocs.borrow_mut().push(byte_len);
        let handle = self.next_handle.get() + 1;
        self.next_handle.set(handle);
        Ok(handle)
    }

    fn upload_resident_many(&self, uploads: &[(u64, &[u8])]) -> Result<(), DispatchError> {
        self.uploads
            .borrow_mut()
            .extend(uploads.iter().map(|(_, bytes)| bytes.to_vec()));
        Ok(())
    }

    fn upload_resident_many_sequence_read_ranges_into(
        &self,
        uploads: &[(u64, &[u8])],
        steps: &[ResidentDispatchStep<'_>],
        read_ranges: &[ResidentReadRange],
        outputs: &mut Vec<Vec<u8>>,
    ) -> Result<(), DispatchError> {
        self.sequence_upload_handles
            .borrow_mut()
            .push(uploads.iter().map(|(handle, _)| *handle).collect());
        self.sequence_step_handles
            .borrow_mut()
            .push(steps.iter().map(|step| step.handle_ids.to_vec()).collect());
        outputs.clear();
        outputs.extend(read_ranges.iter().map(|range| vec![0u8; range.byte_len]));
        Ok(())
    }

    fn free_resident(&self, handle: u64) -> Result<(), DispatchError> {
        self.freed.borrow_mut().push(handle);
        Ok(())
    }
}

#[test]
fn zero_edge_graph_uploads_padded_resident_edge_buffers() {
    let dispatcher = RecordingResidentDispatcher::default();
    let graph = upload_resident_csr_queue_graph(&dispatcher, 3, &[0, 0, 0, 0], &[], &[])
        .expect("Fix: zero-edge resident CSR graph is valid");

    assert_eq!(graph.edge_count(), 0);
    assert_eq!(*dispatcher.allocs.borrow(), vec![16, 4, 4]);
    assert_eq!(
        *dispatcher.uploads.borrow(),
        vec![vec![0; 16], vec![0; 4], vec![0; 4]]
    );
}

#[test]
fn resident_upload_uses_primitive_csr_validation() {
    let dispatcher = RecordingResidentDispatcher::default();
    let err = upload_resident_csr_queue_graph(&dispatcher, 2, &[0, 1, 1], &[5], &[1])
        .expect_err("out-of-range targets must be rejected before upload");
    assert!(
        matches!(err, DispatchError::BadInputs(message) if message.contains("outside node_count"))
    );
    assert!(dispatcher.allocs.borrow().is_empty());
    assert!(dispatcher.uploads.borrow().is_empty());
}

#[test]
fn resident_query_initializes_queue_len_on_device() {
    let dispatcher = RecordingResidentDispatcher::default();
    let graph = ResidentCsrQueueGraph {
        node_count: 1,
        edge_count: 0,
        words: 1,
        edge_offsets_handle: 101,
        edge_targets_handle: 102,
        edge_kind_mask_handle: 103,
    };
    let mut scratch = ResidentCsrQueueScratch::default();
    let mut output = Vec::new();

    run_resident_csr_queue_query_into(
        &dispatcher,
        &graph,
        &mut scratch,
        &[1],
        1,
        u32::MAX,
        &mut output,
    )
    .expect("Fix: recording dispatcher should complete resident CSR queue query");

    let handles = scratch
        .handles
        .expect("Fix: resident CSR queue query should allocate scratch handles");
    assert_eq!(
        dispatcher
            .sequence_upload_handles
            .borrow()
            .last()
            .cloned()
            .expect("Fix: expected one resident sequence"),
        vec![handles.frontier],
        "resident CSR queue query must only upload frontier bytes; queue_len and output clear must stay device-side"
    );
    let steps = dispatcher
        .sequence_step_handles
        .borrow()
        .last()
        .cloned()
        .expect("Fix: expected one resident step sequence");
    assert_eq!(steps.len(), 4);
    assert_eq!(steps[0], vec![handles.queue_len]);
    assert_eq!(steps[1], vec![handles.frontier_out]);
    assert_eq!(
        steps[2],
        vec![handles.frontier, handles.active_queue, handles.queue_len]
    );
    assert_eq!(output, vec![0, 0, 0, 0]);
}

#[test]
fn generated_resident_csr_queue_free_releases_each_handle_once_in_first_seen_order() {
    for seed in 0..4096_u64 {
        let dispatcher = RecordingResidentDispatcher::default();
        let base = 30_000 + seed * 16;
        let graph = ResidentCsrQueueGraph {
            node_count: 4,
            edge_count: 3,
            words: 1,
            edge_offsets_handle: base,
            edge_targets_handle: base + 1,
            edge_kind_mask_handle: base,
        };
        graph.free(&dispatcher).expect("Fix: graph free dedup");
        assert_eq!(dispatcher.freed.borrow().as_slice(), &[base, base + 1]);

        dispatcher.freed.borrow_mut().clear();
        let mut scratch = ResidentCsrQueueScratch::default();
        scratch.handles = Some(ResidentCsrQueueScratchHandles {
            frontier: base + 2,
            active_queue: base + 2,
            queue_len: base + 3,
            frontier_out: base + 4,
            queue_capacity: 4,
            frontier_bytes: 4,
        });
        scratch.free(&dispatcher).expect("Fix: scratch free dedup");
        assert_eq!(
            dispatcher.freed.borrow().as_slice(),
            &[base + 2, base + 3, base + 4]
        );
    }
}
