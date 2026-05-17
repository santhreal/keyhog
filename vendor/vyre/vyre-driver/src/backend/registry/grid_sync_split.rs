//! Shared grid-sync wrapper for backends without native cooperative barriers.

use std::collections::HashSet;

use smallvec::SmallVec;
use vyre_foundation::ir::OpId;
use vyre_foundation::ir::Program;

use crate::backend::{
    BackendError, CompiledPipeline, DispatchConfig, OutputBuffers, PendingDispatch,
    Resource, TimedDispatchResult, VyreBackend,
};

pub(super) fn wrap_grid_sync_split(backend: Box<dyn VyreBackend>) -> Box<dyn VyreBackend> {
    Box::new(GridSyncSplitBackend { inner: backend })
}

struct GridSyncSplitBackend {
    inner: Box<dyn VyreBackend>,
}

impl super::super::private::Sealed for GridSyncSplitBackend {}

impl VyreBackend for GridSyncSplitBackend {
    fn id(&self) -> &'static str {
        self.inner.id()
    }

    fn version(&self) -> &'static str {
        self.inner.version()
    }

    fn supported_ops(&self) -> &HashSet<OpId> {
        self.inner.supported_ops()
    }

    fn dispatch(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        if crate::grid_sync::contains_grid_sync(program) && !self.inner.supports_grid_sync() {
            let borrowed: SmallVec<[&[u8]; 8]> = inputs.iter().map(Vec::as_slice).collect();
            return crate::grid_sync::dispatch_with_grid_sync_split(
                self.inner.as_ref(),
                program,
                &borrowed,
                config,
            );
        }
        self.inner.dispatch(program, inputs, config)
    }

    fn dispatch_borrowed(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        if crate::grid_sync::contains_grid_sync(program) && !self.inner.supports_grid_sync() {
            return crate::grid_sync::dispatch_with_grid_sync_split(
                self.inner.as_ref(),
                program,
                inputs,
                config,
            );
        }
        self.inner.dispatch_borrowed(program, inputs, config)
    }

    fn dispatch_borrowed_timed(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<TimedDispatchResult, BackendError> {
        if crate::grid_sync::contains_grid_sync(program) && !self.inner.supports_grid_sync() {
            let started = std::time::Instant::now();
            let outputs = crate::grid_sync::dispatch_with_grid_sync_split(
                self.inner.as_ref(),
                program,
                inputs,
                config,
            )?;
            return Ok(TimedDispatchResult {
                outputs,
                wall_ns: started.elapsed().as_nanos() as u64,
                device_ns: None,
                enqueue_ns: None,
                wait_ns: None,
            });
        }
        self.inner.dispatch_borrowed_timed(program, inputs, config)
    }

    fn dispatch_borrowed_into(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
        outputs: &mut OutputBuffers,
    ) -> Result<(), BackendError> {
        if crate::grid_sync::contains_grid_sync(program) && !self.inner.supports_grid_sync() {
            let result = crate::grid_sync::dispatch_with_grid_sync_split(
                self.inner.as_ref(),
                program,
                inputs,
                config,
            )?;
            outputs.clear();
            outputs.extend(result);
            return Ok(());
        }
        self.inner
            .dispatch_borrowed_into(program, inputs, config, outputs)
    }

    fn compile_native(
        &self,
        program: &Program,
        config: &DispatchConfig,
    ) -> Result<Option<std::sync::Arc<dyn CompiledPipeline>>, BackendError> {
        if crate::grid_sync::contains_grid_sync(program) && !self.inner.supports_grid_sync() {
            return Ok(None);
        }
        self.inner.compile_native(program, config)
    }

    fn pipeline_cache_snapshot(&self) -> Option<crate::pipeline::PipelineCacheSnapshot> {
        self.inner.pipeline_cache_snapshot()
    }

    fn backend_metric_snapshot(&self) -> Vec<(&'static str, u64)> {
        self.inner.backend_metric_snapshot()
    }

    fn allocate_resident(&self, byte_len: usize) -> Result<Resource, BackendError> {
        self.inner.allocate_resident(byte_len)
    }

    fn upload_resident(&self, resource: &Resource, bytes: &[u8]) -> Result<(), BackendError> {
        self.inner.upload_resident(resource, bytes)
    }

    fn free_resident(&self, resource: Resource) -> Result<(), BackendError> {
        self.inner.free_resident(resource)
    }

    fn dispatch_resident_timed(
        &self,
        program: &Program,
        resources: &[Resource],
        config: &DispatchConfig,
    ) -> Result<TimedDispatchResult, BackendError> {
        if crate::grid_sync::contains_grid_sync(program) && !self.inner.supports_grid_sync() {
            return Err(BackendError::UnsupportedFeature {
                name: "resident grid-sync split dispatch".to_string(),
                backend: self.inner.id().to_string(),
            });
        }
        self.inner.dispatch_resident_timed(program, resources, config)
    }

    fn dispatch_async(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Box<dyn PendingDispatch>, BackendError> {
        if crate::grid_sync::contains_grid_sync(program) && !self.inner.supports_grid_sync() {
            let borrowed: SmallVec<[&[u8]; 8]> = inputs.iter().map(Vec::as_slice).collect();
            let outputs = crate::grid_sync::dispatch_with_grid_sync_split(
                self.inner.as_ref(),
                program,
                &borrowed,
                config,
            )?;
            return Ok(Box::new(super::super::pending_dispatch::ReadyPending {
                outputs,
            }));
        }
        self.inner.dispatch_async(program, inputs, config)
    }

    fn dispatch_borrowed_async(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Box<dyn PendingDispatch>, BackendError> {
        if crate::grid_sync::contains_grid_sync(program) && !self.inner.supports_grid_sync() {
            let outputs = crate::grid_sync::dispatch_with_grid_sync_split(
                self.inner.as_ref(),
                program,
                inputs,
                config,
            )?;
            return Ok(Box::new(super::super::pending_dispatch::ReadyPending {
                outputs,
            }));
        }
        self.inner.dispatch_borrowed_async(program, inputs, config)
    }

    fn supports_subgroup_ops(&self) -> bool {
        self.inner.supports_subgroup_ops()
    }

    fn supports_f16(&self) -> bool {
        self.inner.supports_f16()
    }

    fn supports_bf16(&self) -> bool {
        self.inner.supports_bf16()
    }

    fn supports_tensor_cores(&self) -> bool {
        self.inner.supports_tensor_cores()
    }

    fn supports_async_compute(&self) -> bool {
        self.inner.supports_async_compute()
    }

    fn supports_indirect_dispatch(&self) -> bool {
        self.inner.supports_indirect_dispatch()
    }

    fn supports_speculation(&self) -> bool {
        self.inner.supports_speculation()
    }

    fn supports_persistent_thread_dispatch(&self) -> bool {
        self.inner.supports_persistent_thread_dispatch()
    }

    fn supports_grid_sync(&self) -> bool {
        self.inner.supports_grid_sync()
    }

    fn is_distributed(&self) -> bool {
        self.inner.is_distributed()
    }

    fn max_workgroup_size(&self) -> [u32; 3] {
        self.inner.max_workgroup_size()
    }

    fn max_compute_workgroups_per_dimension(&self) -> u32 {
        self.inner.max_compute_workgroups_per_dimension()
    }

    fn max_compute_invocations_per_workgroup(&self) -> u32 {
        self.inner.max_compute_invocations_per_workgroup()
    }

    fn subgroup_size(&self) -> Option<u32> {
        self.inner.subgroup_size()
    }

    fn max_storage_buffer_bytes(&self) -> u64 {
        self.inner.max_storage_buffer_bytes()
    }

    fn prepare(&self) -> Result<(), BackendError> {
        self.inner.prepare()
    }

    fn flush(&self) -> Result<(), BackendError> {
        self.inner.flush()
    }

    fn shutdown(&self) -> Result<(), BackendError> {
        self.inner.shutdown()
    }

    fn device_lost(&self) -> bool {
        self.inner.device_lost()
    }

    fn try_recover(&self) -> Result<(), BackendError> {
        self.inner.try_recover()
    }
}

#[cfg(test)]
mod tests {
    use super::wrap_grid_sync_split;
    use crate::backend::registry::registered_backends;
    use crate::{BackendError, DispatchConfig, VyreBackend};
    use smallvec::SmallVec;
    use std::sync::{Arc, Mutex};
    use vyre_foundation::ir::{BufferDecl, DataType, Node, Program};
    use vyre_foundation::memory_model::MemoryOrdering;

    #[test]
    fn vyre_core_alone_sees_no_backends() {
        assert!(
            registered_backends().is_empty(),
            "vyre-core has no backend deps; registry must be empty here. \
             Fix: if a backend crate was added as a dependency, move this \
            assertion into that crate's test suite."
        );
    }

    #[derive(Default)]
    struct SegmentRecorder {
        calls: Mutex<Vec<(bool, Vec<Vec<u8>>)>>,
    }

    impl super::super::super::private::Sealed for SegmentRecorder {}

    impl VyreBackend for SegmentRecorder {
        fn id(&self) -> &'static str {
            "segment-recorder"
        }

        fn dispatch(
            &self,
            _program: &Program,
            _inputs: &[Vec<u8>],
            _config: &DispatchConfig,
        ) -> Result<Vec<Vec<u8>>, BackendError> {
            Err(BackendError::new(
                "owned dispatch should not run for split borrowed path. Fix: keep grid-sync split on the borrowed segment dispatcher.",
            ))
        }

        fn dispatch_borrowed(
            &self,
            program: &Program,
            inputs: &[&[u8]],
            _config: &DispatchConfig,
        ) -> Result<Vec<Vec<u8>>, BackendError> {
            let mut calls = self.calls.lock().map_err(BackendError::poisoned_lock)?;
            let has_grid_sync = crate::grid_sync::contains_grid_sync(program);
            let captured = inputs
                .iter()
                .map(|input| input.to_vec())
                .collect::<Vec<_>>();
            calls.push((has_grid_sync, captured));
            Ok(vec![vec![calls.len() as u8]])
        }
    }

    fn grid_sync_program() -> Program {
        Program::wrapped(
            vec![BufferDecl::read_write("state", 0, DataType::U32).with_count(1)],
            [1, 1, 1],
            vec![
                Node::Return,
                Node::barrier_with_ordering(MemoryOrdering::GridSync),
                Node::Return,
            ],
        )
    }

    #[test]
    fn registered_backend_wrapper_splits_grid_sync_without_recursing() {
        let recorder = Arc::new(SegmentRecorder::default());
        let backend = wrap_grid_sync_split(Box::new(ArcBackend {
            inner: Arc::clone(&recorder),
        }));
        let inputs = [vec![0u8]];
        let borrowed: SmallVec<[&[u8]; 8]> = inputs.iter().map(Vec::as_slice).collect();

        let outputs = backend
            .dispatch_borrowed(&grid_sync_program(), &borrowed, &DispatchConfig::default())
            .expect("Fix: grid-sync split wrapper must dispatch every segment");

        assert_eq!(outputs, vec![vec![2]]);
        let calls = recorder
            .calls
            .lock()
            .expect("Fix: segment recorder mutex must not be poisoned");
        assert_eq!(calls.len(), 2);
        assert!(
            calls.iter().all(|(has_grid_sync, _)| !*has_grid_sync),
            "split segment dispatches must not contain GridSync barriers"
        );
        assert_eq!(calls[0].1, vec![vec![0]]);
        assert_eq!(
            calls[1].1,
            vec![vec![1]],
            "second segment must receive the first segment's ReadWrite output"
        );
    }

    struct NativeGridSyncProbe {
        calls: Mutex<usize>,
    }

    impl super::super::super::private::Sealed for NativeGridSyncProbe {}

    impl VyreBackend for NativeGridSyncProbe {
        fn id(&self) -> &'static str {
            "native-grid-sync-probe"
        }

        fn dispatch(
            &self,
            _program: &Program,
            _inputs: &[Vec<u8>],
            _config: &DispatchConfig,
        ) -> Result<Vec<Vec<u8>>, BackendError> {
            Err(BackendError::new(
                "owned dispatch should not run for this test. Fix: keep the borrowed path selected.",
            ))
        }

        fn dispatch_borrowed(
            &self,
            program: &Program,
            _inputs: &[&[u8]],
            _config: &DispatchConfig,
        ) -> Result<Vec<Vec<u8>>, BackendError> {
            assert!(
                crate::grid_sync::contains_grid_sync(program),
                "native grid-sync backends must receive the original unsplit Program"
            );
            *self.calls.lock().map_err(BackendError::poisoned_lock)? += 1;
            Ok(vec![vec![9]])
        }

        fn supports_grid_sync(&self) -> bool {
            true
        }
    }

    #[test]
    fn registered_backend_wrapper_preserves_native_grid_sync_dispatch() {
        let probe = Arc::new(NativeGridSyncProbe {
            calls: Mutex::new(0),
        });
        let backend = wrap_grid_sync_split(Box::new(ArcBackend {
            inner: Arc::clone(&probe),
        }));

        let outputs = backend
            .dispatch_borrowed(&grid_sync_program(), &[], &DispatchConfig::default())
            .expect("Fix: native grid-sync backend should receive original dispatch");

        assert_eq!(outputs, vec![vec![9]]);
        assert_eq!(
            *probe
                .calls
                .lock()
                .expect("Fix: native probe mutex must not be poisoned"),
            1
        );
    }

    struct ArcBackend<T: VyreBackend + 'static> {
        inner: Arc<T>,
    }

    impl<T: VyreBackend + 'static> super::super::super::private::Sealed for ArcBackend<T> {}

    impl<T: VyreBackend + 'static> VyreBackend for ArcBackend<T> {
        fn id(&self) -> &'static str {
            self.inner.id()
        }

        fn dispatch(
            &self,
            program: &Program,
            inputs: &[Vec<u8>],
            config: &DispatchConfig,
        ) -> Result<Vec<Vec<u8>>, BackendError> {
            self.inner.dispatch(program, inputs, config)
        }

        fn dispatch_borrowed(
            &self,
            program: &Program,
            inputs: &[&[u8]],
            config: &DispatchConfig,
        ) -> Result<Vec<Vec<u8>>, BackendError> {
            self.inner.dispatch_borrowed(program, inputs, config)
        }

        fn supports_grid_sync(&self) -> bool {
            self.inner.supports_grid_sync()
        }
    }
}
