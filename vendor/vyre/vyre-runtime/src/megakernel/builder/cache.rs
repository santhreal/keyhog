use super::{persistent_body_with_io, wrap_megakernel_program, wrap_persistent_megakernel_program};
use rustc_hash::FxHashMap;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::Arc;
use vyre_foundation::ir::Program;

const EMPTY_TEMPLATE_CACHE_CAP: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct EmptyTemplateKey {
    workgroup_size_x: u32,
    slot_count: u32,
    include_io_polling: bool,
    finite_once: bool,
}

#[derive(Default)]
struct EmptyTemplateCache {
    entries: FxHashMap<EmptyTemplateKey, Arc<Program>>,
    order: VecDeque<EmptyTemplateKey>,
}

impl EmptyTemplateCache {
    fn get(&self, key: &EmptyTemplateKey) -> Option<Arc<Program>> {
        self.entries.get(key).map(Arc::clone)
    }

    fn insert(&mut self, key: EmptyTemplateKey, program: Arc<Program>) {
        if self.entries.insert(key, program).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > EMPTY_TEMPLATE_CACHE_CAP {
            if let Some(evicted) = self.order.pop_front() {
                self.entries.remove(&evicted);
            }
        }
    }
}

thread_local! {
    static EMPTY_TEMPLATE_CACHE: RefCell<EmptyTemplateCache> =
        RefCell::new(EmptyTemplateCache::default());
}

pub(super) fn cached_empty_sharded_program(
    workgroup_size_x: u32,
    slot_count: u32,
    include_io_polling: bool,
) -> Program {
    cached_empty_sharded_program_shared(workgroup_size_x, slot_count, include_io_polling)
        .as_ref()
        .clone()
}

pub(super) fn cached_empty_sharded_program_shared(
    workgroup_size_x: u32,
    slot_count: u32,
    include_io_polling: bool,
) -> Arc<Program> {
    let key = EmptyTemplateKey {
        workgroup_size_x,
        slot_count,
        include_io_polling,
        finite_once: false,
    };
    if let Some(program) = EMPTY_TEMPLATE_CACHE.with(|cache| cache.borrow().get(&key)) {
        return program;
    }

    let program = wrap_persistent_megakernel_program(
        workgroup_size_x,
        slot_count,
        persistent_body_with_io(workgroup_size_x, &[], include_io_polling),
    );
    let program = Arc::new(program);
    EMPTY_TEMPLATE_CACHE.with(|cache| {
        cache.borrow_mut().insert(key, Arc::clone(&program));
    });
    program
}

pub(super) fn cached_empty_sharded_once_program(
    workgroup_size_x: u32,
    slot_count: u32,
) -> Program {
    cached_empty_sharded_once_program_shared(workgroup_size_x, slot_count)
        .as_ref()
        .clone()
}

pub(super) fn cached_empty_sharded_once_program_shared(
    workgroup_size_x: u32,
    slot_count: u32,
) -> Arc<Program> {
    let key = EmptyTemplateKey {
        workgroup_size_x,
        slot_count,
        include_io_polling: false,
        finite_once: true,
    };
    if let Some(program) = EMPTY_TEMPLATE_CACHE.with(|cache| cache.borrow().get(&key)) {
        return program;
    }

    let program = wrap_megakernel_program(
        workgroup_size_x,
        slot_count,
        persistent_body_with_io(workgroup_size_x, &[], false),
    );
    let program = Arc::new(program);
    EMPTY_TEMPLATE_CACHE.with(|cache| {
        cache.borrow_mut().insert(key, Arc::clone(&program));
    });
    program
}
