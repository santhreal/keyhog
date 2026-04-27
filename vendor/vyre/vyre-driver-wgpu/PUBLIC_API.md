pub mod vyre_driver_wgpu
pub mod vyre_driver_wgpu::buffer
pub struct vyre_driver_wgpu::buffer::BufferPool
impl vyre_driver_wgpu::buffer::BufferPool
pub fn vyre_driver_wgpu::buffer::BufferPool::acquire(&self, len: u64, usage: wgpu_types::BufferUsages) -> core::result::Result<vyre_driver_wgpu::buffer::GpuBufferHandle, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::buffer::BufferPool::device(&self) -> &wgpu::api::device::Device
pub fn vyre_driver_wgpu::buffer::BufferPool::new(device: wgpu::api::device::Device, queue: wgpu::api::queue::Queue, config: &vyre_driver::backend::DispatchConfig) -> Self
pub fn vyre_driver_wgpu::buffer::BufferPool::queue(&self) -> &wgpu::api::queue::Queue
pub fn vyre_driver_wgpu::buffer::BufferPool::release(&self, handle: vyre_driver_wgpu::buffer::GpuBufferHandle)
pub fn vyre_driver_wgpu::buffer::BufferPool::stats(&self) -> vyre_driver_wgpu::buffer::BufferPoolStats
pub fn vyre_driver_wgpu::buffer::BufferPool::with_tiering(device: wgpu::api::device::Device, queue: wgpu::api::queue::Queue, config: &vyre_driver::backend::DispatchConfig, tiers: alloc::vec::Vec<vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier>) -> Self
impl core::clone::Clone for vyre_driver_wgpu::buffer::BufferPool
pub fn vyre_driver_wgpu::buffer::BufferPool::clone(&self) -> vyre_driver_wgpu::buffer::BufferPool
impl core::fmt::Debug for vyre_driver_wgpu::buffer::BufferPool
pub fn vyre_driver_wgpu::buffer::BufferPool::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver_wgpu::buffer::BufferPool
impl core::marker::Send for vyre_driver_wgpu::buffer::BufferPool
impl core::marker::Sync for vyre_driver_wgpu::buffer::BufferPool
impl core::marker::Unpin for vyre_driver_wgpu::buffer::BufferPool
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::buffer::BufferPool
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::buffer::BufferPool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::buffer::BufferPool where U: core::convert::From<T>
pub fn vyre_driver_wgpu::buffer::BufferPool::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::buffer::BufferPool where U: core::convert::Into<T>
pub type vyre_driver_wgpu::buffer::BufferPool::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::buffer::BufferPool::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::buffer::BufferPool where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::buffer::BufferPool::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::buffer::BufferPool::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::buffer::BufferPool where T: core::clone::Clone
pub type vyre_driver_wgpu::buffer::BufferPool::Owned = T
pub fn vyre_driver_wgpu::buffer::BufferPool::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::buffer::BufferPool::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::buffer::BufferPool where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::buffer::BufferPool::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::buffer::BufferPool where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::buffer::BufferPool::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::buffer::BufferPool where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::buffer::BufferPool::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::buffer::BufferPool where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::buffer::BufferPool::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::buffer::BufferPool
pub fn vyre_driver_wgpu::buffer::BufferPool::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::buffer::BufferPool
pub type vyre_driver_wgpu::buffer::BufferPool::Init = T
pub const vyre_driver_wgpu::buffer::BufferPool::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::buffer::BufferPool::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::buffer::BufferPool::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::buffer::BufferPool::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::buffer::BufferPool::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::buffer::BufferPool
pub fn vyre_driver_wgpu::buffer::BufferPool::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::buffer::BufferPool
pub fn vyre_driver_wgpu::buffer::BufferPool::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::buffer::BufferPool
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::buffer::BufferPool
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::buffer::BufferPool where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::buffer::BufferPool where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::buffer::BufferPool where T: core::marker::Sync
pub struct vyre_driver_wgpu::buffer::BufferPoolStats
pub vyre_driver_wgpu::buffer::BufferPoolStats::allocations: usize
pub vyre_driver_wgpu::buffer::BufferPoolStats::evictions: usize
pub vyre_driver_wgpu::buffer::BufferPoolStats::hits: usize
pub vyre_driver_wgpu::buffer::BufferPoolStats::releases: usize
pub vyre_driver_wgpu::buffer::BufferPoolStats::retained_bytes: usize
impl core::clone::Clone for vyre_driver_wgpu::buffer::BufferPoolStats
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::clone(&self) -> vyre_driver_wgpu::buffer::BufferPoolStats
impl core::cmp::Eq for vyre_driver_wgpu::buffer::BufferPoolStats
impl core::cmp::PartialEq for vyre_driver_wgpu::buffer::BufferPoolStats
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::eq(&self, other: &vyre_driver_wgpu::buffer::BufferPoolStats) -> bool
impl core::default::Default for vyre_driver_wgpu::buffer::BufferPoolStats
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::default() -> vyre_driver_wgpu::buffer::BufferPoolStats
impl core::fmt::Debug for vyre_driver_wgpu::buffer::BufferPoolStats
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::buffer::BufferPoolStats
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::buffer::BufferPoolStats
impl core::marker::Freeze for vyre_driver_wgpu::buffer::BufferPoolStats
impl core::marker::Send for vyre_driver_wgpu::buffer::BufferPoolStats
impl core::marker::Sync for vyre_driver_wgpu::buffer::BufferPoolStats
impl core::marker::Unpin for vyre_driver_wgpu::buffer::BufferPoolStats
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::buffer::BufferPoolStats
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::buffer::BufferPoolStats
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::buffer::BufferPoolStats where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::buffer::BufferPoolStats where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::buffer::BufferPoolStats where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::buffer::BufferPoolStats where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::buffer::BufferPoolStats where U: core::convert::From<T>
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::buffer::BufferPoolStats where U: core::convert::Into<T>
pub type vyre_driver_wgpu::buffer::BufferPoolStats::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::buffer::BufferPoolStats where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::buffer::BufferPoolStats::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::buffer::BufferPoolStats where T: core::clone::Clone
pub type vyre_driver_wgpu::buffer::BufferPoolStats::Owned = T
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::buffer::BufferPoolStats where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::buffer::BufferPoolStats where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::buffer::BufferPoolStats where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::buffer::BufferPoolStats where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::buffer::BufferPoolStats::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::buffer::BufferPoolStats
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::buffer::BufferPoolStats
pub type vyre_driver_wgpu::buffer::BufferPoolStats::Init = T
pub const vyre_driver_wgpu::buffer::BufferPoolStats::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::buffer::BufferPoolStats::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::buffer::BufferPoolStats::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::buffer::BufferPoolStats::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::buffer::BufferPoolStats::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::buffer::BufferPoolStats
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::buffer::BufferPoolStats
pub fn vyre_driver_wgpu::buffer::BufferPoolStats::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::buffer::BufferPoolStats
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::buffer::BufferPoolStats
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::buffer::BufferPoolStats where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::buffer::BufferPoolStats where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::buffer::BufferPoolStats where T: core::marker::Sync
pub struct vyre_driver_wgpu::buffer::GpuBufferHandle
impl vyre_driver_wgpu::buffer::GpuBufferHandle
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::alloc(device: &wgpu::api::device::Device, len: u64, usage: wgpu_types::BufferUsages) -> core::result::Result<Self, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::allocation_len(&self) -> u64
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::buffer(&self) -> &wgpu::api::buffer::Buffer
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::buffer_arc(&self) -> alloc::sync::Arc<wgpu::api::buffer::Buffer>
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::byte_len(&self) -> u64
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::element_count(&self) -> usize
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::id(&self) -> u64
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::readback(&self, device: &wgpu::api::device::Device, queue: &wgpu::api::queue::Queue, out: &mut alloc::vec::Vec<u8>) -> core::result::Result<(), vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::upload(device: &wgpu::api::device::Device, queue: &wgpu::api::queue::Queue, bytes: &[u8], usage: wgpu_types::BufferUsages) -> core::result::Result<Self, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::usage(&self) -> wgpu_types::BufferUsages
impl core::clone::Clone for vyre_driver_wgpu::buffer::GpuBufferHandle
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::clone(&self) -> vyre_driver_wgpu::buffer::GpuBufferHandle
impl core::fmt::Debug for vyre_driver_wgpu::buffer::GpuBufferHandle
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver_wgpu::buffer::GpuBufferHandle
impl core::marker::Send for vyre_driver_wgpu::buffer::GpuBufferHandle
impl core::marker::Sync for vyre_driver_wgpu::buffer::GpuBufferHandle
impl core::marker::Unpin for vyre_driver_wgpu::buffer::GpuBufferHandle
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::buffer::GpuBufferHandle
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::buffer::GpuBufferHandle
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::buffer::GpuBufferHandle where U: core::convert::From<T>
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::buffer::GpuBufferHandle where U: core::convert::Into<T>
pub type vyre_driver_wgpu::buffer::GpuBufferHandle::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::buffer::GpuBufferHandle where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::buffer::GpuBufferHandle::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::buffer::GpuBufferHandle where T: core::clone::Clone
pub type vyre_driver_wgpu::buffer::GpuBufferHandle::Owned = T
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::buffer::GpuBufferHandle where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::buffer::GpuBufferHandle where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::buffer::GpuBufferHandle where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::buffer::GpuBufferHandle where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::buffer::GpuBufferHandle::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::buffer::GpuBufferHandle
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::buffer::GpuBufferHandle
pub type vyre_driver_wgpu::buffer::GpuBufferHandle::Init = T
pub const vyre_driver_wgpu::buffer::GpuBufferHandle::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::buffer::GpuBufferHandle::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::buffer::GpuBufferHandle::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::buffer::GpuBufferHandle::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::buffer::GpuBufferHandle::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::buffer::GpuBufferHandle
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::buffer::GpuBufferHandle
pub fn vyre_driver_wgpu::buffer::GpuBufferHandle::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::buffer::GpuBufferHandle
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::buffer::GpuBufferHandle
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::buffer::GpuBufferHandle where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::buffer::GpuBufferHandle where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::buffer::GpuBufferHandle where T: core::marker::Sync
pub mod vyre_driver_wgpu::engine
pub mod vyre_driver_wgpu::engine::graph
pub struct vyre_driver_wgpu::engine::graph::GpuDispatchGraph
impl vyre_driver_wgpu::engine::graph::GpuDispatchGraph
pub fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::dispatch(&self, config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<alloc::vec::Vec<u8>>>, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::is_empty(&self) -> bool
pub fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::len(&self) -> usize
pub fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::new() -> Self
pub fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::push(&mut self, pipeline: vyre_driver_wgpu::pipeline::WgpuPipeline, input: alloc::vec::Vec<u8>)
impl core::default::Default for vyre_driver_wgpu::engine::graph::GpuDispatchGraph
pub fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::default() -> vyre_driver_wgpu::engine::graph::GpuDispatchGraph
impl core::marker::Freeze for vyre_driver_wgpu::engine::graph::GpuDispatchGraph
impl core::marker::Send for vyre_driver_wgpu::engine::graph::GpuDispatchGraph
impl core::marker::Sync for vyre_driver_wgpu::engine::graph::GpuDispatchGraph
impl core::marker::Unpin for vyre_driver_wgpu::engine::graph::GpuDispatchGraph
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::engine::graph::GpuDispatchGraph
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::engine::graph::GpuDispatchGraph
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::engine::graph::GpuDispatchGraph where U: core::convert::From<T>
pub fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::engine::graph::GpuDispatchGraph where U: core::convert::Into<T>
pub type vyre_driver_wgpu::engine::graph::GpuDispatchGraph::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::engine::graph::GpuDispatchGraph where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::engine::graph::GpuDispatchGraph::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::engine::graph::GpuDispatchGraph where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::engine::graph::GpuDispatchGraph where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::engine::graph::GpuDispatchGraph where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::engine::graph::GpuDispatchGraph
pub fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::engine::graph::GpuDispatchGraph
pub type vyre_driver_wgpu::engine::graph::GpuDispatchGraph::Init = T
pub const vyre_driver_wgpu::engine::graph::GpuDispatchGraph::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::engine::graph::GpuDispatchGraph
pub fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::engine::graph::GpuDispatchGraph
pub fn vyre_driver_wgpu::engine::graph::GpuDispatchGraph::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::engine::graph::GpuDispatchGraph
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::engine::graph::GpuDispatchGraph
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::engine::graph::GpuDispatchGraph where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::engine::graph::GpuDispatchGraph where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::engine::graph::GpuDispatchGraph where T: core::marker::Sync
pub struct vyre_driver_wgpu::engine::graph::LaunchAccounting
pub vyre_driver_wgpu::engine::graph::LaunchAccounting::graph_submissions: usize
pub vyre_driver_wgpu::engine::graph::LaunchAccounting::sequential_submissions: usize
impl vyre_driver_wgpu::engine::graph::LaunchAccounting
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::reduction_factor(self) -> usize
impl core::clone::Clone for vyre_driver_wgpu::engine::graph::LaunchAccounting
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::clone(&self) -> vyre_driver_wgpu::engine::graph::LaunchAccounting
impl core::cmp::Eq for vyre_driver_wgpu::engine::graph::LaunchAccounting
impl core::cmp::PartialEq for vyre_driver_wgpu::engine::graph::LaunchAccounting
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::eq(&self, other: &vyre_driver_wgpu::engine::graph::LaunchAccounting) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::engine::graph::LaunchAccounting
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::engine::graph::LaunchAccounting
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::engine::graph::LaunchAccounting
impl core::marker::Freeze for vyre_driver_wgpu::engine::graph::LaunchAccounting
impl core::marker::Send for vyre_driver_wgpu::engine::graph::LaunchAccounting
impl core::marker::Sync for vyre_driver_wgpu::engine::graph::LaunchAccounting
impl core::marker::Unpin for vyre_driver_wgpu::engine::graph::LaunchAccounting
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::engine::graph::LaunchAccounting
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::engine::graph::LaunchAccounting
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::engine::graph::LaunchAccounting where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::graph::LaunchAccounting where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::graph::LaunchAccounting where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::graph::LaunchAccounting where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::engine::graph::LaunchAccounting where U: core::convert::From<T>
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::engine::graph::LaunchAccounting where U: core::convert::Into<T>
pub type vyre_driver_wgpu::engine::graph::LaunchAccounting::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::engine::graph::LaunchAccounting where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::engine::graph::LaunchAccounting::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::engine::graph::LaunchAccounting where T: core::clone::Clone
pub type vyre_driver_wgpu::engine::graph::LaunchAccounting::Owned = T
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::engine::graph::LaunchAccounting where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::engine::graph::LaunchAccounting where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::engine::graph::LaunchAccounting where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::engine::graph::LaunchAccounting where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::engine::graph::LaunchAccounting::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::engine::graph::LaunchAccounting
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::engine::graph::LaunchAccounting
pub type vyre_driver_wgpu::engine::graph::LaunchAccounting::Init = T
pub const vyre_driver_wgpu::engine::graph::LaunchAccounting::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::engine::graph::LaunchAccounting::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::engine::graph::LaunchAccounting::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::engine::graph::LaunchAccounting::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::engine::graph::LaunchAccounting::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::engine::graph::LaunchAccounting
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::engine::graph::LaunchAccounting
pub fn vyre_driver_wgpu::engine::graph::LaunchAccounting::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::engine::graph::LaunchAccounting
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::engine::graph::LaunchAccounting
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::engine::graph::LaunchAccounting where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::engine::graph::LaunchAccounting where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::engine::graph::LaunchAccounting where T: core::marker::Sync
pub fn vyre_driver_wgpu::engine::graph::launch_accounting(op_count: usize) -> vyre_driver_wgpu::engine::graph::LaunchAccounting
pub mod vyre_driver_wgpu::engine::multi_gpu
pub struct vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
pub vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::device_index: usize
pub vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::queued_cost: u64
impl core::clone::Clone for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::clone(&self) -> vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
impl core::cmp::Eq for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
impl core::cmp::PartialEq for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::eq(&self, other: &vyre_driver_wgpu::engine::multi_gpu::DeviceLoad) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
impl core::marker::Freeze for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
impl core::marker::Send for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
impl core::marker::Sync for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
impl core::marker::Unpin for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad where U: core::convert::From<T>
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad where U: core::convert::Into<T>
pub type vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad where T: core::clone::Clone
pub type vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::Owned = T
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
pub type vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::Init = T
pub const vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
pub fn vyre_driver_wgpu::engine::multi_gpu::DeviceLoad::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::engine::multi_gpu::DeviceLoad where T: core::marker::Sync
pub struct vyre_driver_wgpu::engine::multi_gpu::Partition
pub vyre_driver_wgpu::engine::multi_gpu::Partition::device_index: usize
pub vyre_driver_wgpu::engine::multi_gpu::Partition::item_ids: alloc::vec::Vec<usize>
pub vyre_driver_wgpu::engine::multi_gpu::Partition::total_cost: u64
impl core::clone::Clone for vyre_driver_wgpu::engine::multi_gpu::Partition
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::clone(&self) -> vyre_driver_wgpu::engine::multi_gpu::Partition
impl core::cmp::Eq for vyre_driver_wgpu::engine::multi_gpu::Partition
impl core::cmp::PartialEq for vyre_driver_wgpu::engine::multi_gpu::Partition
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::eq(&self, other: &vyre_driver_wgpu::engine::multi_gpu::Partition) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::engine::multi_gpu::Partition
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::engine::multi_gpu::Partition
impl core::marker::Freeze for vyre_driver_wgpu::engine::multi_gpu::Partition
impl core::marker::Send for vyre_driver_wgpu::engine::multi_gpu::Partition
impl core::marker::Sync for vyre_driver_wgpu::engine::multi_gpu::Partition
impl core::marker::Unpin for vyre_driver_wgpu::engine::multi_gpu::Partition
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::engine::multi_gpu::Partition
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::engine::multi_gpu::Partition
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::engine::multi_gpu::Partition where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::multi_gpu::Partition where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::multi_gpu::Partition where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::multi_gpu::Partition where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::engine::multi_gpu::Partition where U: core::convert::From<T>
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::engine::multi_gpu::Partition where U: core::convert::Into<T>
pub type vyre_driver_wgpu::engine::multi_gpu::Partition::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::engine::multi_gpu::Partition where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::engine::multi_gpu::Partition::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::engine::multi_gpu::Partition where T: core::clone::Clone
pub type vyre_driver_wgpu::engine::multi_gpu::Partition::Owned = T
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::engine::multi_gpu::Partition where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::engine::multi_gpu::Partition where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::engine::multi_gpu::Partition where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::engine::multi_gpu::Partition where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::engine::multi_gpu::Partition::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::engine::multi_gpu::Partition
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::engine::multi_gpu::Partition
pub type vyre_driver_wgpu::engine::multi_gpu::Partition::Init = T
pub const vyre_driver_wgpu::engine::multi_gpu::Partition::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::engine::multi_gpu::Partition::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::engine::multi_gpu::Partition::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::engine::multi_gpu::Partition::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::engine::multi_gpu::Partition::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::engine::multi_gpu::Partition
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::engine::multi_gpu::Partition
pub fn vyre_driver_wgpu::engine::multi_gpu::Partition::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::engine::multi_gpu::Partition
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::engine::multi_gpu::Partition
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::engine::multi_gpu::Partition where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::engine::multi_gpu::Partition where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::engine::multi_gpu::Partition where T: core::marker::Sync
pub struct vyre_driver_wgpu::engine::multi_gpu::WorkItem
pub vyre_driver_wgpu::engine::multi_gpu::WorkItem::cost: u64
pub vyre_driver_wgpu::engine::multi_gpu::WorkItem::id: usize
impl core::clone::Clone for vyre_driver_wgpu::engine::multi_gpu::WorkItem
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::clone(&self) -> vyre_driver_wgpu::engine::multi_gpu::WorkItem
impl core::cmp::Eq for vyre_driver_wgpu::engine::multi_gpu::WorkItem
impl core::cmp::PartialEq for vyre_driver_wgpu::engine::multi_gpu::WorkItem
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::eq(&self, other: &vyre_driver_wgpu::engine::multi_gpu::WorkItem) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::engine::multi_gpu::WorkItem
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::engine::multi_gpu::WorkItem
impl core::marker::Freeze for vyre_driver_wgpu::engine::multi_gpu::WorkItem
impl core::marker::Send for vyre_driver_wgpu::engine::multi_gpu::WorkItem
impl core::marker::Sync for vyre_driver_wgpu::engine::multi_gpu::WorkItem
impl core::marker::Unpin for vyre_driver_wgpu::engine::multi_gpu::WorkItem
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::engine::multi_gpu::WorkItem
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::engine::multi_gpu::WorkItem
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::engine::multi_gpu::WorkItem where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::multi_gpu::WorkItem where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::multi_gpu::WorkItem where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::multi_gpu::WorkItem where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::engine::multi_gpu::WorkItem where U: core::convert::From<T>
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::engine::multi_gpu::WorkItem where U: core::convert::Into<T>
pub type vyre_driver_wgpu::engine::multi_gpu::WorkItem::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::engine::multi_gpu::WorkItem where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::engine::multi_gpu::WorkItem::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::engine::multi_gpu::WorkItem where T: core::clone::Clone
pub type vyre_driver_wgpu::engine::multi_gpu::WorkItem::Owned = T
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::engine::multi_gpu::WorkItem where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::engine::multi_gpu::WorkItem where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::engine::multi_gpu::WorkItem where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::engine::multi_gpu::WorkItem where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::engine::multi_gpu::WorkItem
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::engine::multi_gpu::WorkItem
pub type vyre_driver_wgpu::engine::multi_gpu::WorkItem::Init = T
pub const vyre_driver_wgpu::engine::multi_gpu::WorkItem::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::engine::multi_gpu::WorkItem
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::engine::multi_gpu::WorkItem
pub fn vyre_driver_wgpu::engine::multi_gpu::WorkItem::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::engine::multi_gpu::WorkItem
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::engine::multi_gpu::WorkItem
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::engine::multi_gpu::WorkItem where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::engine::multi_gpu::WorkItem where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::engine::multi_gpu::WorkItem where T: core::marker::Sync
pub fn vyre_driver_wgpu::engine::multi_gpu::partition_work_stealing(devices: &[vyre_driver_wgpu::engine::multi_gpu::DeviceLoad], items: &[vyre_driver_wgpu::engine::multi_gpu::WorkItem]) -> core::result::Result<alloc::vec::Vec<vyre_driver_wgpu::engine::multi_gpu::Partition>, alloc::string::String>
pub mod vyre_driver_wgpu::engine::persistent
pub struct vyre_driver_wgpu::engine::persistent::PersistentKernelReport
pub vyre_driver_wgpu::engine::persistent::PersistentKernelReport::kernel_launches: u32
pub vyre_driver_wgpu::engine::persistent::PersistentKernelReport::results: alloc::vec::Vec<vyre_driver_wgpu::engine::persistent::WorkResult>
impl core::clone::Clone for vyre_driver_wgpu::engine::persistent::PersistentKernelReport
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::clone(&self) -> vyre_driver_wgpu::engine::persistent::PersistentKernelReport
impl core::cmp::Eq for vyre_driver_wgpu::engine::persistent::PersistentKernelReport
impl core::cmp::PartialEq for vyre_driver_wgpu::engine::persistent::PersistentKernelReport
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::eq(&self, other: &vyre_driver_wgpu::engine::persistent::PersistentKernelReport) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::engine::persistent::PersistentKernelReport
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::engine::persistent::PersistentKernelReport
impl core::marker::Freeze for vyre_driver_wgpu::engine::persistent::PersistentKernelReport
impl core::marker::Send for vyre_driver_wgpu::engine::persistent::PersistentKernelReport
impl core::marker::Sync for vyre_driver_wgpu::engine::persistent::PersistentKernelReport
impl core::marker::Unpin for vyre_driver_wgpu::engine::persistent::PersistentKernelReport
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::engine::persistent::PersistentKernelReport
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::engine::persistent::PersistentKernelReport
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::engine::persistent::PersistentKernelReport where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::persistent::PersistentKernelReport where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::persistent::PersistentKernelReport where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::persistent::PersistentKernelReport where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::engine::persistent::PersistentKernelReport where U: core::convert::From<T>
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::engine::persistent::PersistentKernelReport where U: core::convert::Into<T>
pub type vyre_driver_wgpu::engine::persistent::PersistentKernelReport::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::engine::persistent::PersistentKernelReport where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::engine::persistent::PersistentKernelReport::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::engine::persistent::PersistentKernelReport where T: core::clone::Clone
pub type vyre_driver_wgpu::engine::persistent::PersistentKernelReport::Owned = T
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::engine::persistent::PersistentKernelReport where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::engine::persistent::PersistentKernelReport where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::engine::persistent::PersistentKernelReport where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::engine::persistent::PersistentKernelReport where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::engine::persistent::PersistentKernelReport
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::engine::persistent::PersistentKernelReport
pub type vyre_driver_wgpu::engine::persistent::PersistentKernelReport::Init = T
pub const vyre_driver_wgpu::engine::persistent::PersistentKernelReport::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::engine::persistent::PersistentKernelReport
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::engine::persistent::PersistentKernelReport
pub fn vyre_driver_wgpu::engine::persistent::PersistentKernelReport::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::engine::persistent::PersistentKernelReport
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::engine::persistent::PersistentKernelReport
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::engine::persistent::PersistentKernelReport where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::engine::persistent::PersistentKernelReport where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::engine::persistent::PersistentKernelReport where T: core::marker::Sync
pub struct vyre_driver_wgpu::engine::persistent::PersistentQueue
impl vyre_driver_wgpu::engine::persistent::PersistentQueue
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::is_empty(&self) -> bool
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::len(&self) -> usize
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::new() -> Self
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::push(&mut self, item: vyre_driver_wgpu::engine::persistent::WorkItem)
impl core::clone::Clone for vyre_driver_wgpu::engine::persistent::PersistentQueue
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::clone(&self) -> vyre_driver_wgpu::engine::persistent::PersistentQueue
impl core::cmp::Eq for vyre_driver_wgpu::engine::persistent::PersistentQueue
impl core::cmp::PartialEq for vyre_driver_wgpu::engine::persistent::PersistentQueue
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::eq(&self, other: &vyre_driver_wgpu::engine::persistent::PersistentQueue) -> bool
impl core::default::Default for vyre_driver_wgpu::engine::persistent::PersistentQueue
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::default() -> vyre_driver_wgpu::engine::persistent::PersistentQueue
impl core::fmt::Debug for vyre_driver_wgpu::engine::persistent::PersistentQueue
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::engine::persistent::PersistentQueue
impl core::marker::Freeze for vyre_driver_wgpu::engine::persistent::PersistentQueue
impl core::marker::Send for vyre_driver_wgpu::engine::persistent::PersistentQueue
impl core::marker::Sync for vyre_driver_wgpu::engine::persistent::PersistentQueue
impl core::marker::Unpin for vyre_driver_wgpu::engine::persistent::PersistentQueue
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::engine::persistent::PersistentQueue
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::engine::persistent::PersistentQueue
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::engine::persistent::PersistentQueue where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::persistent::PersistentQueue where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::persistent::PersistentQueue where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::persistent::PersistentQueue where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::engine::persistent::PersistentQueue where U: core::convert::From<T>
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::engine::persistent::PersistentQueue where U: core::convert::Into<T>
pub type vyre_driver_wgpu::engine::persistent::PersistentQueue::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::engine::persistent::PersistentQueue where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::engine::persistent::PersistentQueue::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::engine::persistent::PersistentQueue where T: core::clone::Clone
pub type vyre_driver_wgpu::engine::persistent::PersistentQueue::Owned = T
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::engine::persistent::PersistentQueue where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::engine::persistent::PersistentQueue where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::engine::persistent::PersistentQueue where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::engine::persistent::PersistentQueue where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::engine::persistent::PersistentQueue::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::engine::persistent::PersistentQueue
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::engine::persistent::PersistentQueue
pub type vyre_driver_wgpu::engine::persistent::PersistentQueue::Init = T
pub const vyre_driver_wgpu::engine::persistent::PersistentQueue::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::engine::persistent::PersistentQueue::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::engine::persistent::PersistentQueue::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::engine::persistent::PersistentQueue::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::engine::persistent::PersistentQueue::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::engine::persistent::PersistentQueue
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::engine::persistent::PersistentQueue
pub fn vyre_driver_wgpu::engine::persistent::PersistentQueue::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::engine::persistent::PersistentQueue
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::engine::persistent::PersistentQueue
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::engine::persistent::PersistentQueue where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::engine::persistent::PersistentQueue where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::engine::persistent::PersistentQueue where T: core::marker::Sync
pub struct vyre_driver_wgpu::engine::persistent::WorkItem
pub vyre_driver_wgpu::engine::persistent::WorkItem::id: u32
pub vyre_driver_wgpu::engine::persistent::WorkItem::payload: alloc::vec::Vec<u8>
impl core::clone::Clone for vyre_driver_wgpu::engine::persistent::WorkItem
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::clone(&self) -> vyre_driver_wgpu::engine::persistent::WorkItem
impl core::cmp::Eq for vyre_driver_wgpu::engine::persistent::WorkItem
impl core::cmp::PartialEq for vyre_driver_wgpu::engine::persistent::WorkItem
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::eq(&self, other: &vyre_driver_wgpu::engine::persistent::WorkItem) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::engine::persistent::WorkItem
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::engine::persistent::WorkItem
impl core::marker::Freeze for vyre_driver_wgpu::engine::persistent::WorkItem
impl core::marker::Send for vyre_driver_wgpu::engine::persistent::WorkItem
impl core::marker::Sync for vyre_driver_wgpu::engine::persistent::WorkItem
impl core::marker::Unpin for vyre_driver_wgpu::engine::persistent::WorkItem
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::engine::persistent::WorkItem
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::engine::persistent::WorkItem
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::engine::persistent::WorkItem where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::persistent::WorkItem where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::persistent::WorkItem where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::persistent::WorkItem where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::engine::persistent::WorkItem where U: core::convert::From<T>
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::engine::persistent::WorkItem where U: core::convert::Into<T>
pub type vyre_driver_wgpu::engine::persistent::WorkItem::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::engine::persistent::WorkItem where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::engine::persistent::WorkItem::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::engine::persistent::WorkItem where T: core::clone::Clone
pub type vyre_driver_wgpu::engine::persistent::WorkItem::Owned = T
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::engine::persistent::WorkItem where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::engine::persistent::WorkItem where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::engine::persistent::WorkItem where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::engine::persistent::WorkItem where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::engine::persistent::WorkItem::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::engine::persistent::WorkItem
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::engine::persistent::WorkItem
pub type vyre_driver_wgpu::engine::persistent::WorkItem::Init = T
pub const vyre_driver_wgpu::engine::persistent::WorkItem::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::engine::persistent::WorkItem::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::engine::persistent::WorkItem::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::engine::persistent::WorkItem::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::engine::persistent::WorkItem::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::engine::persistent::WorkItem
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::engine::persistent::WorkItem
pub fn vyre_driver_wgpu::engine::persistent::WorkItem::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::engine::persistent::WorkItem
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::engine::persistent::WorkItem
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::engine::persistent::WorkItem where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::engine::persistent::WorkItem where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::engine::persistent::WorkItem where T: core::marker::Sync
pub struct vyre_driver_wgpu::engine::persistent::WorkResult
pub vyre_driver_wgpu::engine::persistent::WorkResult::id: u32
pub vyre_driver_wgpu::engine::persistent::WorkResult::payload: alloc::vec::Vec<u8>
impl core::clone::Clone for vyre_driver_wgpu::engine::persistent::WorkResult
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::clone(&self) -> vyre_driver_wgpu::engine::persistent::WorkResult
impl core::cmp::Eq for vyre_driver_wgpu::engine::persistent::WorkResult
impl core::cmp::PartialEq for vyre_driver_wgpu::engine::persistent::WorkResult
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::eq(&self, other: &vyre_driver_wgpu::engine::persistent::WorkResult) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::engine::persistent::WorkResult
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::engine::persistent::WorkResult
impl core::marker::Freeze for vyre_driver_wgpu::engine::persistent::WorkResult
impl core::marker::Send for vyre_driver_wgpu::engine::persistent::WorkResult
impl core::marker::Sync for vyre_driver_wgpu::engine::persistent::WorkResult
impl core::marker::Unpin for vyre_driver_wgpu::engine::persistent::WorkResult
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::engine::persistent::WorkResult
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::engine::persistent::WorkResult
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::engine::persistent::WorkResult where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::persistent::WorkResult where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::persistent::WorkResult where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::engine::persistent::WorkResult where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::engine::persistent::WorkResult where U: core::convert::From<T>
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::engine::persistent::WorkResult where U: core::convert::Into<T>
pub type vyre_driver_wgpu::engine::persistent::WorkResult::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::engine::persistent::WorkResult where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::engine::persistent::WorkResult::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::engine::persistent::WorkResult where T: core::clone::Clone
pub type vyre_driver_wgpu::engine::persistent::WorkResult::Owned = T
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::engine::persistent::WorkResult where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::engine::persistent::WorkResult where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::engine::persistent::WorkResult where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::engine::persistent::WorkResult where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::engine::persistent::WorkResult::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::engine::persistent::WorkResult
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::engine::persistent::WorkResult
pub type vyre_driver_wgpu::engine::persistent::WorkResult::Init = T
pub const vyre_driver_wgpu::engine::persistent::WorkResult::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::engine::persistent::WorkResult::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::engine::persistent::WorkResult::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::engine::persistent::WorkResult::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::engine::persistent::WorkResult::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::engine::persistent::WorkResult
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::engine::persistent::WorkResult
pub fn vyre_driver_wgpu::engine::persistent::WorkResult::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::engine::persistent::WorkResult
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::engine::persistent::WorkResult
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::engine::persistent::WorkResult where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::engine::persistent::WorkResult where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::engine::persistent::WorkResult where T: core::marker::Sync
pub fn vyre_driver_wgpu::engine::persistent::run_persistent_kernel<F>(queue: vyre_driver_wgpu::engine::persistent::PersistentQueue, kernel: F) -> core::result::Result<vyre_driver_wgpu::engine::persistent::PersistentKernelReport, vyre_driver::backend::BackendError> where F: core::ops::function::FnMut(&vyre_driver_wgpu::engine::persistent::WorkItem) -> alloc::vec::Vec<u8>
pub mod vyre_driver_wgpu::engine::streaming
pub mod vyre_driver_wgpu::engine::streaming::async_copy
pub struct vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams
impl vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams
pub fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::async_load<F>(&mut self, tag: impl core::convert::Into<alloc::string::String>, copy: F) -> core::result::Result<(), vyre_driver::backend::BackendError> where F: core::ops::function::FnOnce() -> core::result::Result<(), vyre_driver::backend::BackendError> + core::marker::Send + 'static
pub fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::async_wait(&mut self, tag: &str) -> core::result::Result<(), vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::new() -> Self
pub fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::overlap_copy_compute<C, G>(&mut self, tag: impl core::convert::Into<alloc::string::String>, copy: C, compute: G) -> core::result::Result<(), vyre_driver::backend::BackendError> where C: core::ops::function::FnOnce() -> core::result::Result<(), vyre_driver::backend::BackendError> + core::marker::Send + 'static, G: core::ops::function::FnOnce() -> core::result::Result<(), vyre_driver::backend::BackendError>
impl core::default::Default for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams
pub fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::default() -> vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams
impl core::ops::drop::Drop for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams
pub fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::drop(&mut self)
impl core::marker::Freeze for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams
impl core::marker::Send for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams
impl core::marker::Sync for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams
impl core::marker::Unpin for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams where U: core::convert::From<T>
pub fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams where U: core::convert::Into<T>
pub type vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams
pub fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams
pub type vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::Init = T
pub const vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams
pub fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams
pub fn vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::engine::streaming::async_copy::AsyncCopyStreams where T: core::marker::Sync
pub struct vyre_driver_wgpu::engine::streaming::StreamingDispatch
impl vyre_driver_wgpu::engine::streaming::StreamingDispatch
pub fn vyre_driver_wgpu::engine::streaming::StreamingDispatch::finish(&mut self) -> core::result::Result<core::option::Option<alloc::vec::Vec<alloc::vec::Vec<u8>>>, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::engine::streaming::StreamingDispatch::from_runner<F>(runner: F, config: vyre_driver::backend::DispatchConfig) -> Self where F: core::ops::function::Fn(alloc::vec::Vec<u8>, vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::backend::BackendError> + core::marker::Send + core::marker::Sync + 'static
pub fn vyre_driver_wgpu::engine::streaming::StreamingDispatch::new(pipeline: vyre_driver_wgpu::pipeline::WgpuPipeline, config: vyre_driver::backend::DispatchConfig) -> Self
pub fn vyre_driver_wgpu::engine::streaming::StreamingDispatch::push_chunk(&mut self, bytes: alloc::vec::Vec<u8>) -> core::result::Result<core::option::Option<alloc::vec::Vec<alloc::vec::Vec<u8>>>, vyre_driver::backend::BackendError>
impl core::marker::Freeze for vyre_driver_wgpu::engine::streaming::StreamingDispatch
impl core::marker::Send for vyre_driver_wgpu::engine::streaming::StreamingDispatch
impl core::marker::Sync for vyre_driver_wgpu::engine::streaming::StreamingDispatch
impl core::marker::Unpin for vyre_driver_wgpu::engine::streaming::StreamingDispatch
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::engine::streaming::StreamingDispatch
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::engine::streaming::StreamingDispatch
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::engine::streaming::StreamingDispatch where U: core::convert::From<T>
pub fn vyre_driver_wgpu::engine::streaming::StreamingDispatch::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::engine::streaming::StreamingDispatch where U: core::convert::Into<T>
pub type vyre_driver_wgpu::engine::streaming::StreamingDispatch::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::engine::streaming::StreamingDispatch::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::engine::streaming::StreamingDispatch where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::engine::streaming::StreamingDispatch::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::engine::streaming::StreamingDispatch::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::engine::streaming::StreamingDispatch where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::streaming::StreamingDispatch::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::engine::streaming::StreamingDispatch where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::streaming::StreamingDispatch::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::engine::streaming::StreamingDispatch where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::engine::streaming::StreamingDispatch::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::engine::streaming::StreamingDispatch
pub fn vyre_driver_wgpu::engine::streaming::StreamingDispatch::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::engine::streaming::StreamingDispatch
pub type vyre_driver_wgpu::engine::streaming::StreamingDispatch::Init = T
pub const vyre_driver_wgpu::engine::streaming::StreamingDispatch::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::engine::streaming::StreamingDispatch::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::engine::streaming::StreamingDispatch::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::engine::streaming::StreamingDispatch::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::engine::streaming::StreamingDispatch::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::engine::streaming::StreamingDispatch
pub fn vyre_driver_wgpu::engine::streaming::StreamingDispatch::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::engine::streaming::StreamingDispatch
pub fn vyre_driver_wgpu::engine::streaming::StreamingDispatch::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::engine::streaming::StreamingDispatch
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::engine::streaming::StreamingDispatch
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::engine::streaming::StreamingDispatch where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::engine::streaming::StreamingDispatch where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::engine::streaming::StreamingDispatch where T: core::marker::Sync
pub mod vyre_driver_wgpu::ext
pub trait vyre_driver_wgpu::ext::WgslDispatchExt
pub fn vyre_driver_wgpu::ext::WgslDispatchExt::dispatch_wgsl(&self, wgsl: &str, input: &[u8], output_size: usize, workgroup_size: u32) -> core::result::Result<alloc::vec::Vec<u8>, alloc::string::String>
impl vyre_driver_wgpu::ext::WgslDispatchExt for vyre_driver_wgpu::WgpuBackend
pub fn vyre_driver_wgpu::WgpuBackend::dispatch_wgsl(&self, wgsl: &str, input: &[u8], output_size: usize, workgroup_size: u32) -> core::result::Result<alloc::vec::Vec<u8>, alloc::string::String>
pub mod vyre_driver_wgpu::lowering
pub mod vyre_driver_wgpu::lowering::fusion
pub enum vyre_driver_wgpu::lowering::fusion::FusionDecision
pub vyre_driver_wgpu::lowering::fusion::FusionDecision::Accept
pub vyre_driver_wgpu::lowering::fusion::FusionDecision::NoPipelineDependency
pub vyre_driver_wgpu::lowering::fusion::FusionDecision::OutputConsumedElsewhere
pub vyre_driver_wgpu::lowering::fusion::FusionDecision::SharedMemoryBudget
pub vyre_driver_wgpu::lowering::fusion::FusionDecision::SharedMemoryBudget::cap: u32
pub vyre_driver_wgpu::lowering::fusion::FusionDecision::SharedMemoryBudget::needed: u32
pub vyre_driver_wgpu::lowering::fusion::FusionDecision::WorkgroupSizeMismatch
pub vyre_driver_wgpu::lowering::fusion::FusionDecision::WorkgroupSizeMismatch::downstream: [u32; 3]
pub vyre_driver_wgpu::lowering::fusion::FusionDecision::WorkgroupSizeMismatch::upstream: [u32; 3]
impl core::clone::Clone for vyre_driver_wgpu::lowering::fusion::FusionDecision
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::clone(&self) -> vyre_driver_wgpu::lowering::fusion::FusionDecision
impl core::cmp::Eq for vyre_driver_wgpu::lowering::fusion::FusionDecision
impl core::cmp::PartialEq for vyre_driver_wgpu::lowering::fusion::FusionDecision
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::eq(&self, other: &vyre_driver_wgpu::lowering::fusion::FusionDecision) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::lowering::fusion::FusionDecision
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::lowering::fusion::FusionDecision
impl core::marker::Freeze for vyre_driver_wgpu::lowering::fusion::FusionDecision
impl core::marker::Send for vyre_driver_wgpu::lowering::fusion::FusionDecision
impl core::marker::Sync for vyre_driver_wgpu::lowering::fusion::FusionDecision
impl core::marker::Unpin for vyre_driver_wgpu::lowering::fusion::FusionDecision
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::lowering::fusion::FusionDecision
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::lowering::fusion::FusionDecision
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::lowering::fusion::FusionDecision where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::fusion::FusionDecision where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::fusion::FusionDecision where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::fusion::FusionDecision where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::lowering::fusion::FusionDecision where U: core::convert::From<T>
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::lowering::fusion::FusionDecision where U: core::convert::Into<T>
pub type vyre_driver_wgpu::lowering::fusion::FusionDecision::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::lowering::fusion::FusionDecision where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::lowering::fusion::FusionDecision::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::lowering::fusion::FusionDecision where T: core::clone::Clone
pub type vyre_driver_wgpu::lowering::fusion::FusionDecision::Owned = T
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::lowering::fusion::FusionDecision where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::lowering::fusion::FusionDecision where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::lowering::fusion::FusionDecision where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::lowering::fusion::FusionDecision where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::lowering::fusion::FusionDecision::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::lowering::fusion::FusionDecision
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::lowering::fusion::FusionDecision
pub type vyre_driver_wgpu::lowering::fusion::FusionDecision::Init = T
pub const vyre_driver_wgpu::lowering::fusion::FusionDecision::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::lowering::fusion::FusionDecision::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::lowering::fusion::FusionDecision::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::lowering::fusion::FusionDecision::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::lowering::fusion::FusionDecision::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::lowering::fusion::FusionDecision
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::lowering::fusion::FusionDecision
pub fn vyre_driver_wgpu::lowering::fusion::FusionDecision::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::lowering::fusion::FusionDecision
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::lowering::fusion::FusionDecision
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::lowering::fusion::FusionDecision where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::lowering::fusion::FusionDecision where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::lowering::fusion::FusionDecision where T: core::marker::Sync
pub struct vyre_driver_wgpu::lowering::fusion::DispatchShape
pub vyre_driver_wgpu::lowering::fusion::DispatchShape::id: &'static str
pub vyre_driver_wgpu::lowering::fusion::DispatchShape::inputs: alloc::vec::Vec<&'static str>
pub vyre_driver_wgpu::lowering::fusion::DispatchShape::outputs: alloc::vec::Vec<&'static str>
pub vyre_driver_wgpu::lowering::fusion::DispatchShape::shared_memory_bytes: u32
pub vyre_driver_wgpu::lowering::fusion::DispatchShape::specs: vyre_driver_wgpu::lowering::specialization::SpecMap
pub vyre_driver_wgpu::lowering::fusion::DispatchShape::workgroup_size: [u32; 3]
impl core::clone::Clone for vyre_driver_wgpu::lowering::fusion::DispatchShape
pub fn vyre_driver_wgpu::lowering::fusion::DispatchShape::clone(&self) -> vyre_driver_wgpu::lowering::fusion::DispatchShape
impl core::fmt::Debug for vyre_driver_wgpu::lowering::fusion::DispatchShape
pub fn vyre_driver_wgpu::lowering::fusion::DispatchShape::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver_wgpu::lowering::fusion::DispatchShape
impl core::marker::Send for vyre_driver_wgpu::lowering::fusion::DispatchShape
impl core::marker::Sync for vyre_driver_wgpu::lowering::fusion::DispatchShape
impl core::marker::Unpin for vyre_driver_wgpu::lowering::fusion::DispatchShape
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::lowering::fusion::DispatchShape
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::lowering::fusion::DispatchShape
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::lowering::fusion::DispatchShape where U: core::convert::From<T>
pub fn vyre_driver_wgpu::lowering::fusion::DispatchShape::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::lowering::fusion::DispatchShape where U: core::convert::Into<T>
pub type vyre_driver_wgpu::lowering::fusion::DispatchShape::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::lowering::fusion::DispatchShape::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::lowering::fusion::DispatchShape where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::lowering::fusion::DispatchShape::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::lowering::fusion::DispatchShape::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::lowering::fusion::DispatchShape where T: core::clone::Clone
pub type vyre_driver_wgpu::lowering::fusion::DispatchShape::Owned = T
pub fn vyre_driver_wgpu::lowering::fusion::DispatchShape::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::lowering::fusion::DispatchShape::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::lowering::fusion::DispatchShape where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::fusion::DispatchShape::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::lowering::fusion::DispatchShape where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::fusion::DispatchShape::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::lowering::fusion::DispatchShape where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::fusion::DispatchShape::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::lowering::fusion::DispatchShape where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::lowering::fusion::DispatchShape::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::lowering::fusion::DispatchShape
pub fn vyre_driver_wgpu::lowering::fusion::DispatchShape::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::lowering::fusion::DispatchShape
pub type vyre_driver_wgpu::lowering::fusion::DispatchShape::Init = T
pub const vyre_driver_wgpu::lowering::fusion::DispatchShape::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::lowering::fusion::DispatchShape::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::lowering::fusion::DispatchShape::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::lowering::fusion::DispatchShape::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::lowering::fusion::DispatchShape::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::lowering::fusion::DispatchShape
pub fn vyre_driver_wgpu::lowering::fusion::DispatchShape::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::lowering::fusion::DispatchShape
pub fn vyre_driver_wgpu::lowering::fusion::DispatchShape::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::lowering::fusion::DispatchShape
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::lowering::fusion::DispatchShape
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::lowering::fusion::DispatchShape where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::lowering::fusion::DispatchShape where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::lowering::fusion::DispatchShape where T: core::marker::Sync
pub struct vyre_driver_wgpu::lowering::fusion::FusionCaps
pub vyre_driver_wgpu::lowering::fusion::FusionCaps::max_invocations_per_workgroup: u32
pub vyre_driver_wgpu::lowering::fusion::FusionCaps::max_shared_memory_bytes: u32
impl vyre_driver_wgpu::lowering::fusion::FusionCaps
pub const fn vyre_driver_wgpu::lowering::fusion::FusionCaps::rtx_5090() -> Self
impl core::clone::Clone for vyre_driver_wgpu::lowering::fusion::FusionCaps
pub fn vyre_driver_wgpu::lowering::fusion::FusionCaps::clone(&self) -> vyre_driver_wgpu::lowering::fusion::FusionCaps
impl core::default::Default for vyre_driver_wgpu::lowering::fusion::FusionCaps
pub fn vyre_driver_wgpu::lowering::fusion::FusionCaps::default() -> Self
impl core::fmt::Debug for vyre_driver_wgpu::lowering::fusion::FusionCaps
pub fn vyre_driver_wgpu::lowering::fusion::FusionCaps::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::lowering::fusion::FusionCaps
impl core::marker::Freeze for vyre_driver_wgpu::lowering::fusion::FusionCaps
impl core::marker::Send for vyre_driver_wgpu::lowering::fusion::FusionCaps
impl core::marker::Sync for vyre_driver_wgpu::lowering::fusion::FusionCaps
impl core::marker::Unpin for vyre_driver_wgpu::lowering::fusion::FusionCaps
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::lowering::fusion::FusionCaps
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::lowering::fusion::FusionCaps
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::lowering::fusion::FusionCaps where U: core::convert::From<T>
pub fn vyre_driver_wgpu::lowering::fusion::FusionCaps::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::lowering::fusion::FusionCaps where U: core::convert::Into<T>
pub type vyre_driver_wgpu::lowering::fusion::FusionCaps::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::lowering::fusion::FusionCaps::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::lowering::fusion::FusionCaps where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::lowering::fusion::FusionCaps::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::lowering::fusion::FusionCaps::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::lowering::fusion::FusionCaps where T: core::clone::Clone
pub type vyre_driver_wgpu::lowering::fusion::FusionCaps::Owned = T
pub fn vyre_driver_wgpu::lowering::fusion::FusionCaps::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::lowering::fusion::FusionCaps::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::lowering::fusion::FusionCaps where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::fusion::FusionCaps::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::lowering::fusion::FusionCaps where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::fusion::FusionCaps::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::lowering::fusion::FusionCaps where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::fusion::FusionCaps::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::lowering::fusion::FusionCaps where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::lowering::fusion::FusionCaps::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::lowering::fusion::FusionCaps
pub fn vyre_driver_wgpu::lowering::fusion::FusionCaps::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::lowering::fusion::FusionCaps
pub type vyre_driver_wgpu::lowering::fusion::FusionCaps::Init = T
pub const vyre_driver_wgpu::lowering::fusion::FusionCaps::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::lowering::fusion::FusionCaps::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::lowering::fusion::FusionCaps::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::lowering::fusion::FusionCaps::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::lowering::fusion::FusionCaps::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::lowering::fusion::FusionCaps
pub fn vyre_driver_wgpu::lowering::fusion::FusionCaps::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::lowering::fusion::FusionCaps
pub fn vyre_driver_wgpu::lowering::fusion::FusionCaps::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::lowering::fusion::FusionCaps
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::lowering::fusion::FusionCaps
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::lowering::fusion::FusionCaps where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::lowering::fusion::FusionCaps where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::lowering::fusion::FusionCaps where T: core::marker::Sync
pub struct vyre_driver_wgpu::lowering::fusion::FusionPass
impl vyre_driver_wgpu::lowering::fusion::FusionPass
pub fn vyre_driver_wgpu::lowering::fusion::FusionPass::decide(upstream: &vyre_driver_wgpu::lowering::fusion::DispatchShape, downstream: &vyre_driver_wgpu::lowering::fusion::DispatchShape, caps: vyre_driver_wgpu::lowering::fusion::FusionCaps, other_consumers: &[&str]) -> vyre_driver_wgpu::lowering::fusion::FusionDecision
impl core::marker::Freeze for vyre_driver_wgpu::lowering::fusion::FusionPass
impl core::marker::Send for vyre_driver_wgpu::lowering::fusion::FusionPass
impl core::marker::Sync for vyre_driver_wgpu::lowering::fusion::FusionPass
impl core::marker::Unpin for vyre_driver_wgpu::lowering::fusion::FusionPass
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::lowering::fusion::FusionPass
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::lowering::fusion::FusionPass
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::lowering::fusion::FusionPass where U: core::convert::From<T>
pub fn vyre_driver_wgpu::lowering::fusion::FusionPass::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::lowering::fusion::FusionPass where U: core::convert::Into<T>
pub type vyre_driver_wgpu::lowering::fusion::FusionPass::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::lowering::fusion::FusionPass::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::lowering::fusion::FusionPass where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::lowering::fusion::FusionPass::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::lowering::fusion::FusionPass::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::lowering::fusion::FusionPass where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::fusion::FusionPass::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::lowering::fusion::FusionPass where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::fusion::FusionPass::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::lowering::fusion::FusionPass where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::fusion::FusionPass::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::lowering::fusion::FusionPass
pub fn vyre_driver_wgpu::lowering::fusion::FusionPass::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::lowering::fusion::FusionPass
pub type vyre_driver_wgpu::lowering::fusion::FusionPass::Init = T
pub const vyre_driver_wgpu::lowering::fusion::FusionPass::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::lowering::fusion::FusionPass::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::lowering::fusion::FusionPass::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::lowering::fusion::FusionPass::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::lowering::fusion::FusionPass::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::lowering::fusion::FusionPass
pub fn vyre_driver_wgpu::lowering::fusion::FusionPass::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::lowering::fusion::FusionPass
pub fn vyre_driver_wgpu::lowering::fusion::FusionPass::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::lowering::fusion::FusionPass
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::lowering::fusion::FusionPass
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::lowering::fusion::FusionPass where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::lowering::fusion::FusionPass where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::lowering::fusion::FusionPass where T: core::marker::Sync
pub mod vyre_driver_wgpu::lowering::naga_emit
pub fn vyre_driver_wgpu::lowering::naga_emit::emit_module(program: &vyre_foundation::ir_inner::model::program::Program, _config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<naga::Module, vyre_foundation::lower::LoweringError>
pub mod vyre_driver_wgpu::lowering::specialization
pub enum vyre_driver_wgpu::lowering::specialization::SpecValue
pub vyre_driver_wgpu::lowering::specialization::SpecValue::Bool(bool)
pub vyre_driver_wgpu::lowering::specialization::SpecValue::F32(f32)
pub vyre_driver_wgpu::lowering::specialization::SpecValue::I32(i32)
pub vyre_driver_wgpu::lowering::specialization::SpecValue::U32(u32)
impl vyre_driver_wgpu::lowering::specialization::SpecValue
pub fn vyre_driver_wgpu::lowering::specialization::SpecValue::as_f64(self) -> f64
pub fn vyre_driver_wgpu::lowering::specialization::SpecValue::cache_hash(self) -> u64
impl core::clone::Clone for vyre_driver_wgpu::lowering::specialization::SpecValue
pub fn vyre_driver_wgpu::lowering::specialization::SpecValue::clone(&self) -> vyre_driver_wgpu::lowering::specialization::SpecValue
impl core::cmp::PartialEq for vyre_driver_wgpu::lowering::specialization::SpecValue
pub fn vyre_driver_wgpu::lowering::specialization::SpecValue::eq(&self, other: &vyre_driver_wgpu::lowering::specialization::SpecValue) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::lowering::specialization::SpecValue
pub fn vyre_driver_wgpu::lowering::specialization::SpecValue::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::lowering::specialization::SpecValue
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::lowering::specialization::SpecValue
impl core::marker::Freeze for vyre_driver_wgpu::lowering::specialization::SpecValue
impl core::marker::Send for vyre_driver_wgpu::lowering::specialization::SpecValue
impl core::marker::Sync for vyre_driver_wgpu::lowering::specialization::SpecValue
impl core::marker::Unpin for vyre_driver_wgpu::lowering::specialization::SpecValue
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::lowering::specialization::SpecValue
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::lowering::specialization::SpecValue
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::lowering::specialization::SpecValue where U: core::convert::From<T>
pub fn vyre_driver_wgpu::lowering::specialization::SpecValue::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::lowering::specialization::SpecValue where U: core::convert::Into<T>
pub type vyre_driver_wgpu::lowering::specialization::SpecValue::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::lowering::specialization::SpecValue::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::lowering::specialization::SpecValue where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::lowering::specialization::SpecValue::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::lowering::specialization::SpecValue::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::lowering::specialization::SpecValue where T: core::clone::Clone
pub type vyre_driver_wgpu::lowering::specialization::SpecValue::Owned = T
pub fn vyre_driver_wgpu::lowering::specialization::SpecValue::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::lowering::specialization::SpecValue::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::lowering::specialization::SpecValue where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::specialization::SpecValue::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::lowering::specialization::SpecValue where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::specialization::SpecValue::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::lowering::specialization::SpecValue where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::specialization::SpecValue::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::lowering::specialization::SpecValue where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::lowering::specialization::SpecValue::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::lowering::specialization::SpecValue
pub fn vyre_driver_wgpu::lowering::specialization::SpecValue::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::lowering::specialization::SpecValue
pub type vyre_driver_wgpu::lowering::specialization::SpecValue::Init = T
pub const vyre_driver_wgpu::lowering::specialization::SpecValue::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::lowering::specialization::SpecValue::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::lowering::specialization::SpecValue::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::lowering::specialization::SpecValue::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::lowering::specialization::SpecValue::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::lowering::specialization::SpecValue
pub fn vyre_driver_wgpu::lowering::specialization::SpecValue::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::lowering::specialization::SpecValue
pub fn vyre_driver_wgpu::lowering::specialization::SpecValue::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::lowering::specialization::SpecValue
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::lowering::specialization::SpecValue
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::lowering::specialization::SpecValue where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::lowering::specialization::SpecValue where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::lowering::specialization::SpecValue where T: core::marker::Sync
pub struct vyre_driver_wgpu::lowering::specialization::SpecCacheKey
pub vyre_driver_wgpu::lowering::specialization::SpecCacheKey::binding_sig: u64
pub vyre_driver_wgpu::lowering::specialization::SpecCacheKey::shader_hash: u64
pub vyre_driver_wgpu::lowering::specialization::SpecCacheKey::spec_hash: u64
pub vyre_driver_wgpu::lowering::specialization::SpecCacheKey::workgroup_size: [u32; 3]
impl vyre_driver_wgpu::lowering::specialization::SpecCacheKey
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::new(shader_hash: u64, binding_sig: u64, workgroup_size: [u32; 3], specs: &vyre_driver_wgpu::lowering::specialization::SpecMap) -> Self
impl core::clone::Clone for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::clone(&self) -> vyre_driver_wgpu::lowering::specialization::SpecCacheKey
impl core::cmp::Eq for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
impl core::cmp::PartialEq for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::eq(&self, other: &vyre_driver_wgpu::lowering::specialization::SpecCacheKey) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
impl core::marker::Freeze for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
impl core::marker::Send for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
impl core::marker::Sync for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
impl core::marker::Unpin for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::lowering::specialization::SpecCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::specialization::SpecCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::specialization::SpecCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::specialization::SpecCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::lowering::specialization::SpecCacheKey where U: core::convert::From<T>
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::lowering::specialization::SpecCacheKey where U: core::convert::Into<T>
pub type vyre_driver_wgpu::lowering::specialization::SpecCacheKey::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::lowering::specialization::SpecCacheKey where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::lowering::specialization::SpecCacheKey::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::lowering::specialization::SpecCacheKey where T: core::clone::Clone
pub type vyre_driver_wgpu::lowering::specialization::SpecCacheKey::Owned = T
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::lowering::specialization::SpecCacheKey where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::lowering::specialization::SpecCacheKey where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::lowering::specialization::SpecCacheKey where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::lowering::specialization::SpecCacheKey where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
pub type vyre_driver_wgpu::lowering::specialization::SpecCacheKey::Init = T
pub const vyre_driver_wgpu::lowering::specialization::SpecCacheKey::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
pub fn vyre_driver_wgpu::lowering::specialization::SpecCacheKey::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::lowering::specialization::SpecCacheKey
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::lowering::specialization::SpecCacheKey where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::lowering::specialization::SpecCacheKey where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::lowering::specialization::SpecCacheKey where T: core::marker::Sync
pub struct vyre_driver_wgpu::lowering::specialization::SpecMap
impl vyre_driver_wgpu::lowering::specialization::SpecMap
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::cache_hash(&self) -> u64
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::insert(&mut self, name: impl core::convert::Into<alloc::string::String>, value: vyre_driver_wgpu::lowering::specialization::SpecValue)
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::is_empty(&self) -> bool
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::iter(&self) -> impl core::iter::traits::iterator::Iterator<Item = (&str, vyre_driver_wgpu::lowering::specialization::SpecValue)>
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::len(&self) -> usize
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::new() -> Self
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::to_wgpu_constants(&self) -> std::collections::hash::map::HashMap<alloc::string::String, f64>
impl core::clone::Clone for vyre_driver_wgpu::lowering::specialization::SpecMap
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::clone(&self) -> vyre_driver_wgpu::lowering::specialization::SpecMap
impl core::default::Default for vyre_driver_wgpu::lowering::specialization::SpecMap
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::default() -> vyre_driver_wgpu::lowering::specialization::SpecMap
impl core::fmt::Debug for vyre_driver_wgpu::lowering::specialization::SpecMap
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver_wgpu::lowering::specialization::SpecMap
impl core::marker::Send for vyre_driver_wgpu::lowering::specialization::SpecMap
impl core::marker::Sync for vyre_driver_wgpu::lowering::specialization::SpecMap
impl core::marker::Unpin for vyre_driver_wgpu::lowering::specialization::SpecMap
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::lowering::specialization::SpecMap
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::lowering::specialization::SpecMap
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::lowering::specialization::SpecMap where U: core::convert::From<T>
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::lowering::specialization::SpecMap where U: core::convert::Into<T>
pub type vyre_driver_wgpu::lowering::specialization::SpecMap::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::lowering::specialization::SpecMap where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::lowering::specialization::SpecMap::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::lowering::specialization::SpecMap where T: core::clone::Clone
pub type vyre_driver_wgpu::lowering::specialization::SpecMap::Owned = T
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::lowering::specialization::SpecMap where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::lowering::specialization::SpecMap where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::lowering::specialization::SpecMap where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::lowering::specialization::SpecMap where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::lowering::specialization::SpecMap::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::lowering::specialization::SpecMap
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::lowering::specialization::SpecMap
pub type vyre_driver_wgpu::lowering::specialization::SpecMap::Init = T
pub const vyre_driver_wgpu::lowering::specialization::SpecMap::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::lowering::specialization::SpecMap::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::lowering::specialization::SpecMap::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::lowering::specialization::SpecMap::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::lowering::specialization::SpecMap::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::lowering::specialization::SpecMap
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::lowering::specialization::SpecMap
pub fn vyre_driver_wgpu::lowering::specialization::SpecMap::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::lowering::specialization::SpecMap
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::lowering::specialization::SpecMap
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::lowering::specialization::SpecMap where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::lowering::specialization::SpecMap where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::lowering::specialization::SpecMap where T: core::marker::Sync
pub mod vyre_driver_wgpu::lowering::subgroup_intrinsics
pub enum vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
pub vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::Add
pub vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::Broadcast
pub vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::ExclusiveAdd
pub vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::InclusiveAdd
pub vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::Max
pub vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::Min
pub vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::ShuffleXor
impl vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::all() -> &'static [vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp]
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::wgsl_name(self) -> &'static str
impl core::clone::Clone for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::clone(&self) -> vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
impl core::cmp::Eq for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
impl core::cmp::PartialEq for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::eq(&self, other: &vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
impl core::marker::Freeze for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
impl core::marker::Send for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
impl core::marker::Sync for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
impl core::marker::Unpin for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp where U: core::convert::From<T>
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp where U: core::convert::Into<T>
pub type vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp where T: core::clone::Clone
pub type vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::Owned = T
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
pub type vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::Init = T
pub const vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp where T: core::marker::Sync
pub struct vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
pub vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::subgroup_size: u32
pub vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::supports_subgroup: bool
pub vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::supports_subgroup_vertex: bool
impl vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::from_adapter(adapter: &wgpu::api::adapter::Adapter) -> Self
impl core::clone::Clone for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::clone(&self) -> vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
impl core::cmp::Eq for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
impl core::cmp::PartialEq for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::eq(&self, other: &vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps) -> bool
impl core::default::Default for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::default() -> vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
impl core::fmt::Debug for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
impl core::marker::Freeze for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
impl core::marker::Send for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
impl core::marker::Sync for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
impl core::marker::Unpin for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps where U: core::convert::From<T>
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps where U: core::convert::Into<T>
pub type vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps where T: core::clone::Clone
pub type vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::Owned = T
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
pub type vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::Init = T
pub const vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupCaps where T: core::marker::Sync
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::emit_shuffle_xor(value: &str, mask: &str) -> alloc::string::String
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::emit_sram_scan_fallback(op: vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp, arg: &str, shared_var: &str) -> alloc::string::String
pub fn vyre_driver_wgpu::lowering::subgroup_intrinsics::emit_wgsl_for(op: vyre_driver_wgpu::lowering::subgroup_intrinsics::SubgroupOp, arg: &str) -> alloc::string::String
pub struct vyre_driver_wgpu::lowering::WgpuBindingAssignment
pub vyre_driver_wgpu::lowering::WgpuBindingAssignment::access: vyre_spec::buffer_access::BufferAccess
pub vyre_driver_wgpu::lowering::WgpuBindingAssignment::binding: u32
pub vyre_driver_wgpu::lowering::WgpuBindingAssignment::element: vyre_spec::data_type::DataType
pub vyre_driver_wgpu::lowering::WgpuBindingAssignment::group: u32
pub vyre_driver_wgpu::lowering::WgpuBindingAssignment::kind: vyre_foundation::ir_inner::model::program::MemoryKind
pub vyre_driver_wgpu::lowering::WgpuBindingAssignment::name: alloc::string::String
impl core::clone::Clone for vyre_driver_wgpu::lowering::WgpuBindingAssignment
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::clone(&self) -> vyre_driver_wgpu::lowering::WgpuBindingAssignment
impl core::cmp::Eq for vyre_driver_wgpu::lowering::WgpuBindingAssignment
impl core::cmp::PartialEq for vyre_driver_wgpu::lowering::WgpuBindingAssignment
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::eq(&self, other: &vyre_driver_wgpu::lowering::WgpuBindingAssignment) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::lowering::WgpuBindingAssignment
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::lowering::WgpuBindingAssignment
impl core::marker::Freeze for vyre_driver_wgpu::lowering::WgpuBindingAssignment
impl core::marker::Send for vyre_driver_wgpu::lowering::WgpuBindingAssignment
impl core::marker::Sync for vyre_driver_wgpu::lowering::WgpuBindingAssignment
impl core::marker::Unpin for vyre_driver_wgpu::lowering::WgpuBindingAssignment
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::lowering::WgpuBindingAssignment
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::lowering::WgpuBindingAssignment
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::lowering::WgpuBindingAssignment where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::WgpuBindingAssignment where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::WgpuBindingAssignment where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::WgpuBindingAssignment where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::lowering::WgpuBindingAssignment where U: core::convert::From<T>
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::lowering::WgpuBindingAssignment where U: core::convert::Into<T>
pub type vyre_driver_wgpu::lowering::WgpuBindingAssignment::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::lowering::WgpuBindingAssignment where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::lowering::WgpuBindingAssignment::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::lowering::WgpuBindingAssignment where T: core::clone::Clone
pub type vyre_driver_wgpu::lowering::WgpuBindingAssignment::Owned = T
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::lowering::WgpuBindingAssignment where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::lowering::WgpuBindingAssignment where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::lowering::WgpuBindingAssignment where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::lowering::WgpuBindingAssignment where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::lowering::WgpuBindingAssignment
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::lowering::WgpuBindingAssignment
pub type vyre_driver_wgpu::lowering::WgpuBindingAssignment::Init = T
pub const vyre_driver_wgpu::lowering::WgpuBindingAssignment::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::lowering::WgpuBindingAssignment
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::lowering::WgpuBindingAssignment
pub fn vyre_driver_wgpu::lowering::WgpuBindingAssignment::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::lowering::WgpuBindingAssignment
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::lowering::WgpuBindingAssignment
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::lowering::WgpuBindingAssignment where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::lowering::WgpuBindingAssignment where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::lowering::WgpuBindingAssignment where T: core::marker::Sync
pub struct vyre_driver_wgpu::lowering::WgpuDispatchGeometry
pub vyre_driver_wgpu::lowering::WgpuDispatchGeometry::workgroup_size: [u32; 3]
pub vyre_driver_wgpu::lowering::WgpuDispatchGeometry::workgroups: [u32; 3]
impl core::clone::Clone for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::clone(&self) -> vyre_driver_wgpu::lowering::WgpuDispatchGeometry
impl core::cmp::Eq for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
impl core::cmp::PartialEq for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::eq(&self, other: &vyre_driver_wgpu::lowering::WgpuDispatchGeometry) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
impl core::marker::Freeze for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
impl core::marker::Send for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
impl core::marker::Sync for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
impl core::marker::Unpin for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::lowering::WgpuDispatchGeometry where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::WgpuDispatchGeometry where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::WgpuDispatchGeometry where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::lowering::WgpuDispatchGeometry where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::lowering::WgpuDispatchGeometry where U: core::convert::From<T>
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::lowering::WgpuDispatchGeometry where U: core::convert::Into<T>
pub type vyre_driver_wgpu::lowering::WgpuDispatchGeometry::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::lowering::WgpuDispatchGeometry where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::lowering::WgpuDispatchGeometry::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::lowering::WgpuDispatchGeometry where T: core::clone::Clone
pub type vyre_driver_wgpu::lowering::WgpuDispatchGeometry::Owned = T
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::lowering::WgpuDispatchGeometry where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::lowering::WgpuDispatchGeometry where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::lowering::WgpuDispatchGeometry where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::lowering::WgpuDispatchGeometry where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
pub type vyre_driver_wgpu::lowering::WgpuDispatchGeometry::Init = T
pub const vyre_driver_wgpu::lowering::WgpuDispatchGeometry::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
pub fn vyre_driver_wgpu::lowering::WgpuDispatchGeometry::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::lowering::WgpuDispatchGeometry
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::lowering::WgpuDispatchGeometry where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::lowering::WgpuDispatchGeometry where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::lowering::WgpuDispatchGeometry where T: core::marker::Sync
pub struct vyre_driver_wgpu::lowering::WgpuProgram
pub vyre_driver_wgpu::lowering::WgpuProgram::bindings: alloc::vec::Vec<vyre_driver_wgpu::lowering::WgpuBindingAssignment>
pub vyre_driver_wgpu::lowering::WgpuProgram::dispatch_geometry: vyre_driver_wgpu::lowering::WgpuDispatchGeometry
pub vyre_driver_wgpu::lowering::WgpuProgram::module: naga::Module
pub vyre_driver_wgpu::lowering::WgpuProgram::workgroup_size: [u32; 3]
impl vyre_driver_wgpu::lowering::WgpuProgram
pub fn vyre_driver_wgpu::lowering::WgpuProgram::from_program(program: &vyre_foundation::ir_inner::model::program::Program, config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<Self, vyre_foundation::lower::LoweringError>
impl core::clone::Clone for vyre_driver_wgpu::lowering::WgpuProgram
pub fn vyre_driver_wgpu::lowering::WgpuProgram::clone(&self) -> vyre_driver_wgpu::lowering::WgpuProgram
impl core::fmt::Debug for vyre_driver_wgpu::lowering::WgpuProgram
pub fn vyre_driver_wgpu::lowering::WgpuProgram::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver_wgpu::lowering::WgpuProgram
impl core::marker::Send for vyre_driver_wgpu::lowering::WgpuProgram
impl core::marker::Sync for vyre_driver_wgpu::lowering::WgpuProgram
impl core::marker::Unpin for vyre_driver_wgpu::lowering::WgpuProgram
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::lowering::WgpuProgram
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::lowering::WgpuProgram
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::lowering::WgpuProgram where U: core::convert::From<T>
pub fn vyre_driver_wgpu::lowering::WgpuProgram::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::lowering::WgpuProgram where U: core::convert::Into<T>
pub type vyre_driver_wgpu::lowering::WgpuProgram::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::lowering::WgpuProgram::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::lowering::WgpuProgram where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::lowering::WgpuProgram::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::lowering::WgpuProgram::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::lowering::WgpuProgram where T: core::clone::Clone
pub type vyre_driver_wgpu::lowering::WgpuProgram::Owned = T
pub fn vyre_driver_wgpu::lowering::WgpuProgram::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::lowering::WgpuProgram::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::lowering::WgpuProgram where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::WgpuProgram::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::lowering::WgpuProgram where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::WgpuProgram::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::lowering::WgpuProgram where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::lowering::WgpuProgram::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::lowering::WgpuProgram where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::lowering::WgpuProgram::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::lowering::WgpuProgram
pub fn vyre_driver_wgpu::lowering::WgpuProgram::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::lowering::WgpuProgram
pub type vyre_driver_wgpu::lowering::WgpuProgram::Init = T
pub const vyre_driver_wgpu::lowering::WgpuProgram::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::lowering::WgpuProgram::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::lowering::WgpuProgram::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::lowering::WgpuProgram::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::lowering::WgpuProgram::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::lowering::WgpuProgram
pub fn vyre_driver_wgpu::lowering::WgpuProgram::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::lowering::WgpuProgram
pub fn vyre_driver_wgpu::lowering::WgpuProgram::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::lowering::WgpuProgram
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::lowering::WgpuProgram
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::lowering::WgpuProgram where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::lowering::WgpuProgram where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::lowering::WgpuProgram where T: core::marker::Sync
pub fn vyre_driver_wgpu::lowering::lower(program: &vyre_foundation::ir_inner::model::program::Program) -> core::result::Result<alloc::string::String, vyre_foundation::lower::LoweringError>
pub fn vyre_driver_wgpu::lowering::lower_with_config(program: &vyre_foundation::ir_inner::model::program::Program, config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::string::String, vyre_foundation::lower::LoweringError>
pub mod vyre_driver_wgpu::megakernel
pub struct vyre_driver_wgpu::megakernel::MegakernelCaps
pub vyre_driver_wgpu::megakernel::MegakernelCaps::max_worker_count: u32
pub vyre_driver_wgpu::megakernel::MegakernelCaps::supported: bool
impl vyre_driver_wgpu::megakernel::MegakernelCaps
pub const fn vyre_driver_wgpu::megakernel::MegakernelCaps::supported(max_worker_count: u32) -> Self
pub const fn vyre_driver_wgpu::megakernel::MegakernelCaps::unsupported() -> Self
impl core::clone::Clone for vyre_driver_wgpu::megakernel::MegakernelCaps
pub fn vyre_driver_wgpu::megakernel::MegakernelCaps::clone(&self) -> vyre_driver_wgpu::megakernel::MegakernelCaps
impl core::fmt::Debug for vyre_driver_wgpu::megakernel::MegakernelCaps
pub fn vyre_driver_wgpu::megakernel::MegakernelCaps::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::megakernel::MegakernelCaps
impl core::marker::Freeze for vyre_driver_wgpu::megakernel::MegakernelCaps
impl core::marker::Send for vyre_driver_wgpu::megakernel::MegakernelCaps
impl core::marker::Sync for vyre_driver_wgpu::megakernel::MegakernelCaps
impl core::marker::Unpin for vyre_driver_wgpu::megakernel::MegakernelCaps
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::megakernel::MegakernelCaps
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::megakernel::MegakernelCaps
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::megakernel::MegakernelCaps where U: core::convert::From<T>
pub fn vyre_driver_wgpu::megakernel::MegakernelCaps::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::megakernel::MegakernelCaps where U: core::convert::Into<T>
pub type vyre_driver_wgpu::megakernel::MegakernelCaps::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::megakernel::MegakernelCaps::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::megakernel::MegakernelCaps where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::megakernel::MegakernelCaps::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::megakernel::MegakernelCaps::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::megakernel::MegakernelCaps where T: core::clone::Clone
pub type vyre_driver_wgpu::megakernel::MegakernelCaps::Owned = T
pub fn vyre_driver_wgpu::megakernel::MegakernelCaps::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::megakernel::MegakernelCaps::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::megakernel::MegakernelCaps where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::megakernel::MegakernelCaps::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::megakernel::MegakernelCaps where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::megakernel::MegakernelCaps::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::megakernel::MegakernelCaps where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::megakernel::MegakernelCaps::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::megakernel::MegakernelCaps where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::megakernel::MegakernelCaps::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::megakernel::MegakernelCaps
pub fn vyre_driver_wgpu::megakernel::MegakernelCaps::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::megakernel::MegakernelCaps
pub type vyre_driver_wgpu::megakernel::MegakernelCaps::Init = T
pub const vyre_driver_wgpu::megakernel::MegakernelCaps::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::megakernel::MegakernelCaps::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::megakernel::MegakernelCaps::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::megakernel::MegakernelCaps::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::megakernel::MegakernelCaps::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::megakernel::MegakernelCaps
pub fn vyre_driver_wgpu::megakernel::MegakernelCaps::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::megakernel::MegakernelCaps
pub fn vyre_driver_wgpu::megakernel::MegakernelCaps::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::megakernel::MegakernelCaps
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::megakernel::MegakernelCaps
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::megakernel::MegakernelCaps where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::megakernel::MegakernelCaps where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::megakernel::MegakernelCaps where T: core::marker::Sync
pub struct vyre_driver_wgpu::megakernel::MegakernelConfig
pub vyre_driver_wgpu::megakernel::MegakernelConfig::expected_items_per_worker: u32
pub vyre_driver_wgpu::megakernel::MegakernelConfig::max_wall_time: core::time::Duration
pub vyre_driver_wgpu::megakernel::MegakernelConfig::worker_count: u32
impl vyre_driver_wgpu::megakernel::MegakernelConfig
pub fn vyre_driver_wgpu::megakernel::MegakernelConfig::validate(&self) -> core::result::Result<(), vyre_driver::backend::BackendError>
impl core::clone::Clone for vyre_driver_wgpu::megakernel::MegakernelConfig
pub fn vyre_driver_wgpu::megakernel::MegakernelConfig::clone(&self) -> vyre_driver_wgpu::megakernel::MegakernelConfig
impl core::default::Default for vyre_driver_wgpu::megakernel::MegakernelConfig
pub fn vyre_driver_wgpu::megakernel::MegakernelConfig::default() -> Self
impl core::fmt::Debug for vyre_driver_wgpu::megakernel::MegakernelConfig
pub fn vyre_driver_wgpu::megakernel::MegakernelConfig::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver_wgpu::megakernel::MegakernelConfig
impl core::marker::Send for vyre_driver_wgpu::megakernel::MegakernelConfig
impl core::marker::Sync for vyre_driver_wgpu::megakernel::MegakernelConfig
impl core::marker::Unpin for vyre_driver_wgpu::megakernel::MegakernelConfig
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::megakernel::MegakernelConfig
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::megakernel::MegakernelConfig
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::megakernel::MegakernelConfig where U: core::convert::From<T>
pub fn vyre_driver_wgpu::megakernel::MegakernelConfig::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::megakernel::MegakernelConfig where U: core::convert::Into<T>
pub type vyre_driver_wgpu::megakernel::MegakernelConfig::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::megakernel::MegakernelConfig::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::megakernel::MegakernelConfig where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::megakernel::MegakernelConfig::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::megakernel::MegakernelConfig::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::megakernel::MegakernelConfig where T: core::clone::Clone
pub type vyre_driver_wgpu::megakernel::MegakernelConfig::Owned = T
pub fn vyre_driver_wgpu::megakernel::MegakernelConfig::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::megakernel::MegakernelConfig::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::megakernel::MegakernelConfig where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::megakernel::MegakernelConfig::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::megakernel::MegakernelConfig where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::megakernel::MegakernelConfig::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::megakernel::MegakernelConfig where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::megakernel::MegakernelConfig::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::megakernel::MegakernelConfig where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::megakernel::MegakernelConfig::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::megakernel::MegakernelConfig
pub fn vyre_driver_wgpu::megakernel::MegakernelConfig::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::megakernel::MegakernelConfig
pub type vyre_driver_wgpu::megakernel::MegakernelConfig::Init = T
pub const vyre_driver_wgpu::megakernel::MegakernelConfig::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::megakernel::MegakernelConfig::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::megakernel::MegakernelConfig::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::megakernel::MegakernelConfig::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::megakernel::MegakernelConfig::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::megakernel::MegakernelConfig
pub fn vyre_driver_wgpu::megakernel::MegakernelConfig::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::megakernel::MegakernelConfig
pub fn vyre_driver_wgpu::megakernel::MegakernelConfig::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::megakernel::MegakernelConfig
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::megakernel::MegakernelConfig
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::megakernel::MegakernelConfig where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::megakernel::MegakernelConfig where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::megakernel::MegakernelConfig where T: core::marker::Sync
pub struct vyre_driver_wgpu::megakernel::MegakernelReport
pub vyre_driver_wgpu::megakernel::MegakernelReport::items_processed: u64
pub vyre_driver_wgpu::megakernel::MegakernelReport::items_remaining: u64
pub vyre_driver_wgpu::megakernel::MegakernelReport::wall_time: core::time::Duration
impl core::clone::Clone for vyre_driver_wgpu::megakernel::MegakernelReport
pub fn vyre_driver_wgpu::megakernel::MegakernelReport::clone(&self) -> vyre_driver_wgpu::megakernel::MegakernelReport
impl core::default::Default for vyre_driver_wgpu::megakernel::MegakernelReport
pub fn vyre_driver_wgpu::megakernel::MegakernelReport::default() -> vyre_driver_wgpu::megakernel::MegakernelReport
impl core::fmt::Debug for vyre_driver_wgpu::megakernel::MegakernelReport
pub fn vyre_driver_wgpu::megakernel::MegakernelReport::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver_wgpu::megakernel::MegakernelReport
impl core::marker::Send for vyre_driver_wgpu::megakernel::MegakernelReport
impl core::marker::Sync for vyre_driver_wgpu::megakernel::MegakernelReport
impl core::marker::Unpin for vyre_driver_wgpu::megakernel::MegakernelReport
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::megakernel::MegakernelReport
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::megakernel::MegakernelReport
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::megakernel::MegakernelReport where U: core::convert::From<T>
pub fn vyre_driver_wgpu::megakernel::MegakernelReport::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::megakernel::MegakernelReport where U: core::convert::Into<T>
pub type vyre_driver_wgpu::megakernel::MegakernelReport::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::megakernel::MegakernelReport::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::megakernel::MegakernelReport where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::megakernel::MegakernelReport::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::megakernel::MegakernelReport::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::megakernel::MegakernelReport where T: core::clone::Clone
pub type vyre_driver_wgpu::megakernel::MegakernelReport::Owned = T
pub fn vyre_driver_wgpu::megakernel::MegakernelReport::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::megakernel::MegakernelReport::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::megakernel::MegakernelReport where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::megakernel::MegakernelReport::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::megakernel::MegakernelReport where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::megakernel::MegakernelReport::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::megakernel::MegakernelReport where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::megakernel::MegakernelReport::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::megakernel::MegakernelReport where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::megakernel::MegakernelReport::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::megakernel::MegakernelReport
pub fn vyre_driver_wgpu::megakernel::MegakernelReport::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::megakernel::MegakernelReport
pub type vyre_driver_wgpu::megakernel::MegakernelReport::Init = T
pub const vyre_driver_wgpu::megakernel::MegakernelReport::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::megakernel::MegakernelReport::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::megakernel::MegakernelReport::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::megakernel::MegakernelReport::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::megakernel::MegakernelReport::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::megakernel::MegakernelReport
pub fn vyre_driver_wgpu::megakernel::MegakernelReport::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::megakernel::MegakernelReport
pub fn vyre_driver_wgpu::megakernel::MegakernelReport::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::megakernel::MegakernelReport
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::megakernel::MegakernelReport
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::megakernel::MegakernelReport where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::megakernel::MegakernelReport where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::megakernel::MegakernelReport where T: core::marker::Sync
#[repr(C)] pub struct vyre_driver_wgpu::megakernel::WorkItem
pub vyre_driver_wgpu::megakernel::WorkItem::input_handle: u32
pub vyre_driver_wgpu::megakernel::WorkItem::op_handle: u32
pub vyre_driver_wgpu::megakernel::WorkItem::output_handle: u32
pub vyre_driver_wgpu::megakernel::WorkItem::param: u32
impl bytemuck::pod::Pod for vyre_driver_wgpu::megakernel::WorkItem
impl bytemuck::zeroable::Zeroable for vyre_driver_wgpu::megakernel::WorkItem
impl core::clone::Clone for vyre_driver_wgpu::megakernel::WorkItem
pub fn vyre_driver_wgpu::megakernel::WorkItem::clone(&self) -> vyre_driver_wgpu::megakernel::WorkItem
impl core::fmt::Debug for vyre_driver_wgpu::megakernel::WorkItem
pub fn vyre_driver_wgpu::megakernel::WorkItem::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::megakernel::WorkItem
impl core::marker::Freeze for vyre_driver_wgpu::megakernel::WorkItem
impl core::marker::Send for vyre_driver_wgpu::megakernel::WorkItem
impl core::marker::Sync for vyre_driver_wgpu::megakernel::WorkItem
impl core::marker::Unpin for vyre_driver_wgpu::megakernel::WorkItem
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::megakernel::WorkItem
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::megakernel::WorkItem
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::megakernel::WorkItem where U: core::convert::From<T>
pub fn vyre_driver_wgpu::megakernel::WorkItem::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::megakernel::WorkItem where U: core::convert::Into<T>
pub type vyre_driver_wgpu::megakernel::WorkItem::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::megakernel::WorkItem::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::megakernel::WorkItem where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::megakernel::WorkItem::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::megakernel::WorkItem::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::megakernel::WorkItem where T: core::clone::Clone
pub type vyre_driver_wgpu::megakernel::WorkItem::Owned = T
pub fn vyre_driver_wgpu::megakernel::WorkItem::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::megakernel::WorkItem::to_owned(&self) -> T
impl<T> bytemuck::anybitpattern::AnyBitPattern for vyre_driver_wgpu::megakernel::WorkItem where T: bytemuck::pod::Pod
impl<T> bytemuck::checked::CheckedBitPattern for vyre_driver_wgpu::megakernel::WorkItem where T: bytemuck::anybitpattern::AnyBitPattern
pub type vyre_driver_wgpu::megakernel::WorkItem::Bits = T
pub fn vyre_driver_wgpu::megakernel::WorkItem::is_valid_bit_pattern(_bits: &T) -> bool
impl<T> bytemuck::no_uninit::NoUninit for vyre_driver_wgpu::megakernel::WorkItem where T: bytemuck::pod::Pod
impl<T> core::any::Any for vyre_driver_wgpu::megakernel::WorkItem where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::megakernel::WorkItem::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::megakernel::WorkItem where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::megakernel::WorkItem::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::megakernel::WorkItem where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::megakernel::WorkItem::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::megakernel::WorkItem where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::megakernel::WorkItem::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::megakernel::WorkItem
pub fn vyre_driver_wgpu::megakernel::WorkItem::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::megakernel::WorkItem
pub type vyre_driver_wgpu::megakernel::WorkItem::Init = T
pub const vyre_driver_wgpu::megakernel::WorkItem::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::megakernel::WorkItem::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::megakernel::WorkItem::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::megakernel::WorkItem::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::megakernel::WorkItem::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::megakernel::WorkItem
pub fn vyre_driver_wgpu::megakernel::WorkItem::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::megakernel::WorkItem
pub fn vyre_driver_wgpu::megakernel::WorkItem::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::megakernel::WorkItem
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::megakernel::WorkItem
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::megakernel::WorkItem where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::megakernel::WorkItem where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::megakernel::WorkItem where T: core::marker::Sync
pub trait vyre_driver_wgpu::megakernel::MegakernelDispatch
pub fn vyre_driver_wgpu::megakernel::MegakernelDispatch::dispatch_megakernel(&self, work_queue: &vyre_driver_wgpu::buffer::GpuBufferHandle, config: &vyre_driver_wgpu::megakernel::MegakernelConfig) -> core::result::Result<vyre_driver_wgpu::megakernel::MegakernelReport, vyre_driver::backend::BackendError>
pub mod vyre_driver_wgpu::pipeline
pub struct vyre_driver_wgpu::pipeline::BindGroupCacheStats
pub vyre_driver_wgpu::pipeline::BindGroupCacheStats::entries: usize
pub vyre_driver_wgpu::pipeline::BindGroupCacheStats::evictions: usize
pub vyre_driver_wgpu::pipeline::BindGroupCacheStats::hits: usize
pub vyre_driver_wgpu::pipeline::BindGroupCacheStats::misses: usize
impl core::clone::Clone for vyre_driver_wgpu::pipeline::BindGroupCacheStats
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::clone(&self) -> vyre_driver_wgpu::pipeline::BindGroupCacheStats
impl core::cmp::Eq for vyre_driver_wgpu::pipeline::BindGroupCacheStats
impl core::cmp::PartialEq for vyre_driver_wgpu::pipeline::BindGroupCacheStats
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::eq(&self, other: &vyre_driver_wgpu::pipeline::BindGroupCacheStats) -> bool
impl core::default::Default for vyre_driver_wgpu::pipeline::BindGroupCacheStats
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::default() -> vyre_driver_wgpu::pipeline::BindGroupCacheStats
impl core::fmt::Debug for vyre_driver_wgpu::pipeline::BindGroupCacheStats
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::pipeline::BindGroupCacheStats
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::pipeline::BindGroupCacheStats
impl core::marker::Freeze for vyre_driver_wgpu::pipeline::BindGroupCacheStats
impl core::marker::Send for vyre_driver_wgpu::pipeline::BindGroupCacheStats
impl core::marker::Sync for vyre_driver_wgpu::pipeline::BindGroupCacheStats
impl core::marker::Unpin for vyre_driver_wgpu::pipeline::BindGroupCacheStats
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::pipeline::BindGroupCacheStats
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::pipeline::BindGroupCacheStats
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::pipeline::BindGroupCacheStats where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::pipeline::BindGroupCacheStats where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::pipeline::BindGroupCacheStats where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::pipeline::BindGroupCacheStats where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::pipeline::BindGroupCacheStats where U: core::convert::From<T>
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::pipeline::BindGroupCacheStats where U: core::convert::Into<T>
pub type vyre_driver_wgpu::pipeline::BindGroupCacheStats::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::pipeline::BindGroupCacheStats where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::pipeline::BindGroupCacheStats::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::pipeline::BindGroupCacheStats where T: core::clone::Clone
pub type vyre_driver_wgpu::pipeline::BindGroupCacheStats::Owned = T
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::pipeline::BindGroupCacheStats where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::pipeline::BindGroupCacheStats where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::pipeline::BindGroupCacheStats where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::pipeline::BindGroupCacheStats where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::pipeline::BindGroupCacheStats
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::pipeline::BindGroupCacheStats
pub type vyre_driver_wgpu::pipeline::BindGroupCacheStats::Init = T
pub const vyre_driver_wgpu::pipeline::BindGroupCacheStats::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::pipeline::BindGroupCacheStats
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::pipeline::BindGroupCacheStats
pub fn vyre_driver_wgpu::pipeline::BindGroupCacheStats::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::pipeline::BindGroupCacheStats
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::pipeline::BindGroupCacheStats
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::pipeline::BindGroupCacheStats where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::pipeline::BindGroupCacheStats where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::pipeline::BindGroupCacheStats where T: core::marker::Sync
pub struct vyre_driver_wgpu::pipeline::DispatchItem<'a>
pub vyre_driver_wgpu::pipeline::DispatchItem::inputs: &'a [vyre_driver_wgpu::buffer::GpuBufferHandle]
pub vyre_driver_wgpu::pipeline::DispatchItem::outputs: &'a [vyre_driver_wgpu::buffer::GpuBufferHandle]
pub vyre_driver_wgpu::pipeline::DispatchItem::params: core::option::Option<&'a vyre_driver_wgpu::buffer::GpuBufferHandle>
pub vyre_driver_wgpu::pipeline::DispatchItem::workgroups: [u32; 3]
impl<'a> core::marker::Freeze for vyre_driver_wgpu::pipeline::DispatchItem<'a>
impl<'a> core::marker::Send for vyre_driver_wgpu::pipeline::DispatchItem<'a>
impl<'a> core::marker::Sync for vyre_driver_wgpu::pipeline::DispatchItem<'a>
impl<'a> core::marker::Unpin for vyre_driver_wgpu::pipeline::DispatchItem<'a>
impl<'a> !core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::pipeline::DispatchItem<'a>
impl<'a> !core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::pipeline::DispatchItem<'a>
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::pipeline::DispatchItem<'a> where U: core::convert::From<T>
pub fn vyre_driver_wgpu::pipeline::DispatchItem<'a>::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::pipeline::DispatchItem<'a> where U: core::convert::Into<T>
pub type vyre_driver_wgpu::pipeline::DispatchItem<'a>::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::pipeline::DispatchItem<'a>::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::pipeline::DispatchItem<'a> where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::pipeline::DispatchItem<'a>::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::pipeline::DispatchItem<'a>::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::pipeline::DispatchItem<'a> where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::DispatchItem<'a>::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::pipeline::DispatchItem<'a> where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::DispatchItem<'a>::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::pipeline::DispatchItem<'a> where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::DispatchItem<'a>::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::pipeline::DispatchItem<'a>
pub fn vyre_driver_wgpu::pipeline::DispatchItem<'a>::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::pipeline::DispatchItem<'a>
pub type vyre_driver_wgpu::pipeline::DispatchItem<'a>::Init = T
pub const vyre_driver_wgpu::pipeline::DispatchItem<'a>::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::pipeline::DispatchItem<'a>::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::pipeline::DispatchItem<'a>::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::pipeline::DispatchItem<'a>::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::pipeline::DispatchItem<'a>::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::pipeline::DispatchItem<'a>
pub fn vyre_driver_wgpu::pipeline::DispatchItem<'a>::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::pipeline::DispatchItem<'a>
pub fn vyre_driver_wgpu::pipeline::DispatchItem<'a>::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::pipeline::DispatchItem<'a>
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::pipeline::DispatchItem<'a>
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::pipeline::DispatchItem<'a> where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::pipeline::DispatchItem<'a> where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::pipeline::DispatchItem<'a> where T: core::marker::Sync
pub struct vyre_driver_wgpu::pipeline::IndirectDispatch
pub vyre_driver_wgpu::pipeline::IndirectDispatch::count_buffer: alloc::string::String
pub vyre_driver_wgpu::pipeline::IndirectDispatch::count_offset: u64
impl core::clone::Clone for vyre_driver_wgpu::pipeline::IndirectDispatch
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::clone(&self) -> vyre_driver_wgpu::pipeline::IndirectDispatch
impl core::cmp::Eq for vyre_driver_wgpu::pipeline::IndirectDispatch
impl core::cmp::PartialEq for vyre_driver_wgpu::pipeline::IndirectDispatch
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::eq(&self, other: &vyre_driver_wgpu::pipeline::IndirectDispatch) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::pipeline::IndirectDispatch
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::pipeline::IndirectDispatch
impl core::marker::Freeze for vyre_driver_wgpu::pipeline::IndirectDispatch
impl core::marker::Send for vyre_driver_wgpu::pipeline::IndirectDispatch
impl core::marker::Sync for vyre_driver_wgpu::pipeline::IndirectDispatch
impl core::marker::Unpin for vyre_driver_wgpu::pipeline::IndirectDispatch
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::pipeline::IndirectDispatch
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::pipeline::IndirectDispatch
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::pipeline::IndirectDispatch where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::pipeline::IndirectDispatch where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::pipeline::IndirectDispatch where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::pipeline::IndirectDispatch where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::pipeline::IndirectDispatch where U: core::convert::From<T>
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::pipeline::IndirectDispatch where U: core::convert::Into<T>
pub type vyre_driver_wgpu::pipeline::IndirectDispatch::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::pipeline::IndirectDispatch where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::pipeline::IndirectDispatch::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::pipeline::IndirectDispatch where T: core::clone::Clone
pub type vyre_driver_wgpu::pipeline::IndirectDispatch::Owned = T
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::pipeline::IndirectDispatch where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::pipeline::IndirectDispatch where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::pipeline::IndirectDispatch where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::pipeline::IndirectDispatch where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::pipeline::IndirectDispatch::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::pipeline::IndirectDispatch
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::pipeline::IndirectDispatch
pub type vyre_driver_wgpu::pipeline::IndirectDispatch::Init = T
pub const vyre_driver_wgpu::pipeline::IndirectDispatch::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::pipeline::IndirectDispatch::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::pipeline::IndirectDispatch::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::pipeline::IndirectDispatch::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::pipeline::IndirectDispatch::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::pipeline::IndirectDispatch
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::pipeline::IndirectDispatch
pub fn vyre_driver_wgpu::pipeline::IndirectDispatch::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::pipeline::IndirectDispatch
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::pipeline::IndirectDispatch
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::pipeline::IndirectDispatch where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::pipeline::IndirectDispatch where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::pipeline::IndirectDispatch where T: core::marker::Sync
pub struct vyre_driver_wgpu::pipeline::OutputLayout
pub vyre_driver_wgpu::pipeline::OutputLayout::copy_offset: usize
pub vyre_driver_wgpu::pipeline::OutputLayout::copy_size: usize
pub vyre_driver_wgpu::pipeline::OutputLayout::full_size: usize
pub vyre_driver_wgpu::pipeline::OutputLayout::read_size: usize
pub vyre_driver_wgpu::pipeline::OutputLayout::trim_start: usize
impl core::clone::Clone for vyre_driver_wgpu::pipeline::OutputLayout
pub fn vyre_driver_wgpu::pipeline::OutputLayout::clone(&self) -> vyre_driver_wgpu::pipeline::OutputLayout
impl core::cmp::Eq for vyre_driver_wgpu::pipeline::OutputLayout
impl core::cmp::PartialEq for vyre_driver_wgpu::pipeline::OutputLayout
pub fn vyre_driver_wgpu::pipeline::OutputLayout::eq(&self, other: &vyre_driver_wgpu::pipeline::OutputLayout) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::pipeline::OutputLayout
pub fn vyre_driver_wgpu::pipeline::OutputLayout::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::pipeline::OutputLayout
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::pipeline::OutputLayout
impl core::marker::Freeze for vyre_driver_wgpu::pipeline::OutputLayout
impl core::marker::Send for vyre_driver_wgpu::pipeline::OutputLayout
impl core::marker::Sync for vyre_driver_wgpu::pipeline::OutputLayout
impl core::marker::Unpin for vyre_driver_wgpu::pipeline::OutputLayout
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::pipeline::OutputLayout
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::pipeline::OutputLayout
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::pipeline::OutputLayout where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::OutputLayout::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::pipeline::OutputLayout where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::pipeline::OutputLayout where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::pipeline::OutputLayout where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::OutputLayout::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::pipeline::OutputLayout::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::pipeline::OutputLayout::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::pipeline::OutputLayout where U: core::convert::From<T>
pub fn vyre_driver_wgpu::pipeline::OutputLayout::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::pipeline::OutputLayout where U: core::convert::Into<T>
pub type vyre_driver_wgpu::pipeline::OutputLayout::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::pipeline::OutputLayout::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::pipeline::OutputLayout where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::pipeline::OutputLayout::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::pipeline::OutputLayout::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::pipeline::OutputLayout where T: core::clone::Clone
pub type vyre_driver_wgpu::pipeline::OutputLayout::Owned = T
pub fn vyre_driver_wgpu::pipeline::OutputLayout::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::pipeline::OutputLayout::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::pipeline::OutputLayout where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::OutputLayout::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::pipeline::OutputLayout where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::OutputLayout::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::pipeline::OutputLayout where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::OutputLayout::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::pipeline::OutputLayout where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::pipeline::OutputLayout::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::pipeline::OutputLayout
pub fn vyre_driver_wgpu::pipeline::OutputLayout::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::pipeline::OutputLayout
pub type vyre_driver_wgpu::pipeline::OutputLayout::Init = T
pub const vyre_driver_wgpu::pipeline::OutputLayout::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::pipeline::OutputLayout::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::pipeline::OutputLayout::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::pipeline::OutputLayout::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::pipeline::OutputLayout::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::pipeline::OutputLayout
pub fn vyre_driver_wgpu::pipeline::OutputLayout::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::pipeline::OutputLayout
pub fn vyre_driver_wgpu::pipeline::OutputLayout::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::pipeline::OutputLayout
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::pipeline::OutputLayout
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::pipeline::OutputLayout where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::pipeline::OutputLayout where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::pipeline::OutputLayout where T: core::marker::Sync
pub struct vyre_driver_wgpu::pipeline::WgpuPipeline
impl vyre_driver_wgpu::pipeline::WgpuPipeline
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::bind_group_cache_stats(&self) -> vyre_driver_wgpu::pipeline::BindGroupCacheStats
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::dispatch_persistent(&self, inputs: &[vyre_driver_wgpu::buffer::GpuBufferHandle], outputs: &mut [vyre_driver_wgpu::buffer::GpuBufferHandle], params: core::option::Option<&vyre_driver_wgpu::buffer::GpuBufferHandle>, workgroups: [u32; 3]) -> core::result::Result<(), vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::dispatch_persistent_batched(&self, items: &[vyre_driver_wgpu::pipeline::DispatchItem<'_>]) -> core::result::Result<(), vyre_driver::backend::BackendError>
impl vyre_driver_wgpu::pipeline::WgpuPipeline
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::compile(program: &vyre_foundation::ir_inner::model::program::Program) -> core::result::Result<alloc::sync::Arc<Self>, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::compile_with_config(program: &vyre_foundation::ir_inner::model::program::Program, config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::sync::Arc<Self>, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::push_chunk(&self, bytes: &[u8], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::backend::BackendError>
impl vyre_driver_wgpu::pipeline::WgpuPipeline
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::dispatch_coalesced(&self, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<alloc::vec::Vec<u8>>>, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::dispatch_compound(requests: &[(&vyre_driver_wgpu::pipeline::WgpuPipeline, &[u8])], _config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<alloc::vec::Vec<u8>>>, vyre_driver::backend::BackendError>
impl vyre_driver_wgpu::pipeline::WgpuPipeline
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::prerecord_borrowed_dispatch(&self, inputs: &[&[u8]], workgroups: [u32; 3]) -> core::result::Result<vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::prerecord_persistent_dispatch(&self, inputs: &[vyre_driver_wgpu::buffer::GpuBufferHandle], outputs: &[vyre_driver_wgpu::buffer::GpuBufferHandle], params: core::option::Option<&vyre_driver_wgpu::buffer::GpuBufferHandle>, workgroups: [u32; 3]) -> core::result::Result<vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch, vyre_driver::backend::BackendError>
impl core::clone::Clone for vyre_driver_wgpu::pipeline::WgpuPipeline
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::clone(&self) -> vyre_driver_wgpu::pipeline::WgpuPipeline
impl core::fmt::Debug for vyre_driver_wgpu::pipeline::WgpuPipeline
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl vyre_driver::backend::CompiledPipeline for vyre_driver_wgpu::pipeline::WgpuPipeline
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::dispatch(&self, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::dispatch_borrowed(&self, inputs: &[&[u8]], _config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::id(&self) -> &str
impl core::marker::Freeze for vyre_driver_wgpu::pipeline::WgpuPipeline
impl core::marker::Send for vyre_driver_wgpu::pipeline::WgpuPipeline
impl core::marker::Sync for vyre_driver_wgpu::pipeline::WgpuPipeline
impl core::marker::Unpin for vyre_driver_wgpu::pipeline::WgpuPipeline
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::pipeline::WgpuPipeline
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::pipeline::WgpuPipeline
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::pipeline::WgpuPipeline where U: core::convert::From<T>
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::pipeline::WgpuPipeline where U: core::convert::Into<T>
pub type vyre_driver_wgpu::pipeline::WgpuPipeline::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::pipeline::WgpuPipeline where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::pipeline::WgpuPipeline::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::pipeline::WgpuPipeline where T: core::clone::Clone
pub type vyre_driver_wgpu::pipeline::WgpuPipeline::Owned = T
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::pipeline::WgpuPipeline where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::pipeline::WgpuPipeline where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::pipeline::WgpuPipeline where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::pipeline::WgpuPipeline where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::pipeline::WgpuPipeline::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::pipeline::WgpuPipeline
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::pipeline::WgpuPipeline
pub type vyre_driver_wgpu::pipeline::WgpuPipeline::Init = T
pub const vyre_driver_wgpu::pipeline::WgpuPipeline::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::pipeline::WgpuPipeline::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::pipeline::WgpuPipeline::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::pipeline::WgpuPipeline::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::pipeline::WgpuPipeline::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::pipeline::WgpuPipeline
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::pipeline::WgpuPipeline
pub fn vyre_driver_wgpu::pipeline::WgpuPipeline::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::pipeline::WgpuPipeline
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::pipeline::WgpuPipeline
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::pipeline::WgpuPipeline where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::pipeline::WgpuPipeline where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::pipeline::WgpuPipeline where T: core::marker::Sync
pub const vyre_driver_wgpu::pipeline::MAX_PIPELINE_CACHE_ENTRIES: usize
pub fn vyre_driver_wgpu::pipeline::output_layout_from_program(program: &vyre_foundation::ir_inner::model::program::Program) -> core::result::Result<vyre_driver_wgpu::pipeline::OutputLayout, vyre_driver::backend::BackendError>
pub mod vyre_driver_wgpu::runtime
pub mod vyre_driver_wgpu::runtime::adapter_caps_probe
pub fn vyre_driver_wgpu::runtime::adapter_caps_probe::probe(adapter: &wgpu::api::adapter::Adapter) -> vyre_foundation::optimizer::ctx::AdapterCaps
pub mod vyre_driver_wgpu::runtime::aot
pub struct vyre_driver_wgpu::runtime::aot::AotArtifact
pub vyre_driver_wgpu::runtime::aot::AotArtifact::cache_hit: bool
pub vyre_driver_wgpu::runtime::aot::AotArtifact::key: alloc::string::String
pub vyre_driver_wgpu::runtime::aot::AotArtifact::wgsl: alloc::string::String
impl core::clone::Clone for vyre_driver_wgpu::runtime::aot::AotArtifact
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::clone(&self) -> vyre_driver_wgpu::runtime::aot::AotArtifact
impl core::cmp::Eq for vyre_driver_wgpu::runtime::aot::AotArtifact
impl core::cmp::PartialEq for vyre_driver_wgpu::runtime::aot::AotArtifact
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::eq(&self, other: &vyre_driver_wgpu::runtime::aot::AotArtifact) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::runtime::aot::AotArtifact
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::runtime::aot::AotArtifact
impl core::marker::Freeze for vyre_driver_wgpu::runtime::aot::AotArtifact
impl core::marker::Send for vyre_driver_wgpu::runtime::aot::AotArtifact
impl core::marker::Sync for vyre_driver_wgpu::runtime::aot::AotArtifact
impl core::marker::Unpin for vyre_driver_wgpu::runtime::aot::AotArtifact
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::aot::AotArtifact
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::aot::AotArtifact
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::runtime::aot::AotArtifact where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::aot::AotArtifact where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::aot::AotArtifact where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::aot::AotArtifact where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::aot::AotArtifact where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::aot::AotArtifact where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::aot::AotArtifact::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::aot::AotArtifact where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::aot::AotArtifact::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::aot::AotArtifact where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::aot::AotArtifact::Owned = T
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::aot::AotArtifact where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::aot::AotArtifact where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::aot::AotArtifact where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::aot::AotArtifact where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::aot::AotArtifact::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::aot::AotArtifact
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::aot::AotArtifact
pub type vyre_driver_wgpu::runtime::aot::AotArtifact::Init = T
pub const vyre_driver_wgpu::runtime::aot::AotArtifact::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::aot::AotArtifact::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::aot::AotArtifact::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::aot::AotArtifact::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::aot::AotArtifact::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::aot::AotArtifact
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::aot::AotArtifact
pub fn vyre_driver_wgpu::runtime::aot::AotArtifact::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::aot::AotArtifact
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::aot::AotArtifact
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::aot::AotArtifact where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::aot::AotArtifact where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::aot::AotArtifact where T: core::marker::Sync
pub fn vyre_driver_wgpu::runtime::aot::backend_fingerprint() -> alloc::string::String
pub fn vyre_driver_wgpu::runtime::aot::cache_dir() -> std::path::PathBuf
pub fn vyre_driver_wgpu::runtime::aot::cache_key(spec_hash: &str, backend_fingerprint: &str) -> alloc::string::String
pub fn vyre_driver_wgpu::runtime::aot::load_or_compile(program: &vyre_foundation::ir_inner::model::program::Program, fingerprint: &str) -> core::result::Result<vyre_driver_wgpu::runtime::aot::AotArtifact, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::runtime::aot::load_or_compile_with_config(program: &vyre_foundation::ir_inner::model::program::Program, fingerprint: &str, config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<vyre_driver_wgpu::runtime::aot::AotArtifact, vyre_driver::backend::BackendError>
pub mod vyre_driver_wgpu::runtime::cache
pub mod vyre_driver_wgpu::runtime::cache::buffer_pool
pub struct vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::acquire(&self, device: &wgpu::api::device::Device, label: &str, size: u64, usage: wgpu_types::BufferUsages) -> vyre_foundation::error::Result<vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer>
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::global() -> &'static Self
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::new() -> Self
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::release(&self, buffer: vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer)
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::with_buffer<R>(&self, device: &wgpu::api::device::Device, label: &str, size: u64, usage: wgpu_types::BufferUsages, f: impl core::ops::function::FnOnce(&wgpu::api::buffer::Buffer) -> R) -> vyre_foundation::error::Result<R>
impl core::clone::Clone for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::clone(&self) -> vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl core::default::Default for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::default() -> vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::Owned = T
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::Init = T
pub const vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where T: core::marker::Sync
pub struct vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
impl core::clone::Clone for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::clone(&self) -> vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
impl core::cmp::Eq for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
impl core::cmp::PartialEq for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::eq(&self, other: &vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError) -> bool
impl core::convert::From<vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError> for vyre_foundation::error::Error
pub fn vyre_foundation::error::Error::from(error: vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError) -> Self
impl core::error::Error for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
impl core::fmt::Debug for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::Owned = T
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::Init = T
pub const vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError where T: core::marker::Sync
pub struct vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
impl vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::buffer(&self) -> core::result::Result<&wgpu::api::buffer::Buffer, vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError>
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::buffer_id(&self) -> u64
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::size(&self) -> u64
impl core::ops::drop::Drop for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::drop(&mut self)
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::Init = T
pub const vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where T: core::marker::Sync
pub mod vyre_driver_wgpu::runtime::cache::cache_entry
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::cache::cache_entry::CacheEntry
pub vyre_driver_wgpu::runtime::cache::cache_entry::CacheEntry::key: u64
pub vyre_driver_wgpu::runtime::cache::cache_entry::CacheEntry::size: u64
pub vyre_driver_wgpu::runtime::cache::cache_entry::CacheEntry::tier: usize
impl core::clone::Clone for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::clone(&self) -> vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::cmp::Eq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::cmp::PartialEq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::eq(&self, other: &vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::Owned = T
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: core::marker::Sync
pub mod vyre_driver_wgpu::runtime::cache::cache_tier
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::cache::cache_tier::CacheTier
pub vyre_driver_wgpu::runtime::cache::cache_tier::CacheTier::capacity: u64
pub vyre_driver_wgpu::runtime::cache::cache_tier::CacheTier::name: alloc::string::String
pub vyre_driver_wgpu::runtime::cache::cache_tier::CacheTier::used: u64
impl vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::new(name: impl core::convert::Into<alloc::string::String>, capacity: u64) -> Self
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: core::marker::Sync
pub mod vyre_driver_wgpu::runtime::cache::disk
pub struct vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::device: u32
pub vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::driver: u32
pub vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::vendor: u32
impl vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::fold_into(&self, digest: [u8; 32]) -> [u8; 32]
impl core::clone::Clone for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::clone(&self) -> vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::cmp::Eq for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::cmp::PartialEq for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::eq(&self, other: &vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::Owned = T
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub type vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::Init = T
pub const vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where T: core::marker::Sync
pub struct vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
impl vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::default_root() -> std::path::PathBuf
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::open(root: impl core::convert::Into<std::path::PathBuf>) -> std::io::error::Result<Self>
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::path_for(&self, program_blake3: [u8; 32], fp: vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint) -> std::path::PathBuf
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::read(&self, program_blake3: [u8; 32], fp: vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint) -> std::io::error::Result<core::option::Option<alloc::vec::Vec<u8>>>
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::root(&self) -> &std::path::Path
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::write(&self, program_blake3: [u8; 32], fp: vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint, bytes: &[u8]) -> std::io::error::Result<()>
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
pub type vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::Init = T
pub const vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where T: core::marker::Sync
pub mod vyre_driver_wgpu::runtime::cache::lru
pub struct vyre_driver_wgpu::runtime::cache::lru::AccessMeta
pub vyre_driver_wgpu::runtime::cache::lru::AccessMeta::frequency: u32
pub vyre_driver_wgpu::runtime::cache::lru::AccessMeta::last_access: u64
pub vyre_driver_wgpu::runtime::cache::lru::AccessMeta::size: u64
impl core::clone::Clone for vyre_driver_wgpu::runtime::cache::lru::AccessMeta
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::clone(&self) -> vyre_driver_wgpu::runtime::cache::lru::AccessMeta
impl core::default::Default for vyre_driver_wgpu::runtime::cache::lru::AccessMeta
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::default() -> vyre_driver_wgpu::runtime::cache::lru::AccessMeta
impl core::fmt::Debug for vyre_driver_wgpu::runtime::cache::lru::AccessMeta
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::runtime::cache::lru::AccessMeta
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::lru::AccessMeta
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::lru::AccessMeta
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::lru::AccessMeta
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::lru::AccessMeta
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::lru::AccessMeta
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::lru::AccessMeta
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::lru::AccessMeta where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::lru::AccessMeta where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::lru::AccessMeta::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::lru::AccessMeta where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::lru::AccessMeta::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::cache::lru::AccessMeta where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::cache::lru::AccessMeta::Owned = T
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::lru::AccessMeta where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::lru::AccessMeta where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::lru::AccessMeta where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::cache::lru::AccessMeta where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::lru::AccessMeta
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::lru::AccessMeta
pub type vyre_driver_wgpu::runtime::cache::lru::AccessMeta::Init = T
pub const vyre_driver_wgpu::runtime::cache::lru::AccessMeta::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::lru::AccessMeta
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::lru::AccessMeta
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessMeta::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::lru::AccessMeta
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::lru::AccessMeta
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::lru::AccessMeta where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::lru::AccessMeta where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::lru::AccessMeta where T: core::marker::Sync
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::hot_set(&self, n: usize) -> alloc::vec::Vec<u64>
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::new() -> Self
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::record(&mut self, key: u64)
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::stats(&self, key: u64) -> core::option::Option<vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats>
impl core::default::Default for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::default() -> Self
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::lru::AccessTracker::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::lru::AccessTracker::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub type vyre_driver_wgpu::runtime::cache::lru::AccessTracker::Init = T
pub const vyre_driver_wgpu::runtime::cache::lru::AccessTracker::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: core::marker::Sync
pub struct vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>
impl<K, V> vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V> where K: core::hash::Hash + core::cmp::Eq + core::marker::Copy, V: core::default::Default
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::ensure(&mut self, key: K) -> &mut V
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::get(&self, key: &K) -> core::option::Option<&V>
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::hottest(&self, n: usize) -> alloc::vec::Vec<K>
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::iter_coldest(&self) -> impl core::iter::traits::iterator::Iterator<Item = (&K, &V)> + '_
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::iter_hottest(&self) -> impl core::iter::traits::iterator::Iterator<Item = (&K, &V)> + '_
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::new() -> Self
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::remove(&mut self, key: &K)
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::touch(&mut self, key: K)
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::with_capacity(capacity: usize) -> Self
impl<K, V> core::default::Default for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V> where K: core::hash::Hash + core::cmp::Eq + core::marker::Copy, V: core::default::Default
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::default() -> Self
impl<K, V> core::marker::Freeze for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>
impl<K, V> core::marker::Send for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V> where K: core::marker::Send, V: core::marker::Send
impl<K, V> core::marker::Sync for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V> where K: core::marker::Sync, V: core::marker::Sync
impl<K, V> core::marker::Unpin for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V> where K: core::marker::Unpin, V: core::marker::Unpin
impl<K, V> core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V> where K: core::panic::unwind_safe::RefUnwindSafe, V: core::panic::unwind_safe::RefUnwindSafe
impl<K, V> core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V> where K: core::panic::unwind_safe::UnwindSafe, V: core::panic::unwind_safe::UnwindSafe
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V> where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V> where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V> where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V> where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V> where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V> where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>
pub type vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::Init = T
pub const vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>
pub fn vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V>
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V> where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V> where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<K, V> where T: core::marker::Sync
pub const vyre_driver_wgpu::runtime::cache::lru::DEFAULT_INTRUSIVE_LRU_CAPACITY: usize
pub mod vyre_driver_wgpu::runtime::cache::tier
#[non_exhaustive] pub enum vyre_driver_wgpu::runtime::cache::tier::CacheError
pub vyre_driver_wgpu::runtime::cache::tier::CacheError::EntryTooLarge
pub vyre_driver_wgpu::runtime::cache::tier::CacheError::KeyNotFound
impl core::clone::Clone for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::clone(&self) -> vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::cmp::Eq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::cmp::PartialEq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::eq(&self, other: &vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError) -> bool
impl core::error::Error for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::fmt::Debug for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::Owned = T
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::marker::Sync
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::cache::tier::AccessStats
pub vyre_driver_wgpu::runtime::cache::tier::AccessStats::frequency: u32
pub vyre_driver_wgpu::runtime::cache::tier::AccessStats::last_access: u64
pub vyre_driver_wgpu::runtime::cache::tier::AccessStats::size: u64
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: core::marker::Sync
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::cache::tier::LruPolicy
pub vyre_driver_wgpu::runtime::cache::tier::LruPolicy::promote_threshold: u32
impl vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::DEFAULT_THRESHOLD: u32
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::new(promote_threshold: u32) -> Self
impl core::default::Default for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::default() -> Self
impl vyre_driver_wgpu::runtime::cache::tiered_cache::TierPolicy for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::eviction_candidate(&self, _tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::eviction_candidate_per_tier(&self, _tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, _tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker, tier_lru: &vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<u64, ()>) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::should_promote(&self, _key: u64, stats: &vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats) -> bool
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: core::marker::Sync
pub trait vyre_driver_wgpu::runtime::cache::tier::TierPolicy: core::marker::Send + core::marker::Sync
pub fn vyre_driver_wgpu::runtime::cache::tier::TierPolicy::eviction_candidate(&self, tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tier::TierPolicy::eviction_candidate_per_tier(&self, tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker, tier_lru: &vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<u64, ()>) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tier::TierPolicy::should_promote(&self, key: u64, stats: &vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats) -> bool
impl vyre_driver_wgpu::runtime::cache::tiered_cache::TierPolicy for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::eviction_candidate(&self, _tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::eviction_candidate_per_tier(&self, _tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, _tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker, tier_lru: &vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<u64, ()>) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::should_promote(&self, _key: u64, stats: &vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats) -> bool
pub mod vyre_driver_wgpu::runtime::cache::tiered_cache
#[non_exhaustive] pub enum vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::EntryTooLarge
pub vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::KeyNotFound
impl core::clone::Clone for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::clone(&self) -> vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::cmp::Eq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::cmp::PartialEq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::eq(&self, other: &vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError) -> bool
impl core::error::Error for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::fmt::Debug for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::Owned = T
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::marker::Sync
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
pub vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::frequency: u32
pub vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::last_access: u64
pub vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::size: u64
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: core::marker::Sync
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::key: u64
pub vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::size: u64
pub vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::tier: usize
impl core::clone::Clone for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::clone(&self) -> vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::cmp::Eq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::cmp::PartialEq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::eq(&self, other: &vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::Owned = T
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: core::marker::Sync
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
pub vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::capacity: u64
pub vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::name: alloc::string::String
pub vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::used: u64
impl vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::new(name: impl core::convert::Into<alloc::string::String>, capacity: u64) -> Self
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: core::marker::Sync
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::promote_threshold: u32
impl vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::DEFAULT_THRESHOLD: u32
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::new(promote_threshold: u32) -> Self
impl core::default::Default for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::default() -> Self
impl vyre_driver_wgpu::runtime::cache::tiered_cache::TierPolicy for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::eviction_candidate(&self, _tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::eviction_candidate_per_tier(&self, _tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, _tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker, tier_lru: &vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<u64, ()>) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::should_promote(&self, _key: u64, stats: &vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats) -> bool
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: core::marker::Sync
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P: vyre_driver_wgpu::runtime::cache::tiered_cache::TierPolicy>
impl vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy>::new(tiers: alloc::vec::Vec<vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier>) -> Self
impl<P: vyre_driver_wgpu::runtime::cache::tiered_cache::TierPolicy> vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::demote(&mut self, key: u64) -> core::result::Result<(), vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::get(&self, key: u64) -> core::option::Option<&vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::insert(&mut self, key: u64, size: u64) -> core::result::Result<(), vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::promote(&mut self, key: u64) -> core::result::Result<(), vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::record_access(&mut self, key: u64)
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::with_policy(tiers: alloc::vec::Vec<vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier>, policy: P) -> Self
impl<P> core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where P: core::marker::Freeze
impl<P> core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
impl<P> core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
impl<P> core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where P: core::marker::Unpin
impl<P> core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where P: core::panic::unwind_safe::RefUnwindSafe
impl<P> core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where P: core::panic::unwind_safe::UnwindSafe
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where T: core::marker::Sync
pub trait vyre_driver_wgpu::runtime::cache::tiered_cache::TierPolicy: core::marker::Send + core::marker::Sync
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TierPolicy::eviction_candidate(&self, tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TierPolicy::eviction_candidate_per_tier(&self, tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker, tier_lru: &vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<u64, ()>) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TierPolicy::should_promote(&self, key: u64, stats: &vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats) -> bool
impl vyre_driver_wgpu::runtime::cache::tiered_cache::TierPolicy for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::eviction_candidate(&self, _tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::eviction_candidate_per_tier(&self, _tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, _tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker, tier_lru: &vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<u64, ()>) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::should_promote(&self, _key: u64, stats: &vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats) -> bool
#[non_exhaustive] pub enum vyre_driver_wgpu::runtime::cache::CacheError
pub vyre_driver_wgpu::runtime::cache::CacheError::EntryTooLarge
pub vyre_driver_wgpu::runtime::cache::CacheError::KeyNotFound
impl core::clone::Clone for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::clone(&self) -> vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::cmp::Eq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::cmp::PartialEq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::eq(&self, other: &vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError) -> bool
impl core::error::Error for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::fmt::Debug for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::Owned = T
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::marker::Sync
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::cache::AccessStats
pub vyre_driver_wgpu::runtime::cache::AccessStats::frequency: u32
pub vyre_driver_wgpu::runtime::cache::AccessStats::last_access: u64
pub vyre_driver_wgpu::runtime::cache::AccessStats::size: u64
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: core::marker::Sync
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::cache::AccessTracker
impl vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::hot_set(&self, n: usize) -> alloc::vec::Vec<u64>
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::new() -> Self
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::record(&mut self, key: u64)
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::stats(&self, key: u64) -> core::option::Option<vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats>
impl core::default::Default for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::default() -> Self
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::lru::AccessTracker::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::lru::AccessTracker::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub type vyre_driver_wgpu::runtime::cache::lru::AccessTracker::Init = T
pub const vyre_driver_wgpu::runtime::cache::lru::AccessTracker::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: core::marker::Sync
pub struct vyre_driver_wgpu::runtime::cache::BufferPool
impl vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::acquire(&self, device: &wgpu::api::device::Device, label: &str, size: u64, usage: wgpu_types::BufferUsages) -> vyre_foundation::error::Result<vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer>
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::global() -> &'static Self
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::new() -> Self
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::release(&self, buffer: vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer)
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::with_buffer<R>(&self, device: &wgpu::api::device::Device, label: &str, size: u64, usage: wgpu_types::BufferUsages, f: impl core::ops::function::FnOnce(&wgpu::api::buffer::Buffer) -> R) -> vyre_foundation::error::Result<R>
impl core::clone::Clone for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::clone(&self) -> vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl core::default::Default for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::default() -> vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::Owned = T
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::Init = T
pub const vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPool where T: core::marker::Sync
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::cache::CacheEntry
pub vyre_driver_wgpu::runtime::cache::CacheEntry::key: u64
pub vyre_driver_wgpu::runtime::cache::CacheEntry::size: u64
pub vyre_driver_wgpu::runtime::cache::CacheEntry::tier: usize
impl core::clone::Clone for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::clone(&self) -> vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::cmp::Eq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::cmp::PartialEq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::eq(&self, other: &vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::Owned = T
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry where T: core::marker::Sync
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::cache::CacheTier
pub vyre_driver_wgpu::runtime::cache::CacheTier::capacity: u64
pub vyre_driver_wgpu::runtime::cache::CacheTier::name: alloc::string::String
pub vyre_driver_wgpu::runtime::cache::CacheTier::used: u64
impl vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::new(name: impl core::convert::Into<alloc::string::String>, capacity: u64) -> Self
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier where T: core::marker::Sync
pub struct vyre_driver_wgpu::runtime::cache::DeviceFingerprint
pub vyre_driver_wgpu::runtime::cache::DeviceFingerprint::device: u32
pub vyre_driver_wgpu::runtime::cache::DeviceFingerprint::driver: u32
pub vyre_driver_wgpu::runtime::cache::DeviceFingerprint::vendor: u32
impl vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::fold_into(&self, digest: [u8; 32]) -> [u8; 32]
impl core::clone::Clone for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::clone(&self) -> vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::cmp::Eq for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::cmp::PartialEq for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::eq(&self, other: &vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::Owned = T
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub type vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::Init = T
pub const vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
pub fn vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint where T: core::marker::Sync
pub struct vyre_driver_wgpu::runtime::cache::DiskPipelineCache
impl vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::default_root() -> std::path::PathBuf
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::open(root: impl core::convert::Into<std::path::PathBuf>) -> std::io::error::Result<Self>
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::path_for(&self, program_blake3: [u8; 32], fp: vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint) -> std::path::PathBuf
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::read(&self, program_blake3: [u8; 32], fp: vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint) -> std::io::error::Result<core::option::Option<alloc::vec::Vec<u8>>>
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::root(&self) -> &std::path::Path
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::write(&self, program_blake3: [u8; 32], fp: vyre_driver_wgpu::runtime::cache::disk::DeviceFingerprint, bytes: &[u8]) -> std::io::error::Result<()>
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
pub type vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::Init = T
pub const vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
pub fn vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::disk::DiskPipelineCache where T: core::marker::Sync
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::cache::LruPolicy
pub vyre_driver_wgpu::runtime::cache::LruPolicy::promote_threshold: u32
impl vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::DEFAULT_THRESHOLD: u32
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::new(promote_threshold: u32) -> Self
impl core::default::Default for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::default() -> Self
impl vyre_driver_wgpu::runtime::cache::tiered_cache::TierPolicy for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::eviction_candidate(&self, _tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::eviction_candidate_per_tier(&self, _tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, _tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker, tier_lru: &vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<u64, ()>) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::should_promote(&self, _key: u64, stats: &vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats) -> bool
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: core::marker::Sync
pub struct vyre_driver_wgpu::runtime::cache::PooledBuffer
impl vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::buffer(&self) -> core::result::Result<&wgpu::api::buffer::Buffer, vyre_driver_wgpu::runtime::cache::buffer_pool::BufferPoolError>
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::buffer_id(&self) -> u64
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::size(&self) -> u64
impl core::ops::drop::Drop for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::drop(&mut self)
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
pub type vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::Init = T
pub const vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
pub fn vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::buffer_pool::PooledBuffer where T: core::marker::Sync
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::cache::TieredCache<P: vyre_driver_wgpu::runtime::cache::tiered_cache::TierPolicy>
impl vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy>::new(tiers: alloc::vec::Vec<vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier>) -> Self
impl<P: vyre_driver_wgpu::runtime::cache::tiered_cache::TierPolicy> vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::demote(&mut self, key: u64) -> core::result::Result<(), vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::get(&self, key: u64) -> core::option::Option<&vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::insert(&mut self, key: u64, size: u64) -> core::result::Result<(), vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::promote(&mut self, key: u64) -> core::result::Result<(), vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::record_access(&mut self, key: u64)
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::with_policy(tiers: alloc::vec::Vec<vyre_driver_wgpu::runtime::cache::tiered_cache::CacheTier>, policy: P) -> Self
impl<P> core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where P: core::marker::Freeze
impl<P> core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
impl<P> core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
impl<P> core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where P: core::marker::Unpin
impl<P> core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where P: core::panic::unwind_safe::RefUnwindSafe
impl<P> core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where P: core::panic::unwind_safe::UnwindSafe
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P>
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::TieredCache<P> where T: core::marker::Sync
pub trait vyre_driver_wgpu::runtime::cache::TierPolicy: core::marker::Send + core::marker::Sync
pub fn vyre_driver_wgpu::runtime::cache::TierPolicy::eviction_candidate(&self, tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::TierPolicy::eviction_candidate_per_tier(&self, tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker, tier_lru: &vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<u64, ()>) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::TierPolicy::should_promote(&self, key: u64, stats: &vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats) -> bool
impl vyre_driver_wgpu::runtime::cache::tiered_cache::TierPolicy for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::eviction_candidate(&self, _tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::eviction_candidate_per_tier(&self, _tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, _tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker, tier_lru: &vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<u64, ()>) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::should_promote(&self, _key: u64, stats: &vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats) -> bool
pub mod vyre_driver_wgpu::runtime::device
pub mod vyre_driver_wgpu::runtime::device::cached_device
pub fn vyre_driver_wgpu::runtime::device::cached_device::cached_adapter_info() -> vyre_foundation::error::Result<&'static wgpu_types::AdapterInfo>
pub fn vyre_driver_wgpu::runtime::device::cached_device::cached_device() -> vyre_foundation::error::Result<alloc::sync::Arc<(wgpu::api::device::Device, wgpu::api::queue::Queue)>>
pub mod vyre_driver_wgpu::runtime::device::init_device
pub fn vyre_driver_wgpu::runtime::device::init_device::init_device() -> vyre_foundation::error::Result<((wgpu::api::device::Device, wgpu::api::queue::Queue), wgpu_types::AdapterInfo)>
pub struct vyre_driver_wgpu::runtime::device::AdapterCriteria
pub vyre_driver_wgpu::runtime::device::AdapterCriteria::device_type: core::option::Option<wgpu_types::DeviceType>
pub vyre_driver_wgpu::runtime::device::AdapterCriteria::name_contains: core::option::Option<alloc::string::String>
pub vyre_driver_wgpu::runtime::device::AdapterCriteria::power: core::option::Option<wgpu_types::PowerPreference>
pub vyre_driver_wgpu::runtime::device::AdapterCriteria::vendor: core::option::Option<u32>
impl vyre_driver_wgpu::runtime::device::AdapterCriteria
pub fn vyre_driver_wgpu::runtime::device::AdapterCriteria::high_performance() -> Self
pub fn vyre_driver_wgpu::runtime::device::AdapterCriteria::low_power() -> Self
impl core::clone::Clone for vyre_driver_wgpu::runtime::device::AdapterCriteria
pub fn vyre_driver_wgpu::runtime::device::AdapterCriteria::clone(&self) -> vyre_driver_wgpu::runtime::device::AdapterCriteria
impl core::default::Default for vyre_driver_wgpu::runtime::device::AdapterCriteria
pub fn vyre_driver_wgpu::runtime::device::AdapterCriteria::default() -> vyre_driver_wgpu::runtime::device::AdapterCriteria
impl core::fmt::Debug for vyre_driver_wgpu::runtime::device::AdapterCriteria
pub fn vyre_driver_wgpu::runtime::device::AdapterCriteria::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver_wgpu::runtime::device::AdapterCriteria
impl core::marker::Send for vyre_driver_wgpu::runtime::device::AdapterCriteria
impl core::marker::Sync for vyre_driver_wgpu::runtime::device::AdapterCriteria
impl core::marker::Unpin for vyre_driver_wgpu::runtime::device::AdapterCriteria
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::device::AdapterCriteria
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::device::AdapterCriteria
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::device::AdapterCriteria where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::device::AdapterCriteria::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::device::AdapterCriteria where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::device::AdapterCriteria::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::device::AdapterCriteria::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::device::AdapterCriteria where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::device::AdapterCriteria::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::device::AdapterCriteria::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::device::AdapterCriteria where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::device::AdapterCriteria::Owned = T
pub fn vyre_driver_wgpu::runtime::device::AdapterCriteria::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::device::AdapterCriteria::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::device::AdapterCriteria where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::device::AdapterCriteria::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::device::AdapterCriteria where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::device::AdapterCriteria::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::device::AdapterCriteria where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::device::AdapterCriteria::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::device::AdapterCriteria where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::device::AdapterCriteria::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::device::AdapterCriteria
pub fn vyre_driver_wgpu::runtime::device::AdapterCriteria::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::device::AdapterCriteria
pub type vyre_driver_wgpu::runtime::device::AdapterCriteria::Init = T
pub const vyre_driver_wgpu::runtime::device::AdapterCriteria::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::device::AdapterCriteria::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::device::AdapterCriteria::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::device::AdapterCriteria::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::device::AdapterCriteria::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::device::AdapterCriteria
pub fn vyre_driver_wgpu::runtime::device::AdapterCriteria::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::device::AdapterCriteria
pub fn vyre_driver_wgpu::runtime::device::AdapterCriteria::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::device::AdapterCriteria
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::device::AdapterCriteria
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::device::AdapterCriteria where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::device::AdapterCriteria where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::device::AdapterCriteria where T: core::marker::Sync
pub async fn vyre_driver_wgpu::runtime::device::acquire_gpu() -> vyre_foundation::error::Result<((wgpu::api::device::Device, wgpu::api::queue::Queue), wgpu_types::AdapterInfo)>
pub async fn vyre_driver_wgpu::runtime::device::acquire_gpu_for_adapter(index: usize) -> vyre_foundation::error::Result<((wgpu::api::device::Device, wgpu::api::queue::Queue), wgpu_types::AdapterInfo)>
pub fn vyre_driver_wgpu::runtime::device::adapter_index_from_env() -> core::option::Option<usize>
pub fn vyre_driver_wgpu::runtime::device::cached_device() -> vyre_foundation::error::Result<alloc::sync::Arc<(wgpu::api::device::Device, wgpu::api::queue::Queue)>>
pub fn vyre_driver_wgpu::runtime::device::enumerate_adapters() -> alloc::vec::Vec<wgpu_types::AdapterInfo>
pub fn vyre_driver_wgpu::runtime::device::init_device() -> vyre_foundation::error::Result<((wgpu::api::device::Device, wgpu::api::queue::Queue), wgpu_types::AdapterInfo)>
pub fn vyre_driver_wgpu::runtime::device::init_device_for_adapter(index: usize) -> vyre_foundation::error::Result<((wgpu::api::device::Device, wgpu::api::queue::Queue), wgpu_types::AdapterInfo)>
pub fn vyre_driver_wgpu::runtime::device::select_adapter(criteria: &vyre_driver_wgpu::runtime::device::AdapterCriteria) -> vyre_foundation::error::Result<(usize, wgpu_types::AdapterInfo)>
pub mod vyre_driver_wgpu::runtime::indirect
pub struct vyre_driver_wgpu::runtime::indirect::IndirectArgs
pub vyre_driver_wgpu::runtime::indirect::IndirectArgs::buffer: alloc::sync::Arc<wgpu::api::buffer::Buffer>
pub vyre_driver_wgpu::runtime::indirect::IndirectArgs::offset: u64
impl vyre_driver_wgpu::runtime::indirect::IndirectArgs
pub fn vyre_driver_wgpu::runtime::indirect::IndirectArgs::from_handle(handle: &vyre_driver_wgpu::buffer::GpuBufferHandle, offset: u64) -> core::result::Result<Self, vyre_driver::backend::BackendError>
impl core::marker::Freeze for vyre_driver_wgpu::runtime::indirect::IndirectArgs
impl core::marker::Send for vyre_driver_wgpu::runtime::indirect::IndirectArgs
impl core::marker::Sync for vyre_driver_wgpu::runtime::indirect::IndirectArgs
impl core::marker::Unpin for vyre_driver_wgpu::runtime::indirect::IndirectArgs
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::indirect::IndirectArgs
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::indirect::IndirectArgs
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::indirect::IndirectArgs where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::indirect::IndirectArgs::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::indirect::IndirectArgs where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::indirect::IndirectArgs::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::indirect::IndirectArgs::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::indirect::IndirectArgs where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::indirect::IndirectArgs::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::indirect::IndirectArgs::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::indirect::IndirectArgs where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::indirect::IndirectArgs::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::indirect::IndirectArgs where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::indirect::IndirectArgs::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::indirect::IndirectArgs where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::indirect::IndirectArgs::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::indirect::IndirectArgs
pub fn vyre_driver_wgpu::runtime::indirect::IndirectArgs::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::indirect::IndirectArgs
pub type vyre_driver_wgpu::runtime::indirect::IndirectArgs::Init = T
pub const vyre_driver_wgpu::runtime::indirect::IndirectArgs::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::indirect::IndirectArgs::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::indirect::IndirectArgs::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::indirect::IndirectArgs::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::indirect::IndirectArgs::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::indirect::IndirectArgs
pub fn vyre_driver_wgpu::runtime::indirect::IndirectArgs::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::indirect::IndirectArgs
pub fn vyre_driver_wgpu::runtime::indirect::IndirectArgs::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::indirect::IndirectArgs
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::indirect::IndirectArgs
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::indirect::IndirectArgs where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::indirect::IndirectArgs where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::indirect::IndirectArgs where T: core::marker::Sync
pub const vyre_driver_wgpu::runtime::indirect::INDIRECT_ARGS_BYTES: u64
pub fn vyre_driver_wgpu::runtime::indirect::dispatch_indirect<'a>(pass: &mut wgpu::api::compute_pass::ComputePass<'a>, args: &'a vyre_driver_wgpu::runtime::indirect::IndirectArgs)
pub mod vyre_driver_wgpu::runtime::prerecorded
pub struct vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch
pub vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::bind_group: alloc::sync::Arc<wgpu::api::bind_group::BindGroup>
pub vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::cb: std::sync::poison::mutex::Mutex<core::option::Option<wgpu::api::command_buffer::CommandBuffer>>
pub vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::device: wgpu::api::device::Device
pub vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::handles: alloc::vec::Vec<vyre_driver_wgpu::buffer::GpuBufferHandle>
pub vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::output_handles: alloc::vec::Vec<vyre_driver_wgpu::buffer::GpuBufferHandle>
pub vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::queue: wgpu::api::queue::Queue
impl vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch
pub fn vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::read_output(&self, index: usize) -> core::result::Result<alloc::vec::Vec<u8>, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::replay(&self, queue: &wgpu::api::queue::Queue) -> core::result::Result<wgpu::api::queue::SubmissionIndex, vyre_driver::backend::BackendError>
impl !core::marker::Freeze for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch
impl core::marker::Send for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch
impl core::marker::Sync for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch
impl core::marker::Unpin for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch
pub fn vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch
pub type vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::Init = T
pub const vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch
pub fn vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch
pub fn vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::prerecorded::PrerecordedDispatch where T: core::marker::Sync
pub mod vyre_driver_wgpu::runtime::readback_ring
pub enum vyre_driver_wgpu::runtime::readback_ring::SlotState
pub vyre_driver_wgpu::runtime::readback_ring::SlotState::Free
pub vyre_driver_wgpu::runtime::readback_ring::SlotState::Pending
pub vyre_driver_wgpu::runtime::readback_ring::SlotState::Ready
impl core::clone::Clone for vyre_driver_wgpu::runtime::readback_ring::SlotState
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::clone(&self) -> vyre_driver_wgpu::runtime::readback_ring::SlotState
impl core::cmp::Eq for vyre_driver_wgpu::runtime::readback_ring::SlotState
impl core::cmp::PartialEq for vyre_driver_wgpu::runtime::readback_ring::SlotState
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::eq(&self, other: &vyre_driver_wgpu::runtime::readback_ring::SlotState) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::runtime::readback_ring::SlotState
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::runtime::readback_ring::SlotState
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::runtime::readback_ring::SlotState
impl core::marker::Freeze for vyre_driver_wgpu::runtime::readback_ring::SlotState
impl core::marker::Send for vyre_driver_wgpu::runtime::readback_ring::SlotState
impl core::marker::Sync for vyre_driver_wgpu::runtime::readback_ring::SlotState
impl core::marker::Unpin for vyre_driver_wgpu::runtime::readback_ring::SlotState
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::readback_ring::SlotState
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::readback_ring::SlotState
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::runtime::readback_ring::SlotState where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::readback_ring::SlotState where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::readback_ring::SlotState where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::readback_ring::SlotState where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::readback_ring::SlotState where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::readback_ring::SlotState where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::readback_ring::SlotState::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::readback_ring::SlotState where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::readback_ring::SlotState::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::readback_ring::SlotState where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::readback_ring::SlotState::Owned = T
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::readback_ring::SlotState where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::readback_ring::SlotState where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::readback_ring::SlotState where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::readback_ring::SlotState where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::SlotState::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::readback_ring::SlotState
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::readback_ring::SlotState
pub type vyre_driver_wgpu::runtime::readback_ring::SlotState::Init = T
pub const vyre_driver_wgpu::runtime::readback_ring::SlotState::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::SlotState::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::SlotState::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::SlotState::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::SlotState::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::readback_ring::SlotState
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::readback_ring::SlotState
pub fn vyre_driver_wgpu::runtime::readback_ring::SlotState::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::readback_ring::SlotState
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::readback_ring::SlotState
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::readback_ring::SlotState where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::readback_ring::SlotState where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::readback_ring::SlotState where T: core::marker::Sync
pub struct vyre_driver_wgpu::runtime::readback_ring::BeginResult
pub vyre_driver_wgpu::runtime::readback_ring::BeginResult::dispatch_id: u64
pub vyre_driver_wgpu::runtime::readback_ring::BeginResult::slot_index: usize
pub vyre_driver_wgpu::runtime::readback_ring::BeginResult::stalled: bool
impl core::clone::Clone for vyre_driver_wgpu::runtime::readback_ring::BeginResult
pub fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::clone(&self) -> vyre_driver_wgpu::runtime::readback_ring::BeginResult
impl core::fmt::Debug for vyre_driver_wgpu::runtime::readback_ring::BeginResult
pub fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::runtime::readback_ring::BeginResult
impl core::marker::Freeze for vyre_driver_wgpu::runtime::readback_ring::BeginResult
impl core::marker::Send for vyre_driver_wgpu::runtime::readback_ring::BeginResult
impl core::marker::Sync for vyre_driver_wgpu::runtime::readback_ring::BeginResult
impl core::marker::Unpin for vyre_driver_wgpu::runtime::readback_ring::BeginResult
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::readback_ring::BeginResult
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::readback_ring::BeginResult
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::readback_ring::BeginResult where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::readback_ring::BeginResult where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::readback_ring::BeginResult::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::readback_ring::BeginResult where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::readback_ring::BeginResult::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::readback_ring::BeginResult where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::readback_ring::BeginResult::Owned = T
pub fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::readback_ring::BeginResult where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::readback_ring::BeginResult where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::readback_ring::BeginResult where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::readback_ring::BeginResult where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::readback_ring::BeginResult
pub fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::readback_ring::BeginResult
pub type vyre_driver_wgpu::runtime::readback_ring::BeginResult::Init = T
pub const vyre_driver_wgpu::runtime::readback_ring::BeginResult::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::readback_ring::BeginResult
pub fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::readback_ring::BeginResult
pub fn vyre_driver_wgpu::runtime::readback_ring::BeginResult::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::readback_ring::BeginResult
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::readback_ring::BeginResult
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::readback_ring::BeginResult where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::readback_ring::BeginResult where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::readback_ring::BeginResult where T: core::marker::Sync
pub struct vyre_driver_wgpu::runtime::readback_ring::ReadbackRing
impl vyre_driver_wgpu::runtime::readback_ring::ReadbackRing
pub fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::begin_dispatch(&mut self, byte_len: u64) -> vyre_driver_wgpu::runtime::readback_ring::BeginResult
pub fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::complete_slot(&mut self, slot_index: usize)
pub fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::new(size: usize) -> Self
pub fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::next_slot_index(&self) -> usize
pub fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::release_slot(&mut self, slot_index: usize)
pub fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::size(&self) -> usize
pub fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::slot(&self, idx: usize) -> core::option::Option<&vyre_driver_wgpu::runtime::readback_ring::Slot>
pub fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::stats(&self) -> alloc::sync::Arc<vyre_driver_wgpu::runtime::readback_ring::RingStats>
impl core::marker::Freeze for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing
impl core::marker::Send for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing
impl core::marker::Sync for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing
impl core::marker::Unpin for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing
pub fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing
pub type vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::Init = T
pub const vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing
pub fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing
pub fn vyre_driver_wgpu::runtime::readback_ring::ReadbackRing::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::readback_ring::ReadbackRing where T: core::marker::Sync
pub struct vyre_driver_wgpu::runtime::readback_ring::RingStats
pub vyre_driver_wgpu::runtime::readback_ring::RingStats::dispatches: core::sync::atomic::AtomicU64
pub vyre_driver_wgpu::runtime::readback_ring::RingStats::peak_inflight: core::sync::atomic::AtomicU64
pub vyre_driver_wgpu::runtime::readback_ring::RingStats::readback_stalls: core::sync::atomic::AtomicU64
impl vyre_driver_wgpu::runtime::readback_ring::RingStats
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStats::record_dispatch(&self) -> u64
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStats::record_stall(&self)
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStats::snapshot(&self) -> vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStats::update_peak(&self, current: u64)
impl core::default::Default for vyre_driver_wgpu::runtime::readback_ring::RingStats
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStats::default() -> vyre_driver_wgpu::runtime::readback_ring::RingStats
impl core::fmt::Debug for vyre_driver_wgpu::runtime::readback_ring::RingStats
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStats::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl !core::marker::Freeze for vyre_driver_wgpu::runtime::readback_ring::RingStats
impl core::marker::Send for vyre_driver_wgpu::runtime::readback_ring::RingStats
impl core::marker::Sync for vyre_driver_wgpu::runtime::readback_ring::RingStats
impl core::marker::Unpin for vyre_driver_wgpu::runtime::readback_ring::RingStats
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::readback_ring::RingStats
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::readback_ring::RingStats
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::readback_ring::RingStats where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStats::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::readback_ring::RingStats where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::readback_ring::RingStats::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStats::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::readback_ring::RingStats where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::readback_ring::RingStats::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStats::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::readback_ring::RingStats where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStats::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::readback_ring::RingStats where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStats::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::readback_ring::RingStats where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStats::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::readback_ring::RingStats
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStats::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::readback_ring::RingStats
pub type vyre_driver_wgpu::runtime::readback_ring::RingStats::Init = T
pub const vyre_driver_wgpu::runtime::readback_ring::RingStats::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::RingStats::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::RingStats::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::RingStats::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::RingStats::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::readback_ring::RingStats
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStats::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::readback_ring::RingStats
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStats::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::readback_ring::RingStats
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::readback_ring::RingStats
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::readback_ring::RingStats where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::readback_ring::RingStats where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::readback_ring::RingStats where T: core::marker::Sync
pub struct vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
pub vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::dispatches: u64
pub vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::peak_inflight: u64
pub vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::readback_stalls: u64
impl core::clone::Clone for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::clone(&self) -> vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
impl core::fmt::Debug for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
impl core::marker::Freeze for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
impl core::marker::Send for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
impl core::marker::Sync for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
impl core::marker::Unpin for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::Owned = T
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
pub type vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::Init = T
pub const vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
pub fn vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::readback_ring::RingStatsSnapshot where T: core::marker::Sync
pub struct vyre_driver_wgpu::runtime::readback_ring::Slot
pub vyre_driver_wgpu::runtime::readback_ring::Slot::byte_len: u64
pub vyre_driver_wgpu::runtime::readback_ring::Slot::dispatch_id: core::option::Option<u64>
pub vyre_driver_wgpu::runtime::readback_ring::Slot::state: vyre_driver_wgpu::runtime::readback_ring::SlotState
impl core::clone::Clone for vyre_driver_wgpu::runtime::readback_ring::Slot
pub fn vyre_driver_wgpu::runtime::readback_ring::Slot::clone(&self) -> vyre_driver_wgpu::runtime::readback_ring::Slot
impl core::default::Default for vyre_driver_wgpu::runtime::readback_ring::Slot
pub fn vyre_driver_wgpu::runtime::readback_ring::Slot::default() -> Self
impl core::fmt::Debug for vyre_driver_wgpu::runtime::readback_ring::Slot
pub fn vyre_driver_wgpu::runtime::readback_ring::Slot::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver_wgpu::runtime::readback_ring::Slot
impl core::marker::Send for vyre_driver_wgpu::runtime::readback_ring::Slot
impl core::marker::Sync for vyre_driver_wgpu::runtime::readback_ring::Slot
impl core::marker::Unpin for vyre_driver_wgpu::runtime::readback_ring::Slot
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::readback_ring::Slot
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::readback_ring::Slot
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::readback_ring::Slot where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::readback_ring::Slot::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::readback_ring::Slot where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::readback_ring::Slot::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::readback_ring::Slot::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::readback_ring::Slot where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::readback_ring::Slot::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::readback_ring::Slot::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::readback_ring::Slot where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::readback_ring::Slot::Owned = T
pub fn vyre_driver_wgpu::runtime::readback_ring::Slot::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::readback_ring::Slot::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::readback_ring::Slot where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::Slot::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::readback_ring::Slot where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::Slot::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::readback_ring::Slot where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::readback_ring::Slot::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::readback_ring::Slot where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::Slot::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::readback_ring::Slot
pub fn vyre_driver_wgpu::runtime::readback_ring::Slot::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::readback_ring::Slot
pub type vyre_driver_wgpu::runtime::readback_ring::Slot::Init = T
pub const vyre_driver_wgpu::runtime::readback_ring::Slot::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::Slot::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::Slot::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::Slot::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::readback_ring::Slot::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::readback_ring::Slot
pub fn vyre_driver_wgpu::runtime::readback_ring::Slot::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::readback_ring::Slot
pub fn vyre_driver_wgpu::runtime::readback_ring::Slot::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::readback_ring::Slot
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::readback_ring::Slot
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::readback_ring::Slot where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::readback_ring::Slot where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::readback_ring::Slot where T: core::marker::Sync
pub fn vyre_driver_wgpu::runtime::readback_ring::ring_size_from_env() -> usize
pub mod vyre_driver_wgpu::runtime::router
pub enum vyre_driver_wgpu::runtime::router::Override<'a>
pub vyre_driver_wgpu::runtime::router::Override::Explicit(&'a str)
pub vyre_driver_wgpu::runtime::router::Override::FromEnv
pub vyre_driver_wgpu::runtime::router::Override::None
impl<'a> core::clone::Clone for vyre_driver_wgpu::runtime::router::Override<'a>
pub fn vyre_driver_wgpu::runtime::router::Override<'a>::clone(&self) -> vyre_driver_wgpu::runtime::router::Override<'a>
impl<'a> core::fmt::Debug for vyre_driver_wgpu::runtime::router::Override<'a>
pub fn vyre_driver_wgpu::runtime::router::Override<'a>::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl<'a> core::marker::Copy for vyre_driver_wgpu::runtime::router::Override<'a>
impl<'a> core::marker::Freeze for vyre_driver_wgpu::runtime::router::Override<'a>
impl<'a> core::marker::Send for vyre_driver_wgpu::runtime::router::Override<'a>
impl<'a> core::marker::Sync for vyre_driver_wgpu::runtime::router::Override<'a>
impl<'a> core::marker::Unpin for vyre_driver_wgpu::runtime::router::Override<'a>
impl<'a> core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::router::Override<'a>
impl<'a> core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::router::Override<'a>
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::router::Override<'a> where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::router::Override<'a>::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::router::Override<'a> where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::router::Override<'a>::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::router::Override<'a>::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::router::Override<'a> where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::router::Override<'a>::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::router::Override<'a>::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::router::Override<'a> where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::router::Override<'a>::Owned = T
pub fn vyre_driver_wgpu::runtime::router::Override<'a>::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::router::Override<'a>::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::router::Override<'a> where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::router::Override<'a>::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::router::Override<'a> where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::router::Override<'a>::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::router::Override<'a> where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::router::Override<'a>::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::router::Override<'a> where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::router::Override<'a>::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::router::Override<'a>
pub fn vyre_driver_wgpu::runtime::router::Override<'a>::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::router::Override<'a>
pub type vyre_driver_wgpu::runtime::router::Override<'a>::Init = T
pub const vyre_driver_wgpu::runtime::router::Override<'a>::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::router::Override<'a>::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::router::Override<'a>::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::router::Override<'a>::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::router::Override<'a>::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::router::Override<'a>
pub fn vyre_driver_wgpu::runtime::router::Override<'a>::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::router::Override<'a>
pub fn vyre_driver_wgpu::runtime::router::Override<'a>::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::router::Override<'a>
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::router::Override<'a>
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::router::Override<'a> where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::router::Override<'a> where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::router::Override<'a> where T: core::marker::Sync
pub enum vyre_driver_wgpu::runtime::router::Reason
pub vyre_driver_wgpu::runtime::router::Reason::EnvOverride
pub vyre_driver_wgpu::runtime::router::Reason::Precedence
impl core::clone::Clone for vyre_driver_wgpu::runtime::router::Reason
pub fn vyre_driver_wgpu::runtime::router::Reason::clone(&self) -> vyre_driver_wgpu::runtime::router::Reason
impl core::cmp::Eq for vyre_driver_wgpu::runtime::router::Reason
impl core::cmp::PartialEq for vyre_driver_wgpu::runtime::router::Reason
pub fn vyre_driver_wgpu::runtime::router::Reason::eq(&self, other: &vyre_driver_wgpu::runtime::router::Reason) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::runtime::router::Reason
pub fn vyre_driver_wgpu::runtime::router::Reason::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::runtime::router::Reason
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::runtime::router::Reason
impl core::marker::Freeze for vyre_driver_wgpu::runtime::router::Reason
impl core::marker::Send for vyre_driver_wgpu::runtime::router::Reason
impl core::marker::Sync for vyre_driver_wgpu::runtime::router::Reason
impl core::marker::Unpin for vyre_driver_wgpu::runtime::router::Reason
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::router::Reason
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::router::Reason
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::runtime::router::Reason where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::router::Reason::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::router::Reason where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::router::Reason where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::router::Reason where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::router::Reason::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::router::Reason::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::router::Reason::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::router::Reason where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::router::Reason::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::router::Reason where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::router::Reason::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::router::Reason::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::router::Reason where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::router::Reason::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::router::Reason::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::router::Reason where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::router::Reason::Owned = T
pub fn vyre_driver_wgpu::runtime::router::Reason::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::router::Reason::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::router::Reason where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::router::Reason::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::router::Reason where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::router::Reason::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::router::Reason where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::router::Reason::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::router::Reason where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::router::Reason::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::router::Reason
pub fn vyre_driver_wgpu::runtime::router::Reason::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::router::Reason
pub type vyre_driver_wgpu::runtime::router::Reason::Init = T
pub const vyre_driver_wgpu::runtime::router::Reason::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::router::Reason::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::router::Reason::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::router::Reason::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::router::Reason::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::router::Reason
pub fn vyre_driver_wgpu::runtime::router::Reason::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::router::Reason
pub fn vyre_driver_wgpu::runtime::router::Reason::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::router::Reason
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::router::Reason
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::router::Reason where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::router::Reason where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::router::Reason where T: core::marker::Sync
pub struct vyre_driver_wgpu::runtime::router::BackendRouter
impl vyre_driver_wgpu::runtime::router::BackendRouter
pub fn vyre_driver_wgpu::runtime::router::BackendRouter::enumerate_by_precedence() -> alloc::vec::Vec<&'static vyre_driver::backend::registry::BackendRegistration>
pub fn vyre_driver_wgpu::runtime::router::BackendRouter::new() -> Self
pub fn vyre_driver_wgpu::runtime::router::BackendRouter::pick(&self, program: &vyre_foundation::ir_inner::model::program::Program) -> core::result::Result<vyre_driver_wgpu::runtime::router::RouterDecision, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::runtime::router::BackendRouter::pick_with_override(&self, _program: &vyre_foundation::ir_inner::model::program::Program, source: vyre_driver_wgpu::runtime::router::Override<'_>) -> core::result::Result<vyre_driver_wgpu::runtime::router::RouterDecision, vyre_driver::backend::BackendError>
impl core::default::Default for vyre_driver_wgpu::runtime::router::BackendRouter
pub fn vyre_driver_wgpu::runtime::router::BackendRouter::default() -> vyre_driver_wgpu::runtime::router::BackendRouter
impl core::marker::Freeze for vyre_driver_wgpu::runtime::router::BackendRouter
impl core::marker::Send for vyre_driver_wgpu::runtime::router::BackendRouter
impl core::marker::Sync for vyre_driver_wgpu::runtime::router::BackendRouter
impl core::marker::Unpin for vyre_driver_wgpu::runtime::router::BackendRouter
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::router::BackendRouter
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::router::BackendRouter
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::router::BackendRouter where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::router::BackendRouter::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::router::BackendRouter where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::router::BackendRouter::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::router::BackendRouter::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::router::BackendRouter where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::router::BackendRouter::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::router::BackendRouter::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::router::BackendRouter where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::router::BackendRouter::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::router::BackendRouter where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::router::BackendRouter::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::router::BackendRouter where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::router::BackendRouter::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::router::BackendRouter
pub fn vyre_driver_wgpu::runtime::router::BackendRouter::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::router::BackendRouter
pub type vyre_driver_wgpu::runtime::router::BackendRouter::Init = T
pub const vyre_driver_wgpu::runtime::router::BackendRouter::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::router::BackendRouter::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::router::BackendRouter::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::router::BackendRouter::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::router::BackendRouter::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::router::BackendRouter
pub fn vyre_driver_wgpu::runtime::router::BackendRouter::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::router::BackendRouter
pub fn vyre_driver_wgpu::runtime::router::BackendRouter::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::router::BackendRouter
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::router::BackendRouter
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::router::BackendRouter where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::router::BackendRouter where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::router::BackendRouter where T: core::marker::Sync
pub struct vyre_driver_wgpu::runtime::router::RouterDecision
pub vyre_driver_wgpu::runtime::router::RouterDecision::backend: &'static str
pub vyre_driver_wgpu::runtime::router::RouterDecision::reason: vyre_driver_wgpu::runtime::router::Reason
impl core::clone::Clone for vyre_driver_wgpu::runtime::router::RouterDecision
pub fn vyre_driver_wgpu::runtime::router::RouterDecision::clone(&self) -> vyre_driver_wgpu::runtime::router::RouterDecision
impl core::fmt::Debug for vyre_driver_wgpu::runtime::router::RouterDecision
pub fn vyre_driver_wgpu::runtime::router::RouterDecision::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver_wgpu::runtime::router::RouterDecision
impl core::marker::Send for vyre_driver_wgpu::runtime::router::RouterDecision
impl core::marker::Sync for vyre_driver_wgpu::runtime::router::RouterDecision
impl core::marker::Unpin for vyre_driver_wgpu::runtime::router::RouterDecision
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::router::RouterDecision
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::router::RouterDecision
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::router::RouterDecision where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::router::RouterDecision::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::router::RouterDecision where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::router::RouterDecision::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::router::RouterDecision::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::router::RouterDecision where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::router::RouterDecision::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::router::RouterDecision::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::router::RouterDecision where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::router::RouterDecision::Owned = T
pub fn vyre_driver_wgpu::runtime::router::RouterDecision::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::router::RouterDecision::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::router::RouterDecision where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::router::RouterDecision::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::router::RouterDecision where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::router::RouterDecision::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::router::RouterDecision where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::router::RouterDecision::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::router::RouterDecision where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::router::RouterDecision::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::router::RouterDecision
pub fn vyre_driver_wgpu::runtime::router::RouterDecision::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::router::RouterDecision
pub type vyre_driver_wgpu::runtime::router::RouterDecision::Init = T
pub const vyre_driver_wgpu::runtime::router::RouterDecision::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::router::RouterDecision::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::router::RouterDecision::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::router::RouterDecision::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::router::RouterDecision::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::router::RouterDecision
pub fn vyre_driver_wgpu::runtime::router::RouterDecision::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::router::RouterDecision
pub fn vyre_driver_wgpu::runtime::router::RouterDecision::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::router::RouterDecision
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::router::RouterDecision
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::router::RouterDecision where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::router::RouterDecision where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::router::RouterDecision where T: core::marker::Sync
pub mod vyre_driver_wgpu::runtime::serializer
pub mod vyre_driver_wgpu::runtime::serializer::decode_parts
pub fn vyre_driver_wgpu::runtime::serializer::decode_parts::decode_parts(bytes: &[u8]) -> vyre_foundation::error::Result<alloc::vec::Vec<&[u8]>>
pub mod vyre_driver_wgpu::runtime::serializer::encode_parts
pub const vyre_driver_wgpu::runtime::serializer::encode_parts::MAX_SERIALIZED_PART_BYTES: usize
pub fn vyre_driver_wgpu::runtime::serializer::encode_parts::encode_parts(parts: &[&[u8]]) -> vyre_foundation::error::Result<alloc::vec::Vec<u8>>
pub const vyre_driver_wgpu::runtime::serializer::MAX_SERIALIZED_PART_BYTES: usize
pub fn vyre_driver_wgpu::runtime::serializer::decode_parts(bytes: &[u8]) -> vyre_foundation::error::Result<alloc::vec::Vec<&[u8]>>
pub fn vyre_driver_wgpu::runtime::serializer::encode_parts(parts: &[&[u8]]) -> vyre_foundation::error::Result<alloc::vec::Vec<u8>>
pub mod vyre_driver_wgpu::runtime::shader
pub mod vyre_driver_wgpu::runtime::shader::cache_key
pub fn vyre_driver_wgpu::runtime::shader::cache_key::cache_key(wgsl_source: &str, entry_point: &str) -> alloc::string::String
pub mod vyre_driver_wgpu::runtime::shader::compile_compute_pipeline
pub fn vyre_driver_wgpu::runtime::shader::compile_compute_pipeline::compile_compute_pipeline(device: &wgpu::api::device::Device, label: &str, wgsl_source: &str, entry_point: &str) -> vyre_foundation::error::Result<wgpu::api::compute_pipeline::ComputePipeline>
pub fn vyre_driver_wgpu::runtime::shader::compile_compute_pipeline::compile_compute_pipeline_with_layout(device: &wgpu::api::device::Device, label: &str, wgsl_source: &str, entry_point: &str, layout: core::option::Option<&wgpu::api::pipeline_layout::PipelineLayout>) -> vyre_foundation::error::Result<wgpu::api::compute_pipeline::ComputePipeline>
pub mod vyre_driver_wgpu::runtime::shader::pipeline_cache
pub const vyre_driver_wgpu::runtime::shader::pipeline_cache::MAX_PIPELINE_CACHE_ENTRIES: usize
pub fn vyre_driver_wgpu::runtime::shader::pipeline_cache::cache_key(wgsl_source: &str, entry_point: &str) -> alloc::string::String
pub const vyre_driver_wgpu::runtime::shader::MAX_PIPELINE_CACHE_ENTRIES: usize
pub mod vyre_driver_wgpu::runtime::tuner
pub enum vyre_driver_wgpu::runtime::tuner::Mode
pub vyre_driver_wgpu::runtime::tuner::Mode::OffUseDefault
pub vyre_driver_wgpu::runtime::tuner::Mode::On
impl vyre_driver_wgpu::runtime::tuner::Mode
pub fn vyre_driver_wgpu::runtime::tuner::Mode::from_env() -> Self
impl core::clone::Clone for vyre_driver_wgpu::runtime::tuner::Mode
pub fn vyre_driver_wgpu::runtime::tuner::Mode::clone(&self) -> vyre_driver_wgpu::runtime::tuner::Mode
impl core::cmp::Eq for vyre_driver_wgpu::runtime::tuner::Mode
impl core::cmp::PartialEq for vyre_driver_wgpu::runtime::tuner::Mode
pub fn vyre_driver_wgpu::runtime::tuner::Mode::eq(&self, other: &vyre_driver_wgpu::runtime::tuner::Mode) -> bool
impl core::fmt::Debug for vyre_driver_wgpu::runtime::tuner::Mode
pub fn vyre_driver_wgpu::runtime::tuner::Mode::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::runtime::tuner::Mode
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::runtime::tuner::Mode
impl core::marker::Freeze for vyre_driver_wgpu::runtime::tuner::Mode
impl core::marker::Send for vyre_driver_wgpu::runtime::tuner::Mode
impl core::marker::Sync for vyre_driver_wgpu::runtime::tuner::Mode
impl core::marker::Unpin for vyre_driver_wgpu::runtime::tuner::Mode
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::tuner::Mode
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::tuner::Mode
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::runtime::tuner::Mode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::tuner::Mode::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::tuner::Mode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::tuner::Mode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::tuner::Mode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::tuner::Mode::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::tuner::Mode::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::tuner::Mode::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::tuner::Mode where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::tuner::Mode::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::tuner::Mode where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::tuner::Mode::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::tuner::Mode::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::tuner::Mode where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::tuner::Mode::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::tuner::Mode::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::tuner::Mode where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::tuner::Mode::Owned = T
pub fn vyre_driver_wgpu::runtime::tuner::Mode::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::tuner::Mode::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::tuner::Mode where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::tuner::Mode::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::tuner::Mode where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::tuner::Mode::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::tuner::Mode where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::tuner::Mode::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::tuner::Mode where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::tuner::Mode::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::tuner::Mode
pub fn vyre_driver_wgpu::runtime::tuner::Mode::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::tuner::Mode
pub type vyre_driver_wgpu::runtime::tuner::Mode::Init = T
pub const vyre_driver_wgpu::runtime::tuner::Mode::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::tuner::Mode::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::tuner::Mode::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::tuner::Mode::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::tuner::Mode::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::tuner::Mode
pub fn vyre_driver_wgpu::runtime::tuner::Mode::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::tuner::Mode
pub fn vyre_driver_wgpu::runtime::tuner::Mode::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::tuner::Mode
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::tuner::Mode
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::tuner::Mode where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::tuner::Mode where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::tuner::Mode where T: core::marker::Sync
pub struct vyre_driver_wgpu::runtime::tuner::Tuner
impl vyre_driver_wgpu::runtime::tuner::Tuner
pub fn vyre_driver_wgpu::runtime::tuner::Tuner::cache_path_for_adapter(adapter_fp: &str) -> std::path::PathBuf
pub fn vyre_driver_wgpu::runtime::tuner::Tuner::candidates_for(&self, max_invocations: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver_wgpu::runtime::tuner::Tuner::default_workgroup_size() -> [u32; 3]
pub fn vyre_driver_wgpu::runtime::tuner::Tuner::mode(&self) -> vyre_driver_wgpu::runtime::tuner::Mode
pub fn vyre_driver_wgpu::runtime::tuner::Tuner::new(adapter_fp: &str, mode: vyre_driver_wgpu::runtime::tuner::Mode) -> Self
pub fn vyre_driver_wgpu::runtime::tuner::Tuner::persist(&self) -> core::result::Result<(), alloc::string::String>
pub fn vyre_driver_wgpu::runtime::tuner::Tuner::record_decision(&mut self, program_fp: impl core::convert::Into<alloc::string::String>, size: [u32; 3])
pub fn vyre_driver_wgpu::runtime::tuner::Tuner::resolve(&self, program_fp: &str) -> [u32; 3]
impl core::marker::Freeze for vyre_driver_wgpu::runtime::tuner::Tuner
impl core::marker::Send for vyre_driver_wgpu::runtime::tuner::Tuner
impl core::marker::Sync for vyre_driver_wgpu::runtime::tuner::Tuner
impl core::marker::Unpin for vyre_driver_wgpu::runtime::tuner::Tuner
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::tuner::Tuner
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::tuner::Tuner
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::tuner::Tuner where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::tuner::Tuner::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::tuner::Tuner where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::tuner::Tuner::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::tuner::Tuner::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::tuner::Tuner where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::tuner::Tuner::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::tuner::Tuner::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::tuner::Tuner where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::tuner::Tuner::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::tuner::Tuner where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::tuner::Tuner::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::tuner::Tuner where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::tuner::Tuner::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::tuner::Tuner
pub fn vyre_driver_wgpu::runtime::tuner::Tuner::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::tuner::Tuner
pub type vyre_driver_wgpu::runtime::tuner::Tuner::Init = T
pub const vyre_driver_wgpu::runtime::tuner::Tuner::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::tuner::Tuner::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::tuner::Tuner::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::tuner::Tuner::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::tuner::Tuner::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::tuner::Tuner
pub fn vyre_driver_wgpu::runtime::tuner::Tuner::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::tuner::Tuner
pub fn vyre_driver_wgpu::runtime::tuner::Tuner::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::tuner::Tuner
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::tuner::Tuner
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::tuner::Tuner where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::tuner::Tuner where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::tuner::Tuner where T: core::marker::Sync
pub struct vyre_driver_wgpu::runtime::tuner::TunerCache
pub vyre_driver_wgpu::runtime::tuner::TunerCache::entries: alloc::collections::btree::map::BTreeMap<alloc::string::String, [u32; 3]>
impl vyre_driver_wgpu::runtime::tuner::TunerCache
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::get(&self, program_fp: &str) -> core::option::Option<[u32; 3]>
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::load(path: &std::path::Path) -> core::result::Result<Self, alloc::string::String>
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::save(&self, path: &std::path::Path) -> core::result::Result<(), alloc::string::String>
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::set(&mut self, program_fp: impl core::convert::Into<alloc::string::String>, size: [u32; 3])
impl core::clone::Clone for vyre_driver_wgpu::runtime::tuner::TunerCache
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::clone(&self) -> vyre_driver_wgpu::runtime::tuner::TunerCache
impl core::cmp::Eq for vyre_driver_wgpu::runtime::tuner::TunerCache
impl core::cmp::PartialEq for vyre_driver_wgpu::runtime::tuner::TunerCache
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::eq(&self, other: &vyre_driver_wgpu::runtime::tuner::TunerCache) -> bool
impl core::default::Default for vyre_driver_wgpu::runtime::tuner::TunerCache
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::default() -> vyre_driver_wgpu::runtime::tuner::TunerCache
impl core::fmt::Debug for vyre_driver_wgpu::runtime::tuner::TunerCache
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::runtime::tuner::TunerCache
impl core::marker::Freeze for vyre_driver_wgpu::runtime::tuner::TunerCache
impl core::marker::Send for vyre_driver_wgpu::runtime::tuner::TunerCache
impl core::marker::Sync for vyre_driver_wgpu::runtime::tuner::TunerCache
impl core::marker::Unpin for vyre_driver_wgpu::runtime::tuner::TunerCache
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::tuner::TunerCache
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::tuner::TunerCache
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::runtime::tuner::TunerCache where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::tuner::TunerCache where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::tuner::TunerCache where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::tuner::TunerCache where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::tuner::TunerCache where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::tuner::TunerCache where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::tuner::TunerCache::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::tuner::TunerCache where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::tuner::TunerCache::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::tuner::TunerCache where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::tuner::TunerCache::Owned = T
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::runtime::tuner::TunerCache where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::tuner::TunerCache where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::tuner::TunerCache where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::tuner::TunerCache where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::tuner::TunerCache::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::tuner::TunerCache
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::tuner::TunerCache
pub type vyre_driver_wgpu::runtime::tuner::TunerCache::Init = T
pub const vyre_driver_wgpu::runtime::tuner::TunerCache::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::tuner::TunerCache::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::tuner::TunerCache::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::tuner::TunerCache::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::tuner::TunerCache::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::tuner::TunerCache
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::tuner::TunerCache
pub fn vyre_driver_wgpu::runtime::tuner::TunerCache::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::tuner::TunerCache
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::tuner::TunerCache
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::tuner::TunerCache where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::tuner::TunerCache where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::tuner::TunerCache where T: core::marker::Sync
pub mod vyre_driver_wgpu::runtime::workgroup_size
pub const vyre_driver_wgpu::runtime::workgroup_size::WORKGROUP_SIZE: [u32; 3]
#[non_exhaustive] pub enum vyre_driver_wgpu::runtime::CacheError
pub vyre_driver_wgpu::runtime::CacheError::EntryTooLarge
pub vyre_driver_wgpu::runtime::CacheError::KeyNotFound
impl core::clone::Clone for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::clone(&self) -> vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::cmp::Eq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::cmp::PartialEq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::eq(&self, other: &vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError) -> bool
impl core::error::Error for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::fmt::Debug for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::StructuralPartialEq for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::clone::Clone
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::Owned = T
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::CacheError where T: core::marker::Sync
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::AccessStats
pub vyre_driver_wgpu::runtime::AccessStats::frequency: u32
pub vyre_driver_wgpu::runtime::AccessStats::last_access: u64
pub vyre_driver_wgpu::runtime::AccessStats::size: u64
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats where T: core::marker::Sync
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::AccessTracker
impl vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::hot_set(&self, n: usize) -> alloc::vec::Vec<u64>
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::new() -> Self
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::record(&mut self, key: u64)
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::stats(&self, key: u64) -> core::option::Option<vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats>
impl core::default::Default for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::default() -> Self
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::lru::AccessTracker::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::lru::AccessTracker::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub type vyre_driver_wgpu::runtime::cache::lru::AccessTracker::Init = T
pub const vyre_driver_wgpu::runtime::cache::lru::AccessTracker::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
pub fn vyre_driver_wgpu::runtime::cache::lru::AccessTracker::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::lru::AccessTracker
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::lru::AccessTracker where T: core::marker::Sync
#[non_exhaustive] pub struct vyre_driver_wgpu::runtime::LruPolicy
pub vyre_driver_wgpu::runtime::LruPolicy::promote_threshold: u32
impl vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::DEFAULT_THRESHOLD: u32
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::new(promote_threshold: u32) -> Self
impl core::default::Default for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::default() -> Self
impl vyre_driver_wgpu::runtime::cache::tiered_cache::TierPolicy for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::eviction_candidate(&self, _tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::eviction_candidate_per_tier(&self, _tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, _tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker, tier_lru: &vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<u64, ()>) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::should_promote(&self, _key: u64, stats: &vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats) -> bool
impl core::marker::Freeze for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::marker::Send for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::marker::Sync for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::marker::Unpin for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where U: core::convert::From<T>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where U: core::convert::Into<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub type vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::Init = T
pub const vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy where T: core::marker::Sync
pub const vyre_driver_wgpu::runtime::WORKGROUP_SIZE: [u32; 3]
pub trait vyre_driver_wgpu::runtime::TierPolicy: core::marker::Send + core::marker::Sync
pub fn vyre_driver_wgpu::runtime::TierPolicy::eviction_candidate(&self, tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::TierPolicy::eviction_candidate_per_tier(&self, tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker, tier_lru: &vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<u64, ()>) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::TierPolicy::should_promote(&self, key: u64, stats: &vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats) -> bool
impl vyre_driver_wgpu::runtime::cache::tiered_cache::TierPolicy for vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::eviction_candidate(&self, _tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::eviction_candidate_per_tier(&self, _tier: usize, entries: &rustc_hash::FxHashMap<u64, vyre_driver_wgpu::runtime::cache::tiered_cache::CacheEntry>, _tracker: &vyre_driver_wgpu::runtime::cache::lru::AccessTracker, tier_lru: &vyre_driver_wgpu::runtime::cache::lru::IntrusiveLru<u64, ()>) -> core::option::Option<u64>
pub fn vyre_driver_wgpu::runtime::cache::tiered_cache::LruPolicy::should_promote(&self, _key: u64, stats: &vyre_driver_wgpu::runtime::cache::tiered_cache::AccessStats) -> bool
pub fn vyre_driver_wgpu::runtime::bg_entry(binding: u32, buffer: &wgpu::api::buffer::Buffer) -> wgpu::api::bind_group::BindGroupEntry<'_>
pub fn vyre_driver_wgpu::runtime::cached_adapter_info() -> vyre_foundation::error::Result<&'static wgpu_types::AdapterInfo>
pub fn vyre_driver_wgpu::runtime::cached_device() -> vyre_foundation::error::Result<alloc::sync::Arc<(wgpu::api::device::Device, wgpu::api::queue::Queue)>>
pub fn vyre_driver_wgpu::runtime::compile_compute_pipeline(device: &wgpu::api::device::Device, label: &str, wgsl_source: &str, entry_point: &str) -> vyre_foundation::error::Result<wgpu::api::compute_pipeline::ComputePipeline>
pub fn vyre_driver_wgpu::runtime::compile_compute_pipeline_with_layout(device: &wgpu::api::device::Device, label: &str, wgsl_source: &str, entry_point: &str, layout: core::option::Option<&wgpu::api::pipeline_layout::PipelineLayout>) -> vyre_foundation::error::Result<wgpu::api::compute_pipeline::ComputePipeline>
pub fn vyre_driver_wgpu::runtime::init_device() -> vyre_foundation::error::Result<((wgpu::api::device::Device, wgpu::api::queue::Queue), wgpu_types::AdapterInfo)>
pub mod vyre_driver_wgpu::spirv_backend
pub struct vyre_driver_wgpu::spirv_backend::SpirvEmitter
impl vyre_driver_wgpu::spirv_backend::SpirvEmitter
pub fn vyre_driver_wgpu::spirv_backend::SpirvEmitter::default_flags() -> naga::back::spv::WriterFlags
pub fn vyre_driver_wgpu::spirv_backend::SpirvEmitter::emit(module: &naga::Module, entry: &str) -> core::result::Result<alloc::vec::Vec<u32>, alloc::string::String>
impl core::marker::Freeze for vyre_driver_wgpu::spirv_backend::SpirvEmitter
impl core::marker::Send for vyre_driver_wgpu::spirv_backend::SpirvEmitter
impl core::marker::Sync for vyre_driver_wgpu::spirv_backend::SpirvEmitter
impl core::marker::Unpin for vyre_driver_wgpu::spirv_backend::SpirvEmitter
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::spirv_backend::SpirvEmitter
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::spirv_backend::SpirvEmitter
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::spirv_backend::SpirvEmitter where U: core::convert::From<T>
pub fn vyre_driver_wgpu::spirv_backend::SpirvEmitter::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::spirv_backend::SpirvEmitter where U: core::convert::Into<T>
pub type vyre_driver_wgpu::spirv_backend::SpirvEmitter::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::spirv_backend::SpirvEmitter::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::spirv_backend::SpirvEmitter where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::spirv_backend::SpirvEmitter::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::spirv_backend::SpirvEmitter::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::spirv_backend::SpirvEmitter where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::spirv_backend::SpirvEmitter::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::spirv_backend::SpirvEmitter where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::spirv_backend::SpirvEmitter::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::spirv_backend::SpirvEmitter where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::spirv_backend::SpirvEmitter::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::spirv_backend::SpirvEmitter
pub fn vyre_driver_wgpu::spirv_backend::SpirvEmitter::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::spirv_backend::SpirvEmitter
pub type vyre_driver_wgpu::spirv_backend::SpirvEmitter::Init = T
pub const vyre_driver_wgpu::spirv_backend::SpirvEmitter::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::spirv_backend::SpirvEmitter::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::spirv_backend::SpirvEmitter::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::spirv_backend::SpirvEmitter::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::spirv_backend::SpirvEmitter::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::spirv_backend::SpirvEmitter
pub fn vyre_driver_wgpu::spirv_backend::SpirvEmitter::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::spirv_backend::SpirvEmitter
pub fn vyre_driver_wgpu::spirv_backend::SpirvEmitter::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::spirv_backend::SpirvEmitter
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::spirv_backend::SpirvEmitter
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::spirv_backend::SpirvEmitter where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::spirv_backend::SpirvEmitter where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::spirv_backend::SpirvEmitter where T: core::marker::Sync
pub const vyre_driver_wgpu::spirv_backend::SPIRV_BACKEND_ID: &str
pub struct vyre_driver_wgpu::DispatchArena
impl vyre_driver_wgpu::DispatchArena
pub fn vyre_driver_wgpu::DispatchArena::new() -> Self
impl core::clone::Clone for vyre_driver_wgpu::DispatchArena
pub fn vyre_driver_wgpu::DispatchArena::clone(&self) -> vyre_driver_wgpu::DispatchArena
impl core::default::Default for vyre_driver_wgpu::DispatchArena
pub fn vyre_driver_wgpu::DispatchArena::default() -> vyre_driver_wgpu::DispatchArena
impl core::fmt::Debug for vyre_driver_wgpu::DispatchArena
pub fn vyre_driver_wgpu::DispatchArena::fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver_wgpu::DispatchArena
impl core::marker::Send for vyre_driver_wgpu::DispatchArena
impl core::marker::Sync for vyre_driver_wgpu::DispatchArena
impl core::marker::Unpin for vyre_driver_wgpu::DispatchArena
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::DispatchArena
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::DispatchArena
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::DispatchArena where U: core::convert::From<T>
pub fn vyre_driver_wgpu::DispatchArena::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::DispatchArena where U: core::convert::Into<T>
pub type vyre_driver_wgpu::DispatchArena::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::DispatchArena::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::DispatchArena where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::DispatchArena::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::DispatchArena::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::DispatchArena where T: core::clone::Clone
pub type vyre_driver_wgpu::DispatchArena::Owned = T
pub fn vyre_driver_wgpu::DispatchArena::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::DispatchArena::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::DispatchArena where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::DispatchArena::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::DispatchArena where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::DispatchArena::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::DispatchArena where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::DispatchArena::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::DispatchArena where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::DispatchArena::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::DispatchArena
pub fn vyre_driver_wgpu::DispatchArena::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::DispatchArena
pub type vyre_driver_wgpu::DispatchArena::Init = T
pub const vyre_driver_wgpu::DispatchArena::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::DispatchArena::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::DispatchArena::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::DispatchArena::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::DispatchArena::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::DispatchArena
pub fn vyre_driver_wgpu::DispatchArena::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::DispatchArena
pub fn vyre_driver_wgpu::DispatchArena::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::DispatchArena
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::DispatchArena
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::DispatchArena where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::DispatchArena where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::DispatchArena where T: core::marker::Sync
pub struct vyre_driver_wgpu::WgpuBackend
impl vyre_driver_wgpu::WgpuBackend
pub fn vyre_driver_wgpu::WgpuBackend::acquire() -> core::result::Result<Self, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::WgpuBackend::adapter_info(&self) -> &wgpu_types::AdapterInfo
pub fn vyre_driver_wgpu::WgpuBackend::compile_streaming(&self, program: &vyre_foundation::ir_inner::model::program::Program, config: vyre_driver::backend::DispatchConfig) -> core::result::Result<vyre_driver_wgpu::engine::streaming::StreamingDispatch, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::WgpuBackend::device_limits(&self) -> &wgpu_types::Limits
pub fn vyre_driver_wgpu::WgpuBackend::force_device_lost(&self) -> core::result::Result<(), vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::WgpuBackend::new() -> core::result::Result<Self, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::WgpuBackend::probe_op(&self, op: vyre_spec::un_op::UnOp, input: &[u8]) -> core::result::Result<alloc::vec::Vec<u8>, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::WgpuBackend::stats(&self) -> vyre_driver_wgpu::WgpuBackendStats
impl core::clone::Clone for vyre_driver_wgpu::WgpuBackend
pub fn vyre_driver_wgpu::WgpuBackend::clone(&self) -> vyre_driver_wgpu::WgpuBackend
impl core::fmt::Debug for vyre_driver_wgpu::WgpuBackend
pub fn vyre_driver_wgpu::WgpuBackend::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl vyre_driver::backend::VyreBackend for vyre_driver_wgpu::WgpuBackend
pub fn vyre_driver_wgpu::WgpuBackend::compile_native(&self, program: &vyre_foundation::ir_inner::model::program::Program, config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<core::option::Option<alloc::sync::Arc<dyn vyre_driver::backend::CompiledPipeline>>, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::WgpuBackend::device_lost(&self) -> bool
pub fn vyre_driver_wgpu::WgpuBackend::dispatch(&self, program: &vyre_foundation::ir_inner::model::program::Program, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::WgpuBackend::dispatch_borrowed(&self, program: &vyre_foundation::ir_inner::model::program::Program, inputs: &[&[u8]], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::WgpuBackend::flush(&self) -> core::result::Result<(), vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::WgpuBackend::id(&self) -> &'static str
pub fn vyre_driver_wgpu::WgpuBackend::is_distributed(&self) -> bool
pub fn vyre_driver_wgpu::WgpuBackend::max_storage_buffer_bytes(&self) -> u64
pub fn vyre_driver_wgpu::WgpuBackend::max_workgroup_size(&self) -> [u32; 3]
pub fn vyre_driver_wgpu::WgpuBackend::supports_async_compute(&self) -> bool
pub fn vyre_driver_wgpu::WgpuBackend::supports_bf16(&self) -> bool
pub fn vyre_driver_wgpu::WgpuBackend::supports_f16(&self) -> bool
pub fn vyre_driver_wgpu::WgpuBackend::supports_indirect_dispatch(&self) -> bool
pub fn vyre_driver_wgpu::WgpuBackend::supports_subgroup_ops(&self) -> bool
pub fn vyre_driver_wgpu::WgpuBackend::supports_tensor_cores(&self) -> bool
pub fn vyre_driver_wgpu::WgpuBackend::try_recover(&self) -> core::result::Result<(), vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::WgpuBackend::version(&self) -> &'static str
impl vyre_driver::backend::capability::Compilable for vyre_driver_wgpu::WgpuBackend
pub type vyre_driver_wgpu::WgpuBackend::Compiled = vyre_driver_wgpu::WgpuIR
pub fn vyre_driver_wgpu::WgpuBackend::compile(&self, program: &vyre_foundation::ir_inner::model::program::Program) -> core::result::Result<Self::Compiled, vyre_driver::backend::BackendError>
pub fn vyre_driver_wgpu::WgpuBackend::execute_compiled(&self, compiled: &Self::Compiled, inputs: &[vyre_driver::backend::capability::MemoryRef<'_>], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<vyre_driver::backend::capability::Memory>, vyre_driver::backend::BackendError>
impl vyre_driver::backend::capability::Executable for vyre_driver_wgpu::WgpuBackend
pub fn vyre_driver_wgpu::WgpuBackend::execute(&self, program: &vyre_foundation::ir_inner::model::program::Program, inputs: &[vyre_driver::backend::capability::MemoryRef<'_>], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<vyre_driver::backend::capability::Memory>, vyre_driver::backend::BackendError>
impl vyre_driver_wgpu::ext::WgslDispatchExt for vyre_driver_wgpu::WgpuBackend
pub fn vyre_driver_wgpu::WgpuBackend::dispatch_wgsl(&self, wgsl: &str, input: &[u8], output_size: usize, workgroup_size: u32) -> core::result::Result<alloc::vec::Vec<u8>, alloc::string::String>
impl vyre_foundation::lower::LoweringPipeline<naga::Module> for vyre_driver_wgpu::WgpuBackend
pub type vyre_driver_wgpu::WgpuBackend::BackendIr = vyre_driver_wgpu::lowering::WgpuProgram
pub fn vyre_driver_wgpu::WgpuBackend::lower_to_backend_ir(&self, program: &vyre_foundation::ir_inner::model::program::Program) -> core::result::Result<Self::BackendIr, vyre_foundation::lower::LoweringError>
pub fn vyre_driver_wgpu::WgpuBackend::lower_to_target(&self, bir: &Self::BackendIr) -> core::result::Result<naga::Module, vyre_foundation::lower::LoweringError>
impl core::marker::Freeze for vyre_driver_wgpu::WgpuBackend
impl core::marker::Send for vyre_driver_wgpu::WgpuBackend
impl core::marker::Sync for vyre_driver_wgpu::WgpuBackend
impl core::marker::Unpin for vyre_driver_wgpu::WgpuBackend
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::WgpuBackend
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::WgpuBackend
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::WgpuBackend where U: core::convert::From<T>
pub fn vyre_driver_wgpu::WgpuBackend::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::WgpuBackend where U: core::convert::Into<T>
pub type vyre_driver_wgpu::WgpuBackend::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::WgpuBackend::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::WgpuBackend where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::WgpuBackend::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::WgpuBackend::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::WgpuBackend where T: core::clone::Clone
pub type vyre_driver_wgpu::WgpuBackend::Owned = T
pub fn vyre_driver_wgpu::WgpuBackend::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::WgpuBackend::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::WgpuBackend where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::WgpuBackend::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::WgpuBackend where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::WgpuBackend::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::WgpuBackend where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::WgpuBackend::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::WgpuBackend where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::WgpuBackend::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::WgpuBackend
pub fn vyre_driver_wgpu::WgpuBackend::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::WgpuBackend
pub type vyre_driver_wgpu::WgpuBackend::Init = T
pub const vyre_driver_wgpu::WgpuBackend::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::WgpuBackend::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::WgpuBackend::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::WgpuBackend::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::WgpuBackend::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::WgpuBackend
pub fn vyre_driver_wgpu::WgpuBackend::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::WgpuBackend
pub fn vyre_driver_wgpu::WgpuBackend::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::WgpuBackend
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::WgpuBackend
impl<T> vyre_driver::backend::capability::Backend for vyre_driver_wgpu::WgpuBackend where T: vyre_driver::backend::VyreBackend + ?core::marker::Sized
pub fn vyre_driver_wgpu::WgpuBackend::id(&self) -> &'static str
pub fn vyre_driver_wgpu::WgpuBackend::supported_ops(&self) -> &std::collections::hash::set::HashSet<alloc::sync::Arc<str>>
pub fn vyre_driver_wgpu::WgpuBackend::version(&self) -> &'static str
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::WgpuBackend where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::WgpuBackend where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::WgpuBackend where T: core::marker::Sync
pub struct vyre_driver_wgpu::WgpuBackendStats
pub vyre_driver_wgpu::WgpuBackendStats::adapter_name: alloc::string::String
pub vyre_driver_wgpu::WgpuBackendStats::persistent_pool: vyre_driver_wgpu::buffer::BufferPoolStats
pub vyre_driver_wgpu::WgpuBackendStats::pipeline_cache_capacity: usize
pub vyre_driver_wgpu::WgpuBackendStats::pipeline_cache_entries: usize
impl core::clone::Clone for vyre_driver_wgpu::WgpuBackendStats
pub fn vyre_driver_wgpu::WgpuBackendStats::clone(&self) -> vyre_driver_wgpu::WgpuBackendStats
impl core::fmt::Debug for vyre_driver_wgpu::WgpuBackendStats
pub fn vyre_driver_wgpu::WgpuBackendStats::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver_wgpu::WgpuBackendStats
impl core::marker::Send for vyre_driver_wgpu::WgpuBackendStats
impl core::marker::Sync for vyre_driver_wgpu::WgpuBackendStats
impl core::marker::Unpin for vyre_driver_wgpu::WgpuBackendStats
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::WgpuBackendStats
impl core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::WgpuBackendStats
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::WgpuBackendStats where U: core::convert::From<T>
pub fn vyre_driver_wgpu::WgpuBackendStats::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::WgpuBackendStats where U: core::convert::Into<T>
pub type vyre_driver_wgpu::WgpuBackendStats::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::WgpuBackendStats::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::WgpuBackendStats where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::WgpuBackendStats::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::WgpuBackendStats::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver_wgpu::WgpuBackendStats where T: core::clone::Clone
pub type vyre_driver_wgpu::WgpuBackendStats::Owned = T
pub fn vyre_driver_wgpu::WgpuBackendStats::clone_into(&self, target: &mut T)
pub fn vyre_driver_wgpu::WgpuBackendStats::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver_wgpu::WgpuBackendStats where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::WgpuBackendStats::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::WgpuBackendStats where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::WgpuBackendStats::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::WgpuBackendStats where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::WgpuBackendStats::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver_wgpu::WgpuBackendStats where T: core::clone::Clone
pub unsafe fn vyre_driver_wgpu::WgpuBackendStats::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver_wgpu::WgpuBackendStats
pub fn vyre_driver_wgpu::WgpuBackendStats::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::WgpuBackendStats
pub type vyre_driver_wgpu::WgpuBackendStats::Init = T
pub const vyre_driver_wgpu::WgpuBackendStats::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::WgpuBackendStats::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::WgpuBackendStats::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::WgpuBackendStats::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::WgpuBackendStats::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::WgpuBackendStats
pub fn vyre_driver_wgpu::WgpuBackendStats::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::WgpuBackendStats
pub fn vyre_driver_wgpu::WgpuBackendStats::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::WgpuBackendStats
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::WgpuBackendStats
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::WgpuBackendStats where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::WgpuBackendStats where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::WgpuBackendStats where T: core::marker::Sync
pub struct vyre_driver_wgpu::WgpuIR
pub vyre_driver_wgpu::WgpuIR::pipeline: vyre_driver_wgpu::pipeline::WgpuPipeline
impl core::marker::Freeze for vyre_driver_wgpu::WgpuIR
impl core::marker::Send for vyre_driver_wgpu::WgpuIR
impl core::marker::Sync for vyre_driver_wgpu::WgpuIR
impl core::marker::Unpin for vyre_driver_wgpu::WgpuIR
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver_wgpu::WgpuIR
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver_wgpu::WgpuIR
impl<T, U> core::convert::Into<U> for vyre_driver_wgpu::WgpuIR where U: core::convert::From<T>
pub fn vyre_driver_wgpu::WgpuIR::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver_wgpu::WgpuIR where U: core::convert::Into<T>
pub type vyre_driver_wgpu::WgpuIR::Error = core::convert::Infallible
pub fn vyre_driver_wgpu::WgpuIR::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver_wgpu::WgpuIR where U: core::convert::TryFrom<T>
pub type vyre_driver_wgpu::WgpuIR::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver_wgpu::WgpuIR::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver_wgpu::WgpuIR where T: 'static + ?core::marker::Sized
pub fn vyre_driver_wgpu::WgpuIR::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver_wgpu::WgpuIR where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::WgpuIR::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver_wgpu::WgpuIR where T: ?core::marker::Sized
pub fn vyre_driver_wgpu::WgpuIR::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver_wgpu::WgpuIR
pub fn vyre_driver_wgpu::WgpuIR::from(t: T) -> T
impl<T> crossbeam_epoch::atomic::Pointable for vyre_driver_wgpu::WgpuIR
pub type vyre_driver_wgpu::WgpuIR::Init = T
pub const vyre_driver_wgpu::WgpuIR::ALIGN: usize
pub unsafe fn vyre_driver_wgpu::WgpuIR::deref<'a>(ptr: usize) -> &'a T
pub unsafe fn vyre_driver_wgpu::WgpuIR::deref_mut<'a>(ptr: usize) -> &'a mut T
pub unsafe fn vyre_driver_wgpu::WgpuIR::drop(ptr: usize)
pub unsafe fn vyre_driver_wgpu::WgpuIR::init(init: <T as crossbeam_epoch::atomic::Pointable>::Init) -> usize
impl<T> khronos_egl::Downcast<T> for vyre_driver_wgpu::WgpuIR
pub fn vyre_driver_wgpu::WgpuIR::downcast(&self) -> &T
impl<T> khronos_egl::Upcast<T> for vyre_driver_wgpu::WgpuIR
pub fn vyre_driver_wgpu::WgpuIR::upcast(&self) -> core::option::Option<&T>
impl<T> tracing::instrument::Instrument for vyre_driver_wgpu::WgpuIR
impl<T> tracing::instrument::WithSubscriber for vyre_driver_wgpu::WgpuIR
impl<T> wgpu_types::send_sync::WasmNotSend for vyre_driver_wgpu::WgpuIR where T: core::marker::Send
impl<T> wgpu_types::send_sync::WasmNotSendSync for vyre_driver_wgpu::WgpuIR where T: wgpu_types::send_sync::WasmNotSend + wgpu_types::send_sync::WasmNotSync
impl<T> wgpu_types::send_sync::WasmNotSync for vyre_driver_wgpu::WgpuIR where T: core::marker::Sync
pub trait vyre_driver_wgpu::WgslDispatchExt
pub fn vyre_driver_wgpu::WgslDispatchExt::dispatch_wgsl(&self, wgsl: &str, input: &[u8], output_size: usize, workgroup_size: u32) -> core::result::Result<alloc::vec::Vec<u8>, alloc::string::String>
impl vyre_driver_wgpu::ext::WgslDispatchExt for vyre_driver_wgpu::WgpuBackend
pub fn vyre_driver_wgpu::WgpuBackend::dispatch_wgsl(&self, wgsl: &str, input: &[u8], output_size: usize, workgroup_size: u32) -> core::result::Result<alloc::vec::Vec<u8>, alloc::string::String>
