pub mod vyre_driver
pub use vyre_driver::AttrSchema
pub use vyre_driver::AttrType
pub use vyre_driver::Category
pub use vyre_driver::CpuRef
pub use vyre_driver::Error
pub use vyre_driver::InternedOpId
pub use vyre_driver::LoweringCtx
pub use vyre_driver::LoweringTable
pub use vyre_driver::MetalBuilder
pub use vyre_driver::MetalModule
pub use vyre_driver::NagaBuilder
pub use vyre_driver::OpDef
pub use vyre_driver::PtxBuilder
pub use vyre_driver::PtxModule
pub use vyre_driver::Signature
pub use vyre_driver::SpirvBuilder
pub use vyre_driver::TypedParam
pub use vyre_driver::error
pub use vyre_driver::intern_string
pub mod vyre_driver::backend
pub mod vyre_driver::backend::lowering
pub trait vyre_driver::backend::lowering::LowerableOp: core::marker::Send + core::marker::Sync + 'static
pub fn vyre_driver::backend::lowering::LowerableOp::lower_naga(&self, _ctx: &mut dyn vyre_driver::backend::lowering::NagaGenCtx, _program: &vyre_foundation::ir_inner::model::program::Program) -> core::result::Result<(), alloc::string::String>
pub fn vyre_driver::backend::lowering::LowerableOp::lower_spirv(&self, _ctx: &mut (), _program: &vyre_foundation::ir_inner::model::program::Program) -> core::result::Result<(), alloc::string::String>
pub trait vyre_driver::backend::lowering::NagaGenCtx
pub fn vyre_driver::backend::lowering::NagaGenCtx::register_expression(&mut self, format: &str) -> core::result::Result<(), ()>
pub mod vyre_driver::backend::validation
pub fn vyre_driver::backend::validation::default_supported_ops() -> &'static std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn vyre_driver::backend::validation::node_op_id(node: &vyre_foundation::ir_inner::model::generated::Node) -> vyre_foundation::ir_inner::model::node_kind::OpId
pub fn vyre_driver::backend::validation::validate_program(program: &vyre_foundation::ir_inner::model::program::Program, backend: &dyn vyre_driver::backend::Backend) -> core::result::Result<(), vyre_foundation::validate::validation_error::ValidationError>
#[non_exhaustive] pub enum vyre_driver::backend::BackendError
pub vyre_driver::backend::BackendError::DeviceOutOfMemory
pub vyre_driver::backend::BackendError::DeviceOutOfMemory::available: u64
pub vyre_driver::backend::BackendError::DeviceOutOfMemory::requested: u64
pub vyre_driver::backend::BackendError::DispatchFailed
pub vyre_driver::backend::BackendError::DispatchFailed::code: core::option::Option<i32>
pub vyre_driver::backend::BackendError::DispatchFailed::message: alloc::string::String
pub vyre_driver::backend::BackendError::InvalidProgram
pub vyre_driver::backend::BackendError::InvalidProgram::fix: alloc::string::String
pub vyre_driver::backend::BackendError::Raw(alloc::string::String)
pub vyre_driver::backend::BackendError::KernelCompileFailed
pub vyre_driver::backend::BackendError::KernelCompileFailed::backend: alloc::string::String
pub vyre_driver::backend::BackendError::KernelCompileFailed::compiler_message: alloc::string::String
pub vyre_driver::backend::BackendError::UnsupportedFeature
pub vyre_driver::backend::BackendError::UnsupportedFeature::backend: alloc::string::String
pub vyre_driver::backend::BackendError::UnsupportedFeature::name: alloc::string::String
impl vyre_driver::backend::BackendError
pub fn vyre_driver::backend::BackendError::code(&self) -> vyre_driver::backend::ErrorCode
pub fn vyre_driver::backend::BackendError::into_message(self) -> alloc::string::String
pub fn vyre_driver::backend::BackendError::message(&self) -> alloc::string::String
pub fn vyre_driver::backend::BackendError::new(message: impl core::convert::Into<alloc::string::String>) -> Self
pub fn vyre_driver::backend::BackendError::unsupported_extension(backend: impl core::convert::Into<alloc::string::String>, extension_kind: &str, debug_identity: &str) -> Self
impl core::clone::Clone for vyre_driver::backend::BackendError
pub fn vyre_driver::backend::BackendError::clone(&self) -> vyre_driver::backend::BackendError
impl core::cmp::Eq for vyre_driver::backend::BackendError
impl core::cmp::PartialEq for vyre_driver::backend::BackendError
pub fn vyre_driver::backend::BackendError::eq(&self, other: &vyre_driver::backend::BackendError) -> bool
impl core::convert::From<vyre_foundation::error::Error> for vyre_driver::backend::BackendError
pub fn vyre_driver::backend::BackendError::from(error: vyre_foundation::error::Error) -> Self
impl core::error::Error for vyre_driver::backend::BackendError
impl core::fmt::Debug for vyre_driver::backend::BackendError
pub fn vyre_driver::backend::BackendError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::backend::BackendError
pub fn vyre_driver::backend::BackendError::fmt(&self, __formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::backend::BackendError
impl core::marker::Freeze for vyre_driver::backend::BackendError
impl core::marker::Send for vyre_driver::backend::BackendError
impl core::marker::Sync for vyre_driver::backend::BackendError
impl core::marker::Unpin for vyre_driver::backend::BackendError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::backend::BackendError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::backend::BackendError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::backend::BackendError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::backend::BackendError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::backend::BackendError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::backend::BackendError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::backend::BackendError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::backend::BackendError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::backend::BackendError where U: core::convert::From<T>
pub fn vyre_driver::backend::BackendError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::backend::BackendError where U: core::convert::Into<T>
pub type vyre_driver::backend::BackendError::Error = core::convert::Infallible
pub fn vyre_driver::backend::BackendError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::backend::BackendError where U: core::convert::TryFrom<T>
pub type vyre_driver::backend::BackendError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::backend::BackendError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::backend::BackendError where T: core::clone::Clone
pub type vyre_driver::backend::BackendError::Owned = T
pub fn vyre_driver::backend::BackendError::clone_into(&self, target: &mut T)
pub fn vyre_driver::backend::BackendError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::backend::BackendError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::backend::BackendError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::backend::BackendError where T: 'static + ?core::marker::Sized
pub fn vyre_driver::backend::BackendError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::backend::BackendError where T: ?core::marker::Sized
pub fn vyre_driver::backend::BackendError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::backend::BackendError where T: ?core::marker::Sized
pub fn vyre_driver::backend::BackendError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::backend::BackendError where T: core::clone::Clone
pub unsafe fn vyre_driver::backend::BackendError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::backend::BackendError
pub fn vyre_driver::backend::BackendError::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::backend::BackendError
impl<T> tracing::instrument::WithSubscriber for vyre_driver::backend::BackendError
#[non_exhaustive] pub enum vyre_driver::backend::ErrorCode
pub vyre_driver::backend::ErrorCode::DeviceOutOfMemory
pub vyre_driver::backend::ErrorCode::DispatchFailed
pub vyre_driver::backend::ErrorCode::InvalidProgram
pub vyre_driver::backend::ErrorCode::KernelCompileFailed
pub vyre_driver::backend::ErrorCode::Unknown
pub vyre_driver::backend::ErrorCode::UnsupportedFeature
impl vyre_driver::backend::ErrorCode
pub const fn vyre_driver::backend::ErrorCode::stable_id(self) -> u32
impl core::clone::Clone for vyre_driver::backend::ErrorCode
pub fn vyre_driver::backend::ErrorCode::clone(&self) -> vyre_driver::backend::ErrorCode
impl core::cmp::Eq for vyre_driver::backend::ErrorCode
impl core::cmp::PartialEq for vyre_driver::backend::ErrorCode
pub fn vyre_driver::backend::ErrorCode::eq(&self, other: &vyre_driver::backend::ErrorCode) -> bool
impl core::fmt::Debug for vyre_driver::backend::ErrorCode
pub fn vyre_driver::backend::ErrorCode::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::backend::ErrorCode
impl core::marker::StructuralPartialEq for vyre_driver::backend::ErrorCode
impl core::marker::Freeze for vyre_driver::backend::ErrorCode
impl core::marker::Send for vyre_driver::backend::ErrorCode
impl core::marker::Sync for vyre_driver::backend::ErrorCode
impl core::marker::Unpin for vyre_driver::backend::ErrorCode
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::backend::ErrorCode
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::backend::ErrorCode
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::backend::ErrorCode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::backend::ErrorCode::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::backend::ErrorCode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::backend::ErrorCode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::backend::ErrorCode::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::backend::ErrorCode::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::backend::ErrorCode where U: core::convert::From<T>
pub fn vyre_driver::backend::ErrorCode::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::backend::ErrorCode where U: core::convert::Into<T>
pub type vyre_driver::backend::ErrorCode::Error = core::convert::Infallible
pub fn vyre_driver::backend::ErrorCode::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::backend::ErrorCode where U: core::convert::TryFrom<T>
pub type vyre_driver::backend::ErrorCode::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::backend::ErrorCode::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::backend::ErrorCode where T: core::clone::Clone
pub type vyre_driver::backend::ErrorCode::Owned = T
pub fn vyre_driver::backend::ErrorCode::clone_into(&self, target: &mut T)
pub fn vyre_driver::backend::ErrorCode::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::backend::ErrorCode where T: 'static + ?core::marker::Sized
pub fn vyre_driver::backend::ErrorCode::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::backend::ErrorCode where T: ?core::marker::Sized
pub fn vyre_driver::backend::ErrorCode::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::backend::ErrorCode where T: ?core::marker::Sized
pub fn vyre_driver::backend::ErrorCode::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::backend::ErrorCode where T: core::clone::Clone
pub unsafe fn vyre_driver::backend::ErrorCode::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::backend::ErrorCode
pub fn vyre_driver::backend::ErrorCode::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::backend::ErrorCode
impl<T> tracing::instrument::WithSubscriber for vyre_driver::backend::ErrorCode
pub struct vyre_driver::backend::BackendRegistration
pub vyre_driver::backend::BackendRegistration::factory: fn() -> core::result::Result<alloc::boxed::Box<dyn vyre_driver::backend::VyreBackend>, vyre_driver::backend::BackendError>
pub vyre_driver::backend::BackendRegistration::id: &'static str
pub vyre_driver::backend::BackendRegistration::supported_ops: fn() -> &'static std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
impl inventory::Collect for vyre_driver::BackendRegistration
impl core::marker::Freeze for vyre_driver::BackendRegistration
impl core::marker::Send for vyre_driver::BackendRegistration
impl core::marker::Sync for vyre_driver::BackendRegistration
impl core::marker::Unpin for vyre_driver::BackendRegistration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::BackendRegistration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::BackendRegistration
impl<T, U> core::convert::Into<U> for vyre_driver::BackendRegistration where U: core::convert::From<T>
pub fn vyre_driver::BackendRegistration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::BackendRegistration where U: core::convert::Into<T>
pub type vyre_driver::BackendRegistration::Error = core::convert::Infallible
pub fn vyre_driver::BackendRegistration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::BackendRegistration where U: core::convert::TryFrom<T>
pub type vyre_driver::BackendRegistration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::BackendRegistration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::BackendRegistration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::BackendRegistration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::BackendRegistration where T: ?core::marker::Sized
pub fn vyre_driver::BackendRegistration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::BackendRegistration where T: ?core::marker::Sized
pub fn vyre_driver::BackendRegistration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::BackendRegistration
pub fn vyre_driver::BackendRegistration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::BackendRegistration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::BackendRegistration
#[non_exhaustive] pub struct vyre_driver::backend::DispatchConfig
pub vyre_driver::backend::DispatchConfig::label: core::option::Option<alloc::string::String>
pub vyre_driver::backend::DispatchConfig::max_output_bytes: core::option::Option<usize>
pub vyre_driver::backend::DispatchConfig::profile: core::option::Option<alloc::string::String>
pub vyre_driver::backend::DispatchConfig::timeout: core::option::Option<core::time::Duration>
pub vyre_driver::backend::DispatchConfig::ulp_budget: core::option::Option<u8>
impl core::clone::Clone for vyre_driver::backend::DispatchConfig
pub fn vyre_driver::backend::DispatchConfig::clone(&self) -> vyre_driver::backend::DispatchConfig
impl core::cmp::Eq for vyre_driver::backend::DispatchConfig
impl core::cmp::PartialEq for vyre_driver::backend::DispatchConfig
pub fn vyre_driver::backend::DispatchConfig::eq(&self, other: &vyre_driver::backend::DispatchConfig) -> bool
impl core::default::Default for vyre_driver::backend::DispatchConfig
pub fn vyre_driver::backend::DispatchConfig::default() -> vyre_driver::backend::DispatchConfig
impl core::fmt::Debug for vyre_driver::backend::DispatchConfig
pub fn vyre_driver::backend::DispatchConfig::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::backend::DispatchConfig
impl core::marker::Freeze for vyre_driver::backend::DispatchConfig
impl core::marker::Send for vyre_driver::backend::DispatchConfig
impl core::marker::Sync for vyre_driver::backend::DispatchConfig
impl core::marker::Unpin for vyre_driver::backend::DispatchConfig
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::backend::DispatchConfig
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::backend::DispatchConfig
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::backend::DispatchConfig where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::backend::DispatchConfig::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::backend::DispatchConfig where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::backend::DispatchConfig where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::backend::DispatchConfig::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::backend::DispatchConfig::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::backend::DispatchConfig where U: core::convert::From<T>
pub fn vyre_driver::backend::DispatchConfig::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::backend::DispatchConfig where U: core::convert::Into<T>
pub type vyre_driver::backend::DispatchConfig::Error = core::convert::Infallible
pub fn vyre_driver::backend::DispatchConfig::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::backend::DispatchConfig where U: core::convert::TryFrom<T>
pub type vyre_driver::backend::DispatchConfig::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::backend::DispatchConfig::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::backend::DispatchConfig where T: core::clone::Clone
pub type vyre_driver::backend::DispatchConfig::Owned = T
pub fn vyre_driver::backend::DispatchConfig::clone_into(&self, target: &mut T)
pub fn vyre_driver::backend::DispatchConfig::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::backend::DispatchConfig where T: 'static + ?core::marker::Sized
pub fn vyre_driver::backend::DispatchConfig::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::backend::DispatchConfig where T: ?core::marker::Sized
pub fn vyre_driver::backend::DispatchConfig::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::backend::DispatchConfig where T: ?core::marker::Sized
pub fn vyre_driver::backend::DispatchConfig::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::backend::DispatchConfig where T: core::clone::Clone
pub unsafe fn vyre_driver::backend::DispatchConfig::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::backend::DispatchConfig
pub fn vyre_driver::backend::DispatchConfig::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::backend::DispatchConfig
impl<T> tracing::instrument::WithSubscriber for vyre_driver::backend::DispatchConfig
pub trait vyre_driver::backend::Backend: core::marker::Send + core::marker::Sync
pub fn vyre_driver::backend::Backend::id(&self) -> &'static str
pub fn vyre_driver::backend::Backend::supported_ops(&self) -> &std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn vyre_driver::backend::Backend::version(&self) -> &'static str
impl<T: vyre_driver::backend::VyreBackend + ?core::marker::Sized> vyre_driver::backend::Backend for T
pub fn T::id(&self) -> &'static str
pub fn T::supported_ops(&self) -> &std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn T::version(&self) -> &'static str
pub trait vyre_driver::backend::Compilable: vyre_driver::backend::Backend
pub type vyre_driver::backend::Compilable::Compiled: core::marker::Send + core::marker::Sync
pub fn vyre_driver::backend::Compilable::compile(&self, program: &vyre_foundation::ir_inner::model::program::Program) -> core::result::Result<Self::Compiled, vyre_driver::backend::BackendError>
pub fn vyre_driver::backend::Compilable::execute_compiled(&self, compiled: &Self::Compiled, inputs: &[vyre_driver::MemoryRef<'_>], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<vyre_driver::Memory>, vyre_driver::backend::BackendError>
pub trait vyre_driver::backend::CompiledPipeline: core::marker::Send + core::marker::Sync
pub fn vyre_driver::backend::CompiledPipeline::dispatch(&self, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::backend::BackendError>
pub fn vyre_driver::backend::CompiledPipeline::dispatch_borrowed(&self, inputs: &[&[u8]], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::backend::BackendError>
pub fn vyre_driver::backend::CompiledPipeline::id(&self) -> &str
pub trait vyre_driver::backend::Executable: vyre_driver::backend::Backend
pub fn vyre_driver::backend::Executable::execute(&self, program: &vyre_foundation::ir_inner::model::program::Program, inputs: &[vyre_driver::MemoryRef<'_>], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<vyre_driver::Memory>, vyre_driver::backend::BackendError>
pub trait vyre_driver::backend::PendingDispatch: core::marker::Send + core::marker::Sync
pub fn vyre_driver::backend::PendingDispatch::await_result(self: alloc::boxed::Box<Self>) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::backend::BackendError>
pub fn vyre_driver::backend::PendingDispatch::is_ready(&self) -> bool
pub trait vyre_driver::backend::Streamable: vyre_driver::backend::Backend
pub fn vyre_driver::backend::Streamable::stream<'a, I: core::iter::traits::iterator::Iterator<Item = vyre_driver::MemoryRef<'a>>>(&self, program: &vyre_foundation::ir_inner::model::program::Program, chunks: I, config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::boxed::Box<dyn core::iter::traits::iterator::Iterator<Item = core::result::Result<vyre_driver::Memory, vyre_driver::backend::BackendError>>>, vyre_driver::backend::BackendError>
pub trait vyre_driver::backend::VyreBackend: core::marker::Send + core::marker::Sync
pub fn vyre_driver::backend::VyreBackend::compile_native(&self, _program: &vyre_foundation::ir_inner::model::program::Program, _config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<core::option::Option<alloc::sync::Arc<dyn vyre_driver::backend::CompiledPipeline>>, vyre_driver::backend::BackendError>
pub fn vyre_driver::backend::VyreBackend::device_lost(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::dispatch(&self, program: &vyre_foundation::ir_inner::model::program::Program, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::backend::BackendError>
pub fn vyre_driver::backend::VyreBackend::dispatch_async(&self, program: &vyre_foundation::ir_inner::model::program::Program, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::boxed::Box<dyn vyre_driver::backend::PendingDispatch>, vyre_driver::backend::BackendError>
pub fn vyre_driver::backend::VyreBackend::dispatch_borrowed(&self, program: &vyre_foundation::ir_inner::model::program::Program, inputs: &[&[u8]], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::backend::BackendError>
pub fn vyre_driver::backend::VyreBackend::flush(&self) -> core::result::Result<(), vyre_driver::backend::BackendError>
pub fn vyre_driver::backend::VyreBackend::id(&self) -> &'static str
pub fn vyre_driver::backend::VyreBackend::is_distributed(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::max_storage_buffer_bytes(&self) -> u64
pub fn vyre_driver::backend::VyreBackend::max_workgroup_size(&self) -> [u32; 3]
pub fn vyre_driver::backend::VyreBackend::prepare(&self) -> core::result::Result<(), vyre_driver::backend::BackendError>
pub fn vyre_driver::backend::VyreBackend::shutdown(&self) -> core::result::Result<(), vyre_driver::backend::BackendError>
pub fn vyre_driver::backend::VyreBackend::supported_ops(&self) -> &std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn vyre_driver::backend::VyreBackend::supports_async_compute(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::supports_bf16(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::supports_f16(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::supports_indirect_dispatch(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::supports_subgroup_ops(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::supports_tensor_cores(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::try_recover(&self) -> core::result::Result<(), vyre_driver::backend::BackendError>
pub fn vyre_driver::backend::VyreBackend::version(&self) -> &'static str
pub fn vyre_driver::backend::core_supported_ops() -> &'static std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn vyre_driver::backend::default_supported_ops() -> &'static std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn vyre_driver::backend::dialect_and_language_supported_ops() -> &'static std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn vyre_driver::backend::dialect_only_supported_ops() -> &'static std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn vyre_driver::backend::node_op_id(node: &vyre_foundation::ir_inner::model::generated::Node) -> vyre_foundation::ir_inner::model::node_kind::OpId
pub fn vyre_driver::backend::registered_backends() -> &'static [&'static vyre_driver::BackendRegistration]
pub fn vyre_driver::backend::validate_program(program: &vyre_foundation::ir_inner::model::program::Program, backend: &dyn vyre_driver::backend::Backend) -> core::result::Result<(), vyre_foundation::validate::validation_error::ValidationError>
pub type vyre_driver::backend::Memory = alloc::vec::Vec<u8>
pub type vyre_driver::backend::MemoryRef<'a> = &'a [u8]
pub mod vyre_driver::diagnostics
pub enum vyre_driver::diagnostics::Severity
pub vyre_driver::diagnostics::Severity::Error
pub vyre_driver::diagnostics::Severity::Note
pub vyre_driver::diagnostics::Severity::Warning
impl vyre_driver::Severity
pub const fn vyre_driver::Severity::label(self) -> &'static str
impl core::clone::Clone for vyre_driver::Severity
pub fn vyre_driver::Severity::clone(&self) -> vyre_driver::Severity
impl core::cmp::Eq for vyre_driver::Severity
impl core::cmp::PartialEq for vyre_driver::Severity
pub fn vyre_driver::Severity::eq(&self, other: &vyre_driver::Severity) -> bool
impl core::fmt::Debug for vyre_driver::Severity
pub fn vyre_driver::Severity::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::Severity
pub fn vyre_driver::Severity::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::Severity
impl core::marker::StructuralPartialEq for vyre_driver::Severity
impl serde_core::ser::Serialize for vyre_driver::Severity
pub fn vyre_driver::Severity::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::Severity
pub fn vyre_driver::Severity::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::Severity
impl core::marker::Send for vyre_driver::Severity
impl core::marker::Sync for vyre_driver::Severity
impl core::marker::Unpin for vyre_driver::Severity
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::Severity
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::Severity
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::Severity where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::Severity::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::Severity where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::Severity where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::Severity::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::Severity::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::Severity where U: core::convert::From<T>
pub fn vyre_driver::Severity::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::Severity where U: core::convert::Into<T>
pub type vyre_driver::Severity::Error = core::convert::Infallible
pub fn vyre_driver::Severity::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::Severity where U: core::convert::TryFrom<T>
pub type vyre_driver::Severity::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::Severity::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::Severity where T: core::clone::Clone
pub type vyre_driver::Severity::Owned = T
pub fn vyre_driver::Severity::clone_into(&self, target: &mut T)
pub fn vyre_driver::Severity::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::Severity where T: 'static + ?core::marker::Sized
pub fn vyre_driver::Severity::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::Severity where T: ?core::marker::Sized
pub fn vyre_driver::Severity::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::Severity where T: ?core::marker::Sized
pub fn vyre_driver::Severity::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::Severity where T: core::clone::Clone
pub unsafe fn vyre_driver::Severity::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::Severity
pub fn vyre_driver::Severity::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::Severity where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::Severity
impl<T> tracing::instrument::WithSubscriber for vyre_driver::Severity
pub struct vyre_driver::diagnostics::Diagnostic
pub vyre_driver::diagnostics::Diagnostic::code: vyre_driver::DiagnosticCode
pub vyre_driver::diagnostics::Diagnostic::doc_url: core::option::Option<alloc::borrow::Cow<'static, str>>
pub vyre_driver::diagnostics::Diagnostic::location: core::option::Option<vyre_driver::OpLocation>
pub vyre_driver::diagnostics::Diagnostic::message: alloc::borrow::Cow<'static, str>
pub vyre_driver::diagnostics::Diagnostic::severity: vyre_driver::Severity
pub vyre_driver::diagnostics::Diagnostic::suggested_fix: core::option::Option<alloc::borrow::Cow<'static, str>>
impl vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::error(code: &'static str, message: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::Diagnostic::note(code: &'static str, message: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::Diagnostic::render_human(&self) -> alloc::string::String
pub fn vyre_driver::Diagnostic::to_json(&self) -> alloc::string::String
pub fn vyre_driver::Diagnostic::warning(code: &'static str, message: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::Diagnostic::with_doc_url(self, url: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::Diagnostic::with_fix(self, fix: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::Diagnostic::with_location(self, loc: vyre_driver::OpLocation) -> Self
impl core::clone::Clone for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::clone(&self) -> vyre_driver::Diagnostic
impl core::cmp::Eq for vyre_driver::Diagnostic
impl core::cmp::PartialEq for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::eq(&self, other: &vyre_driver::Diagnostic) -> bool
impl core::convert::From<&vyre_foundation::error::Error> for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::from(err: &vyre_foundation::error::Error) -> Self
impl core::convert::From<vyre_foundation::error::Error> for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::from(err: vyre_foundation::error::Error) -> Self
impl core::fmt::Debug for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::Diagnostic
impl serde_core::ser::Serialize for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::Diagnostic
impl core::marker::Send for vyre_driver::Diagnostic
impl core::marker::Sync for vyre_driver::Diagnostic
impl core::marker::Unpin for vyre_driver::Diagnostic
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::Diagnostic
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::Diagnostic
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::Diagnostic where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::Diagnostic::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::Diagnostic where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::Diagnostic where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::Diagnostic::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::Diagnostic::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::Diagnostic where U: core::convert::From<T>
pub fn vyre_driver::Diagnostic::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::Diagnostic where U: core::convert::Into<T>
pub type vyre_driver::Diagnostic::Error = core::convert::Infallible
pub fn vyre_driver::Diagnostic::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::Diagnostic where U: core::convert::TryFrom<T>
pub type vyre_driver::Diagnostic::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::Diagnostic::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::Diagnostic where T: core::clone::Clone
pub type vyre_driver::Diagnostic::Owned = T
pub fn vyre_driver::Diagnostic::clone_into(&self, target: &mut T)
pub fn vyre_driver::Diagnostic::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::Diagnostic where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::Diagnostic::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::Diagnostic where T: 'static + ?core::marker::Sized
pub fn vyre_driver::Diagnostic::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::Diagnostic where T: ?core::marker::Sized
pub fn vyre_driver::Diagnostic::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::Diagnostic where T: ?core::marker::Sized
pub fn vyre_driver::Diagnostic::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::Diagnostic where T: core::clone::Clone
pub unsafe fn vyre_driver::Diagnostic::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::Diagnostic where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::Diagnostic
impl<T> tracing::instrument::WithSubscriber for vyre_driver::Diagnostic
pub struct vyre_driver::diagnostics::DiagnosticCode(pub alloc::borrow::Cow<'static, str>)
impl vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::as_str(&self) -> &str
pub const fn vyre_driver::DiagnosticCode::new(code: &'static str) -> Self
impl core::clone::Clone for vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::clone(&self) -> vyre_driver::DiagnosticCode
impl core::cmp::Eq for vyre_driver::DiagnosticCode
impl core::cmp::PartialEq for vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::eq(&self, other: &vyre_driver::DiagnosticCode) -> bool
impl core::fmt::Debug for vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::StructuralPartialEq for vyre_driver::DiagnosticCode
impl serde_core::ser::Serialize for vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::DiagnosticCode
impl core::marker::Send for vyre_driver::DiagnosticCode
impl core::marker::Sync for vyre_driver::DiagnosticCode
impl core::marker::Unpin for vyre_driver::DiagnosticCode
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::DiagnosticCode
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::DiagnosticCode
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::DiagnosticCode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::DiagnosticCode::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::DiagnosticCode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::DiagnosticCode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::DiagnosticCode::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::DiagnosticCode::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::DiagnosticCode where U: core::convert::From<T>
pub fn vyre_driver::DiagnosticCode::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::DiagnosticCode where U: core::convert::Into<T>
pub type vyre_driver::DiagnosticCode::Error = core::convert::Infallible
pub fn vyre_driver::DiagnosticCode::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::DiagnosticCode where U: core::convert::TryFrom<T>
pub type vyre_driver::DiagnosticCode::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::DiagnosticCode::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::DiagnosticCode where T: core::clone::Clone
pub type vyre_driver::DiagnosticCode::Owned = T
pub fn vyre_driver::DiagnosticCode::clone_into(&self, target: &mut T)
pub fn vyre_driver::DiagnosticCode::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::DiagnosticCode where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::DiagnosticCode::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::DiagnosticCode where T: 'static + ?core::marker::Sized
pub fn vyre_driver::DiagnosticCode::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::DiagnosticCode where T: ?core::marker::Sized
pub fn vyre_driver::DiagnosticCode::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::DiagnosticCode where T: ?core::marker::Sized
pub fn vyre_driver::DiagnosticCode::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::DiagnosticCode where T: core::clone::Clone
pub unsafe fn vyre_driver::DiagnosticCode::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::DiagnosticCode where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::DiagnosticCode
impl<T> tracing::instrument::WithSubscriber for vyre_driver::DiagnosticCode
pub struct vyre_driver::diagnostics::OpLocation
pub vyre_driver::diagnostics::OpLocation::attr_name: core::option::Option<alloc::borrow::Cow<'static, str>>
pub vyre_driver::diagnostics::OpLocation::op_id: alloc::borrow::Cow<'static, str>
pub vyre_driver::diagnostics::OpLocation::operand_idx: core::option::Option<u32>
impl vyre_driver::OpLocation
pub fn vyre_driver::OpLocation::op(op_id: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::OpLocation::with_attr(self, name: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::OpLocation::with_operand(self, idx: u32) -> Self
impl core::clone::Clone for vyre_driver::OpLocation
pub fn vyre_driver::OpLocation::clone(&self) -> vyre_driver::OpLocation
impl core::cmp::Eq for vyre_driver::OpLocation
impl core::cmp::PartialEq for vyre_driver::OpLocation
pub fn vyre_driver::OpLocation::eq(&self, other: &vyre_driver::OpLocation) -> bool
impl core::fmt::Debug for vyre_driver::OpLocation
pub fn vyre_driver::OpLocation::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::OpLocation
impl serde_core::ser::Serialize for vyre_driver::OpLocation
pub fn vyre_driver::OpLocation::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::OpLocation
pub fn vyre_driver::OpLocation::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::OpLocation
impl core::marker::Send for vyre_driver::OpLocation
impl core::marker::Sync for vyre_driver::OpLocation
impl core::marker::Unpin for vyre_driver::OpLocation
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::OpLocation
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::OpLocation
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::OpLocation where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::OpLocation::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::OpLocation where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::OpLocation where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::OpLocation::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::OpLocation::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::OpLocation where U: core::convert::From<T>
pub fn vyre_driver::OpLocation::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::OpLocation where U: core::convert::Into<T>
pub type vyre_driver::OpLocation::Error = core::convert::Infallible
pub fn vyre_driver::OpLocation::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::OpLocation where U: core::convert::TryFrom<T>
pub type vyre_driver::OpLocation::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::OpLocation::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::OpLocation where T: core::clone::Clone
pub type vyre_driver::OpLocation::Owned = T
pub fn vyre_driver::OpLocation::clone_into(&self, target: &mut T)
pub fn vyre_driver::OpLocation::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::OpLocation where T: 'static + ?core::marker::Sized
pub fn vyre_driver::OpLocation::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::OpLocation where T: ?core::marker::Sized
pub fn vyre_driver::OpLocation::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::OpLocation where T: ?core::marker::Sized
pub fn vyre_driver::OpLocation::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::OpLocation where T: core::clone::Clone
pub unsafe fn vyre_driver::OpLocation::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::OpLocation
pub fn vyre_driver::OpLocation::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::OpLocation where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::OpLocation
impl<T> tracing::instrument::WithSubscriber for vyre_driver::OpLocation
pub mod vyre_driver::pgo
pub struct vyre_driver::pgo::BackendLatency
pub vyre_driver::pgo::BackendLatency::backend: alloc::string::String
pub vyre_driver::pgo::BackendLatency::latency_ns: u128
impl core::clone::Clone for vyre_driver::pgo::BackendLatency
pub fn vyre_driver::pgo::BackendLatency::clone(&self) -> vyre_driver::pgo::BackendLatency
impl core::cmp::Eq for vyre_driver::pgo::BackendLatency
impl core::cmp::PartialEq for vyre_driver::pgo::BackendLatency
pub fn vyre_driver::pgo::BackendLatency::eq(&self, other: &vyre_driver::pgo::BackendLatency) -> bool
impl core::fmt::Debug for vyre_driver::pgo::BackendLatency
pub fn vyre_driver::pgo::BackendLatency::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::pgo::BackendLatency
impl serde_core::ser::Serialize for vyre_driver::pgo::BackendLatency
pub fn vyre_driver::pgo::BackendLatency::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::pgo::BackendLatency
pub fn vyre_driver::pgo::BackendLatency::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::pgo::BackendLatency
impl core::marker::Send for vyre_driver::pgo::BackendLatency
impl core::marker::Sync for vyre_driver::pgo::BackendLatency
impl core::marker::Unpin for vyre_driver::pgo::BackendLatency
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::pgo::BackendLatency
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::pgo::BackendLatency
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::pgo::BackendLatency where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pgo::BackendLatency::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pgo::BackendLatency where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pgo::BackendLatency where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pgo::BackendLatency::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::pgo::BackendLatency::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::pgo::BackendLatency where U: core::convert::From<T>
pub fn vyre_driver::pgo::BackendLatency::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::pgo::BackendLatency where U: core::convert::Into<T>
pub type vyre_driver::pgo::BackendLatency::Error = core::convert::Infallible
pub fn vyre_driver::pgo::BackendLatency::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::pgo::BackendLatency where U: core::convert::TryFrom<T>
pub type vyre_driver::pgo::BackendLatency::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::pgo::BackendLatency::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::pgo::BackendLatency where T: core::clone::Clone
pub type vyre_driver::pgo::BackendLatency::Owned = T
pub fn vyre_driver::pgo::BackendLatency::clone_into(&self, target: &mut T)
pub fn vyre_driver::pgo::BackendLatency::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::pgo::BackendLatency where T: 'static + ?core::marker::Sized
pub fn vyre_driver::pgo::BackendLatency::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::pgo::BackendLatency where T: ?core::marker::Sized
pub fn vyre_driver::pgo::BackendLatency::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::pgo::BackendLatency where T: ?core::marker::Sized
pub fn vyre_driver::pgo::BackendLatency::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::pgo::BackendLatency where T: core::clone::Clone
pub unsafe fn vyre_driver::pgo::BackendLatency::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::pgo::BackendLatency
pub fn vyre_driver::pgo::BackendLatency::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::pgo::BackendLatency where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::pgo::BackendLatency
impl<T> tracing::instrument::WithSubscriber for vyre_driver::pgo::BackendLatency
pub struct vyre_driver::pgo::PgoTable
pub vyre_driver::pgo::PgoTable::routes: alloc::collections::btree::map::BTreeMap<alloc::string::String, vyre_driver::pgo::RouteDecision>
impl vyre_driver::pgo::PgoTable
pub fn vyre_driver::pgo::PgoTable::certify_op(&mut self, op_id: impl core::convert::Into<alloc::string::String>, program: &vyre_foundation::ir_inner::model::program::Program, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::backend::DispatchConfig, backends: &[&dyn vyre_driver::backend::VyreBackend]) -> core::result::Result<&vyre_driver::pgo::RouteDecision, vyre_driver::backend::BackendError>
pub fn vyre_driver::pgo::PgoTable::fastest_backend(&self, op_id: &str) -> core::option::Option<&str>
pub fn vyre_driver::pgo::PgoTable::load(path: &std::path::Path) -> core::result::Result<Self, alloc::string::String>
pub fn vyre_driver::pgo::PgoTable::save(&self, path: &std::path::Path) -> core::result::Result<(), alloc::string::String>
impl core::clone::Clone for vyre_driver::pgo::PgoTable
pub fn vyre_driver::pgo::PgoTable::clone(&self) -> vyre_driver::pgo::PgoTable
impl core::cmp::Eq for vyre_driver::pgo::PgoTable
impl core::cmp::PartialEq for vyre_driver::pgo::PgoTable
pub fn vyre_driver::pgo::PgoTable::eq(&self, other: &vyre_driver::pgo::PgoTable) -> bool
impl core::default::Default for vyre_driver::pgo::PgoTable
pub fn vyre_driver::pgo::PgoTable::default() -> vyre_driver::pgo::PgoTable
impl core::fmt::Debug for vyre_driver::pgo::PgoTable
pub fn vyre_driver::pgo::PgoTable::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::pgo::PgoTable
impl serde_core::ser::Serialize for vyre_driver::pgo::PgoTable
pub fn vyre_driver::pgo::PgoTable::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::pgo::PgoTable
pub fn vyre_driver::pgo::PgoTable::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::pgo::PgoTable
impl core::marker::Send for vyre_driver::pgo::PgoTable
impl core::marker::Sync for vyre_driver::pgo::PgoTable
impl core::marker::Unpin for vyre_driver::pgo::PgoTable
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::pgo::PgoTable
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::pgo::PgoTable
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::pgo::PgoTable where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pgo::PgoTable::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pgo::PgoTable where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pgo::PgoTable where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pgo::PgoTable::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::pgo::PgoTable::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::pgo::PgoTable where U: core::convert::From<T>
pub fn vyre_driver::pgo::PgoTable::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::pgo::PgoTable where U: core::convert::Into<T>
pub type vyre_driver::pgo::PgoTable::Error = core::convert::Infallible
pub fn vyre_driver::pgo::PgoTable::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::pgo::PgoTable where U: core::convert::TryFrom<T>
pub type vyre_driver::pgo::PgoTable::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::pgo::PgoTable::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::pgo::PgoTable where T: core::clone::Clone
pub type vyre_driver::pgo::PgoTable::Owned = T
pub fn vyre_driver::pgo::PgoTable::clone_into(&self, target: &mut T)
pub fn vyre_driver::pgo::PgoTable::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::pgo::PgoTable where T: 'static + ?core::marker::Sized
pub fn vyre_driver::pgo::PgoTable::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::pgo::PgoTable where T: ?core::marker::Sized
pub fn vyre_driver::pgo::PgoTable::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::pgo::PgoTable where T: ?core::marker::Sized
pub fn vyre_driver::pgo::PgoTable::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::pgo::PgoTable where T: core::clone::Clone
pub unsafe fn vyre_driver::pgo::PgoTable::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::pgo::PgoTable
pub fn vyre_driver::pgo::PgoTable::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::pgo::PgoTable where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::pgo::PgoTable
impl<T> tracing::instrument::WithSubscriber for vyre_driver::pgo::PgoTable
pub struct vyre_driver::pgo::RouteDecision
pub vyre_driver::pgo::RouteDecision::backend: alloc::string::String
pub vyre_driver::pgo::RouteDecision::observations: alloc::vec::Vec<vyre_driver::pgo::BackendLatency>
impl core::clone::Clone for vyre_driver::pgo::RouteDecision
pub fn vyre_driver::pgo::RouteDecision::clone(&self) -> vyre_driver::pgo::RouteDecision
impl core::cmp::Eq for vyre_driver::pgo::RouteDecision
impl core::cmp::PartialEq for vyre_driver::pgo::RouteDecision
pub fn vyre_driver::pgo::RouteDecision::eq(&self, other: &vyre_driver::pgo::RouteDecision) -> bool
impl core::fmt::Debug for vyre_driver::pgo::RouteDecision
pub fn vyre_driver::pgo::RouteDecision::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::pgo::RouteDecision
impl serde_core::ser::Serialize for vyre_driver::pgo::RouteDecision
pub fn vyre_driver::pgo::RouteDecision::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::pgo::RouteDecision
pub fn vyre_driver::pgo::RouteDecision::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::pgo::RouteDecision
impl core::marker::Send for vyre_driver::pgo::RouteDecision
impl core::marker::Sync for vyre_driver::pgo::RouteDecision
impl core::marker::Unpin for vyre_driver::pgo::RouteDecision
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::pgo::RouteDecision
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::pgo::RouteDecision
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::pgo::RouteDecision where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pgo::RouteDecision::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pgo::RouteDecision where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pgo::RouteDecision where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pgo::RouteDecision::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::pgo::RouteDecision::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::pgo::RouteDecision where U: core::convert::From<T>
pub fn vyre_driver::pgo::RouteDecision::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::pgo::RouteDecision where U: core::convert::Into<T>
pub type vyre_driver::pgo::RouteDecision::Error = core::convert::Infallible
pub fn vyre_driver::pgo::RouteDecision::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::pgo::RouteDecision where U: core::convert::TryFrom<T>
pub type vyre_driver::pgo::RouteDecision::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::pgo::RouteDecision::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::pgo::RouteDecision where T: core::clone::Clone
pub type vyre_driver::pgo::RouteDecision::Owned = T
pub fn vyre_driver::pgo::RouteDecision::clone_into(&self, target: &mut T)
pub fn vyre_driver::pgo::RouteDecision::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::pgo::RouteDecision where T: 'static + ?core::marker::Sized
pub fn vyre_driver::pgo::RouteDecision::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::pgo::RouteDecision where T: ?core::marker::Sized
pub fn vyre_driver::pgo::RouteDecision::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::pgo::RouteDecision where T: ?core::marker::Sized
pub fn vyre_driver::pgo::RouteDecision::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::pgo::RouteDecision where T: core::clone::Clone
pub unsafe fn vyre_driver::pgo::RouteDecision::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::pgo::RouteDecision
pub fn vyre_driver::pgo::RouteDecision::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::pgo::RouteDecision where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::pgo::RouteDecision
impl<T> tracing::instrument::WithSubscriber for vyre_driver::pgo::RouteDecision
pub fn vyre_driver::pgo::default_pgo_path() -> std::path::PathBuf
pub mod vyre_driver::pipeline
pub struct vyre_driver::pipeline::PipelineCacheKey
pub vyre_driver::pipeline::PipelineCacheKey::backend_id: vyre_spec::intrinsic_descriptor::BackendId
pub vyre_driver::pipeline::PipelineCacheKey::bind_group_layout_hash: [u8; 32]
pub vyre_driver::pipeline::PipelineCacheKey::feature_flags: vyre_driver::PipelineFeatureFlags
pub vyre_driver::pipeline::PipelineCacheKey::push_constant_size: u32
pub vyre_driver::pipeline::PipelineCacheKey::shader_hash: [u8; 32]
pub vyre_driver::pipeline::PipelineCacheKey::version: u32
pub vyre_driver::pipeline::PipelineCacheKey::workgroup_size: [u32; 3]
impl vyre_driver::PipelineCacheKey
pub fn vyre_driver::PipelineCacheKey::new(shader_hash: [u8; 32], bind_group_layout_hash: [u8; 32], push_constant_size: u32, workgroup_size: [u32; 3], feature_flags: vyre_driver::PipelineFeatureFlags, backend_id: vyre_spec::intrinsic_descriptor::BackendId) -> Self
impl core::clone::Clone for vyre_driver::PipelineCacheKey
pub fn vyre_driver::PipelineCacheKey::clone(&self) -> vyre_driver::PipelineCacheKey
impl core::cmp::Eq for vyre_driver::PipelineCacheKey
impl core::cmp::PartialEq for vyre_driver::PipelineCacheKey
pub fn vyre_driver::PipelineCacheKey::eq(&self, other: &vyre_driver::PipelineCacheKey) -> bool
impl core::fmt::Debug for vyre_driver::PipelineCacheKey
pub fn vyre_driver::PipelineCacheKey::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::PipelineCacheKey
pub fn vyre_driver::PipelineCacheKey::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::StructuralPartialEq for vyre_driver::PipelineCacheKey
impl core::marker::Freeze for vyre_driver::PipelineCacheKey
impl core::marker::Send for vyre_driver::PipelineCacheKey
impl core::marker::Sync for vyre_driver::PipelineCacheKey
impl core::marker::Unpin for vyre_driver::PipelineCacheKey
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::PipelineCacheKey
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::PipelineCacheKey
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::PipelineCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::PipelineCacheKey::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::PipelineCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::PipelineCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::PipelineCacheKey::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::PipelineCacheKey::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::PipelineCacheKey where U: core::convert::From<T>
pub fn vyre_driver::PipelineCacheKey::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::PipelineCacheKey where U: core::convert::Into<T>
pub type vyre_driver::PipelineCacheKey::Error = core::convert::Infallible
pub fn vyre_driver::PipelineCacheKey::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::PipelineCacheKey where U: core::convert::TryFrom<T>
pub type vyre_driver::PipelineCacheKey::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::PipelineCacheKey::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::PipelineCacheKey where T: core::clone::Clone
pub type vyre_driver::PipelineCacheKey::Owned = T
pub fn vyre_driver::PipelineCacheKey::clone_into(&self, target: &mut T)
pub fn vyre_driver::PipelineCacheKey::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::PipelineCacheKey where T: 'static + ?core::marker::Sized
pub fn vyre_driver::PipelineCacheKey::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::PipelineCacheKey where T: ?core::marker::Sized
pub fn vyre_driver::PipelineCacheKey::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::PipelineCacheKey where T: ?core::marker::Sized
pub fn vyre_driver::PipelineCacheKey::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::PipelineCacheKey where T: core::clone::Clone
pub unsafe fn vyre_driver::PipelineCacheKey::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::PipelineCacheKey
pub fn vyre_driver::PipelineCacheKey::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::PipelineCacheKey
impl<T> tracing::instrument::WithSubscriber for vyre_driver::PipelineCacheKey
pub struct vyre_driver::pipeline::PipelineFeatureFlags(pub u32)
impl vyre_driver::PipelineFeatureFlags
pub const vyre_driver::PipelineFeatureFlags::ASYNC_COMPUTE: Self
pub const vyre_driver::PipelineFeatureFlags::BF16: Self
pub const vyre_driver::PipelineFeatureFlags::F16: Self
pub const vyre_driver::PipelineFeatureFlags::INDIRECT_DISPATCH: Self
pub const vyre_driver::PipelineFeatureFlags::PUSH_CONSTANTS: Self
pub const vyre_driver::PipelineFeatureFlags::SUBGROUP_OPS: Self
pub const vyre_driver::PipelineFeatureFlags::TENSOR_CORES: Self
pub const fn vyre_driver::PipelineFeatureFlags::bits(self) -> u32
pub const fn vyre_driver::PipelineFeatureFlags::contains(self, other: Self) -> bool
pub const fn vyre_driver::PipelineFeatureFlags::empty() -> Self
pub const fn vyre_driver::PipelineFeatureFlags::union(self, other: Self) -> Self
impl core::clone::Clone for vyre_driver::PipelineFeatureFlags
pub fn vyre_driver::PipelineFeatureFlags::clone(&self) -> vyre_driver::PipelineFeatureFlags
impl core::cmp::Eq for vyre_driver::PipelineFeatureFlags
impl core::cmp::PartialEq for vyre_driver::PipelineFeatureFlags
pub fn vyre_driver::PipelineFeatureFlags::eq(&self, other: &vyre_driver::PipelineFeatureFlags) -> bool
impl core::default::Default for vyre_driver::PipelineFeatureFlags
pub fn vyre_driver::PipelineFeatureFlags::default() -> vyre_driver::PipelineFeatureFlags
impl core::fmt::Debug for vyre_driver::PipelineFeatureFlags
pub fn vyre_driver::PipelineFeatureFlags::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::PipelineFeatureFlags
pub fn vyre_driver::PipelineFeatureFlags::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::PipelineFeatureFlags
impl core::marker::StructuralPartialEq for vyre_driver::PipelineFeatureFlags
impl serde_core::ser::Serialize for vyre_driver::PipelineFeatureFlags
pub fn vyre_driver::PipelineFeatureFlags::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::PipelineFeatureFlags
pub fn vyre_driver::PipelineFeatureFlags::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::PipelineFeatureFlags
impl core::marker::Send for vyre_driver::PipelineFeatureFlags
impl core::marker::Sync for vyre_driver::PipelineFeatureFlags
impl core::marker::Unpin for vyre_driver::PipelineFeatureFlags
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::PipelineFeatureFlags
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::PipelineFeatureFlags
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::PipelineFeatureFlags where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::PipelineFeatureFlags::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::PipelineFeatureFlags where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::PipelineFeatureFlags where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::PipelineFeatureFlags::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::PipelineFeatureFlags::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::PipelineFeatureFlags where U: core::convert::From<T>
pub fn vyre_driver::PipelineFeatureFlags::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::PipelineFeatureFlags where U: core::convert::Into<T>
pub type vyre_driver::PipelineFeatureFlags::Error = core::convert::Infallible
pub fn vyre_driver::PipelineFeatureFlags::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::PipelineFeatureFlags where U: core::convert::TryFrom<T>
pub type vyre_driver::PipelineFeatureFlags::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::PipelineFeatureFlags::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::PipelineFeatureFlags where T: core::clone::Clone
pub type vyre_driver::PipelineFeatureFlags::Owned = T
pub fn vyre_driver::PipelineFeatureFlags::clone_into(&self, target: &mut T)
pub fn vyre_driver::PipelineFeatureFlags::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::PipelineFeatureFlags where T: 'static + ?core::marker::Sized
pub fn vyre_driver::PipelineFeatureFlags::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::PipelineFeatureFlags where T: ?core::marker::Sized
pub fn vyre_driver::PipelineFeatureFlags::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::PipelineFeatureFlags where T: ?core::marker::Sized
pub fn vyre_driver::PipelineFeatureFlags::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::PipelineFeatureFlags where T: core::clone::Clone
pub unsafe fn vyre_driver::PipelineFeatureFlags::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::PipelineFeatureFlags
pub fn vyre_driver::PipelineFeatureFlags::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::PipelineFeatureFlags where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::PipelineFeatureFlags
impl<T> tracing::instrument::WithSubscriber for vyre_driver::PipelineFeatureFlags
pub const vyre_driver::pipeline::CURRENT_PIPELINE_CACHE_KEY_VERSION: u32
pub fn vyre_driver::pipeline::compile(backend: alloc::sync::Arc<dyn vyre_driver::backend::VyreBackend>, program: &vyre_foundation::ir_inner::model::program::Program, config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::sync::Arc<dyn vyre_driver::backend::CompiledPipeline>, vyre_driver::backend::BackendError>
pub fn vyre_driver::pipeline::compile_shared(backend: alloc::sync::Arc<dyn vyre_driver::backend::VyreBackend>, program: alloc::sync::Arc<vyre_foundation::ir_inner::model::program::Program>, config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::sync::Arc<dyn vyre_driver::backend::CompiledPipeline>, vyre_driver::backend::BackendError>
pub mod vyre_driver::registry
pub use vyre_driver::registry::AttrSchema
pub use vyre_driver::registry::AttrType
pub use vyre_driver::registry::Category
pub use vyre_driver::registry::CpuRef
pub use vyre_driver::registry::InternedOpId
pub use vyre_driver::registry::LoweringCtx
pub use vyre_driver::registry::LoweringTable
pub use vyre_driver::registry::MetalBuilder
pub use vyre_driver::registry::MetalModule
pub use vyre_driver::registry::NagaBuilder
pub use vyre_driver::registry::OpDef
pub use vyre_driver::registry::PtxBuilder
pub use vyre_driver::registry::PtxModule
pub use vyre_driver::registry::Signature
pub use vyre_driver::registry::SpirvBuilder
pub use vyre_driver::registry::TypedParam
pub use vyre_driver::registry::intern_string
pub mod vyre_driver::registry::core_indirect
pub const vyre_driver::registry::core_indirect::INDIRECT_DISPATCH_OP_ID: &str
pub mod vyre_driver::registry::dialect
pub struct vyre_driver::registry::dialect::Dialect
pub vyre_driver::registry::dialect::Dialect::backends_required: &'static [vyre_spec::intrinsic_descriptor::Backend]
pub vyre_driver::registry::dialect::Dialect::id: &'static str
pub vyre_driver::registry::dialect::Dialect::ops: &'static [&'static str]
pub vyre_driver::registry::dialect::Dialect::parent: core::option::Option<&'static str>
pub vyre_driver::registry::dialect::Dialect::validator: fn() -> bool
pub vyre_driver::registry::dialect::Dialect::version: u32
impl core::marker::Freeze for vyre_driver::registry::Dialect
impl core::marker::Send for vyre_driver::registry::Dialect
impl core::marker::Sync for vyre_driver::registry::Dialect
impl core::marker::Unpin for vyre_driver::registry::Dialect
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::Dialect
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::Dialect
impl<T, U> core::convert::Into<U> for vyre_driver::registry::Dialect where U: core::convert::From<T>
pub fn vyre_driver::registry::Dialect::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::Dialect where U: core::convert::Into<T>
pub type vyre_driver::registry::Dialect::Error = core::convert::Infallible
pub fn vyre_driver::registry::Dialect::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::Dialect where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::Dialect::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::Dialect::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::Dialect where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::Dialect::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::Dialect where T: ?core::marker::Sized
pub fn vyre_driver::registry::Dialect::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::Dialect where T: ?core::marker::Sized
pub fn vyre_driver::registry::Dialect::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::Dialect
pub fn vyre_driver::registry::Dialect::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::Dialect
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::Dialect
pub struct vyre_driver::registry::dialect::DialectRegistration
pub vyre_driver::registry::dialect::DialectRegistration::dialect: fn() -> vyre_driver::registry::Dialect
impl inventory::Collect for vyre_driver::registry::DialectRegistration
impl core::marker::Freeze for vyre_driver::registry::DialectRegistration
impl core::marker::Send for vyre_driver::registry::DialectRegistration
impl core::marker::Sync for vyre_driver::registry::DialectRegistration
impl core::marker::Unpin for vyre_driver::registry::DialectRegistration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::DialectRegistration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::DialectRegistration
impl<T, U> core::convert::Into<U> for vyre_driver::registry::DialectRegistration where U: core::convert::From<T>
pub fn vyre_driver::registry::DialectRegistration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::DialectRegistration where U: core::convert::Into<T>
pub type vyre_driver::registry::DialectRegistration::Error = core::convert::Infallible
pub fn vyre_driver::registry::DialectRegistration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::DialectRegistration where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::DialectRegistration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::DialectRegistration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::DialectRegistration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::DialectRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::DialectRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::DialectRegistration
pub fn vyre_driver::registry::DialectRegistration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::DialectRegistration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::DialectRegistration
pub struct vyre_driver::registry::dialect::OpBackendTarget
pub vyre_driver::registry::dialect::OpBackendTarget::op: &'static str
pub vyre_driver::registry::dialect::OpBackendTarget::target: &'static str
impl inventory::Collect for vyre_driver::registry::OpBackendTarget
impl core::marker::Freeze for vyre_driver::registry::OpBackendTarget
impl core::marker::Send for vyre_driver::registry::OpBackendTarget
impl core::marker::Sync for vyre_driver::registry::OpBackendTarget
impl core::marker::Unpin for vyre_driver::registry::OpBackendTarget
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::OpBackendTarget
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::OpBackendTarget
impl<T, U> core::convert::Into<U> for vyre_driver::registry::OpBackendTarget where U: core::convert::From<T>
pub fn vyre_driver::registry::OpBackendTarget::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::OpBackendTarget where U: core::convert::Into<T>
pub type vyre_driver::registry::OpBackendTarget::Error = core::convert::Infallible
pub fn vyre_driver::registry::OpBackendTarget::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::OpBackendTarget where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::OpBackendTarget::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::OpBackendTarget::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::OpBackendTarget where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::OpBackendTarget::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::OpBackendTarget where T: ?core::marker::Sized
pub fn vyre_driver::registry::OpBackendTarget::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::OpBackendTarget where T: ?core::marker::Sized
pub fn vyre_driver::registry::OpBackendTarget::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::OpBackendTarget
pub fn vyre_driver::registry::OpBackendTarget::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::OpBackendTarget
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::OpBackendTarget
pub struct vyre_driver::registry::dialect::OpDefRegistration
pub vyre_driver::registry::dialect::OpDefRegistration::op: fn() -> vyre_foundation::dialect_lookup::OpDef
impl vyre_driver::registry::OpDefRegistration
pub const fn vyre_driver::registry::OpDefRegistration::new(op: fn() -> vyre_foundation::dialect_lookup::OpDef) -> Self
impl inventory::Collect for vyre_driver::registry::OpDefRegistration
impl core::marker::Freeze for vyre_driver::registry::OpDefRegistration
impl core::marker::Send for vyre_driver::registry::OpDefRegistration
impl core::marker::Sync for vyre_driver::registry::OpDefRegistration
impl core::marker::Unpin for vyre_driver::registry::OpDefRegistration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::OpDefRegistration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::OpDefRegistration
impl<T, U> core::convert::Into<U> for vyre_driver::registry::OpDefRegistration where U: core::convert::From<T>
pub fn vyre_driver::registry::OpDefRegistration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::OpDefRegistration where U: core::convert::Into<T>
pub type vyre_driver::registry::OpDefRegistration::Error = core::convert::Infallible
pub fn vyre_driver::registry::OpDefRegistration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::OpDefRegistration where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::OpDefRegistration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::OpDefRegistration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::OpDefRegistration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::OpDefRegistration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::OpDefRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::OpDefRegistration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::OpDefRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::OpDefRegistration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::OpDefRegistration
pub fn vyre_driver::registry::OpDefRegistration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::OpDefRegistration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::OpDefRegistration
pub fn vyre_driver::registry::dialect::default_validator() -> bool
pub mod vyre_driver::registry::enforce
pub enum vyre_driver::registry::enforce::EnforceVerdict
pub vyre_driver::registry::enforce::EnforceVerdict::Allow
pub vyre_driver::registry::enforce::EnforceVerdict::Deny
pub vyre_driver::registry::enforce::EnforceVerdict::Deny::detail: alloc::string::String
pub vyre_driver::registry::enforce::EnforceVerdict::Deny::policy: &'static str
impl core::clone::Clone for vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::EnforceVerdict::clone(&self) -> vyre_driver::registry::EnforceVerdict
impl core::cmp::Eq for vyre_driver::registry::EnforceVerdict
impl core::cmp::PartialEq for vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::EnforceVerdict::eq(&self, other: &vyre_driver::registry::EnforceVerdict) -> bool
impl core::fmt::Debug for vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::EnforceVerdict::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::EnforceVerdict
impl core::marker::Freeze for vyre_driver::registry::EnforceVerdict
impl core::marker::Send for vyre_driver::registry::EnforceVerdict
impl core::marker::Sync for vyre_driver::registry::EnforceVerdict
impl core::marker::Unpin for vyre_driver::registry::EnforceVerdict
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::EnforceVerdict
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::EnforceVerdict
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::EnforceVerdict::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::EnforceVerdict::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::EnforceVerdict::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::EnforceVerdict where U: core::convert::From<T>
pub fn vyre_driver::registry::EnforceVerdict::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::EnforceVerdict where U: core::convert::Into<T>
pub type vyre_driver::registry::EnforceVerdict::Error = core::convert::Infallible
pub fn vyre_driver::registry::EnforceVerdict::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::EnforceVerdict where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::EnforceVerdict::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::EnforceVerdict::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::EnforceVerdict where T: core::clone::Clone
pub type vyre_driver::registry::EnforceVerdict::Owned = T
pub fn vyre_driver::registry::EnforceVerdict::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::EnforceVerdict::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::EnforceVerdict where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::EnforceVerdict::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::EnforceVerdict where T: ?core::marker::Sized
pub fn vyre_driver::registry::EnforceVerdict::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::EnforceVerdict where T: ?core::marker::Sized
pub fn vyre_driver::registry::EnforceVerdict::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::EnforceVerdict where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::EnforceVerdict::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::EnforceVerdict::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::EnforceVerdict
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::EnforceVerdict
pub struct vyre_driver::registry::enforce::Chain<A, B>
impl<A: vyre_driver::registry::EnforceGate, B: vyre_driver::registry::EnforceGate> vyre_driver::registry::Chain<A, B>
pub fn vyre_driver::registry::Chain<A, B>::new(first: A, second: B) -> Self
impl<A: vyre_driver::registry::EnforceGate, B: vyre_driver::registry::EnforceGate> vyre_driver::registry::EnforceGate for vyre_driver::registry::Chain<A, B>
pub fn vyre_driver::registry::Chain<A, B>::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::Program) -> vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::Chain<A, B>::name(&self) -> &'static str
impl<A, B> core::marker::Freeze for vyre_driver::registry::Chain<A, B> where A: core::marker::Freeze, B: core::marker::Freeze
impl<A, B> core::marker::Send for vyre_driver::registry::Chain<A, B> where A: core::marker::Send, B: core::marker::Send
impl<A, B> core::marker::Sync for vyre_driver::registry::Chain<A, B> where A: core::marker::Sync, B: core::marker::Sync
impl<A, B> core::marker::Unpin for vyre_driver::registry::Chain<A, B> where A: core::marker::Unpin, B: core::marker::Unpin
impl<A, B> core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::Chain<A, B> where A: core::panic::unwind_safe::RefUnwindSafe, B: core::panic::unwind_safe::RefUnwindSafe
impl<A, B> core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::Chain<A, B> where A: core::panic::unwind_safe::UnwindSafe, B: core::panic::unwind_safe::UnwindSafe
impl<T, U> core::convert::Into<U> for vyre_driver::registry::Chain<A, B> where U: core::convert::From<T>
pub fn vyre_driver::registry::Chain<A, B>::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::Chain<A, B> where U: core::convert::Into<T>
pub type vyre_driver::registry::Chain<A, B>::Error = core::convert::Infallible
pub fn vyre_driver::registry::Chain<A, B>::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::Chain<A, B> where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::Chain<A, B>::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::Chain<A, B>::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::Chain<A, B> where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::Chain<A, B>::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::Chain<A, B> where T: ?core::marker::Sized
pub fn vyre_driver::registry::Chain<A, B>::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::Chain<A, B> where T: ?core::marker::Sized
pub fn vyre_driver::registry::Chain<A, B>::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::Chain<A, B>
pub fn vyre_driver::registry::Chain<A, B>::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::Chain<A, B>
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::Chain<A, B>
pub trait vyre_driver::registry::enforce::EnforceGate: core::marker::Send + core::marker::Sync
pub fn vyre_driver::registry::enforce::EnforceGate::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::Program) -> vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::enforce::EnforceGate::name(&self) -> &'static str
impl<A: vyre_driver::registry::EnforceGate, B: vyre_driver::registry::EnforceGate> vyre_driver::registry::EnforceGate for vyre_driver::registry::Chain<A, B>
pub fn vyre_driver::registry::Chain<A, B>::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::Program) -> vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::Chain<A, B>::name(&self) -> &'static str
pub mod vyre_driver::registry::interner
pub use vyre_driver::registry::interner::InternedOpId
pub use vyre_driver::registry::interner::intern_string
pub mod vyre_driver::registry::io
pub mod vyre_driver::registry::lowering
pub use vyre_driver::registry::lowering::CpuRef
pub use vyre_driver::registry::lowering::LoweringCtx
pub use vyre_driver::registry::lowering::LoweringTable
pub use vyre_driver::registry::lowering::MetalBuilder
pub use vyre_driver::registry::lowering::MetalModule
pub use vyre_driver::registry::lowering::NagaBuilder
pub use vyre_driver::registry::lowering::PtxBuilder
pub use vyre_driver::registry::lowering::PtxModule
pub use vyre_driver::registry::lowering::SpirvBuilder
pub mod vyre_driver::registry::migration
pub enum vyre_driver::registry::migration::AttrValue
pub vyre_driver::registry::migration::AttrValue::Bool(bool)
pub vyre_driver::registry::migration::AttrValue::Bytes(alloc::vec::Vec<u8>)
pub vyre_driver::registry::migration::AttrValue::F32(f32)
pub vyre_driver::registry::migration::AttrValue::I32(i32)
pub vyre_driver::registry::migration::AttrValue::String(alloc::string::String)
pub vyre_driver::registry::migration::AttrValue::U32(u32)
impl core::clone::Clone for vyre_driver::registry::AttrValue
pub fn vyre_driver::registry::AttrValue::clone(&self) -> vyre_driver::registry::AttrValue
impl core::cmp::PartialEq for vyre_driver::registry::AttrValue
pub fn vyre_driver::registry::AttrValue::eq(&self, other: &vyre_driver::registry::AttrValue) -> bool
impl core::fmt::Debug for vyre_driver::registry::AttrValue
pub fn vyre_driver::registry::AttrValue::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::AttrValue
impl core::marker::Freeze for vyre_driver::registry::AttrValue
impl core::marker::Send for vyre_driver::registry::AttrValue
impl core::marker::Sync for vyre_driver::registry::AttrValue
impl core::marker::Unpin for vyre_driver::registry::AttrValue
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::AttrValue
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::AttrValue
impl<T, U> core::convert::Into<U> for vyre_driver::registry::AttrValue where U: core::convert::From<T>
pub fn vyre_driver::registry::AttrValue::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::AttrValue where U: core::convert::Into<T>
pub type vyre_driver::registry::AttrValue::Error = core::convert::Infallible
pub fn vyre_driver::registry::AttrValue::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::AttrValue where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::AttrValue::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::AttrValue::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::AttrValue where T: core::clone::Clone
pub type vyre_driver::registry::AttrValue::Owned = T
pub fn vyre_driver::registry::AttrValue::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::AttrValue::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::AttrValue where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::AttrValue::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::AttrValue where T: ?core::marker::Sized
pub fn vyre_driver::registry::AttrValue::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::AttrValue where T: ?core::marker::Sized
pub fn vyre_driver::registry::AttrValue::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::AttrValue where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::AttrValue::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::AttrValue
pub fn vyre_driver::registry::AttrValue::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::AttrValue
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::AttrValue
pub enum vyre_driver::registry::migration::MigrationError
pub vyre_driver::registry::migration::MigrationError::Custom
pub vyre_driver::registry::migration::MigrationError::Custom::reason: alloc::string::String
pub vyre_driver::registry::migration::MigrationError::MissingAttribute
pub vyre_driver::registry::migration::MigrationError::MissingAttribute::name: alloc::string::String
pub vyre_driver::registry::migration::MigrationError::OutOfRange
pub vyre_driver::registry::migration::MigrationError::OutOfRange::name: alloc::string::String
pub vyre_driver::registry::migration::MigrationError::WrongType
pub vyre_driver::registry::migration::MigrationError::WrongType::expected: &'static str
pub vyre_driver::registry::migration::MigrationError::WrongType::name: alloc::string::String
impl core::clone::Clone for vyre_driver::registry::MigrationError
pub fn vyre_driver::registry::MigrationError::clone(&self) -> vyre_driver::registry::MigrationError
impl core::cmp::Eq for vyre_driver::registry::MigrationError
impl core::cmp::PartialEq for vyre_driver::registry::MigrationError
pub fn vyre_driver::registry::MigrationError::eq(&self, other: &vyre_driver::registry::MigrationError) -> bool
impl core::error::Error for vyre_driver::registry::MigrationError
impl core::fmt::Debug for vyre_driver::registry::MigrationError
pub fn vyre_driver::registry::MigrationError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::registry::MigrationError
pub fn vyre_driver::registry::MigrationError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::MigrationError
impl core::marker::Freeze for vyre_driver::registry::MigrationError
impl core::marker::Send for vyre_driver::registry::MigrationError
impl core::marker::Sync for vyre_driver::registry::MigrationError
impl core::marker::Unpin for vyre_driver::registry::MigrationError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::MigrationError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::MigrationError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::MigrationError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::MigrationError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::MigrationError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::MigrationError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::MigrationError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::MigrationError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::MigrationError where U: core::convert::From<T>
pub fn vyre_driver::registry::MigrationError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::MigrationError where U: core::convert::Into<T>
pub type vyre_driver::registry::MigrationError::Error = core::convert::Infallible
pub fn vyre_driver::registry::MigrationError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::MigrationError where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::MigrationError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::MigrationError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::MigrationError where T: core::clone::Clone
pub type vyre_driver::registry::MigrationError::Owned = T
pub fn vyre_driver::registry::MigrationError::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::MigrationError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::registry::MigrationError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::registry::MigrationError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::registry::MigrationError where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::MigrationError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::MigrationError where T: ?core::marker::Sized
pub fn vyre_driver::registry::MigrationError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::MigrationError where T: ?core::marker::Sized
pub fn vyre_driver::registry::MigrationError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::MigrationError where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::MigrationError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::MigrationError
pub fn vyre_driver::registry::MigrationError::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::MigrationError
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::MigrationError
pub struct vyre_driver::registry::migration::AttrMap
impl vyre_driver::registry::AttrMap
pub fn vyre_driver::registry::AttrMap::get(&self, key: &str) -> core::option::Option<&vyre_driver::registry::AttrValue>
pub fn vyre_driver::registry::AttrMap::insert(&mut self, key: impl core::convert::Into<alloc::string::String>, value: vyre_driver::registry::AttrValue) -> core::option::Option<vyre_driver::registry::AttrValue>
pub fn vyre_driver::registry::AttrMap::is_empty(&self) -> bool
pub fn vyre_driver::registry::AttrMap::iter(&self) -> impl core::iter::traits::iterator::Iterator<Item = (&str, &vyre_driver::registry::AttrValue)>
pub fn vyre_driver::registry::AttrMap::len(&self) -> usize
pub fn vyre_driver::registry::AttrMap::new() -> Self
pub fn vyre_driver::registry::AttrMap::remove(&mut self, key: &str) -> core::option::Option<vyre_driver::registry::AttrValue>
pub fn vyre_driver::registry::AttrMap::rename(&mut self, from: &str, to: impl core::convert::Into<alloc::string::String>) -> bool
impl core::clone::Clone for vyre_driver::registry::AttrMap
pub fn vyre_driver::registry::AttrMap::clone(&self) -> vyre_driver::registry::AttrMap
impl core::default::Default for vyre_driver::registry::AttrMap
pub fn vyre_driver::registry::AttrMap::default() -> vyre_driver::registry::AttrMap
impl core::fmt::Debug for vyre_driver::registry::AttrMap
pub fn vyre_driver::registry::AttrMap::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::registry::AttrMap
impl core::marker::Send for vyre_driver::registry::AttrMap
impl core::marker::Sync for vyre_driver::registry::AttrMap
impl core::marker::Unpin for vyre_driver::registry::AttrMap
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::AttrMap
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::AttrMap
impl<T, U> core::convert::Into<U> for vyre_driver::registry::AttrMap where U: core::convert::From<T>
pub fn vyre_driver::registry::AttrMap::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::AttrMap where U: core::convert::Into<T>
pub type vyre_driver::registry::AttrMap::Error = core::convert::Infallible
pub fn vyre_driver::registry::AttrMap::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::AttrMap where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::AttrMap::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::AttrMap::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::AttrMap where T: core::clone::Clone
pub type vyre_driver::registry::AttrMap::Owned = T
pub fn vyre_driver::registry::AttrMap::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::AttrMap::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::AttrMap where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::AttrMap::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::AttrMap where T: ?core::marker::Sized
pub fn vyre_driver::registry::AttrMap::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::AttrMap where T: ?core::marker::Sized
pub fn vyre_driver::registry::AttrMap::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::AttrMap where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::AttrMap::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::AttrMap
pub fn vyre_driver::registry::AttrMap::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::AttrMap
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::AttrMap
pub struct vyre_driver::registry::migration::Deprecation
pub vyre_driver::registry::migration::Deprecation::deprecated_since: vyre_driver::registry::Semver
pub vyre_driver::registry::migration::Deprecation::note: &'static str
pub vyre_driver::registry::migration::Deprecation::op_id: &'static str
impl vyre_driver::registry::Deprecation
pub const fn vyre_driver::registry::Deprecation::new(op_id: &'static str, deprecated_since: vyre_driver::registry::Semver, note: &'static str) -> Self
impl inventory::Collect for vyre_driver::registry::Deprecation
impl core::marker::Freeze for vyre_driver::registry::Deprecation
impl core::marker::Send for vyre_driver::registry::Deprecation
impl core::marker::Sync for vyre_driver::registry::Deprecation
impl core::marker::Unpin for vyre_driver::registry::Deprecation
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::Deprecation
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::Deprecation
impl<T, U> core::convert::Into<U> for vyre_driver::registry::Deprecation where U: core::convert::From<T>
pub fn vyre_driver::registry::Deprecation::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::Deprecation where U: core::convert::Into<T>
pub type vyre_driver::registry::Deprecation::Error = core::convert::Infallible
pub fn vyre_driver::registry::Deprecation::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::Deprecation where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::Deprecation::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::Deprecation::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::Deprecation where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::Deprecation::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::Deprecation where T: ?core::marker::Sized
pub fn vyre_driver::registry::Deprecation::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::Deprecation where T: ?core::marker::Sized
pub fn vyre_driver::registry::Deprecation::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::Deprecation
pub fn vyre_driver::registry::Deprecation::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::Deprecation
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::Deprecation
pub struct vyre_driver::registry::migration::Migration
pub vyre_driver::registry::migration::Migration::from: (&'static str, vyre_driver::registry::Semver)
pub vyre_driver::registry::migration::Migration::rewrite: fn(&mut vyre_driver::registry::AttrMap) -> core::result::Result<(), vyre_driver::registry::MigrationError>
pub vyre_driver::registry::migration::Migration::to: (&'static str, vyre_driver::registry::Semver)
impl vyre_driver::registry::Migration
pub const fn vyre_driver::registry::Migration::new(from: (&'static str, vyre_driver::registry::Semver), to: (&'static str, vyre_driver::registry::Semver), rewrite: fn(&mut vyre_driver::registry::AttrMap) -> core::result::Result<(), vyre_driver::registry::MigrationError>) -> Self
impl inventory::Collect for vyre_driver::registry::Migration
impl core::marker::Freeze for vyre_driver::registry::Migration
impl core::marker::Send for vyre_driver::registry::Migration
impl core::marker::Sync for vyre_driver::registry::Migration
impl core::marker::Unpin for vyre_driver::registry::Migration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::Migration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::Migration
impl<T, U> core::convert::Into<U> for vyre_driver::registry::Migration where U: core::convert::From<T>
pub fn vyre_driver::registry::Migration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::Migration where U: core::convert::Into<T>
pub type vyre_driver::registry::Migration::Error = core::convert::Infallible
pub fn vyre_driver::registry::Migration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::Migration where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::Migration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::Migration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::Migration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::Migration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::Migration where T: ?core::marker::Sized
pub fn vyre_driver::registry::Migration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::Migration where T: ?core::marker::Sized
pub fn vyre_driver::registry::Migration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::Migration
pub fn vyre_driver::registry::Migration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::Migration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::Migration
pub struct vyre_driver::registry::migration::MigrationRegistry
impl vyre_driver::registry::MigrationRegistry
pub fn vyre_driver::registry::MigrationRegistry::apply_chain(&self, op_id: &'static str, from: vyre_driver::registry::Semver, attrs: &mut vyre_driver::registry::AttrMap) -> core::result::Result<(&'static str, vyre_driver::registry::Semver), vyre_driver::registry::MigrationError>
pub fn vyre_driver::registry::MigrationRegistry::deprecation(&self, op_id: &str) -> core::option::Option<&'static vyre_driver::registry::Deprecation>
pub fn vyre_driver::registry::MigrationRegistry::global() -> &'static vyre_driver::registry::MigrationRegistry
pub fn vyre_driver::registry::MigrationRegistry::lookup(&self, op_id: &str, from: vyre_driver::registry::Semver) -> core::option::Option<&'static vyre_driver::registry::Migration>
impl core::marker::Freeze for vyre_driver::registry::MigrationRegistry
impl core::marker::Send for vyre_driver::registry::MigrationRegistry
impl core::marker::Sync for vyre_driver::registry::MigrationRegistry
impl core::marker::Unpin for vyre_driver::registry::MigrationRegistry
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::MigrationRegistry
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::MigrationRegistry
impl<T, U> core::convert::Into<U> for vyre_driver::registry::MigrationRegistry where U: core::convert::From<T>
pub fn vyre_driver::registry::MigrationRegistry::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::MigrationRegistry where U: core::convert::Into<T>
pub type vyre_driver::registry::MigrationRegistry::Error = core::convert::Infallible
pub fn vyre_driver::registry::MigrationRegistry::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::MigrationRegistry where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::MigrationRegistry::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::MigrationRegistry::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::MigrationRegistry where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::MigrationRegistry::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::MigrationRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::MigrationRegistry::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::MigrationRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::MigrationRegistry::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::MigrationRegistry
pub fn vyre_driver::registry::MigrationRegistry::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::MigrationRegistry
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::MigrationRegistry
pub struct vyre_driver::registry::migration::Semver
pub vyre_driver::registry::migration::Semver::major: u32
pub vyre_driver::registry::migration::Semver::minor: u32
pub vyre_driver::registry::migration::Semver::patch: u32
impl vyre_driver::registry::Semver
pub const fn vyre_driver::registry::Semver::new(major: u32, minor: u32, patch: u32) -> Self
impl core::clone::Clone for vyre_driver::registry::Semver
pub fn vyre_driver::registry::Semver::clone(&self) -> vyre_driver::registry::Semver
impl core::cmp::Eq for vyre_driver::registry::Semver
impl core::cmp::Ord for vyre_driver::registry::Semver
pub fn vyre_driver::registry::Semver::cmp(&self, other: &vyre_driver::registry::Semver) -> core::cmp::Ordering
impl core::cmp::PartialEq for vyre_driver::registry::Semver
pub fn vyre_driver::registry::Semver::eq(&self, other: &vyre_driver::registry::Semver) -> bool
impl core::cmp::PartialOrd for vyre_driver::registry::Semver
pub fn vyre_driver::registry::Semver::partial_cmp(&self, other: &vyre_driver::registry::Semver) -> core::option::Option<core::cmp::Ordering>
impl core::fmt::Debug for vyre_driver::registry::Semver
pub fn vyre_driver::registry::Semver::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::registry::Semver
pub fn vyre_driver::registry::Semver::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::registry::Semver
pub fn vyre_driver::registry::Semver::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::registry::Semver
impl core::marker::StructuralPartialEq for vyre_driver::registry::Semver
impl core::marker::Freeze for vyre_driver::registry::Semver
impl core::marker::Send for vyre_driver::registry::Semver
impl core::marker::Sync for vyre_driver::registry::Semver
impl core::marker::Unpin for vyre_driver::registry::Semver
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::Semver
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::Semver
impl<Q, K> equivalent::Comparable<K> for vyre_driver::registry::Semver where Q: core::cmp::Ord + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::Semver::compare(&self, key: &K) -> core::cmp::Ordering
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::Semver where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::Semver::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::Semver where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::Semver where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::Semver::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::Semver::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::Semver where U: core::convert::From<T>
pub fn vyre_driver::registry::Semver::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::Semver where U: core::convert::Into<T>
pub type vyre_driver::registry::Semver::Error = core::convert::Infallible
pub fn vyre_driver::registry::Semver::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::Semver where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::Semver::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::Semver::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::Semver where T: core::clone::Clone
pub type vyre_driver::registry::Semver::Owned = T
pub fn vyre_driver::registry::Semver::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::Semver::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::registry::Semver where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::registry::Semver::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::registry::Semver where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::Semver::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::Semver where T: ?core::marker::Sized
pub fn vyre_driver::registry::Semver::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::Semver where T: ?core::marker::Sized
pub fn vyre_driver::registry::Semver::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::Semver where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::Semver::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::Semver
pub fn vyre_driver::registry::Semver::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::Semver
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::Semver
pub fn vyre_driver::registry::migration::deprecation_diagnostic(dep: &vyre_driver::registry::Deprecation) -> vyre_driver::Diagnostic
pub mod vyre_driver::registry::mutation
pub enum vyre_driver::registry::mutation::MutationClass
pub vyre_driver::registry::mutation::MutationClass::Cosmetic
pub vyre_driver::registry::mutation::MutationClass::Lowering
pub vyre_driver::registry::mutation::MutationClass::Semantic
pub vyre_driver::registry::mutation::MutationClass::Structural
impl vyre_driver::registry::MutationClass
pub const fn vyre_driver::registry::MutationClass::requires_byte_parity(self) -> bool
pub const fn vyre_driver::registry::MutationClass::uses_law_proof(self) -> bool
impl core::clone::Clone for vyre_driver::registry::MutationClass
pub fn vyre_driver::registry::MutationClass::clone(&self) -> vyre_driver::registry::MutationClass
impl core::cmp::Eq for vyre_driver::registry::MutationClass
impl core::cmp::PartialEq for vyre_driver::registry::MutationClass
pub fn vyre_driver::registry::MutationClass::eq(&self, other: &vyre_driver::registry::MutationClass) -> bool
impl core::fmt::Debug for vyre_driver::registry::MutationClass
pub fn vyre_driver::registry::MutationClass::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::registry::MutationClass
pub fn vyre_driver::registry::MutationClass::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::registry::MutationClass
impl core::marker::StructuralPartialEq for vyre_driver::registry::MutationClass
impl core::marker::Freeze for vyre_driver::registry::MutationClass
impl core::marker::Send for vyre_driver::registry::MutationClass
impl core::marker::Sync for vyre_driver::registry::MutationClass
impl core::marker::Unpin for vyre_driver::registry::MutationClass
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::MutationClass
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::MutationClass
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::MutationClass::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::MutationClass::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::MutationClass::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::MutationClass where U: core::convert::From<T>
pub fn vyre_driver::registry::MutationClass::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::MutationClass where U: core::convert::Into<T>
pub type vyre_driver::registry::MutationClass::Error = core::convert::Infallible
pub fn vyre_driver::registry::MutationClass::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::MutationClass where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::MutationClass::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::MutationClass::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::MutationClass where T: core::clone::Clone
pub type vyre_driver::registry::MutationClass::Owned = T
pub fn vyre_driver::registry::MutationClass::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::MutationClass::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::MutationClass where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::MutationClass::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::MutationClass where T: ?core::marker::Sized
pub fn vyre_driver::registry::MutationClass::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::MutationClass where T: ?core::marker::Sized
pub fn vyre_driver::registry::MutationClass::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::MutationClass where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::MutationClass::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::MutationClass
pub fn vyre_driver::registry::MutationClass::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::MutationClass
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::MutationClass
pub mod vyre_driver::registry::op_def
pub use vyre_driver::registry::op_def::AttrSchema
pub use vyre_driver::registry::op_def::AttrType
pub use vyre_driver::registry::op_def::Category
pub use vyre_driver::registry::op_def::OpDef
pub use vyre_driver::registry::op_def::Signature
pub use vyre_driver::registry::op_def::TypedParam
pub mod vyre_driver::registry::registry
#[non_exhaustive] pub enum vyre_driver::registry::registry::Target
pub vyre_driver::registry::registry::Target::CpuRef
pub vyre_driver::registry::registry::Target::Extension(&'static str)
pub vyre_driver::registry::registry::Target::MetalIr
pub vyre_driver::registry::registry::Target::Ptx
pub vyre_driver::registry::registry::Target::Spirv
pub vyre_driver::registry::registry::Target::Wgsl
impl core::clone::Clone for vyre_driver::registry::Target
pub fn vyre_driver::registry::Target::clone(&self) -> vyre_driver::registry::Target
impl core::cmp::Eq for vyre_driver::registry::Target
impl core::cmp::PartialEq for vyre_driver::registry::Target
pub fn vyre_driver::registry::Target::eq(&self, other: &vyre_driver::registry::Target) -> bool
impl core::fmt::Debug for vyre_driver::registry::Target
pub fn vyre_driver::registry::Target::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::registry::Target
pub fn vyre_driver::registry::Target::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::registry::Target
impl core::marker::StructuralPartialEq for vyre_driver::registry::Target
impl core::marker::Freeze for vyre_driver::registry::Target
impl core::marker::Send for vyre_driver::registry::Target
impl core::marker::Sync for vyre_driver::registry::Target
impl core::marker::Unpin for vyre_driver::registry::Target
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::Target
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::Target
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::Target::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::Target::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::Target::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::Target where U: core::convert::From<T>
pub fn vyre_driver::registry::Target::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::Target where U: core::convert::Into<T>
pub type vyre_driver::registry::Target::Error = core::convert::Infallible
pub fn vyre_driver::registry::Target::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::Target where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::Target::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::Target::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::Target where T: core::clone::Clone
pub type vyre_driver::registry::Target::Owned = T
pub fn vyre_driver::registry::Target::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::Target::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::Target where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::Target::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::Target where T: ?core::marker::Sized
pub fn vyre_driver::registry::Target::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::Target where T: ?core::marker::Sized
pub fn vyre_driver::registry::Target::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::Target where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::Target::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::Target
pub fn vyre_driver::registry::Target::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::Target
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::Target
pub struct vyre_driver::registry::registry::DialectRegistry
impl vyre_driver::registry::DialectRegistry
pub fn vyre_driver::registry::DialectRegistry::get_lowering(&self, id: vyre_foundation::dialect_lookup::InternedOpId, target: vyre_driver::registry::Target) -> core::option::Option<vyre_foundation::dialect_lookup::CpuRef>
pub fn vyre_driver::registry::DialectRegistry::global() -> arc_swap::Guard<alloc::sync::Arc<Self>>
pub fn vyre_driver::registry::DialectRegistry::install(new: Self)
pub fn vyre_driver::registry::DialectRegistry::intern_op(&self, name: &str) -> vyre_foundation::dialect_lookup::InternedOpId
pub fn vyre_driver::registry::DialectRegistry::iter(&self) -> impl core::iter::traits::iterator::Iterator<Item = &'static vyre_foundation::dialect_lookup::OpDef> + '_
pub fn vyre_driver::registry::DialectRegistry::lookup(&self, id: vyre_foundation::dialect_lookup::InternedOpId) -> core::option::Option<&'static vyre_foundation::dialect_lookup::OpDef>
pub fn vyre_driver::registry::DialectRegistry::validate_no_duplicates<'a>(defs: impl core::iter::traits::collect::IntoIterator<Item = &'a vyre_foundation::dialect_lookup::OpDef>) -> core::result::Result<(), vyre_driver::registry::DuplicateOpIdError>
impl vyre_foundation::dialect_lookup::DialectLookup for vyre_driver::registry::DialectRegistry
pub fn vyre_driver::registry::DialectRegistry::intern_op(&self, name: &str) -> vyre_foundation::dialect_lookup::InternedOpId
pub fn vyre_driver::registry::DialectRegistry::lookup(&self, id: vyre_foundation::dialect_lookup::InternedOpId) -> core::option::Option<&'static vyre_foundation::dialect_lookup::OpDef>
impl core::marker::Freeze for vyre_driver::registry::DialectRegistry
impl core::marker::Send for vyre_driver::registry::DialectRegistry
impl core::marker::Sync for vyre_driver::registry::DialectRegistry
impl core::marker::Unpin for vyre_driver::registry::DialectRegistry
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::DialectRegistry
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::DialectRegistry
impl<T, U> core::convert::Into<U> for vyre_driver::registry::DialectRegistry where U: core::convert::From<T>
pub fn vyre_driver::registry::DialectRegistry::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::DialectRegistry where U: core::convert::Into<T>
pub type vyre_driver::registry::DialectRegistry::Error = core::convert::Infallible
pub fn vyre_driver::registry::DialectRegistry::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::DialectRegistry where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::DialectRegistry::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::DialectRegistry::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::DialectRegistry where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistry::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::DialectRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistry::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::DialectRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistry::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::DialectRegistry
pub fn vyre_driver::registry::DialectRegistry::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::DialectRegistry
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::DialectRegistry
pub struct vyre_driver::registry::registry::DuplicateOpIdError
impl vyre_driver::registry::DuplicateOpIdError
pub const fn vyre_driver::registry::DuplicateOpIdError::op_id(&self) -> &'static str
impl core::clone::Clone for vyre_driver::registry::DuplicateOpIdError
pub fn vyre_driver::registry::DuplicateOpIdError::clone(&self) -> vyre_driver::registry::DuplicateOpIdError
impl core::cmp::Eq for vyre_driver::registry::DuplicateOpIdError
impl core::cmp::PartialEq for vyre_driver::registry::DuplicateOpIdError
pub fn vyre_driver::registry::DuplicateOpIdError::eq(&self, other: &vyre_driver::registry::DuplicateOpIdError) -> bool
impl core::error::Error for vyre_driver::registry::DuplicateOpIdError
impl core::fmt::Debug for vyre_driver::registry::DuplicateOpIdError
pub fn vyre_driver::registry::DuplicateOpIdError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::registry::DuplicateOpIdError
pub fn vyre_driver::registry::DuplicateOpIdError::fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::DuplicateOpIdError
impl core::marker::Freeze for vyre_driver::registry::DuplicateOpIdError
impl core::marker::Send for vyre_driver::registry::DuplicateOpIdError
impl core::marker::Sync for vyre_driver::registry::DuplicateOpIdError
impl core::marker::Unpin for vyre_driver::registry::DuplicateOpIdError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::DuplicateOpIdError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::DuplicateOpIdError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::DuplicateOpIdError where U: core::convert::From<T>
pub fn vyre_driver::registry::DuplicateOpIdError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::DuplicateOpIdError where U: core::convert::Into<T>
pub type vyre_driver::registry::DuplicateOpIdError::Error = core::convert::Infallible
pub fn vyre_driver::registry::DuplicateOpIdError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::DuplicateOpIdError where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::DuplicateOpIdError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::DuplicateOpIdError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::DuplicateOpIdError where T: core::clone::Clone
pub type vyre_driver::registry::DuplicateOpIdError::Owned = T
pub fn vyre_driver::registry::DuplicateOpIdError::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::DuplicateOpIdError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::registry::DuplicateOpIdError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::registry::DuplicateOpIdError where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::DuplicateOpIdError where T: ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::DuplicateOpIdError where T: ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::DuplicateOpIdError where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::DuplicateOpIdError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::DuplicateOpIdError
pub fn vyre_driver::registry::DuplicateOpIdError::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::DuplicateOpIdError
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::DuplicateOpIdError
pub mod vyre_driver::registry::toml_loader
pub struct vyre_driver::registry::toml_loader::DialectManifest
pub vyre_driver::registry::toml_loader::DialectManifest::description: core::option::Option<alloc::string::String>
pub vyre_driver::registry::toml_loader::DialectManifest::dialect: alloc::string::String
pub vyre_driver::registry::toml_loader::DialectManifest::ops: alloc::vec::Vec<vyre_driver::registry::OpManifest>
pub vyre_driver::registry::toml_loader::DialectManifest::version: alloc::string::String
impl core::clone::Clone for vyre_driver::registry::DialectManifest
pub fn vyre_driver::registry::DialectManifest::clone(&self) -> vyre_driver::registry::DialectManifest
impl core::cmp::PartialEq for vyre_driver::registry::DialectManifest
pub fn vyre_driver::registry::DialectManifest::eq(&self, other: &vyre_driver::registry::DialectManifest) -> bool
impl core::fmt::Debug for vyre_driver::registry::DialectManifest
pub fn vyre_driver::registry::DialectManifest::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::DialectManifest
impl serde_core::ser::Serialize for vyre_driver::registry::DialectManifest
pub fn vyre_driver::registry::DialectManifest::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::registry::DialectManifest
pub fn vyre_driver::registry::DialectManifest::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::registry::DialectManifest
impl core::marker::Send for vyre_driver::registry::DialectManifest
impl core::marker::Sync for vyre_driver::registry::DialectManifest
impl core::marker::Unpin for vyre_driver::registry::DialectManifest
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::DialectManifest
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::DialectManifest
impl<T, U> core::convert::Into<U> for vyre_driver::registry::DialectManifest where U: core::convert::From<T>
pub fn vyre_driver::registry::DialectManifest::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::DialectManifest where U: core::convert::Into<T>
pub type vyre_driver::registry::DialectManifest::Error = core::convert::Infallible
pub fn vyre_driver::registry::DialectManifest::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::DialectManifest where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::DialectManifest::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::DialectManifest::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::DialectManifest where T: core::clone::Clone
pub type vyre_driver::registry::DialectManifest::Owned = T
pub fn vyre_driver::registry::DialectManifest::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::DialectManifest::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::DialectManifest where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::DialectManifest::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::DialectManifest where T: ?core::marker::Sized
pub fn vyre_driver::registry::DialectManifest::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::DialectManifest where T: ?core::marker::Sized
pub fn vyre_driver::registry::DialectManifest::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::DialectManifest where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::DialectManifest::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::DialectManifest
pub fn vyre_driver::registry::DialectManifest::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::registry::DialectManifest where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::registry::DialectManifest
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::DialectManifest
pub struct vyre_driver::registry::toml_loader::OpManifest
pub vyre_driver::registry::toml_loader::OpManifest::category: alloc::string::String
pub vyre_driver::registry::toml_loader::OpManifest::id: alloc::string::String
pub vyre_driver::registry::toml_loader::OpManifest::inputs: alloc::vec::Vec<(alloc::string::String, alloc::string::String)>
pub vyre_driver::registry::toml_loader::OpManifest::laws: alloc::vec::Vec<alloc::string::String>
pub vyre_driver::registry::toml_loader::OpManifest::outputs: alloc::vec::Vec<(alloc::string::String, alloc::string::String)>
pub vyre_driver::registry::toml_loader::OpManifest::summary: core::option::Option<alloc::string::String>
impl core::clone::Clone for vyre_driver::registry::OpManifest
pub fn vyre_driver::registry::OpManifest::clone(&self) -> vyre_driver::registry::OpManifest
impl core::cmp::PartialEq for vyre_driver::registry::OpManifest
pub fn vyre_driver::registry::OpManifest::eq(&self, other: &vyre_driver::registry::OpManifest) -> bool
impl core::fmt::Debug for vyre_driver::registry::OpManifest
pub fn vyre_driver::registry::OpManifest::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::OpManifest
impl serde_core::ser::Serialize for vyre_driver::registry::OpManifest
pub fn vyre_driver::registry::OpManifest::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::registry::OpManifest
pub fn vyre_driver::registry::OpManifest::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::registry::OpManifest
impl core::marker::Send for vyre_driver::registry::OpManifest
impl core::marker::Sync for vyre_driver::registry::OpManifest
impl core::marker::Unpin for vyre_driver::registry::OpManifest
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::OpManifest
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::OpManifest
impl<T, U> core::convert::Into<U> for vyre_driver::registry::OpManifest where U: core::convert::From<T>
pub fn vyre_driver::registry::OpManifest::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::OpManifest where U: core::convert::Into<T>
pub type vyre_driver::registry::OpManifest::Error = core::convert::Infallible
pub fn vyre_driver::registry::OpManifest::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::OpManifest where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::OpManifest::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::OpManifest::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::OpManifest where T: core::clone::Clone
pub type vyre_driver::registry::OpManifest::Owned = T
pub fn vyre_driver::registry::OpManifest::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::OpManifest::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::OpManifest where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::OpManifest::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::OpManifest where T: ?core::marker::Sized
pub fn vyre_driver::registry::OpManifest::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::OpManifest where T: ?core::marker::Sized
pub fn vyre_driver::registry::OpManifest::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::OpManifest where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::OpManifest::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::OpManifest
pub fn vyre_driver::registry::OpManifest::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::registry::OpManifest where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::registry::OpManifest
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::OpManifest
pub struct vyre_driver::registry::toml_loader::TomlDialectStore
impl vyre_driver::registry::TomlDialectStore
pub fn vyre_driver::registry::TomlDialectStore::contains_op(&self, op_id: &str) -> bool
pub fn vyre_driver::registry::TomlDialectStore::diagnostics(&self) -> &[vyre_driver::Diagnostic]
pub fn vyre_driver::registry::TomlDialectStore::dialect(&self, id: &str) -> core::option::Option<&vyre_driver::registry::DialectManifest>
pub fn vyre_driver::registry::TomlDialectStore::from_env() -> Self
pub fn vyre_driver::registry::TomlDialectStore::load_file(&mut self, path: &std::path::Path)
pub fn vyre_driver::registry::TomlDialectStore::manifests(&self) -> alloc::vec::Vec<&vyre_driver::registry::DialectManifest>
pub fn vyre_driver::registry::TomlDialectStore::ops_in(&self, dialect: &str) -> &[vyre_driver::registry::OpManifest]
pub fn vyre_driver::registry::TomlDialectStore::scan_dir(&mut self, dir: &std::path::Path)
impl core::clone::Clone for vyre_driver::registry::TomlDialectStore
pub fn vyre_driver::registry::TomlDialectStore::clone(&self) -> vyre_driver::registry::TomlDialectStore
impl core::default::Default for vyre_driver::registry::TomlDialectStore
pub fn vyre_driver::registry::TomlDialectStore::default() -> vyre_driver::registry::TomlDialectStore
impl core::fmt::Debug for vyre_driver::registry::TomlDialectStore
pub fn vyre_driver::registry::TomlDialectStore::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::registry::TomlDialectStore
impl core::marker::Send for vyre_driver::registry::TomlDialectStore
impl core::marker::Sync for vyre_driver::registry::TomlDialectStore
impl core::marker::Unpin for vyre_driver::registry::TomlDialectStore
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::TomlDialectStore
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::TomlDialectStore
impl<T, U> core::convert::Into<U> for vyre_driver::registry::TomlDialectStore where U: core::convert::From<T>
pub fn vyre_driver::registry::TomlDialectStore::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::TomlDialectStore where U: core::convert::Into<T>
pub type vyre_driver::registry::TomlDialectStore::Error = core::convert::Infallible
pub fn vyre_driver::registry::TomlDialectStore::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::TomlDialectStore where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::TomlDialectStore::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::TomlDialectStore::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::TomlDialectStore where T: core::clone::Clone
pub type vyre_driver::registry::TomlDialectStore::Owned = T
pub fn vyre_driver::registry::TomlDialectStore::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::TomlDialectStore::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::TomlDialectStore where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::TomlDialectStore::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::TomlDialectStore where T: ?core::marker::Sized
pub fn vyre_driver::registry::TomlDialectStore::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::TomlDialectStore where T: ?core::marker::Sized
pub fn vyre_driver::registry::TomlDialectStore::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::TomlDialectStore where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::TomlDialectStore::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::TomlDialectStore
pub fn vyre_driver::registry::TomlDialectStore::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::TomlDialectStore
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::TomlDialectStore
pub const vyre_driver::registry::toml_loader::CODE_PARSE: vyre_driver::DiagnosticCode
pub fn vyre_driver::registry::toml_loader::workspace_dialect_fixture_path() -> std::path::PathBuf
pub enum vyre_driver::registry::AttrValue
pub vyre_driver::registry::AttrValue::Bool(bool)
pub vyre_driver::registry::AttrValue::Bytes(alloc::vec::Vec<u8>)
pub vyre_driver::registry::AttrValue::F32(f32)
pub vyre_driver::registry::AttrValue::I32(i32)
pub vyre_driver::registry::AttrValue::String(alloc::string::String)
pub vyre_driver::registry::AttrValue::U32(u32)
impl core::clone::Clone for vyre_driver::registry::AttrValue
pub fn vyre_driver::registry::AttrValue::clone(&self) -> vyre_driver::registry::AttrValue
impl core::cmp::PartialEq for vyre_driver::registry::AttrValue
pub fn vyre_driver::registry::AttrValue::eq(&self, other: &vyre_driver::registry::AttrValue) -> bool
impl core::fmt::Debug for vyre_driver::registry::AttrValue
pub fn vyre_driver::registry::AttrValue::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::AttrValue
impl core::marker::Freeze for vyre_driver::registry::AttrValue
impl core::marker::Send for vyre_driver::registry::AttrValue
impl core::marker::Sync for vyre_driver::registry::AttrValue
impl core::marker::Unpin for vyre_driver::registry::AttrValue
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::AttrValue
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::AttrValue
impl<T, U> core::convert::Into<U> for vyre_driver::registry::AttrValue where U: core::convert::From<T>
pub fn vyre_driver::registry::AttrValue::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::AttrValue where U: core::convert::Into<T>
pub type vyre_driver::registry::AttrValue::Error = core::convert::Infallible
pub fn vyre_driver::registry::AttrValue::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::AttrValue where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::AttrValue::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::AttrValue::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::AttrValue where T: core::clone::Clone
pub type vyre_driver::registry::AttrValue::Owned = T
pub fn vyre_driver::registry::AttrValue::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::AttrValue::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::AttrValue where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::AttrValue::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::AttrValue where T: ?core::marker::Sized
pub fn vyre_driver::registry::AttrValue::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::AttrValue where T: ?core::marker::Sized
pub fn vyre_driver::registry::AttrValue::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::AttrValue where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::AttrValue::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::AttrValue
pub fn vyre_driver::registry::AttrValue::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::AttrValue
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::AttrValue
pub enum vyre_driver::registry::EnforceVerdict
pub vyre_driver::registry::EnforceVerdict::Allow
pub vyre_driver::registry::EnforceVerdict::Deny
pub vyre_driver::registry::EnforceVerdict::Deny::detail: alloc::string::String
pub vyre_driver::registry::EnforceVerdict::Deny::policy: &'static str
impl core::clone::Clone for vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::EnforceVerdict::clone(&self) -> vyre_driver::registry::EnforceVerdict
impl core::cmp::Eq for vyre_driver::registry::EnforceVerdict
impl core::cmp::PartialEq for vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::EnforceVerdict::eq(&self, other: &vyre_driver::registry::EnforceVerdict) -> bool
impl core::fmt::Debug for vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::EnforceVerdict::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::EnforceVerdict
impl core::marker::Freeze for vyre_driver::registry::EnforceVerdict
impl core::marker::Send for vyre_driver::registry::EnforceVerdict
impl core::marker::Sync for vyre_driver::registry::EnforceVerdict
impl core::marker::Unpin for vyre_driver::registry::EnforceVerdict
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::EnforceVerdict
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::EnforceVerdict
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::EnforceVerdict::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::EnforceVerdict::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::EnforceVerdict::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::EnforceVerdict where U: core::convert::From<T>
pub fn vyre_driver::registry::EnforceVerdict::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::EnforceVerdict where U: core::convert::Into<T>
pub type vyre_driver::registry::EnforceVerdict::Error = core::convert::Infallible
pub fn vyre_driver::registry::EnforceVerdict::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::EnforceVerdict where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::EnforceVerdict::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::EnforceVerdict::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::EnforceVerdict where T: core::clone::Clone
pub type vyre_driver::registry::EnforceVerdict::Owned = T
pub fn vyre_driver::registry::EnforceVerdict::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::EnforceVerdict::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::EnforceVerdict where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::EnforceVerdict::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::EnforceVerdict where T: ?core::marker::Sized
pub fn vyre_driver::registry::EnforceVerdict::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::EnforceVerdict where T: ?core::marker::Sized
pub fn vyre_driver::registry::EnforceVerdict::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::EnforceVerdict where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::EnforceVerdict::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::EnforceVerdict::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::EnforceVerdict
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::EnforceVerdict
pub enum vyre_driver::registry::MigrationError
pub vyre_driver::registry::MigrationError::Custom
pub vyre_driver::registry::MigrationError::Custom::reason: alloc::string::String
pub vyre_driver::registry::MigrationError::MissingAttribute
pub vyre_driver::registry::MigrationError::MissingAttribute::name: alloc::string::String
pub vyre_driver::registry::MigrationError::OutOfRange
pub vyre_driver::registry::MigrationError::OutOfRange::name: alloc::string::String
pub vyre_driver::registry::MigrationError::WrongType
pub vyre_driver::registry::MigrationError::WrongType::expected: &'static str
pub vyre_driver::registry::MigrationError::WrongType::name: alloc::string::String
impl core::clone::Clone for vyre_driver::registry::MigrationError
pub fn vyre_driver::registry::MigrationError::clone(&self) -> vyre_driver::registry::MigrationError
impl core::cmp::Eq for vyre_driver::registry::MigrationError
impl core::cmp::PartialEq for vyre_driver::registry::MigrationError
pub fn vyre_driver::registry::MigrationError::eq(&self, other: &vyre_driver::registry::MigrationError) -> bool
impl core::error::Error for vyre_driver::registry::MigrationError
impl core::fmt::Debug for vyre_driver::registry::MigrationError
pub fn vyre_driver::registry::MigrationError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::registry::MigrationError
pub fn vyre_driver::registry::MigrationError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::MigrationError
impl core::marker::Freeze for vyre_driver::registry::MigrationError
impl core::marker::Send for vyre_driver::registry::MigrationError
impl core::marker::Sync for vyre_driver::registry::MigrationError
impl core::marker::Unpin for vyre_driver::registry::MigrationError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::MigrationError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::MigrationError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::MigrationError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::MigrationError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::MigrationError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::MigrationError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::MigrationError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::MigrationError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::MigrationError where U: core::convert::From<T>
pub fn vyre_driver::registry::MigrationError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::MigrationError where U: core::convert::Into<T>
pub type vyre_driver::registry::MigrationError::Error = core::convert::Infallible
pub fn vyre_driver::registry::MigrationError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::MigrationError where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::MigrationError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::MigrationError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::MigrationError where T: core::clone::Clone
pub type vyre_driver::registry::MigrationError::Owned = T
pub fn vyre_driver::registry::MigrationError::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::MigrationError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::registry::MigrationError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::registry::MigrationError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::registry::MigrationError where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::MigrationError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::MigrationError where T: ?core::marker::Sized
pub fn vyre_driver::registry::MigrationError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::MigrationError where T: ?core::marker::Sized
pub fn vyre_driver::registry::MigrationError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::MigrationError where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::MigrationError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::MigrationError
pub fn vyre_driver::registry::MigrationError::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::MigrationError
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::MigrationError
pub enum vyre_driver::registry::MutationClass
pub vyre_driver::registry::MutationClass::Cosmetic
pub vyre_driver::registry::MutationClass::Lowering
pub vyre_driver::registry::MutationClass::Semantic
pub vyre_driver::registry::MutationClass::Structural
impl vyre_driver::registry::MutationClass
pub const fn vyre_driver::registry::MutationClass::requires_byte_parity(self) -> bool
pub const fn vyre_driver::registry::MutationClass::uses_law_proof(self) -> bool
impl core::clone::Clone for vyre_driver::registry::MutationClass
pub fn vyre_driver::registry::MutationClass::clone(&self) -> vyre_driver::registry::MutationClass
impl core::cmp::Eq for vyre_driver::registry::MutationClass
impl core::cmp::PartialEq for vyre_driver::registry::MutationClass
pub fn vyre_driver::registry::MutationClass::eq(&self, other: &vyre_driver::registry::MutationClass) -> bool
impl core::fmt::Debug for vyre_driver::registry::MutationClass
pub fn vyre_driver::registry::MutationClass::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::registry::MutationClass
pub fn vyre_driver::registry::MutationClass::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::registry::MutationClass
impl core::marker::StructuralPartialEq for vyre_driver::registry::MutationClass
impl core::marker::Freeze for vyre_driver::registry::MutationClass
impl core::marker::Send for vyre_driver::registry::MutationClass
impl core::marker::Sync for vyre_driver::registry::MutationClass
impl core::marker::Unpin for vyre_driver::registry::MutationClass
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::MutationClass
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::MutationClass
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::MutationClass::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::MutationClass::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::MutationClass::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::MutationClass where U: core::convert::From<T>
pub fn vyre_driver::registry::MutationClass::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::MutationClass where U: core::convert::Into<T>
pub type vyre_driver::registry::MutationClass::Error = core::convert::Infallible
pub fn vyre_driver::registry::MutationClass::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::MutationClass where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::MutationClass::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::MutationClass::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::MutationClass where T: core::clone::Clone
pub type vyre_driver::registry::MutationClass::Owned = T
pub fn vyre_driver::registry::MutationClass::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::MutationClass::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::MutationClass where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::MutationClass::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::MutationClass where T: ?core::marker::Sized
pub fn vyre_driver::registry::MutationClass::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::MutationClass where T: ?core::marker::Sized
pub fn vyre_driver::registry::MutationClass::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::MutationClass where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::MutationClass::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::MutationClass
pub fn vyre_driver::registry::MutationClass::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::MutationClass
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::MutationClass
#[non_exhaustive] pub enum vyre_driver::registry::Target
pub vyre_driver::registry::Target::CpuRef
pub vyre_driver::registry::Target::Extension(&'static str)
pub vyre_driver::registry::Target::MetalIr
pub vyre_driver::registry::Target::Ptx
pub vyre_driver::registry::Target::Spirv
pub vyre_driver::registry::Target::Wgsl
impl core::clone::Clone for vyre_driver::registry::Target
pub fn vyre_driver::registry::Target::clone(&self) -> vyre_driver::registry::Target
impl core::cmp::Eq for vyre_driver::registry::Target
impl core::cmp::PartialEq for vyre_driver::registry::Target
pub fn vyre_driver::registry::Target::eq(&self, other: &vyre_driver::registry::Target) -> bool
impl core::fmt::Debug for vyre_driver::registry::Target
pub fn vyre_driver::registry::Target::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::registry::Target
pub fn vyre_driver::registry::Target::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::registry::Target
impl core::marker::StructuralPartialEq for vyre_driver::registry::Target
impl core::marker::Freeze for vyre_driver::registry::Target
impl core::marker::Send for vyre_driver::registry::Target
impl core::marker::Sync for vyre_driver::registry::Target
impl core::marker::Unpin for vyre_driver::registry::Target
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::Target
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::Target
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::Target::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::Target::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::Target::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::Target where U: core::convert::From<T>
pub fn vyre_driver::registry::Target::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::Target where U: core::convert::Into<T>
pub type vyre_driver::registry::Target::Error = core::convert::Infallible
pub fn vyre_driver::registry::Target::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::Target where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::Target::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::Target::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::Target where T: core::clone::Clone
pub type vyre_driver::registry::Target::Owned = T
pub fn vyre_driver::registry::Target::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::Target::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::Target where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::Target::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::Target where T: ?core::marker::Sized
pub fn vyre_driver::registry::Target::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::Target where T: ?core::marker::Sized
pub fn vyre_driver::registry::Target::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::Target where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::Target::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::Target
pub fn vyre_driver::registry::Target::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::Target
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::Target
pub struct vyre_driver::registry::AttrMap
impl vyre_driver::registry::AttrMap
pub fn vyre_driver::registry::AttrMap::get(&self, key: &str) -> core::option::Option<&vyre_driver::registry::AttrValue>
pub fn vyre_driver::registry::AttrMap::insert(&mut self, key: impl core::convert::Into<alloc::string::String>, value: vyre_driver::registry::AttrValue) -> core::option::Option<vyre_driver::registry::AttrValue>
pub fn vyre_driver::registry::AttrMap::is_empty(&self) -> bool
pub fn vyre_driver::registry::AttrMap::iter(&self) -> impl core::iter::traits::iterator::Iterator<Item = (&str, &vyre_driver::registry::AttrValue)>
pub fn vyre_driver::registry::AttrMap::len(&self) -> usize
pub fn vyre_driver::registry::AttrMap::new() -> Self
pub fn vyre_driver::registry::AttrMap::remove(&mut self, key: &str) -> core::option::Option<vyre_driver::registry::AttrValue>
pub fn vyre_driver::registry::AttrMap::rename(&mut self, from: &str, to: impl core::convert::Into<alloc::string::String>) -> bool
impl core::clone::Clone for vyre_driver::registry::AttrMap
pub fn vyre_driver::registry::AttrMap::clone(&self) -> vyre_driver::registry::AttrMap
impl core::default::Default for vyre_driver::registry::AttrMap
pub fn vyre_driver::registry::AttrMap::default() -> vyre_driver::registry::AttrMap
impl core::fmt::Debug for vyre_driver::registry::AttrMap
pub fn vyre_driver::registry::AttrMap::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::registry::AttrMap
impl core::marker::Send for vyre_driver::registry::AttrMap
impl core::marker::Sync for vyre_driver::registry::AttrMap
impl core::marker::Unpin for vyre_driver::registry::AttrMap
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::AttrMap
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::AttrMap
impl<T, U> core::convert::Into<U> for vyre_driver::registry::AttrMap where U: core::convert::From<T>
pub fn vyre_driver::registry::AttrMap::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::AttrMap where U: core::convert::Into<T>
pub type vyre_driver::registry::AttrMap::Error = core::convert::Infallible
pub fn vyre_driver::registry::AttrMap::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::AttrMap where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::AttrMap::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::AttrMap::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::AttrMap where T: core::clone::Clone
pub type vyre_driver::registry::AttrMap::Owned = T
pub fn vyre_driver::registry::AttrMap::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::AttrMap::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::AttrMap where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::AttrMap::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::AttrMap where T: ?core::marker::Sized
pub fn vyre_driver::registry::AttrMap::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::AttrMap where T: ?core::marker::Sized
pub fn vyre_driver::registry::AttrMap::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::AttrMap where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::AttrMap::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::AttrMap
pub fn vyre_driver::registry::AttrMap::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::AttrMap
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::AttrMap
pub struct vyre_driver::registry::Chain<A, B>
impl<A: vyre_driver::registry::EnforceGate, B: vyre_driver::registry::EnforceGate> vyre_driver::registry::Chain<A, B>
pub fn vyre_driver::registry::Chain<A, B>::new(first: A, second: B) -> Self
impl<A: vyre_driver::registry::EnforceGate, B: vyre_driver::registry::EnforceGate> vyre_driver::registry::EnforceGate for vyre_driver::registry::Chain<A, B>
pub fn vyre_driver::registry::Chain<A, B>::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::Program) -> vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::Chain<A, B>::name(&self) -> &'static str
impl<A, B> core::marker::Freeze for vyre_driver::registry::Chain<A, B> where A: core::marker::Freeze, B: core::marker::Freeze
impl<A, B> core::marker::Send for vyre_driver::registry::Chain<A, B> where A: core::marker::Send, B: core::marker::Send
impl<A, B> core::marker::Sync for vyre_driver::registry::Chain<A, B> where A: core::marker::Sync, B: core::marker::Sync
impl<A, B> core::marker::Unpin for vyre_driver::registry::Chain<A, B> where A: core::marker::Unpin, B: core::marker::Unpin
impl<A, B> core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::Chain<A, B> where A: core::panic::unwind_safe::RefUnwindSafe, B: core::panic::unwind_safe::RefUnwindSafe
impl<A, B> core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::Chain<A, B> where A: core::panic::unwind_safe::UnwindSafe, B: core::panic::unwind_safe::UnwindSafe
impl<T, U> core::convert::Into<U> for vyre_driver::registry::Chain<A, B> where U: core::convert::From<T>
pub fn vyre_driver::registry::Chain<A, B>::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::Chain<A, B> where U: core::convert::Into<T>
pub type vyre_driver::registry::Chain<A, B>::Error = core::convert::Infallible
pub fn vyre_driver::registry::Chain<A, B>::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::Chain<A, B> where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::Chain<A, B>::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::Chain<A, B>::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::Chain<A, B> where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::Chain<A, B>::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::Chain<A, B> where T: ?core::marker::Sized
pub fn vyre_driver::registry::Chain<A, B>::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::Chain<A, B> where T: ?core::marker::Sized
pub fn vyre_driver::registry::Chain<A, B>::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::Chain<A, B>
pub fn vyre_driver::registry::Chain<A, B>::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::Chain<A, B>
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::Chain<A, B>
pub struct vyre_driver::registry::Deprecation
pub vyre_driver::registry::Deprecation::deprecated_since: vyre_driver::registry::Semver
pub vyre_driver::registry::Deprecation::note: &'static str
pub vyre_driver::registry::Deprecation::op_id: &'static str
impl vyre_driver::registry::Deprecation
pub const fn vyre_driver::registry::Deprecation::new(op_id: &'static str, deprecated_since: vyre_driver::registry::Semver, note: &'static str) -> Self
impl inventory::Collect for vyre_driver::registry::Deprecation
impl core::marker::Freeze for vyre_driver::registry::Deprecation
impl core::marker::Send for vyre_driver::registry::Deprecation
impl core::marker::Sync for vyre_driver::registry::Deprecation
impl core::marker::Unpin for vyre_driver::registry::Deprecation
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::Deprecation
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::Deprecation
impl<T, U> core::convert::Into<U> for vyre_driver::registry::Deprecation where U: core::convert::From<T>
pub fn vyre_driver::registry::Deprecation::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::Deprecation where U: core::convert::Into<T>
pub type vyre_driver::registry::Deprecation::Error = core::convert::Infallible
pub fn vyre_driver::registry::Deprecation::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::Deprecation where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::Deprecation::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::Deprecation::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::Deprecation where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::Deprecation::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::Deprecation where T: ?core::marker::Sized
pub fn vyre_driver::registry::Deprecation::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::Deprecation where T: ?core::marker::Sized
pub fn vyre_driver::registry::Deprecation::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::Deprecation
pub fn vyre_driver::registry::Deprecation::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::Deprecation
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::Deprecation
pub struct vyre_driver::registry::Dialect
pub vyre_driver::registry::Dialect::backends_required: &'static [vyre_spec::intrinsic_descriptor::Backend]
pub vyre_driver::registry::Dialect::id: &'static str
pub vyre_driver::registry::Dialect::ops: &'static [&'static str]
pub vyre_driver::registry::Dialect::parent: core::option::Option<&'static str>
pub vyre_driver::registry::Dialect::validator: fn() -> bool
pub vyre_driver::registry::Dialect::version: u32
impl core::marker::Freeze for vyre_driver::registry::Dialect
impl core::marker::Send for vyre_driver::registry::Dialect
impl core::marker::Sync for vyre_driver::registry::Dialect
impl core::marker::Unpin for vyre_driver::registry::Dialect
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::Dialect
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::Dialect
impl<T, U> core::convert::Into<U> for vyre_driver::registry::Dialect where U: core::convert::From<T>
pub fn vyre_driver::registry::Dialect::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::Dialect where U: core::convert::Into<T>
pub type vyre_driver::registry::Dialect::Error = core::convert::Infallible
pub fn vyre_driver::registry::Dialect::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::Dialect where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::Dialect::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::Dialect::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::Dialect where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::Dialect::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::Dialect where T: ?core::marker::Sized
pub fn vyre_driver::registry::Dialect::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::Dialect where T: ?core::marker::Sized
pub fn vyre_driver::registry::Dialect::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::Dialect
pub fn vyre_driver::registry::Dialect::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::Dialect
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::Dialect
pub struct vyre_driver::registry::DialectManifest
pub vyre_driver::registry::DialectManifest::description: core::option::Option<alloc::string::String>
pub vyre_driver::registry::DialectManifest::dialect: alloc::string::String
pub vyre_driver::registry::DialectManifest::ops: alloc::vec::Vec<vyre_driver::registry::OpManifest>
pub vyre_driver::registry::DialectManifest::version: alloc::string::String
impl core::clone::Clone for vyre_driver::registry::DialectManifest
pub fn vyre_driver::registry::DialectManifest::clone(&self) -> vyre_driver::registry::DialectManifest
impl core::cmp::PartialEq for vyre_driver::registry::DialectManifest
pub fn vyre_driver::registry::DialectManifest::eq(&self, other: &vyre_driver::registry::DialectManifest) -> bool
impl core::fmt::Debug for vyre_driver::registry::DialectManifest
pub fn vyre_driver::registry::DialectManifest::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::DialectManifest
impl serde_core::ser::Serialize for vyre_driver::registry::DialectManifest
pub fn vyre_driver::registry::DialectManifest::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::registry::DialectManifest
pub fn vyre_driver::registry::DialectManifest::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::registry::DialectManifest
impl core::marker::Send for vyre_driver::registry::DialectManifest
impl core::marker::Sync for vyre_driver::registry::DialectManifest
impl core::marker::Unpin for vyre_driver::registry::DialectManifest
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::DialectManifest
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::DialectManifest
impl<T, U> core::convert::Into<U> for vyre_driver::registry::DialectManifest where U: core::convert::From<T>
pub fn vyre_driver::registry::DialectManifest::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::DialectManifest where U: core::convert::Into<T>
pub type vyre_driver::registry::DialectManifest::Error = core::convert::Infallible
pub fn vyre_driver::registry::DialectManifest::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::DialectManifest where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::DialectManifest::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::DialectManifest::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::DialectManifest where T: core::clone::Clone
pub type vyre_driver::registry::DialectManifest::Owned = T
pub fn vyre_driver::registry::DialectManifest::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::DialectManifest::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::DialectManifest where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::DialectManifest::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::DialectManifest where T: ?core::marker::Sized
pub fn vyre_driver::registry::DialectManifest::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::DialectManifest where T: ?core::marker::Sized
pub fn vyre_driver::registry::DialectManifest::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::DialectManifest where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::DialectManifest::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::DialectManifest
pub fn vyre_driver::registry::DialectManifest::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::registry::DialectManifest where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::registry::DialectManifest
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::DialectManifest
pub struct vyre_driver::registry::DialectRegistration
pub vyre_driver::registry::DialectRegistration::dialect: fn() -> vyre_driver::registry::Dialect
impl inventory::Collect for vyre_driver::registry::DialectRegistration
impl core::marker::Freeze for vyre_driver::registry::DialectRegistration
impl core::marker::Send for vyre_driver::registry::DialectRegistration
impl core::marker::Sync for vyre_driver::registry::DialectRegistration
impl core::marker::Unpin for vyre_driver::registry::DialectRegistration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::DialectRegistration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::DialectRegistration
impl<T, U> core::convert::Into<U> for vyre_driver::registry::DialectRegistration where U: core::convert::From<T>
pub fn vyre_driver::registry::DialectRegistration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::DialectRegistration where U: core::convert::Into<T>
pub type vyre_driver::registry::DialectRegistration::Error = core::convert::Infallible
pub fn vyre_driver::registry::DialectRegistration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::DialectRegistration where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::DialectRegistration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::DialectRegistration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::DialectRegistration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::DialectRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::DialectRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::DialectRegistration
pub fn vyre_driver::registry::DialectRegistration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::DialectRegistration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::DialectRegistration
pub struct vyre_driver::registry::DialectRegistry
impl vyre_driver::registry::DialectRegistry
pub fn vyre_driver::registry::DialectRegistry::get_lowering(&self, id: vyre_foundation::dialect_lookup::InternedOpId, target: vyre_driver::registry::Target) -> core::option::Option<vyre_foundation::dialect_lookup::CpuRef>
pub fn vyre_driver::registry::DialectRegistry::global() -> arc_swap::Guard<alloc::sync::Arc<Self>>
pub fn vyre_driver::registry::DialectRegistry::install(new: Self)
pub fn vyre_driver::registry::DialectRegistry::intern_op(&self, name: &str) -> vyre_foundation::dialect_lookup::InternedOpId
pub fn vyre_driver::registry::DialectRegistry::iter(&self) -> impl core::iter::traits::iterator::Iterator<Item = &'static vyre_foundation::dialect_lookup::OpDef> + '_
pub fn vyre_driver::registry::DialectRegistry::lookup(&self, id: vyre_foundation::dialect_lookup::InternedOpId) -> core::option::Option<&'static vyre_foundation::dialect_lookup::OpDef>
pub fn vyre_driver::registry::DialectRegistry::validate_no_duplicates<'a>(defs: impl core::iter::traits::collect::IntoIterator<Item = &'a vyre_foundation::dialect_lookup::OpDef>) -> core::result::Result<(), vyre_driver::registry::DuplicateOpIdError>
impl vyre_foundation::dialect_lookup::DialectLookup for vyre_driver::registry::DialectRegistry
pub fn vyre_driver::registry::DialectRegistry::intern_op(&self, name: &str) -> vyre_foundation::dialect_lookup::InternedOpId
pub fn vyre_driver::registry::DialectRegistry::lookup(&self, id: vyre_foundation::dialect_lookup::InternedOpId) -> core::option::Option<&'static vyre_foundation::dialect_lookup::OpDef>
impl core::marker::Freeze for vyre_driver::registry::DialectRegistry
impl core::marker::Send for vyre_driver::registry::DialectRegistry
impl core::marker::Sync for vyre_driver::registry::DialectRegistry
impl core::marker::Unpin for vyre_driver::registry::DialectRegistry
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::DialectRegistry
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::DialectRegistry
impl<T, U> core::convert::Into<U> for vyre_driver::registry::DialectRegistry where U: core::convert::From<T>
pub fn vyre_driver::registry::DialectRegistry::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::DialectRegistry where U: core::convert::Into<T>
pub type vyre_driver::registry::DialectRegistry::Error = core::convert::Infallible
pub fn vyre_driver::registry::DialectRegistry::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::DialectRegistry where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::DialectRegistry::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::DialectRegistry::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::DialectRegistry where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistry::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::DialectRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistry::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::DialectRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistry::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::DialectRegistry
pub fn vyre_driver::registry::DialectRegistry::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::DialectRegistry
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::DialectRegistry
pub struct vyre_driver::registry::DuplicateOpIdError
impl vyre_driver::registry::DuplicateOpIdError
pub const fn vyre_driver::registry::DuplicateOpIdError::op_id(&self) -> &'static str
impl core::clone::Clone for vyre_driver::registry::DuplicateOpIdError
pub fn vyre_driver::registry::DuplicateOpIdError::clone(&self) -> vyre_driver::registry::DuplicateOpIdError
impl core::cmp::Eq for vyre_driver::registry::DuplicateOpIdError
impl core::cmp::PartialEq for vyre_driver::registry::DuplicateOpIdError
pub fn vyre_driver::registry::DuplicateOpIdError::eq(&self, other: &vyre_driver::registry::DuplicateOpIdError) -> bool
impl core::error::Error for vyre_driver::registry::DuplicateOpIdError
impl core::fmt::Debug for vyre_driver::registry::DuplicateOpIdError
pub fn vyre_driver::registry::DuplicateOpIdError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::registry::DuplicateOpIdError
pub fn vyre_driver::registry::DuplicateOpIdError::fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::DuplicateOpIdError
impl core::marker::Freeze for vyre_driver::registry::DuplicateOpIdError
impl core::marker::Send for vyre_driver::registry::DuplicateOpIdError
impl core::marker::Sync for vyre_driver::registry::DuplicateOpIdError
impl core::marker::Unpin for vyre_driver::registry::DuplicateOpIdError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::DuplicateOpIdError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::DuplicateOpIdError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::DuplicateOpIdError where U: core::convert::From<T>
pub fn vyre_driver::registry::DuplicateOpIdError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::DuplicateOpIdError where U: core::convert::Into<T>
pub type vyre_driver::registry::DuplicateOpIdError::Error = core::convert::Infallible
pub fn vyre_driver::registry::DuplicateOpIdError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::DuplicateOpIdError where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::DuplicateOpIdError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::DuplicateOpIdError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::DuplicateOpIdError where T: core::clone::Clone
pub type vyre_driver::registry::DuplicateOpIdError::Owned = T
pub fn vyre_driver::registry::DuplicateOpIdError::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::DuplicateOpIdError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::registry::DuplicateOpIdError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::registry::DuplicateOpIdError where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::DuplicateOpIdError where T: ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::DuplicateOpIdError where T: ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::DuplicateOpIdError where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::DuplicateOpIdError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::DuplicateOpIdError
pub fn vyre_driver::registry::DuplicateOpIdError::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::DuplicateOpIdError
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::DuplicateOpIdError
pub struct vyre_driver::registry::Migration
pub vyre_driver::registry::Migration::from: (&'static str, vyre_driver::registry::Semver)
pub vyre_driver::registry::Migration::rewrite: fn(&mut vyre_driver::registry::AttrMap) -> core::result::Result<(), vyre_driver::registry::MigrationError>
pub vyre_driver::registry::Migration::to: (&'static str, vyre_driver::registry::Semver)
impl vyre_driver::registry::Migration
pub const fn vyre_driver::registry::Migration::new(from: (&'static str, vyre_driver::registry::Semver), to: (&'static str, vyre_driver::registry::Semver), rewrite: fn(&mut vyre_driver::registry::AttrMap) -> core::result::Result<(), vyre_driver::registry::MigrationError>) -> Self
impl inventory::Collect for vyre_driver::registry::Migration
impl core::marker::Freeze for vyre_driver::registry::Migration
impl core::marker::Send for vyre_driver::registry::Migration
impl core::marker::Sync for vyre_driver::registry::Migration
impl core::marker::Unpin for vyre_driver::registry::Migration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::Migration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::Migration
impl<T, U> core::convert::Into<U> for vyre_driver::registry::Migration where U: core::convert::From<T>
pub fn vyre_driver::registry::Migration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::Migration where U: core::convert::Into<T>
pub type vyre_driver::registry::Migration::Error = core::convert::Infallible
pub fn vyre_driver::registry::Migration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::Migration where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::Migration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::Migration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::Migration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::Migration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::Migration where T: ?core::marker::Sized
pub fn vyre_driver::registry::Migration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::Migration where T: ?core::marker::Sized
pub fn vyre_driver::registry::Migration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::Migration
pub fn vyre_driver::registry::Migration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::Migration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::Migration
pub struct vyre_driver::registry::MigrationRegistry
impl vyre_driver::registry::MigrationRegistry
pub fn vyre_driver::registry::MigrationRegistry::apply_chain(&self, op_id: &'static str, from: vyre_driver::registry::Semver, attrs: &mut vyre_driver::registry::AttrMap) -> core::result::Result<(&'static str, vyre_driver::registry::Semver), vyre_driver::registry::MigrationError>
pub fn vyre_driver::registry::MigrationRegistry::deprecation(&self, op_id: &str) -> core::option::Option<&'static vyre_driver::registry::Deprecation>
pub fn vyre_driver::registry::MigrationRegistry::global() -> &'static vyre_driver::registry::MigrationRegistry
pub fn vyre_driver::registry::MigrationRegistry::lookup(&self, op_id: &str, from: vyre_driver::registry::Semver) -> core::option::Option<&'static vyre_driver::registry::Migration>
impl core::marker::Freeze for vyre_driver::registry::MigrationRegistry
impl core::marker::Send for vyre_driver::registry::MigrationRegistry
impl core::marker::Sync for vyre_driver::registry::MigrationRegistry
impl core::marker::Unpin for vyre_driver::registry::MigrationRegistry
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::MigrationRegistry
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::MigrationRegistry
impl<T, U> core::convert::Into<U> for vyre_driver::registry::MigrationRegistry where U: core::convert::From<T>
pub fn vyre_driver::registry::MigrationRegistry::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::MigrationRegistry where U: core::convert::Into<T>
pub type vyre_driver::registry::MigrationRegistry::Error = core::convert::Infallible
pub fn vyre_driver::registry::MigrationRegistry::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::MigrationRegistry where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::MigrationRegistry::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::MigrationRegistry::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::MigrationRegistry where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::MigrationRegistry::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::MigrationRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::MigrationRegistry::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::MigrationRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::MigrationRegistry::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::MigrationRegistry
pub fn vyre_driver::registry::MigrationRegistry::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::MigrationRegistry
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::MigrationRegistry
pub struct vyre_driver::registry::OpBackendTarget
pub vyre_driver::registry::OpBackendTarget::op: &'static str
pub vyre_driver::registry::OpBackendTarget::target: &'static str
impl inventory::Collect for vyre_driver::registry::OpBackendTarget
impl core::marker::Freeze for vyre_driver::registry::OpBackendTarget
impl core::marker::Send for vyre_driver::registry::OpBackendTarget
impl core::marker::Sync for vyre_driver::registry::OpBackendTarget
impl core::marker::Unpin for vyre_driver::registry::OpBackendTarget
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::OpBackendTarget
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::OpBackendTarget
impl<T, U> core::convert::Into<U> for vyre_driver::registry::OpBackendTarget where U: core::convert::From<T>
pub fn vyre_driver::registry::OpBackendTarget::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::OpBackendTarget where U: core::convert::Into<T>
pub type vyre_driver::registry::OpBackendTarget::Error = core::convert::Infallible
pub fn vyre_driver::registry::OpBackendTarget::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::OpBackendTarget where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::OpBackendTarget::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::OpBackendTarget::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::OpBackendTarget where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::OpBackendTarget::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::OpBackendTarget where T: ?core::marker::Sized
pub fn vyre_driver::registry::OpBackendTarget::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::OpBackendTarget where T: ?core::marker::Sized
pub fn vyre_driver::registry::OpBackendTarget::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::OpBackendTarget
pub fn vyre_driver::registry::OpBackendTarget::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::OpBackendTarget
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::OpBackendTarget
pub struct vyre_driver::registry::OpDefRegistration
pub vyre_driver::registry::OpDefRegistration::op: fn() -> vyre_foundation::dialect_lookup::OpDef
impl vyre_driver::registry::OpDefRegistration
pub const fn vyre_driver::registry::OpDefRegistration::new(op: fn() -> vyre_foundation::dialect_lookup::OpDef) -> Self
impl inventory::Collect for vyre_driver::registry::OpDefRegistration
impl core::marker::Freeze for vyre_driver::registry::OpDefRegistration
impl core::marker::Send for vyre_driver::registry::OpDefRegistration
impl core::marker::Sync for vyre_driver::registry::OpDefRegistration
impl core::marker::Unpin for vyre_driver::registry::OpDefRegistration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::OpDefRegistration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::OpDefRegistration
impl<T, U> core::convert::Into<U> for vyre_driver::registry::OpDefRegistration where U: core::convert::From<T>
pub fn vyre_driver::registry::OpDefRegistration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::OpDefRegistration where U: core::convert::Into<T>
pub type vyre_driver::registry::OpDefRegistration::Error = core::convert::Infallible
pub fn vyre_driver::registry::OpDefRegistration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::OpDefRegistration where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::OpDefRegistration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::OpDefRegistration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::OpDefRegistration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::OpDefRegistration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::OpDefRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::OpDefRegistration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::OpDefRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::OpDefRegistration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::OpDefRegistration
pub fn vyre_driver::registry::OpDefRegistration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::OpDefRegistration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::OpDefRegistration
pub struct vyre_driver::registry::OpManifest
pub vyre_driver::registry::OpManifest::category: alloc::string::String
pub vyre_driver::registry::OpManifest::id: alloc::string::String
pub vyre_driver::registry::OpManifest::inputs: alloc::vec::Vec<(alloc::string::String, alloc::string::String)>
pub vyre_driver::registry::OpManifest::laws: alloc::vec::Vec<alloc::string::String>
pub vyre_driver::registry::OpManifest::outputs: alloc::vec::Vec<(alloc::string::String, alloc::string::String)>
pub vyre_driver::registry::OpManifest::summary: core::option::Option<alloc::string::String>
impl core::clone::Clone for vyre_driver::registry::OpManifest
pub fn vyre_driver::registry::OpManifest::clone(&self) -> vyre_driver::registry::OpManifest
impl core::cmp::PartialEq for vyre_driver::registry::OpManifest
pub fn vyre_driver::registry::OpManifest::eq(&self, other: &vyre_driver::registry::OpManifest) -> bool
impl core::fmt::Debug for vyre_driver::registry::OpManifest
pub fn vyre_driver::registry::OpManifest::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::OpManifest
impl serde_core::ser::Serialize for vyre_driver::registry::OpManifest
pub fn vyre_driver::registry::OpManifest::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::registry::OpManifest
pub fn vyre_driver::registry::OpManifest::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::registry::OpManifest
impl core::marker::Send for vyre_driver::registry::OpManifest
impl core::marker::Sync for vyre_driver::registry::OpManifest
impl core::marker::Unpin for vyre_driver::registry::OpManifest
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::OpManifest
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::OpManifest
impl<T, U> core::convert::Into<U> for vyre_driver::registry::OpManifest where U: core::convert::From<T>
pub fn vyre_driver::registry::OpManifest::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::OpManifest where U: core::convert::Into<T>
pub type vyre_driver::registry::OpManifest::Error = core::convert::Infallible
pub fn vyre_driver::registry::OpManifest::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::OpManifest where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::OpManifest::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::OpManifest::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::OpManifest where T: core::clone::Clone
pub type vyre_driver::registry::OpManifest::Owned = T
pub fn vyre_driver::registry::OpManifest::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::OpManifest::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::OpManifest where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::OpManifest::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::OpManifest where T: ?core::marker::Sized
pub fn vyre_driver::registry::OpManifest::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::OpManifest where T: ?core::marker::Sized
pub fn vyre_driver::registry::OpManifest::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::OpManifest where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::OpManifest::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::OpManifest
pub fn vyre_driver::registry::OpManifest::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::registry::OpManifest where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::registry::OpManifest
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::OpManifest
pub struct vyre_driver::registry::Semver
pub vyre_driver::registry::Semver::major: u32
pub vyre_driver::registry::Semver::minor: u32
pub vyre_driver::registry::Semver::patch: u32
impl vyre_driver::registry::Semver
pub const fn vyre_driver::registry::Semver::new(major: u32, minor: u32, patch: u32) -> Self
impl core::clone::Clone for vyre_driver::registry::Semver
pub fn vyre_driver::registry::Semver::clone(&self) -> vyre_driver::registry::Semver
impl core::cmp::Eq for vyre_driver::registry::Semver
impl core::cmp::Ord for vyre_driver::registry::Semver
pub fn vyre_driver::registry::Semver::cmp(&self, other: &vyre_driver::registry::Semver) -> core::cmp::Ordering
impl core::cmp::PartialEq for vyre_driver::registry::Semver
pub fn vyre_driver::registry::Semver::eq(&self, other: &vyre_driver::registry::Semver) -> bool
impl core::cmp::PartialOrd for vyre_driver::registry::Semver
pub fn vyre_driver::registry::Semver::partial_cmp(&self, other: &vyre_driver::registry::Semver) -> core::option::Option<core::cmp::Ordering>
impl core::fmt::Debug for vyre_driver::registry::Semver
pub fn vyre_driver::registry::Semver::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::registry::Semver
pub fn vyre_driver::registry::Semver::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::registry::Semver
pub fn vyre_driver::registry::Semver::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::registry::Semver
impl core::marker::StructuralPartialEq for vyre_driver::registry::Semver
impl core::marker::Freeze for vyre_driver::registry::Semver
impl core::marker::Send for vyre_driver::registry::Semver
impl core::marker::Sync for vyre_driver::registry::Semver
impl core::marker::Unpin for vyre_driver::registry::Semver
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::Semver
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::Semver
impl<Q, K> equivalent::Comparable<K> for vyre_driver::registry::Semver where Q: core::cmp::Ord + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::Semver::compare(&self, key: &K) -> core::cmp::Ordering
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::Semver where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::Semver::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::Semver where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::Semver where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::Semver::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::Semver::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::Semver where U: core::convert::From<T>
pub fn vyre_driver::registry::Semver::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::Semver where U: core::convert::Into<T>
pub type vyre_driver::registry::Semver::Error = core::convert::Infallible
pub fn vyre_driver::registry::Semver::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::Semver where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::Semver::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::Semver::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::Semver where T: core::clone::Clone
pub type vyre_driver::registry::Semver::Owned = T
pub fn vyre_driver::registry::Semver::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::Semver::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::registry::Semver where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::registry::Semver::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::registry::Semver where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::Semver::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::Semver where T: ?core::marker::Sized
pub fn vyre_driver::registry::Semver::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::Semver where T: ?core::marker::Sized
pub fn vyre_driver::registry::Semver::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::Semver where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::Semver::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::Semver
pub fn vyre_driver::registry::Semver::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::Semver
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::Semver
pub struct vyre_driver::registry::TomlDialectStore
impl vyre_driver::registry::TomlDialectStore
pub fn vyre_driver::registry::TomlDialectStore::contains_op(&self, op_id: &str) -> bool
pub fn vyre_driver::registry::TomlDialectStore::diagnostics(&self) -> &[vyre_driver::Diagnostic]
pub fn vyre_driver::registry::TomlDialectStore::dialect(&self, id: &str) -> core::option::Option<&vyre_driver::registry::DialectManifest>
pub fn vyre_driver::registry::TomlDialectStore::from_env() -> Self
pub fn vyre_driver::registry::TomlDialectStore::load_file(&mut self, path: &std::path::Path)
pub fn vyre_driver::registry::TomlDialectStore::manifests(&self) -> alloc::vec::Vec<&vyre_driver::registry::DialectManifest>
pub fn vyre_driver::registry::TomlDialectStore::ops_in(&self, dialect: &str) -> &[vyre_driver::registry::OpManifest]
pub fn vyre_driver::registry::TomlDialectStore::scan_dir(&mut self, dir: &std::path::Path)
impl core::clone::Clone for vyre_driver::registry::TomlDialectStore
pub fn vyre_driver::registry::TomlDialectStore::clone(&self) -> vyre_driver::registry::TomlDialectStore
impl core::default::Default for vyre_driver::registry::TomlDialectStore
pub fn vyre_driver::registry::TomlDialectStore::default() -> vyre_driver::registry::TomlDialectStore
impl core::fmt::Debug for vyre_driver::registry::TomlDialectStore
pub fn vyre_driver::registry::TomlDialectStore::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::registry::TomlDialectStore
impl core::marker::Send for vyre_driver::registry::TomlDialectStore
impl core::marker::Sync for vyre_driver::registry::TomlDialectStore
impl core::marker::Unpin for vyre_driver::registry::TomlDialectStore
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::TomlDialectStore
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::TomlDialectStore
impl<T, U> core::convert::Into<U> for vyre_driver::registry::TomlDialectStore where U: core::convert::From<T>
pub fn vyre_driver::registry::TomlDialectStore::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::TomlDialectStore where U: core::convert::Into<T>
pub type vyre_driver::registry::TomlDialectStore::Error = core::convert::Infallible
pub fn vyre_driver::registry::TomlDialectStore::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::TomlDialectStore where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::TomlDialectStore::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::TomlDialectStore::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::TomlDialectStore where T: core::clone::Clone
pub type vyre_driver::registry::TomlDialectStore::Owned = T
pub fn vyre_driver::registry::TomlDialectStore::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::TomlDialectStore::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::TomlDialectStore where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::TomlDialectStore::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::TomlDialectStore where T: ?core::marker::Sized
pub fn vyre_driver::registry::TomlDialectStore::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::TomlDialectStore where T: ?core::marker::Sized
pub fn vyre_driver::registry::TomlDialectStore::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::TomlDialectStore where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::TomlDialectStore::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::TomlDialectStore
pub fn vyre_driver::registry::TomlDialectStore::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::TomlDialectStore
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::TomlDialectStore
pub const vyre_driver::registry::CODE_PARSE: vyre_driver::DiagnosticCode
pub const vyre_driver::registry::INDIRECT_DISPATCH_OP_ID: &str
pub trait vyre_driver::registry::EnforceGate: core::marker::Send + core::marker::Sync
pub fn vyre_driver::registry::EnforceGate::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::Program) -> vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::EnforceGate::name(&self) -> &'static str
impl<A: vyre_driver::registry::EnforceGate, B: vyre_driver::registry::EnforceGate> vyre_driver::registry::EnforceGate for vyre_driver::registry::Chain<A, B>
pub fn vyre_driver::registry::Chain<A, B>::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::Program) -> vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::Chain<A, B>::name(&self) -> &'static str
pub fn vyre_driver::registry::default_validator() -> bool
pub fn vyre_driver::registry::deprecation_diagnostic(dep: &vyre_driver::registry::Deprecation) -> vyre_driver::Diagnostic
pub fn vyre_driver::registry::workspace_dialect_fixture_path() -> std::path::PathBuf
pub mod vyre_driver::routing
pub mod vyre_driver::routing::pgo
pub struct vyre_driver::routing::pgo::BackendLatency
pub vyre_driver::routing::pgo::BackendLatency::backend: alloc::string::String
pub vyre_driver::routing::pgo::BackendLatency::latency_ns: u128
impl core::clone::Clone for vyre_driver::pgo::BackendLatency
pub fn vyre_driver::pgo::BackendLatency::clone(&self) -> vyre_driver::pgo::BackendLatency
impl core::cmp::Eq for vyre_driver::pgo::BackendLatency
impl core::cmp::PartialEq for vyre_driver::pgo::BackendLatency
pub fn vyre_driver::pgo::BackendLatency::eq(&self, other: &vyre_driver::pgo::BackendLatency) -> bool
impl core::fmt::Debug for vyre_driver::pgo::BackendLatency
pub fn vyre_driver::pgo::BackendLatency::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::pgo::BackendLatency
impl serde_core::ser::Serialize for vyre_driver::pgo::BackendLatency
pub fn vyre_driver::pgo::BackendLatency::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::pgo::BackendLatency
pub fn vyre_driver::pgo::BackendLatency::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::pgo::BackendLatency
impl core::marker::Send for vyre_driver::pgo::BackendLatency
impl core::marker::Sync for vyre_driver::pgo::BackendLatency
impl core::marker::Unpin for vyre_driver::pgo::BackendLatency
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::pgo::BackendLatency
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::pgo::BackendLatency
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::pgo::BackendLatency where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pgo::BackendLatency::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pgo::BackendLatency where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pgo::BackendLatency where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pgo::BackendLatency::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::pgo::BackendLatency::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::pgo::BackendLatency where U: core::convert::From<T>
pub fn vyre_driver::pgo::BackendLatency::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::pgo::BackendLatency where U: core::convert::Into<T>
pub type vyre_driver::pgo::BackendLatency::Error = core::convert::Infallible
pub fn vyre_driver::pgo::BackendLatency::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::pgo::BackendLatency where U: core::convert::TryFrom<T>
pub type vyre_driver::pgo::BackendLatency::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::pgo::BackendLatency::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::pgo::BackendLatency where T: core::clone::Clone
pub type vyre_driver::pgo::BackendLatency::Owned = T
pub fn vyre_driver::pgo::BackendLatency::clone_into(&self, target: &mut T)
pub fn vyre_driver::pgo::BackendLatency::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::pgo::BackendLatency where T: 'static + ?core::marker::Sized
pub fn vyre_driver::pgo::BackendLatency::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::pgo::BackendLatency where T: ?core::marker::Sized
pub fn vyre_driver::pgo::BackendLatency::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::pgo::BackendLatency where T: ?core::marker::Sized
pub fn vyre_driver::pgo::BackendLatency::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::pgo::BackendLatency where T: core::clone::Clone
pub unsafe fn vyre_driver::pgo::BackendLatency::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::pgo::BackendLatency
pub fn vyre_driver::pgo::BackendLatency::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::pgo::BackendLatency where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::pgo::BackendLatency
impl<T> tracing::instrument::WithSubscriber for vyre_driver::pgo::BackendLatency
pub struct vyre_driver::routing::pgo::PgoTable
pub vyre_driver::routing::pgo::PgoTable::routes: alloc::collections::btree::map::BTreeMap<alloc::string::String, vyre_driver::pgo::RouteDecision>
impl vyre_driver::pgo::PgoTable
pub fn vyre_driver::pgo::PgoTable::certify_op(&mut self, op_id: impl core::convert::Into<alloc::string::String>, program: &vyre_foundation::ir_inner::model::program::Program, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::backend::DispatchConfig, backends: &[&dyn vyre_driver::backend::VyreBackend]) -> core::result::Result<&vyre_driver::pgo::RouteDecision, vyre_driver::backend::BackendError>
pub fn vyre_driver::pgo::PgoTable::fastest_backend(&self, op_id: &str) -> core::option::Option<&str>
pub fn vyre_driver::pgo::PgoTable::load(path: &std::path::Path) -> core::result::Result<Self, alloc::string::String>
pub fn vyre_driver::pgo::PgoTable::save(&self, path: &std::path::Path) -> core::result::Result<(), alloc::string::String>
impl core::clone::Clone for vyre_driver::pgo::PgoTable
pub fn vyre_driver::pgo::PgoTable::clone(&self) -> vyre_driver::pgo::PgoTable
impl core::cmp::Eq for vyre_driver::pgo::PgoTable
impl core::cmp::PartialEq for vyre_driver::pgo::PgoTable
pub fn vyre_driver::pgo::PgoTable::eq(&self, other: &vyre_driver::pgo::PgoTable) -> bool
impl core::default::Default for vyre_driver::pgo::PgoTable
pub fn vyre_driver::pgo::PgoTable::default() -> vyre_driver::pgo::PgoTable
impl core::fmt::Debug for vyre_driver::pgo::PgoTable
pub fn vyre_driver::pgo::PgoTable::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::pgo::PgoTable
impl serde_core::ser::Serialize for vyre_driver::pgo::PgoTable
pub fn vyre_driver::pgo::PgoTable::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::pgo::PgoTable
pub fn vyre_driver::pgo::PgoTable::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::pgo::PgoTable
impl core::marker::Send for vyre_driver::pgo::PgoTable
impl core::marker::Sync for vyre_driver::pgo::PgoTable
impl core::marker::Unpin for vyre_driver::pgo::PgoTable
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::pgo::PgoTable
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::pgo::PgoTable
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::pgo::PgoTable where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pgo::PgoTable::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pgo::PgoTable where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pgo::PgoTable where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pgo::PgoTable::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::pgo::PgoTable::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::pgo::PgoTable where U: core::convert::From<T>
pub fn vyre_driver::pgo::PgoTable::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::pgo::PgoTable where U: core::convert::Into<T>
pub type vyre_driver::pgo::PgoTable::Error = core::convert::Infallible
pub fn vyre_driver::pgo::PgoTable::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::pgo::PgoTable where U: core::convert::TryFrom<T>
pub type vyre_driver::pgo::PgoTable::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::pgo::PgoTable::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::pgo::PgoTable where T: core::clone::Clone
pub type vyre_driver::pgo::PgoTable::Owned = T
pub fn vyre_driver::pgo::PgoTable::clone_into(&self, target: &mut T)
pub fn vyre_driver::pgo::PgoTable::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::pgo::PgoTable where T: 'static + ?core::marker::Sized
pub fn vyre_driver::pgo::PgoTable::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::pgo::PgoTable where T: ?core::marker::Sized
pub fn vyre_driver::pgo::PgoTable::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::pgo::PgoTable where T: ?core::marker::Sized
pub fn vyre_driver::pgo::PgoTable::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::pgo::PgoTable where T: core::clone::Clone
pub unsafe fn vyre_driver::pgo::PgoTable::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::pgo::PgoTable
pub fn vyre_driver::pgo::PgoTable::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::pgo::PgoTable where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::pgo::PgoTable
impl<T> tracing::instrument::WithSubscriber for vyre_driver::pgo::PgoTable
pub struct vyre_driver::routing::pgo::RouteDecision
pub vyre_driver::routing::pgo::RouteDecision::backend: alloc::string::String
pub vyre_driver::routing::pgo::RouteDecision::observations: alloc::vec::Vec<vyre_driver::pgo::BackendLatency>
impl core::clone::Clone for vyre_driver::pgo::RouteDecision
pub fn vyre_driver::pgo::RouteDecision::clone(&self) -> vyre_driver::pgo::RouteDecision
impl core::cmp::Eq for vyre_driver::pgo::RouteDecision
impl core::cmp::PartialEq for vyre_driver::pgo::RouteDecision
pub fn vyre_driver::pgo::RouteDecision::eq(&self, other: &vyre_driver::pgo::RouteDecision) -> bool
impl core::fmt::Debug for vyre_driver::pgo::RouteDecision
pub fn vyre_driver::pgo::RouteDecision::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::pgo::RouteDecision
impl serde_core::ser::Serialize for vyre_driver::pgo::RouteDecision
pub fn vyre_driver::pgo::RouteDecision::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::pgo::RouteDecision
pub fn vyre_driver::pgo::RouteDecision::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::pgo::RouteDecision
impl core::marker::Send for vyre_driver::pgo::RouteDecision
impl core::marker::Sync for vyre_driver::pgo::RouteDecision
impl core::marker::Unpin for vyre_driver::pgo::RouteDecision
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::pgo::RouteDecision
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::pgo::RouteDecision
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::pgo::RouteDecision where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pgo::RouteDecision::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pgo::RouteDecision where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pgo::RouteDecision where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pgo::RouteDecision::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::pgo::RouteDecision::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::pgo::RouteDecision where U: core::convert::From<T>
pub fn vyre_driver::pgo::RouteDecision::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::pgo::RouteDecision where U: core::convert::Into<T>
pub type vyre_driver::pgo::RouteDecision::Error = core::convert::Infallible
pub fn vyre_driver::pgo::RouteDecision::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::pgo::RouteDecision where U: core::convert::TryFrom<T>
pub type vyre_driver::pgo::RouteDecision::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::pgo::RouteDecision::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::pgo::RouteDecision where T: core::clone::Clone
pub type vyre_driver::pgo::RouteDecision::Owned = T
pub fn vyre_driver::pgo::RouteDecision::clone_into(&self, target: &mut T)
pub fn vyre_driver::pgo::RouteDecision::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::pgo::RouteDecision where T: 'static + ?core::marker::Sized
pub fn vyre_driver::pgo::RouteDecision::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::pgo::RouteDecision where T: ?core::marker::Sized
pub fn vyre_driver::pgo::RouteDecision::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::pgo::RouteDecision where T: ?core::marker::Sized
pub fn vyre_driver::pgo::RouteDecision::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::pgo::RouteDecision where T: core::clone::Clone
pub unsafe fn vyre_driver::pgo::RouteDecision::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::pgo::RouteDecision
pub fn vyre_driver::pgo::RouteDecision::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::pgo::RouteDecision where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::pgo::RouteDecision
impl<T> tracing::instrument::WithSubscriber for vyre_driver::pgo::RouteDecision
pub fn vyre_driver::routing::pgo::default_pgo_path() -> std::path::PathBuf
pub enum vyre_driver::routing::SortBackend
pub vyre_driver::routing::SortBackend::BitonicSort
pub vyre_driver::routing::SortBackend::InsertionSort
pub vyre_driver::routing::SortBackend::RadixSort
impl core::clone::Clone for vyre_driver::SortBackend
pub fn vyre_driver::SortBackend::clone(&self) -> vyre_driver::SortBackend
impl core::cmp::Eq for vyre_driver::SortBackend
impl core::cmp::PartialEq for vyre_driver::SortBackend
pub fn vyre_driver::SortBackend::eq(&self, other: &vyre_driver::SortBackend) -> bool
impl core::fmt::Debug for vyre_driver::SortBackend
pub fn vyre_driver::SortBackend::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::SortBackend
impl core::marker::StructuralPartialEq for vyre_driver::SortBackend
impl core::marker::Freeze for vyre_driver::SortBackend
impl core::marker::Send for vyre_driver::SortBackend
impl core::marker::Sync for vyre_driver::SortBackend
impl core::marker::Unpin for vyre_driver::SortBackend
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::SortBackend
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::SortBackend
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::SortBackend where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::SortBackend::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::SortBackend where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::SortBackend where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::SortBackend::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::SortBackend::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::SortBackend where U: core::convert::From<T>
pub fn vyre_driver::SortBackend::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::SortBackend where U: core::convert::Into<T>
pub type vyre_driver::SortBackend::Error = core::convert::Infallible
pub fn vyre_driver::SortBackend::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::SortBackend where U: core::convert::TryFrom<T>
pub type vyre_driver::SortBackend::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::SortBackend::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::SortBackend where T: core::clone::Clone
pub type vyre_driver::SortBackend::Owned = T
pub fn vyre_driver::SortBackend::clone_into(&self, target: &mut T)
pub fn vyre_driver::SortBackend::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::SortBackend where T: 'static + ?core::marker::Sized
pub fn vyre_driver::SortBackend::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::SortBackend where T: ?core::marker::Sized
pub fn vyre_driver::SortBackend::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::SortBackend where T: ?core::marker::Sized
pub fn vyre_driver::SortBackend::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::SortBackend where T: core::clone::Clone
pub unsafe fn vyre_driver::SortBackend::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::SortBackend
pub fn vyre_driver::SortBackend::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::SortBackend
impl<T> tracing::instrument::WithSubscriber for vyre_driver::SortBackend
pub struct vyre_driver::routing::Distribution
impl vyre_driver::Distribution
pub fn vyre_driver::Distribution::observe(values: &[u32]) -> Self
impl core::clone::Clone for vyre_driver::Distribution
pub fn vyre_driver::Distribution::clone(&self) -> vyre_driver::Distribution
impl core::cmp::Eq for vyre_driver::Distribution
impl core::cmp::PartialEq for vyre_driver::Distribution
pub fn vyre_driver::Distribution::eq(&self, other: &vyre_driver::Distribution) -> bool
impl core::fmt::Debug for vyre_driver::Distribution
pub fn vyre_driver::Distribution::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::Distribution
impl core::marker::StructuralPartialEq for vyre_driver::Distribution
impl core::marker::Freeze for vyre_driver::Distribution
impl core::marker::Send for vyre_driver::Distribution
impl core::marker::Sync for vyre_driver::Distribution
impl core::marker::Unpin for vyre_driver::Distribution
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::Distribution
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::Distribution
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::Distribution where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::Distribution::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::Distribution where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::Distribution where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::Distribution::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::Distribution::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::Distribution where U: core::convert::From<T>
pub fn vyre_driver::Distribution::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::Distribution where U: core::convert::Into<T>
pub type vyre_driver::Distribution::Error = core::convert::Infallible
pub fn vyre_driver::Distribution::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::Distribution where U: core::convert::TryFrom<T>
pub type vyre_driver::Distribution::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::Distribution::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::Distribution where T: core::clone::Clone
pub type vyre_driver::Distribution::Owned = T
pub fn vyre_driver::Distribution::clone_into(&self, target: &mut T)
pub fn vyre_driver::Distribution::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::Distribution where T: 'static + ?core::marker::Sized
pub fn vyre_driver::Distribution::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::Distribution where T: ?core::marker::Sized
pub fn vyre_driver::Distribution::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::Distribution where T: ?core::marker::Sized
pub fn vyre_driver::Distribution::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::Distribution where T: core::clone::Clone
pub unsafe fn vyre_driver::Distribution::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::Distribution
pub fn vyre_driver::Distribution::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::Distribution
impl<T> tracing::instrument::WithSubscriber for vyre_driver::Distribution
pub struct vyre_driver::routing::RoutingTable
impl vyre_driver::RoutingTable
pub fn vyre_driver::RoutingTable::distribution(&self, call_site: &str) -> core::option::Option<vyre_driver::Distribution>
pub fn vyre_driver::RoutingTable::observe_sort_u32(&self, call_site: alloc::borrow::Cow<'_, str>, values: &[u32]) -> core::result::Result<vyre_driver::SortBackend, alloc::string::String>
impl core::default::Default for vyre_driver::RoutingTable
pub fn vyre_driver::RoutingTable::default() -> vyre_driver::RoutingTable
impl core::fmt::Debug for vyre_driver::RoutingTable
pub fn vyre_driver::RoutingTable::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl !core::marker::Freeze for vyre_driver::RoutingTable
impl core::marker::Send for vyre_driver::RoutingTable
impl core::marker::Sync for vyre_driver::RoutingTable
impl core::marker::Unpin for vyre_driver::RoutingTable
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::RoutingTable
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::RoutingTable
impl<T, U> core::convert::Into<U> for vyre_driver::RoutingTable where U: core::convert::From<T>
pub fn vyre_driver::RoutingTable::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::RoutingTable where U: core::convert::Into<T>
pub type vyre_driver::RoutingTable::Error = core::convert::Infallible
pub fn vyre_driver::RoutingTable::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::RoutingTable where U: core::convert::TryFrom<T>
pub type vyre_driver::RoutingTable::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::RoutingTable::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::RoutingTable where T: 'static + ?core::marker::Sized
pub fn vyre_driver::RoutingTable::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::RoutingTable where T: ?core::marker::Sized
pub fn vyre_driver::RoutingTable::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::RoutingTable where T: ?core::marker::Sized
pub fn vyre_driver::RoutingTable::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::RoutingTable
pub fn vyre_driver::RoutingTable::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::RoutingTable
impl<T> tracing::instrument::WithSubscriber for vyre_driver::RoutingTable
pub fn vyre_driver::routing::select_sort_backend(distribution: vyre_driver::Distribution) -> vyre_driver::SortBackend
#[non_exhaustive] pub enum vyre_driver::BackendError
pub vyre_driver::BackendError::DeviceOutOfMemory
pub vyre_driver::BackendError::DeviceOutOfMemory::available: u64
pub vyre_driver::BackendError::DeviceOutOfMemory::requested: u64
pub vyre_driver::BackendError::DispatchFailed
pub vyre_driver::BackendError::DispatchFailed::code: core::option::Option<i32>
pub vyre_driver::BackendError::DispatchFailed::message: alloc::string::String
pub vyre_driver::BackendError::InvalidProgram
pub vyre_driver::BackendError::InvalidProgram::fix: alloc::string::String
pub vyre_driver::BackendError::Raw(alloc::string::String)
pub vyre_driver::BackendError::KernelCompileFailed
pub vyre_driver::BackendError::KernelCompileFailed::backend: alloc::string::String
pub vyre_driver::BackendError::KernelCompileFailed::compiler_message: alloc::string::String
pub vyre_driver::BackendError::UnsupportedFeature
pub vyre_driver::BackendError::UnsupportedFeature::backend: alloc::string::String
pub vyre_driver::BackendError::UnsupportedFeature::name: alloc::string::String
impl vyre_driver::backend::BackendError
pub fn vyre_driver::backend::BackendError::code(&self) -> vyre_driver::backend::ErrorCode
pub fn vyre_driver::backend::BackendError::into_message(self) -> alloc::string::String
pub fn vyre_driver::backend::BackendError::message(&self) -> alloc::string::String
pub fn vyre_driver::backend::BackendError::new(message: impl core::convert::Into<alloc::string::String>) -> Self
pub fn vyre_driver::backend::BackendError::unsupported_extension(backend: impl core::convert::Into<alloc::string::String>, extension_kind: &str, debug_identity: &str) -> Self
impl core::clone::Clone for vyre_driver::backend::BackendError
pub fn vyre_driver::backend::BackendError::clone(&self) -> vyre_driver::backend::BackendError
impl core::cmp::Eq for vyre_driver::backend::BackendError
impl core::cmp::PartialEq for vyre_driver::backend::BackendError
pub fn vyre_driver::backend::BackendError::eq(&self, other: &vyre_driver::backend::BackendError) -> bool
impl core::convert::From<vyre_foundation::error::Error> for vyre_driver::backend::BackendError
pub fn vyre_driver::backend::BackendError::from(error: vyre_foundation::error::Error) -> Self
impl core::error::Error for vyre_driver::backend::BackendError
impl core::fmt::Debug for vyre_driver::backend::BackendError
pub fn vyre_driver::backend::BackendError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::backend::BackendError
pub fn vyre_driver::backend::BackendError::fmt(&self, __formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::backend::BackendError
impl core::marker::Freeze for vyre_driver::backend::BackendError
impl core::marker::Send for vyre_driver::backend::BackendError
impl core::marker::Sync for vyre_driver::backend::BackendError
impl core::marker::Unpin for vyre_driver::backend::BackendError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::backend::BackendError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::backend::BackendError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::backend::BackendError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::backend::BackendError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::backend::BackendError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::backend::BackendError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::backend::BackendError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::backend::BackendError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::backend::BackendError where U: core::convert::From<T>
pub fn vyre_driver::backend::BackendError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::backend::BackendError where U: core::convert::Into<T>
pub type vyre_driver::backend::BackendError::Error = core::convert::Infallible
pub fn vyre_driver::backend::BackendError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::backend::BackendError where U: core::convert::TryFrom<T>
pub type vyre_driver::backend::BackendError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::backend::BackendError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::backend::BackendError where T: core::clone::Clone
pub type vyre_driver::backend::BackendError::Owned = T
pub fn vyre_driver::backend::BackendError::clone_into(&self, target: &mut T)
pub fn vyre_driver::backend::BackendError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::backend::BackendError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::backend::BackendError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::backend::BackendError where T: 'static + ?core::marker::Sized
pub fn vyre_driver::backend::BackendError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::backend::BackendError where T: ?core::marker::Sized
pub fn vyre_driver::backend::BackendError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::backend::BackendError where T: ?core::marker::Sized
pub fn vyre_driver::backend::BackendError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::backend::BackendError where T: core::clone::Clone
pub unsafe fn vyre_driver::backend::BackendError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::backend::BackendError
pub fn vyre_driver::backend::BackendError::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::backend::BackendError
impl<T> tracing::instrument::WithSubscriber for vyre_driver::backend::BackendError
pub enum vyre_driver::EnforceVerdict
pub vyre_driver::EnforceVerdict::Allow
pub vyre_driver::EnforceVerdict::Deny
pub vyre_driver::EnforceVerdict::Deny::detail: alloc::string::String
pub vyre_driver::EnforceVerdict::Deny::policy: &'static str
impl core::clone::Clone for vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::EnforceVerdict::clone(&self) -> vyre_driver::registry::EnforceVerdict
impl core::cmp::Eq for vyre_driver::registry::EnforceVerdict
impl core::cmp::PartialEq for vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::EnforceVerdict::eq(&self, other: &vyre_driver::registry::EnforceVerdict) -> bool
impl core::fmt::Debug for vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::EnforceVerdict::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::EnforceVerdict
impl core::marker::Freeze for vyre_driver::registry::EnforceVerdict
impl core::marker::Send for vyre_driver::registry::EnforceVerdict
impl core::marker::Sync for vyre_driver::registry::EnforceVerdict
impl core::marker::Unpin for vyre_driver::registry::EnforceVerdict
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::EnforceVerdict
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::EnforceVerdict
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::EnforceVerdict::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::EnforceVerdict::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::EnforceVerdict::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::EnforceVerdict where U: core::convert::From<T>
pub fn vyre_driver::registry::EnforceVerdict::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::EnforceVerdict where U: core::convert::Into<T>
pub type vyre_driver::registry::EnforceVerdict::Error = core::convert::Infallible
pub fn vyre_driver::registry::EnforceVerdict::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::EnforceVerdict where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::EnforceVerdict::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::EnforceVerdict::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::EnforceVerdict where T: core::clone::Clone
pub type vyre_driver::registry::EnforceVerdict::Owned = T
pub fn vyre_driver::registry::EnforceVerdict::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::EnforceVerdict::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::EnforceVerdict where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::EnforceVerdict::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::EnforceVerdict where T: ?core::marker::Sized
pub fn vyre_driver::registry::EnforceVerdict::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::EnforceVerdict where T: ?core::marker::Sized
pub fn vyre_driver::registry::EnforceVerdict::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::EnforceVerdict where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::EnforceVerdict::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::EnforceVerdict::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::EnforceVerdict
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::EnforceVerdict
pub enum vyre_driver::MutationClass
pub vyre_driver::MutationClass::Cosmetic
pub vyre_driver::MutationClass::Lowering
pub vyre_driver::MutationClass::Semantic
pub vyre_driver::MutationClass::Structural
impl vyre_driver::registry::MutationClass
pub const fn vyre_driver::registry::MutationClass::requires_byte_parity(self) -> bool
pub const fn vyre_driver::registry::MutationClass::uses_law_proof(self) -> bool
impl core::clone::Clone for vyre_driver::registry::MutationClass
pub fn vyre_driver::registry::MutationClass::clone(&self) -> vyre_driver::registry::MutationClass
impl core::cmp::Eq for vyre_driver::registry::MutationClass
impl core::cmp::PartialEq for vyre_driver::registry::MutationClass
pub fn vyre_driver::registry::MutationClass::eq(&self, other: &vyre_driver::registry::MutationClass) -> bool
impl core::fmt::Debug for vyre_driver::registry::MutationClass
pub fn vyre_driver::registry::MutationClass::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::registry::MutationClass
pub fn vyre_driver::registry::MutationClass::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::registry::MutationClass
impl core::marker::StructuralPartialEq for vyre_driver::registry::MutationClass
impl core::marker::Freeze for vyre_driver::registry::MutationClass
impl core::marker::Send for vyre_driver::registry::MutationClass
impl core::marker::Sync for vyre_driver::registry::MutationClass
impl core::marker::Unpin for vyre_driver::registry::MutationClass
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::MutationClass
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::MutationClass
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::MutationClass::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::MutationClass::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::MutationClass::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::MutationClass where U: core::convert::From<T>
pub fn vyre_driver::registry::MutationClass::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::MutationClass where U: core::convert::Into<T>
pub type vyre_driver::registry::MutationClass::Error = core::convert::Infallible
pub fn vyre_driver::registry::MutationClass::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::MutationClass where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::MutationClass::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::MutationClass::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::MutationClass where T: core::clone::Clone
pub type vyre_driver::registry::MutationClass::Owned = T
pub fn vyre_driver::registry::MutationClass::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::MutationClass::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::MutationClass where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::MutationClass::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::MutationClass where T: ?core::marker::Sized
pub fn vyre_driver::registry::MutationClass::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::MutationClass where T: ?core::marker::Sized
pub fn vyre_driver::registry::MutationClass::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::MutationClass where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::MutationClass::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::MutationClass
pub fn vyre_driver::registry::MutationClass::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::MutationClass
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::MutationClass
pub enum vyre_driver::Severity
pub vyre_driver::Severity::Error
pub vyre_driver::Severity::Note
pub vyre_driver::Severity::Warning
impl vyre_driver::Severity
pub const fn vyre_driver::Severity::label(self) -> &'static str
impl core::clone::Clone for vyre_driver::Severity
pub fn vyre_driver::Severity::clone(&self) -> vyre_driver::Severity
impl core::cmp::Eq for vyre_driver::Severity
impl core::cmp::PartialEq for vyre_driver::Severity
pub fn vyre_driver::Severity::eq(&self, other: &vyre_driver::Severity) -> bool
impl core::fmt::Debug for vyre_driver::Severity
pub fn vyre_driver::Severity::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::Severity
pub fn vyre_driver::Severity::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::Severity
impl core::marker::StructuralPartialEq for vyre_driver::Severity
impl serde_core::ser::Serialize for vyre_driver::Severity
pub fn vyre_driver::Severity::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::Severity
pub fn vyre_driver::Severity::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::Severity
impl core::marker::Send for vyre_driver::Severity
impl core::marker::Sync for vyre_driver::Severity
impl core::marker::Unpin for vyre_driver::Severity
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::Severity
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::Severity
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::Severity where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::Severity::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::Severity where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::Severity where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::Severity::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::Severity::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::Severity where U: core::convert::From<T>
pub fn vyre_driver::Severity::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::Severity where U: core::convert::Into<T>
pub type vyre_driver::Severity::Error = core::convert::Infallible
pub fn vyre_driver::Severity::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::Severity where U: core::convert::TryFrom<T>
pub type vyre_driver::Severity::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::Severity::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::Severity where T: core::clone::Clone
pub type vyre_driver::Severity::Owned = T
pub fn vyre_driver::Severity::clone_into(&self, target: &mut T)
pub fn vyre_driver::Severity::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::Severity where T: 'static + ?core::marker::Sized
pub fn vyre_driver::Severity::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::Severity where T: ?core::marker::Sized
pub fn vyre_driver::Severity::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::Severity where T: ?core::marker::Sized
pub fn vyre_driver::Severity::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::Severity where T: core::clone::Clone
pub unsafe fn vyre_driver::Severity::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::Severity
pub fn vyre_driver::Severity::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::Severity where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::Severity
impl<T> tracing::instrument::WithSubscriber for vyre_driver::Severity
pub enum vyre_driver::SortBackend
pub vyre_driver::SortBackend::BitonicSort
pub vyre_driver::SortBackend::InsertionSort
pub vyre_driver::SortBackend::RadixSort
impl core::clone::Clone for vyre_driver::SortBackend
pub fn vyre_driver::SortBackend::clone(&self) -> vyre_driver::SortBackend
impl core::cmp::Eq for vyre_driver::SortBackend
impl core::cmp::PartialEq for vyre_driver::SortBackend
pub fn vyre_driver::SortBackend::eq(&self, other: &vyre_driver::SortBackend) -> bool
impl core::fmt::Debug for vyre_driver::SortBackend
pub fn vyre_driver::SortBackend::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::SortBackend
impl core::marker::StructuralPartialEq for vyre_driver::SortBackend
impl core::marker::Freeze for vyre_driver::SortBackend
impl core::marker::Send for vyre_driver::SortBackend
impl core::marker::Sync for vyre_driver::SortBackend
impl core::marker::Unpin for vyre_driver::SortBackend
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::SortBackend
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::SortBackend
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::SortBackend where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::SortBackend::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::SortBackend where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::SortBackend where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::SortBackend::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::SortBackend::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::SortBackend where U: core::convert::From<T>
pub fn vyre_driver::SortBackend::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::SortBackend where U: core::convert::Into<T>
pub type vyre_driver::SortBackend::Error = core::convert::Infallible
pub fn vyre_driver::SortBackend::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::SortBackend where U: core::convert::TryFrom<T>
pub type vyre_driver::SortBackend::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::SortBackend::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::SortBackend where T: core::clone::Clone
pub type vyre_driver::SortBackend::Owned = T
pub fn vyre_driver::SortBackend::clone_into(&self, target: &mut T)
pub fn vyre_driver::SortBackend::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::SortBackend where T: 'static + ?core::marker::Sized
pub fn vyre_driver::SortBackend::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::SortBackend where T: ?core::marker::Sized
pub fn vyre_driver::SortBackend::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::SortBackend where T: ?core::marker::Sized
pub fn vyre_driver::SortBackend::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::SortBackend where T: core::clone::Clone
pub unsafe fn vyre_driver::SortBackend::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::SortBackend
pub fn vyre_driver::SortBackend::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::SortBackend
impl<T> tracing::instrument::WithSubscriber for vyre_driver::SortBackend
#[non_exhaustive] pub enum vyre_driver::Target
pub vyre_driver::Target::CpuRef
pub vyre_driver::Target::Extension(&'static str)
pub vyre_driver::Target::MetalIr
pub vyre_driver::Target::Ptx
pub vyre_driver::Target::Spirv
pub vyre_driver::Target::Wgsl
impl core::clone::Clone for vyre_driver::registry::Target
pub fn vyre_driver::registry::Target::clone(&self) -> vyre_driver::registry::Target
impl core::cmp::Eq for vyre_driver::registry::Target
impl core::cmp::PartialEq for vyre_driver::registry::Target
pub fn vyre_driver::registry::Target::eq(&self, other: &vyre_driver::registry::Target) -> bool
impl core::fmt::Debug for vyre_driver::registry::Target
pub fn vyre_driver::registry::Target::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::registry::Target
pub fn vyre_driver::registry::Target::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::registry::Target
impl core::marker::StructuralPartialEq for vyre_driver::registry::Target
impl core::marker::Freeze for vyre_driver::registry::Target
impl core::marker::Send for vyre_driver::registry::Target
impl core::marker::Sync for vyre_driver::registry::Target
impl core::marker::Unpin for vyre_driver::registry::Target
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::Target
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::Target
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::Target::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::Target::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::Target::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::Target where U: core::convert::From<T>
pub fn vyre_driver::registry::Target::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::Target where U: core::convert::Into<T>
pub type vyre_driver::registry::Target::Error = core::convert::Infallible
pub fn vyre_driver::registry::Target::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::Target where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::Target::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::Target::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::Target where T: core::clone::Clone
pub type vyre_driver::registry::Target::Owned = T
pub fn vyre_driver::registry::Target::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::Target::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::Target where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::Target::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::Target where T: ?core::marker::Sized
pub fn vyre_driver::registry::Target::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::Target where T: ?core::marker::Sized
pub fn vyre_driver::registry::Target::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::Target where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::Target::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::Target
pub fn vyre_driver::registry::Target::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::Target
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::Target
pub struct vyre_driver::BackendRegistration
pub vyre_driver::BackendRegistration::factory: fn() -> core::result::Result<alloc::boxed::Box<dyn vyre_driver::backend::VyreBackend>, vyre_driver::backend::BackendError>
pub vyre_driver::BackendRegistration::id: &'static str
pub vyre_driver::BackendRegistration::supported_ops: fn() -> &'static std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
impl inventory::Collect for vyre_driver::BackendRegistration
impl core::marker::Freeze for vyre_driver::BackendRegistration
impl core::marker::Send for vyre_driver::BackendRegistration
impl core::marker::Sync for vyre_driver::BackendRegistration
impl core::marker::Unpin for vyre_driver::BackendRegistration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::BackendRegistration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::BackendRegistration
impl<T, U> core::convert::Into<U> for vyre_driver::BackendRegistration where U: core::convert::From<T>
pub fn vyre_driver::BackendRegistration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::BackendRegistration where U: core::convert::Into<T>
pub type vyre_driver::BackendRegistration::Error = core::convert::Infallible
pub fn vyre_driver::BackendRegistration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::BackendRegistration where U: core::convert::TryFrom<T>
pub type vyre_driver::BackendRegistration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::BackendRegistration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::BackendRegistration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::BackendRegistration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::BackendRegistration where T: ?core::marker::Sized
pub fn vyre_driver::BackendRegistration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::BackendRegistration where T: ?core::marker::Sized
pub fn vyre_driver::BackendRegistration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::BackendRegistration
pub fn vyre_driver::BackendRegistration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::BackendRegistration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::BackendRegistration
pub struct vyre_driver::Chain<A, B>
impl<A: vyre_driver::registry::EnforceGate, B: vyre_driver::registry::EnforceGate> vyre_driver::registry::Chain<A, B>
pub fn vyre_driver::registry::Chain<A, B>::new(first: A, second: B) -> Self
impl<A: vyre_driver::registry::EnforceGate, B: vyre_driver::registry::EnforceGate> vyre_driver::registry::EnforceGate for vyre_driver::registry::Chain<A, B>
pub fn vyre_driver::registry::Chain<A, B>::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::Program) -> vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::Chain<A, B>::name(&self) -> &'static str
impl<A, B> core::marker::Freeze for vyre_driver::registry::Chain<A, B> where A: core::marker::Freeze, B: core::marker::Freeze
impl<A, B> core::marker::Send for vyre_driver::registry::Chain<A, B> where A: core::marker::Send, B: core::marker::Send
impl<A, B> core::marker::Sync for vyre_driver::registry::Chain<A, B> where A: core::marker::Sync, B: core::marker::Sync
impl<A, B> core::marker::Unpin for vyre_driver::registry::Chain<A, B> where A: core::marker::Unpin, B: core::marker::Unpin
impl<A, B> core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::Chain<A, B> where A: core::panic::unwind_safe::RefUnwindSafe, B: core::panic::unwind_safe::RefUnwindSafe
impl<A, B> core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::Chain<A, B> where A: core::panic::unwind_safe::UnwindSafe, B: core::panic::unwind_safe::UnwindSafe
impl<T, U> core::convert::Into<U> for vyre_driver::registry::Chain<A, B> where U: core::convert::From<T>
pub fn vyre_driver::registry::Chain<A, B>::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::Chain<A, B> where U: core::convert::Into<T>
pub type vyre_driver::registry::Chain<A, B>::Error = core::convert::Infallible
pub fn vyre_driver::registry::Chain<A, B>::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::Chain<A, B> where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::Chain<A, B>::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::Chain<A, B>::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::Chain<A, B> where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::Chain<A, B>::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::Chain<A, B> where T: ?core::marker::Sized
pub fn vyre_driver::registry::Chain<A, B>::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::Chain<A, B> where T: ?core::marker::Sized
pub fn vyre_driver::registry::Chain<A, B>::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::Chain<A, B>
pub fn vyre_driver::registry::Chain<A, B>::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::Chain<A, B>
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::Chain<A, B>
pub struct vyre_driver::Diagnostic
pub vyre_driver::Diagnostic::code: vyre_driver::DiagnosticCode
pub vyre_driver::Diagnostic::doc_url: core::option::Option<alloc::borrow::Cow<'static, str>>
pub vyre_driver::Diagnostic::location: core::option::Option<vyre_driver::OpLocation>
pub vyre_driver::Diagnostic::message: alloc::borrow::Cow<'static, str>
pub vyre_driver::Diagnostic::severity: vyre_driver::Severity
pub vyre_driver::Diagnostic::suggested_fix: core::option::Option<alloc::borrow::Cow<'static, str>>
impl vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::error(code: &'static str, message: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::Diagnostic::note(code: &'static str, message: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::Diagnostic::render_human(&self) -> alloc::string::String
pub fn vyre_driver::Diagnostic::to_json(&self) -> alloc::string::String
pub fn vyre_driver::Diagnostic::warning(code: &'static str, message: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::Diagnostic::with_doc_url(self, url: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::Diagnostic::with_fix(self, fix: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::Diagnostic::with_location(self, loc: vyre_driver::OpLocation) -> Self
impl core::clone::Clone for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::clone(&self) -> vyre_driver::Diagnostic
impl core::cmp::Eq for vyre_driver::Diagnostic
impl core::cmp::PartialEq for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::eq(&self, other: &vyre_driver::Diagnostic) -> bool
impl core::convert::From<&vyre_foundation::error::Error> for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::from(err: &vyre_foundation::error::Error) -> Self
impl core::convert::From<vyre_foundation::error::Error> for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::from(err: vyre_foundation::error::Error) -> Self
impl core::fmt::Debug for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::Diagnostic
impl serde_core::ser::Serialize for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::Diagnostic
impl core::marker::Send for vyre_driver::Diagnostic
impl core::marker::Sync for vyre_driver::Diagnostic
impl core::marker::Unpin for vyre_driver::Diagnostic
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::Diagnostic
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::Diagnostic
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::Diagnostic where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::Diagnostic::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::Diagnostic where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::Diagnostic where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::Diagnostic::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::Diagnostic::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::Diagnostic where U: core::convert::From<T>
pub fn vyre_driver::Diagnostic::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::Diagnostic where U: core::convert::Into<T>
pub type vyre_driver::Diagnostic::Error = core::convert::Infallible
pub fn vyre_driver::Diagnostic::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::Diagnostic where U: core::convert::TryFrom<T>
pub type vyre_driver::Diagnostic::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::Diagnostic::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::Diagnostic where T: core::clone::Clone
pub type vyre_driver::Diagnostic::Owned = T
pub fn vyre_driver::Diagnostic::clone_into(&self, target: &mut T)
pub fn vyre_driver::Diagnostic::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::Diagnostic where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::Diagnostic::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::Diagnostic where T: 'static + ?core::marker::Sized
pub fn vyre_driver::Diagnostic::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::Diagnostic where T: ?core::marker::Sized
pub fn vyre_driver::Diagnostic::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::Diagnostic where T: ?core::marker::Sized
pub fn vyre_driver::Diagnostic::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::Diagnostic where T: core::clone::Clone
pub unsafe fn vyre_driver::Diagnostic::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::Diagnostic
pub fn vyre_driver::Diagnostic::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::Diagnostic where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::Diagnostic
impl<T> tracing::instrument::WithSubscriber for vyre_driver::Diagnostic
pub struct vyre_driver::DiagnosticCode(pub alloc::borrow::Cow<'static, str>)
impl vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::as_str(&self) -> &str
pub const fn vyre_driver::DiagnosticCode::new(code: &'static str) -> Self
impl core::clone::Clone for vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::clone(&self) -> vyre_driver::DiagnosticCode
impl core::cmp::Eq for vyre_driver::DiagnosticCode
impl core::cmp::PartialEq for vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::eq(&self, other: &vyre_driver::DiagnosticCode) -> bool
impl core::fmt::Debug for vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::StructuralPartialEq for vyre_driver::DiagnosticCode
impl serde_core::ser::Serialize for vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::DiagnosticCode
impl core::marker::Send for vyre_driver::DiagnosticCode
impl core::marker::Sync for vyre_driver::DiagnosticCode
impl core::marker::Unpin for vyre_driver::DiagnosticCode
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::DiagnosticCode
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::DiagnosticCode
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::DiagnosticCode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::DiagnosticCode::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::DiagnosticCode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::DiagnosticCode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::DiagnosticCode::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::DiagnosticCode::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::DiagnosticCode where U: core::convert::From<T>
pub fn vyre_driver::DiagnosticCode::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::DiagnosticCode where U: core::convert::Into<T>
pub type vyre_driver::DiagnosticCode::Error = core::convert::Infallible
pub fn vyre_driver::DiagnosticCode::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::DiagnosticCode where U: core::convert::TryFrom<T>
pub type vyre_driver::DiagnosticCode::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::DiagnosticCode::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::DiagnosticCode where T: core::clone::Clone
pub type vyre_driver::DiagnosticCode::Owned = T
pub fn vyre_driver::DiagnosticCode::clone_into(&self, target: &mut T)
pub fn vyre_driver::DiagnosticCode::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::DiagnosticCode where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::DiagnosticCode::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::DiagnosticCode where T: 'static + ?core::marker::Sized
pub fn vyre_driver::DiagnosticCode::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::DiagnosticCode where T: ?core::marker::Sized
pub fn vyre_driver::DiagnosticCode::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::DiagnosticCode where T: ?core::marker::Sized
pub fn vyre_driver::DiagnosticCode::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::DiagnosticCode where T: core::clone::Clone
pub unsafe fn vyre_driver::DiagnosticCode::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::DiagnosticCode
pub fn vyre_driver::DiagnosticCode::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::DiagnosticCode where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::DiagnosticCode
impl<T> tracing::instrument::WithSubscriber for vyre_driver::DiagnosticCode
pub struct vyre_driver::Dialect
pub vyre_driver::Dialect::backends_required: &'static [vyre_spec::intrinsic_descriptor::Backend]
pub vyre_driver::Dialect::id: &'static str
pub vyre_driver::Dialect::ops: &'static [&'static str]
pub vyre_driver::Dialect::parent: core::option::Option<&'static str>
pub vyre_driver::Dialect::validator: fn() -> bool
pub vyre_driver::Dialect::version: u32
impl core::marker::Freeze for vyre_driver::registry::Dialect
impl core::marker::Send for vyre_driver::registry::Dialect
impl core::marker::Sync for vyre_driver::registry::Dialect
impl core::marker::Unpin for vyre_driver::registry::Dialect
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::Dialect
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::Dialect
impl<T, U> core::convert::Into<U> for vyre_driver::registry::Dialect where U: core::convert::From<T>
pub fn vyre_driver::registry::Dialect::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::Dialect where U: core::convert::Into<T>
pub type vyre_driver::registry::Dialect::Error = core::convert::Infallible
pub fn vyre_driver::registry::Dialect::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::Dialect where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::Dialect::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::Dialect::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::Dialect where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::Dialect::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::Dialect where T: ?core::marker::Sized
pub fn vyre_driver::registry::Dialect::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::Dialect where T: ?core::marker::Sized
pub fn vyre_driver::registry::Dialect::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::Dialect
pub fn vyre_driver::registry::Dialect::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::Dialect
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::Dialect
pub struct vyre_driver::DialectRegistration
pub vyre_driver::DialectRegistration::dialect: fn() -> vyre_driver::registry::Dialect
impl inventory::Collect for vyre_driver::registry::DialectRegistration
impl core::marker::Freeze for vyre_driver::registry::DialectRegistration
impl core::marker::Send for vyre_driver::registry::DialectRegistration
impl core::marker::Sync for vyre_driver::registry::DialectRegistration
impl core::marker::Unpin for vyre_driver::registry::DialectRegistration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::DialectRegistration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::DialectRegistration
impl<T, U> core::convert::Into<U> for vyre_driver::registry::DialectRegistration where U: core::convert::From<T>
pub fn vyre_driver::registry::DialectRegistration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::DialectRegistration where U: core::convert::Into<T>
pub type vyre_driver::registry::DialectRegistration::Error = core::convert::Infallible
pub fn vyre_driver::registry::DialectRegistration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::DialectRegistration where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::DialectRegistration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::DialectRegistration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::DialectRegistration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::DialectRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::DialectRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::DialectRegistration
pub fn vyre_driver::registry::DialectRegistration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::DialectRegistration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::DialectRegistration
pub struct vyre_driver::DialectRegistry
impl vyre_driver::registry::DialectRegistry
pub fn vyre_driver::registry::DialectRegistry::get_lowering(&self, id: vyre_foundation::dialect_lookup::InternedOpId, target: vyre_driver::registry::Target) -> core::option::Option<vyre_foundation::dialect_lookup::CpuRef>
pub fn vyre_driver::registry::DialectRegistry::global() -> arc_swap::Guard<alloc::sync::Arc<Self>>
pub fn vyre_driver::registry::DialectRegistry::install(new: Self)
pub fn vyre_driver::registry::DialectRegistry::intern_op(&self, name: &str) -> vyre_foundation::dialect_lookup::InternedOpId
pub fn vyre_driver::registry::DialectRegistry::iter(&self) -> impl core::iter::traits::iterator::Iterator<Item = &'static vyre_foundation::dialect_lookup::OpDef> + '_
pub fn vyre_driver::registry::DialectRegistry::lookup(&self, id: vyre_foundation::dialect_lookup::InternedOpId) -> core::option::Option<&'static vyre_foundation::dialect_lookup::OpDef>
pub fn vyre_driver::registry::DialectRegistry::validate_no_duplicates<'a>(defs: impl core::iter::traits::collect::IntoIterator<Item = &'a vyre_foundation::dialect_lookup::OpDef>) -> core::result::Result<(), vyre_driver::registry::DuplicateOpIdError>
impl vyre_foundation::dialect_lookup::DialectLookup for vyre_driver::registry::DialectRegistry
pub fn vyre_driver::registry::DialectRegistry::intern_op(&self, name: &str) -> vyre_foundation::dialect_lookup::InternedOpId
pub fn vyre_driver::registry::DialectRegistry::lookup(&self, id: vyre_foundation::dialect_lookup::InternedOpId) -> core::option::Option<&'static vyre_foundation::dialect_lookup::OpDef>
impl core::marker::Freeze for vyre_driver::registry::DialectRegistry
impl core::marker::Send for vyre_driver::registry::DialectRegistry
impl core::marker::Sync for vyre_driver::registry::DialectRegistry
impl core::marker::Unpin for vyre_driver::registry::DialectRegistry
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::DialectRegistry
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::DialectRegistry
impl<T, U> core::convert::Into<U> for vyre_driver::registry::DialectRegistry where U: core::convert::From<T>
pub fn vyre_driver::registry::DialectRegistry::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::DialectRegistry where U: core::convert::Into<T>
pub type vyre_driver::registry::DialectRegistry::Error = core::convert::Infallible
pub fn vyre_driver::registry::DialectRegistry::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::DialectRegistry where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::DialectRegistry::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::DialectRegistry::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::DialectRegistry where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistry::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::DialectRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistry::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::DialectRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::DialectRegistry::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::DialectRegistry
pub fn vyre_driver::registry::DialectRegistry::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::DialectRegistry
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::DialectRegistry
#[non_exhaustive] pub struct vyre_driver::DispatchConfig
pub vyre_driver::DispatchConfig::label: core::option::Option<alloc::string::String>
pub vyre_driver::DispatchConfig::max_output_bytes: core::option::Option<usize>
pub vyre_driver::DispatchConfig::profile: core::option::Option<alloc::string::String>
pub vyre_driver::DispatchConfig::timeout: core::option::Option<core::time::Duration>
pub vyre_driver::DispatchConfig::ulp_budget: core::option::Option<u8>
impl core::clone::Clone for vyre_driver::backend::DispatchConfig
pub fn vyre_driver::backend::DispatchConfig::clone(&self) -> vyre_driver::backend::DispatchConfig
impl core::cmp::Eq for vyre_driver::backend::DispatchConfig
impl core::cmp::PartialEq for vyre_driver::backend::DispatchConfig
pub fn vyre_driver::backend::DispatchConfig::eq(&self, other: &vyre_driver::backend::DispatchConfig) -> bool
impl core::default::Default for vyre_driver::backend::DispatchConfig
pub fn vyre_driver::backend::DispatchConfig::default() -> vyre_driver::backend::DispatchConfig
impl core::fmt::Debug for vyre_driver::backend::DispatchConfig
pub fn vyre_driver::backend::DispatchConfig::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::backend::DispatchConfig
impl core::marker::Freeze for vyre_driver::backend::DispatchConfig
impl core::marker::Send for vyre_driver::backend::DispatchConfig
impl core::marker::Sync for vyre_driver::backend::DispatchConfig
impl core::marker::Unpin for vyre_driver::backend::DispatchConfig
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::backend::DispatchConfig
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::backend::DispatchConfig
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::backend::DispatchConfig where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::backend::DispatchConfig::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::backend::DispatchConfig where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::backend::DispatchConfig where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::backend::DispatchConfig::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::backend::DispatchConfig::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::backend::DispatchConfig where U: core::convert::From<T>
pub fn vyre_driver::backend::DispatchConfig::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::backend::DispatchConfig where U: core::convert::Into<T>
pub type vyre_driver::backend::DispatchConfig::Error = core::convert::Infallible
pub fn vyre_driver::backend::DispatchConfig::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::backend::DispatchConfig where U: core::convert::TryFrom<T>
pub type vyre_driver::backend::DispatchConfig::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::backend::DispatchConfig::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::backend::DispatchConfig where T: core::clone::Clone
pub type vyre_driver::backend::DispatchConfig::Owned = T
pub fn vyre_driver::backend::DispatchConfig::clone_into(&self, target: &mut T)
pub fn vyre_driver::backend::DispatchConfig::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::backend::DispatchConfig where T: 'static + ?core::marker::Sized
pub fn vyre_driver::backend::DispatchConfig::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::backend::DispatchConfig where T: ?core::marker::Sized
pub fn vyre_driver::backend::DispatchConfig::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::backend::DispatchConfig where T: ?core::marker::Sized
pub fn vyre_driver::backend::DispatchConfig::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::backend::DispatchConfig where T: core::clone::Clone
pub unsafe fn vyre_driver::backend::DispatchConfig::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::backend::DispatchConfig
pub fn vyre_driver::backend::DispatchConfig::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::backend::DispatchConfig
impl<T> tracing::instrument::WithSubscriber for vyre_driver::backend::DispatchConfig
pub struct vyre_driver::Distribution
impl vyre_driver::Distribution
pub fn vyre_driver::Distribution::observe(values: &[u32]) -> Self
impl core::clone::Clone for vyre_driver::Distribution
pub fn vyre_driver::Distribution::clone(&self) -> vyre_driver::Distribution
impl core::cmp::Eq for vyre_driver::Distribution
impl core::cmp::PartialEq for vyre_driver::Distribution
pub fn vyre_driver::Distribution::eq(&self, other: &vyre_driver::Distribution) -> bool
impl core::fmt::Debug for vyre_driver::Distribution
pub fn vyre_driver::Distribution::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::Distribution
impl core::marker::StructuralPartialEq for vyre_driver::Distribution
impl core::marker::Freeze for vyre_driver::Distribution
impl core::marker::Send for vyre_driver::Distribution
impl core::marker::Sync for vyre_driver::Distribution
impl core::marker::Unpin for vyre_driver::Distribution
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::Distribution
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::Distribution
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::Distribution where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::Distribution::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::Distribution where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::Distribution where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::Distribution::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::Distribution::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::Distribution where U: core::convert::From<T>
pub fn vyre_driver::Distribution::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::Distribution where U: core::convert::Into<T>
pub type vyre_driver::Distribution::Error = core::convert::Infallible
pub fn vyre_driver::Distribution::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::Distribution where U: core::convert::TryFrom<T>
pub type vyre_driver::Distribution::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::Distribution::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::Distribution where T: core::clone::Clone
pub type vyre_driver::Distribution::Owned = T
pub fn vyre_driver::Distribution::clone_into(&self, target: &mut T)
pub fn vyre_driver::Distribution::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::Distribution where T: 'static + ?core::marker::Sized
pub fn vyre_driver::Distribution::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::Distribution where T: ?core::marker::Sized
pub fn vyre_driver::Distribution::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::Distribution where T: ?core::marker::Sized
pub fn vyre_driver::Distribution::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::Distribution where T: core::clone::Clone
pub unsafe fn vyre_driver::Distribution::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::Distribution
pub fn vyre_driver::Distribution::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::Distribution
impl<T> tracing::instrument::WithSubscriber for vyre_driver::Distribution
pub struct vyre_driver::DuplicateOpIdError
impl vyre_driver::registry::DuplicateOpIdError
pub const fn vyre_driver::registry::DuplicateOpIdError::op_id(&self) -> &'static str
impl core::clone::Clone for vyre_driver::registry::DuplicateOpIdError
pub fn vyre_driver::registry::DuplicateOpIdError::clone(&self) -> vyre_driver::registry::DuplicateOpIdError
impl core::cmp::Eq for vyre_driver::registry::DuplicateOpIdError
impl core::cmp::PartialEq for vyre_driver::registry::DuplicateOpIdError
pub fn vyre_driver::registry::DuplicateOpIdError::eq(&self, other: &vyre_driver::registry::DuplicateOpIdError) -> bool
impl core::error::Error for vyre_driver::registry::DuplicateOpIdError
impl core::fmt::Debug for vyre_driver::registry::DuplicateOpIdError
pub fn vyre_driver::registry::DuplicateOpIdError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::registry::DuplicateOpIdError
pub fn vyre_driver::registry::DuplicateOpIdError::fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::DuplicateOpIdError
impl core::marker::Freeze for vyre_driver::registry::DuplicateOpIdError
impl core::marker::Send for vyre_driver::registry::DuplicateOpIdError
impl core::marker::Sync for vyre_driver::registry::DuplicateOpIdError
impl core::marker::Unpin for vyre_driver::registry::DuplicateOpIdError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::DuplicateOpIdError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::DuplicateOpIdError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::DuplicateOpIdError where U: core::convert::From<T>
pub fn vyre_driver::registry::DuplicateOpIdError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::DuplicateOpIdError where U: core::convert::Into<T>
pub type vyre_driver::registry::DuplicateOpIdError::Error = core::convert::Infallible
pub fn vyre_driver::registry::DuplicateOpIdError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::DuplicateOpIdError where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::DuplicateOpIdError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::DuplicateOpIdError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::DuplicateOpIdError where T: core::clone::Clone
pub type vyre_driver::registry::DuplicateOpIdError::Owned = T
pub fn vyre_driver::registry::DuplicateOpIdError::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::DuplicateOpIdError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::registry::DuplicateOpIdError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::registry::DuplicateOpIdError where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::DuplicateOpIdError where T: ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::DuplicateOpIdError where T: ?core::marker::Sized
pub fn vyre_driver::registry::DuplicateOpIdError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::DuplicateOpIdError where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::DuplicateOpIdError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::DuplicateOpIdError
pub fn vyre_driver::registry::DuplicateOpIdError::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::DuplicateOpIdError
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::DuplicateOpIdError
pub struct vyre_driver::OpBackendTarget
pub vyre_driver::OpBackendTarget::op: &'static str
pub vyre_driver::OpBackendTarget::target: &'static str
impl inventory::Collect for vyre_driver::registry::OpBackendTarget
impl core::marker::Freeze for vyre_driver::registry::OpBackendTarget
impl core::marker::Send for vyre_driver::registry::OpBackendTarget
impl core::marker::Sync for vyre_driver::registry::OpBackendTarget
impl core::marker::Unpin for vyre_driver::registry::OpBackendTarget
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::OpBackendTarget
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::OpBackendTarget
impl<T, U> core::convert::Into<U> for vyre_driver::registry::OpBackendTarget where U: core::convert::From<T>
pub fn vyre_driver::registry::OpBackendTarget::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::OpBackendTarget where U: core::convert::Into<T>
pub type vyre_driver::registry::OpBackendTarget::Error = core::convert::Infallible
pub fn vyre_driver::registry::OpBackendTarget::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::OpBackendTarget where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::OpBackendTarget::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::OpBackendTarget::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::OpBackendTarget where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::OpBackendTarget::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::OpBackendTarget where T: ?core::marker::Sized
pub fn vyre_driver::registry::OpBackendTarget::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::OpBackendTarget where T: ?core::marker::Sized
pub fn vyre_driver::registry::OpBackendTarget::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::OpBackendTarget
pub fn vyre_driver::registry::OpBackendTarget::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::OpBackendTarget
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::OpBackendTarget
pub struct vyre_driver::OpDefRegistration
pub vyre_driver::OpDefRegistration::op: fn() -> vyre_foundation::dialect_lookup::OpDef
impl vyre_driver::registry::OpDefRegistration
pub const fn vyre_driver::registry::OpDefRegistration::new(op: fn() -> vyre_foundation::dialect_lookup::OpDef) -> Self
impl inventory::Collect for vyre_driver::registry::OpDefRegistration
impl core::marker::Freeze for vyre_driver::registry::OpDefRegistration
impl core::marker::Send for vyre_driver::registry::OpDefRegistration
impl core::marker::Sync for vyre_driver::registry::OpDefRegistration
impl core::marker::Unpin for vyre_driver::registry::OpDefRegistration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::OpDefRegistration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::OpDefRegistration
impl<T, U> core::convert::Into<U> for vyre_driver::registry::OpDefRegistration where U: core::convert::From<T>
pub fn vyre_driver::registry::OpDefRegistration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::OpDefRegistration where U: core::convert::Into<T>
pub type vyre_driver::registry::OpDefRegistration::Error = core::convert::Infallible
pub fn vyre_driver::registry::OpDefRegistration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::OpDefRegistration where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::OpDefRegistration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::OpDefRegistration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::OpDefRegistration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::OpDefRegistration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::OpDefRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::OpDefRegistration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::OpDefRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::OpDefRegistration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::OpDefRegistration
pub fn vyre_driver::registry::OpDefRegistration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::OpDefRegistration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::OpDefRegistration
pub struct vyre_driver::OpLocation
pub vyre_driver::OpLocation::attr_name: core::option::Option<alloc::borrow::Cow<'static, str>>
pub vyre_driver::OpLocation::op_id: alloc::borrow::Cow<'static, str>
pub vyre_driver::OpLocation::operand_idx: core::option::Option<u32>
impl vyre_driver::OpLocation
pub fn vyre_driver::OpLocation::op(op_id: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::OpLocation::with_attr(self, name: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::OpLocation::with_operand(self, idx: u32) -> Self
impl core::clone::Clone for vyre_driver::OpLocation
pub fn vyre_driver::OpLocation::clone(&self) -> vyre_driver::OpLocation
impl core::cmp::Eq for vyre_driver::OpLocation
impl core::cmp::PartialEq for vyre_driver::OpLocation
pub fn vyre_driver::OpLocation::eq(&self, other: &vyre_driver::OpLocation) -> bool
impl core::fmt::Debug for vyre_driver::OpLocation
pub fn vyre_driver::OpLocation::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::OpLocation
impl serde_core::ser::Serialize for vyre_driver::OpLocation
pub fn vyre_driver::OpLocation::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::OpLocation
pub fn vyre_driver::OpLocation::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::OpLocation
impl core::marker::Send for vyre_driver::OpLocation
impl core::marker::Sync for vyre_driver::OpLocation
impl core::marker::Unpin for vyre_driver::OpLocation
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::OpLocation
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::OpLocation
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::OpLocation where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::OpLocation::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::OpLocation where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::OpLocation where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::OpLocation::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::OpLocation::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::OpLocation where U: core::convert::From<T>
pub fn vyre_driver::OpLocation::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::OpLocation where U: core::convert::Into<T>
pub type vyre_driver::OpLocation::Error = core::convert::Infallible
pub fn vyre_driver::OpLocation::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::OpLocation where U: core::convert::TryFrom<T>
pub type vyre_driver::OpLocation::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::OpLocation::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::OpLocation where T: core::clone::Clone
pub type vyre_driver::OpLocation::Owned = T
pub fn vyre_driver::OpLocation::clone_into(&self, target: &mut T)
pub fn vyre_driver::OpLocation::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::OpLocation where T: 'static + ?core::marker::Sized
pub fn vyre_driver::OpLocation::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::OpLocation where T: ?core::marker::Sized
pub fn vyre_driver::OpLocation::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::OpLocation where T: ?core::marker::Sized
pub fn vyre_driver::OpLocation::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::OpLocation where T: core::clone::Clone
pub unsafe fn vyre_driver::OpLocation::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::OpLocation
pub fn vyre_driver::OpLocation::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::OpLocation where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::OpLocation
impl<T> tracing::instrument::WithSubscriber for vyre_driver::OpLocation
pub struct vyre_driver::PipelineCacheKey
pub vyre_driver::PipelineCacheKey::backend_id: vyre_spec::intrinsic_descriptor::BackendId
pub vyre_driver::PipelineCacheKey::bind_group_layout_hash: [u8; 32]
pub vyre_driver::PipelineCacheKey::feature_flags: vyre_driver::PipelineFeatureFlags
pub vyre_driver::PipelineCacheKey::push_constant_size: u32
pub vyre_driver::PipelineCacheKey::shader_hash: [u8; 32]
pub vyre_driver::PipelineCacheKey::version: u32
pub vyre_driver::PipelineCacheKey::workgroup_size: [u32; 3]
impl vyre_driver::PipelineCacheKey
pub fn vyre_driver::PipelineCacheKey::new(shader_hash: [u8; 32], bind_group_layout_hash: [u8; 32], push_constant_size: u32, workgroup_size: [u32; 3], feature_flags: vyre_driver::PipelineFeatureFlags, backend_id: vyre_spec::intrinsic_descriptor::BackendId) -> Self
impl core::clone::Clone for vyre_driver::PipelineCacheKey
pub fn vyre_driver::PipelineCacheKey::clone(&self) -> vyre_driver::PipelineCacheKey
impl core::cmp::Eq for vyre_driver::PipelineCacheKey
impl core::cmp::PartialEq for vyre_driver::PipelineCacheKey
pub fn vyre_driver::PipelineCacheKey::eq(&self, other: &vyre_driver::PipelineCacheKey) -> bool
impl core::fmt::Debug for vyre_driver::PipelineCacheKey
pub fn vyre_driver::PipelineCacheKey::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::PipelineCacheKey
pub fn vyre_driver::PipelineCacheKey::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::StructuralPartialEq for vyre_driver::PipelineCacheKey
impl core::marker::Freeze for vyre_driver::PipelineCacheKey
impl core::marker::Send for vyre_driver::PipelineCacheKey
impl core::marker::Sync for vyre_driver::PipelineCacheKey
impl core::marker::Unpin for vyre_driver::PipelineCacheKey
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::PipelineCacheKey
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::PipelineCacheKey
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::PipelineCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::PipelineCacheKey::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::PipelineCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::PipelineCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::PipelineCacheKey::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::PipelineCacheKey::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::PipelineCacheKey where U: core::convert::From<T>
pub fn vyre_driver::PipelineCacheKey::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::PipelineCacheKey where U: core::convert::Into<T>
pub type vyre_driver::PipelineCacheKey::Error = core::convert::Infallible
pub fn vyre_driver::PipelineCacheKey::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::PipelineCacheKey where U: core::convert::TryFrom<T>
pub type vyre_driver::PipelineCacheKey::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::PipelineCacheKey::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::PipelineCacheKey where T: core::clone::Clone
pub type vyre_driver::PipelineCacheKey::Owned = T
pub fn vyre_driver::PipelineCacheKey::clone_into(&self, target: &mut T)
pub fn vyre_driver::PipelineCacheKey::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::PipelineCacheKey where T: 'static + ?core::marker::Sized
pub fn vyre_driver::PipelineCacheKey::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::PipelineCacheKey where T: ?core::marker::Sized
pub fn vyre_driver::PipelineCacheKey::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::PipelineCacheKey where T: ?core::marker::Sized
pub fn vyre_driver::PipelineCacheKey::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::PipelineCacheKey where T: core::clone::Clone
pub unsafe fn vyre_driver::PipelineCacheKey::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::PipelineCacheKey
pub fn vyre_driver::PipelineCacheKey::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::PipelineCacheKey
impl<T> tracing::instrument::WithSubscriber for vyre_driver::PipelineCacheKey
pub struct vyre_driver::PipelineFeatureFlags(pub u32)
impl vyre_driver::PipelineFeatureFlags
pub const vyre_driver::PipelineFeatureFlags::ASYNC_COMPUTE: Self
pub const vyre_driver::PipelineFeatureFlags::BF16: Self
pub const vyre_driver::PipelineFeatureFlags::F16: Self
pub const vyre_driver::PipelineFeatureFlags::INDIRECT_DISPATCH: Self
pub const vyre_driver::PipelineFeatureFlags::PUSH_CONSTANTS: Self
pub const vyre_driver::PipelineFeatureFlags::SUBGROUP_OPS: Self
pub const vyre_driver::PipelineFeatureFlags::TENSOR_CORES: Self
pub const fn vyre_driver::PipelineFeatureFlags::bits(self) -> u32
pub const fn vyre_driver::PipelineFeatureFlags::contains(self, other: Self) -> bool
pub const fn vyre_driver::PipelineFeatureFlags::empty() -> Self
pub const fn vyre_driver::PipelineFeatureFlags::union(self, other: Self) -> Self
impl core::clone::Clone for vyre_driver::PipelineFeatureFlags
pub fn vyre_driver::PipelineFeatureFlags::clone(&self) -> vyre_driver::PipelineFeatureFlags
impl core::cmp::Eq for vyre_driver::PipelineFeatureFlags
impl core::cmp::PartialEq for vyre_driver::PipelineFeatureFlags
pub fn vyre_driver::PipelineFeatureFlags::eq(&self, other: &vyre_driver::PipelineFeatureFlags) -> bool
impl core::default::Default for vyre_driver::PipelineFeatureFlags
pub fn vyre_driver::PipelineFeatureFlags::default() -> vyre_driver::PipelineFeatureFlags
impl core::fmt::Debug for vyre_driver::PipelineFeatureFlags
pub fn vyre_driver::PipelineFeatureFlags::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::PipelineFeatureFlags
pub fn vyre_driver::PipelineFeatureFlags::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::PipelineFeatureFlags
impl core::marker::StructuralPartialEq for vyre_driver::PipelineFeatureFlags
impl serde_core::ser::Serialize for vyre_driver::PipelineFeatureFlags
pub fn vyre_driver::PipelineFeatureFlags::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::PipelineFeatureFlags
pub fn vyre_driver::PipelineFeatureFlags::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::PipelineFeatureFlags
impl core::marker::Send for vyre_driver::PipelineFeatureFlags
impl core::marker::Sync for vyre_driver::PipelineFeatureFlags
impl core::marker::Unpin for vyre_driver::PipelineFeatureFlags
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::PipelineFeatureFlags
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::PipelineFeatureFlags
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::PipelineFeatureFlags where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::PipelineFeatureFlags::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::PipelineFeatureFlags where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::PipelineFeatureFlags where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::PipelineFeatureFlags::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::PipelineFeatureFlags::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::PipelineFeatureFlags where U: core::convert::From<T>
pub fn vyre_driver::PipelineFeatureFlags::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::PipelineFeatureFlags where U: core::convert::Into<T>
pub type vyre_driver::PipelineFeatureFlags::Error = core::convert::Infallible
pub fn vyre_driver::PipelineFeatureFlags::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::PipelineFeatureFlags where U: core::convert::TryFrom<T>
pub type vyre_driver::PipelineFeatureFlags::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::PipelineFeatureFlags::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::PipelineFeatureFlags where T: core::clone::Clone
pub type vyre_driver::PipelineFeatureFlags::Owned = T
pub fn vyre_driver::PipelineFeatureFlags::clone_into(&self, target: &mut T)
pub fn vyre_driver::PipelineFeatureFlags::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::PipelineFeatureFlags where T: 'static + ?core::marker::Sized
pub fn vyre_driver::PipelineFeatureFlags::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::PipelineFeatureFlags where T: ?core::marker::Sized
pub fn vyre_driver::PipelineFeatureFlags::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::PipelineFeatureFlags where T: ?core::marker::Sized
pub fn vyre_driver::PipelineFeatureFlags::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::PipelineFeatureFlags where T: core::clone::Clone
pub unsafe fn vyre_driver::PipelineFeatureFlags::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::PipelineFeatureFlags
pub fn vyre_driver::PipelineFeatureFlags::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::PipelineFeatureFlags where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::PipelineFeatureFlags
impl<T> tracing::instrument::WithSubscriber for vyre_driver::PipelineFeatureFlags
pub struct vyre_driver::RoutingTable
impl vyre_driver::RoutingTable
pub fn vyre_driver::RoutingTable::distribution(&self, call_site: &str) -> core::option::Option<vyre_driver::Distribution>
pub fn vyre_driver::RoutingTable::observe_sort_u32(&self, call_site: alloc::borrow::Cow<'_, str>, values: &[u32]) -> core::result::Result<vyre_driver::SortBackend, alloc::string::String>
impl core::default::Default for vyre_driver::RoutingTable
pub fn vyre_driver::RoutingTable::default() -> vyre_driver::RoutingTable
impl core::fmt::Debug for vyre_driver::RoutingTable
pub fn vyre_driver::RoutingTable::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl !core::marker::Freeze for vyre_driver::RoutingTable
impl core::marker::Send for vyre_driver::RoutingTable
impl core::marker::Sync for vyre_driver::RoutingTable
impl core::marker::Unpin for vyre_driver::RoutingTable
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::RoutingTable
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::RoutingTable
impl<T, U> core::convert::Into<U> for vyre_driver::RoutingTable where U: core::convert::From<T>
pub fn vyre_driver::RoutingTable::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::RoutingTable where U: core::convert::Into<T>
pub type vyre_driver::RoutingTable::Error = core::convert::Infallible
pub fn vyre_driver::RoutingTable::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::RoutingTable where U: core::convert::TryFrom<T>
pub type vyre_driver::RoutingTable::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::RoutingTable::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::RoutingTable where T: 'static + ?core::marker::Sized
pub fn vyre_driver::RoutingTable::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::RoutingTable where T: ?core::marker::Sized
pub fn vyre_driver::RoutingTable::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::RoutingTable where T: ?core::marker::Sized
pub fn vyre_driver::RoutingTable::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::RoutingTable
pub fn vyre_driver::RoutingTable::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::RoutingTable
impl<T> tracing::instrument::WithSubscriber for vyre_driver::RoutingTable
pub const vyre_driver::CURRENT_PIPELINE_CACHE_KEY_VERSION: u32
pub trait vyre_driver::Compilable: vyre_driver::backend::Backend
pub type vyre_driver::Compilable::Compiled: core::marker::Send + core::marker::Sync
pub fn vyre_driver::Compilable::compile(&self, program: &vyre_foundation::ir_inner::model::program::Program) -> core::result::Result<Self::Compiled, vyre_driver::backend::BackendError>
pub fn vyre_driver::Compilable::execute_compiled(&self, compiled: &Self::Compiled, inputs: &[vyre_driver::MemoryRef<'_>], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<vyre_driver::Memory>, vyre_driver::backend::BackendError>
pub trait vyre_driver::CompiledPipeline: core::marker::Send + core::marker::Sync
pub fn vyre_driver::CompiledPipeline::dispatch(&self, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::backend::BackendError>
pub fn vyre_driver::CompiledPipeline::dispatch_borrowed(&self, inputs: &[&[u8]], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::backend::BackendError>
pub fn vyre_driver::CompiledPipeline::id(&self) -> &str
pub trait vyre_driver::EnforceGate: core::marker::Send + core::marker::Sync
pub fn vyre_driver::EnforceGate::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::Program) -> vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::EnforceGate::name(&self) -> &'static str
impl<A: vyre_driver::registry::EnforceGate, B: vyre_driver::registry::EnforceGate> vyre_driver::registry::EnforceGate for vyre_driver::registry::Chain<A, B>
pub fn vyre_driver::registry::Chain<A, B>::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::Program) -> vyre_driver::registry::EnforceVerdict
pub fn vyre_driver::registry::Chain<A, B>::name(&self) -> &'static str
pub trait vyre_driver::Executable: vyre_driver::backend::Backend
pub fn vyre_driver::Executable::execute(&self, program: &vyre_foundation::ir_inner::model::program::Program, inputs: &[vyre_driver::MemoryRef<'_>], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<vyre_driver::Memory>, vyre_driver::backend::BackendError>
pub trait vyre_driver::PendingDispatch: core::marker::Send + core::marker::Sync
pub fn vyre_driver::PendingDispatch::await_result(self: alloc::boxed::Box<Self>) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::backend::BackendError>
pub fn vyre_driver::PendingDispatch::is_ready(&self) -> bool
pub trait vyre_driver::VyreBackend: core::marker::Send + core::marker::Sync
pub fn vyre_driver::VyreBackend::compile_native(&self, _program: &vyre_foundation::ir_inner::model::program::Program, _config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<core::option::Option<alloc::sync::Arc<dyn vyre_driver::backend::CompiledPipeline>>, vyre_driver::backend::BackendError>
pub fn vyre_driver::VyreBackend::device_lost(&self) -> bool
pub fn vyre_driver::VyreBackend::dispatch(&self, program: &vyre_foundation::ir_inner::model::program::Program, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::backend::BackendError>
pub fn vyre_driver::VyreBackend::dispatch_async(&self, program: &vyre_foundation::ir_inner::model::program::Program, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::boxed::Box<dyn vyre_driver::backend::PendingDispatch>, vyre_driver::backend::BackendError>
pub fn vyre_driver::VyreBackend::dispatch_borrowed(&self, program: &vyre_foundation::ir_inner::model::program::Program, inputs: &[&[u8]], config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::backend::BackendError>
pub fn vyre_driver::VyreBackend::flush(&self) -> core::result::Result<(), vyre_driver::backend::BackendError>
pub fn vyre_driver::VyreBackend::id(&self) -> &'static str
pub fn vyre_driver::VyreBackend::is_distributed(&self) -> bool
pub fn vyre_driver::VyreBackend::max_storage_buffer_bytes(&self) -> u64
pub fn vyre_driver::VyreBackend::max_workgroup_size(&self) -> [u32; 3]
pub fn vyre_driver::VyreBackend::prepare(&self) -> core::result::Result<(), vyre_driver::backend::BackendError>
pub fn vyre_driver::VyreBackend::shutdown(&self) -> core::result::Result<(), vyre_driver::backend::BackendError>
pub fn vyre_driver::VyreBackend::supported_ops(&self) -> &std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn vyre_driver::VyreBackend::supports_async_compute(&self) -> bool
pub fn vyre_driver::VyreBackend::supports_bf16(&self) -> bool
pub fn vyre_driver::VyreBackend::supports_f16(&self) -> bool
pub fn vyre_driver::VyreBackend::supports_indirect_dispatch(&self) -> bool
pub fn vyre_driver::VyreBackend::supports_subgroup_ops(&self) -> bool
pub fn vyre_driver::VyreBackend::supports_tensor_cores(&self) -> bool
pub fn vyre_driver::VyreBackend::try_recover(&self) -> core::result::Result<(), vyre_driver::backend::BackendError>
pub fn vyre_driver::VyreBackend::version(&self) -> &'static str
pub fn vyre_driver::compile(backend: alloc::sync::Arc<dyn vyre_driver::backend::VyreBackend>, program: &vyre_foundation::ir_inner::model::program::Program, config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::sync::Arc<dyn vyre_driver::backend::CompiledPipeline>, vyre_driver::backend::BackendError>
pub fn vyre_driver::compile_shared(backend: alloc::sync::Arc<dyn vyre_driver::backend::VyreBackend>, program: alloc::sync::Arc<vyre_foundation::ir_inner::model::program::Program>, config: &vyre_driver::backend::DispatchConfig) -> core::result::Result<alloc::sync::Arc<dyn vyre_driver::backend::CompiledPipeline>, vyre_driver::backend::BackendError>
pub fn vyre_driver::default_validator() -> bool
pub fn vyre_driver::select_sort_backend(distribution: vyre_driver::Distribution) -> vyre_driver::SortBackend
pub type vyre_driver::Memory = alloc::vec::Vec<u8>
pub type vyre_driver::MemoryRef<'a> = &'a [u8]
