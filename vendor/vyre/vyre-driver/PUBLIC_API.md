pub mod vyre_driver
pub use vyre_driver::AttrSchema
pub use vyre_driver::AttrType
pub use vyre_driver::Category
pub use vyre_driver::Error
pub use vyre_driver::InternedOpId
pub use vyre_driver::LoweringCtx
pub use vyre_driver::LoweringTable
pub use vyre_driver::NativeModuleBuilder
pub use vyre_driver::NativeModule
pub use vyre_driver::PrimaryTextBuilder
pub use vyre_driver::OpDef
pub use vyre_driver::SecondaryTextBuilder
pub use vyre_driver::TextModule
pub use vyre_driver::ReferenceKind
pub use vyre_driver::Signature
pub use vyre_driver::PrimaryBinaryBuilder
pub use vyre_driver::TypedParam
pub use vyre_driver::error
pub use vyre_driver::intern_string
pub mod vyre_driver::aot
pub struct vyre_driver::aot::AotEmitter
pub vyre_driver::aot::AotEmitter::emit: fn(&vyre_foundation::ir_inner::model::program::core::Program, &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<u8>, alloc::string::String>
pub vyre_driver::aot::AotEmitter::target: vyre_driver::aot::AotTargetId
impl inventory::Collect for vyre_driver::aot::AotEmitter
impl core::marker::Freeze for vyre_driver::aot::AotEmitter
impl core::marker::Send for vyre_driver::aot::AotEmitter
impl core::marker::Sync for vyre_driver::aot::AotEmitter
impl core::marker::Unpin for vyre_driver::aot::AotEmitter
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::aot::AotEmitter
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::aot::AotEmitter
impl<T, U> core::convert::Into<U> for vyre_driver::aot::AotEmitter where U: core::convert::From<T>
pub fn vyre_driver::aot::AotEmitter::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::aot::AotEmitter where U: core::convert::Into<T>
pub type vyre_driver::aot::AotEmitter::Error = core::convert::Infallible
pub fn vyre_driver::aot::AotEmitter::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::aot::AotEmitter where U: core::convert::TryFrom<T>
pub type vyre_driver::aot::AotEmitter::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::aot::AotEmitter::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::aot::AotEmitter where T: 'static + ?core::marker::Sized
pub fn vyre_driver::aot::AotEmitter::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::aot::AotEmitter where T: ?core::marker::Sized
pub fn vyre_driver::aot::AotEmitter::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::aot::AotEmitter where T: ?core::marker::Sized
pub fn vyre_driver::aot::AotEmitter::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::aot::AotEmitter
pub fn vyre_driver::aot::AotEmitter::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::aot::AotEmitter
impl<T> tracing::instrument::WithSubscriber for vyre_driver::aot::AotEmitter
impl<T> typenum::type_operators::Same for vyre_driver::aot::AotEmitter
pub type vyre_driver::aot::AotEmitter::Output = T
pub fn vyre_driver::aot::emit_aot_target(target: &str, program: &vyre_foundation::ir_inner::model::program::core::Program, config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<u8>, vyre_driver::BackendError>
pub fn vyre_driver::aot::registered_aot_emitters() -> alloc::vec::Vec<&'static vyre_driver::aot::AotEmitter>
pub type vyre_driver::aot::AotTargetId = &'static str
pub mod vyre_driver::backend
pub mod vyre_driver::backend::lowering
pub trait vyre_driver::backend::lowering::LowerableOp: core::marker::Send + core::marker::Sync + 'static
pub fn vyre_driver::backend::lowering::LowerableOp::lower_binary(&self, ctx: &mut (), program: &vyre_foundation::ir_inner::model::program::core::Program) -> core::result::Result<(), alloc::string::String>
pub fn vyre_driver::backend::lowering::LowerableOp::lower_expression(&self, ctx: &mut dyn vyre_driver::backend::lowering::TargetGenCtx, program: &vyre_foundation::ir_inner::model::program::core::Program) -> core::result::Result<(), alloc::string::String>
pub trait vyre_driver::backend::lowering::TargetGenCtx
pub fn vyre_driver::backend::lowering::TargetGenCtx::register_expression(&mut self, format: &str) -> core::result::Result<(), ()>
pub mod vyre_driver::backend::validation
pub fn vyre_driver::backend::validation::default_supported_ops() -> &'static std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn vyre_driver::backend::validation::node_op_id(node: &vyre_foundation::ir_inner::model::generated::Node) -> &'static str
pub fn vyre_driver::backend::validation::validate_program(program: &vyre_foundation::ir_inner::model::program::core::Program, backend: &dyn vyre_driver::backend::Backend) -> core::result::Result<(), vyre_foundation::validate::validation_error::ValidationError>
#[non_exhaustive] pub enum vyre_driver::backend::BackendError
pub vyre_driver::backend::BackendError::DeviceOutOfMemory
pub vyre_driver::backend::BackendError::DeviceOutOfMemory::available: u64
pub vyre_driver::backend::BackendError::DeviceOutOfMemory::requested: u64
pub vyre_driver::backend::BackendError::DispatchFailed
pub vyre_driver::backend::BackendError::DispatchFailed::code: core::option::Option<i32>
pub vyre_driver::backend::BackendError::DispatchFailed::message: alloc::string::String
pub vyre_driver::backend::BackendError::InvalidProgram
pub vyre_driver::backend::BackendError::InvalidProgram::fix: alloc::string::String
pub vyre_driver::backend::BackendError::KernelCompileFailed
pub vyre_driver::backend::BackendError::KernelCompileFailed::backend: alloc::string::String
pub vyre_driver::backend::BackendError::KernelCompileFailed::compiler_message: alloc::string::String
pub vyre_driver::backend::BackendError::PoisonedLock
pub vyre_driver::backend::BackendError::PoisonedLock::lock_error: alloc::string::String
pub vyre_driver::backend::BackendError::Raw(alloc::string::String)
pub vyre_driver::backend::BackendError::UnsupportedFeature
pub vyre_driver::backend::BackendError::UnsupportedFeature::backend: alloc::string::String
pub vyre_driver::backend::BackendError::UnsupportedFeature::name: alloc::string::String
impl vyre_driver::BackendError
pub fn vyre_driver::BackendError::code(&self) -> vyre_driver::backend::ErrorCode
pub fn vyre_driver::BackendError::into_message(self) -> alloc::string::String
pub fn vyre_driver::BackendError::message(&self) -> alloc::string::String
pub fn vyre_driver::BackendError::new(message: impl core::convert::Into<alloc::string::String>) -> Self
pub fn vyre_driver::BackendError::poisoned_lock<T>(error: std::sync::poison::PoisonError<T>) -> Self
pub fn vyre_driver::BackendError::unsupported_extension(backend: impl core::convert::Into<alloc::string::String>, extension_kind: &str, debug_identity: &str) -> Self
impl core::clone::Clone for vyre_driver::BackendError
pub fn vyre_driver::BackendError::clone(&self) -> vyre_driver::BackendError
impl core::cmp::Eq for vyre_driver::BackendError
impl core::cmp::PartialEq for vyre_driver::BackendError
pub fn vyre_driver::BackendError::eq(&self, other: &vyre_driver::BackendError) -> bool
impl core::convert::From<vyre_foundation::error::Error> for vyre_driver::BackendError
pub fn vyre_driver::BackendError::from(error: vyre_foundation::error::Error) -> Self
impl core::error::Error for vyre_driver::BackendError
impl core::fmt::Debug for vyre_driver::BackendError
pub fn vyre_driver::BackendError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::BackendError
pub fn vyre_driver::BackendError::fmt(&self, __formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::BackendError
impl core::marker::Freeze for vyre_driver::BackendError
impl core::marker::Send for vyre_driver::BackendError
impl core::marker::Sync for vyre_driver::BackendError
impl core::marker::Unpin for vyre_driver::BackendError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::BackendError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::BackendError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::BackendError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::BackendError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::BackendError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::BackendError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::BackendError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::BackendError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::BackendError where U: core::convert::From<T>
pub fn vyre_driver::BackendError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::BackendError where U: core::convert::Into<T>
pub type vyre_driver::BackendError::Error = core::convert::Infallible
pub fn vyre_driver::BackendError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::BackendError where U: core::convert::TryFrom<T>
pub type vyre_driver::BackendError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::BackendError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::BackendError where T: core::clone::Clone
pub type vyre_driver::BackendError::Owned = T
pub fn vyre_driver::BackendError::clone_into(&self, target: &mut T)
pub fn vyre_driver::BackendError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::BackendError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::BackendError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::BackendError where T: 'static + ?core::marker::Sized
pub fn vyre_driver::BackendError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::BackendError where T: ?core::marker::Sized
pub fn vyre_driver::BackendError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::BackendError where T: ?core::marker::Sized
pub fn vyre_driver::BackendError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::BackendError where T: core::clone::Clone
pub unsafe fn vyre_driver::BackendError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::BackendError
pub fn vyre_driver::BackendError::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::BackendError
impl<T> tracing::instrument::WithSubscriber for vyre_driver::BackendError
impl<T> typenum::type_operators::Same for vyre_driver::BackendError
pub type vyre_driver::BackendError::Output = T
#[non_exhaustive] pub enum vyre_driver::backend::ErrorCode
pub vyre_driver::backend::ErrorCode::DeviceOutOfMemory
pub vyre_driver::backend::ErrorCode::DispatchFailed
pub vyre_driver::backend::ErrorCode::InvalidProgram
pub vyre_driver::backend::ErrorCode::KernelCompileFailed
pub vyre_driver::backend::ErrorCode::PoisonedLock
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
impl<T> typenum::type_operators::Same for vyre_driver::backend::ErrorCode
pub type vyre_driver::backend::ErrorCode::Output = T
pub enum vyre_driver::backend::Resource
pub vyre_driver::backend::Resource::Borrowed(alloc::vec::Vec<u8>)
pub vyre_driver::backend::Resource::Resident(u64)
impl core::clone::Clone for vyre_driver::Resource
pub fn vyre_driver::Resource::clone(&self) -> vyre_driver::Resource
impl core::cmp::Eq for vyre_driver::Resource
impl core::cmp::PartialEq for vyre_driver::Resource
pub fn vyre_driver::Resource::eq(&self, other: &vyre_driver::Resource) -> bool
impl core::convert::From<alloc::vec::Vec<u8>> for vyre_driver::Resource
pub fn vyre_driver::Resource::from(bytes: alloc::vec::Vec<u8>) -> Self
impl core::default::Default for vyre_driver::Resource
pub fn vyre_driver::Resource::default() -> Self
impl core::fmt::Debug for vyre_driver::Resource
pub fn vyre_driver::Resource::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::Resource
impl core::marker::Freeze for vyre_driver::Resource
impl core::marker::Send for vyre_driver::Resource
impl core::marker::Sync for vyre_driver::Resource
impl core::marker::Unpin for vyre_driver::Resource
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::Resource
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::Resource
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::Resource where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::Resource::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::Resource where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::Resource where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::Resource::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::Resource::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::Resource where U: core::convert::From<T>
pub fn vyre_driver::Resource::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::Resource where U: core::convert::Into<T>
pub type vyre_driver::Resource::Error = core::convert::Infallible
pub fn vyre_driver::Resource::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::Resource where U: core::convert::TryFrom<T>
pub type vyre_driver::Resource::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::Resource::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::Resource where T: core::clone::Clone
pub type vyre_driver::Resource::Owned = T
pub fn vyre_driver::Resource::clone_into(&self, target: &mut T)
pub fn vyre_driver::Resource::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::Resource where T: 'static + ?core::marker::Sized
pub fn vyre_driver::Resource::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::Resource where T: ?core::marker::Sized
pub fn vyre_driver::Resource::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::Resource where T: ?core::marker::Sized
pub fn vyre_driver::Resource::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::Resource where T: core::clone::Clone
pub unsafe fn vyre_driver::Resource::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::Resource
pub fn vyre_driver::Resource::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::Resource
impl<T> tracing::instrument::WithSubscriber for vyre_driver::Resource
impl<T> typenum::type_operators::Same for vyre_driver::Resource
pub type vyre_driver::Resource::Output = T
pub struct vyre_driver::backend::BackendCapability
pub vyre_driver::backend::BackendCapability::dispatches: bool
pub vyre_driver::backend::BackendCapability::id: &'static str
impl inventory::Collect for vyre_driver::backend::BackendCapability
impl core::marker::Freeze for vyre_driver::backend::BackendCapability
impl core::marker::Send for vyre_driver::backend::BackendCapability
impl core::marker::Sync for vyre_driver::backend::BackendCapability
impl core::marker::Unpin for vyre_driver::backend::BackendCapability
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::backend::BackendCapability
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::backend::BackendCapability
impl<T, U> core::convert::Into<U> for vyre_driver::backend::BackendCapability where U: core::convert::From<T>
pub fn vyre_driver::backend::BackendCapability::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::backend::BackendCapability where U: core::convert::Into<T>
pub type vyre_driver::backend::BackendCapability::Error = core::convert::Infallible
pub fn vyre_driver::backend::BackendCapability::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::backend::BackendCapability where U: core::convert::TryFrom<T>
pub type vyre_driver::backend::BackendCapability::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::backend::BackendCapability::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::backend::BackendCapability where T: 'static + ?core::marker::Sized
pub fn vyre_driver::backend::BackendCapability::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::backend::BackendCapability where T: ?core::marker::Sized
pub fn vyre_driver::backend::BackendCapability::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::backend::BackendCapability where T: ?core::marker::Sized
pub fn vyre_driver::backend::BackendCapability::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::backend::BackendCapability
pub fn vyre_driver::backend::BackendCapability::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::backend::BackendCapability
impl<T> tracing::instrument::WithSubscriber for vyre_driver::backend::BackendCapability
impl<T> typenum::type_operators::Same for vyre_driver::backend::BackendCapability
pub type vyre_driver::backend::BackendCapability::Output = T
pub struct vyre_driver::backend::BackendPrecedence
pub vyre_driver::backend::BackendPrecedence::id: &'static str
pub vyre_driver::backend::BackendPrecedence::rank: u32
impl inventory::Collect for vyre_driver::backend::BackendPrecedence
impl core::marker::Freeze for vyre_driver::backend::BackendPrecedence
impl core::marker::Send for vyre_driver::backend::BackendPrecedence
impl core::marker::Sync for vyre_driver::backend::BackendPrecedence
impl core::marker::Unpin for vyre_driver::backend::BackendPrecedence
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::backend::BackendPrecedence
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::backend::BackendPrecedence
impl<T, U> core::convert::Into<U> for vyre_driver::backend::BackendPrecedence where U: core::convert::From<T>
pub fn vyre_driver::backend::BackendPrecedence::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::backend::BackendPrecedence where U: core::convert::Into<T>
pub type vyre_driver::backend::BackendPrecedence::Error = core::convert::Infallible
pub fn vyre_driver::backend::BackendPrecedence::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::backend::BackendPrecedence where U: core::convert::TryFrom<T>
pub type vyre_driver::backend::BackendPrecedence::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::backend::BackendPrecedence::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::backend::BackendPrecedence where T: 'static + ?core::marker::Sized
pub fn vyre_driver::backend::BackendPrecedence::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::backend::BackendPrecedence where T: ?core::marker::Sized
pub fn vyre_driver::backend::BackendPrecedence::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::backend::BackendPrecedence where T: ?core::marker::Sized
pub fn vyre_driver::backend::BackendPrecedence::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::backend::BackendPrecedence
pub fn vyre_driver::backend::BackendPrecedence::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::backend::BackendPrecedence
impl<T> tracing::instrument::WithSubscriber for vyre_driver::backend::BackendPrecedence
impl<T> typenum::type_operators::Same for vyre_driver::backend::BackendPrecedence
pub type vyre_driver::backend::BackendPrecedence::Output = T
pub struct vyre_driver::backend::BackendRegistration
pub vyre_driver::backend::BackendRegistration::factory: fn() -> core::result::Result<alloc::boxed::Box<dyn vyre_driver::VyreBackend>, vyre_driver::BackendError>
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
impl<T> typenum::type_operators::Same for vyre_driver::BackendRegistration
pub type vyre_driver::BackendRegistration::Output = T
#[non_exhaustive] pub struct vyre_driver::backend::DispatchConfig
pub vyre_driver::backend::DispatchConfig::fixpoint_iterations: core::option::Option<u32>
pub vyre_driver::backend::DispatchConfig::grid_override: core::option::Option<[u32; 3]>
pub vyre_driver::backend::DispatchConfig::label: core::option::Option<alloc::string::String>
pub vyre_driver::backend::DispatchConfig::max_output_bytes: core::option::Option<usize>
pub vyre_driver::backend::DispatchConfig::persistent_thread: core::option::Option<vyre_driver::persistent::PersistentThreadMode>
pub vyre_driver::backend::DispatchConfig::profile: core::option::Option<alloc::string::String>
pub vyre_driver::backend::DispatchConfig::speculation: core::option::Option<vyre_driver::speculate::SpeculationMode>
pub vyre_driver::backend::DispatchConfig::timeout: core::option::Option<core::time::Duration>
pub vyre_driver::backend::DispatchConfig::ulp_budget: core::option::Option<u8>
pub vyre_driver::backend::DispatchConfig::workgroup_override: core::option::Option<[u32; 3]>
impl vyre_driver::DispatchConfig
pub fn vyre_driver::DispatchConfig::new(profile: core::option::Option<alloc::string::String>, ulp_budget: core::option::Option<u8>, timeout: core::option::Option<core::time::Duration>, label: core::option::Option<alloc::string::String>) -> Self
impl core::clone::Clone for vyre_driver::DispatchConfig
pub fn vyre_driver::DispatchConfig::clone(&self) -> vyre_driver::DispatchConfig
impl core::cmp::Eq for vyre_driver::DispatchConfig
impl core::cmp::PartialEq for vyre_driver::DispatchConfig
pub fn vyre_driver::DispatchConfig::eq(&self, other: &vyre_driver::DispatchConfig) -> bool
impl core::default::Default for vyre_driver::DispatchConfig
pub fn vyre_driver::DispatchConfig::default() -> vyre_driver::DispatchConfig
impl core::fmt::Debug for vyre_driver::DispatchConfig
pub fn vyre_driver::DispatchConfig::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::DispatchConfig
impl core::marker::Freeze for vyre_driver::DispatchConfig
impl core::marker::Send for vyre_driver::DispatchConfig
impl core::marker::Sync for vyre_driver::DispatchConfig
impl core::marker::Unpin for vyre_driver::DispatchConfig
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::DispatchConfig
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::DispatchConfig
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::DispatchConfig where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::DispatchConfig::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::DispatchConfig where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::DispatchConfig where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::DispatchConfig::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::DispatchConfig::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::DispatchConfig where U: core::convert::From<T>
pub fn vyre_driver::DispatchConfig::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::DispatchConfig where U: core::convert::Into<T>
pub type vyre_driver::DispatchConfig::Error = core::convert::Infallible
pub fn vyre_driver::DispatchConfig::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::DispatchConfig where U: core::convert::TryFrom<T>
pub type vyre_driver::DispatchConfig::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::DispatchConfig::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::DispatchConfig where T: core::clone::Clone
pub type vyre_driver::DispatchConfig::Owned = T
pub fn vyre_driver::DispatchConfig::clone_into(&self, target: &mut T)
pub fn vyre_driver::DispatchConfig::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::DispatchConfig where T: 'static + ?core::marker::Sized
pub fn vyre_driver::DispatchConfig::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::DispatchConfig where T: ?core::marker::Sized
pub fn vyre_driver::DispatchConfig::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::DispatchConfig where T: ?core::marker::Sized
pub fn vyre_driver::DispatchConfig::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::DispatchConfig where T: core::clone::Clone
pub unsafe fn vyre_driver::DispatchConfig::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::DispatchConfig
pub fn vyre_driver::DispatchConfig::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::DispatchConfig
impl<T> tracing::instrument::WithSubscriber for vyre_driver::DispatchConfig
impl<T> typenum::type_operators::Same for vyre_driver::DispatchConfig
pub type vyre_driver::DispatchConfig::Output = T
pub trait vyre_driver::backend::Backend: core::marker::Send + core::marker::Sync
pub fn vyre_driver::backend::Backend::id(&self) -> &'static str
pub fn vyre_driver::backend::Backend::supported_ops(&self) -> &std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn vyre_driver::backend::Backend::version(&self) -> &'static str
impl<T: vyre_driver::VyreBackend + ?core::marker::Sized> vyre_driver::backend::Backend for T
pub fn T::id(&self) -> &'static str
pub fn T::supported_ops(&self) -> &std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn T::version(&self) -> &'static str
pub trait vyre_driver::backend::CompiledPipeline: private::Sealed + core::marker::Send + core::marker::Sync
pub fn vyre_driver::backend::CompiledPipeline::dispatch(&self, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::BackendError>
pub fn vyre_driver::backend::CompiledPipeline::dispatch_borrowed(&self, inputs: &[&[u8]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::BackendError>
pub fn vyre_driver::backend::CompiledPipeline::dispatch_borrowed_into(&self, inputs: &[&[u8]], config: &vyre_driver::DispatchConfig, outputs: &mut vyre_driver::OutputBuffers) -> core::result::Result<(), vyre_driver::BackendError>
pub fn vyre_driver::backend::CompiledPipeline::dispatch_persistent_handles(&self, _inputs: &[vyre_driver::Resource], _config: &vyre_driver::DispatchConfig) -> core::result::Result<vyre_driver::OutputBuffers, vyre_driver::BackendError>
pub fn vyre_driver::backend::CompiledPipeline::id(&self) -> &str
pub trait vyre_driver::backend::Executable: vyre_driver::backend::Backend
pub fn vyre_driver::backend::Executable::dispatch(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[vyre_driver::MemoryRef<'_>], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<vyre_driver::Memory>, vyre_driver::BackendError>
pub trait vyre_driver::backend::PendingDispatch: private::Sealed + core::marker::Send + core::marker::Sync
pub fn vyre_driver::backend::PendingDispatch::await_result(self: alloc::boxed::Box<Self>) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::BackendError>
pub fn vyre_driver::backend::PendingDispatch::is_ready(&self) -> bool
pub trait vyre_driver::backend::Streamable: vyre_driver::backend::Backend
pub fn vyre_driver::backend::Streamable::stream(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, chunks: &mut dyn core::iter::traits::iterator::Iterator<Item = vyre_driver::MemoryRef<'_>>, config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::boxed::Box<dyn core::iter::traits::iterator::Iterator<Item = core::result::Result<vyre_driver::Memory, vyre_driver::BackendError>>>, vyre_driver::BackendError>
pub trait vyre_driver::backend::TypedDispatchExt: vyre_driver::VyreBackend
pub fn vyre_driver::backend::TypedDispatchExt::dispatch_bytes(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[u8]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::BackendError>
pub fn vyre_driver::backend::TypedDispatchExt::dispatch_f32(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[f32]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<f32>>, vyre_driver::BackendError>
pub fn vyre_driver::backend::TypedDispatchExt::dispatch_pod<T: bytemuck::pod::Pod>(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[T]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<T>>, vyre_driver::BackendError>
pub fn vyre_driver::backend::TypedDispatchExt::dispatch_u32(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[u32]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u32>>, vyre_driver::BackendError>
impl<T: vyre_driver::VyreBackend + ?core::marker::Sized> vyre_driver::TypedDispatchExt for T
pub fn T::dispatch_bytes(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[u8]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::BackendError>
pub fn T::dispatch_f32(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[f32]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<f32>>, vyre_driver::BackendError>
pub fn T::dispatch_pod<T: bytemuck::pod::Pod>(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[T]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<T>>, vyre_driver::BackendError>
pub fn T::dispatch_u32(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[u32]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u32>>, vyre_driver::BackendError>
pub trait vyre_driver::backend::VyreBackend: private::Sealed + core::marker::Send + core::marker::Sync
pub fn vyre_driver::backend::VyreBackend::compile_native(&self, _program: &vyre_foundation::ir_inner::model::program::core::Program, _config: &vyre_driver::DispatchConfig) -> core::result::Result<core::option::Option<alloc::sync::Arc<dyn vyre_driver::CompiledPipeline>>, vyre_driver::BackendError>
pub fn vyre_driver::backend::VyreBackend::device_lost(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::dispatch(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::BackendError>
pub fn vyre_driver::backend::VyreBackend::dispatch_async(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::boxed::Box<dyn vyre_driver::PendingDispatch>, vyre_driver::BackendError>
pub fn vyre_driver::backend::VyreBackend::dispatch_borrowed(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[u8]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::BackendError>
pub fn vyre_driver::backend::VyreBackend::dispatch_borrowed_async(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[u8]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::boxed::Box<dyn vyre_driver::PendingDispatch>, vyre_driver::BackendError>
pub fn vyre_driver::backend::VyreBackend::dispatch_borrowed_into(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[u8]], config: &vyre_driver::DispatchConfig, outputs: &mut vyre_driver::OutputBuffers) -> core::result::Result<(), vyre_driver::BackendError>
pub fn vyre_driver::backend::VyreBackend::flush(&self) -> core::result::Result<(), vyre_driver::BackendError>
pub fn vyre_driver::backend::VyreBackend::id(&self) -> &'static str
pub fn vyre_driver::backend::VyreBackend::is_distributed(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::max_compute_invocations_per_workgroup(&self) -> u32
pub fn vyre_driver::backend::VyreBackend::max_compute_workgroups_per_dimension(&self) -> u32
pub fn vyre_driver::backend::VyreBackend::max_storage_buffer_bytes(&self) -> u64
pub fn vyre_driver::backend::VyreBackend::max_workgroup_size(&self) -> [u32; 3]
pub fn vyre_driver::backend::VyreBackend::prepare(&self) -> core::result::Result<(), vyre_driver::BackendError>
pub fn vyre_driver::backend::VyreBackend::shutdown(&self) -> core::result::Result<(), vyre_driver::BackendError>
pub fn vyre_driver::backend::VyreBackend::subgroup_size(&self) -> core::option::Option<u32>
pub fn vyre_driver::backend::VyreBackend::supported_ops(&self) -> &std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn vyre_driver::backend::VyreBackend::supports_async_compute(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::supports_bf16(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::supports_f16(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::supports_indirect_dispatch(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::supports_persistent_thread_dispatch(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::supports_speculation(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::supports_subgroup_ops(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::supports_tensor_cores(&self) -> bool
pub fn vyre_driver::backend::VyreBackend::try_recover(&self) -> core::result::Result<(), vyre_driver::BackendError>
pub fn vyre_driver::backend::VyreBackend::version(&self) -> &'static str
pub fn vyre_driver::backend::acquire(id: &str) -> core::result::Result<alloc::boxed::Box<dyn vyre_driver::VyreBackend>, vyre_driver::BackendError>
pub fn vyre_driver::backend::acquire_preferred_dispatch_backend() -> core::result::Result<alloc::boxed::Box<dyn vyre_driver::VyreBackend>, vyre_driver::BackendError>
pub fn vyre_driver::backend::backend_dispatches(id: &str) -> bool
pub fn vyre_driver::backend::backend_precedence(id: &str) -> u32
pub fn vyre_driver::backend::core_supported_ops() -> &'static std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn vyre_driver::backend::default_supported_ops() -> &'static std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn vyre_driver::backend::dialect_and_language_supported_ops() -> &'static std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn vyre_driver::backend::dialect_only_supported_ops() -> &'static std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn vyre_driver::backend::node_op_id(node: &vyre_foundation::ir_inner::model::generated::Node) -> &'static str
pub fn vyre_driver::backend::registered_backends() -> &'static [&'static vyre_driver::BackendRegistration]
pub fn vyre_driver::backend::registered_backends_by_precedence() -> alloc::vec::Vec<&'static vyre_driver::BackendRegistration>
pub fn vyre_driver::backend::registered_backends_by_precedence_slice() -> &'static [&'static vyre_driver::BackendRegistration]
pub fn vyre_driver::backend::validate_program(program: &vyre_foundation::ir_inner::model::program::core::Program, backend: &dyn vyre_driver::backend::Backend) -> core::result::Result<(), vyre_foundation::validate::validation_error::ValidationError>
pub type vyre_driver::backend::Memory = alloc::vec::Vec<u8>
pub type vyre_driver::backend::MemoryRef<'a> = &'a [u8]
pub type vyre_driver::backend::OutputBuffers = alloc::vec::Vec<alloc::vec::Vec<u8>>
pub mod vyre_driver::binding
pub enum vyre_driver::binding::BindingRole
pub vyre_driver::binding::BindingRole::Input
pub vyre_driver::binding::BindingRole::InputOutput
pub vyre_driver::binding::BindingRole::Output
pub vyre_driver::binding::BindingRole::Persistent
pub vyre_driver::binding::BindingRole::Shared
pub vyre_driver::binding::BindingRole::Uniform
impl core::clone::Clone for vyre_driver::binding::BindingRole
pub fn vyre_driver::binding::BindingRole::clone(&self) -> vyre_driver::binding::BindingRole
impl core::cmp::Eq for vyre_driver::binding::BindingRole
impl core::cmp::PartialEq for vyre_driver::binding::BindingRole
pub fn vyre_driver::binding::BindingRole::eq(&self, other: &vyre_driver::binding::BindingRole) -> bool
impl core::fmt::Debug for vyre_driver::binding::BindingRole
pub fn vyre_driver::binding::BindingRole::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::binding::BindingRole
impl core::marker::StructuralPartialEq for vyre_driver::binding::BindingRole
impl core::marker::Freeze for vyre_driver::binding::BindingRole
impl core::marker::Send for vyre_driver::binding::BindingRole
impl core::marker::Sync for vyre_driver::binding::BindingRole
impl core::marker::Unpin for vyre_driver::binding::BindingRole
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::binding::BindingRole
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::binding::BindingRole
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::binding::BindingRole where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::binding::BindingRole::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::binding::BindingRole where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::binding::BindingRole where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::binding::BindingRole::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::binding::BindingRole::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::binding::BindingRole where U: core::convert::From<T>
pub fn vyre_driver::binding::BindingRole::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::binding::BindingRole where U: core::convert::Into<T>
pub type vyre_driver::binding::BindingRole::Error = core::convert::Infallible
pub fn vyre_driver::binding::BindingRole::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::binding::BindingRole where U: core::convert::TryFrom<T>
pub type vyre_driver::binding::BindingRole::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::binding::BindingRole::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::binding::BindingRole where T: core::clone::Clone
pub type vyre_driver::binding::BindingRole::Owned = T
pub fn vyre_driver::binding::BindingRole::clone_into(&self, target: &mut T)
pub fn vyre_driver::binding::BindingRole::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::binding::BindingRole where T: 'static + ?core::marker::Sized
pub fn vyre_driver::binding::BindingRole::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::binding::BindingRole where T: ?core::marker::Sized
pub fn vyre_driver::binding::BindingRole::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::binding::BindingRole where T: ?core::marker::Sized
pub fn vyre_driver::binding::BindingRole::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::binding::BindingRole where T: core::clone::Clone
pub unsafe fn vyre_driver::binding::BindingRole::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::binding::BindingRole
pub fn vyre_driver::binding::BindingRole::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::binding::BindingRole
impl<T> tracing::instrument::WithSubscriber for vyre_driver::binding::BindingRole
impl<T> typenum::type_operators::Same for vyre_driver::binding::BindingRole
pub type vyre_driver::binding::BindingRole::Output = T
pub struct vyre_driver::binding::Binding
pub vyre_driver::binding::Binding::binding: u32
pub vyre_driver::binding::Binding::buffer_index: usize
pub vyre_driver::binding::Binding::element_count: u32
pub vyre_driver::binding::Binding::element_size: usize
pub vyre_driver::binding::Binding::input_index: core::option::Option<usize>
pub vyre_driver::binding::Binding::name: alloc::string::String
pub vyre_driver::binding::Binding::output_index: core::option::Option<usize>
pub vyre_driver::binding::Binding::role: vyre_driver::binding::BindingRole
pub vyre_driver::binding::Binding::static_byte_len: core::option::Option<usize>
impl core::clone::Clone for vyre_driver::binding::Binding
pub fn vyre_driver::binding::Binding::clone(&self) -> vyre_driver::binding::Binding
impl core::cmp::Eq for vyre_driver::binding::Binding
impl core::cmp::PartialEq for vyre_driver::binding::Binding
pub fn vyre_driver::binding::Binding::eq(&self, other: &vyre_driver::binding::Binding) -> bool
impl core::fmt::Debug for vyre_driver::binding::Binding
pub fn vyre_driver::binding::Binding::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::binding::Binding
impl core::marker::Freeze for vyre_driver::binding::Binding
impl core::marker::Send for vyre_driver::binding::Binding
impl core::marker::Sync for vyre_driver::binding::Binding
impl core::marker::Unpin for vyre_driver::binding::Binding
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::binding::Binding
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::binding::Binding
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::binding::Binding where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::binding::Binding::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::binding::Binding where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::binding::Binding where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::binding::Binding::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::binding::Binding::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::binding::Binding where U: core::convert::From<T>
pub fn vyre_driver::binding::Binding::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::binding::Binding where U: core::convert::Into<T>
pub type vyre_driver::binding::Binding::Error = core::convert::Infallible
pub fn vyre_driver::binding::Binding::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::binding::Binding where U: core::convert::TryFrom<T>
pub type vyre_driver::binding::Binding::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::binding::Binding::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::binding::Binding where T: core::clone::Clone
pub type vyre_driver::binding::Binding::Owned = T
pub fn vyre_driver::binding::Binding::clone_into(&self, target: &mut T)
pub fn vyre_driver::binding::Binding::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::binding::Binding where T: 'static + ?core::marker::Sized
pub fn vyre_driver::binding::Binding::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::binding::Binding where T: ?core::marker::Sized
pub fn vyre_driver::binding::Binding::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::binding::Binding where T: ?core::marker::Sized
pub fn vyre_driver::binding::Binding::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::binding::Binding where T: core::clone::Clone
pub unsafe fn vyre_driver::binding::Binding::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::binding::Binding
pub fn vyre_driver::binding::Binding::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::binding::Binding
impl<T> tracing::instrument::WithSubscriber for vyre_driver::binding::Binding
impl<T> typenum::type_operators::Same for vyre_driver::binding::Binding
pub type vyre_driver::binding::Binding::Output = T
pub struct vyre_driver::binding::BindingPlan
pub vyre_driver::binding::BindingPlan::bindings: alloc::vec::Vec<vyre_driver::binding::Binding>
pub vyre_driver::binding::BindingPlan::input_indices: alloc::vec::Vec<usize>
pub vyre_driver::binding::BindingPlan::output_indices: alloc::vec::Vec<usize>
pub vyre_driver::binding::BindingPlan::shared_indices: alloc::vec::Vec<usize>
impl vyre_driver::binding::BindingPlan
pub fn vyre_driver::binding::BindingPlan::build(program: &vyre_foundation::ir_inner::model::program::core::Program) -> core::result::Result<Self, vyre_driver::BackendError>
pub fn vyre_driver::binding::BindingPlan::from_program(program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[alloc::vec::Vec<u8>]) -> core::result::Result<Self, vyre_driver::BackendError>
pub fn vyre_driver::binding::BindingPlan::validate_inputs(&self, inputs: &[alloc::vec::Vec<u8>]) -> core::result::Result<(), vyre_driver::BackendError>
impl core::clone::Clone for vyre_driver::binding::BindingPlan
pub fn vyre_driver::binding::BindingPlan::clone(&self) -> vyre_driver::binding::BindingPlan
impl core::cmp::Eq for vyre_driver::binding::BindingPlan
impl core::cmp::PartialEq for vyre_driver::binding::BindingPlan
pub fn vyre_driver::binding::BindingPlan::eq(&self, other: &vyre_driver::binding::BindingPlan) -> bool
impl core::fmt::Debug for vyre_driver::binding::BindingPlan
pub fn vyre_driver::binding::BindingPlan::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::binding::BindingPlan
impl core::marker::Freeze for vyre_driver::binding::BindingPlan
impl core::marker::Send for vyre_driver::binding::BindingPlan
impl core::marker::Sync for vyre_driver::binding::BindingPlan
impl core::marker::Unpin for vyre_driver::binding::BindingPlan
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::binding::BindingPlan
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::binding::BindingPlan
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::binding::BindingPlan where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::binding::BindingPlan::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::binding::BindingPlan where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::binding::BindingPlan where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::binding::BindingPlan::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::binding::BindingPlan::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::binding::BindingPlan where U: core::convert::From<T>
pub fn vyre_driver::binding::BindingPlan::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::binding::BindingPlan where U: core::convert::Into<T>
pub type vyre_driver::binding::BindingPlan::Error = core::convert::Infallible
pub fn vyre_driver::binding::BindingPlan::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::binding::BindingPlan where U: core::convert::TryFrom<T>
pub type vyre_driver::binding::BindingPlan::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::binding::BindingPlan::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::binding::BindingPlan where T: core::clone::Clone
pub type vyre_driver::binding::BindingPlan::Owned = T
pub fn vyre_driver::binding::BindingPlan::clone_into(&self, target: &mut T)
pub fn vyre_driver::binding::BindingPlan::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::binding::BindingPlan where T: 'static + ?core::marker::Sized
pub fn vyre_driver::binding::BindingPlan::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::binding::BindingPlan where T: ?core::marker::Sized
pub fn vyre_driver::binding::BindingPlan::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::binding::BindingPlan where T: ?core::marker::Sized
pub fn vyre_driver::binding::BindingPlan::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::binding::BindingPlan where T: core::clone::Clone
pub unsafe fn vyre_driver::binding::BindingPlan::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::binding::BindingPlan
pub fn vyre_driver::binding::BindingPlan::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::binding::BindingPlan
impl<T> tracing::instrument::WithSubscriber for vyre_driver::binding::BindingPlan
impl<T> typenum::type_operators::Same for vyre_driver::binding::BindingPlan
pub type vyre_driver::binding::BindingPlan::Output = T
pub mod vyre_driver::diagnostics
#[non_exhaustive] pub enum vyre_driver::diagnostics::Severity
pub vyre_driver::diagnostics::Severity::Error
pub vyre_driver::diagnostics::Severity::Note
pub vyre_driver::diagnostics::Severity::Warning
impl vyre_driver::diagnostics::Severity
pub const fn vyre_driver::diagnostics::Severity::label(self) -> &'static str
impl core::clone::Clone for vyre_driver::diagnostics::Severity
pub fn vyre_driver::diagnostics::Severity::clone(&self) -> vyre_driver::diagnostics::Severity
impl core::cmp::Eq for vyre_driver::diagnostics::Severity
impl core::cmp::PartialEq for vyre_driver::diagnostics::Severity
pub fn vyre_driver::diagnostics::Severity::eq(&self, other: &vyre_driver::diagnostics::Severity) -> bool
impl core::fmt::Debug for vyre_driver::diagnostics::Severity
pub fn vyre_driver::diagnostics::Severity::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::diagnostics::Severity
pub fn vyre_driver::diagnostics::Severity::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::diagnostics::Severity
impl core::marker::StructuralPartialEq for vyre_driver::diagnostics::Severity
impl serde_core::ser::Serialize for vyre_driver::diagnostics::Severity
pub fn vyre_driver::diagnostics::Severity::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::diagnostics::Severity
pub fn vyre_driver::diagnostics::Severity::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::diagnostics::Severity
impl core::marker::Send for vyre_driver::diagnostics::Severity
impl core::marker::Sync for vyre_driver::diagnostics::Severity
impl core::marker::Unpin for vyre_driver::diagnostics::Severity
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::diagnostics::Severity
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::diagnostics::Severity
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::diagnostics::Severity where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::diagnostics::Severity::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::diagnostics::Severity where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::diagnostics::Severity where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::diagnostics::Severity::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::diagnostics::Severity::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::diagnostics::Severity where U: core::convert::From<T>
pub fn vyre_driver::diagnostics::Severity::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::diagnostics::Severity where U: core::convert::Into<T>
pub type vyre_driver::diagnostics::Severity::Error = core::convert::Infallible
pub fn vyre_driver::diagnostics::Severity::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::diagnostics::Severity where U: core::convert::TryFrom<T>
pub type vyre_driver::diagnostics::Severity::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::diagnostics::Severity::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::diagnostics::Severity where T: core::clone::Clone
pub type vyre_driver::diagnostics::Severity::Owned = T
pub fn vyre_driver::diagnostics::Severity::clone_into(&self, target: &mut T)
pub fn vyre_driver::diagnostics::Severity::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::diagnostics::Severity where T: 'static + ?core::marker::Sized
pub fn vyre_driver::diagnostics::Severity::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::diagnostics::Severity where T: ?core::marker::Sized
pub fn vyre_driver::diagnostics::Severity::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::diagnostics::Severity where T: ?core::marker::Sized
pub fn vyre_driver::diagnostics::Severity::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::diagnostics::Severity where T: core::clone::Clone
pub unsafe fn vyre_driver::diagnostics::Severity::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::diagnostics::Severity
pub fn vyre_driver::diagnostics::Severity::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::diagnostics::Severity where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::diagnostics::Severity
impl<T> tracing::instrument::WithSubscriber for vyre_driver::diagnostics::Severity
impl<T> typenum::type_operators::Same for vyre_driver::diagnostics::Severity
pub type vyre_driver::diagnostics::Severity::Output = T
pub struct vyre_driver::diagnostics::Diagnostic
pub vyre_driver::diagnostics::Diagnostic::code: vyre_driver::diagnostics::DiagnosticCode
pub vyre_driver::diagnostics::Diagnostic::doc_url: core::option::Option<alloc::borrow::Cow<'static, str>>
pub vyre_driver::diagnostics::Diagnostic::location: core::option::Option<vyre_driver::diagnostics::OpLocation>
pub vyre_driver::diagnostics::Diagnostic::message: alloc::borrow::Cow<'static, str>
pub vyre_driver::diagnostics::Diagnostic::severity: vyre_driver::diagnostics::Severity
pub vyre_driver::diagnostics::Diagnostic::suggested_fix: core::option::Option<alloc::borrow::Cow<'static, str>>
impl vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::error(code: &'static str, message: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::diagnostics::Diagnostic::note(code: &'static str, message: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::diagnostics::Diagnostic::render_human(&self) -> alloc::string::String
pub fn vyre_driver::diagnostics::Diagnostic::to_json(&self) -> alloc::string::String
pub fn vyre_driver::diagnostics::Diagnostic::warning(code: &'static str, message: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::diagnostics::Diagnostic::with_doc_url(self, url: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::diagnostics::Diagnostic::with_fix(self, fix: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::diagnostics::Diagnostic::with_location(self, loc: vyre_driver::diagnostics::OpLocation) -> Self
impl core::clone::Clone for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::clone(&self) -> vyre_driver::diagnostics::Diagnostic
impl core::cmp::Eq for vyre_driver::diagnostics::Diagnostic
impl core::cmp::PartialEq for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::eq(&self, other: &vyre_driver::diagnostics::Diagnostic) -> bool
impl core::convert::From<&vyre_foundation::error::Error> for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::from(err: &vyre_foundation::error::Error) -> Self
impl core::convert::From<vyre_foundation::error::Error> for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::from(err: vyre_foundation::error::Error) -> Self
impl core::fmt::Debug for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::diagnostics::Diagnostic
impl serde_core::ser::Serialize for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::diagnostics::Diagnostic
impl core::marker::Send for vyre_driver::diagnostics::Diagnostic
impl core::marker::Sync for vyre_driver::diagnostics::Diagnostic
impl core::marker::Unpin for vyre_driver::diagnostics::Diagnostic
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::diagnostics::Diagnostic
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::diagnostics::Diagnostic
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::diagnostics::Diagnostic where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::diagnostics::Diagnostic::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::diagnostics::Diagnostic where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::diagnostics::Diagnostic where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::diagnostics::Diagnostic::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::diagnostics::Diagnostic::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::diagnostics::Diagnostic where U: core::convert::From<T>
pub fn vyre_driver::diagnostics::Diagnostic::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::diagnostics::Diagnostic where U: core::convert::Into<T>
pub type vyre_driver::diagnostics::Diagnostic::Error = core::convert::Infallible
pub fn vyre_driver::diagnostics::Diagnostic::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::diagnostics::Diagnostic where U: core::convert::TryFrom<T>
pub type vyre_driver::diagnostics::Diagnostic::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::diagnostics::Diagnostic::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::diagnostics::Diagnostic where T: core::clone::Clone
pub type vyre_driver::diagnostics::Diagnostic::Owned = T
pub fn vyre_driver::diagnostics::Diagnostic::clone_into(&self, target: &mut T)
pub fn vyre_driver::diagnostics::Diagnostic::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::diagnostics::Diagnostic where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::diagnostics::Diagnostic::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::diagnostics::Diagnostic where T: 'static + ?core::marker::Sized
pub fn vyre_driver::diagnostics::Diagnostic::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::diagnostics::Diagnostic where T: ?core::marker::Sized
pub fn vyre_driver::diagnostics::Diagnostic::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::diagnostics::Diagnostic where T: ?core::marker::Sized
pub fn vyre_driver::diagnostics::Diagnostic::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::diagnostics::Diagnostic where T: core::clone::Clone
pub unsafe fn vyre_driver::diagnostics::Diagnostic::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::diagnostics::Diagnostic where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::diagnostics::Diagnostic
impl<T> tracing::instrument::WithSubscriber for vyre_driver::diagnostics::Diagnostic
impl<T> typenum::type_operators::Same for vyre_driver::diagnostics::Diagnostic
pub type vyre_driver::diagnostics::Diagnostic::Output = T
pub struct vyre_driver::diagnostics::DiagnosticCode(pub alloc::borrow::Cow<'static, str>)
impl vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::as_str(&self) -> &str
pub const fn vyre_driver::diagnostics::DiagnosticCode::new(code: &'static str) -> Self
impl core::clone::Clone for vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::clone(&self) -> vyre_driver::diagnostics::DiagnosticCode
impl core::cmp::Eq for vyre_driver::diagnostics::DiagnosticCode
impl core::cmp::PartialEq for vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::eq(&self, other: &vyre_driver::diagnostics::DiagnosticCode) -> bool
impl core::fmt::Debug for vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::StructuralPartialEq for vyre_driver::diagnostics::DiagnosticCode
impl serde_core::ser::Serialize for vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::diagnostics::DiagnosticCode
impl core::marker::Send for vyre_driver::diagnostics::DiagnosticCode
impl core::marker::Sync for vyre_driver::diagnostics::DiagnosticCode
impl core::marker::Unpin for vyre_driver::diagnostics::DiagnosticCode
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::diagnostics::DiagnosticCode
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::diagnostics::DiagnosticCode
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::diagnostics::DiagnosticCode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::diagnostics::DiagnosticCode::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::diagnostics::DiagnosticCode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::diagnostics::DiagnosticCode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::diagnostics::DiagnosticCode::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::diagnostics::DiagnosticCode::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::diagnostics::DiagnosticCode where U: core::convert::From<T>
pub fn vyre_driver::diagnostics::DiagnosticCode::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::diagnostics::DiagnosticCode where U: core::convert::Into<T>
pub type vyre_driver::diagnostics::DiagnosticCode::Error = core::convert::Infallible
pub fn vyre_driver::diagnostics::DiagnosticCode::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::diagnostics::DiagnosticCode where U: core::convert::TryFrom<T>
pub type vyre_driver::diagnostics::DiagnosticCode::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::diagnostics::DiagnosticCode::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::diagnostics::DiagnosticCode where T: core::clone::Clone
pub type vyre_driver::diagnostics::DiagnosticCode::Owned = T
pub fn vyre_driver::diagnostics::DiagnosticCode::clone_into(&self, target: &mut T)
pub fn vyre_driver::diagnostics::DiagnosticCode::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::diagnostics::DiagnosticCode where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::diagnostics::DiagnosticCode::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::diagnostics::DiagnosticCode where T: 'static + ?core::marker::Sized
pub fn vyre_driver::diagnostics::DiagnosticCode::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::diagnostics::DiagnosticCode where T: ?core::marker::Sized
pub fn vyre_driver::diagnostics::DiagnosticCode::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::diagnostics::DiagnosticCode where T: ?core::marker::Sized
pub fn vyre_driver::diagnostics::DiagnosticCode::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::diagnostics::DiagnosticCode where T: core::clone::Clone
pub unsafe fn vyre_driver::diagnostics::DiagnosticCode::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::diagnostics::DiagnosticCode where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::diagnostics::DiagnosticCode
impl<T> tracing::instrument::WithSubscriber for vyre_driver::diagnostics::DiagnosticCode
impl<T> typenum::type_operators::Same for vyre_driver::diagnostics::DiagnosticCode
pub type vyre_driver::diagnostics::DiagnosticCode::Output = T
pub struct vyre_driver::diagnostics::OpLocation
pub vyre_driver::diagnostics::OpLocation::attr_name: core::option::Option<alloc::borrow::Cow<'static, str>>
pub vyre_driver::diagnostics::OpLocation::op_id: alloc::borrow::Cow<'static, str>
pub vyre_driver::diagnostics::OpLocation::operand_idx: core::option::Option<u32>
impl vyre_driver::diagnostics::OpLocation
pub fn vyre_driver::diagnostics::OpLocation::op(op_id: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::diagnostics::OpLocation::with_attr(self, name: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::diagnostics::OpLocation::with_operand(self, idx: u32) -> Self
impl core::clone::Clone for vyre_driver::diagnostics::OpLocation
pub fn vyre_driver::diagnostics::OpLocation::clone(&self) -> vyre_driver::diagnostics::OpLocation
impl core::cmp::Eq for vyre_driver::diagnostics::OpLocation
impl core::cmp::PartialEq for vyre_driver::diagnostics::OpLocation
pub fn vyre_driver::diagnostics::OpLocation::eq(&self, other: &vyre_driver::diagnostics::OpLocation) -> bool
impl core::fmt::Debug for vyre_driver::diagnostics::OpLocation
pub fn vyre_driver::diagnostics::OpLocation::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::diagnostics::OpLocation
impl serde_core::ser::Serialize for vyre_driver::diagnostics::OpLocation
pub fn vyre_driver::diagnostics::OpLocation::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::diagnostics::OpLocation
pub fn vyre_driver::diagnostics::OpLocation::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::diagnostics::OpLocation
impl core::marker::Send for vyre_driver::diagnostics::OpLocation
impl core::marker::Sync for vyre_driver::diagnostics::OpLocation
impl core::marker::Unpin for vyre_driver::diagnostics::OpLocation
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::diagnostics::OpLocation
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::diagnostics::OpLocation
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::diagnostics::OpLocation where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::diagnostics::OpLocation::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::diagnostics::OpLocation where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::diagnostics::OpLocation where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::diagnostics::OpLocation::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::diagnostics::OpLocation::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::diagnostics::OpLocation where U: core::convert::From<T>
pub fn vyre_driver::diagnostics::OpLocation::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::diagnostics::OpLocation where U: core::convert::Into<T>
pub type vyre_driver::diagnostics::OpLocation::Error = core::convert::Infallible
pub fn vyre_driver::diagnostics::OpLocation::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::diagnostics::OpLocation where U: core::convert::TryFrom<T>
pub type vyre_driver::diagnostics::OpLocation::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::diagnostics::OpLocation::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::diagnostics::OpLocation where T: core::clone::Clone
pub type vyre_driver::diagnostics::OpLocation::Owned = T
pub fn vyre_driver::diagnostics::OpLocation::clone_into(&self, target: &mut T)
pub fn vyre_driver::diagnostics::OpLocation::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::diagnostics::OpLocation where T: 'static + ?core::marker::Sized
pub fn vyre_driver::diagnostics::OpLocation::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::diagnostics::OpLocation where T: ?core::marker::Sized
pub fn vyre_driver::diagnostics::OpLocation::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::diagnostics::OpLocation where T: ?core::marker::Sized
pub fn vyre_driver::diagnostics::OpLocation::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::diagnostics::OpLocation where T: core::clone::Clone
pub unsafe fn vyre_driver::diagnostics::OpLocation::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::diagnostics::OpLocation
pub fn vyre_driver::diagnostics::OpLocation::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::diagnostics::OpLocation where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::diagnostics::OpLocation
impl<T> tracing::instrument::WithSubscriber for vyre_driver::diagnostics::OpLocation
impl<T> typenum::type_operators::Same for vyre_driver::diagnostics::OpLocation
pub type vyre_driver::diagnostics::OpLocation::Output = T
pub mod vyre_driver::fusion
#[non_exhaustive] pub enum vyre_driver::fusion::FusionDecision
pub vyre_driver::fusion::FusionDecision::Accept
pub vyre_driver::fusion::FusionDecision::NoPipelineDependency
pub vyre_driver::fusion::FusionDecision::OutputConsumedElsewhere
pub vyre_driver::fusion::FusionDecision::SharedMemoryBudget
pub vyre_driver::fusion::FusionDecision::SharedMemoryBudget::cap: u32
pub vyre_driver::fusion::FusionDecision::SharedMemoryBudget::needed: u32
pub vyre_driver::fusion::FusionDecision::WorkgroupSizeMismatch
pub vyre_driver::fusion::FusionDecision::WorkgroupSizeMismatch::downstream: [u32; 3]
pub vyre_driver::fusion::FusionDecision::WorkgroupSizeMismatch::upstream: [u32; 3]
impl core::clone::Clone for vyre_driver::fusion::FusionDecision
pub fn vyre_driver::fusion::FusionDecision::clone(&self) -> vyre_driver::fusion::FusionDecision
impl core::cmp::Eq for vyre_driver::fusion::FusionDecision
impl core::cmp::PartialEq for vyre_driver::fusion::FusionDecision
pub fn vyre_driver::fusion::FusionDecision::eq(&self, other: &vyre_driver::fusion::FusionDecision) -> bool
impl core::fmt::Debug for vyre_driver::fusion::FusionDecision
pub fn vyre_driver::fusion::FusionDecision::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::fusion::FusionDecision
impl core::marker::Freeze for vyre_driver::fusion::FusionDecision
impl core::marker::Send for vyre_driver::fusion::FusionDecision
impl core::marker::Sync for vyre_driver::fusion::FusionDecision
impl core::marker::Unpin for vyre_driver::fusion::FusionDecision
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::fusion::FusionDecision
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::fusion::FusionDecision
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::fusion::FusionDecision where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::fusion::FusionDecision::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::fusion::FusionDecision where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::fusion::FusionDecision where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::fusion::FusionDecision::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::fusion::FusionDecision::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::fusion::FusionDecision where U: core::convert::From<T>
pub fn vyre_driver::fusion::FusionDecision::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::fusion::FusionDecision where U: core::convert::Into<T>
pub type vyre_driver::fusion::FusionDecision::Error = core::convert::Infallible
pub fn vyre_driver::fusion::FusionDecision::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::fusion::FusionDecision where U: core::convert::TryFrom<T>
pub type vyre_driver::fusion::FusionDecision::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::fusion::FusionDecision::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::fusion::FusionDecision where T: core::clone::Clone
pub type vyre_driver::fusion::FusionDecision::Owned = T
pub fn vyre_driver::fusion::FusionDecision::clone_into(&self, target: &mut T)
pub fn vyre_driver::fusion::FusionDecision::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::fusion::FusionDecision where T: 'static + ?core::marker::Sized
pub fn vyre_driver::fusion::FusionDecision::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::fusion::FusionDecision where T: ?core::marker::Sized
pub fn vyre_driver::fusion::FusionDecision::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::fusion::FusionDecision where T: ?core::marker::Sized
pub fn vyre_driver::fusion::FusionDecision::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::fusion::FusionDecision where T: core::clone::Clone
pub unsafe fn vyre_driver::fusion::FusionDecision::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::fusion::FusionDecision
pub fn vyre_driver::fusion::FusionDecision::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::fusion::FusionDecision
impl<T> tracing::instrument::WithSubscriber for vyre_driver::fusion::FusionDecision
impl<T> typenum::type_operators::Same for vyre_driver::fusion::FusionDecision
pub type vyre_driver::fusion::FusionDecision::Output = T
pub struct vyre_driver::fusion::DispatchShape
pub vyre_driver::fusion::DispatchShape::id: &'static str
pub vyre_driver::fusion::DispatchShape::inputs: alloc::vec::Vec<&'static str>
pub vyre_driver::fusion::DispatchShape::outputs: alloc::vec::Vec<&'static str>
pub vyre_driver::fusion::DispatchShape::shared_memory_bytes: u32
pub vyre_driver::fusion::DispatchShape::specs: vyre_driver::specialization::SpecMap
pub vyre_driver::fusion::DispatchShape::workgroup_size: [u32; 3]
impl core::clone::Clone for vyre_driver::fusion::DispatchShape
pub fn vyre_driver::fusion::DispatchShape::clone(&self) -> vyre_driver::fusion::DispatchShape
impl core::fmt::Debug for vyre_driver::fusion::DispatchShape
pub fn vyre_driver::fusion::DispatchShape::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::fusion::DispatchShape
impl core::marker::Send for vyre_driver::fusion::DispatchShape
impl core::marker::Sync for vyre_driver::fusion::DispatchShape
impl core::marker::Unpin for vyre_driver::fusion::DispatchShape
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::fusion::DispatchShape
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::fusion::DispatchShape
impl<T, U> core::convert::Into<U> for vyre_driver::fusion::DispatchShape where U: core::convert::From<T>
pub fn vyre_driver::fusion::DispatchShape::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::fusion::DispatchShape where U: core::convert::Into<T>
pub type vyre_driver::fusion::DispatchShape::Error = core::convert::Infallible
pub fn vyre_driver::fusion::DispatchShape::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::fusion::DispatchShape where U: core::convert::TryFrom<T>
pub type vyre_driver::fusion::DispatchShape::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::fusion::DispatchShape::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::fusion::DispatchShape where T: core::clone::Clone
pub type vyre_driver::fusion::DispatchShape::Owned = T
pub fn vyre_driver::fusion::DispatchShape::clone_into(&self, target: &mut T)
pub fn vyre_driver::fusion::DispatchShape::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::fusion::DispatchShape where T: 'static + ?core::marker::Sized
pub fn vyre_driver::fusion::DispatchShape::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::fusion::DispatchShape where T: ?core::marker::Sized
pub fn vyre_driver::fusion::DispatchShape::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::fusion::DispatchShape where T: ?core::marker::Sized
pub fn vyre_driver::fusion::DispatchShape::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::fusion::DispatchShape where T: core::clone::Clone
pub unsafe fn vyre_driver::fusion::DispatchShape::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::fusion::DispatchShape
pub fn vyre_driver::fusion::DispatchShape::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::fusion::DispatchShape
impl<T> tracing::instrument::WithSubscriber for vyre_driver::fusion::DispatchShape
impl<T> typenum::type_operators::Same for vyre_driver::fusion::DispatchShape
pub type vyre_driver::fusion::DispatchShape::Output = T
pub struct vyre_driver::fusion::FusionCaps
pub vyre_driver::fusion::FusionCaps::max_invocations_per_workgroup: u32
pub vyre_driver::fusion::FusionCaps::max_shared_memory_bytes: u32
impl vyre_driver::fusion::FusionCaps
pub const fn vyre_driver::fusion::FusionCaps::rtx_5090() -> Self
impl core::clone::Clone for vyre_driver::fusion::FusionCaps
pub fn vyre_driver::fusion::FusionCaps::clone(&self) -> vyre_driver::fusion::FusionCaps
impl core::default::Default for vyre_driver::fusion::FusionCaps
pub fn vyre_driver::fusion::FusionCaps::default() -> Self
impl core::fmt::Debug for vyre_driver::fusion::FusionCaps
pub fn vyre_driver::fusion::FusionCaps::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::fusion::FusionCaps
impl core::marker::Freeze for vyre_driver::fusion::FusionCaps
impl core::marker::Send for vyre_driver::fusion::FusionCaps
impl core::marker::Sync for vyre_driver::fusion::FusionCaps
impl core::marker::Unpin for vyre_driver::fusion::FusionCaps
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::fusion::FusionCaps
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::fusion::FusionCaps
impl<T, U> core::convert::Into<U> for vyre_driver::fusion::FusionCaps where U: core::convert::From<T>
pub fn vyre_driver::fusion::FusionCaps::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::fusion::FusionCaps where U: core::convert::Into<T>
pub type vyre_driver::fusion::FusionCaps::Error = core::convert::Infallible
pub fn vyre_driver::fusion::FusionCaps::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::fusion::FusionCaps where U: core::convert::TryFrom<T>
pub type vyre_driver::fusion::FusionCaps::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::fusion::FusionCaps::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::fusion::FusionCaps where T: core::clone::Clone
pub type vyre_driver::fusion::FusionCaps::Owned = T
pub fn vyre_driver::fusion::FusionCaps::clone_into(&self, target: &mut T)
pub fn vyre_driver::fusion::FusionCaps::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::fusion::FusionCaps where T: 'static + ?core::marker::Sized
pub fn vyre_driver::fusion::FusionCaps::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::fusion::FusionCaps where T: ?core::marker::Sized
pub fn vyre_driver::fusion::FusionCaps::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::fusion::FusionCaps where T: ?core::marker::Sized
pub fn vyre_driver::fusion::FusionCaps::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::fusion::FusionCaps where T: core::clone::Clone
pub unsafe fn vyre_driver::fusion::FusionCaps::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::fusion::FusionCaps
pub fn vyre_driver::fusion::FusionCaps::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::fusion::FusionCaps
impl<T> tracing::instrument::WithSubscriber for vyre_driver::fusion::FusionCaps
impl<T> typenum::type_operators::Same for vyre_driver::fusion::FusionCaps
pub type vyre_driver::fusion::FusionCaps::Output = T
pub struct vyre_driver::fusion::FusionPass
impl vyre_driver::fusion::FusionPass
pub fn vyre_driver::fusion::FusionPass::decide(upstream: &vyre_driver::fusion::DispatchShape, downstream: &vyre_driver::fusion::DispatchShape, caps: vyre_driver::fusion::FusionCaps, other_consumers: &[&str]) -> vyre_driver::fusion::FusionDecision
impl core::marker::Freeze for vyre_driver::fusion::FusionPass
impl core::marker::Send for vyre_driver::fusion::FusionPass
impl core::marker::Sync for vyre_driver::fusion::FusionPass
impl core::marker::Unpin for vyre_driver::fusion::FusionPass
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::fusion::FusionPass
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::fusion::FusionPass
impl<T, U> core::convert::Into<U> for vyre_driver::fusion::FusionPass where U: core::convert::From<T>
pub fn vyre_driver::fusion::FusionPass::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::fusion::FusionPass where U: core::convert::Into<T>
pub type vyre_driver::fusion::FusionPass::Error = core::convert::Infallible
pub fn vyre_driver::fusion::FusionPass::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::fusion::FusionPass where U: core::convert::TryFrom<T>
pub type vyre_driver::fusion::FusionPass::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::fusion::FusionPass::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::fusion::FusionPass where T: 'static + ?core::marker::Sized
pub fn vyre_driver::fusion::FusionPass::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::fusion::FusionPass where T: ?core::marker::Sized
pub fn vyre_driver::fusion::FusionPass::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::fusion::FusionPass where T: ?core::marker::Sized
pub fn vyre_driver::fusion::FusionPass::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::fusion::FusionPass
pub fn vyre_driver::fusion::FusionPass::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::fusion::FusionPass
impl<T> tracing::instrument::WithSubscriber for vyre_driver::fusion::FusionPass
impl<T> typenum::type_operators::Same for vyre_driver::fusion::FusionPass
pub type vyre_driver::fusion::FusionPass::Output = T
pub mod vyre_driver::observability
pub struct vyre_driver::observability::DriverObservability
pub vyre_driver::observability::DriverObservability::decision_buckets: alloc::vec::Vec<(&'static str, u64)>
pub vyre_driver::observability::DriverObservability::substrate_calls: alloc::vec::Vec<(&'static str, u64)>
pub vyre_driver::observability::DriverObservability::substrate_total_calls: u64
impl vyre_driver::observability::DriverObservability
pub fn vyre_driver::observability::DriverObservability::snapshot() -> Self
pub fn vyre_driver::observability::DriverObservability::to_prometheus(&self) -> alloc::string::String
impl core::clone::Clone for vyre_driver::observability::DriverObservability
pub fn vyre_driver::observability::DriverObservability::clone(&self) -> vyre_driver::observability::DriverObservability
impl core::fmt::Debug for vyre_driver::observability::DriverObservability
pub fn vyre_driver::observability::DriverObservability::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::observability::DriverObservability
impl core::marker::Send for vyre_driver::observability::DriverObservability
impl core::marker::Sync for vyre_driver::observability::DriverObservability
impl core::marker::Unpin for vyre_driver::observability::DriverObservability
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::observability::DriverObservability
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::observability::DriverObservability
impl<T, U> core::convert::Into<U> for vyre_driver::observability::DriverObservability where U: core::convert::From<T>
pub fn vyre_driver::observability::DriverObservability::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::observability::DriverObservability where U: core::convert::Into<T>
pub type vyre_driver::observability::DriverObservability::Error = core::convert::Infallible
pub fn vyre_driver::observability::DriverObservability::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::observability::DriverObservability where U: core::convert::TryFrom<T>
pub type vyre_driver::observability::DriverObservability::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::observability::DriverObservability::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::observability::DriverObservability where T: core::clone::Clone
pub type vyre_driver::observability::DriverObservability::Owned = T
pub fn vyre_driver::observability::DriverObservability::clone_into(&self, target: &mut T)
pub fn vyre_driver::observability::DriverObservability::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::observability::DriverObservability where T: 'static + ?core::marker::Sized
pub fn vyre_driver::observability::DriverObservability::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::observability::DriverObservability where T: ?core::marker::Sized
pub fn vyre_driver::observability::DriverObservability::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::observability::DriverObservability where T: ?core::marker::Sized
pub fn vyre_driver::observability::DriverObservability::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::observability::DriverObservability where T: core::clone::Clone
pub unsafe fn vyre_driver::observability::DriverObservability::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::observability::DriverObservability
pub fn vyre_driver::observability::DriverObservability::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::observability::DriverObservability
impl<T> tracing::instrument::WithSubscriber for vyre_driver::observability::DriverObservability
impl<T> typenum::type_operators::Same for vyre_driver::observability::DriverObservability
pub type vyre_driver::observability::DriverObservability::Output = T
pub trait vyre_driver::observability::BackendObservabilityProvider
pub fn vyre_driver::observability::BackendObservabilityProvider::backend_metrics(&self) -> alloc::vec::Vec<(&'static str, u64)>
pub mod vyre_driver::persistent
pub enum vyre_driver::persistent::PersistentThreadMode
pub vyre_driver::persistent::PersistentThreadMode::Auto
pub vyre_driver::persistent::PersistentThreadMode::Disable
pub vyre_driver::persistent::PersistentThreadMode::Force
impl core::clone::Clone for vyre_driver::persistent::PersistentThreadMode
pub fn vyre_driver::persistent::PersistentThreadMode::clone(&self) -> vyre_driver::persistent::PersistentThreadMode
impl core::cmp::Eq for vyre_driver::persistent::PersistentThreadMode
impl core::cmp::PartialEq for vyre_driver::persistent::PersistentThreadMode
pub fn vyre_driver::persistent::PersistentThreadMode::eq(&self, other: &vyre_driver::persistent::PersistentThreadMode) -> bool
impl core::default::Default for vyre_driver::persistent::PersistentThreadMode
pub fn vyre_driver::persistent::PersistentThreadMode::default() -> vyre_driver::persistent::PersistentThreadMode
impl core::fmt::Debug for vyre_driver::persistent::PersistentThreadMode
pub fn vyre_driver::persistent::PersistentThreadMode::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::persistent::PersistentThreadMode
impl core::marker::StructuralPartialEq for vyre_driver::persistent::PersistentThreadMode
impl core::marker::Freeze for vyre_driver::persistent::PersistentThreadMode
impl core::marker::Send for vyre_driver::persistent::PersistentThreadMode
impl core::marker::Sync for vyre_driver::persistent::PersistentThreadMode
impl core::marker::Unpin for vyre_driver::persistent::PersistentThreadMode
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::persistent::PersistentThreadMode
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::persistent::PersistentThreadMode
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::persistent::PersistentThreadMode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::persistent::PersistentThreadMode::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::persistent::PersistentThreadMode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::persistent::PersistentThreadMode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::persistent::PersistentThreadMode::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::persistent::PersistentThreadMode::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::persistent::PersistentThreadMode where U: core::convert::From<T>
pub fn vyre_driver::persistent::PersistentThreadMode::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::persistent::PersistentThreadMode where U: core::convert::Into<T>
pub type vyre_driver::persistent::PersistentThreadMode::Error = core::convert::Infallible
pub fn vyre_driver::persistent::PersistentThreadMode::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::persistent::PersistentThreadMode where U: core::convert::TryFrom<T>
pub type vyre_driver::persistent::PersistentThreadMode::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::persistent::PersistentThreadMode::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::persistent::PersistentThreadMode where T: core::clone::Clone
pub type vyre_driver::persistent::PersistentThreadMode::Owned = T
pub fn vyre_driver::persistent::PersistentThreadMode::clone_into(&self, target: &mut T)
pub fn vyre_driver::persistent::PersistentThreadMode::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::persistent::PersistentThreadMode where T: 'static + ?core::marker::Sized
pub fn vyre_driver::persistent::PersistentThreadMode::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::persistent::PersistentThreadMode where T: ?core::marker::Sized
pub fn vyre_driver::persistent::PersistentThreadMode::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::persistent::PersistentThreadMode where T: ?core::marker::Sized
pub fn vyre_driver::persistent::PersistentThreadMode::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::persistent::PersistentThreadMode where T: core::clone::Clone
pub unsafe fn vyre_driver::persistent::PersistentThreadMode::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::persistent::PersistentThreadMode
pub fn vyre_driver::persistent::PersistentThreadMode::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::persistent::PersistentThreadMode
impl<T> tracing::instrument::WithSubscriber for vyre_driver::persistent::PersistentThreadMode
impl<T> typenum::type_operators::Same for vyre_driver::persistent::PersistentThreadMode
pub type vyre_driver::persistent::PersistentThreadMode::Output = T
pub struct vyre_driver::persistent::PersistentEngine
impl vyre_driver::persistent::PersistentEngine
pub fn vyre_driver::persistent::PersistentEngine::claim(&self) -> core::option::Option<vyre_driver::persistent::WorkItem>
pub fn vyre_driver::persistent::PersistentEngine::enqueue(&self, item: vyre_driver::persistent::WorkItem) -> core::result::Result<u32, vyre_driver::persistent::QueueFull>
pub fn vyre_driver::persistent::PersistentEngine::head(&self) -> u32
pub fn vyre_driver::persistent::PersistentEngine::in_flight(&self) -> u32
pub fn vyre_driver::persistent::PersistentEngine::is_done(&self, slot_idx: u32) -> bool
pub fn vyre_driver::persistent::PersistentEngine::mark_done(&self, slot_idx: u32)
pub fn vyre_driver::persistent::PersistentEngine::new(ring_size: u32) -> Self
pub fn vyre_driver::persistent::PersistentEngine::ring_size(&self) -> u32
pub fn vyre_driver::persistent::PersistentEngine::tail(&self) -> u32
impl core::fmt::Debug for vyre_driver::persistent::PersistentEngine
pub fn vyre_driver::persistent::PersistentEngine::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl !core::marker::Freeze for vyre_driver::persistent::PersistentEngine
impl core::marker::Send for vyre_driver::persistent::PersistentEngine
impl core::marker::Sync for vyre_driver::persistent::PersistentEngine
impl core::marker::Unpin for vyre_driver::persistent::PersistentEngine
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::persistent::PersistentEngine
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::persistent::PersistentEngine
impl<T, U> core::convert::Into<U> for vyre_driver::persistent::PersistentEngine where U: core::convert::From<T>
pub fn vyre_driver::persistent::PersistentEngine::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::persistent::PersistentEngine where U: core::convert::Into<T>
pub type vyre_driver::persistent::PersistentEngine::Error = core::convert::Infallible
pub fn vyre_driver::persistent::PersistentEngine::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::persistent::PersistentEngine where U: core::convert::TryFrom<T>
pub type vyre_driver::persistent::PersistentEngine::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::persistent::PersistentEngine::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::persistent::PersistentEngine where T: 'static + ?core::marker::Sized
pub fn vyre_driver::persistent::PersistentEngine::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::persistent::PersistentEngine where T: ?core::marker::Sized
pub fn vyre_driver::persistent::PersistentEngine::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::persistent::PersistentEngine where T: ?core::marker::Sized
pub fn vyre_driver::persistent::PersistentEngine::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::persistent::PersistentEngine
pub fn vyre_driver::persistent::PersistentEngine::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::persistent::PersistentEngine
impl<T> tracing::instrument::WithSubscriber for vyre_driver::persistent::PersistentEngine
impl<T> typenum::type_operators::Same for vyre_driver::persistent::PersistentEngine
pub type vyre_driver::persistent::PersistentEngine::Output = T
pub struct vyre_driver::persistent::QueueFull
impl core::clone::Clone for vyre_driver::persistent::QueueFull
pub fn vyre_driver::persistent::QueueFull::clone(&self) -> vyre_driver::persistent::QueueFull
impl core::cmp::Eq for vyre_driver::persistent::QueueFull
impl core::cmp::PartialEq for vyre_driver::persistent::QueueFull
pub fn vyre_driver::persistent::QueueFull::eq(&self, other: &vyre_driver::persistent::QueueFull) -> bool
impl core::error::Error for vyre_driver::persistent::QueueFull
impl core::fmt::Debug for vyre_driver::persistent::QueueFull
pub fn vyre_driver::persistent::QueueFull::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::persistent::QueueFull
pub fn vyre_driver::persistent::QueueFull::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::persistent::QueueFull
impl core::marker::StructuralPartialEq for vyre_driver::persistent::QueueFull
impl core::marker::Freeze for vyre_driver::persistent::QueueFull
impl core::marker::Send for vyre_driver::persistent::QueueFull
impl core::marker::Sync for vyre_driver::persistent::QueueFull
impl core::marker::Unpin for vyre_driver::persistent::QueueFull
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::persistent::QueueFull
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::persistent::QueueFull
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::persistent::QueueFull where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::persistent::QueueFull::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::persistent::QueueFull where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::persistent::QueueFull where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::persistent::QueueFull::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::persistent::QueueFull::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::persistent::QueueFull where U: core::convert::From<T>
pub fn vyre_driver::persistent::QueueFull::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::persistent::QueueFull where U: core::convert::Into<T>
pub type vyre_driver::persistent::QueueFull::Error = core::convert::Infallible
pub fn vyre_driver::persistent::QueueFull::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::persistent::QueueFull where U: core::convert::TryFrom<T>
pub type vyre_driver::persistent::QueueFull::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::persistent::QueueFull::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::persistent::QueueFull where T: core::clone::Clone
pub type vyre_driver::persistent::QueueFull::Owned = T
pub fn vyre_driver::persistent::QueueFull::clone_into(&self, target: &mut T)
pub fn vyre_driver::persistent::QueueFull::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::persistent::QueueFull where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::persistent::QueueFull::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::persistent::QueueFull where T: 'static + ?core::marker::Sized
pub fn vyre_driver::persistent::QueueFull::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::persistent::QueueFull where T: ?core::marker::Sized
pub fn vyre_driver::persistent::QueueFull::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::persistent::QueueFull where T: ?core::marker::Sized
pub fn vyre_driver::persistent::QueueFull::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::persistent::QueueFull where T: core::clone::Clone
pub unsafe fn vyre_driver::persistent::QueueFull::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::persistent::QueueFull
pub fn vyre_driver::persistent::QueueFull::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::persistent::QueueFull
impl<T> tracing::instrument::WithSubscriber for vyre_driver::persistent::QueueFull
impl<T> typenum::type_operators::Same for vyre_driver::persistent::QueueFull
pub type vyre_driver::persistent::QueueFull::Output = T
pub struct vyre_driver::persistent::RingAtomics
pub vyre_driver::persistent::RingAtomics::done: alloc::vec::Vec<core::sync::atomic::AtomicU32>
pub vyre_driver::persistent::RingAtomics::head: core::sync::atomic::AtomicU32
pub vyre_driver::persistent::RingAtomics::tail: core::sync::atomic::AtomicU32
impl core::fmt::Debug for vyre_driver::persistent::RingAtomics
pub fn vyre_driver::persistent::RingAtomics::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl !core::marker::Freeze for vyre_driver::persistent::RingAtomics
impl core::marker::Send for vyre_driver::persistent::RingAtomics
impl core::marker::Sync for vyre_driver::persistent::RingAtomics
impl core::marker::Unpin for vyre_driver::persistent::RingAtomics
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::persistent::RingAtomics
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::persistent::RingAtomics
impl<T, U> core::convert::Into<U> for vyre_driver::persistent::RingAtomics where U: core::convert::From<T>
pub fn vyre_driver::persistent::RingAtomics::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::persistent::RingAtomics where U: core::convert::Into<T>
pub type vyre_driver::persistent::RingAtomics::Error = core::convert::Infallible
pub fn vyre_driver::persistent::RingAtomics::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::persistent::RingAtomics where U: core::convert::TryFrom<T>
pub type vyre_driver::persistent::RingAtomics::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::persistent::RingAtomics::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::persistent::RingAtomics where T: 'static + ?core::marker::Sized
pub fn vyre_driver::persistent::RingAtomics::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::persistent::RingAtomics where T: ?core::marker::Sized
pub fn vyre_driver::persistent::RingAtomics::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::persistent::RingAtomics where T: ?core::marker::Sized
pub fn vyre_driver::persistent::RingAtomics::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::persistent::RingAtomics
pub fn vyre_driver::persistent::RingAtomics::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::persistent::RingAtomics
impl<T> tracing::instrument::WithSubscriber for vyre_driver::persistent::RingAtomics
impl<T> typenum::type_operators::Same for vyre_driver::persistent::RingAtomics
pub type vyre_driver::persistent::RingAtomics::Output = T
#[repr(C)] pub struct vyre_driver::persistent::WorkItem
pub vyre_driver::persistent::WorkItem::correlation: u32
pub vyre_driver::persistent::WorkItem::input_len: u32
pub vyre_driver::persistent::WorkItem::input_offset: u32
pub vyre_driver::persistent::WorkItem::rule_set_id: u32
impl core::clone::Clone for vyre_driver::persistent::WorkItem
pub fn vyre_driver::persistent::WorkItem::clone(&self) -> vyre_driver::persistent::WorkItem
impl core::cmp::Eq for vyre_driver::persistent::WorkItem
impl core::cmp::PartialEq for vyre_driver::persistent::WorkItem
pub fn vyre_driver::persistent::WorkItem::eq(&self, other: &vyre_driver::persistent::WorkItem) -> bool
impl core::fmt::Debug for vyre_driver::persistent::WorkItem
pub fn vyre_driver::persistent::WorkItem::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::persistent::WorkItem
impl core::marker::StructuralPartialEq for vyre_driver::persistent::WorkItem
impl core::marker::Freeze for vyre_driver::persistent::WorkItem
impl core::marker::Send for vyre_driver::persistent::WorkItem
impl core::marker::Sync for vyre_driver::persistent::WorkItem
impl core::marker::Unpin for vyre_driver::persistent::WorkItem
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::persistent::WorkItem
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::persistent::WorkItem
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::persistent::WorkItem where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::persistent::WorkItem::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::persistent::WorkItem where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::persistent::WorkItem where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::persistent::WorkItem::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::persistent::WorkItem::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::persistent::WorkItem where U: core::convert::From<T>
pub fn vyre_driver::persistent::WorkItem::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::persistent::WorkItem where U: core::convert::Into<T>
pub type vyre_driver::persistent::WorkItem::Error = core::convert::Infallible
pub fn vyre_driver::persistent::WorkItem::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::persistent::WorkItem where U: core::convert::TryFrom<T>
pub type vyre_driver::persistent::WorkItem::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::persistent::WorkItem::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::persistent::WorkItem where T: core::clone::Clone
pub type vyre_driver::persistent::WorkItem::Owned = T
pub fn vyre_driver::persistent::WorkItem::clone_into(&self, target: &mut T)
pub fn vyre_driver::persistent::WorkItem::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::persistent::WorkItem where T: 'static + ?core::marker::Sized
pub fn vyre_driver::persistent::WorkItem::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::persistent::WorkItem where T: ?core::marker::Sized
pub fn vyre_driver::persistent::WorkItem::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::persistent::WorkItem where T: ?core::marker::Sized
pub fn vyre_driver::persistent::WorkItem::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::persistent::WorkItem where T: core::clone::Clone
pub unsafe fn vyre_driver::persistent::WorkItem::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::persistent::WorkItem
pub fn vyre_driver::persistent::WorkItem::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::persistent::WorkItem
impl<T> tracing::instrument::WithSubscriber for vyre_driver::persistent::WorkItem
impl<T> typenum::type_operators::Same for vyre_driver::persistent::WorkItem
pub type vyre_driver::persistent::WorkItem::Output = T
pub mod vyre_driver::pipeline
pub mod vyre_driver::pipeline::on_disk
pub enum vyre_driver::pipeline::on_disk::CacheError
pub vyre_driver::pipeline::on_disk::CacheError::Io
pub vyre_driver::pipeline::on_disk::CacheError::Io::path: std::path::PathBuf
pub vyre_driver::pipeline::on_disk::CacheError::Io::source: std::io::error::Error
pub vyre_driver::pipeline::on_disk::CacheError::Wire(alloc::string::String)
impl core::error::Error for vyre_driver::pipeline::on_disk::CacheError
pub fn vyre_driver::pipeline::on_disk::CacheError::source(&self) -> core::option::Option<&(dyn core::error::Error + 'static)>
impl core::fmt::Debug for vyre_driver::pipeline::on_disk::CacheError
pub fn vyre_driver::pipeline::on_disk::CacheError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::pipeline::on_disk::CacheError
pub fn vyre_driver::pipeline::on_disk::CacheError::fmt(&self, __formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::pipeline::on_disk::CacheError
impl core::marker::Send for vyre_driver::pipeline::on_disk::CacheError
impl core::marker::Sync for vyre_driver::pipeline::on_disk::CacheError
impl core::marker::Unpin for vyre_driver::pipeline::on_disk::CacheError
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver::pipeline::on_disk::CacheError
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver::pipeline::on_disk::CacheError
impl<T, U> core::convert::Into<U> for vyre_driver::pipeline::on_disk::CacheError where U: core::convert::From<T>
pub fn vyre_driver::pipeline::on_disk::CacheError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::pipeline::on_disk::CacheError where U: core::convert::Into<T>
pub type vyre_driver::pipeline::on_disk::CacheError::Error = core::convert::Infallible
pub fn vyre_driver::pipeline::on_disk::CacheError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::pipeline::on_disk::CacheError where U: core::convert::TryFrom<T>
pub type vyre_driver::pipeline::on_disk::CacheError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::pipeline::on_disk::CacheError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::string::ToString for vyre_driver::pipeline::on_disk::CacheError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::pipeline::on_disk::CacheError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::pipeline::on_disk::CacheError where T: 'static + ?core::marker::Sized
pub fn vyre_driver::pipeline::on_disk::CacheError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::pipeline::on_disk::CacheError where T: ?core::marker::Sized
pub fn vyre_driver::pipeline::on_disk::CacheError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::pipeline::on_disk::CacheError where T: ?core::marker::Sized
pub fn vyre_driver::pipeline::on_disk::CacheError::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::pipeline::on_disk::CacheError
pub fn vyre_driver::pipeline::on_disk::CacheError::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::pipeline::on_disk::CacheError
impl<T> tracing::instrument::WithSubscriber for vyre_driver::pipeline::on_disk::CacheError
impl<T> typenum::type_operators::Same for vyre_driver::pipeline::on_disk::CacheError
pub type vyre_driver::pipeline::on_disk::CacheError::Output = T
pub const vyre_driver::pipeline::on_disk::CACHE_EXTENSION: &str
pub fn vyre_driver::pipeline::on_disk::cache_path(cache_dir: &std::path::Path, key: &[u8; 32]) -> std::path::PathBuf
pub fn vyre_driver::pipeline::on_disk::compute_cache_key(program_wire: &[u8], backend_id: &str, driver_version: &str, device_gen: &str, feature_flags: vyre_driver::pipeline::PipelineFeatureFlags) -> [u8; 32]
pub fn vyre_driver::pipeline::on_disk::compute_cache_key_for(program: &vyre_foundation::ir_inner::model::program::core::Program, backend_id: &str, driver_version: &str, device_gen: &str, feature_flags: vyre_driver::pipeline::PipelineFeatureFlags) -> core::result::Result<[u8; 32], vyre_driver::pipeline::on_disk::CacheError>
pub fn vyre_driver::pipeline::on_disk::default_cache_dir() -> core::option::Option<std::path::PathBuf>
pub fn vyre_driver::pipeline::on_disk::load(cache_dir: &std::path::Path, key: &[u8; 32]) -> core::result::Result<core::option::Option<alloc::vec::Vec<u8>>, vyre_driver::pipeline::on_disk::CacheError>
pub fn vyre_driver::pipeline::on_disk::store(cache_dir: &std::path::Path, key: &[u8; 32], bytes: &[u8]) -> core::result::Result<(), vyre_driver::pipeline::on_disk::CacheError>
pub struct vyre_driver::pipeline::PipelineCacheKey
pub vyre_driver::pipeline::PipelineCacheKey::backend_id: vyre_spec::intrinsic_descriptor::BackendId
pub vyre_driver::pipeline::PipelineCacheKey::bind_group_layout_hash: [u8; 32]
pub vyre_driver::pipeline::PipelineCacheKey::feature_flags: vyre_driver::pipeline::PipelineFeatureFlags
pub vyre_driver::pipeline::PipelineCacheKey::push_constant_size: u32
pub vyre_driver::pipeline::PipelineCacheKey::shader_hash: [u8; 32]
pub vyre_driver::pipeline::PipelineCacheKey::version: u32
pub vyre_driver::pipeline::PipelineCacheKey::workgroup_size: [u32; 3]
impl vyre_driver::pipeline::PipelineCacheKey
pub fn vyre_driver::pipeline::PipelineCacheKey::new(shader_hash: [u8; 32], bind_group_layout_hash: [u8; 32], push_constant_size: u32, workgroup_size: [u32; 3], feature_flags: vyre_driver::pipeline::PipelineFeatureFlags, backend_id: vyre_spec::intrinsic_descriptor::BackendId) -> Self
impl core::clone::Clone for vyre_driver::pipeline::PipelineCacheKey
pub fn vyre_driver::pipeline::PipelineCacheKey::clone(&self) -> vyre_driver::pipeline::PipelineCacheKey
impl core::cmp::Eq for vyre_driver::pipeline::PipelineCacheKey
impl core::cmp::PartialEq for vyre_driver::pipeline::PipelineCacheKey
pub fn vyre_driver::pipeline::PipelineCacheKey::eq(&self, other: &vyre_driver::pipeline::PipelineCacheKey) -> bool
impl core::fmt::Debug for vyre_driver::pipeline::PipelineCacheKey
pub fn vyre_driver::pipeline::PipelineCacheKey::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::pipeline::PipelineCacheKey
pub fn vyre_driver::pipeline::PipelineCacheKey::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::StructuralPartialEq for vyre_driver::pipeline::PipelineCacheKey
impl core::marker::Freeze for vyre_driver::pipeline::PipelineCacheKey
impl core::marker::Send for vyre_driver::pipeline::PipelineCacheKey
impl core::marker::Sync for vyre_driver::pipeline::PipelineCacheKey
impl core::marker::Unpin for vyre_driver::pipeline::PipelineCacheKey
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::pipeline::PipelineCacheKey
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::pipeline::PipelineCacheKey
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::pipeline::PipelineCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineCacheKey::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pipeline::PipelineCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pipeline::PipelineCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineCacheKey::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::pipeline::PipelineCacheKey::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::pipeline::PipelineCacheKey where U: core::convert::From<T>
pub fn vyre_driver::pipeline::PipelineCacheKey::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::pipeline::PipelineCacheKey where U: core::convert::Into<T>
pub type vyre_driver::pipeline::PipelineCacheKey::Error = core::convert::Infallible
pub fn vyre_driver::pipeline::PipelineCacheKey::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::pipeline::PipelineCacheKey where U: core::convert::TryFrom<T>
pub type vyre_driver::pipeline::PipelineCacheKey::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::pipeline::PipelineCacheKey::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::pipeline::PipelineCacheKey where T: core::clone::Clone
pub type vyre_driver::pipeline::PipelineCacheKey::Owned = T
pub fn vyre_driver::pipeline::PipelineCacheKey::clone_into(&self, target: &mut T)
pub fn vyre_driver::pipeline::PipelineCacheKey::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::pipeline::PipelineCacheKey where T: 'static + ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineCacheKey::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::pipeline::PipelineCacheKey where T: ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineCacheKey::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::pipeline::PipelineCacheKey where T: ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineCacheKey::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::pipeline::PipelineCacheKey where T: core::clone::Clone
pub unsafe fn vyre_driver::pipeline::PipelineCacheKey::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::pipeline::PipelineCacheKey
pub fn vyre_driver::pipeline::PipelineCacheKey::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::pipeline::PipelineCacheKey
impl<T> tracing::instrument::WithSubscriber for vyre_driver::pipeline::PipelineCacheKey
impl<T> typenum::type_operators::Same for vyre_driver::pipeline::PipelineCacheKey
pub type vyre_driver::pipeline::PipelineCacheKey::Output = T
pub struct vyre_driver::pipeline::PipelineFeatureFlags(pub u32)
impl vyre_driver::pipeline::PipelineFeatureFlags
pub const vyre_driver::pipeline::PipelineFeatureFlags::ASYNC_COMPUTE: Self
pub const vyre_driver::pipeline::PipelineFeatureFlags::BF16: Self
pub const vyre_driver::pipeline::PipelineFeatureFlags::F16: Self
pub const vyre_driver::pipeline::PipelineFeatureFlags::INDIRECT_DISPATCH: Self
pub const vyre_driver::pipeline::PipelineFeatureFlags::PERSISTENT_THREAD: Self
pub const vyre_driver::pipeline::PipelineFeatureFlags::PUSH_CONSTANTS: Self
pub const vyre_driver::pipeline::PipelineFeatureFlags::SPECULATIVE: Self
pub const vyre_driver::pipeline::PipelineFeatureFlags::SUBGROUP_OPS: Self
pub const vyre_driver::pipeline::PipelineFeatureFlags::TENSOR_CORES: Self
pub const fn vyre_driver::pipeline::PipelineFeatureFlags::bits(self) -> u32
pub const fn vyre_driver::pipeline::PipelineFeatureFlags::contains(self, other: Self) -> bool
pub const fn vyre_driver::pipeline::PipelineFeatureFlags::empty() -> Self
pub const fn vyre_driver::pipeline::PipelineFeatureFlags::union(self, other: Self) -> Self
impl core::clone::Clone for vyre_driver::pipeline::PipelineFeatureFlags
pub fn vyre_driver::pipeline::PipelineFeatureFlags::clone(&self) -> vyre_driver::pipeline::PipelineFeatureFlags
impl core::cmp::Eq for vyre_driver::pipeline::PipelineFeatureFlags
impl core::cmp::PartialEq for vyre_driver::pipeline::PipelineFeatureFlags
pub fn vyre_driver::pipeline::PipelineFeatureFlags::eq(&self, other: &vyre_driver::pipeline::PipelineFeatureFlags) -> bool
impl core::default::Default for vyre_driver::pipeline::PipelineFeatureFlags
pub fn vyre_driver::pipeline::PipelineFeatureFlags::default() -> vyre_driver::pipeline::PipelineFeatureFlags
impl core::fmt::Debug for vyre_driver::pipeline::PipelineFeatureFlags
pub fn vyre_driver::pipeline::PipelineFeatureFlags::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::pipeline::PipelineFeatureFlags
pub fn vyre_driver::pipeline::PipelineFeatureFlags::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::pipeline::PipelineFeatureFlags
impl core::marker::StructuralPartialEq for vyre_driver::pipeline::PipelineFeatureFlags
impl serde_core::ser::Serialize for vyre_driver::pipeline::PipelineFeatureFlags
pub fn vyre_driver::pipeline::PipelineFeatureFlags::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::pipeline::PipelineFeatureFlags
pub fn vyre_driver::pipeline::PipelineFeatureFlags::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::pipeline::PipelineFeatureFlags
impl core::marker::Send for vyre_driver::pipeline::PipelineFeatureFlags
impl core::marker::Sync for vyre_driver::pipeline::PipelineFeatureFlags
impl core::marker::Unpin for vyre_driver::pipeline::PipelineFeatureFlags
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::pipeline::PipelineFeatureFlags
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::pipeline::PipelineFeatureFlags
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::pipeline::PipelineFeatureFlags where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineFeatureFlags::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pipeline::PipelineFeatureFlags where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pipeline::PipelineFeatureFlags where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineFeatureFlags::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::pipeline::PipelineFeatureFlags::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::pipeline::PipelineFeatureFlags where U: core::convert::From<T>
pub fn vyre_driver::pipeline::PipelineFeatureFlags::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::pipeline::PipelineFeatureFlags where U: core::convert::Into<T>
pub type vyre_driver::pipeline::PipelineFeatureFlags::Error = core::convert::Infallible
pub fn vyre_driver::pipeline::PipelineFeatureFlags::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::pipeline::PipelineFeatureFlags where U: core::convert::TryFrom<T>
pub type vyre_driver::pipeline::PipelineFeatureFlags::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::pipeline::PipelineFeatureFlags::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::pipeline::PipelineFeatureFlags where T: core::clone::Clone
pub type vyre_driver::pipeline::PipelineFeatureFlags::Owned = T
pub fn vyre_driver::pipeline::PipelineFeatureFlags::clone_into(&self, target: &mut T)
pub fn vyre_driver::pipeline::PipelineFeatureFlags::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::pipeline::PipelineFeatureFlags where T: 'static + ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineFeatureFlags::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::pipeline::PipelineFeatureFlags where T: ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineFeatureFlags::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::pipeline::PipelineFeatureFlags where T: ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineFeatureFlags::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::pipeline::PipelineFeatureFlags where T: core::clone::Clone
pub unsafe fn vyre_driver::pipeline::PipelineFeatureFlags::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::pipeline::PipelineFeatureFlags
pub fn vyre_driver::pipeline::PipelineFeatureFlags::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::pipeline::PipelineFeatureFlags where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::pipeline::PipelineFeatureFlags
impl<T> tracing::instrument::WithSubscriber for vyre_driver::pipeline::PipelineFeatureFlags
impl<T> typenum::type_operators::Same for vyre_driver::pipeline::PipelineFeatureFlags
pub type vyre_driver::pipeline::PipelineFeatureFlags::Output = T
pub const vyre_driver::pipeline::CURRENT_PIPELINE_CACHE_KEY_VERSION: u32
pub fn vyre_driver::pipeline::compile(backend: alloc::sync::Arc<dyn vyre_driver::VyreBackend>, program: &vyre_foundation::ir_inner::model::program::core::Program, config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::sync::Arc<dyn vyre_driver::CompiledPipeline>, vyre_driver::BackendError>
pub fn vyre_driver::pipeline::compile_shared(backend: alloc::sync::Arc<dyn vyre_driver::VyreBackend>, program: alloc::sync::Arc<vyre_foundation::ir_inner::model::program::core::Program>, config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::sync::Arc<dyn vyre_driver::CompiledPipeline>, vyre_driver::BackendError>
pub mod vyre_driver::program_walks
pub struct vyre_driver::program_walks::IndirectDispatch
pub vyre_driver::program_walks::IndirectDispatch::count_buffer: alloc::string::String
pub vyre_driver::program_walks::IndirectDispatch::count_offset: u64
impl core::clone::Clone for vyre_driver::program_walks::IndirectDispatch
pub fn vyre_driver::program_walks::IndirectDispatch::clone(&self) -> vyre_driver::program_walks::IndirectDispatch
impl core::cmp::Eq for vyre_driver::program_walks::IndirectDispatch
impl core::cmp::PartialEq for vyre_driver::program_walks::IndirectDispatch
pub fn vyre_driver::program_walks::IndirectDispatch::eq(&self, other: &vyre_driver::program_walks::IndirectDispatch) -> bool
impl core::fmt::Debug for vyre_driver::program_walks::IndirectDispatch
pub fn vyre_driver::program_walks::IndirectDispatch::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::program_walks::IndirectDispatch
impl core::marker::Freeze for vyre_driver::program_walks::IndirectDispatch
impl core::marker::Send for vyre_driver::program_walks::IndirectDispatch
impl core::marker::Sync for vyre_driver::program_walks::IndirectDispatch
impl core::marker::Unpin for vyre_driver::program_walks::IndirectDispatch
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::program_walks::IndirectDispatch
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::program_walks::IndirectDispatch
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::program_walks::IndirectDispatch where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::program_walks::IndirectDispatch::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::program_walks::IndirectDispatch where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::program_walks::IndirectDispatch where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::program_walks::IndirectDispatch::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::program_walks::IndirectDispatch::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::program_walks::IndirectDispatch where U: core::convert::From<T>
pub fn vyre_driver::program_walks::IndirectDispatch::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::program_walks::IndirectDispatch where U: core::convert::Into<T>
pub type vyre_driver::program_walks::IndirectDispatch::Error = core::convert::Infallible
pub fn vyre_driver::program_walks::IndirectDispatch::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::program_walks::IndirectDispatch where U: core::convert::TryFrom<T>
pub type vyre_driver::program_walks::IndirectDispatch::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::program_walks::IndirectDispatch::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::program_walks::IndirectDispatch where T: core::clone::Clone
pub type vyre_driver::program_walks::IndirectDispatch::Owned = T
pub fn vyre_driver::program_walks::IndirectDispatch::clone_into(&self, target: &mut T)
pub fn vyre_driver::program_walks::IndirectDispatch::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::program_walks::IndirectDispatch where T: 'static + ?core::marker::Sized
pub fn vyre_driver::program_walks::IndirectDispatch::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::program_walks::IndirectDispatch where T: ?core::marker::Sized
pub fn vyre_driver::program_walks::IndirectDispatch::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::program_walks::IndirectDispatch where T: ?core::marker::Sized
pub fn vyre_driver::program_walks::IndirectDispatch::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::program_walks::IndirectDispatch where T: core::clone::Clone
pub unsafe fn vyre_driver::program_walks::IndirectDispatch::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::program_walks::IndirectDispatch
pub fn vyre_driver::program_walks::IndirectDispatch::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::program_walks::IndirectDispatch
impl<T> tracing::instrument::WithSubscriber for vyre_driver::program_walks::IndirectDispatch
impl<T> typenum::type_operators::Same for vyre_driver::program_walks::IndirectDispatch
pub type vyre_driver::program_walks::IndirectDispatch::Output = T
pub struct vyre_driver::program_walks::OutputBindingLayout
pub vyre_driver::program_walks::OutputBindingLayout::binding: u32
pub vyre_driver::program_walks::OutputBindingLayout::layout: vyre_driver::program_walks::OutputLayout
pub vyre_driver::program_walks::OutputBindingLayout::name: alloc::sync::Arc<str>
pub vyre_driver::program_walks::OutputBindingLayout::word_count: usize
impl core::clone::Clone for vyre_driver::program_walks::OutputBindingLayout
pub fn vyre_driver::program_walks::OutputBindingLayout::clone(&self) -> vyre_driver::program_walks::OutputBindingLayout
impl core::fmt::Debug for vyre_driver::program_walks::OutputBindingLayout
pub fn vyre_driver::program_walks::OutputBindingLayout::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::program_walks::OutputBindingLayout
impl core::marker::Send for vyre_driver::program_walks::OutputBindingLayout
impl core::marker::Sync for vyre_driver::program_walks::OutputBindingLayout
impl core::marker::Unpin for vyre_driver::program_walks::OutputBindingLayout
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::program_walks::OutputBindingLayout
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::program_walks::OutputBindingLayout
impl<T, U> core::convert::Into<U> for vyre_driver::program_walks::OutputBindingLayout where U: core::convert::From<T>
pub fn vyre_driver::program_walks::OutputBindingLayout::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::program_walks::OutputBindingLayout where U: core::convert::Into<T>
pub type vyre_driver::program_walks::OutputBindingLayout::Error = core::convert::Infallible
pub fn vyre_driver::program_walks::OutputBindingLayout::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::program_walks::OutputBindingLayout where U: core::convert::TryFrom<T>
pub type vyre_driver::program_walks::OutputBindingLayout::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::program_walks::OutputBindingLayout::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::program_walks::OutputBindingLayout where T: core::clone::Clone
pub type vyre_driver::program_walks::OutputBindingLayout::Owned = T
pub fn vyre_driver::program_walks::OutputBindingLayout::clone_into(&self, target: &mut T)
pub fn vyre_driver::program_walks::OutputBindingLayout::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::program_walks::OutputBindingLayout where T: 'static + ?core::marker::Sized
pub fn vyre_driver::program_walks::OutputBindingLayout::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::program_walks::OutputBindingLayout where T: ?core::marker::Sized
pub fn vyre_driver::program_walks::OutputBindingLayout::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::program_walks::OutputBindingLayout where T: ?core::marker::Sized
pub fn vyre_driver::program_walks::OutputBindingLayout::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::program_walks::OutputBindingLayout where T: core::clone::Clone
pub unsafe fn vyre_driver::program_walks::OutputBindingLayout::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::program_walks::OutputBindingLayout
pub fn vyre_driver::program_walks::OutputBindingLayout::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::program_walks::OutputBindingLayout
impl<T> tracing::instrument::WithSubscriber for vyre_driver::program_walks::OutputBindingLayout
impl<T> typenum::type_operators::Same for vyre_driver::program_walks::OutputBindingLayout
pub type vyre_driver::program_walks::OutputBindingLayout::Output = T
pub struct vyre_driver::program_walks::OutputLayout
pub vyre_driver::program_walks::OutputLayout::copy_offset: usize
pub vyre_driver::program_walks::OutputLayout::copy_size: usize
pub vyre_driver::program_walks::OutputLayout::full_size: usize
pub vyre_driver::program_walks::OutputLayout::read_size: usize
pub vyre_driver::program_walks::OutputLayout::trim_start: usize
impl core::clone::Clone for vyre_driver::program_walks::OutputLayout
pub fn vyre_driver::program_walks::OutputLayout::clone(&self) -> vyre_driver::program_walks::OutputLayout
impl core::cmp::Eq for vyre_driver::program_walks::OutputLayout
impl core::cmp::PartialEq for vyre_driver::program_walks::OutputLayout
pub fn vyre_driver::program_walks::OutputLayout::eq(&self, other: &vyre_driver::program_walks::OutputLayout) -> bool
impl core::fmt::Debug for vyre_driver::program_walks::OutputLayout
pub fn vyre_driver::program_walks::OutputLayout::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::program_walks::OutputLayout
impl core::marker::StructuralPartialEq for vyre_driver::program_walks::OutputLayout
impl core::marker::Freeze for vyre_driver::program_walks::OutputLayout
impl core::marker::Send for vyre_driver::program_walks::OutputLayout
impl core::marker::Sync for vyre_driver::program_walks::OutputLayout
impl core::marker::Unpin for vyre_driver::program_walks::OutputLayout
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::program_walks::OutputLayout
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::program_walks::OutputLayout
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::program_walks::OutputLayout where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::program_walks::OutputLayout::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::program_walks::OutputLayout where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::program_walks::OutputLayout where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::program_walks::OutputLayout::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::program_walks::OutputLayout::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::program_walks::OutputLayout where U: core::convert::From<T>
pub fn vyre_driver::program_walks::OutputLayout::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::program_walks::OutputLayout where U: core::convert::Into<T>
pub type vyre_driver::program_walks::OutputLayout::Error = core::convert::Infallible
pub fn vyre_driver::program_walks::OutputLayout::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::program_walks::OutputLayout where U: core::convert::TryFrom<T>
pub type vyre_driver::program_walks::OutputLayout::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::program_walks::OutputLayout::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::program_walks::OutputLayout where T: core::clone::Clone
pub type vyre_driver::program_walks::OutputLayout::Owned = T
pub fn vyre_driver::program_walks::OutputLayout::clone_into(&self, target: &mut T)
pub fn vyre_driver::program_walks::OutputLayout::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::program_walks::OutputLayout where T: 'static + ?core::marker::Sized
pub fn vyre_driver::program_walks::OutputLayout::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::program_walks::OutputLayout where T: ?core::marker::Sized
pub fn vyre_driver::program_walks::OutputLayout::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::program_walks::OutputLayout where T: ?core::marker::Sized
pub fn vyre_driver::program_walks::OutputLayout::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::program_walks::OutputLayout where T: core::clone::Clone
pub unsafe fn vyre_driver::program_walks::OutputLayout::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::program_walks::OutputLayout
pub fn vyre_driver::program_walks::OutputLayout::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::program_walks::OutputLayout
impl<T> tracing::instrument::WithSubscriber for vyre_driver::program_walks::OutputLayout
impl<T> typenum::type_operators::Same for vyre_driver::program_walks::OutputLayout
pub type vyre_driver::program_walks::OutputLayout::Output = T
pub fn vyre_driver::program_walks::dispatch_element_count(bindings: &[vyre_driver::binding::Binding]) -> u32
pub fn vyre_driver::program_walks::dispatch_param_words(bindings: &[vyre_driver::binding::Binding], element_count: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::program_walks::element_size_bytes(data_type: &vyre_spec::data_type::DataType) -> core::result::Result<usize, vyre_driver::BackendError>
pub fn vyre_driver::program_walks::enforce_actual_output_budget(config: &vyre_driver::DispatchConfig, outputs: &[alloc::vec::Vec<u8>]) -> core::result::Result<(), vyre_driver::BackendError>
pub fn vyre_driver::program_walks::find_indirect_dispatch(program: &vyre_foundation::ir_inner::model::program::core::Program) -> core::result::Result<core::option::Option<vyre_driver::program_walks::IndirectDispatch>, vyre_driver::BackendError>
pub fn vyre_driver::program_walks::output_binding_layout(output: &vyre_foundation::ir_inner::model::program::buffer_decl::BufferDecl) -> core::result::Result<vyre_driver::program_walks::OutputBindingLayout, vyre_driver::BackendError>
pub fn vyre_driver::program_walks::output_binding_layouts(program: &vyre_foundation::ir_inner::model::program::core::Program) -> core::result::Result<alloc::vec::Vec<vyre_driver::program_walks::OutputBindingLayout>, vyre_driver::BackendError>
pub fn vyre_driver::program_walks::output_layout_from_program(program: &vyre_foundation::ir_inner::model::program::core::Program) -> core::result::Result<vyre_driver::program_walks::OutputLayout, vyre_driver::BackendError>
pub mod vyre_driver::registry
pub use vyre_driver::registry::AttrSchema
pub use vyre_driver::registry::AttrType
pub use vyre_driver::registry::Category
pub use vyre_driver::registry::InternedOpId
pub use vyre_driver::registry::LoweringCtx
pub use vyre_driver::registry::LoweringTable
pub use vyre_driver::registry::NativeModuleBuilder
pub use vyre_driver::registry::NativeModule
pub use vyre_driver::registry::PrimaryTextBuilder
pub use vyre_driver::registry::OpDef
pub use vyre_driver::registry::SecondaryTextBuilder
pub use vyre_driver::registry::TextModule
pub use vyre_driver::registry::ReferenceKind
pub use vyre_driver::registry::Signature
pub use vyre_driver::registry::PrimaryBinaryBuilder
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
impl core::marker::Freeze for vyre_driver::registry::dialect::Dialect
impl core::marker::Send for vyre_driver::registry::dialect::Dialect
impl core::marker::Sync for vyre_driver::registry::dialect::Dialect
impl core::marker::Unpin for vyre_driver::registry::dialect::Dialect
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::dialect::Dialect
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::dialect::Dialect
impl<T, U> core::convert::Into<U> for vyre_driver::registry::dialect::Dialect where U: core::convert::From<T>
pub fn vyre_driver::registry::dialect::Dialect::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::dialect::Dialect where U: core::convert::Into<T>
pub type vyre_driver::registry::dialect::Dialect::Error = core::convert::Infallible
pub fn vyre_driver::registry::dialect::Dialect::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::dialect::Dialect where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::dialect::Dialect::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::dialect::Dialect::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::dialect::Dialect where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::dialect::Dialect::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::dialect::Dialect where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::Dialect::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::dialect::Dialect where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::Dialect::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::dialect::Dialect
pub fn vyre_driver::registry::dialect::Dialect::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::dialect::Dialect
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::dialect::Dialect
impl<T> typenum::type_operators::Same for vyre_driver::registry::dialect::Dialect
pub type vyre_driver::registry::dialect::Dialect::Output = T
pub struct vyre_driver::registry::dialect::DialectRegistration
pub vyre_driver::registry::dialect::DialectRegistration::dialect: fn() -> vyre_driver::registry::dialect::Dialect
impl inventory::Collect for vyre_driver::registry::dialect::DialectRegistration
impl core::marker::Freeze for vyre_driver::registry::dialect::DialectRegistration
impl core::marker::Send for vyre_driver::registry::dialect::DialectRegistration
impl core::marker::Sync for vyre_driver::registry::dialect::DialectRegistration
impl core::marker::Unpin for vyre_driver::registry::dialect::DialectRegistration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::dialect::DialectRegistration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::dialect::DialectRegistration
impl<T, U> core::convert::Into<U> for vyre_driver::registry::dialect::DialectRegistration where U: core::convert::From<T>
pub fn vyre_driver::registry::dialect::DialectRegistration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::dialect::DialectRegistration where U: core::convert::Into<T>
pub type vyre_driver::registry::dialect::DialectRegistration::Error = core::convert::Infallible
pub fn vyre_driver::registry::dialect::DialectRegistration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::dialect::DialectRegistration where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::dialect::DialectRegistration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::dialect::DialectRegistration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::dialect::DialectRegistration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::dialect::DialectRegistration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::dialect::DialectRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::DialectRegistration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::dialect::DialectRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::DialectRegistration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::dialect::DialectRegistration
pub fn vyre_driver::registry::dialect::DialectRegistration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::dialect::DialectRegistration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::dialect::DialectRegistration
impl<T> typenum::type_operators::Same for vyre_driver::registry::dialect::DialectRegistration
pub type vyre_driver::registry::dialect::DialectRegistration::Output = T
pub struct vyre_driver::registry::dialect::OpBackendTarget
pub vyre_driver::registry::dialect::OpBackendTarget::op: &'static str
pub vyre_driver::registry::dialect::OpBackendTarget::target: &'static str
impl inventory::Collect for vyre_driver::registry::dialect::OpBackendTarget
impl core::marker::Freeze for vyre_driver::registry::dialect::OpBackendTarget
impl core::marker::Send for vyre_driver::registry::dialect::OpBackendTarget
impl core::marker::Sync for vyre_driver::registry::dialect::OpBackendTarget
impl core::marker::Unpin for vyre_driver::registry::dialect::OpBackendTarget
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::dialect::OpBackendTarget
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::dialect::OpBackendTarget
impl<T, U> core::convert::Into<U> for vyre_driver::registry::dialect::OpBackendTarget where U: core::convert::From<T>
pub fn vyre_driver::registry::dialect::OpBackendTarget::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::dialect::OpBackendTarget where U: core::convert::Into<T>
pub type vyre_driver::registry::dialect::OpBackendTarget::Error = core::convert::Infallible
pub fn vyre_driver::registry::dialect::OpBackendTarget::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::dialect::OpBackendTarget where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::dialect::OpBackendTarget::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::dialect::OpBackendTarget::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::dialect::OpBackendTarget where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpBackendTarget::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::dialect::OpBackendTarget where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpBackendTarget::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::dialect::OpBackendTarget where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpBackendTarget::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::dialect::OpBackendTarget
pub fn vyre_driver::registry::dialect::OpBackendTarget::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::dialect::OpBackendTarget
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::dialect::OpBackendTarget
impl<T> typenum::type_operators::Same for vyre_driver::registry::dialect::OpBackendTarget
pub type vyre_driver::registry::dialect::OpBackendTarget::Output = T
pub struct vyre_driver::registry::dialect::OpDefRegistration
pub vyre_driver::registry::dialect::OpDefRegistration::op: fn() -> vyre_foundation::dialect_lookup::OpDef
impl vyre_driver::registry::dialect::OpDefRegistration
pub const fn vyre_driver::registry::dialect::OpDefRegistration::new(op: fn() -> vyre_foundation::dialect_lookup::OpDef) -> Self
impl inventory::Collect for vyre_driver::registry::dialect::OpDefRegistration
impl core::marker::Freeze for vyre_driver::registry::dialect::OpDefRegistration
impl core::marker::Send for vyre_driver::registry::dialect::OpDefRegistration
impl core::marker::Sync for vyre_driver::registry::dialect::OpDefRegistration
impl core::marker::Unpin for vyre_driver::registry::dialect::OpDefRegistration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::dialect::OpDefRegistration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::dialect::OpDefRegistration
impl<T, U> core::convert::Into<U> for vyre_driver::registry::dialect::OpDefRegistration where U: core::convert::From<T>
pub fn vyre_driver::registry::dialect::OpDefRegistration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::dialect::OpDefRegistration where U: core::convert::Into<T>
pub type vyre_driver::registry::dialect::OpDefRegistration::Error = core::convert::Infallible
pub fn vyre_driver::registry::dialect::OpDefRegistration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::dialect::OpDefRegistration where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::dialect::OpDefRegistration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::dialect::OpDefRegistration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::dialect::OpDefRegistration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpDefRegistration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::dialect::OpDefRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpDefRegistration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::dialect::OpDefRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpDefRegistration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::dialect::OpDefRegistration
pub fn vyre_driver::registry::dialect::OpDefRegistration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::dialect::OpDefRegistration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::dialect::OpDefRegistration
impl<T> typenum::type_operators::Same for vyre_driver::registry::dialect::OpDefRegistration
pub type vyre_driver::registry::dialect::OpDefRegistration::Output = T
pub fn vyre_driver::registry::dialect::default_validator() -> bool
pub mod vyre_driver::registry::enforce
#[non_exhaustive] pub enum vyre_driver::registry::enforce::EnforceVerdict
pub vyre_driver::registry::enforce::EnforceVerdict::Allow
pub vyre_driver::registry::enforce::EnforceVerdict::Deny
pub vyre_driver::registry::enforce::EnforceVerdict::Deny::detail: alloc::string::String
pub vyre_driver::registry::enforce::EnforceVerdict::Deny::policy: &'static str
impl core::clone::Clone for vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::EnforceVerdict::clone(&self) -> vyre_driver::registry::enforce::EnforceVerdict
impl core::cmp::Eq for vyre_driver::registry::enforce::EnforceVerdict
impl core::cmp::PartialEq for vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::EnforceVerdict::eq(&self, other: &vyre_driver::registry::enforce::EnforceVerdict) -> bool
impl core::fmt::Debug for vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::EnforceVerdict::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::enforce::EnforceVerdict
impl core::marker::Freeze for vyre_driver::registry::enforce::EnforceVerdict
impl core::marker::Send for vyre_driver::registry::enforce::EnforceVerdict
impl core::marker::Sync for vyre_driver::registry::enforce::EnforceVerdict
impl core::marker::Unpin for vyre_driver::registry::enforce::EnforceVerdict
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::enforce::EnforceVerdict
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::enforce::EnforceVerdict
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::enforce::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::enforce::EnforceVerdict::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::enforce::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::enforce::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::enforce::EnforceVerdict::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::enforce::EnforceVerdict::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::enforce::EnforceVerdict where U: core::convert::From<T>
pub fn vyre_driver::registry::enforce::EnforceVerdict::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::enforce::EnforceVerdict where U: core::convert::Into<T>
pub type vyre_driver::registry::enforce::EnforceVerdict::Error = core::convert::Infallible
pub fn vyre_driver::registry::enforce::EnforceVerdict::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::enforce::EnforceVerdict where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::enforce::EnforceVerdict::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::enforce::EnforceVerdict::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::enforce::EnforceVerdict where T: core::clone::Clone
pub type vyre_driver::registry::enforce::EnforceVerdict::Owned = T
pub fn vyre_driver::registry::enforce::EnforceVerdict::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::enforce::EnforceVerdict::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::enforce::EnforceVerdict where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::enforce::EnforceVerdict::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::enforce::EnforceVerdict where T: ?core::marker::Sized
pub fn vyre_driver::registry::enforce::EnforceVerdict::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::enforce::EnforceVerdict where T: ?core::marker::Sized
pub fn vyre_driver::registry::enforce::EnforceVerdict::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::enforce::EnforceVerdict where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::enforce::EnforceVerdict::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::EnforceVerdict::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::enforce::EnforceVerdict
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::enforce::EnforceVerdict
impl<T> typenum::type_operators::Same for vyre_driver::registry::enforce::EnforceVerdict
pub type vyre_driver::registry::enforce::EnforceVerdict::Output = T
pub struct vyre_driver::registry::enforce::Chain<A, B>
impl<A: vyre_driver::registry::enforce::EnforceGate, B: vyre_driver::registry::enforce::EnforceGate> vyre_driver::registry::enforce::Chain<A, B>
pub fn vyre_driver::registry::enforce::Chain<A, B>::new(first: A, second: B) -> Self
impl<A: vyre_driver::registry::enforce::EnforceGate, B: vyre_driver::registry::enforce::EnforceGate> vyre_driver::registry::enforce::EnforceGate for vyre_driver::registry::enforce::Chain<A, B>
pub fn vyre_driver::registry::enforce::Chain<A, B>::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::core::Program) -> vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::Chain<A, B>::name(&self) -> &'static str
impl<A, B> core::marker::Freeze for vyre_driver::registry::enforce::Chain<A, B> where A: core::marker::Freeze, B: core::marker::Freeze
impl<A, B> core::marker::Send for vyre_driver::registry::enforce::Chain<A, B> where A: core::marker::Send, B: core::marker::Send
impl<A, B> core::marker::Sync for vyre_driver::registry::enforce::Chain<A, B> where A: core::marker::Sync, B: core::marker::Sync
impl<A, B> core::marker::Unpin for vyre_driver::registry::enforce::Chain<A, B> where A: core::marker::Unpin, B: core::marker::Unpin
impl<A, B> core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::enforce::Chain<A, B> where A: core::panic::unwind_safe::RefUnwindSafe, B: core::panic::unwind_safe::RefUnwindSafe
impl<A, B> core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::enforce::Chain<A, B> where A: core::panic::unwind_safe::UnwindSafe, B: core::panic::unwind_safe::UnwindSafe
impl<T, U> core::convert::Into<U> for vyre_driver::registry::enforce::Chain<A, B> where U: core::convert::From<T>
pub fn vyre_driver::registry::enforce::Chain<A, B>::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::enforce::Chain<A, B> where U: core::convert::Into<T>
pub type vyre_driver::registry::enforce::Chain<A, B>::Error = core::convert::Infallible
pub fn vyre_driver::registry::enforce::Chain<A, B>::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::enforce::Chain<A, B> where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::enforce::Chain<A, B>::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::enforce::Chain<A, B>::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::enforce::Chain<A, B> where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::enforce::Chain<A, B>::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::enforce::Chain<A, B> where T: ?core::marker::Sized
pub fn vyre_driver::registry::enforce::Chain<A, B>::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::enforce::Chain<A, B> where T: ?core::marker::Sized
pub fn vyre_driver::registry::enforce::Chain<A, B>::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::enforce::Chain<A, B>
pub fn vyre_driver::registry::enforce::Chain<A, B>::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::enforce::Chain<A, B>
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::enforce::Chain<A, B>
impl<T> typenum::type_operators::Same for vyre_driver::registry::enforce::Chain<A, B>
pub type vyre_driver::registry::enforce::Chain<A, B>::Output = T
pub trait vyre_driver::registry::enforce::EnforceGate: vyre_driver::registry::enforce::private::Sealed + core::marker::Send + core::marker::Sync
pub fn vyre_driver::registry::enforce::EnforceGate::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::core::Program) -> vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::EnforceGate::name(&self) -> &'static str
impl<A: vyre_driver::registry::enforce::EnforceGate, B: vyre_driver::registry::enforce::EnforceGate> vyre_driver::registry::enforce::EnforceGate for vyre_driver::registry::enforce::Chain<A, B>
pub fn vyre_driver::registry::enforce::Chain<A, B>::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::core::Program) -> vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::Chain<A, B>::name(&self) -> &'static str
pub mod vyre_driver::registry::interner
pub use vyre_driver::registry::interner::InternedOpId
pub use vyre_driver::registry::interner::intern_string
pub mod vyre_driver::registry::io
pub mod vyre_driver::registry::lowering
pub use vyre_driver::registry::lowering::LoweringCtx
pub use vyre_driver::registry::lowering::LoweringTable
pub use vyre_driver::registry::lowering::NativeModuleBuilder
pub use vyre_driver::registry::lowering::NativeModule
pub use vyre_driver::registry::lowering::PrimaryTextBuilder
pub use vyre_driver::registry::lowering::SecondaryTextBuilder
pub use vyre_driver::registry::lowering::TextModule
pub use vyre_driver::registry::lowering::ReferenceKind
pub use vyre_driver::registry::lowering::PrimaryBinaryBuilder
pub mod vyre_driver::registry::migration
#[non_exhaustive] pub enum vyre_driver::registry::migration::AttrValue
pub vyre_driver::registry::migration::AttrValue::Bool(bool)
pub vyre_driver::registry::migration::AttrValue::Bytes(alloc::vec::Vec<u8>)
pub vyre_driver::registry::migration::AttrValue::F32(f32)
pub vyre_driver::registry::migration::AttrValue::I32(i32)
pub vyre_driver::registry::migration::AttrValue::String(alloc::string::String)
pub vyre_driver::registry::migration::AttrValue::U32(u32)
impl core::clone::Clone for vyre_driver::registry::migration::AttrValue
pub fn vyre_driver::registry::migration::AttrValue::clone(&self) -> vyre_driver::registry::migration::AttrValue
impl core::cmp::PartialEq for vyre_driver::registry::migration::AttrValue
pub fn vyre_driver::registry::migration::AttrValue::eq(&self, other: &vyre_driver::registry::migration::AttrValue) -> bool
impl core::fmt::Debug for vyre_driver::registry::migration::AttrValue
pub fn vyre_driver::registry::migration::AttrValue::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::migration::AttrValue
impl core::marker::Freeze for vyre_driver::registry::migration::AttrValue
impl core::marker::Send for vyre_driver::registry::migration::AttrValue
impl core::marker::Sync for vyre_driver::registry::migration::AttrValue
impl core::marker::Unpin for vyre_driver::registry::migration::AttrValue
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::migration::AttrValue
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::migration::AttrValue
impl<T, U> core::convert::Into<U> for vyre_driver::registry::migration::AttrValue where U: core::convert::From<T>
pub fn vyre_driver::registry::migration::AttrValue::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::migration::AttrValue where U: core::convert::Into<T>
pub type vyre_driver::registry::migration::AttrValue::Error = core::convert::Infallible
pub fn vyre_driver::registry::migration::AttrValue::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::migration::AttrValue where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::migration::AttrValue::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::migration::AttrValue::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::migration::AttrValue where T: core::clone::Clone
pub type vyre_driver::registry::migration::AttrValue::Owned = T
pub fn vyre_driver::registry::migration::AttrValue::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::migration::AttrValue::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::migration::AttrValue where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::migration::AttrValue::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::migration::AttrValue where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::AttrValue::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::migration::AttrValue where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::AttrValue::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::migration::AttrValue where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::migration::AttrValue::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::migration::AttrValue
pub fn vyre_driver::registry::migration::AttrValue::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::migration::AttrValue
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::migration::AttrValue
impl<T> typenum::type_operators::Same for vyre_driver::registry::migration::AttrValue
pub type vyre_driver::registry::migration::AttrValue::Output = T
#[non_exhaustive] pub enum vyre_driver::registry::migration::MigrationError
pub vyre_driver::registry::migration::MigrationError::Custom
pub vyre_driver::registry::migration::MigrationError::Custom::reason: alloc::string::String
pub vyre_driver::registry::migration::MigrationError::MissingAttribute
pub vyre_driver::registry::migration::MigrationError::MissingAttribute::name: alloc::string::String
pub vyre_driver::registry::migration::MigrationError::OutOfRange
pub vyre_driver::registry::migration::MigrationError::OutOfRange::name: alloc::string::String
pub vyre_driver::registry::migration::MigrationError::WrongType
pub vyre_driver::registry::migration::MigrationError::WrongType::expected: &'static str
pub vyre_driver::registry::migration::MigrationError::WrongType::name: alloc::string::String
impl core::clone::Clone for vyre_driver::registry::migration::MigrationError
pub fn vyre_driver::registry::migration::MigrationError::clone(&self) -> vyre_driver::registry::migration::MigrationError
impl core::cmp::Eq for vyre_driver::registry::migration::MigrationError
impl core::cmp::PartialEq for vyre_driver::registry::migration::MigrationError
pub fn vyre_driver::registry::migration::MigrationError::eq(&self, other: &vyre_driver::registry::migration::MigrationError) -> bool
impl core::error::Error for vyre_driver::registry::migration::MigrationError
impl core::fmt::Debug for vyre_driver::registry::migration::MigrationError
pub fn vyre_driver::registry::migration::MigrationError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::registry::migration::MigrationError
pub fn vyre_driver::registry::migration::MigrationError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::migration::MigrationError
impl core::marker::Freeze for vyre_driver::registry::migration::MigrationError
impl core::marker::Send for vyre_driver::registry::migration::MigrationError
impl core::marker::Sync for vyre_driver::registry::migration::MigrationError
impl core::marker::Unpin for vyre_driver::registry::migration::MigrationError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::migration::MigrationError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::migration::MigrationError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::migration::MigrationError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::migration::MigrationError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::migration::MigrationError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::migration::MigrationError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::migration::MigrationError where U: core::convert::From<T>
pub fn vyre_driver::registry::migration::MigrationError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::migration::MigrationError where U: core::convert::Into<T>
pub type vyre_driver::registry::migration::MigrationError::Error = core::convert::Infallible
pub fn vyre_driver::registry::migration::MigrationError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::migration::MigrationError where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::migration::MigrationError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::migration::MigrationError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::migration::MigrationError where T: core::clone::Clone
pub type vyre_driver::registry::migration::MigrationError::Owned = T
pub fn vyre_driver::registry::migration::MigrationError::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::migration::MigrationError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::registry::migration::MigrationError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::registry::migration::MigrationError where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::migration::MigrationError where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::migration::MigrationError where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::migration::MigrationError where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::migration::MigrationError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::migration::MigrationError
pub fn vyre_driver::registry::migration::MigrationError::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::migration::MigrationError
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::migration::MigrationError
impl<T> typenum::type_operators::Same for vyre_driver::registry::migration::MigrationError
pub type vyre_driver::registry::migration::MigrationError::Output = T
pub struct vyre_driver::registry::migration::AttrMap
impl vyre_driver::registry::migration::AttrMap
pub fn vyre_driver::registry::migration::AttrMap::get(&self, key: &str) -> core::option::Option<&vyre_driver::registry::migration::AttrValue>
pub fn vyre_driver::registry::migration::AttrMap::insert(&mut self, key: impl core::convert::Into<alloc::string::String>, value: vyre_driver::registry::migration::AttrValue) -> core::option::Option<vyre_driver::registry::migration::AttrValue>
pub fn vyre_driver::registry::migration::AttrMap::is_empty(&self) -> bool
pub fn vyre_driver::registry::migration::AttrMap::iter(&self) -> impl core::iter::traits::iterator::Iterator<Item = (&str, &vyre_driver::registry::migration::AttrValue)>
pub fn vyre_driver::registry::migration::AttrMap::len(&self) -> usize
pub fn vyre_driver::registry::migration::AttrMap::new() -> Self
pub fn vyre_driver::registry::migration::AttrMap::remove(&mut self, key: &str) -> core::option::Option<vyre_driver::registry::migration::AttrValue>
pub fn vyre_driver::registry::migration::AttrMap::rename(&mut self, from: &str, to: impl core::convert::Into<alloc::string::String>) -> bool
impl core::clone::Clone for vyre_driver::registry::migration::AttrMap
pub fn vyre_driver::registry::migration::AttrMap::clone(&self) -> vyre_driver::registry::migration::AttrMap
impl core::default::Default for vyre_driver::registry::migration::AttrMap
pub fn vyre_driver::registry::migration::AttrMap::default() -> vyre_driver::registry::migration::AttrMap
impl core::fmt::Debug for vyre_driver::registry::migration::AttrMap
pub fn vyre_driver::registry::migration::AttrMap::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::registry::migration::AttrMap
impl core::marker::Send for vyre_driver::registry::migration::AttrMap
impl core::marker::Sync for vyre_driver::registry::migration::AttrMap
impl core::marker::Unpin for vyre_driver::registry::migration::AttrMap
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::migration::AttrMap
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::migration::AttrMap
impl<T, U> core::convert::Into<U> for vyre_driver::registry::migration::AttrMap where U: core::convert::From<T>
pub fn vyre_driver::registry::migration::AttrMap::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::migration::AttrMap where U: core::convert::Into<T>
pub type vyre_driver::registry::migration::AttrMap::Error = core::convert::Infallible
pub fn vyre_driver::registry::migration::AttrMap::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::migration::AttrMap where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::migration::AttrMap::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::migration::AttrMap::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::migration::AttrMap where T: core::clone::Clone
pub type vyre_driver::registry::migration::AttrMap::Owned = T
pub fn vyre_driver::registry::migration::AttrMap::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::migration::AttrMap::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::migration::AttrMap where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::migration::AttrMap::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::migration::AttrMap where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::AttrMap::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::migration::AttrMap where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::AttrMap::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::migration::AttrMap where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::migration::AttrMap::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::migration::AttrMap
pub fn vyre_driver::registry::migration::AttrMap::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::migration::AttrMap
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::migration::AttrMap
impl<T> typenum::type_operators::Same for vyre_driver::registry::migration::AttrMap
pub type vyre_driver::registry::migration::AttrMap::Output = T
pub struct vyre_driver::registry::migration::Deprecation
pub vyre_driver::registry::migration::Deprecation::deprecated_since: vyre_driver::registry::migration::Semver
pub vyre_driver::registry::migration::Deprecation::note: &'static str
pub vyre_driver::registry::migration::Deprecation::op_id: &'static str
impl vyre_driver::registry::migration::Deprecation
pub const fn vyre_driver::registry::migration::Deprecation::new(op_id: &'static str, deprecated_since: vyre_driver::registry::migration::Semver, note: &'static str) -> Self
impl inventory::Collect for vyre_driver::registry::migration::Deprecation
impl core::marker::Freeze for vyre_driver::registry::migration::Deprecation
impl core::marker::Send for vyre_driver::registry::migration::Deprecation
impl core::marker::Sync for vyre_driver::registry::migration::Deprecation
impl core::marker::Unpin for vyre_driver::registry::migration::Deprecation
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::migration::Deprecation
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::migration::Deprecation
impl<T, U> core::convert::Into<U> for vyre_driver::registry::migration::Deprecation where U: core::convert::From<T>
pub fn vyre_driver::registry::migration::Deprecation::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::migration::Deprecation where U: core::convert::Into<T>
pub type vyre_driver::registry::migration::Deprecation::Error = core::convert::Infallible
pub fn vyre_driver::registry::migration::Deprecation::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::migration::Deprecation where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::migration::Deprecation::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::migration::Deprecation::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::migration::Deprecation where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::migration::Deprecation::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::migration::Deprecation where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::Deprecation::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::migration::Deprecation where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::Deprecation::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::migration::Deprecation
pub fn vyre_driver::registry::migration::Deprecation::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::migration::Deprecation
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::migration::Deprecation
impl<T> typenum::type_operators::Same for vyre_driver::registry::migration::Deprecation
pub type vyre_driver::registry::migration::Deprecation::Output = T
pub struct vyre_driver::registry::migration::Migration
pub vyre_driver::registry::migration::Migration::from: (&'static str, vyre_driver::registry::migration::Semver)
pub vyre_driver::registry::migration::Migration::rewrite: fn(&mut vyre_driver::registry::migration::AttrMap) -> core::result::Result<(), vyre_driver::registry::migration::MigrationError>
pub vyre_driver::registry::migration::Migration::to: (&'static str, vyre_driver::registry::migration::Semver)
impl vyre_driver::registry::migration::Migration
pub const fn vyre_driver::registry::migration::Migration::new(from: (&'static str, vyre_driver::registry::migration::Semver), to: (&'static str, vyre_driver::registry::migration::Semver), rewrite: fn(&mut vyre_driver::registry::migration::AttrMap) -> core::result::Result<(), vyre_driver::registry::migration::MigrationError>) -> Self
impl inventory::Collect for vyre_driver::registry::migration::Migration
impl core::marker::Freeze for vyre_driver::registry::migration::Migration
impl core::marker::Send for vyre_driver::registry::migration::Migration
impl core::marker::Sync for vyre_driver::registry::migration::Migration
impl core::marker::Unpin for vyre_driver::registry::migration::Migration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::migration::Migration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::migration::Migration
impl<T, U> core::convert::Into<U> for vyre_driver::registry::migration::Migration where U: core::convert::From<T>
pub fn vyre_driver::registry::migration::Migration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::migration::Migration where U: core::convert::Into<T>
pub type vyre_driver::registry::migration::Migration::Error = core::convert::Infallible
pub fn vyre_driver::registry::migration::Migration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::migration::Migration where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::migration::Migration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::migration::Migration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::migration::Migration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::migration::Migration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::migration::Migration where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::Migration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::migration::Migration where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::Migration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::migration::Migration
pub fn vyre_driver::registry::migration::Migration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::migration::Migration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::migration::Migration
impl<T> typenum::type_operators::Same for vyre_driver::registry::migration::Migration
pub type vyre_driver::registry::migration::Migration::Output = T
pub struct vyre_driver::registry::migration::MigrationRegistry
impl vyre_driver::registry::migration::MigrationRegistry
pub fn vyre_driver::registry::migration::MigrationRegistry::apply_chain(&self, op_id: &'static str, from: vyre_driver::registry::migration::Semver, attrs: &mut vyre_driver::registry::migration::AttrMap) -> core::result::Result<(&'static str, vyre_driver::registry::migration::Semver), vyre_driver::registry::migration::MigrationError>
pub fn vyre_driver::registry::migration::MigrationRegistry::deprecation(&self, op_id: &str) -> core::option::Option<&'static vyre_driver::registry::migration::Deprecation>
pub fn vyre_driver::registry::migration::MigrationRegistry::global() -> &'static vyre_driver::registry::migration::MigrationRegistry
pub fn vyre_driver::registry::migration::MigrationRegistry::lookup(&self, op_id: &str, from: vyre_driver::registry::migration::Semver) -> core::option::Option<&'static vyre_driver::registry::migration::Migration>
impl core::marker::Freeze for vyre_driver::registry::migration::MigrationRegistry
impl core::marker::Send for vyre_driver::registry::migration::MigrationRegistry
impl core::marker::Sync for vyre_driver::registry::migration::MigrationRegistry
impl core::marker::Unpin for vyre_driver::registry::migration::MigrationRegistry
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::migration::MigrationRegistry
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::migration::MigrationRegistry
impl<T, U> core::convert::Into<U> for vyre_driver::registry::migration::MigrationRegistry where U: core::convert::From<T>
pub fn vyre_driver::registry::migration::MigrationRegistry::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::migration::MigrationRegistry where U: core::convert::Into<T>
pub type vyre_driver::registry::migration::MigrationRegistry::Error = core::convert::Infallible
pub fn vyre_driver::registry::migration::MigrationRegistry::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::migration::MigrationRegistry where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::migration::MigrationRegistry::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::migration::MigrationRegistry::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::migration::MigrationRegistry where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationRegistry::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::migration::MigrationRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationRegistry::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::migration::MigrationRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationRegistry::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::migration::MigrationRegistry
pub fn vyre_driver::registry::migration::MigrationRegistry::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::migration::MigrationRegistry
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::migration::MigrationRegistry
impl<T> typenum::type_operators::Same for vyre_driver::registry::migration::MigrationRegistry
pub type vyre_driver::registry::migration::MigrationRegistry::Output = T
pub struct vyre_driver::registry::migration::Semver
pub vyre_driver::registry::migration::Semver::major: u32
pub vyre_driver::registry::migration::Semver::minor: u32
pub vyre_driver::registry::migration::Semver::patch: u32
impl vyre_driver::registry::migration::Semver
pub const fn vyre_driver::registry::migration::Semver::new(major: u32, minor: u32, patch: u32) -> Self
impl core::clone::Clone for vyre_driver::registry::migration::Semver
pub fn vyre_driver::registry::migration::Semver::clone(&self) -> vyre_driver::registry::migration::Semver
impl core::cmp::Eq for vyre_driver::registry::migration::Semver
impl core::cmp::Ord for vyre_driver::registry::migration::Semver
pub fn vyre_driver::registry::migration::Semver::cmp(&self, other: &vyre_driver::registry::migration::Semver) -> core::cmp::Ordering
impl core::cmp::PartialEq for vyre_driver::registry::migration::Semver
pub fn vyre_driver::registry::migration::Semver::eq(&self, other: &vyre_driver::registry::migration::Semver) -> bool
impl core::cmp::PartialOrd for vyre_driver::registry::migration::Semver
pub fn vyre_driver::registry::migration::Semver::partial_cmp(&self, other: &vyre_driver::registry::migration::Semver) -> core::option::Option<core::cmp::Ordering>
impl core::fmt::Debug for vyre_driver::registry::migration::Semver
pub fn vyre_driver::registry::migration::Semver::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::registry::migration::Semver
pub fn vyre_driver::registry::migration::Semver::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::registry::migration::Semver
pub fn vyre_driver::registry::migration::Semver::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::registry::migration::Semver
impl core::marker::StructuralPartialEq for vyre_driver::registry::migration::Semver
impl core::marker::Freeze for vyre_driver::registry::migration::Semver
impl core::marker::Send for vyre_driver::registry::migration::Semver
impl core::marker::Sync for vyre_driver::registry::migration::Semver
impl core::marker::Unpin for vyre_driver::registry::migration::Semver
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::migration::Semver
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::migration::Semver
impl<Q, K> equivalent::Comparable<K> for vyre_driver::registry::migration::Semver where Q: core::cmp::Ord + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::migration::Semver::compare(&self, key: &K) -> core::cmp::Ordering
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::migration::Semver where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::migration::Semver::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::migration::Semver where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::migration::Semver where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::migration::Semver::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::migration::Semver::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::migration::Semver where U: core::convert::From<T>
pub fn vyre_driver::registry::migration::Semver::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::migration::Semver where U: core::convert::Into<T>
pub type vyre_driver::registry::migration::Semver::Error = core::convert::Infallible
pub fn vyre_driver::registry::migration::Semver::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::migration::Semver where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::migration::Semver::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::migration::Semver::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::migration::Semver where T: core::clone::Clone
pub type vyre_driver::registry::migration::Semver::Owned = T
pub fn vyre_driver::registry::migration::Semver::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::migration::Semver::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::registry::migration::Semver where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::registry::migration::Semver::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::registry::migration::Semver where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::migration::Semver::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::migration::Semver where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::Semver::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::migration::Semver where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::Semver::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::migration::Semver where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::migration::Semver::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::migration::Semver
pub fn vyre_driver::registry::migration::Semver::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::migration::Semver
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::migration::Semver
impl<T> typenum::type_operators::Same for vyre_driver::registry::migration::Semver
pub type vyre_driver::registry::migration::Semver::Output = T
pub fn vyre_driver::registry::migration::deprecation_diagnostic(dep: &vyre_driver::registry::migration::Deprecation) -> vyre_driver::diagnostics::Diagnostic
pub mod vyre_driver::registry::mutation
#[non_exhaustive] pub enum vyre_driver::registry::mutation::MutationClass
pub vyre_driver::registry::mutation::MutationClass::Cosmetic
pub vyre_driver::registry::mutation::MutationClass::Lowering
pub vyre_driver::registry::mutation::MutationClass::Semantic
pub vyre_driver::registry::mutation::MutationClass::Structural
impl vyre_driver::registry::mutation::MutationClass
pub const fn vyre_driver::registry::mutation::MutationClass::requires_byte_parity(self) -> bool
pub const fn vyre_driver::registry::mutation::MutationClass::uses_law_proof(self) -> bool
impl core::clone::Clone for vyre_driver::registry::mutation::MutationClass
pub fn vyre_driver::registry::mutation::MutationClass::clone(&self) -> vyre_driver::registry::mutation::MutationClass
impl core::cmp::Eq for vyre_driver::registry::mutation::MutationClass
impl core::cmp::PartialEq for vyre_driver::registry::mutation::MutationClass
pub fn vyre_driver::registry::mutation::MutationClass::eq(&self, other: &vyre_driver::registry::mutation::MutationClass) -> bool
impl core::fmt::Debug for vyre_driver::registry::mutation::MutationClass
pub fn vyre_driver::registry::mutation::MutationClass::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::registry::mutation::MutationClass
pub fn vyre_driver::registry::mutation::MutationClass::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::registry::mutation::MutationClass
impl core::marker::StructuralPartialEq for vyre_driver::registry::mutation::MutationClass
impl core::marker::Freeze for vyre_driver::registry::mutation::MutationClass
impl core::marker::Send for vyre_driver::registry::mutation::MutationClass
impl core::marker::Sync for vyre_driver::registry::mutation::MutationClass
impl core::marker::Unpin for vyre_driver::registry::mutation::MutationClass
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::mutation::MutationClass
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::mutation::MutationClass
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::mutation::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::mutation::MutationClass::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::mutation::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::mutation::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::mutation::MutationClass::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::mutation::MutationClass::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::mutation::MutationClass where U: core::convert::From<T>
pub fn vyre_driver::registry::mutation::MutationClass::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::mutation::MutationClass where U: core::convert::Into<T>
pub type vyre_driver::registry::mutation::MutationClass::Error = core::convert::Infallible
pub fn vyre_driver::registry::mutation::MutationClass::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::mutation::MutationClass where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::mutation::MutationClass::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::mutation::MutationClass::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::mutation::MutationClass where T: core::clone::Clone
pub type vyre_driver::registry::mutation::MutationClass::Owned = T
pub fn vyre_driver::registry::mutation::MutationClass::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::mutation::MutationClass::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::mutation::MutationClass where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::mutation::MutationClass::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::mutation::MutationClass where T: ?core::marker::Sized
pub fn vyre_driver::registry::mutation::MutationClass::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::mutation::MutationClass where T: ?core::marker::Sized
pub fn vyre_driver::registry::mutation::MutationClass::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::mutation::MutationClass where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::mutation::MutationClass::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::mutation::MutationClass
pub fn vyre_driver::registry::mutation::MutationClass::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::mutation::MutationClass
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::mutation::MutationClass
impl<T> typenum::type_operators::Same for vyre_driver::registry::mutation::MutationClass
pub type vyre_driver::registry::mutation::MutationClass::Output = T
pub mod vyre_driver::registry::op_def
pub use vyre_driver::registry::op_def::AttrSchema
pub use vyre_driver::registry::op_def::AttrType
pub use vyre_driver::registry::op_def::Category
pub use vyre_driver::registry::op_def::OpDef
pub use vyre_driver::registry::op_def::Signature
pub use vyre_driver::registry::op_def::TypedParam
pub mod vyre_driver::registry::registry
#[non_exhaustive] pub enum vyre_driver::registry::registry::Target
pub vyre_driver::registry::registry::Target::Extension(&'static str)
pub vyre_driver::registry::registry::Target::MetalIr
pub vyre_driver::registry::registry::Target::Ptx
pub vyre_driver::registry::registry::Target::ReferenceBackend
pub vyre_driver::registry::registry::Target::Spirv
pub vyre_driver::registry::registry::Target::Wgsl
impl core::clone::Clone for vyre_driver::registry::registry::Target
pub fn vyre_driver::registry::registry::Target::clone(&self) -> vyre_driver::registry::registry::Target
impl core::cmp::Eq for vyre_driver::registry::registry::Target
impl core::cmp::PartialEq for vyre_driver::registry::registry::Target
pub fn vyre_driver::registry::registry::Target::eq(&self, other: &vyre_driver::registry::registry::Target) -> bool
impl core::fmt::Debug for vyre_driver::registry::registry::Target
pub fn vyre_driver::registry::registry::Target::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::registry::registry::Target
pub fn vyre_driver::registry::registry::Target::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::registry::registry::Target
impl core::marker::StructuralPartialEq for vyre_driver::registry::registry::Target
impl core::marker::Freeze for vyre_driver::registry::registry::Target
impl core::marker::Send for vyre_driver::registry::registry::Target
impl core::marker::Sync for vyre_driver::registry::registry::Target
impl core::marker::Unpin for vyre_driver::registry::registry::Target
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::registry::Target
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::registry::Target
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::registry::Target::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::registry::Target::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::registry::Target::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::registry::Target where U: core::convert::From<T>
pub fn vyre_driver::registry::registry::Target::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::registry::Target where U: core::convert::Into<T>
pub type vyre_driver::registry::registry::Target::Error = core::convert::Infallible
pub fn vyre_driver::registry::registry::Target::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::registry::Target where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::registry::Target::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::registry::Target::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::registry::Target where T: core::clone::Clone
pub type vyre_driver::registry::registry::Target::Owned = T
pub fn vyre_driver::registry::registry::Target::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::registry::Target::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::registry::Target where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::registry::Target::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::registry::Target where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::Target::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::registry::Target where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::Target::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::registry::Target where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::registry::Target::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::registry::Target
pub fn vyre_driver::registry::registry::Target::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::registry::Target
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::registry::Target
impl<T> typenum::type_operators::Same for vyre_driver::registry::registry::Target
pub type vyre_driver::registry::registry::Target::Output = T
pub struct vyre_driver::registry::registry::DialectRegistry
impl vyre_driver::registry::registry::DialectRegistry
pub fn vyre_driver::registry::registry::DialectRegistry::get_lowering(&self, id: vyre_foundation::dialect_lookup::InternedOpId, target: vyre_driver::registry::registry::Target) -> core::option::Option<vyre_foundation::dialect_lookup::ReferenceKind>
pub fn vyre_driver::registry::registry::DialectRegistry::global() -> arc_swap::Guard<alloc::sync::Arc<Self>>
pub fn vyre_driver::registry::registry::DialectRegistry::install(new: Self)
pub fn vyre_driver::registry::registry::DialectRegistry::intern_op(&self, name: &str) -> vyre_foundation::dialect_lookup::InternedOpId
pub fn vyre_driver::registry::registry::DialectRegistry::iter(&self) -> impl core::iter::traits::iterator::Iterator<Item = &'static vyre_foundation::dialect_lookup::OpDef> + '_
pub fn vyre_driver::registry::registry::DialectRegistry::lookup(&self, id: vyre_foundation::dialect_lookup::InternedOpId) -> core::option::Option<&'static vyre_foundation::dialect_lookup::OpDef>
pub fn vyre_driver::registry::registry::DialectRegistry::validate_no_duplicates<'a>(defs: impl core::iter::traits::collect::IntoIterator<Item = &'a vyre_foundation::dialect_lookup::OpDef>) -> core::result::Result<(), vyre_driver::registry::registry::DuplicateOpIdError>
impl vyre_foundation::dialect_lookup::DialectLookup for vyre_driver::registry::registry::DialectRegistry
pub fn vyre_driver::registry::registry::DialectRegistry::intern_op(&self, name: &str) -> vyre_foundation::dialect_lookup::InternedOpId
pub fn vyre_driver::registry::registry::DialectRegistry::lookup(&self, id: vyre_foundation::dialect_lookup::InternedOpId) -> core::option::Option<&'static vyre_foundation::dialect_lookup::OpDef>
pub fn vyre_driver::registry::registry::DialectRegistry::provider_id(&self) -> &'static str
impl vyre_foundation::dialect_lookup::private::Sealed for vyre_driver::registry::registry::DialectRegistry
impl core::marker::Freeze for vyre_driver::registry::registry::DialectRegistry
impl core::marker::Send for vyre_driver::registry::registry::DialectRegistry
impl core::marker::Sync for vyre_driver::registry::registry::DialectRegistry
impl core::marker::Unpin for vyre_driver::registry::registry::DialectRegistry
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::registry::DialectRegistry
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::registry::DialectRegistry
impl<T, U> core::convert::Into<U> for vyre_driver::registry::registry::DialectRegistry where U: core::convert::From<T>
pub fn vyre_driver::registry::registry::DialectRegistry::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::registry::DialectRegistry where U: core::convert::Into<T>
pub type vyre_driver::registry::registry::DialectRegistry::Error = core::convert::Infallible
pub fn vyre_driver::registry::registry::DialectRegistry::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::registry::DialectRegistry where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::registry::DialectRegistry::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::registry::DialectRegistry::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::registry::DialectRegistry where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::registry::DialectRegistry::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::registry::DialectRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::DialectRegistry::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::registry::DialectRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::DialectRegistry::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::registry::DialectRegistry
pub fn vyre_driver::registry::registry::DialectRegistry::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::registry::DialectRegistry
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::registry::DialectRegistry
impl<T> typenum::type_operators::Same for vyre_driver::registry::registry::DialectRegistry
pub type vyre_driver::registry::registry::DialectRegistry::Output = T
pub struct vyre_driver::registry::registry::DuplicateOpIdError
impl vyre_driver::registry::registry::DuplicateOpIdError
pub const fn vyre_driver::registry::registry::DuplicateOpIdError::first_registrant(&self) -> &'static str
pub const fn vyre_driver::registry::registry::DuplicateOpIdError::op_id(&self) -> &'static str
pub const fn vyre_driver::registry::registry::DuplicateOpIdError::second_registrant(&self) -> &'static str
impl core::clone::Clone for vyre_driver::registry::registry::DuplicateOpIdError
pub fn vyre_driver::registry::registry::DuplicateOpIdError::clone(&self) -> vyre_driver::registry::registry::DuplicateOpIdError
impl core::cmp::Eq for vyre_driver::registry::registry::DuplicateOpIdError
impl core::cmp::PartialEq for vyre_driver::registry::registry::DuplicateOpIdError
pub fn vyre_driver::registry::registry::DuplicateOpIdError::eq(&self, other: &vyre_driver::registry::registry::DuplicateOpIdError) -> bool
impl core::error::Error for vyre_driver::registry::registry::DuplicateOpIdError
impl core::fmt::Debug for vyre_driver::registry::registry::DuplicateOpIdError
pub fn vyre_driver::registry::registry::DuplicateOpIdError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::registry::registry::DuplicateOpIdError
pub fn vyre_driver::registry::registry::DuplicateOpIdError::fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::registry::DuplicateOpIdError
impl core::marker::Freeze for vyre_driver::registry::registry::DuplicateOpIdError
impl core::marker::Send for vyre_driver::registry::registry::DuplicateOpIdError
impl core::marker::Sync for vyre_driver::registry::registry::DuplicateOpIdError
impl core::marker::Unpin for vyre_driver::registry::registry::DuplicateOpIdError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::registry::DuplicateOpIdError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::registry::DuplicateOpIdError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::registry::DuplicateOpIdError where U: core::convert::From<T>
pub fn vyre_driver::registry::registry::DuplicateOpIdError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::registry::DuplicateOpIdError where U: core::convert::Into<T>
pub type vyre_driver::registry::registry::DuplicateOpIdError::Error = core::convert::Infallible
pub fn vyre_driver::registry::registry::DuplicateOpIdError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::registry::DuplicateOpIdError where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::registry::DuplicateOpIdError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::registry::DuplicateOpIdError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::registry::DuplicateOpIdError where T: core::clone::Clone
pub type vyre_driver::registry::registry::DuplicateOpIdError::Owned = T
pub fn vyre_driver::registry::registry::DuplicateOpIdError::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::registry::DuplicateOpIdError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::registry::registry::DuplicateOpIdError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::registry::registry::DuplicateOpIdError where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::registry::DuplicateOpIdError where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::registry::DuplicateOpIdError where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::registry::DuplicateOpIdError where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::registry::DuplicateOpIdError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::registry::DuplicateOpIdError
pub fn vyre_driver::registry::registry::DuplicateOpIdError::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::registry::DuplicateOpIdError
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::registry::DuplicateOpIdError
impl<T> typenum::type_operators::Same for vyre_driver::registry::registry::DuplicateOpIdError
pub type vyre_driver::registry::registry::DuplicateOpIdError::Output = T
pub mod vyre_driver::registry::toml_loader
pub struct vyre_driver::registry::toml_loader::DialectManifest
pub vyre_driver::registry::toml_loader::DialectManifest::description: core::option::Option<alloc::string::String>
pub vyre_driver::registry::toml_loader::DialectManifest::dialect: alloc::string::String
pub vyre_driver::registry::toml_loader::DialectManifest::ops: alloc::vec::Vec<vyre_driver::registry::toml_loader::OpManifest>
pub vyre_driver::registry::toml_loader::DialectManifest::version: alloc::string::String
impl core::clone::Clone for vyre_driver::registry::toml_loader::DialectManifest
pub fn vyre_driver::registry::toml_loader::DialectManifest::clone(&self) -> vyre_driver::registry::toml_loader::DialectManifest
impl core::cmp::PartialEq for vyre_driver::registry::toml_loader::DialectManifest
pub fn vyre_driver::registry::toml_loader::DialectManifest::eq(&self, other: &vyre_driver::registry::toml_loader::DialectManifest) -> bool
impl core::fmt::Debug for vyre_driver::registry::toml_loader::DialectManifest
pub fn vyre_driver::registry::toml_loader::DialectManifest::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::toml_loader::DialectManifest
impl serde_core::ser::Serialize for vyre_driver::registry::toml_loader::DialectManifest
pub fn vyre_driver::registry::toml_loader::DialectManifest::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::registry::toml_loader::DialectManifest
pub fn vyre_driver::registry::toml_loader::DialectManifest::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::registry::toml_loader::DialectManifest
impl core::marker::Send for vyre_driver::registry::toml_loader::DialectManifest
impl core::marker::Sync for vyre_driver::registry::toml_loader::DialectManifest
impl core::marker::Unpin for vyre_driver::registry::toml_loader::DialectManifest
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::toml_loader::DialectManifest
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::toml_loader::DialectManifest
impl<T, U> core::convert::Into<U> for vyre_driver::registry::toml_loader::DialectManifest where U: core::convert::From<T>
pub fn vyre_driver::registry::toml_loader::DialectManifest::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::toml_loader::DialectManifest where U: core::convert::Into<T>
pub type vyre_driver::registry::toml_loader::DialectManifest::Error = core::convert::Infallible
pub fn vyre_driver::registry::toml_loader::DialectManifest::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::toml_loader::DialectManifest where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::toml_loader::DialectManifest::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::toml_loader::DialectManifest::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::toml_loader::DialectManifest where T: core::clone::Clone
pub type vyre_driver::registry::toml_loader::DialectManifest::Owned = T
pub fn vyre_driver::registry::toml_loader::DialectManifest::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::toml_loader::DialectManifest::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::toml_loader::DialectManifest where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::DialectManifest::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::toml_loader::DialectManifest where T: ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::DialectManifest::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::toml_loader::DialectManifest where T: ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::DialectManifest::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::toml_loader::DialectManifest where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::toml_loader::DialectManifest::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::toml_loader::DialectManifest
pub fn vyre_driver::registry::toml_loader::DialectManifest::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::registry::toml_loader::DialectManifest where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::registry::toml_loader::DialectManifest
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::toml_loader::DialectManifest
impl<T> typenum::type_operators::Same for vyre_driver::registry::toml_loader::DialectManifest
pub type vyre_driver::registry::toml_loader::DialectManifest::Output = T
pub struct vyre_driver::registry::toml_loader::OpManifest
pub vyre_driver::registry::toml_loader::OpManifest::category: alloc::string::String
pub vyre_driver::registry::toml_loader::OpManifest::id: alloc::string::String
pub vyre_driver::registry::toml_loader::OpManifest::inputs: alloc::vec::Vec<(alloc::string::String, alloc::string::String)>
pub vyre_driver::registry::toml_loader::OpManifest::laws: alloc::vec::Vec<alloc::string::String>
pub vyre_driver::registry::toml_loader::OpManifest::outputs: alloc::vec::Vec<(alloc::string::String, alloc::string::String)>
pub vyre_driver::registry::toml_loader::OpManifest::summary: core::option::Option<alloc::string::String>
impl core::clone::Clone for vyre_driver::registry::toml_loader::OpManifest
pub fn vyre_driver::registry::toml_loader::OpManifest::clone(&self) -> vyre_driver::registry::toml_loader::OpManifest
impl core::cmp::PartialEq for vyre_driver::registry::toml_loader::OpManifest
pub fn vyre_driver::registry::toml_loader::OpManifest::eq(&self, other: &vyre_driver::registry::toml_loader::OpManifest) -> bool
impl core::fmt::Debug for vyre_driver::registry::toml_loader::OpManifest
pub fn vyre_driver::registry::toml_loader::OpManifest::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::toml_loader::OpManifest
impl serde_core::ser::Serialize for vyre_driver::registry::toml_loader::OpManifest
pub fn vyre_driver::registry::toml_loader::OpManifest::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::registry::toml_loader::OpManifest
pub fn vyre_driver::registry::toml_loader::OpManifest::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::registry::toml_loader::OpManifest
impl core::marker::Send for vyre_driver::registry::toml_loader::OpManifest
impl core::marker::Sync for vyre_driver::registry::toml_loader::OpManifest
impl core::marker::Unpin for vyre_driver::registry::toml_loader::OpManifest
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::toml_loader::OpManifest
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::toml_loader::OpManifest
impl<T, U> core::convert::Into<U> for vyre_driver::registry::toml_loader::OpManifest where U: core::convert::From<T>
pub fn vyre_driver::registry::toml_loader::OpManifest::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::toml_loader::OpManifest where U: core::convert::Into<T>
pub type vyre_driver::registry::toml_loader::OpManifest::Error = core::convert::Infallible
pub fn vyre_driver::registry::toml_loader::OpManifest::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::toml_loader::OpManifest where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::toml_loader::OpManifest::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::toml_loader::OpManifest::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::toml_loader::OpManifest where T: core::clone::Clone
pub type vyre_driver::registry::toml_loader::OpManifest::Owned = T
pub fn vyre_driver::registry::toml_loader::OpManifest::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::toml_loader::OpManifest::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::toml_loader::OpManifest where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::OpManifest::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::toml_loader::OpManifest where T: ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::OpManifest::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::toml_loader::OpManifest where T: ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::OpManifest::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::toml_loader::OpManifest where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::toml_loader::OpManifest::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::toml_loader::OpManifest
pub fn vyre_driver::registry::toml_loader::OpManifest::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::registry::toml_loader::OpManifest where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::registry::toml_loader::OpManifest
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::toml_loader::OpManifest
impl<T> typenum::type_operators::Same for vyre_driver::registry::toml_loader::OpManifest
pub type vyre_driver::registry::toml_loader::OpManifest::Output = T
pub struct vyre_driver::registry::toml_loader::TomlDialectStore
impl vyre_driver::registry::toml_loader::TomlDialectStore
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::contains_op(&self, op_id: &str) -> bool
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::diagnostics(&self) -> &[vyre_driver::diagnostics::Diagnostic]
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::dialect(&self, id: &str) -> core::option::Option<&vyre_driver::registry::toml_loader::DialectManifest>
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::from_env() -> Self
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::load_file(&mut self, path: &std::path::Path)
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::manifests(&self) -> alloc::vec::Vec<&vyre_driver::registry::toml_loader::DialectManifest>
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::ops_in(&self, dialect: &str) -> &[vyre_driver::registry::toml_loader::OpManifest]
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::scan_dir(&mut self, dir: &std::path::Path)
impl core::clone::Clone for vyre_driver::registry::toml_loader::TomlDialectStore
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::clone(&self) -> vyre_driver::registry::toml_loader::TomlDialectStore
impl core::default::Default for vyre_driver::registry::toml_loader::TomlDialectStore
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::default() -> vyre_driver::registry::toml_loader::TomlDialectStore
impl core::fmt::Debug for vyre_driver::registry::toml_loader::TomlDialectStore
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::registry::toml_loader::TomlDialectStore
impl core::marker::Send for vyre_driver::registry::toml_loader::TomlDialectStore
impl core::marker::Sync for vyre_driver::registry::toml_loader::TomlDialectStore
impl core::marker::Unpin for vyre_driver::registry::toml_loader::TomlDialectStore
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::toml_loader::TomlDialectStore
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::toml_loader::TomlDialectStore
impl<T, U> core::convert::Into<U> for vyre_driver::registry::toml_loader::TomlDialectStore where U: core::convert::From<T>
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::toml_loader::TomlDialectStore where U: core::convert::Into<T>
pub type vyre_driver::registry::toml_loader::TomlDialectStore::Error = core::convert::Infallible
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::toml_loader::TomlDialectStore where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::toml_loader::TomlDialectStore::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::toml_loader::TomlDialectStore where T: core::clone::Clone
pub type vyre_driver::registry::toml_loader::TomlDialectStore::Owned = T
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::toml_loader::TomlDialectStore where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::toml_loader::TomlDialectStore where T: ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::toml_loader::TomlDialectStore where T: ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::toml_loader::TomlDialectStore where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::toml_loader::TomlDialectStore::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::toml_loader::TomlDialectStore
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::toml_loader::TomlDialectStore
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::toml_loader::TomlDialectStore
impl<T> typenum::type_operators::Same for vyre_driver::registry::toml_loader::TomlDialectStore
pub type vyre_driver::registry::toml_loader::TomlDialectStore::Output = T
pub const vyre_driver::registry::toml_loader::CODE_PARSE: vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::registry::toml_loader::workspace_dialect_fixture_path() -> std::path::PathBuf
#[non_exhaustive] pub enum vyre_driver::registry::AttrValue
pub vyre_driver::registry::AttrValue::Bool(bool)
pub vyre_driver::registry::AttrValue::Bytes(alloc::vec::Vec<u8>)
pub vyre_driver::registry::AttrValue::F32(f32)
pub vyre_driver::registry::AttrValue::I32(i32)
pub vyre_driver::registry::AttrValue::String(alloc::string::String)
pub vyre_driver::registry::AttrValue::U32(u32)
impl core::clone::Clone for vyre_driver::registry::migration::AttrValue
pub fn vyre_driver::registry::migration::AttrValue::clone(&self) -> vyre_driver::registry::migration::AttrValue
impl core::cmp::PartialEq for vyre_driver::registry::migration::AttrValue
pub fn vyre_driver::registry::migration::AttrValue::eq(&self, other: &vyre_driver::registry::migration::AttrValue) -> bool
impl core::fmt::Debug for vyre_driver::registry::migration::AttrValue
pub fn vyre_driver::registry::migration::AttrValue::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::migration::AttrValue
impl core::marker::Freeze for vyre_driver::registry::migration::AttrValue
impl core::marker::Send for vyre_driver::registry::migration::AttrValue
impl core::marker::Sync for vyre_driver::registry::migration::AttrValue
impl core::marker::Unpin for vyre_driver::registry::migration::AttrValue
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::migration::AttrValue
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::migration::AttrValue
impl<T, U> core::convert::Into<U> for vyre_driver::registry::migration::AttrValue where U: core::convert::From<T>
pub fn vyre_driver::registry::migration::AttrValue::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::migration::AttrValue where U: core::convert::Into<T>
pub type vyre_driver::registry::migration::AttrValue::Error = core::convert::Infallible
pub fn vyre_driver::registry::migration::AttrValue::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::migration::AttrValue where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::migration::AttrValue::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::migration::AttrValue::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::migration::AttrValue where T: core::clone::Clone
pub type vyre_driver::registry::migration::AttrValue::Owned = T
pub fn vyre_driver::registry::migration::AttrValue::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::migration::AttrValue::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::migration::AttrValue where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::migration::AttrValue::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::migration::AttrValue where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::AttrValue::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::migration::AttrValue where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::AttrValue::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::migration::AttrValue where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::migration::AttrValue::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::migration::AttrValue
pub fn vyre_driver::registry::migration::AttrValue::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::migration::AttrValue
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::migration::AttrValue
impl<T> typenum::type_operators::Same for vyre_driver::registry::migration::AttrValue
pub type vyre_driver::registry::migration::AttrValue::Output = T
#[non_exhaustive] pub enum vyre_driver::registry::EnforceVerdict
pub vyre_driver::registry::EnforceVerdict::Allow
pub vyre_driver::registry::EnforceVerdict::Deny
pub vyre_driver::registry::EnforceVerdict::Deny::detail: alloc::string::String
pub vyre_driver::registry::EnforceVerdict::Deny::policy: &'static str
impl core::clone::Clone for vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::EnforceVerdict::clone(&self) -> vyre_driver::registry::enforce::EnforceVerdict
impl core::cmp::Eq for vyre_driver::registry::enforce::EnforceVerdict
impl core::cmp::PartialEq for vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::EnforceVerdict::eq(&self, other: &vyre_driver::registry::enforce::EnforceVerdict) -> bool
impl core::fmt::Debug for vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::EnforceVerdict::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::enforce::EnforceVerdict
impl core::marker::Freeze for vyre_driver::registry::enforce::EnforceVerdict
impl core::marker::Send for vyre_driver::registry::enforce::EnforceVerdict
impl core::marker::Sync for vyre_driver::registry::enforce::EnforceVerdict
impl core::marker::Unpin for vyre_driver::registry::enforce::EnforceVerdict
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::enforce::EnforceVerdict
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::enforce::EnforceVerdict
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::enforce::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::enforce::EnforceVerdict::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::enforce::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::enforce::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::enforce::EnforceVerdict::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::enforce::EnforceVerdict::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::enforce::EnforceVerdict where U: core::convert::From<T>
pub fn vyre_driver::registry::enforce::EnforceVerdict::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::enforce::EnforceVerdict where U: core::convert::Into<T>
pub type vyre_driver::registry::enforce::EnforceVerdict::Error = core::convert::Infallible
pub fn vyre_driver::registry::enforce::EnforceVerdict::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::enforce::EnforceVerdict where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::enforce::EnforceVerdict::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::enforce::EnforceVerdict::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::enforce::EnforceVerdict where T: core::clone::Clone
pub type vyre_driver::registry::enforce::EnforceVerdict::Owned = T
pub fn vyre_driver::registry::enforce::EnforceVerdict::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::enforce::EnforceVerdict::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::enforce::EnforceVerdict where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::enforce::EnforceVerdict::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::enforce::EnforceVerdict where T: ?core::marker::Sized
pub fn vyre_driver::registry::enforce::EnforceVerdict::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::enforce::EnforceVerdict where T: ?core::marker::Sized
pub fn vyre_driver::registry::enforce::EnforceVerdict::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::enforce::EnforceVerdict where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::enforce::EnforceVerdict::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::EnforceVerdict::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::enforce::EnforceVerdict
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::enforce::EnforceVerdict
impl<T> typenum::type_operators::Same for vyre_driver::registry::enforce::EnforceVerdict
pub type vyre_driver::registry::enforce::EnforceVerdict::Output = T
#[non_exhaustive] pub enum vyre_driver::registry::MigrationError
pub vyre_driver::registry::MigrationError::Custom
pub vyre_driver::registry::MigrationError::Custom::reason: alloc::string::String
pub vyre_driver::registry::MigrationError::MissingAttribute
pub vyre_driver::registry::MigrationError::MissingAttribute::name: alloc::string::String
pub vyre_driver::registry::MigrationError::OutOfRange
pub vyre_driver::registry::MigrationError::OutOfRange::name: alloc::string::String
pub vyre_driver::registry::MigrationError::WrongType
pub vyre_driver::registry::MigrationError::WrongType::expected: &'static str
pub vyre_driver::registry::MigrationError::WrongType::name: alloc::string::String
impl core::clone::Clone for vyre_driver::registry::migration::MigrationError
pub fn vyre_driver::registry::migration::MigrationError::clone(&self) -> vyre_driver::registry::migration::MigrationError
impl core::cmp::Eq for vyre_driver::registry::migration::MigrationError
impl core::cmp::PartialEq for vyre_driver::registry::migration::MigrationError
pub fn vyre_driver::registry::migration::MigrationError::eq(&self, other: &vyre_driver::registry::migration::MigrationError) -> bool
impl core::error::Error for vyre_driver::registry::migration::MigrationError
impl core::fmt::Debug for vyre_driver::registry::migration::MigrationError
pub fn vyre_driver::registry::migration::MigrationError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::registry::migration::MigrationError
pub fn vyre_driver::registry::migration::MigrationError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::migration::MigrationError
impl core::marker::Freeze for vyre_driver::registry::migration::MigrationError
impl core::marker::Send for vyre_driver::registry::migration::MigrationError
impl core::marker::Sync for vyre_driver::registry::migration::MigrationError
impl core::marker::Unpin for vyre_driver::registry::migration::MigrationError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::migration::MigrationError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::migration::MigrationError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::migration::MigrationError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::migration::MigrationError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::migration::MigrationError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::migration::MigrationError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::migration::MigrationError where U: core::convert::From<T>
pub fn vyre_driver::registry::migration::MigrationError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::migration::MigrationError where U: core::convert::Into<T>
pub type vyre_driver::registry::migration::MigrationError::Error = core::convert::Infallible
pub fn vyre_driver::registry::migration::MigrationError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::migration::MigrationError where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::migration::MigrationError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::migration::MigrationError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::migration::MigrationError where T: core::clone::Clone
pub type vyre_driver::registry::migration::MigrationError::Owned = T
pub fn vyre_driver::registry::migration::MigrationError::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::migration::MigrationError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::registry::migration::MigrationError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::registry::migration::MigrationError where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::migration::MigrationError where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::migration::MigrationError where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::migration::MigrationError where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::migration::MigrationError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::migration::MigrationError
pub fn vyre_driver::registry::migration::MigrationError::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::migration::MigrationError
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::migration::MigrationError
impl<T> typenum::type_operators::Same for vyre_driver::registry::migration::MigrationError
pub type vyre_driver::registry::migration::MigrationError::Output = T
#[non_exhaustive] pub enum vyre_driver::registry::MutationClass
pub vyre_driver::registry::MutationClass::Cosmetic
pub vyre_driver::registry::MutationClass::Lowering
pub vyre_driver::registry::MutationClass::Semantic
pub vyre_driver::registry::MutationClass::Structural
impl vyre_driver::registry::mutation::MutationClass
pub const fn vyre_driver::registry::mutation::MutationClass::requires_byte_parity(self) -> bool
pub const fn vyre_driver::registry::mutation::MutationClass::uses_law_proof(self) -> bool
impl core::clone::Clone for vyre_driver::registry::mutation::MutationClass
pub fn vyre_driver::registry::mutation::MutationClass::clone(&self) -> vyre_driver::registry::mutation::MutationClass
impl core::cmp::Eq for vyre_driver::registry::mutation::MutationClass
impl core::cmp::PartialEq for vyre_driver::registry::mutation::MutationClass
pub fn vyre_driver::registry::mutation::MutationClass::eq(&self, other: &vyre_driver::registry::mutation::MutationClass) -> bool
impl core::fmt::Debug for vyre_driver::registry::mutation::MutationClass
pub fn vyre_driver::registry::mutation::MutationClass::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::registry::mutation::MutationClass
pub fn vyre_driver::registry::mutation::MutationClass::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::registry::mutation::MutationClass
impl core::marker::StructuralPartialEq for vyre_driver::registry::mutation::MutationClass
impl core::marker::Freeze for vyre_driver::registry::mutation::MutationClass
impl core::marker::Send for vyre_driver::registry::mutation::MutationClass
impl core::marker::Sync for vyre_driver::registry::mutation::MutationClass
impl core::marker::Unpin for vyre_driver::registry::mutation::MutationClass
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::mutation::MutationClass
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::mutation::MutationClass
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::mutation::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::mutation::MutationClass::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::mutation::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::mutation::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::mutation::MutationClass::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::mutation::MutationClass::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::mutation::MutationClass where U: core::convert::From<T>
pub fn vyre_driver::registry::mutation::MutationClass::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::mutation::MutationClass where U: core::convert::Into<T>
pub type vyre_driver::registry::mutation::MutationClass::Error = core::convert::Infallible
pub fn vyre_driver::registry::mutation::MutationClass::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::mutation::MutationClass where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::mutation::MutationClass::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::mutation::MutationClass::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::mutation::MutationClass where T: core::clone::Clone
pub type vyre_driver::registry::mutation::MutationClass::Owned = T
pub fn vyre_driver::registry::mutation::MutationClass::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::mutation::MutationClass::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::mutation::MutationClass where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::mutation::MutationClass::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::mutation::MutationClass where T: ?core::marker::Sized
pub fn vyre_driver::registry::mutation::MutationClass::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::mutation::MutationClass where T: ?core::marker::Sized
pub fn vyre_driver::registry::mutation::MutationClass::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::mutation::MutationClass where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::mutation::MutationClass::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::mutation::MutationClass
pub fn vyre_driver::registry::mutation::MutationClass::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::mutation::MutationClass
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::mutation::MutationClass
impl<T> typenum::type_operators::Same for vyre_driver::registry::mutation::MutationClass
pub type vyre_driver::registry::mutation::MutationClass::Output = T
#[non_exhaustive] pub enum vyre_driver::registry::Target
pub vyre_driver::registry::Target::Extension(&'static str)
pub vyre_driver::registry::Target::MetalIr
pub vyre_driver::registry::Target::Ptx
pub vyre_driver::registry::Target::ReferenceBackend
pub vyre_driver::registry::Target::Spirv
pub vyre_driver::registry::Target::Wgsl
impl core::clone::Clone for vyre_driver::registry::registry::Target
pub fn vyre_driver::registry::registry::Target::clone(&self) -> vyre_driver::registry::registry::Target
impl core::cmp::Eq for vyre_driver::registry::registry::Target
impl core::cmp::PartialEq for vyre_driver::registry::registry::Target
pub fn vyre_driver::registry::registry::Target::eq(&self, other: &vyre_driver::registry::registry::Target) -> bool
impl core::fmt::Debug for vyre_driver::registry::registry::Target
pub fn vyre_driver::registry::registry::Target::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::registry::registry::Target
pub fn vyre_driver::registry::registry::Target::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::registry::registry::Target
impl core::marker::StructuralPartialEq for vyre_driver::registry::registry::Target
impl core::marker::Freeze for vyre_driver::registry::registry::Target
impl core::marker::Send for vyre_driver::registry::registry::Target
impl core::marker::Sync for vyre_driver::registry::registry::Target
impl core::marker::Unpin for vyre_driver::registry::registry::Target
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::registry::Target
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::registry::Target
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::registry::Target::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::registry::Target::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::registry::Target::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::registry::Target where U: core::convert::From<T>
pub fn vyre_driver::registry::registry::Target::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::registry::Target where U: core::convert::Into<T>
pub type vyre_driver::registry::registry::Target::Error = core::convert::Infallible
pub fn vyre_driver::registry::registry::Target::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::registry::Target where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::registry::Target::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::registry::Target::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::registry::Target where T: core::clone::Clone
pub type vyre_driver::registry::registry::Target::Owned = T
pub fn vyre_driver::registry::registry::Target::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::registry::Target::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::registry::Target where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::registry::Target::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::registry::Target where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::Target::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::registry::Target where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::Target::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::registry::Target where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::registry::Target::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::registry::Target
pub fn vyre_driver::registry::registry::Target::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::registry::Target
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::registry::Target
impl<T> typenum::type_operators::Same for vyre_driver::registry::registry::Target
pub type vyre_driver::registry::registry::Target::Output = T
pub struct vyre_driver::registry::AttrMap
impl vyre_driver::registry::migration::AttrMap
pub fn vyre_driver::registry::migration::AttrMap::get(&self, key: &str) -> core::option::Option<&vyre_driver::registry::migration::AttrValue>
pub fn vyre_driver::registry::migration::AttrMap::insert(&mut self, key: impl core::convert::Into<alloc::string::String>, value: vyre_driver::registry::migration::AttrValue) -> core::option::Option<vyre_driver::registry::migration::AttrValue>
pub fn vyre_driver::registry::migration::AttrMap::is_empty(&self) -> bool
pub fn vyre_driver::registry::migration::AttrMap::iter(&self) -> impl core::iter::traits::iterator::Iterator<Item = (&str, &vyre_driver::registry::migration::AttrValue)>
pub fn vyre_driver::registry::migration::AttrMap::len(&self) -> usize
pub fn vyre_driver::registry::migration::AttrMap::new() -> Self
pub fn vyre_driver::registry::migration::AttrMap::remove(&mut self, key: &str) -> core::option::Option<vyre_driver::registry::migration::AttrValue>
pub fn vyre_driver::registry::migration::AttrMap::rename(&mut self, from: &str, to: impl core::convert::Into<alloc::string::String>) -> bool
impl core::clone::Clone for vyre_driver::registry::migration::AttrMap
pub fn vyre_driver::registry::migration::AttrMap::clone(&self) -> vyre_driver::registry::migration::AttrMap
impl core::default::Default for vyre_driver::registry::migration::AttrMap
pub fn vyre_driver::registry::migration::AttrMap::default() -> vyre_driver::registry::migration::AttrMap
impl core::fmt::Debug for vyre_driver::registry::migration::AttrMap
pub fn vyre_driver::registry::migration::AttrMap::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::registry::migration::AttrMap
impl core::marker::Send for vyre_driver::registry::migration::AttrMap
impl core::marker::Sync for vyre_driver::registry::migration::AttrMap
impl core::marker::Unpin for vyre_driver::registry::migration::AttrMap
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::migration::AttrMap
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::migration::AttrMap
impl<T, U> core::convert::Into<U> for vyre_driver::registry::migration::AttrMap where U: core::convert::From<T>
pub fn vyre_driver::registry::migration::AttrMap::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::migration::AttrMap where U: core::convert::Into<T>
pub type vyre_driver::registry::migration::AttrMap::Error = core::convert::Infallible
pub fn vyre_driver::registry::migration::AttrMap::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::migration::AttrMap where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::migration::AttrMap::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::migration::AttrMap::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::migration::AttrMap where T: core::clone::Clone
pub type vyre_driver::registry::migration::AttrMap::Owned = T
pub fn vyre_driver::registry::migration::AttrMap::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::migration::AttrMap::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::migration::AttrMap where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::migration::AttrMap::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::migration::AttrMap where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::AttrMap::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::migration::AttrMap where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::AttrMap::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::migration::AttrMap where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::migration::AttrMap::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::migration::AttrMap
pub fn vyre_driver::registry::migration::AttrMap::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::migration::AttrMap
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::migration::AttrMap
impl<T> typenum::type_operators::Same for vyre_driver::registry::migration::AttrMap
pub type vyre_driver::registry::migration::AttrMap::Output = T
pub struct vyre_driver::registry::Chain<A, B>
impl<A: vyre_driver::registry::enforce::EnforceGate, B: vyre_driver::registry::enforce::EnforceGate> vyre_driver::registry::enforce::Chain<A, B>
pub fn vyre_driver::registry::enforce::Chain<A, B>::new(first: A, second: B) -> Self
impl<A: vyre_driver::registry::enforce::EnforceGate, B: vyre_driver::registry::enforce::EnforceGate> vyre_driver::registry::enforce::EnforceGate for vyre_driver::registry::enforce::Chain<A, B>
pub fn vyre_driver::registry::enforce::Chain<A, B>::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::core::Program) -> vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::Chain<A, B>::name(&self) -> &'static str
impl<A, B> core::marker::Freeze for vyre_driver::registry::enforce::Chain<A, B> where A: core::marker::Freeze, B: core::marker::Freeze
impl<A, B> core::marker::Send for vyre_driver::registry::enforce::Chain<A, B> where A: core::marker::Send, B: core::marker::Send
impl<A, B> core::marker::Sync for vyre_driver::registry::enforce::Chain<A, B> where A: core::marker::Sync, B: core::marker::Sync
impl<A, B> core::marker::Unpin for vyre_driver::registry::enforce::Chain<A, B> where A: core::marker::Unpin, B: core::marker::Unpin
impl<A, B> core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::enforce::Chain<A, B> where A: core::panic::unwind_safe::RefUnwindSafe, B: core::panic::unwind_safe::RefUnwindSafe
impl<A, B> core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::enforce::Chain<A, B> where A: core::panic::unwind_safe::UnwindSafe, B: core::panic::unwind_safe::UnwindSafe
impl<T, U> core::convert::Into<U> for vyre_driver::registry::enforce::Chain<A, B> where U: core::convert::From<T>
pub fn vyre_driver::registry::enforce::Chain<A, B>::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::enforce::Chain<A, B> where U: core::convert::Into<T>
pub type vyre_driver::registry::enforce::Chain<A, B>::Error = core::convert::Infallible
pub fn vyre_driver::registry::enforce::Chain<A, B>::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::enforce::Chain<A, B> where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::enforce::Chain<A, B>::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::enforce::Chain<A, B>::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::enforce::Chain<A, B> where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::enforce::Chain<A, B>::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::enforce::Chain<A, B> where T: ?core::marker::Sized
pub fn vyre_driver::registry::enforce::Chain<A, B>::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::enforce::Chain<A, B> where T: ?core::marker::Sized
pub fn vyre_driver::registry::enforce::Chain<A, B>::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::enforce::Chain<A, B>
pub fn vyre_driver::registry::enforce::Chain<A, B>::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::enforce::Chain<A, B>
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::enforce::Chain<A, B>
impl<T> typenum::type_operators::Same for vyre_driver::registry::enforce::Chain<A, B>
pub type vyre_driver::registry::enforce::Chain<A, B>::Output = T
pub struct vyre_driver::registry::Deprecation
pub vyre_driver::registry::Deprecation::deprecated_since: vyre_driver::registry::migration::Semver
pub vyre_driver::registry::Deprecation::note: &'static str
pub vyre_driver::registry::Deprecation::op_id: &'static str
impl vyre_driver::registry::migration::Deprecation
pub const fn vyre_driver::registry::migration::Deprecation::new(op_id: &'static str, deprecated_since: vyre_driver::registry::migration::Semver, note: &'static str) -> Self
impl inventory::Collect for vyre_driver::registry::migration::Deprecation
impl core::marker::Freeze for vyre_driver::registry::migration::Deprecation
impl core::marker::Send for vyre_driver::registry::migration::Deprecation
impl core::marker::Sync for vyre_driver::registry::migration::Deprecation
impl core::marker::Unpin for vyre_driver::registry::migration::Deprecation
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::migration::Deprecation
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::migration::Deprecation
impl<T, U> core::convert::Into<U> for vyre_driver::registry::migration::Deprecation where U: core::convert::From<T>
pub fn vyre_driver::registry::migration::Deprecation::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::migration::Deprecation where U: core::convert::Into<T>
pub type vyre_driver::registry::migration::Deprecation::Error = core::convert::Infallible
pub fn vyre_driver::registry::migration::Deprecation::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::migration::Deprecation where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::migration::Deprecation::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::migration::Deprecation::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::migration::Deprecation where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::migration::Deprecation::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::migration::Deprecation where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::Deprecation::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::migration::Deprecation where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::Deprecation::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::migration::Deprecation
pub fn vyre_driver::registry::migration::Deprecation::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::migration::Deprecation
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::migration::Deprecation
impl<T> typenum::type_operators::Same for vyre_driver::registry::migration::Deprecation
pub type vyre_driver::registry::migration::Deprecation::Output = T
pub struct vyre_driver::registry::Dialect
pub vyre_driver::registry::Dialect::backends_required: &'static [vyre_spec::intrinsic_descriptor::Backend]
pub vyre_driver::registry::Dialect::id: &'static str
pub vyre_driver::registry::Dialect::ops: &'static [&'static str]
pub vyre_driver::registry::Dialect::parent: core::option::Option<&'static str>
pub vyre_driver::registry::Dialect::validator: fn() -> bool
pub vyre_driver::registry::Dialect::version: u32
impl core::marker::Freeze for vyre_driver::registry::dialect::Dialect
impl core::marker::Send for vyre_driver::registry::dialect::Dialect
impl core::marker::Sync for vyre_driver::registry::dialect::Dialect
impl core::marker::Unpin for vyre_driver::registry::dialect::Dialect
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::dialect::Dialect
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::dialect::Dialect
impl<T, U> core::convert::Into<U> for vyre_driver::registry::dialect::Dialect where U: core::convert::From<T>
pub fn vyre_driver::registry::dialect::Dialect::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::dialect::Dialect where U: core::convert::Into<T>
pub type vyre_driver::registry::dialect::Dialect::Error = core::convert::Infallible
pub fn vyre_driver::registry::dialect::Dialect::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::dialect::Dialect where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::dialect::Dialect::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::dialect::Dialect::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::dialect::Dialect where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::dialect::Dialect::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::dialect::Dialect where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::Dialect::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::dialect::Dialect where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::Dialect::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::dialect::Dialect
pub fn vyre_driver::registry::dialect::Dialect::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::dialect::Dialect
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::dialect::Dialect
impl<T> typenum::type_operators::Same for vyre_driver::registry::dialect::Dialect
pub type vyre_driver::registry::dialect::Dialect::Output = T
pub struct vyre_driver::registry::DialectManifest
pub vyre_driver::registry::DialectManifest::description: core::option::Option<alloc::string::String>
pub vyre_driver::registry::DialectManifest::dialect: alloc::string::String
pub vyre_driver::registry::DialectManifest::ops: alloc::vec::Vec<vyre_driver::registry::toml_loader::OpManifest>
pub vyre_driver::registry::DialectManifest::version: alloc::string::String
impl core::clone::Clone for vyre_driver::registry::toml_loader::DialectManifest
pub fn vyre_driver::registry::toml_loader::DialectManifest::clone(&self) -> vyre_driver::registry::toml_loader::DialectManifest
impl core::cmp::PartialEq for vyre_driver::registry::toml_loader::DialectManifest
pub fn vyre_driver::registry::toml_loader::DialectManifest::eq(&self, other: &vyre_driver::registry::toml_loader::DialectManifest) -> bool
impl core::fmt::Debug for vyre_driver::registry::toml_loader::DialectManifest
pub fn vyre_driver::registry::toml_loader::DialectManifest::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::toml_loader::DialectManifest
impl serde_core::ser::Serialize for vyre_driver::registry::toml_loader::DialectManifest
pub fn vyre_driver::registry::toml_loader::DialectManifest::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::registry::toml_loader::DialectManifest
pub fn vyre_driver::registry::toml_loader::DialectManifest::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::registry::toml_loader::DialectManifest
impl core::marker::Send for vyre_driver::registry::toml_loader::DialectManifest
impl core::marker::Sync for vyre_driver::registry::toml_loader::DialectManifest
impl core::marker::Unpin for vyre_driver::registry::toml_loader::DialectManifest
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::toml_loader::DialectManifest
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::toml_loader::DialectManifest
impl<T, U> core::convert::Into<U> for vyre_driver::registry::toml_loader::DialectManifest where U: core::convert::From<T>
pub fn vyre_driver::registry::toml_loader::DialectManifest::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::toml_loader::DialectManifest where U: core::convert::Into<T>
pub type vyre_driver::registry::toml_loader::DialectManifest::Error = core::convert::Infallible
pub fn vyre_driver::registry::toml_loader::DialectManifest::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::toml_loader::DialectManifest where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::toml_loader::DialectManifest::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::toml_loader::DialectManifest::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::toml_loader::DialectManifest where T: core::clone::Clone
pub type vyre_driver::registry::toml_loader::DialectManifest::Owned = T
pub fn vyre_driver::registry::toml_loader::DialectManifest::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::toml_loader::DialectManifest::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::toml_loader::DialectManifest where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::DialectManifest::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::toml_loader::DialectManifest where T: ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::DialectManifest::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::toml_loader::DialectManifest where T: ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::DialectManifest::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::toml_loader::DialectManifest where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::toml_loader::DialectManifest::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::toml_loader::DialectManifest
pub fn vyre_driver::registry::toml_loader::DialectManifest::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::registry::toml_loader::DialectManifest where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::registry::toml_loader::DialectManifest
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::toml_loader::DialectManifest
impl<T> typenum::type_operators::Same for vyre_driver::registry::toml_loader::DialectManifest
pub type vyre_driver::registry::toml_loader::DialectManifest::Output = T
pub struct vyre_driver::registry::DialectRegistration
pub vyre_driver::registry::DialectRegistration::dialect: fn() -> vyre_driver::registry::dialect::Dialect
impl inventory::Collect for vyre_driver::registry::dialect::DialectRegistration
impl core::marker::Freeze for vyre_driver::registry::dialect::DialectRegistration
impl core::marker::Send for vyre_driver::registry::dialect::DialectRegistration
impl core::marker::Sync for vyre_driver::registry::dialect::DialectRegistration
impl core::marker::Unpin for vyre_driver::registry::dialect::DialectRegistration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::dialect::DialectRegistration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::dialect::DialectRegistration
impl<T, U> core::convert::Into<U> for vyre_driver::registry::dialect::DialectRegistration where U: core::convert::From<T>
pub fn vyre_driver::registry::dialect::DialectRegistration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::dialect::DialectRegistration where U: core::convert::Into<T>
pub type vyre_driver::registry::dialect::DialectRegistration::Error = core::convert::Infallible
pub fn vyre_driver::registry::dialect::DialectRegistration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::dialect::DialectRegistration where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::dialect::DialectRegistration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::dialect::DialectRegistration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::dialect::DialectRegistration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::dialect::DialectRegistration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::dialect::DialectRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::DialectRegistration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::dialect::DialectRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::DialectRegistration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::dialect::DialectRegistration
pub fn vyre_driver::registry::dialect::DialectRegistration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::dialect::DialectRegistration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::dialect::DialectRegistration
impl<T> typenum::type_operators::Same for vyre_driver::registry::dialect::DialectRegistration
pub type vyre_driver::registry::dialect::DialectRegistration::Output = T
pub struct vyre_driver::registry::DialectRegistry
impl vyre_driver::registry::registry::DialectRegistry
pub fn vyre_driver::registry::registry::DialectRegistry::get_lowering(&self, id: vyre_foundation::dialect_lookup::InternedOpId, target: vyre_driver::registry::registry::Target) -> core::option::Option<vyre_foundation::dialect_lookup::ReferenceKind>
pub fn vyre_driver::registry::registry::DialectRegistry::global() -> arc_swap::Guard<alloc::sync::Arc<Self>>
pub fn vyre_driver::registry::registry::DialectRegistry::install(new: Self)
pub fn vyre_driver::registry::registry::DialectRegistry::intern_op(&self, name: &str) -> vyre_foundation::dialect_lookup::InternedOpId
pub fn vyre_driver::registry::registry::DialectRegistry::iter(&self) -> impl core::iter::traits::iterator::Iterator<Item = &'static vyre_foundation::dialect_lookup::OpDef> + '_
pub fn vyre_driver::registry::registry::DialectRegistry::lookup(&self, id: vyre_foundation::dialect_lookup::InternedOpId) -> core::option::Option<&'static vyre_foundation::dialect_lookup::OpDef>
pub fn vyre_driver::registry::registry::DialectRegistry::validate_no_duplicates<'a>(defs: impl core::iter::traits::collect::IntoIterator<Item = &'a vyre_foundation::dialect_lookup::OpDef>) -> core::result::Result<(), vyre_driver::registry::registry::DuplicateOpIdError>
impl vyre_foundation::dialect_lookup::DialectLookup for vyre_driver::registry::registry::DialectRegistry
pub fn vyre_driver::registry::registry::DialectRegistry::intern_op(&self, name: &str) -> vyre_foundation::dialect_lookup::InternedOpId
pub fn vyre_driver::registry::registry::DialectRegistry::lookup(&self, id: vyre_foundation::dialect_lookup::InternedOpId) -> core::option::Option<&'static vyre_foundation::dialect_lookup::OpDef>
pub fn vyre_driver::registry::registry::DialectRegistry::provider_id(&self) -> &'static str
impl vyre_foundation::dialect_lookup::private::Sealed for vyre_driver::registry::registry::DialectRegistry
impl core::marker::Freeze for vyre_driver::registry::registry::DialectRegistry
impl core::marker::Send for vyre_driver::registry::registry::DialectRegistry
impl core::marker::Sync for vyre_driver::registry::registry::DialectRegistry
impl core::marker::Unpin for vyre_driver::registry::registry::DialectRegistry
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::registry::DialectRegistry
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::registry::DialectRegistry
impl<T, U> core::convert::Into<U> for vyre_driver::registry::registry::DialectRegistry where U: core::convert::From<T>
pub fn vyre_driver::registry::registry::DialectRegistry::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::registry::DialectRegistry where U: core::convert::Into<T>
pub type vyre_driver::registry::registry::DialectRegistry::Error = core::convert::Infallible
pub fn vyre_driver::registry::registry::DialectRegistry::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::registry::DialectRegistry where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::registry::DialectRegistry::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::registry::DialectRegistry::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::registry::DialectRegistry where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::registry::DialectRegistry::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::registry::DialectRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::DialectRegistry::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::registry::DialectRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::DialectRegistry::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::registry::DialectRegistry
pub fn vyre_driver::registry::registry::DialectRegistry::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::registry::DialectRegistry
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::registry::DialectRegistry
impl<T> typenum::type_operators::Same for vyre_driver::registry::registry::DialectRegistry
pub type vyre_driver::registry::registry::DialectRegistry::Output = T
pub struct vyre_driver::registry::DuplicateOpIdError
impl vyre_driver::registry::registry::DuplicateOpIdError
pub const fn vyre_driver::registry::registry::DuplicateOpIdError::first_registrant(&self) -> &'static str
pub const fn vyre_driver::registry::registry::DuplicateOpIdError::op_id(&self) -> &'static str
pub const fn vyre_driver::registry::registry::DuplicateOpIdError::second_registrant(&self) -> &'static str
impl core::clone::Clone for vyre_driver::registry::registry::DuplicateOpIdError
pub fn vyre_driver::registry::registry::DuplicateOpIdError::clone(&self) -> vyre_driver::registry::registry::DuplicateOpIdError
impl core::cmp::Eq for vyre_driver::registry::registry::DuplicateOpIdError
impl core::cmp::PartialEq for vyre_driver::registry::registry::DuplicateOpIdError
pub fn vyre_driver::registry::registry::DuplicateOpIdError::eq(&self, other: &vyre_driver::registry::registry::DuplicateOpIdError) -> bool
impl core::error::Error for vyre_driver::registry::registry::DuplicateOpIdError
impl core::fmt::Debug for vyre_driver::registry::registry::DuplicateOpIdError
pub fn vyre_driver::registry::registry::DuplicateOpIdError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::registry::registry::DuplicateOpIdError
pub fn vyre_driver::registry::registry::DuplicateOpIdError::fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::registry::DuplicateOpIdError
impl core::marker::Freeze for vyre_driver::registry::registry::DuplicateOpIdError
impl core::marker::Send for vyre_driver::registry::registry::DuplicateOpIdError
impl core::marker::Sync for vyre_driver::registry::registry::DuplicateOpIdError
impl core::marker::Unpin for vyre_driver::registry::registry::DuplicateOpIdError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::registry::DuplicateOpIdError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::registry::DuplicateOpIdError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::registry::DuplicateOpIdError where U: core::convert::From<T>
pub fn vyre_driver::registry::registry::DuplicateOpIdError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::registry::DuplicateOpIdError where U: core::convert::Into<T>
pub type vyre_driver::registry::registry::DuplicateOpIdError::Error = core::convert::Infallible
pub fn vyre_driver::registry::registry::DuplicateOpIdError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::registry::DuplicateOpIdError where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::registry::DuplicateOpIdError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::registry::DuplicateOpIdError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::registry::DuplicateOpIdError where T: core::clone::Clone
pub type vyre_driver::registry::registry::DuplicateOpIdError::Owned = T
pub fn vyre_driver::registry::registry::DuplicateOpIdError::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::registry::DuplicateOpIdError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::registry::registry::DuplicateOpIdError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::registry::registry::DuplicateOpIdError where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::registry::DuplicateOpIdError where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::registry::DuplicateOpIdError where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::registry::DuplicateOpIdError where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::registry::DuplicateOpIdError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::registry::DuplicateOpIdError
pub fn vyre_driver::registry::registry::DuplicateOpIdError::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::registry::DuplicateOpIdError
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::registry::DuplicateOpIdError
impl<T> typenum::type_operators::Same for vyre_driver::registry::registry::DuplicateOpIdError
pub type vyre_driver::registry::registry::DuplicateOpIdError::Output = T
pub struct vyre_driver::registry::Migration
pub vyre_driver::registry::Migration::from: (&'static str, vyre_driver::registry::migration::Semver)
pub vyre_driver::registry::Migration::rewrite: fn(&mut vyre_driver::registry::migration::AttrMap) -> core::result::Result<(), vyre_driver::registry::migration::MigrationError>
pub vyre_driver::registry::Migration::to: (&'static str, vyre_driver::registry::migration::Semver)
impl vyre_driver::registry::migration::Migration
pub const fn vyre_driver::registry::migration::Migration::new(from: (&'static str, vyre_driver::registry::migration::Semver), to: (&'static str, vyre_driver::registry::migration::Semver), rewrite: fn(&mut vyre_driver::registry::migration::AttrMap) -> core::result::Result<(), vyre_driver::registry::migration::MigrationError>) -> Self
impl inventory::Collect for vyre_driver::registry::migration::Migration
impl core::marker::Freeze for vyre_driver::registry::migration::Migration
impl core::marker::Send for vyre_driver::registry::migration::Migration
impl core::marker::Sync for vyre_driver::registry::migration::Migration
impl core::marker::Unpin for vyre_driver::registry::migration::Migration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::migration::Migration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::migration::Migration
impl<T, U> core::convert::Into<U> for vyre_driver::registry::migration::Migration where U: core::convert::From<T>
pub fn vyre_driver::registry::migration::Migration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::migration::Migration where U: core::convert::Into<T>
pub type vyre_driver::registry::migration::Migration::Error = core::convert::Infallible
pub fn vyre_driver::registry::migration::Migration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::migration::Migration where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::migration::Migration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::migration::Migration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::migration::Migration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::migration::Migration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::migration::Migration where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::Migration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::migration::Migration where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::Migration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::migration::Migration
pub fn vyre_driver::registry::migration::Migration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::migration::Migration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::migration::Migration
impl<T> typenum::type_operators::Same for vyre_driver::registry::migration::Migration
pub type vyre_driver::registry::migration::Migration::Output = T
pub struct vyre_driver::registry::MigrationRegistry
impl vyre_driver::registry::migration::MigrationRegistry
pub fn vyre_driver::registry::migration::MigrationRegistry::apply_chain(&self, op_id: &'static str, from: vyre_driver::registry::migration::Semver, attrs: &mut vyre_driver::registry::migration::AttrMap) -> core::result::Result<(&'static str, vyre_driver::registry::migration::Semver), vyre_driver::registry::migration::MigrationError>
pub fn vyre_driver::registry::migration::MigrationRegistry::deprecation(&self, op_id: &str) -> core::option::Option<&'static vyre_driver::registry::migration::Deprecation>
pub fn vyre_driver::registry::migration::MigrationRegistry::global() -> &'static vyre_driver::registry::migration::MigrationRegistry
pub fn vyre_driver::registry::migration::MigrationRegistry::lookup(&self, op_id: &str, from: vyre_driver::registry::migration::Semver) -> core::option::Option<&'static vyre_driver::registry::migration::Migration>
impl core::marker::Freeze for vyre_driver::registry::migration::MigrationRegistry
impl core::marker::Send for vyre_driver::registry::migration::MigrationRegistry
impl core::marker::Sync for vyre_driver::registry::migration::MigrationRegistry
impl core::marker::Unpin for vyre_driver::registry::migration::MigrationRegistry
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::migration::MigrationRegistry
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::migration::MigrationRegistry
impl<T, U> core::convert::Into<U> for vyre_driver::registry::migration::MigrationRegistry where U: core::convert::From<T>
pub fn vyre_driver::registry::migration::MigrationRegistry::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::migration::MigrationRegistry where U: core::convert::Into<T>
pub type vyre_driver::registry::migration::MigrationRegistry::Error = core::convert::Infallible
pub fn vyre_driver::registry::migration::MigrationRegistry::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::migration::MigrationRegistry where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::migration::MigrationRegistry::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::migration::MigrationRegistry::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::migration::MigrationRegistry where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationRegistry::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::migration::MigrationRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationRegistry::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::migration::MigrationRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::MigrationRegistry::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::migration::MigrationRegistry
pub fn vyre_driver::registry::migration::MigrationRegistry::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::migration::MigrationRegistry
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::migration::MigrationRegistry
impl<T> typenum::type_operators::Same for vyre_driver::registry::migration::MigrationRegistry
pub type vyre_driver::registry::migration::MigrationRegistry::Output = T
pub struct vyre_driver::registry::OpBackendTarget
pub vyre_driver::registry::OpBackendTarget::op: &'static str
pub vyre_driver::registry::OpBackendTarget::target: &'static str
impl inventory::Collect for vyre_driver::registry::dialect::OpBackendTarget
impl core::marker::Freeze for vyre_driver::registry::dialect::OpBackendTarget
impl core::marker::Send for vyre_driver::registry::dialect::OpBackendTarget
impl core::marker::Sync for vyre_driver::registry::dialect::OpBackendTarget
impl core::marker::Unpin for vyre_driver::registry::dialect::OpBackendTarget
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::dialect::OpBackendTarget
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::dialect::OpBackendTarget
impl<T, U> core::convert::Into<U> for vyre_driver::registry::dialect::OpBackendTarget where U: core::convert::From<T>
pub fn vyre_driver::registry::dialect::OpBackendTarget::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::dialect::OpBackendTarget where U: core::convert::Into<T>
pub type vyre_driver::registry::dialect::OpBackendTarget::Error = core::convert::Infallible
pub fn vyre_driver::registry::dialect::OpBackendTarget::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::dialect::OpBackendTarget where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::dialect::OpBackendTarget::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::dialect::OpBackendTarget::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::dialect::OpBackendTarget where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpBackendTarget::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::dialect::OpBackendTarget where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpBackendTarget::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::dialect::OpBackendTarget where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpBackendTarget::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::dialect::OpBackendTarget
pub fn vyre_driver::registry::dialect::OpBackendTarget::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::dialect::OpBackendTarget
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::dialect::OpBackendTarget
impl<T> typenum::type_operators::Same for vyre_driver::registry::dialect::OpBackendTarget
pub type vyre_driver::registry::dialect::OpBackendTarget::Output = T
pub struct vyre_driver::registry::OpDefRegistration
pub vyre_driver::registry::OpDefRegistration::op: fn() -> vyre_foundation::dialect_lookup::OpDef
impl vyre_driver::registry::dialect::OpDefRegistration
pub const fn vyre_driver::registry::dialect::OpDefRegistration::new(op: fn() -> vyre_foundation::dialect_lookup::OpDef) -> Self
impl inventory::Collect for vyre_driver::registry::dialect::OpDefRegistration
impl core::marker::Freeze for vyre_driver::registry::dialect::OpDefRegistration
impl core::marker::Send for vyre_driver::registry::dialect::OpDefRegistration
impl core::marker::Sync for vyre_driver::registry::dialect::OpDefRegistration
impl core::marker::Unpin for vyre_driver::registry::dialect::OpDefRegistration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::dialect::OpDefRegistration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::dialect::OpDefRegistration
impl<T, U> core::convert::Into<U> for vyre_driver::registry::dialect::OpDefRegistration where U: core::convert::From<T>
pub fn vyre_driver::registry::dialect::OpDefRegistration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::dialect::OpDefRegistration where U: core::convert::Into<T>
pub type vyre_driver::registry::dialect::OpDefRegistration::Error = core::convert::Infallible
pub fn vyre_driver::registry::dialect::OpDefRegistration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::dialect::OpDefRegistration where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::dialect::OpDefRegistration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::dialect::OpDefRegistration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::dialect::OpDefRegistration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpDefRegistration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::dialect::OpDefRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpDefRegistration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::dialect::OpDefRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpDefRegistration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::dialect::OpDefRegistration
pub fn vyre_driver::registry::dialect::OpDefRegistration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::dialect::OpDefRegistration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::dialect::OpDefRegistration
impl<T> typenum::type_operators::Same for vyre_driver::registry::dialect::OpDefRegistration
pub type vyre_driver::registry::dialect::OpDefRegistration::Output = T
pub struct vyre_driver::registry::OpManifest
pub vyre_driver::registry::OpManifest::category: alloc::string::String
pub vyre_driver::registry::OpManifest::id: alloc::string::String
pub vyre_driver::registry::OpManifest::inputs: alloc::vec::Vec<(alloc::string::String, alloc::string::String)>
pub vyre_driver::registry::OpManifest::laws: alloc::vec::Vec<alloc::string::String>
pub vyre_driver::registry::OpManifest::outputs: alloc::vec::Vec<(alloc::string::String, alloc::string::String)>
pub vyre_driver::registry::OpManifest::summary: core::option::Option<alloc::string::String>
impl core::clone::Clone for vyre_driver::registry::toml_loader::OpManifest
pub fn vyre_driver::registry::toml_loader::OpManifest::clone(&self) -> vyre_driver::registry::toml_loader::OpManifest
impl core::cmp::PartialEq for vyre_driver::registry::toml_loader::OpManifest
pub fn vyre_driver::registry::toml_loader::OpManifest::eq(&self, other: &vyre_driver::registry::toml_loader::OpManifest) -> bool
impl core::fmt::Debug for vyre_driver::registry::toml_loader::OpManifest
pub fn vyre_driver::registry::toml_loader::OpManifest::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::toml_loader::OpManifest
impl serde_core::ser::Serialize for vyre_driver::registry::toml_loader::OpManifest
pub fn vyre_driver::registry::toml_loader::OpManifest::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::registry::toml_loader::OpManifest
pub fn vyre_driver::registry::toml_loader::OpManifest::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::registry::toml_loader::OpManifest
impl core::marker::Send for vyre_driver::registry::toml_loader::OpManifest
impl core::marker::Sync for vyre_driver::registry::toml_loader::OpManifest
impl core::marker::Unpin for vyre_driver::registry::toml_loader::OpManifest
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::toml_loader::OpManifest
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::toml_loader::OpManifest
impl<T, U> core::convert::Into<U> for vyre_driver::registry::toml_loader::OpManifest where U: core::convert::From<T>
pub fn vyre_driver::registry::toml_loader::OpManifest::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::toml_loader::OpManifest where U: core::convert::Into<T>
pub type vyre_driver::registry::toml_loader::OpManifest::Error = core::convert::Infallible
pub fn vyre_driver::registry::toml_loader::OpManifest::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::toml_loader::OpManifest where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::toml_loader::OpManifest::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::toml_loader::OpManifest::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::toml_loader::OpManifest where T: core::clone::Clone
pub type vyre_driver::registry::toml_loader::OpManifest::Owned = T
pub fn vyre_driver::registry::toml_loader::OpManifest::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::toml_loader::OpManifest::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::toml_loader::OpManifest where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::OpManifest::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::toml_loader::OpManifest where T: ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::OpManifest::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::toml_loader::OpManifest where T: ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::OpManifest::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::toml_loader::OpManifest where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::toml_loader::OpManifest::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::toml_loader::OpManifest
pub fn vyre_driver::registry::toml_loader::OpManifest::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::registry::toml_loader::OpManifest where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::registry::toml_loader::OpManifest
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::toml_loader::OpManifest
impl<T> typenum::type_operators::Same for vyre_driver::registry::toml_loader::OpManifest
pub type vyre_driver::registry::toml_loader::OpManifest::Output = T
pub struct vyre_driver::registry::Semver
pub vyre_driver::registry::Semver::major: u32
pub vyre_driver::registry::Semver::minor: u32
pub vyre_driver::registry::Semver::patch: u32
impl vyre_driver::registry::migration::Semver
pub const fn vyre_driver::registry::migration::Semver::new(major: u32, minor: u32, patch: u32) -> Self
impl core::clone::Clone for vyre_driver::registry::migration::Semver
pub fn vyre_driver::registry::migration::Semver::clone(&self) -> vyre_driver::registry::migration::Semver
impl core::cmp::Eq for vyre_driver::registry::migration::Semver
impl core::cmp::Ord for vyre_driver::registry::migration::Semver
pub fn vyre_driver::registry::migration::Semver::cmp(&self, other: &vyre_driver::registry::migration::Semver) -> core::cmp::Ordering
impl core::cmp::PartialEq for vyre_driver::registry::migration::Semver
pub fn vyre_driver::registry::migration::Semver::eq(&self, other: &vyre_driver::registry::migration::Semver) -> bool
impl core::cmp::PartialOrd for vyre_driver::registry::migration::Semver
pub fn vyre_driver::registry::migration::Semver::partial_cmp(&self, other: &vyre_driver::registry::migration::Semver) -> core::option::Option<core::cmp::Ordering>
impl core::fmt::Debug for vyre_driver::registry::migration::Semver
pub fn vyre_driver::registry::migration::Semver::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::registry::migration::Semver
pub fn vyre_driver::registry::migration::Semver::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::registry::migration::Semver
pub fn vyre_driver::registry::migration::Semver::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::registry::migration::Semver
impl core::marker::StructuralPartialEq for vyre_driver::registry::migration::Semver
impl core::marker::Freeze for vyre_driver::registry::migration::Semver
impl core::marker::Send for vyre_driver::registry::migration::Semver
impl core::marker::Sync for vyre_driver::registry::migration::Semver
impl core::marker::Unpin for vyre_driver::registry::migration::Semver
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::migration::Semver
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::migration::Semver
impl<Q, K> equivalent::Comparable<K> for vyre_driver::registry::migration::Semver where Q: core::cmp::Ord + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::migration::Semver::compare(&self, key: &K) -> core::cmp::Ordering
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::migration::Semver where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::migration::Semver::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::migration::Semver where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::migration::Semver where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::migration::Semver::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::migration::Semver::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::migration::Semver where U: core::convert::From<T>
pub fn vyre_driver::registry::migration::Semver::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::migration::Semver where U: core::convert::Into<T>
pub type vyre_driver::registry::migration::Semver::Error = core::convert::Infallible
pub fn vyre_driver::registry::migration::Semver::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::migration::Semver where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::migration::Semver::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::migration::Semver::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::migration::Semver where T: core::clone::Clone
pub type vyre_driver::registry::migration::Semver::Owned = T
pub fn vyre_driver::registry::migration::Semver::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::migration::Semver::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::registry::migration::Semver where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::registry::migration::Semver::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::registry::migration::Semver where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::migration::Semver::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::migration::Semver where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::Semver::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::migration::Semver where T: ?core::marker::Sized
pub fn vyre_driver::registry::migration::Semver::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::migration::Semver where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::migration::Semver::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::migration::Semver
pub fn vyre_driver::registry::migration::Semver::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::migration::Semver
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::migration::Semver
impl<T> typenum::type_operators::Same for vyre_driver::registry::migration::Semver
pub type vyre_driver::registry::migration::Semver::Output = T
pub struct vyre_driver::registry::TomlDialectStore
impl vyre_driver::registry::toml_loader::TomlDialectStore
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::contains_op(&self, op_id: &str) -> bool
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::diagnostics(&self) -> &[vyre_driver::diagnostics::Diagnostic]
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::dialect(&self, id: &str) -> core::option::Option<&vyre_driver::registry::toml_loader::DialectManifest>
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::from_env() -> Self
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::load_file(&mut self, path: &std::path::Path)
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::manifests(&self) -> alloc::vec::Vec<&vyre_driver::registry::toml_loader::DialectManifest>
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::ops_in(&self, dialect: &str) -> &[vyre_driver::registry::toml_loader::OpManifest]
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::scan_dir(&mut self, dir: &std::path::Path)
impl core::clone::Clone for vyre_driver::registry::toml_loader::TomlDialectStore
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::clone(&self) -> vyre_driver::registry::toml_loader::TomlDialectStore
impl core::default::Default for vyre_driver::registry::toml_loader::TomlDialectStore
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::default() -> vyre_driver::registry::toml_loader::TomlDialectStore
impl core::fmt::Debug for vyre_driver::registry::toml_loader::TomlDialectStore
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::registry::toml_loader::TomlDialectStore
impl core::marker::Send for vyre_driver::registry::toml_loader::TomlDialectStore
impl core::marker::Sync for vyre_driver::registry::toml_loader::TomlDialectStore
impl core::marker::Unpin for vyre_driver::registry::toml_loader::TomlDialectStore
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::toml_loader::TomlDialectStore
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::toml_loader::TomlDialectStore
impl<T, U> core::convert::Into<U> for vyre_driver::registry::toml_loader::TomlDialectStore where U: core::convert::From<T>
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::toml_loader::TomlDialectStore where U: core::convert::Into<T>
pub type vyre_driver::registry::toml_loader::TomlDialectStore::Error = core::convert::Infallible
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::toml_loader::TomlDialectStore where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::toml_loader::TomlDialectStore::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::toml_loader::TomlDialectStore where T: core::clone::Clone
pub type vyre_driver::registry::toml_loader::TomlDialectStore::Owned = T
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::toml_loader::TomlDialectStore where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::toml_loader::TomlDialectStore where T: ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::toml_loader::TomlDialectStore where T: ?core::marker::Sized
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::toml_loader::TomlDialectStore where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::toml_loader::TomlDialectStore::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::toml_loader::TomlDialectStore
pub fn vyre_driver::registry::toml_loader::TomlDialectStore::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::toml_loader::TomlDialectStore
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::toml_loader::TomlDialectStore
impl<T> typenum::type_operators::Same for vyre_driver::registry::toml_loader::TomlDialectStore
pub type vyre_driver::registry::toml_loader::TomlDialectStore::Output = T
pub const vyre_driver::registry::CODE_PARSE: vyre_driver::diagnostics::DiagnosticCode
pub const vyre_driver::registry::INDIRECT_DISPATCH_OP_ID: &str
pub trait vyre_driver::registry::EnforceGate: vyre_driver::registry::enforce::private::Sealed + core::marker::Send + core::marker::Sync
pub fn vyre_driver::registry::EnforceGate::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::core::Program) -> vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::EnforceGate::name(&self) -> &'static str
impl<A: vyre_driver::registry::enforce::EnforceGate, B: vyre_driver::registry::enforce::EnforceGate> vyre_driver::registry::enforce::EnforceGate for vyre_driver::registry::enforce::Chain<A, B>
pub fn vyre_driver::registry::enforce::Chain<A, B>::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::core::Program) -> vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::Chain<A, B>::name(&self) -> &'static str
pub fn vyre_driver::registry::default_validator() -> bool
pub fn vyre_driver::registry::deprecation_diagnostic(dep: &vyre_driver::registry::migration::Deprecation) -> vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::registry::workspace_dialect_fixture_path() -> std::path::PathBuf
pub mod vyre_driver::routing
pub mod vyre_driver::routing::pgo
pub struct vyre_driver::routing::pgo::BackendLatency
pub vyre_driver::routing::pgo::BackendLatency::backend: alloc::string::String
pub vyre_driver::routing::pgo::BackendLatency::latency_ns: u128
impl core::clone::Clone for vyre_driver::routing::pgo::BackendLatency
pub fn vyre_driver::routing::pgo::BackendLatency::clone(&self) -> vyre_driver::routing::pgo::BackendLatency
impl core::cmp::Eq for vyre_driver::routing::pgo::BackendLatency
impl core::cmp::PartialEq for vyre_driver::routing::pgo::BackendLatency
pub fn vyre_driver::routing::pgo::BackendLatency::eq(&self, other: &vyre_driver::routing::pgo::BackendLatency) -> bool
impl core::fmt::Debug for vyre_driver::routing::pgo::BackendLatency
pub fn vyre_driver::routing::pgo::BackendLatency::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::routing::pgo::BackendLatency
impl serde_core::ser::Serialize for vyre_driver::routing::pgo::BackendLatency
pub fn vyre_driver::routing::pgo::BackendLatency::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::routing::pgo::BackendLatency
pub fn vyre_driver::routing::pgo::BackendLatency::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::routing::pgo::BackendLatency
impl core::marker::Send for vyre_driver::routing::pgo::BackendLatency
impl core::marker::Sync for vyre_driver::routing::pgo::BackendLatency
impl core::marker::Unpin for vyre_driver::routing::pgo::BackendLatency
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::routing::pgo::BackendLatency
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::routing::pgo::BackendLatency
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::routing::pgo::BackendLatency where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::routing::pgo::BackendLatency::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::routing::pgo::BackendLatency where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::routing::pgo::BackendLatency where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::routing::pgo::BackendLatency::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::routing::pgo::BackendLatency::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::routing::pgo::BackendLatency where U: core::convert::From<T>
pub fn vyre_driver::routing::pgo::BackendLatency::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::routing::pgo::BackendLatency where U: core::convert::Into<T>
pub type vyre_driver::routing::pgo::BackendLatency::Error = core::convert::Infallible
pub fn vyre_driver::routing::pgo::BackendLatency::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::routing::pgo::BackendLatency where U: core::convert::TryFrom<T>
pub type vyre_driver::routing::pgo::BackendLatency::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::routing::pgo::BackendLatency::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::routing::pgo::BackendLatency where T: core::clone::Clone
pub type vyre_driver::routing::pgo::BackendLatency::Owned = T
pub fn vyre_driver::routing::pgo::BackendLatency::clone_into(&self, target: &mut T)
pub fn vyre_driver::routing::pgo::BackendLatency::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::routing::pgo::BackendLatency where T: 'static + ?core::marker::Sized
pub fn vyre_driver::routing::pgo::BackendLatency::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::routing::pgo::BackendLatency where T: ?core::marker::Sized
pub fn vyre_driver::routing::pgo::BackendLatency::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::routing::pgo::BackendLatency where T: ?core::marker::Sized
pub fn vyre_driver::routing::pgo::BackendLatency::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::routing::pgo::BackendLatency where T: core::clone::Clone
pub unsafe fn vyre_driver::routing::pgo::BackendLatency::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::routing::pgo::BackendLatency
pub fn vyre_driver::routing::pgo::BackendLatency::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::routing::pgo::BackendLatency where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::routing::pgo::BackendLatency
impl<T> tracing::instrument::WithSubscriber for vyre_driver::routing::pgo::BackendLatency
impl<T> typenum::type_operators::Same for vyre_driver::routing::pgo::BackendLatency
pub type vyre_driver::routing::pgo::BackendLatency::Output = T
pub struct vyre_driver::routing::pgo::PgoTable
pub vyre_driver::routing::pgo::PgoTable::routes: alloc::collections::btree::map::BTreeMap<alloc::string::String, vyre_driver::routing::pgo::RouteDecision>
impl vyre_driver::routing::pgo::PgoTable
pub fn vyre_driver::routing::pgo::PgoTable::certify_op(&mut self, op_id: impl core::convert::Into<alloc::string::String>, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::DispatchConfig, backends: &[&dyn vyre_driver::VyreBackend]) -> core::result::Result<&vyre_driver::routing::pgo::RouteDecision, vyre_driver::BackendError>
pub fn vyre_driver::routing::pgo::PgoTable::certify_op_borrowed(&mut self, op_id: impl core::convert::Into<alloc::string::String>, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[u8]], config: &vyre_driver::DispatchConfig, backends: &[&dyn vyre_driver::VyreBackend]) -> core::result::Result<&vyre_driver::routing::pgo::RouteDecision, vyre_driver::BackendError>
pub fn vyre_driver::routing::pgo::PgoTable::fastest_backend(&self, op_id: &str) -> core::option::Option<&str>
pub fn vyre_driver::routing::pgo::PgoTable::load(path: &std::path::Path) -> core::result::Result<Self, alloc::string::String>
pub fn vyre_driver::routing::pgo::PgoTable::save(&self, path: &std::path::Path) -> core::result::Result<(), alloc::string::String>
impl core::clone::Clone for vyre_driver::routing::pgo::PgoTable
pub fn vyre_driver::routing::pgo::PgoTable::clone(&self) -> vyre_driver::routing::pgo::PgoTable
impl core::cmp::Eq for vyre_driver::routing::pgo::PgoTable
impl core::cmp::PartialEq for vyre_driver::routing::pgo::PgoTable
pub fn vyre_driver::routing::pgo::PgoTable::eq(&self, other: &vyre_driver::routing::pgo::PgoTable) -> bool
impl core::default::Default for vyre_driver::routing::pgo::PgoTable
pub fn vyre_driver::routing::pgo::PgoTable::default() -> vyre_driver::routing::pgo::PgoTable
impl core::fmt::Debug for vyre_driver::routing::pgo::PgoTable
pub fn vyre_driver::routing::pgo::PgoTable::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::routing::pgo::PgoTable
impl serde_core::ser::Serialize for vyre_driver::routing::pgo::PgoTable
pub fn vyre_driver::routing::pgo::PgoTable::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::routing::pgo::PgoTable
pub fn vyre_driver::routing::pgo::PgoTable::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::routing::pgo::PgoTable
impl core::marker::Send for vyre_driver::routing::pgo::PgoTable
impl core::marker::Sync for vyre_driver::routing::pgo::PgoTable
impl core::marker::Unpin for vyre_driver::routing::pgo::PgoTable
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::routing::pgo::PgoTable
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::routing::pgo::PgoTable
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::routing::pgo::PgoTable where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::routing::pgo::PgoTable::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::routing::pgo::PgoTable where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::routing::pgo::PgoTable where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::routing::pgo::PgoTable::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::routing::pgo::PgoTable::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::routing::pgo::PgoTable where U: core::convert::From<T>
pub fn vyre_driver::routing::pgo::PgoTable::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::routing::pgo::PgoTable where U: core::convert::Into<T>
pub type vyre_driver::routing::pgo::PgoTable::Error = core::convert::Infallible
pub fn vyre_driver::routing::pgo::PgoTable::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::routing::pgo::PgoTable where U: core::convert::TryFrom<T>
pub type vyre_driver::routing::pgo::PgoTable::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::routing::pgo::PgoTable::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::routing::pgo::PgoTable where T: core::clone::Clone
pub type vyre_driver::routing::pgo::PgoTable::Owned = T
pub fn vyre_driver::routing::pgo::PgoTable::clone_into(&self, target: &mut T)
pub fn vyre_driver::routing::pgo::PgoTable::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::routing::pgo::PgoTable where T: 'static + ?core::marker::Sized
pub fn vyre_driver::routing::pgo::PgoTable::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::routing::pgo::PgoTable where T: ?core::marker::Sized
pub fn vyre_driver::routing::pgo::PgoTable::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::routing::pgo::PgoTable where T: ?core::marker::Sized
pub fn vyre_driver::routing::pgo::PgoTable::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::routing::pgo::PgoTable where T: core::clone::Clone
pub unsafe fn vyre_driver::routing::pgo::PgoTable::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::routing::pgo::PgoTable
pub fn vyre_driver::routing::pgo::PgoTable::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::routing::pgo::PgoTable where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::routing::pgo::PgoTable
impl<T> tracing::instrument::WithSubscriber for vyre_driver::routing::pgo::PgoTable
impl<T> typenum::type_operators::Same for vyre_driver::routing::pgo::PgoTable
pub type vyre_driver::routing::pgo::PgoTable::Output = T
pub struct vyre_driver::routing::pgo::RouteDecision
pub vyre_driver::routing::pgo::RouteDecision::backend: alloc::string::String
pub vyre_driver::routing::pgo::RouteDecision::observations: alloc::vec::Vec<vyre_driver::routing::pgo::BackendLatency>
impl core::clone::Clone for vyre_driver::routing::pgo::RouteDecision
pub fn vyre_driver::routing::pgo::RouteDecision::clone(&self) -> vyre_driver::routing::pgo::RouteDecision
impl core::cmp::Eq for vyre_driver::routing::pgo::RouteDecision
impl core::cmp::PartialEq for vyre_driver::routing::pgo::RouteDecision
pub fn vyre_driver::routing::pgo::RouteDecision::eq(&self, other: &vyre_driver::routing::pgo::RouteDecision) -> bool
impl core::fmt::Debug for vyre_driver::routing::pgo::RouteDecision
pub fn vyre_driver::routing::pgo::RouteDecision::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::routing::pgo::RouteDecision
impl serde_core::ser::Serialize for vyre_driver::routing::pgo::RouteDecision
pub fn vyre_driver::routing::pgo::RouteDecision::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::routing::pgo::RouteDecision
pub fn vyre_driver::routing::pgo::RouteDecision::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::routing::pgo::RouteDecision
impl core::marker::Send for vyre_driver::routing::pgo::RouteDecision
impl core::marker::Sync for vyre_driver::routing::pgo::RouteDecision
impl core::marker::Unpin for vyre_driver::routing::pgo::RouteDecision
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::routing::pgo::RouteDecision
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::routing::pgo::RouteDecision
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::routing::pgo::RouteDecision where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::routing::pgo::RouteDecision::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::routing::pgo::RouteDecision where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::routing::pgo::RouteDecision where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::routing::pgo::RouteDecision::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::routing::pgo::RouteDecision::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::routing::pgo::RouteDecision where U: core::convert::From<T>
pub fn vyre_driver::routing::pgo::RouteDecision::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::routing::pgo::RouteDecision where U: core::convert::Into<T>
pub type vyre_driver::routing::pgo::RouteDecision::Error = core::convert::Infallible
pub fn vyre_driver::routing::pgo::RouteDecision::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::routing::pgo::RouteDecision where U: core::convert::TryFrom<T>
pub type vyre_driver::routing::pgo::RouteDecision::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::routing::pgo::RouteDecision::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::routing::pgo::RouteDecision where T: core::clone::Clone
pub type vyre_driver::routing::pgo::RouteDecision::Owned = T
pub fn vyre_driver::routing::pgo::RouteDecision::clone_into(&self, target: &mut T)
pub fn vyre_driver::routing::pgo::RouteDecision::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::routing::pgo::RouteDecision where T: 'static + ?core::marker::Sized
pub fn vyre_driver::routing::pgo::RouteDecision::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::routing::pgo::RouteDecision where T: ?core::marker::Sized
pub fn vyre_driver::routing::pgo::RouteDecision::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::routing::pgo::RouteDecision where T: ?core::marker::Sized
pub fn vyre_driver::routing::pgo::RouteDecision::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::routing::pgo::RouteDecision where T: core::clone::Clone
pub unsafe fn vyre_driver::routing::pgo::RouteDecision::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::routing::pgo::RouteDecision
pub fn vyre_driver::routing::pgo::RouteDecision::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::routing::pgo::RouteDecision where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::routing::pgo::RouteDecision
impl<T> tracing::instrument::WithSubscriber for vyre_driver::routing::pgo::RouteDecision
impl<T> typenum::type_operators::Same for vyre_driver::routing::pgo::RouteDecision
pub type vyre_driver::routing::pgo::RouteDecision::Output = T
pub fn vyre_driver::routing::pgo::default_pgo_path() -> std::path::PathBuf
#[non_exhaustive] pub enum vyre_driver::routing::SortBackend
pub vyre_driver::routing::SortBackend::BitonicSort
pub vyre_driver::routing::SortBackend::InsertionSort
pub vyre_driver::routing::SortBackend::RadixSort
impl core::clone::Clone for vyre_driver::routing::SortBackend
pub fn vyre_driver::routing::SortBackend::clone(&self) -> vyre_driver::routing::SortBackend
impl core::cmp::Eq for vyre_driver::routing::SortBackend
impl core::cmp::PartialEq for vyre_driver::routing::SortBackend
pub fn vyre_driver::routing::SortBackend::eq(&self, other: &vyre_driver::routing::SortBackend) -> bool
impl core::fmt::Debug for vyre_driver::routing::SortBackend
pub fn vyre_driver::routing::SortBackend::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::routing::SortBackend
impl core::marker::StructuralPartialEq for vyre_driver::routing::SortBackend
impl core::marker::Freeze for vyre_driver::routing::SortBackend
impl core::marker::Send for vyre_driver::routing::SortBackend
impl core::marker::Sync for vyre_driver::routing::SortBackend
impl core::marker::Unpin for vyre_driver::routing::SortBackend
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::routing::SortBackend
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::routing::SortBackend
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::routing::SortBackend where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::routing::SortBackend::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::routing::SortBackend where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::routing::SortBackend where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::routing::SortBackend::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::routing::SortBackend::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::routing::SortBackend where U: core::convert::From<T>
pub fn vyre_driver::routing::SortBackend::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::routing::SortBackend where U: core::convert::Into<T>
pub type vyre_driver::routing::SortBackend::Error = core::convert::Infallible
pub fn vyre_driver::routing::SortBackend::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::routing::SortBackend where U: core::convert::TryFrom<T>
pub type vyre_driver::routing::SortBackend::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::routing::SortBackend::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::routing::SortBackend where T: core::clone::Clone
pub type vyre_driver::routing::SortBackend::Owned = T
pub fn vyre_driver::routing::SortBackend::clone_into(&self, target: &mut T)
pub fn vyre_driver::routing::SortBackend::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::routing::SortBackend where T: 'static + ?core::marker::Sized
pub fn vyre_driver::routing::SortBackend::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::routing::SortBackend where T: ?core::marker::Sized
pub fn vyre_driver::routing::SortBackend::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::routing::SortBackend where T: ?core::marker::Sized
pub fn vyre_driver::routing::SortBackend::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::routing::SortBackend where T: core::clone::Clone
pub unsafe fn vyre_driver::routing::SortBackend::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::routing::SortBackend
pub fn vyre_driver::routing::SortBackend::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::routing::SortBackend
impl<T> tracing::instrument::WithSubscriber for vyre_driver::routing::SortBackend
impl<T> typenum::type_operators::Same for vyre_driver::routing::SortBackend
pub type vyre_driver::routing::SortBackend::Output = T
pub struct vyre_driver::routing::Distribution
impl vyre_driver::routing::Distribution
pub fn vyre_driver::routing::Distribution::observe(values: &[u32]) -> Self
impl core::clone::Clone for vyre_driver::routing::Distribution
pub fn vyre_driver::routing::Distribution::clone(&self) -> vyre_driver::routing::Distribution
impl core::cmp::Eq for vyre_driver::routing::Distribution
impl core::cmp::PartialEq for vyre_driver::routing::Distribution
pub fn vyre_driver::routing::Distribution::eq(&self, other: &vyre_driver::routing::Distribution) -> bool
impl core::fmt::Debug for vyre_driver::routing::Distribution
pub fn vyre_driver::routing::Distribution::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::routing::Distribution
impl core::marker::StructuralPartialEq for vyre_driver::routing::Distribution
impl core::marker::Freeze for vyre_driver::routing::Distribution
impl core::marker::Send for vyre_driver::routing::Distribution
impl core::marker::Sync for vyre_driver::routing::Distribution
impl core::marker::Unpin for vyre_driver::routing::Distribution
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::routing::Distribution
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::routing::Distribution
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::routing::Distribution where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::routing::Distribution::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::routing::Distribution where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::routing::Distribution where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::routing::Distribution::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::routing::Distribution::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::routing::Distribution where U: core::convert::From<T>
pub fn vyre_driver::routing::Distribution::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::routing::Distribution where U: core::convert::Into<T>
pub type vyre_driver::routing::Distribution::Error = core::convert::Infallible
pub fn vyre_driver::routing::Distribution::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::routing::Distribution where U: core::convert::TryFrom<T>
pub type vyre_driver::routing::Distribution::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::routing::Distribution::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::routing::Distribution where T: core::clone::Clone
pub type vyre_driver::routing::Distribution::Owned = T
pub fn vyre_driver::routing::Distribution::clone_into(&self, target: &mut T)
pub fn vyre_driver::routing::Distribution::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::routing::Distribution where T: 'static + ?core::marker::Sized
pub fn vyre_driver::routing::Distribution::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::routing::Distribution where T: ?core::marker::Sized
pub fn vyre_driver::routing::Distribution::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::routing::Distribution where T: ?core::marker::Sized
pub fn vyre_driver::routing::Distribution::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::routing::Distribution where T: core::clone::Clone
pub unsafe fn vyre_driver::routing::Distribution::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::routing::Distribution
pub fn vyre_driver::routing::Distribution::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::routing::Distribution
impl<T> tracing::instrument::WithSubscriber for vyre_driver::routing::Distribution
impl<T> typenum::type_operators::Same for vyre_driver::routing::Distribution
pub type vyre_driver::routing::Distribution::Output = T
pub struct vyre_driver::routing::RoutingTable
impl vyre_driver::routing::RoutingTable
pub fn vyre_driver::routing::RoutingTable::distribution(&self, call_site: &str) -> core::option::Option<vyre_driver::routing::Distribution>
pub fn vyre_driver::routing::RoutingTable::observe_sort_u32(&self, call_site: alloc::borrow::Cow<'_, str>, values: &[u32]) -> core::result::Result<vyre_driver::routing::SortBackend, alloc::string::String>
impl core::default::Default for vyre_driver::routing::RoutingTable
pub fn vyre_driver::routing::RoutingTable::default() -> vyre_driver::routing::RoutingTable
impl core::fmt::Debug for vyre_driver::routing::RoutingTable
pub fn vyre_driver::routing::RoutingTable::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::routing::RoutingTable
impl core::marker::Send for vyre_driver::routing::RoutingTable
impl core::marker::Sync for vyre_driver::routing::RoutingTable
impl core::marker::Unpin for vyre_driver::routing::RoutingTable
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver::routing::RoutingTable
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::routing::RoutingTable
impl<T, U> core::convert::Into<U> for vyre_driver::routing::RoutingTable where U: core::convert::From<T>
pub fn vyre_driver::routing::RoutingTable::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::routing::RoutingTable where U: core::convert::Into<T>
pub type vyre_driver::routing::RoutingTable::Error = core::convert::Infallible
pub fn vyre_driver::routing::RoutingTable::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::routing::RoutingTable where U: core::convert::TryFrom<T>
pub type vyre_driver::routing::RoutingTable::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::routing::RoutingTable::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::routing::RoutingTable where T: 'static + ?core::marker::Sized
pub fn vyre_driver::routing::RoutingTable::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::routing::RoutingTable where T: ?core::marker::Sized
pub fn vyre_driver::routing::RoutingTable::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::routing::RoutingTable where T: ?core::marker::Sized
pub fn vyre_driver::routing::RoutingTable::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::routing::RoutingTable
pub fn vyre_driver::routing::RoutingTable::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::routing::RoutingTable
impl<T> tracing::instrument::WithSubscriber for vyre_driver::routing::RoutingTable
impl<T> typenum::type_operators::Same for vyre_driver::routing::RoutingTable
pub type vyre_driver::routing::RoutingTable::Output = T
pub fn vyre_driver::routing::select_sort_backend(distribution: vyre_driver::routing::Distribution) -> vyre_driver::routing::SortBackend
pub mod vyre_driver::self_substrate
pub mod vyre_driver::self_substrate::adjustment_set_pass_dependency
pub fn vyre_driver::self_substrate::adjustment_set_pass_dependency::ordering_is_safe(adj: &[u32], treatment: u32, outcome: u32, n: u32) -> bool
pub mod vyre_driver::self_substrate::alias_registry
pub fn vyre_driver::self_substrate::alias_registry::alias_union_registered(registry: &vyre_primitives::graph::alias_registry::AliasRegistry) -> bool
pub fn vyre_driver::self_substrate::alias_registry::build_default_registry() -> vyre_primitives::graph::alias_registry::AliasRegistry
pub fn vyre_driver::self_substrate::alias_registry::lookup_alias_op<'a>(registry: &'a vyre_primitives::graph::alias_registry::AliasRegistry, op_id: &str) -> core::option::Option<&'a vyre_primitives::graph::alias_registry::AliasOpDescriptor>
pub mod vyre_driver::self_substrate::amg_pass_solver
pub const vyre_driver::self_substrate::amg_pass_solver::DEFAULT_OMEGA: f64
pub const vyre_driver::self_substrate::amg_pass_solver::DEFAULT_OMEGA_FIXED: u32
pub fn vyre_driver::self_substrate::amg_pass_solver::smooth_matroid_flow(a: &[f64], b: &[f64], x: &[f64], r_mat: &[f64], p_mat: &[f64], a_c: &[f64], n_fine: u32, n_coarse: u32) -> alloc::vec::Vec<f64>
pub fn vyre_driver::self_substrate::amg_pass_solver::smooth_matroid_flow_fixed_via(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, a_fixed: &[u32], b_fixed: &[u32], x_fixed: &[u32], r_mat_fixed: &[u32], p_mat_fixed: &[u32], a_c_fixed: &[u32], n_fine: u32, n_coarse: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::amg_pass_solver::smooth_matroid_flow_fixed_via_into(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, a_fixed: &[u32], b_fixed: &[u32], x_fixed: &[u32], r_mat_fixed: &[u32], p_mat_fixed: &[u32], a_c_fixed: &[u32], n_fine: u32, n_coarse: u32, out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::amg_pass_solver::solve_to_tolerance(a: &[f64], b: &[f64], x0: &[f64], r_mat: &[f64], p_mat: &[f64], a_c: &[f64], n_fine: u32, n_coarse: u32, tol: f64, max_cycles: u32) -> (alloc::vec::Vec<f64>, u32)
pub mod vyre_driver::self_substrate::bellman_tn_order
pub const vyre_driver::self_substrate::bellman_tn_order::OP_ID: &str
pub fn vyre_driver::self_substrate::bellman_tn_order::bellman_tn_order_program(src: &str, dst: &str, weight: &str, dist: &str, next_dist: &str, changed: &str, n_nodes: u32, n_edges: u32, max_iterations: u32) -> vyre_foundation::ir_inner::model::program::core::Program
pub fn vyre_driver::self_substrate::bellman_tn_order::bellman_tn_order_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, src: &[u32], dst: &[u32], weight: &[u32], dist_init: &[u32], n_nodes: u32, max_iterations: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::bellman_tn_order::bellman_tn_order_via_into(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, src: &[u32], dst: &[u32], weight: &[u32], dist_init: &[u32], n_nodes: u32, max_iterations: u32, out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub mod vyre_driver::self_substrate::bitset_summary
pub fn vyre_driver::self_substrate::bitset_summary::per_word_popcount(input: &[u32]) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::bitset_summary::per_word_popcount_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, input: &[u32]) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::bitset_summary::per_word_popcount_via_into(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, input: &[u32], out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::bitset_summary::saturation_ratio(input: &[u32]) -> f64
pub fn vyre_driver::self_substrate::bitset_summary::saturation_ratio_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, input: &[u32]) -> core::result::Result<f64, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::bitset_summary::total_set_bits(input: &[u32]) -> u64
pub fn vyre_driver::self_substrate::bitset_summary::total_set_bits_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, input: &[u32]) -> core::result::Result<u64, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub mod vyre_driver::self_substrate::categorical_check
pub fn vyre_driver::self_substrate::categorical_check::check_adjunction(c_cat: &vyre_primitives::cat::yoneda::FiniteCategory, d_cat: &vyre_primitives::cat::yoneda::FiniteCategory, f: &vyre_primitives::cat::adjoint::FiniteFunctor, g: &vyre_primitives::cat::adjoint::FiniteFunctor) -> vyre_primitives::cat::adjoint::AdjointPair
pub fn vyre_driver::self_substrate::categorical_check::left_kan_at(k: &vyre_primitives::cat::adjoint::FiniteFunctor, f_image: &[u32], c: u32) -> u32
pub fn vyre_driver::self_substrate::categorical_check::natural_transformation_count(category: &vyre_primitives::cat::yoneda::FiniteCategory, x: u32, f_at_x: u32) -> u32
pub fn vyre_driver::self_substrate::categorical_check::right_kan_at(k: &vyre_primitives::cat::adjoint::FiniteFunctor, f_image: &[u32], c: u32) -> u32
pub mod vyre_driver::self_substrate::cost_model
pub fn vyre_driver::self_substrate::cost_model::predict_runtime(feature_circuit_kinds: &[u32], feature_circuit_offsets: &[u32], feature_circuit_counts: &[u32], feature_circuit_children: &[u32], feature_circuit_weights: &[f64], feature_values: &[f64], historical_residuals: &[u32], alpha: f64) -> (f64, u32)
pub mod vyre_driver::self_substrate::csr_bidirectional
pub fn vyre_driver::self_substrate::csr_bidirectional::bidirectional_closure(node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], seed: &[u32], allow_mask: u32, max_iters: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::csr_bidirectional::bidirectional_step(node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], frontier_in: &[u32], allow_mask: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::csr_bidirectional::bidirectional_step_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], frontier_in: &[u32], allow_mask: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::csr_bidirectional::bidirectional_step_via_into(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], frontier_in: &[u32], allow_mask: u32, out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::csr_bidirectional::bidirectional_closure_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], seed: &[u32], allow_mask: u32, max_iters: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::csr_bidirectional::bidirectional_closure_via_into(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], seed: &[u32], allow_mask: u32, max_iters: u32, current: &mut alloc::vec::Vec<u32>, next: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub mod vyre_driver::self_substrate::csr_forward_or_changed
pub fn vyre_driver::self_substrate::csr_forward_or_changed::forward_closure_via_change_flag(node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], seed: &[u32], allow_mask: u32, max_iters: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::csr_forward_or_changed::forward_closure_via_change_flag_gpu(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], seed: &[u32], allow_mask: u32, max_iters: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::csr_forward_or_changed::forward_closure_via_change_flag_gpu_into(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], seed: &[u32], allow_mask: u32, max_iters: u32, frontier: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::csr_forward_or_changed::forward_step_with_change_flag(node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], frontier: &[u32], allow_mask: u32) -> (alloc::vec::Vec<u32>, u32)
pub mod vyre_driver::self_substrate::dataflow_fixpoint
pub enum vyre_driver::self_substrate::dataflow_fixpoint::Semiring
pub vyre_driver::self_substrate::dataflow_fixpoint::Semiring::BoolOr
pub vyre_driver::self_substrate::dataflow_fixpoint::Semiring::Lineage
pub vyre_driver::self_substrate::dataflow_fixpoint::Semiring::MinPlus
impl vyre_driver::self_substrate::dataflow_fixpoint::Semiring
pub fn vyre_driver::self_substrate::dataflow_fixpoint::Semiring::identity(self) -> u32
impl core::clone::Clone for vyre_driver::self_substrate::dataflow_fixpoint::Semiring
pub fn vyre_driver::self_substrate::dataflow_fixpoint::Semiring::clone(&self) -> vyre_driver::self_substrate::dataflow_fixpoint::Semiring
impl core::cmp::Eq for vyre_driver::self_substrate::dataflow_fixpoint::Semiring
impl core::cmp::PartialEq for vyre_driver::self_substrate::dataflow_fixpoint::Semiring
pub fn vyre_driver::self_substrate::dataflow_fixpoint::Semiring::eq(&self, other: &vyre_driver::self_substrate::dataflow_fixpoint::Semiring) -> bool
impl core::fmt::Debug for vyre_driver::self_substrate::dataflow_fixpoint::Semiring
pub fn vyre_driver::self_substrate::dataflow_fixpoint::Semiring::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::self_substrate::dataflow_fixpoint::Semiring
impl core::marker::StructuralPartialEq for vyre_driver::self_substrate::dataflow_fixpoint::Semiring
impl core::marker::Freeze for vyre_driver::self_substrate::dataflow_fixpoint::Semiring
impl core::marker::Send for vyre_driver::self_substrate::dataflow_fixpoint::Semiring
impl core::marker::Sync for vyre_driver::self_substrate::dataflow_fixpoint::Semiring
impl core::marker::Unpin for vyre_driver::self_substrate::dataflow_fixpoint::Semiring
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::self_substrate::dataflow_fixpoint::Semiring
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::self_substrate::dataflow_fixpoint::Semiring
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::self_substrate::dataflow_fixpoint::Semiring where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::self_substrate::dataflow_fixpoint::Semiring::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::self_substrate::dataflow_fixpoint::Semiring where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::self_substrate::dataflow_fixpoint::Semiring where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::self_substrate::dataflow_fixpoint::Semiring::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::self_substrate::dataflow_fixpoint::Semiring::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::self_substrate::dataflow_fixpoint::Semiring where U: core::convert::From<T>
pub fn vyre_driver::self_substrate::dataflow_fixpoint::Semiring::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::self_substrate::dataflow_fixpoint::Semiring where U: core::convert::Into<T>
pub type vyre_driver::self_substrate::dataflow_fixpoint::Semiring::Error = core::convert::Infallible
pub fn vyre_driver::self_substrate::dataflow_fixpoint::Semiring::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::self_substrate::dataflow_fixpoint::Semiring where U: core::convert::TryFrom<T>
pub type vyre_driver::self_substrate::dataflow_fixpoint::Semiring::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::self_substrate::dataflow_fixpoint::Semiring::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::self_substrate::dataflow_fixpoint::Semiring where T: core::clone::Clone
pub type vyre_driver::self_substrate::dataflow_fixpoint::Semiring::Owned = T
pub fn vyre_driver::self_substrate::dataflow_fixpoint::Semiring::clone_into(&self, target: &mut T)
pub fn vyre_driver::self_substrate::dataflow_fixpoint::Semiring::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::self_substrate::dataflow_fixpoint::Semiring where T: 'static + ?core::marker::Sized
pub fn vyre_driver::self_substrate::dataflow_fixpoint::Semiring::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::self_substrate::dataflow_fixpoint::Semiring where T: ?core::marker::Sized
pub fn vyre_driver::self_substrate::dataflow_fixpoint::Semiring::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::self_substrate::dataflow_fixpoint::Semiring where T: ?core::marker::Sized
pub fn vyre_driver::self_substrate::dataflow_fixpoint::Semiring::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::self_substrate::dataflow_fixpoint::Semiring where T: core::clone::Clone
pub unsafe fn vyre_driver::self_substrate::dataflow_fixpoint::Semiring::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::self_substrate::dataflow_fixpoint::Semiring
pub fn vyre_driver::self_substrate::dataflow_fixpoint::Semiring::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::self_substrate::dataflow_fixpoint::Semiring
impl<T> tracing::instrument::WithSubscriber for vyre_driver::self_substrate::dataflow_fixpoint::Semiring
impl<T> typenum::type_operators::Same for vyre_driver::self_substrate::dataflow_fixpoint::Semiring
pub type vyre_driver::self_substrate::dataflow_fixpoint::Semiring::Output = T
pub fn vyre_driver::self_substrate::dataflow_fixpoint::forward_backward_bitsets_for_pivot(adj: &[u32], pivot: u32, n: u32) -> (alloc::vec::Vec<u32>, alloc::vec::Vec<u32>)
pub fn vyre_driver::self_substrate::dataflow_fixpoint::forward_backward_bitsets_for_pivot_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, adj: &[u32], pivot: u32, n: u32) -> core::result::Result<(alloc::vec::Vec<u32>, alloc::vec::Vec<u32>), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::dataflow_fixpoint::lineage_closure(adj: &[u32], n: u32, max_iters: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::dataflow_fixpoint::lineage_closure_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, adj: &[u32], n: u32, max_iters: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::dataflow_fixpoint::reachability_closure(adj: &[u32], n: u32, max_iters: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::dataflow_fixpoint::reachability_closure_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, adj: &[u32], n: u32, max_iters: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::dataflow_fixpoint::scc_components_via_substrate(adj: &[u32], n: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::dataflow_fixpoint::scc_components_via_substrate_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, adj: &[u32], n: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::dataflow_fixpoint::semiring_gemm_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, a: &[u32], b: &[u32], m: u32, n: u32, k: u32, semiring: vyre_driver::self_substrate::dataflow_fixpoint::Semiring) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::dataflow_fixpoint::semiring_gemm_via_into(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, a: &[u32], b: &[u32], m: u32, n: u32, k: u32, semiring: vyre_driver::self_substrate::dataflow_fixpoint::Semiring, c: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::dataflow_fixpoint::semiring_gemm_via_bool_or(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, a: &[u32], b: &[u32], m: u32, n: u32, k: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::dataflow_fixpoint::semiring_gemm_via_min_plus(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, a: &[u32], b: &[u32], m: u32, n: u32, k: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::dataflow_fixpoint::semiring_gemm_via_lineage(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, a: &[u32], b: &[u32], m: u32, n: u32, k: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::dataflow_fixpoint::shortest_path_closure(adj: &[u32], n: u32, max_iters: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::dataflow_fixpoint::shortest_path_closure_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, adj: &[u32], n: u32, max_iters: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub mod vyre_driver::self_substrate::decision_telemetry
pub static vyre_driver::self_substrate::decision_telemetry::AUTOTUNE_DELTA_LARGE: core::sync::atomic::AtomicU64
pub static vyre_driver::self_substrate::decision_telemetry::AUTOTUNE_DELTA_NONE: core::sync::atomic::AtomicU64
pub static vyre_driver::self_substrate::decision_telemetry::AUTOTUNE_DELTA_SMALL: core::sync::atomic::AtomicU64
pub static vyre_driver::self_substrate::decision_telemetry::EVICTION_DROPPED_GT_HALF: core::sync::atomic::AtomicU64
pub static vyre_driver::self_substrate::decision_telemetry::EVICTION_DROPPED_LE_HALF: core::sync::atomic::AtomicU64
pub static vyre_driver::self_substrate::decision_telemetry::EVICTION_DROPPED_LE_QUARTER: core::sync::atomic::AtomicU64
pub static vyre_driver::self_substrate::decision_telemetry::EVICTION_KEPT_ALL: core::sync::atomic::AtomicU64
pub static vyre_driver::self_substrate::decision_telemetry::FUSION_RATE_BELOW_QUARTER: core::sync::atomic::AtomicU64
pub static vyre_driver::self_substrate::decision_telemetry::FUSION_RATE_FULL_OPTIMAL: core::sync::atomic::AtomicU64
pub static vyre_driver::self_substrate::decision_telemetry::FUSION_RATE_LE_HALF: core::sync::atomic::AtomicU64
pub static vyre_driver::self_substrate::decision_telemetry::FUSION_SELECTED_FIVE_TO_SIXTEEN: core::sync::atomic::AtomicU64
pub static vyre_driver::self_substrate::decision_telemetry::FUSION_SELECTED_ONE_TO_FOUR: core::sync::atomic::AtomicU64
pub static vyre_driver::self_substrate::decision_telemetry::FUSION_SELECTED_SEVENTEEN_PLUS: core::sync::atomic::AtomicU64
pub static vyre_driver::self_substrate::decision_telemetry::FUSION_SELECTED_ZERO: core::sync::atomic::AtomicU64
pub static vyre_driver::self_substrate::decision_telemetry::PROVENANCE_EMPTY: core::sync::atomic::AtomicU64
pub static vyre_driver::self_substrate::decision_telemetry::PROVENANCE_FULL: core::sync::atomic::AtomicU64
pub static vyre_driver::self_substrate::decision_telemetry::PROVENANCE_PARTIAL: core::sync::atomic::AtomicU64
pub fn vyre_driver::self_substrate::decision_telemetry::record_autotune(relative_delta: f64)
pub fn vyre_driver::self_substrate::decision_telemetry::record_eviction(dropped_fraction: f64)
pub fn vyre_driver::self_substrate::decision_telemetry::record_fusion(selected_count: u32, total: u32)
pub fn vyre_driver::self_substrate::decision_telemetry::record_fusion_rate(rate: f64)
pub fn vyre_driver::self_substrate::decision_telemetry::record_provenance(nonempty_fraction: f64)
pub fn vyre_driver::self_substrate::decision_telemetry::snapshot_decisions() -> alloc::vec::Vec<(&'static str, u64)>
pub mod vyre_driver::self_substrate::differentiable_autotune
pub fn vyre_driver::self_substrate::differentiable_autotune::config_gradient(costs: &[f64], temperature: f64) -> alloc::vec::Vec<f64>
pub fn vyre_driver::self_substrate::differentiable_autotune::pick_best_config(costs: &[f64]) -> usize
pub fn vyre_driver::self_substrate::differentiable_autotune::pick_config(costs: &[f64], temperature: f64) -> alloc::vec::Vec<f64>
pub mod vyre_driver::self_substrate::dnnf_compile
pub fn vyre_driver::self_substrate::dnnf_compile::compile_precondition(clauses: &[alloc::vec::Vec<(u32, bool)>], num_vars: u32, max_depth: u32) -> vyre_primitives::dnnf::compile::DnnfDag
pub fn vyre_driver::self_substrate::dnnf_compile::count_models(dag: &vyre_primitives::dnnf::compile::DnnfDag) -> u64
pub fn vyre_driver::self_substrate::dnnf_compile::is_satisfiable(dag: &vyre_primitives::dnnf::compile::DnnfDag) -> bool
pub fn vyre_driver::self_substrate::dnnf_compile::is_tautology(dag: &vyre_primitives::dnnf::compile::DnnfDag, num_vars: u32) -> bool
pub mod vyre_driver::self_substrate::do_calculus_change_impact
pub fn vyre_driver::self_substrate::do_calculus_change_impact::impact_subgraph(adj: &[u32], intervention_mask: &[u32], n: u32) -> (alloc::vec::Vec<u32>, alloc::vec::Vec<u32>)
pub fn vyre_driver::self_substrate::do_calculus_change_impact::intervention_delete_incoming_via(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, adj: &[u32], intervention_mask: &[u32], n: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::do_calculus_change_impact::intervention_delete_incoming_via_into(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, adj: &[u32], intervention_mask: &[u32], n: u32, out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::do_calculus_change_impact::predict_impact(adj: &[u32], intervention_mask: &[u32], n: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::do_calculus_change_impact::predict_impact_observation_form(adj: &[u32], observation_mask: &[u32], n: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::do_calculus_change_impact::rule2_reverse_incoming_via(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, adj: &[u32], treatment_mask: &[u32], n: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::do_calculus_change_impact::rule2_reverse_incoming_via_into(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, adj: &[u32], treatment_mask: &[u32], n: u32, out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub mod vyre_driver::self_substrate::dominator_frontier
pub fn vyre_driver::self_substrate::dominator_frontier::compute_dominance_frontier(node_count: u32, dom_offsets: &[u32], dom_targets: &[u32], pred_offsets: &[u32], pred_targets: &[u32], seed: &[u32]) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::dominator_frontier::compute_dominance_frontier_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, node_count: u32, dom_offsets: &[u32], dom_targets: &[u32], pred_offsets: &[u32], pred_targets: &[u32], seed: &[u32]) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::dominator_frontier::compute_dominance_frontier_via_into(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, node_count: u32, dom_offsets: &[u32], dom_targets: &[u32], pred_offsets: &[u32], pred_targets: &[u32], seed: &[u32], frontier_out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::dominator_frontier::frontier_size(frontier: &[u32]) -> u32
pub mod vyre_driver::self_substrate::effect_signature_check
pub fn vyre_driver::self_substrate::effect_signature_check::check_signature(signature: vyre_primitives::effects::handler_apply::EffectRow, observed: vyre_primitives::effects::handler_apply::EffectRow) -> core::result::Result<(), vyre_primitives::effects::type_checker::EffectTypeError>
pub fn vyre_driver::self_substrate::effect_signature_check::signature_fits(signature: vyre_primitives::effects::handler_apply::EffectRow, observed: vyre_primitives::effects::handler_apply::EffectRow) -> bool
pub mod vyre_driver::self_substrate::exploded
pub fn vyre_driver::self_substrate::exploded::build_ifds_csr(num_procs: u32, blocks_per_proc: u32, facts_per_proc: u32, intra_edges: &[(u32, u32, u32)], inter_edges: &[(u32, u32, u32, u32)], flow_gen: &[(u32, u32, u32)], flow_kill: &[(u32, u32, u32)]) -> (alloc::vec::Vec<u32>, alloc::vec::Vec<u32>)
pub fn vyre_driver::self_substrate::exploded::build_ifds_csr_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, num_procs: u32, blocks_per_proc: u32, facts_per_proc: u32, intra_edges: &[(u32, u32, u32)], inter_edges: &[(u32, u32, u32, u32)], flow_gen: &[(u32, u32, u32)], flow_kill: &[(u32, u32, u32)]) -> core::result::Result<(alloc::vec::Vec<u32>, alloc::vec::Vec<u32>), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::exploded::build_ifds_csr_via_into(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, num_procs: u32, blocks_per_proc: u32, facts_per_proc: u32, intra_edges: &[(u32, u32, u32)], inter_edges: &[(u32, u32, u32, u32)], flow_gen: &[(u32, u32, u32)], flow_kill: &[(u32, u32, u32)], row_ptr_out: &mut alloc::vec::Vec<u32>, col_idx_out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::exploded::ifds_node_count(num_procs: u32, blocks_per_proc: u32, facts_per_proc: u32) -> u32
pub fn vyre_driver::self_substrate::exploded::round_trip_dense(dense: u32, blocks_per_proc: u32, facts_per_proc: u32) -> u32
pub mod vyre_driver::self_substrate::fmm_polyhedral_compress
pub fn vyre_driver::self_substrate::fmm_polyhedral_compress::aggregate_to_cells(scores: &[f64], cell_assignment: &[u32]) -> alloc::vec::Vec<f64>
pub fn vyre_driver::self_substrate::fmm_polyhedral_compress::evaluate_at_regions(cell_local: &[f64], cell_assignment: &[u32], n: u32) -> alloc::vec::Vec<f64>
pub fn vyre_driver::self_substrate::fmm_polyhedral_compress::fmm_compress_pairwise(scores: &[f64], cell_assignment: &[u32], cell_distances: &[f64], n: u32) -> alloc::vec::Vec<f64>
pub fn vyre_driver::self_substrate::fmm_polyhedral_compress::translate_to_targets(cell_moments: &[f64], cell_distances: &[f64]) -> alloc::vec::Vec<f64>
pub mod vyre_driver::self_substrate::functorial_pass_composition
pub fn vyre_driver::self_substrate::functorial_pass_composition::apply_pass_functor(view_in: &[u32], column_mapping: &[u32], target_n_cols: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::functorial_pass_composition::apply_pass_functor_via(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, view_in: &[u32], column_mapping: &[u32], target_n_cols: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::functorial_pass_composition::apply_pass_functor_via_into(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, view_in: &[u32], column_mapping: &[u32], target_n_cols: u32, out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::functorial_pass_composition::compose_passes(view_in: &[u32], mapping_g: &[u32], n_mid: u32, mapping_f: &[u32], n_out: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::functorial_pass_composition::identity_functor(n_cols: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::functorial_pass_composition::passes_commute_on(view_in: &[u32], mapping_a: &[u32], n_mid_a: u32, mapping_b_after_a: &[u32], mapping_b: &[u32], n_mid_b: u32, mapping_a_after_b: &[u32], n_out: u32) -> bool
pub mod vyre_driver::self_substrate::kfac_autotune_step
pub const vyre_driver::self_substrate::kfac_autotune_step::OP_ID: &str
pub fn vyre_driver::self_substrate::kfac_autotune_step::kfac_autotune_step_program(blocks_out: &str, blocks_in: &str, scratch: &str, num_blocks: u32, n: u32) -> vyre_foundation::ir_inner::model::program::core::Program
pub fn vyre_driver::self_substrate::kfac_autotune_step::kfac_autotune_step_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, blocks_in: &[f32], num_blocks: u32, n: u32) -> core::result::Result<alloc::vec::Vec<f32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::kfac_autotune_step::kfac_autotune_step_via_into(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, blocks_in: &[f32], num_blocks: u32, n: u32, out: &mut alloc::vec::Vec<f32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub mod vyre_driver::self_substrate::knowledge_compile_pass_precondition
pub fn vyre_driver::self_substrate::knowledge_compile_pass_precondition::pass_applies(nodes: &[(u32, u32, u32)], node_var: &[u32], children: &[u32], var_assignments: &[u32], topo_order: &[u32]) -> u32
pub fn vyre_driver::self_substrate::knowledge_compile_pass_precondition::pass_applies_via(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, nodes: &[(u32, u32, u32)], node_var: &[u32], children: &[u32], var_assignments: &[u32], waves: &[alloc::vec::Vec<u32>]) -> core::result::Result<u32, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::knowledge_compile_pass_precondition::pass_applies_via_into(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, nodes: &[(u32, u32, u32)], node_var: &[u32], children: &[u32], var_assignments: &[u32], waves: &[alloc::vec::Vec<u32>], evals_out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::knowledge_compile_pass_precondition::pass_conflicts(nodes: &[(u32, u32, u32)], node_var: &[u32], children: &[u32], var_assignments: &[u32], topo_order: &[u32]) -> bool
pub mod vyre_driver::self_substrate::level_wave_pass
pub fn vyre_driver::self_substrate::level_wave_pass::build_callee_before_caller_program(step_body: alloc::vec::Vec<vyre_foundation::ir_inner::model::generated::Node>, depth_buf: &str, max_depth: u32, function_count: u32) -> vyre_foundation::ir_inner::model::program::core::Program
pub mod vyre_driver::self_substrate::linear_type_check
pub fn vyre_driver::self_substrate::linear_type_check::use_count_ok(discipline: vyre_primitives::types::linear_check::LinearDiscipline, uses: u32) -> bool
pub fn vyre_driver::self_substrate::linear_type_check::verify_use_count(discipline: vyre_primitives::types::linear_check::LinearDiscipline, uses: u32) -> core::result::Result<(), vyre_primitives::types::linear_check::LinearTypeError>
pub mod vyre_driver::self_substrate::matroid_exact_megakernel
pub fn vyre_driver::self_substrate::matroid_exact_megakernel::count_selected(subset: &[u32]) -> u32
pub fn vyre_driver::self_substrate::matroid_exact_megakernel::select_optimal_subset(exchange_adj: &[u32], sources: &[u32], sinks: &[u32], seed_x: &[u32], n: usize, max_augmentations: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::matroid_exact_megakernel::select_optimal_subset_via(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, exchange_adj: &[u32], sources: &[u32], sinks: &[u32], seed_x: &[u32], n: usize, max_augmentations: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::matroid_exact_megakernel::select_optimal_subset_via_into(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, exchange_adj: &[u32], sources: &[u32], sinks: &[u32], seed_x: &[u32], n: usize, max_augmentations: u32, out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub mod vyre_driver::self_substrate::matroid_megakernel_scheduler
pub fn vyre_driver::self_substrate::matroid_megakernel_scheduler::count_selected(subset: &[u32]) -> u32
pub fn vyre_driver::self_substrate::matroid_megakernel_scheduler::max_fusion_subset(seed: &[u32], exchange_adj: &[u32], n: usize, max_iters: u32) -> alloc::vec::Vec<u32>
pub mod vyre_driver::self_substrate::megakernel_schedule
pub fn vyre_driver::self_substrate::megakernel_schedule::schedule_via_homotopy(costs: &[f64], n: u32, n_steps: u32, dt: f64) -> alloc::vec::Vec<f64>
pub mod vyre_driver::self_substrate::mori_zwanzig_region_coarsen
pub fn vyre_driver::self_substrate::mori_zwanzig_region_coarsen::cluster_projection_matrix(assignments: &[u32], n: u32, k: u32) -> alloc::vec::Vec<f64>
pub fn vyre_driver::self_substrate::mori_zwanzig_region_coarsen::coarsen_region_state(p_matrix: &[f64], state: &[f64], n: u32) -> alloc::vec::Vec<f64>
pub fn vyre_driver::self_substrate::mori_zwanzig_region_coarsen::coarsen_region_state_fixed_via(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, p_matrix_fixed: &[u32], state_fixed: &[u32], n: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::mori_zwanzig_region_coarsen::coarsen_region_state_fixed_via_into(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, p_matrix_fixed: &[u32], state_fixed: &[u32], n: u32, out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::mori_zwanzig_region_coarsen::coarsen_via_clustering(state: &[f64], assignments: &[u32], n: u32, k: u32) -> alloc::vec::Vec<f64>
pub mod vyre_driver::self_substrate::motif
pub fn vyre_driver::self_substrate::motif::match_motif(node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], motif_edges: &[vyre_primitives::graph::motif::MotifEdge]) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::motif::match_motif_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], motif_edges: &[vyre_primitives::graph::motif::MotifEdge]) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::motif::match_motif_via_into(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], motif_edges: &[vyre_primitives::graph::motif::MotifEdge], witness_out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::motif::motif_matches(node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], motif_edges: &[vyre_primitives::graph::motif::MotifEdge]) -> bool
pub fn vyre_driver::self_substrate::motif::motif_participation_count(node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], motif_edges: &[vyre_primitives::graph::motif::MotifEdge]) -> u32
pub mod vyre_driver::self_substrate::multigrid_matroid_solver
pub fn vyre_driver::self_substrate::multigrid_matroid_solver::matroid_solve_step(a: &[f64], b: &[f64], x_in: &[f64], omega: f64, n: u32) -> alloc::vec::Vec<f64>
pub fn vyre_driver::self_substrate::multigrid_matroid_solver::matroid_solve_step_fixed_via(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, a_fixed: &[u32], b_fixed: &[u32], x_in_fixed: &[u32], omega_fixed: u32, n: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::multigrid_matroid_solver::matroid_solve_step_fixed_via_into(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, a_fixed: &[u32], b_fixed: &[u32], x_in_fixed: &[u32], omega_fixed: u32, n: u32, out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::multigrid_matroid_solver::solve_to_tolerance(a: &[f64], b: &[f64], x0: &[f64], omega: f64, n: u32, tol: f64, max_iters: u32) -> (alloc::vec::Vec<f64>, u32)
pub mod vyre_driver::self_substrate::natural_gradient_autotuner
pub fn vyre_driver::self_substrate::natural_gradient_autotuner::autotune_step(m_inv_sqrt: &[f64], grad: &[f64], n: u32, learning_rate: f64) -> alloc::vec::Vec<f64>
pub fn vyre_driver::self_substrate::natural_gradient_autotuner::identity_fisher_block(n: u32) -> alloc::vec::Vec<f64>
pub fn vyre_driver::self_substrate::natural_gradient_autotuner::precondition_autotune_gradient(m_inv_sqrt: &[f64], grad: &[f64], n: u32) -> alloc::vec::Vec<f64>
pub fn vyre_driver::self_substrate::natural_gradient_autotuner::precondition_autotune_gradient_fixed_via(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, m_inv_sqrt_fixed: &[u32], grad_fixed: &[u32], n: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::natural_gradient_autotuner::precondition_autotune_gradient_fixed_via_into(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, m_inv_sqrt_fixed: &[u32], grad_fixed: &[u32], n: u32, out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub mod vyre_driver::self_substrate::observability
pub fn vyre_driver::self_substrate::observability::snapshot_counters() -> alloc::vec::Vec<(&'static str, u64)>
pub fn vyre_driver::self_substrate::observability::total_calls() -> u64
pub mod vyre_driver::self_substrate::path_reconstruct
pub fn vyre_driver::self_substrate::path_reconstruct::path_to_root(parent: &[u32], target: u32, max_depth: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::path_reconstruct::path_to_root_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, parent: &[u32], target: u32, max_depth: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::path_reconstruct::reconstruct_path(parent: &[u32], target: u32, max_depth: u32, scratch: &mut alloc::vec::Vec<u32>) -> u32
pub fn vyre_driver::self_substrate::path_reconstruct::reconstruct_path_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, parent: &[u32], target: u32, max_depth: u32, scratch: &mut alloc::vec::Vec<u32>) -> core::result::Result<u32, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::path_reconstruct::reconstruct_paths_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, parent: &[u32], targets: &[u32], max_depth: u32) -> core::result::Result<(alloc::vec::Vec<u32>, alloc::vec::Vec<u32>), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub mod vyre_driver::self_substrate::persistent_bfs
pub fn vyre_driver::self_substrate::persistent_bfs::bfs_expand(node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], frontier_in: &[u32], allow_mask: u32, max_iters: u32) -> (alloc::vec::Vec<u32>, u32)
pub fn vyre_driver::self_substrate::persistent_bfs::bfs_expand_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], frontier_in: &[u32], allow_mask: u32, max_iters: u32) -> core::result::Result<(alloc::vec::Vec<u32>, u32), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::persistent_bfs::bfs_expand_via_into(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], frontier_in: &[u32], allow_mask: u32, max_iters: u32, frontier_out: &mut alloc::vec::Vec<u32>) -> core::result::Result<u32, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::persistent_bfs::forward_reach(node_count: u32, edge_offsets: &[u32], edge_targets: &[u32], edge_kind_mask: &[u32], seed: &[u32], allow_mask: u32) -> alloc::vec::Vec<u32>
pub mod vyre_driver::self_substrate::persistent_homology_loop_signature
pub fn vyre_driver::self_substrate::persistent_homology_loop_signature::reference_h1_birth_scales(dist_matrix: &[f64], epsilons: &[f64], n: u32) -> alloc::vec::Vec<(f64, u32)>
pub fn vyre_driver::self_substrate::persistent_homology_loop_signature::reference_loop_filtration_betti(dist_matrix: &[f64], epsilons: &[f64], n: u32) -> alloc::vec::Vec<(u32, u32)>
pub fn vyre_driver::self_substrate::persistent_homology_loop_signature::reference_loop_filtration_edge_counts(dist_matrix: &[f64], epsilons: &[f64], n: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::persistent_homology_loop_signature::reference_region_loop_edges(dist_matrix: &[f64], epsilon: f64, n: u32) -> alloc::vec::Vec<(u32, u32)>
pub fn vyre_driver::self_substrate::persistent_homology_loop_signature::reference_region_loop_skeleton(dist_matrix: &[f64], epsilon: f64, n: u32) -> alloc::vec::Vec<u32>
pub mod vyre_driver::self_substrate::planar_rewrite_pass_scheduler
pub fn vyre_driver::self_substrate::planar_rewrite_pass_scheduler::batch_reduction_ratio(candidate_count: u32, scheduled_count: u32) -> f64
pub fn vyre_driver::self_substrate::planar_rewrite_pass_scheduler::count_scheduled(schedule: &[u32]) -> u32
pub fn vyre_driver::self_substrate::planar_rewrite_pass_scheduler::schedule_disjoint_rewrites(candidates: &[u32], h: u32, w: u32, k: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::planar_rewrite_pass_scheduler::schedule_disjoint_rewrites_via(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, candidates: &[u32], h: u32, w: u32, k: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::planar_rewrite_pass_scheduler::schedule_disjoint_rewrites_via_into(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, candidates: &[u32], h: u32, w: u32, k: u32, out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub mod vyre_driver::self_substrate::polyhedral_fusion
pub fn vyre_driver::self_substrate::polyhedral_fusion::fusable_pairs(adj: &[u32], n: u32, max_iters: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::polyhedral_fusion::fusion_score(adj: &[u32], n: u32, max_iters: u32) -> u32
pub mod vyre_driver::self_substrate::qsvt_matrix_function_fusion
pub fn vyre_driver::self_substrate::qsvt_matrix_function_fusion::fusion_affinity(transport_residual: &[f64]) -> alloc::vec::Vec<f64>
pub fn vyre_driver::self_substrate::qsvt_matrix_function_fusion::negative_truncator_coeffs(k_steps: u32) -> alloc::vec::Vec<f64>
pub fn vyre_driver::self_substrate::qsvt_matrix_function_fusion::transport_residual(dispatch_cost: &[f64], weights: &[f64], n: u32, chebyshev_order: u32) -> alloc::vec::Vec<f64>
pub mod vyre_driver::self_substrate::scallop_provenance
pub const vyre_driver::self_substrate::scallop_provenance::DEFAULT_PROVENANCE_MAX_ITERATIONS: u32
pub fn vyre_driver::self_substrate::scallop_provenance::build_provenance_program(n: u32, max_iterations: u32) -> vyre_foundation::ir_inner::model::program::core::Program
pub fn vyre_driver::self_substrate::scallop_provenance::reference_provenance_closure(state: &[u32], join_rules: &[u32], n: u32, max_iterations: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::scallop_provenance::reference_provenance_closure_with_scratch(state: &[u32], join_rules: &[u32], n: u32, max_iterations: u32, scratch: &mut vyre_driver::self_substrate::scallop_provenance::ScallopProvenanceScratch) -> u32
pub fn vyre_driver::self_substrate::scallop_provenance::provenance_closure_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, state: &[u32], join_rules: &[u32], n: u32, max_iterations: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::scallop_provenance::provenance_closure_via_into(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, state: &[u32], join_rules: &[u32], n: u32, max_iterations: u32, closure: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::scallop_provenance::lineage_for_output(closure: &[u32], n: u32, out: u32) -> alloc::vec::Vec<u32>
pub mod vyre_driver::self_substrate::scallop_provenance_wide
pub const vyre_driver::self_substrate::scallop_provenance_wide::OP_ID: &str
pub fn vyre_driver::self_substrate::scallop_provenance_wide::scallop_provenance_wide_program(state: &str, next: &str, join_rules: &str, changed: &str, n: u32, w: u32, max_iterations: u32) -> vyre_foundation::ir_inner::model::program::core::Program
pub mod vyre_driver::self_substrate::shape_smt_check
pub fn vyre_driver::self_substrate::shape_smt_check::evaluate_shape_formula(formula: &vyre_primitives::types::shape_smt::ShapeFormula, count: u32) -> bool
pub fn vyre_driver::self_substrate::shape_smt_check::formula_proves_non_empty(formula: &vyre_primitives::types::shape_smt::ShapeFormula) -> bool
pub mod vyre_driver::self_substrate::sheaf_heterophilic_dispatch
pub fn vyre_driver::self_substrate::sheaf_heterophilic_dispatch::diffuse_dispatch_stalks(stalks: &[f64], restriction_diag: &[f64], damping: f64) -> alloc::vec::Vec<f64>
pub fn vyre_driver::self_substrate::sheaf_heterophilic_dispatch::diffuse_dispatch_stalks_fixed_via(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, stalks_fixed: &[u32], restriction_diag_fixed: &[u32], damping_fixed: u32, n_nodes: u32, d: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::sheaf_heterophilic_dispatch::diffuse_dispatch_stalks_fixed_via_into(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, stalks_fixed: &[u32], restriction_diag_fixed: &[u32], damping_fixed: u32, n_nodes: u32, d: u32, out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::sheaf_heterophilic_dispatch::diffuse_to_equilibrium(initial_stalks: &[f64], restriction_diag: &[f64], damping: f64, tol: f64, max_iters: u32) -> (alloc::vec::Vec<f64>, u32)
pub fn vyre_driver::self_substrate::sheaf_heterophilic_dispatch::flag_fusion_incompatible(initial_stalks: &[f64], diffused_stalks: &[f64], divergence_threshold: f64) -> alloc::vec::Vec<u32>
pub mod vyre_driver::self_substrate::sheaf_spectral_clustering
pub const vyre_driver::self_substrate::sheaf_spectral_clustering::DEFAULT_POWER_ITERATIONS: u32
pub struct vyre_driver::self_substrate::sheaf_spectral_clustering::FixedSheafSpectrum
pub fn vyre_driver::self_substrate::sheaf_spectral_clustering::dominant_spectrum(restriction_diag: &[f64], iterations: u32) -> (f64, alloc::vec::Vec<f64>)
pub fn vyre_driver::self_substrate::sheaf_spectral_clustering::dominant_spectrum_fixed_via(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, restriction_diag_fixed: &[u32], v_init_fixed: &[u32], n_nodes: u32, d: u32, iterations: u32) -> core::result::Result<vyre_driver::self_substrate::sheaf_spectral_clustering::FixedSheafSpectrum, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::sheaf_spectral_clustering::dominant_spectrum_fixed_via_into(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, restriction_diag_fixed: &[u32], v_init_fixed: &[u32], n_nodes: u32, d: u32, iterations: u32, eigenvector_out: &mut alloc::vec::Vec<u32>) -> core::result::Result<u32, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::sheaf_spectral_clustering::spectral_gap(restriction_diag: &[f64]) -> f64
pub fn vyre_driver::self_substrate::sheaf_spectral_clustering::suggested_cluster_count(restriction_diag: &[f64]) -> u32
pub mod vyre_driver::self_substrate::sinkhorn_dispatch_clustering
pub const vyre_driver::self_substrate::sinkhorn_dispatch_clustering::OP_ID: &str
pub fn vyre_driver::self_substrate::sinkhorn_dispatch_clustering::sinkhorn_clustering_program(m: u32, n: u32, d: u32, iters: u32, eps: f32) -> vyre_foundation::ir_inner::model::program::core::Program
pub fn vyre_driver::self_substrate::sinkhorn_dispatch_clustering::sinkhorn_clustering_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, region_features: &[f32], cluster_centroids: &[f32], region_weights: &[f32], cluster_capacities: &[f32], m: u32, n: u32, d: u32, iters: u32, eps: f32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::sinkhorn_dispatch_clustering::sinkhorn_clustering_via_into(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, region_features: &[f32], cluster_centroids: &[f32], region_weights: &[f32], cluster_capacities: &[f32], m: u32, n: u32, d: u32, iters: u32, eps: f32, assignments_out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub mod vyre_driver::self_substrate::sinkhorn_full_clustering
pub const vyre_driver::self_substrate::sinkhorn_full_clustering::OP_ID: &str
pub fn vyre_driver::self_substrate::sinkhorn_full_clustering::sinkhorn_full_clustering_program(k: &str, k_t: &str, a: &str, b: &str, u_curr: &str, u_next: &str, v: &str, kv: &str, ktu: &str, changed: &str, m: u32, n: u32, max_iterations: u32) -> vyre_foundation::ir_inner::model::program::core::Program
pub mod vyre_driver::self_substrate::spectral_schedule
pub fn vyre_driver::self_substrate::spectral_schedule::fusion_scores(laplacian: &[f32], n: u32) -> alloc::vec::Vec<f32>
pub fn vyre_driver::self_substrate::spectral_schedule::fusion_scores_fixed_via(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, laplacian_fixed: &[u32], signal_fixed: &[u32], coeffs_fixed: &[u32], n: u32, k_steps: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::spectral_schedule::fusion_scores_fixed_via_into(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, laplacian_fixed: &[u32], signal_fixed: &[u32], coeffs_fixed: &[u32], n: u32, k_steps: u32, out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::spectral_schedule::shape_spectrum(eigenvalues: &[f64], n_dispatches: u32, n_features: u32) -> alloc::vec::Vec<f64>
pub fn vyre_driver::self_substrate::spectral_schedule::shape_spectrum_fixed_via(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, eigenvalues_fixed: &[u32], mp_edge_fixed: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::spectral_schedule::shape_spectrum_fixed_via_into(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, eigenvalues_fixed: &[u32], mp_edge_fixed: u32, out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub mod vyre_driver::self_substrate::string_diagram_ir_rewrite
pub fn vyre_driver::self_substrate::string_diagram_ir_rewrite::compose_ir_arrows(f: &[f64], g: &[f64], a: u32, b: u32, c: u32) -> alloc::vec::Vec<f64>
pub fn vyre_driver::self_substrate::string_diagram_ir_rewrite::compose_ir_arrows_fixed_via(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, f_fixed: &[u32], g_fixed: &[u32], a: u32, b: u32, c: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::string_diagram_ir_rewrite::compose_ir_arrows_fixed_via_into(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, f_fixed: &[u32], g_fixed: &[u32], a: u32, b: u32, c: u32, out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::string_diagram_ir_rewrite::composition_associates(f: &[f64], g: &[f64], h: &[f64], a: u32, b: u32, c: u32, d: u32) -> bool
pub fn vyre_driver::self_substrate::string_diagram_ir_rewrite::identity_arrow(n: u32) -> alloc::vec::Vec<f64>
pub mod vyre_driver::self_substrate::submodular_cache_eviction
pub fn vyre_driver::self_substrate::submodular_cache_eviction::greedy_quality_bound(optimum: u32) -> u32
pub fn vyre_driver::self_substrate::submodular_cache_eviction::invert_to_eviction_set(retention: &[u32]) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::submodular_cache_eviction::select_retention_set(gains: &mut [u32], n: u32, k: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::submodular_cache_eviction::select_retention_set_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, gains: &mut [u32], n: u32, k: u32) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::submodular_cache_eviction::select_retention_set_via_into(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, gains: &mut [u32], n: u32, k: u32, picked: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub mod vyre_driver::self_substrate::tensor_network_fusion_order
pub use vyre_driver::self_substrate::tensor_network_fusion_order::fusion_order_cost
pub use vyre_driver::self_substrate::tensor_network_fusion_order::optimal_fusion_order
pub mod vyre_driver::self_substrate::tensor_train_chain_fusion
pub fn vyre_driver::self_substrate::tensor_train_chain_fusion::fusion_pressure(shared_buffer_ranks: &[u32]) -> f64
pub fn vyre_driver::self_substrate::tensor_train_chain_fusion::fusion_pressure_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, shared_buffer_ranks: &[u32]) -> core::result::Result<f64, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::tensor_train_chain_fusion::should_fuse_chain(shared_buffer_ranks: &[u32], threshold_per_link: f64) -> bool
pub fn vyre_driver::self_substrate::tensor_train_chain_fusion::should_fuse_chain_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, shared_buffer_ranks: &[u32], threshold_per_link: f64) -> core::result::Result<bool, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub mod vyre_driver::self_substrate::tensor_train_compression
pub struct vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor
pub vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::cores: alloc::vec::Vec<alloc::vec::Vec<f64>>
pub vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::dims: alloc::vec::Vec<u32>
pub vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::ranks: alloc::vec::Vec<u32>
pub struct vyre_driver::self_substrate::tensor_train_compression::CompressedFixedCostTensor
pub vyre_driver::self_substrate::tensor_train_compression::CompressedFixedCostTensor::cores: alloc::vec::Vec<alloc::vec::Vec<u32>>
pub vyre_driver::self_substrate::tensor_train_compression::CompressedFixedCostTensor::dims: alloc::vec::Vec<u32>
pub vyre_driver::self_substrate::tensor_train_compression::CompressedFixedCostTensor::ranks: alloc::vec::Vec<u32>
impl core::clone::Clone for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor
pub fn vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::clone(&self) -> vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor
impl core::fmt::Debug for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor
pub fn vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor
impl core::marker::Send for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor
impl core::marker::Sync for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor
impl core::marker::Unpin for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor
impl<T, U> core::convert::Into<U> for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor where U: core::convert::From<T>
pub fn vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor where U: core::convert::Into<T>
pub type vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::Error = core::convert::Infallible
pub fn vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor where U: core::convert::TryFrom<T>
pub type vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor where T: core::clone::Clone
pub type vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::Owned = T
pub fn vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::clone_into(&self, target: &mut T)
pub fn vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor where T: 'static + ?core::marker::Sized
pub fn vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor where T: ?core::marker::Sized
pub fn vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor where T: ?core::marker::Sized
pub fn vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor where T: core::clone::Clone
pub unsafe fn vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor
pub fn vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor
impl<T> tracing::instrument::WithSubscriber for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor
impl<T> typenum::type_operators::Same for vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor
pub type vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor::Output = T
pub fn vyre_driver::self_substrate::tensor_train_compression::compress_cost_tensor(tensor: &[f64], dims: &[u32], target_ranks: &[u32]) -> vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor
pub fn vyre_driver::self_substrate::tensor_train_compression::compress_cost_tensor_fixed_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, tensor_fixed: &[u32], dims: &[u32], target_ranks: &[u32]) -> core::result::Result<vyre_driver::self_substrate::tensor_train_compression::CompressedFixedCostTensor, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::tensor_train_compression::compress_cost_tensor_fixed_via_into(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, tensor_fixed: &[u32], dims: &[u32], target_ranks: &[u32], cores_out: &mut alloc::vec::Vec<alloc::vec::Vec<u32>>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::tensor_train_compression::compression_ratio(compressed: &vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor) -> f64
pub fn vyre_driver::self_substrate::tensor_train_compression::tt_storage_size(compressed: &vyre_driver::self_substrate::tensor_train_compression::CompressedCostTensor) -> usize
pub mod vyre_driver::self_substrate::toposort
pub fn vyre_driver::self_substrate::toposort::all_reachable(node_count: u32, edges: &[(u32, u32)], sources: &[u32], targets: &[u32]) -> core::result::Result<bool, vyre_primitives::graph::reachable::UnknownNode>
pub fn vyre_driver::self_substrate::toposort::reachable_set(node_count: u32, edges: &[(u32, u32)], sources: &[u32]) -> core::result::Result<std::collections::hash::set::HashSet<u32>, vyre_primitives::graph::reachable::UnknownNode>
pub fn vyre_driver::self_substrate::toposort::topo_order(node_count: u32, edges: &[(u32, u32)]) -> core::result::Result<alloc::vec::Vec<u32>, vyre_primitives::graph::toposort::ToposortError>
pub fn vyre_driver::self_substrate::toposort::topo_order_csr_via(dispatcher: &impl vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, node_count: u32, offsets: &[u32], targets: &[u32]) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub mod vyre_driver::self_substrate::union_find_emit
pub fn vyre_driver::self_substrate::union_find_emit::canonicalize_parent_to_roots(parent: &[u32]) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::union_find_emit::reference_union_find_alias(parent_init: &[u32], edge_a: &[u32], edge_b: &[u32]) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::union_find_emit::union_find_alias_program(parent: &str, edge_a: &str, edge_b: &str, node_count: u32, edge_count: u32) -> vyre_foundation::ir_inner::model::program::core::Program
pub fn vyre_driver::self_substrate::union_find_emit::union_find_alias_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, parent_init: &[u32], edge_a: &[u32], edge_b: &[u32]) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::union_find_emit::union_find_alias_via_into(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, parent_init: &[u32], edge_a: &[u32], edge_b: &[u32], parent_out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub mod vyre_driver::self_substrate::vsa_fingerprint
pub fn vyre_driver::self_substrate::vsa_fingerprint::fingerprint(kind_hv: &[u32], signature_hv: &[u32], region_hv: &[u32]) -> alloc::vec::Vec<u32>
pub fn vyre_driver::self_substrate::vsa_fingerprint::fingerprint_via(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, kind_hv: &[u32], signature_hv: &[u32], region_hv: &[u32]) -> core::result::Result<alloc::vec::Vec<u32>, vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::vsa_fingerprint::fingerprint_via_into(dispatcher: &dyn vyre_driver::self_substrate::optimizer::dispatcher::OptimizerDispatcher, kind_hv: &[u32], signature_hv: &[u32], region_hv: &[u32], out: &mut alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::self_substrate::optimizer::dispatcher::DispatchError>
pub fn vyre_driver::self_substrate::vsa_fingerprint::lookup_approximate(query: &[u32], cached: &[alloc::vec::Vec<u32>], threshold: f32) -> core::option::Option<usize>
pub mod vyre_driver::self_substrate::zx_rewrite
pub fn vyre_driver::self_substrate::zx_rewrite::flip_spider(diagram: &mut vyre_primitives::zx::rewrite::ZxDiagram, v: u32)
pub fn vyre_driver::self_substrate::zx_rewrite::fuse_diagram(diagram: vyre_primitives::zx::rewrite::ZxDiagram) -> vyre_primitives::zx::rewrite::ZxDiagram
pub fn vyre_driver::self_substrate::zx_rewrite::remove_identities(diagram: vyre_primitives::zx::rewrite::ZxDiagram) -> vyre_primitives::zx::rewrite::ZxDiagram
pub fn vyre_driver::self_substrate::zx_rewrite::simplify_diagram(diagram: vyre_primitives::zx::rewrite::ZxDiagram) -> vyre_primitives::zx::rewrite::ZxDiagram
pub mod vyre_driver::shadow
pub enum vyre_driver::shadow::ConformanceError
pub vyre_driver::shadow::ConformanceError::BackendRejected
pub vyre_driver::shadow::ConformanceError::BackendRejected::case_label: alloc::string::String
pub vyre_driver::shadow::ConformanceError::BackendRejected::source: vyre_driver::BackendError
pub vyre_driver::shadow::ConformanceError::Diverged
pub vyre_driver::shadow::ConformanceError::Diverged::event: alloc::boxed::Box<vyre_driver::shadow::DivergenceEvent>
pub vyre_driver::shadow::ConformanceError::Diverged::event_case_label: alloc::string::String
pub vyre_driver::shadow::ConformanceError::EmptyMatrix
pub vyre_driver::shadow::ConformanceError::ReferenceRejected
pub vyre_driver::shadow::ConformanceError::ReferenceRejected::case_label: alloc::string::String
pub vyre_driver::shadow::ConformanceError::ReferenceRejected::source: vyre_driver::BackendError
impl core::error::Error for vyre_driver::shadow::ConformanceError
pub fn vyre_driver::shadow::ConformanceError::source(&self) -> core::option::Option<&(dyn core::error::Error + 'static)>
impl core::fmt::Debug for vyre_driver::shadow::ConformanceError
pub fn vyre_driver::shadow::ConformanceError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::shadow::ConformanceError
pub fn vyre_driver::shadow::ConformanceError::fmt(&self, __formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::shadow::ConformanceError
impl core::marker::Send for vyre_driver::shadow::ConformanceError
impl core::marker::Sync for vyre_driver::shadow::ConformanceError
impl core::marker::Unpin for vyre_driver::shadow::ConformanceError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::shadow::ConformanceError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::shadow::ConformanceError
impl<T, U> core::convert::Into<U> for vyre_driver::shadow::ConformanceError where U: core::convert::From<T>
pub fn vyre_driver::shadow::ConformanceError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::shadow::ConformanceError where U: core::convert::Into<T>
pub type vyre_driver::shadow::ConformanceError::Error = core::convert::Infallible
pub fn vyre_driver::shadow::ConformanceError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::shadow::ConformanceError where U: core::convert::TryFrom<T>
pub type vyre_driver::shadow::ConformanceError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::shadow::ConformanceError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::string::ToString for vyre_driver::shadow::ConformanceError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::shadow::ConformanceError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::shadow::ConformanceError where T: 'static + ?core::marker::Sized
pub fn vyre_driver::shadow::ConformanceError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::shadow::ConformanceError where T: ?core::marker::Sized
pub fn vyre_driver::shadow::ConformanceError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::shadow::ConformanceError where T: ?core::marker::Sized
pub fn vyre_driver::shadow::ConformanceError::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::shadow::ConformanceError
pub fn vyre_driver::shadow::ConformanceError::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::shadow::ConformanceError
impl<T> tracing::instrument::WithSubscriber for vyre_driver::shadow::ConformanceError
impl<T> typenum::type_operators::Same for vyre_driver::shadow::ConformanceError
pub type vyre_driver::shadow::ConformanceError::Output = T
pub struct vyre_driver::shadow::ConformanceCase
impl vyre_driver::shadow::ConformanceCase
pub fn vyre_driver::shadow::ConformanceCase::inputs(&self) -> &[alloc::vec::Vec<u8>]
pub fn vyre_driver::shadow::ConformanceCase::label(&self) -> &str
pub fn vyre_driver::shadow::ConformanceCase::new(label: impl core::convert::Into<alloc::string::String>, inputs: alloc::vec::Vec<alloc::vec::Vec<u8>>) -> Self
impl core::clone::Clone for vyre_driver::shadow::ConformanceCase
pub fn vyre_driver::shadow::ConformanceCase::clone(&self) -> vyre_driver::shadow::ConformanceCase
impl core::cmp::Eq for vyre_driver::shadow::ConformanceCase
impl core::cmp::PartialEq for vyre_driver::shadow::ConformanceCase
pub fn vyre_driver::shadow::ConformanceCase::eq(&self, other: &vyre_driver::shadow::ConformanceCase) -> bool
impl core::fmt::Debug for vyre_driver::shadow::ConformanceCase
pub fn vyre_driver::shadow::ConformanceCase::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::shadow::ConformanceCase
impl core::marker::Freeze for vyre_driver::shadow::ConformanceCase
impl core::marker::Send for vyre_driver::shadow::ConformanceCase
impl core::marker::Sync for vyre_driver::shadow::ConformanceCase
impl core::marker::Unpin for vyre_driver::shadow::ConformanceCase
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::shadow::ConformanceCase
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::shadow::ConformanceCase
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::shadow::ConformanceCase where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::shadow::ConformanceCase::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::shadow::ConformanceCase where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::shadow::ConformanceCase where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::shadow::ConformanceCase::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::shadow::ConformanceCase::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::shadow::ConformanceCase where U: core::convert::From<T>
pub fn vyre_driver::shadow::ConformanceCase::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::shadow::ConformanceCase where U: core::convert::Into<T>
pub type vyre_driver::shadow::ConformanceCase::Error = core::convert::Infallible
pub fn vyre_driver::shadow::ConformanceCase::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::shadow::ConformanceCase where U: core::convert::TryFrom<T>
pub type vyre_driver::shadow::ConformanceCase::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::shadow::ConformanceCase::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::shadow::ConformanceCase where T: core::clone::Clone
pub type vyre_driver::shadow::ConformanceCase::Owned = T
pub fn vyre_driver::shadow::ConformanceCase::clone_into(&self, target: &mut T)
pub fn vyre_driver::shadow::ConformanceCase::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::shadow::ConformanceCase where T: 'static + ?core::marker::Sized
pub fn vyre_driver::shadow::ConformanceCase::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::shadow::ConformanceCase where T: ?core::marker::Sized
pub fn vyre_driver::shadow::ConformanceCase::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::shadow::ConformanceCase where T: ?core::marker::Sized
pub fn vyre_driver::shadow::ConformanceCase::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::shadow::ConformanceCase where T: core::clone::Clone
pub unsafe fn vyre_driver::shadow::ConformanceCase::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::shadow::ConformanceCase
pub fn vyre_driver::shadow::ConformanceCase::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::shadow::ConformanceCase
impl<T> tracing::instrument::WithSubscriber for vyre_driver::shadow::ConformanceCase
impl<T> typenum::type_operators::Same for vyre_driver::shadow::ConformanceCase
pub type vyre_driver::shadow::ConformanceCase::Output = T
pub struct vyre_driver::shadow::ConformanceMatrix
impl vyre_driver::shadow::ConformanceMatrix
pub fn vyre_driver::shadow::ConformanceMatrix::cases(&self) -> &[vyre_driver::shadow::ConformanceCase]
pub fn vyre_driver::shadow::ConformanceMatrix::is_empty(&self) -> bool
pub fn vyre_driver::shadow::ConformanceMatrix::new(cases: alloc::vec::Vec<vyre_driver::shadow::ConformanceCase>) -> Self
pub fn vyre_driver::shadow::ConformanceMatrix::push(&mut self, case: vyre_driver::shadow::ConformanceCase)
impl core::clone::Clone for vyre_driver::shadow::ConformanceMatrix
pub fn vyre_driver::shadow::ConformanceMatrix::clone(&self) -> vyre_driver::shadow::ConformanceMatrix
impl core::cmp::Eq for vyre_driver::shadow::ConformanceMatrix
impl core::cmp::PartialEq for vyre_driver::shadow::ConformanceMatrix
pub fn vyre_driver::shadow::ConformanceMatrix::eq(&self, other: &vyre_driver::shadow::ConformanceMatrix) -> bool
impl core::default::Default for vyre_driver::shadow::ConformanceMatrix
pub fn vyre_driver::shadow::ConformanceMatrix::default() -> vyre_driver::shadow::ConformanceMatrix
impl core::fmt::Debug for vyre_driver::shadow::ConformanceMatrix
pub fn vyre_driver::shadow::ConformanceMatrix::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::shadow::ConformanceMatrix
impl core::marker::Freeze for vyre_driver::shadow::ConformanceMatrix
impl core::marker::Send for vyre_driver::shadow::ConformanceMatrix
impl core::marker::Sync for vyre_driver::shadow::ConformanceMatrix
impl core::marker::Unpin for vyre_driver::shadow::ConformanceMatrix
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::shadow::ConformanceMatrix
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::shadow::ConformanceMatrix
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::shadow::ConformanceMatrix where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::shadow::ConformanceMatrix::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::shadow::ConformanceMatrix where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::shadow::ConformanceMatrix where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::shadow::ConformanceMatrix::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::shadow::ConformanceMatrix::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::shadow::ConformanceMatrix where U: core::convert::From<T>
pub fn vyre_driver::shadow::ConformanceMatrix::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::shadow::ConformanceMatrix where U: core::convert::Into<T>
pub type vyre_driver::shadow::ConformanceMatrix::Error = core::convert::Infallible
pub fn vyre_driver::shadow::ConformanceMatrix::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::shadow::ConformanceMatrix where U: core::convert::TryFrom<T>
pub type vyre_driver::shadow::ConformanceMatrix::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::shadow::ConformanceMatrix::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::shadow::ConformanceMatrix where T: core::clone::Clone
pub type vyre_driver::shadow::ConformanceMatrix::Owned = T
pub fn vyre_driver::shadow::ConformanceMatrix::clone_into(&self, target: &mut T)
pub fn vyre_driver::shadow::ConformanceMatrix::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::shadow::ConformanceMatrix where T: 'static + ?core::marker::Sized
pub fn vyre_driver::shadow::ConformanceMatrix::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::shadow::ConformanceMatrix where T: ?core::marker::Sized
pub fn vyre_driver::shadow::ConformanceMatrix::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::shadow::ConformanceMatrix where T: ?core::marker::Sized
pub fn vyre_driver::shadow::ConformanceMatrix::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::shadow::ConformanceMatrix where T: core::clone::Clone
pub unsafe fn vyre_driver::shadow::ConformanceMatrix::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::shadow::ConformanceMatrix
pub fn vyre_driver::shadow::ConformanceMatrix::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::shadow::ConformanceMatrix
impl<T> tracing::instrument::WithSubscriber for vyre_driver::shadow::ConformanceMatrix
impl<T> typenum::type_operators::Same for vyre_driver::shadow::ConformanceMatrix
pub type vyre_driver::shadow::ConformanceMatrix::Output = T
pub struct vyre_driver::shadow::DivergenceEvent
pub vyre_driver::shadow::DivergenceEvent::backend_output: alloc::vec::Vec<alloc::vec::Vec<u8>>
pub vyre_driver::shadow::DivergenceEvent::case_label: alloc::string::String
pub vyre_driver::shadow::DivergenceEvent::inputs: alloc::vec::Vec<alloc::vec::Vec<u8>>
pub vyre_driver::shadow::DivergenceEvent::program_fingerprint: [u8; 32]
pub vyre_driver::shadow::DivergenceEvent::reference_output: alloc::vec::Vec<alloc::vec::Vec<u8>>
impl core::clone::Clone for vyre_driver::shadow::DivergenceEvent
pub fn vyre_driver::shadow::DivergenceEvent::clone(&self) -> vyre_driver::shadow::DivergenceEvent
impl core::cmp::Eq for vyre_driver::shadow::DivergenceEvent
impl core::cmp::PartialEq for vyre_driver::shadow::DivergenceEvent
pub fn vyre_driver::shadow::DivergenceEvent::eq(&self, other: &vyre_driver::shadow::DivergenceEvent) -> bool
impl core::fmt::Debug for vyre_driver::shadow::DivergenceEvent
pub fn vyre_driver::shadow::DivergenceEvent::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::shadow::DivergenceEvent
impl core::marker::Freeze for vyre_driver::shadow::DivergenceEvent
impl core::marker::Send for vyre_driver::shadow::DivergenceEvent
impl core::marker::Sync for vyre_driver::shadow::DivergenceEvent
impl core::marker::Unpin for vyre_driver::shadow::DivergenceEvent
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::shadow::DivergenceEvent
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::shadow::DivergenceEvent
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::shadow::DivergenceEvent where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::shadow::DivergenceEvent::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::shadow::DivergenceEvent where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::shadow::DivergenceEvent where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::shadow::DivergenceEvent::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::shadow::DivergenceEvent::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::shadow::DivergenceEvent where U: core::convert::From<T>
pub fn vyre_driver::shadow::DivergenceEvent::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::shadow::DivergenceEvent where U: core::convert::Into<T>
pub type vyre_driver::shadow::DivergenceEvent::Error = core::convert::Infallible
pub fn vyre_driver::shadow::DivergenceEvent::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::shadow::DivergenceEvent where U: core::convert::TryFrom<T>
pub type vyre_driver::shadow::DivergenceEvent::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::shadow::DivergenceEvent::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::shadow::DivergenceEvent where T: core::clone::Clone
pub type vyre_driver::shadow::DivergenceEvent::Owned = T
pub fn vyre_driver::shadow::DivergenceEvent::clone_into(&self, target: &mut T)
pub fn vyre_driver::shadow::DivergenceEvent::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::shadow::DivergenceEvent where T: 'static + ?core::marker::Sized
pub fn vyre_driver::shadow::DivergenceEvent::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::shadow::DivergenceEvent where T: ?core::marker::Sized
pub fn vyre_driver::shadow::DivergenceEvent::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::shadow::DivergenceEvent where T: ?core::marker::Sized
pub fn vyre_driver::shadow::DivergenceEvent::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::shadow::DivergenceEvent where T: core::clone::Clone
pub unsafe fn vyre_driver::shadow::DivergenceEvent::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::shadow::DivergenceEvent
pub fn vyre_driver::shadow::DivergenceEvent::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::shadow::DivergenceEvent
impl<T> tracing::instrument::WithSubscriber for vyre_driver::shadow::DivergenceEvent
impl<T> typenum::type_operators::Same for vyre_driver::shadow::DivergenceEvent
pub type vyre_driver::shadow::DivergenceEvent::Output = T
pub struct vyre_driver::shadow::ReferenceExecutor
impl vyre_driver::shadow::ReferenceExecutor
pub fn vyre_driver::shadow::ReferenceExecutor::new<F>(run: F) -> Self where F: core::ops::function::Fn(&vyre_foundation::ir_inner::model::program::core::Program, &[alloc::vec::Vec<u8>]) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::BackendError> + core::marker::Send + core::marker::Sync + 'static
pub fn vyre_driver::shadow::ReferenceExecutor::run(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[alloc::vec::Vec<u8>]) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::BackendError>
impl core::clone::Clone for vyre_driver::shadow::ReferenceExecutor
pub fn vyre_driver::shadow::ReferenceExecutor::clone(&self) -> vyre_driver::shadow::ReferenceExecutor
impl core::marker::Freeze for vyre_driver::shadow::ReferenceExecutor
impl core::marker::Send for vyre_driver::shadow::ReferenceExecutor
impl core::marker::Sync for vyre_driver::shadow::ReferenceExecutor
impl core::marker::Unpin for vyre_driver::shadow::ReferenceExecutor
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver::shadow::ReferenceExecutor
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver::shadow::ReferenceExecutor
impl<T, U> core::convert::Into<U> for vyre_driver::shadow::ReferenceExecutor where U: core::convert::From<T>
pub fn vyre_driver::shadow::ReferenceExecutor::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::shadow::ReferenceExecutor where U: core::convert::Into<T>
pub type vyre_driver::shadow::ReferenceExecutor::Error = core::convert::Infallible
pub fn vyre_driver::shadow::ReferenceExecutor::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::shadow::ReferenceExecutor where U: core::convert::TryFrom<T>
pub type vyre_driver::shadow::ReferenceExecutor::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::shadow::ReferenceExecutor::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::shadow::ReferenceExecutor where T: core::clone::Clone
pub type vyre_driver::shadow::ReferenceExecutor::Owned = T
pub fn vyre_driver::shadow::ReferenceExecutor::clone_into(&self, target: &mut T)
pub fn vyre_driver::shadow::ReferenceExecutor::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::shadow::ReferenceExecutor where T: 'static + ?core::marker::Sized
pub fn vyre_driver::shadow::ReferenceExecutor::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::shadow::ReferenceExecutor where T: ?core::marker::Sized
pub fn vyre_driver::shadow::ReferenceExecutor::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::shadow::ReferenceExecutor where T: ?core::marker::Sized
pub fn vyre_driver::shadow::ReferenceExecutor::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::shadow::ReferenceExecutor where T: core::clone::Clone
pub unsafe fn vyre_driver::shadow::ReferenceExecutor::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::shadow::ReferenceExecutor
pub fn vyre_driver::shadow::ReferenceExecutor::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::shadow::ReferenceExecutor
impl<T> tracing::instrument::WithSubscriber for vyre_driver::shadow::ReferenceExecutor
impl<T> typenum::type_operators::Same for vyre_driver::shadow::ReferenceExecutor
pub type vyre_driver::shadow::ReferenceExecutor::Output = T
pub fn vyre_driver::shadow::assert_exhaustive_byte_identity(pipeline: &dyn vyre_driver::CompiledPipeline, program: &vyre_foundation::ir_inner::model::program::core::Program, reference: &vyre_driver::shadow::ReferenceExecutor, matrix: &vyre_driver::shadow::ConformanceMatrix, config: &vyre_driver::DispatchConfig) -> core::result::Result<(), vyre_driver::shadow::ConformanceError>
pub mod vyre_driver::specialization
#[non_exhaustive] pub enum vyre_driver::specialization::SpecValue
pub vyre_driver::specialization::SpecValue::Bool(bool)
pub vyre_driver::specialization::SpecValue::F32(f32)
pub vyre_driver::specialization::SpecValue::I32(i32)
pub vyre_driver::specialization::SpecValue::U32(u32)
impl vyre_driver::specialization::SpecValue
pub fn vyre_driver::specialization::SpecValue::as_pipeline_f64(self) -> f64
pub fn vyre_driver::specialization::SpecValue::cache_hash(self) -> u64
impl core::clone::Clone for vyre_driver::specialization::SpecValue
pub fn vyre_driver::specialization::SpecValue::clone(&self) -> vyre_driver::specialization::SpecValue
impl core::cmp::PartialEq for vyre_driver::specialization::SpecValue
pub fn vyre_driver::specialization::SpecValue::eq(&self, other: &vyre_driver::specialization::SpecValue) -> bool
impl core::fmt::Debug for vyre_driver::specialization::SpecValue
pub fn vyre_driver::specialization::SpecValue::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::specialization::SpecValue
impl core::marker::StructuralPartialEq for vyre_driver::specialization::SpecValue
impl core::marker::Freeze for vyre_driver::specialization::SpecValue
impl core::marker::Send for vyre_driver::specialization::SpecValue
impl core::marker::Sync for vyre_driver::specialization::SpecValue
impl core::marker::Unpin for vyre_driver::specialization::SpecValue
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::specialization::SpecValue
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::specialization::SpecValue
impl<T, U> core::convert::Into<U> for vyre_driver::specialization::SpecValue where U: core::convert::From<T>
pub fn vyre_driver::specialization::SpecValue::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::specialization::SpecValue where U: core::convert::Into<T>
pub type vyre_driver::specialization::SpecValue::Error = core::convert::Infallible
pub fn vyre_driver::specialization::SpecValue::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::specialization::SpecValue where U: core::convert::TryFrom<T>
pub type vyre_driver::specialization::SpecValue::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::specialization::SpecValue::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::specialization::SpecValue where T: core::clone::Clone
pub type vyre_driver::specialization::SpecValue::Owned = T
pub fn vyre_driver::specialization::SpecValue::clone_into(&self, target: &mut T)
pub fn vyre_driver::specialization::SpecValue::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::specialization::SpecValue where T: 'static + ?core::marker::Sized
pub fn vyre_driver::specialization::SpecValue::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::specialization::SpecValue where T: ?core::marker::Sized
pub fn vyre_driver::specialization::SpecValue::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::specialization::SpecValue where T: ?core::marker::Sized
pub fn vyre_driver::specialization::SpecValue::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::specialization::SpecValue where T: core::clone::Clone
pub unsafe fn vyre_driver::specialization::SpecValue::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::specialization::SpecValue
pub fn vyre_driver::specialization::SpecValue::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::specialization::SpecValue
impl<T> tracing::instrument::WithSubscriber for vyre_driver::specialization::SpecValue
impl<T> typenum::type_operators::Same for vyre_driver::specialization::SpecValue
pub type vyre_driver::specialization::SpecValue::Output = T
pub struct vyre_driver::specialization::SpecCacheKey
pub vyre_driver::specialization::SpecCacheKey::binding_sig: u64
pub vyre_driver::specialization::SpecCacheKey::shader_hash: u64
pub vyre_driver::specialization::SpecCacheKey::spec_hash: u64
pub vyre_driver::specialization::SpecCacheKey::workgroup_size: [u32; 3]
impl vyre_driver::specialization::SpecCacheKey
pub fn vyre_driver::specialization::SpecCacheKey::new(shader_hash: u64, binding_sig: u64, workgroup_size: [u32; 3], specs: &vyre_driver::specialization::SpecMap) -> Self
impl core::clone::Clone for vyre_driver::specialization::SpecCacheKey
pub fn vyre_driver::specialization::SpecCacheKey::clone(&self) -> vyre_driver::specialization::SpecCacheKey
impl core::cmp::Eq for vyre_driver::specialization::SpecCacheKey
impl core::cmp::PartialEq for vyre_driver::specialization::SpecCacheKey
pub fn vyre_driver::specialization::SpecCacheKey::eq(&self, other: &vyre_driver::specialization::SpecCacheKey) -> bool
impl core::fmt::Debug for vyre_driver::specialization::SpecCacheKey
pub fn vyre_driver::specialization::SpecCacheKey::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::specialization::SpecCacheKey
pub fn vyre_driver::specialization::SpecCacheKey::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::StructuralPartialEq for vyre_driver::specialization::SpecCacheKey
impl core::marker::Freeze for vyre_driver::specialization::SpecCacheKey
impl core::marker::Send for vyre_driver::specialization::SpecCacheKey
impl core::marker::Sync for vyre_driver::specialization::SpecCacheKey
impl core::marker::Unpin for vyre_driver::specialization::SpecCacheKey
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::specialization::SpecCacheKey
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::specialization::SpecCacheKey
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::specialization::SpecCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::specialization::SpecCacheKey::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::specialization::SpecCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::specialization::SpecCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::specialization::SpecCacheKey::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::specialization::SpecCacheKey::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::specialization::SpecCacheKey where U: core::convert::From<T>
pub fn vyre_driver::specialization::SpecCacheKey::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::specialization::SpecCacheKey where U: core::convert::Into<T>
pub type vyre_driver::specialization::SpecCacheKey::Error = core::convert::Infallible
pub fn vyre_driver::specialization::SpecCacheKey::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::specialization::SpecCacheKey where U: core::convert::TryFrom<T>
pub type vyre_driver::specialization::SpecCacheKey::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::specialization::SpecCacheKey::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::specialization::SpecCacheKey where T: core::clone::Clone
pub type vyre_driver::specialization::SpecCacheKey::Owned = T
pub fn vyre_driver::specialization::SpecCacheKey::clone_into(&self, target: &mut T)
pub fn vyre_driver::specialization::SpecCacheKey::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::specialization::SpecCacheKey where T: 'static + ?core::marker::Sized
pub fn vyre_driver::specialization::SpecCacheKey::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::specialization::SpecCacheKey where T: ?core::marker::Sized
pub fn vyre_driver::specialization::SpecCacheKey::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::specialization::SpecCacheKey where T: ?core::marker::Sized
pub fn vyre_driver::specialization::SpecCacheKey::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::specialization::SpecCacheKey where T: core::clone::Clone
pub unsafe fn vyre_driver::specialization::SpecCacheKey::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::specialization::SpecCacheKey
pub fn vyre_driver::specialization::SpecCacheKey::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::specialization::SpecCacheKey
impl<T> tracing::instrument::WithSubscriber for vyre_driver::specialization::SpecCacheKey
impl<T> typenum::type_operators::Same for vyre_driver::specialization::SpecCacheKey
pub type vyre_driver::specialization::SpecCacheKey::Output = T
pub struct vyre_driver::specialization::SpecMap
impl vyre_driver::specialization::SpecMap
pub fn vyre_driver::specialization::SpecMap::cache_hash(&self) -> u64
pub fn vyre_driver::specialization::SpecMap::insert(&mut self, name: impl core::convert::Into<alloc::string::String>, value: vyre_driver::specialization::SpecValue)
pub fn vyre_driver::specialization::SpecMap::is_empty(&self) -> bool
pub fn vyre_driver::specialization::SpecMap::iter(&self) -> impl core::iter::traits::iterator::Iterator<Item = (&str, vyre_driver::specialization::SpecValue)>
pub fn vyre_driver::specialization::SpecMap::len(&self) -> usize
pub fn vyre_driver::specialization::SpecMap::new() -> Self
pub fn vyre_driver::specialization::SpecMap::to_numeric_constants(&self) -> std::collections::hash::map::HashMap<alloc::string::String, f64>
impl core::clone::Clone for vyre_driver::specialization::SpecMap
pub fn vyre_driver::specialization::SpecMap::clone(&self) -> vyre_driver::specialization::SpecMap
impl core::default::Default for vyre_driver::specialization::SpecMap
pub fn vyre_driver::specialization::SpecMap::default() -> vyre_driver::specialization::SpecMap
impl core::fmt::Debug for vyre_driver::specialization::SpecMap
pub fn vyre_driver::specialization::SpecMap::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::specialization::SpecMap
impl core::marker::Send for vyre_driver::specialization::SpecMap
impl core::marker::Sync for vyre_driver::specialization::SpecMap
impl core::marker::Unpin for vyre_driver::specialization::SpecMap
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::specialization::SpecMap
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::specialization::SpecMap
impl<T, U> core::convert::Into<U> for vyre_driver::specialization::SpecMap where U: core::convert::From<T>
pub fn vyre_driver::specialization::SpecMap::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::specialization::SpecMap where U: core::convert::Into<T>
pub type vyre_driver::specialization::SpecMap::Error = core::convert::Infallible
pub fn vyre_driver::specialization::SpecMap::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::specialization::SpecMap where U: core::convert::TryFrom<T>
pub type vyre_driver::specialization::SpecMap::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::specialization::SpecMap::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::specialization::SpecMap where T: core::clone::Clone
pub type vyre_driver::specialization::SpecMap::Owned = T
pub fn vyre_driver::specialization::SpecMap::clone_into(&self, target: &mut T)
pub fn vyre_driver::specialization::SpecMap::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::specialization::SpecMap where T: 'static + ?core::marker::Sized
pub fn vyre_driver::specialization::SpecMap::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::specialization::SpecMap where T: ?core::marker::Sized
pub fn vyre_driver::specialization::SpecMap::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::specialization::SpecMap where T: ?core::marker::Sized
pub fn vyre_driver::specialization::SpecMap::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::specialization::SpecMap where T: core::clone::Clone
pub unsafe fn vyre_driver::specialization::SpecMap::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::specialization::SpecMap
pub fn vyre_driver::specialization::SpecMap::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::specialization::SpecMap
impl<T> tracing::instrument::WithSubscriber for vyre_driver::specialization::SpecMap
impl<T> typenum::type_operators::Same for vyre_driver::specialization::SpecMap
pub type vyre_driver::specialization::SpecMap::Output = T
pub mod vyre_driver::speculate
pub enum vyre_driver::speculate::SpeculationMode
pub vyre_driver::speculate::SpeculationMode::Auto
pub vyre_driver::speculate::SpeculationMode::Disable
pub vyre_driver::speculate::SpeculationMode::Force
impl core::clone::Clone for vyre_driver::speculate::SpeculationMode
pub fn vyre_driver::speculate::SpeculationMode::clone(&self) -> vyre_driver::speculate::SpeculationMode
impl core::cmp::Eq for vyre_driver::speculate::SpeculationMode
impl core::cmp::PartialEq for vyre_driver::speculate::SpeculationMode
pub fn vyre_driver::speculate::SpeculationMode::eq(&self, other: &vyre_driver::speculate::SpeculationMode) -> bool
impl core::default::Default for vyre_driver::speculate::SpeculationMode
pub fn vyre_driver::speculate::SpeculationMode::default() -> vyre_driver::speculate::SpeculationMode
impl core::fmt::Debug for vyre_driver::speculate::SpeculationMode
pub fn vyre_driver::speculate::SpeculationMode::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::speculate::SpeculationMode
impl core::marker::StructuralPartialEq for vyre_driver::speculate::SpeculationMode
impl core::marker::Freeze for vyre_driver::speculate::SpeculationMode
impl core::marker::Send for vyre_driver::speculate::SpeculationMode
impl core::marker::Sync for vyre_driver::speculate::SpeculationMode
impl core::marker::Unpin for vyre_driver::speculate::SpeculationMode
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::speculate::SpeculationMode
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::speculate::SpeculationMode
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::speculate::SpeculationMode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculationMode::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::speculate::SpeculationMode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::speculate::SpeculationMode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculationMode::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::speculate::SpeculationMode::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::speculate::SpeculationMode where U: core::convert::From<T>
pub fn vyre_driver::speculate::SpeculationMode::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::speculate::SpeculationMode where U: core::convert::Into<T>
pub type vyre_driver::speculate::SpeculationMode::Error = core::convert::Infallible
pub fn vyre_driver::speculate::SpeculationMode::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::speculate::SpeculationMode where U: core::convert::TryFrom<T>
pub type vyre_driver::speculate::SpeculationMode::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::speculate::SpeculationMode::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::speculate::SpeculationMode where T: core::clone::Clone
pub type vyre_driver::speculate::SpeculationMode::Owned = T
pub fn vyre_driver::speculate::SpeculationMode::clone_into(&self, target: &mut T)
pub fn vyre_driver::speculate::SpeculationMode::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::speculate::SpeculationMode where T: 'static + ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculationMode::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::speculate::SpeculationMode where T: ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculationMode::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::speculate::SpeculationMode where T: ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculationMode::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::speculate::SpeculationMode where T: core::clone::Clone
pub unsafe fn vyre_driver::speculate::SpeculationMode::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::speculate::SpeculationMode
pub fn vyre_driver::speculate::SpeculationMode::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::speculate::SpeculationMode
impl<T> tracing::instrument::WithSubscriber for vyre_driver::speculate::SpeculationMode
impl<T> typenum::type_operators::Same for vyre_driver::speculate::SpeculationMode
pub type vyre_driver::speculate::SpeculationMode::Output = T
pub struct vyre_driver::speculate::AdaptiveSpeculator
impl vyre_driver::speculate::AdaptiveSpeculator
pub fn vyre_driver::speculate::AdaptiveSpeculator::commit_rate_ppm(&self) -> u32
pub fn vyre_driver::speculate::AdaptiveSpeculator::default_threshold() -> Self
pub fn vyre_driver::speculate::AdaptiveSpeculator::new(threshold_pct: u32) -> Self
pub fn vyre_driver::speculate::AdaptiveSpeculator::record(&self, report: vyre_driver::speculate::SpeculationReport)
pub fn vyre_driver::speculate::AdaptiveSpeculator::samples(&self) -> u32
pub fn vyre_driver::speculate::AdaptiveSpeculator::should_speculate(&self) -> bool
pub fn vyre_driver::speculate::AdaptiveSpeculator::threshold_ppm(&self) -> u32
impl core::fmt::Debug for vyre_driver::speculate::AdaptiveSpeculator
pub fn vyre_driver::speculate::AdaptiveSpeculator::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl !core::marker::Freeze for vyre_driver::speculate::AdaptiveSpeculator
impl core::marker::Send for vyre_driver::speculate::AdaptiveSpeculator
impl core::marker::Sync for vyre_driver::speculate::AdaptiveSpeculator
impl core::marker::Unpin for vyre_driver::speculate::AdaptiveSpeculator
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::speculate::AdaptiveSpeculator
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::speculate::AdaptiveSpeculator
impl<T, U> core::convert::Into<U> for vyre_driver::speculate::AdaptiveSpeculator where U: core::convert::From<T>
pub fn vyre_driver::speculate::AdaptiveSpeculator::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::speculate::AdaptiveSpeculator where U: core::convert::Into<T>
pub type vyre_driver::speculate::AdaptiveSpeculator::Error = core::convert::Infallible
pub fn vyre_driver::speculate::AdaptiveSpeculator::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::speculate::AdaptiveSpeculator where U: core::convert::TryFrom<T>
pub type vyre_driver::speculate::AdaptiveSpeculator::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::speculate::AdaptiveSpeculator::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::speculate::AdaptiveSpeculator where T: 'static + ?core::marker::Sized
pub fn vyre_driver::speculate::AdaptiveSpeculator::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::speculate::AdaptiveSpeculator where T: ?core::marker::Sized
pub fn vyre_driver::speculate::AdaptiveSpeculator::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::speculate::AdaptiveSpeculator where T: ?core::marker::Sized
pub fn vyre_driver::speculate::AdaptiveSpeculator::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::speculate::AdaptiveSpeculator
pub fn vyre_driver::speculate::AdaptiveSpeculator::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::speculate::AdaptiveSpeculator
impl<T> tracing::instrument::WithSubscriber for vyre_driver::speculate::AdaptiveSpeculator
impl<T> typenum::type_operators::Same for vyre_driver::speculate::AdaptiveSpeculator
pub type vyre_driver::speculate::AdaptiveSpeculator::Output = T
pub struct vyre_driver::speculate::SpeculationReport
pub vyre_driver::speculate::SpeculationReport::committed_tiles: u32
pub vyre_driver::speculate::SpeculationReport::rolled_back_tiles: u32
impl vyre_driver::speculate::SpeculationReport
pub fn vyre_driver::speculate::SpeculationReport::attempted_tiles(&self) -> u32
pub fn vyre_driver::speculate::SpeculationReport::commit_rate_pct(&self) -> u32
pub fn vyre_driver::speculate::SpeculationReport::commit_rate_ppm(&self) -> u32
pub fn vyre_driver::speculate::SpeculationReport::empty() -> Self
pub fn vyre_driver::speculate::SpeculationReport::from_counts(committed: u32, rolled: u32) -> Self
pub fn vyre_driver::speculate::SpeculationReport::worthwhile(&self, threshold_pct: u32) -> bool
impl core::clone::Clone for vyre_driver::speculate::SpeculationReport
pub fn vyre_driver::speculate::SpeculationReport::clone(&self) -> vyre_driver::speculate::SpeculationReport
impl core::cmp::Eq for vyre_driver::speculate::SpeculationReport
impl core::cmp::PartialEq for vyre_driver::speculate::SpeculationReport
pub fn vyre_driver::speculate::SpeculationReport::eq(&self, other: &vyre_driver::speculate::SpeculationReport) -> bool
impl core::default::Default for vyre_driver::speculate::SpeculationReport
pub fn vyre_driver::speculate::SpeculationReport::default() -> vyre_driver::speculate::SpeculationReport
impl core::fmt::Debug for vyre_driver::speculate::SpeculationReport
pub fn vyre_driver::speculate::SpeculationReport::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::speculate::SpeculationReport
impl core::marker::StructuralPartialEq for vyre_driver::speculate::SpeculationReport
impl core::marker::Freeze for vyre_driver::speculate::SpeculationReport
impl core::marker::Send for vyre_driver::speculate::SpeculationReport
impl core::marker::Sync for vyre_driver::speculate::SpeculationReport
impl core::marker::Unpin for vyre_driver::speculate::SpeculationReport
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::speculate::SpeculationReport
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::speculate::SpeculationReport
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::speculate::SpeculationReport where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculationReport::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::speculate::SpeculationReport where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::speculate::SpeculationReport where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculationReport::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::speculate::SpeculationReport::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::speculate::SpeculationReport where U: core::convert::From<T>
pub fn vyre_driver::speculate::SpeculationReport::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::speculate::SpeculationReport where U: core::convert::Into<T>
pub type vyre_driver::speculate::SpeculationReport::Error = core::convert::Infallible
pub fn vyre_driver::speculate::SpeculationReport::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::speculate::SpeculationReport where U: core::convert::TryFrom<T>
pub type vyre_driver::speculate::SpeculationReport::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::speculate::SpeculationReport::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::speculate::SpeculationReport where T: core::clone::Clone
pub type vyre_driver::speculate::SpeculationReport::Owned = T
pub fn vyre_driver::speculate::SpeculationReport::clone_into(&self, target: &mut T)
pub fn vyre_driver::speculate::SpeculationReport::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::speculate::SpeculationReport where T: 'static + ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculationReport::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::speculate::SpeculationReport where T: ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculationReport::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::speculate::SpeculationReport where T: ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculationReport::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::speculate::SpeculationReport where T: core::clone::Clone
pub unsafe fn vyre_driver::speculate::SpeculationReport::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::speculate::SpeculationReport
pub fn vyre_driver::speculate::SpeculationReport::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::speculate::SpeculationReport
impl<T> tracing::instrument::WithSubscriber for vyre_driver::speculate::SpeculationReport
impl<T> typenum::type_operators::Same for vyre_driver::speculate::SpeculationReport
pub type vyre_driver::speculate::SpeculationReport::Output = T
pub struct vyre_driver::speculate::SpeculativeDispatchOutcome
pub vyre_driver::speculate::SpeculativeDispatchOutcome::outputs: vyre_driver::OutputBuffers
pub vyre_driver::speculate::SpeculativeDispatchOutcome::report: core::option::Option<vyre_driver::speculate::SpeculationReport>
pub vyre_driver::speculate::SpeculativeDispatchOutcome::used_speculative_path: bool
impl core::clone::Clone for vyre_driver::speculate::SpeculativeDispatchOutcome
pub fn vyre_driver::speculate::SpeculativeDispatchOutcome::clone(&self) -> vyre_driver::speculate::SpeculativeDispatchOutcome
impl core::cmp::Eq for vyre_driver::speculate::SpeculativeDispatchOutcome
impl core::cmp::PartialEq for vyre_driver::speculate::SpeculativeDispatchOutcome
pub fn vyre_driver::speculate::SpeculativeDispatchOutcome::eq(&self, other: &vyre_driver::speculate::SpeculativeDispatchOutcome) -> bool
impl core::fmt::Debug for vyre_driver::speculate::SpeculativeDispatchOutcome
pub fn vyre_driver::speculate::SpeculativeDispatchOutcome::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::speculate::SpeculativeDispatchOutcome
impl core::marker::Freeze for vyre_driver::speculate::SpeculativeDispatchOutcome
impl core::marker::Send for vyre_driver::speculate::SpeculativeDispatchOutcome
impl core::marker::Sync for vyre_driver::speculate::SpeculativeDispatchOutcome
impl core::marker::Unpin for vyre_driver::speculate::SpeculativeDispatchOutcome
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::speculate::SpeculativeDispatchOutcome
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::speculate::SpeculativeDispatchOutcome
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::speculate::SpeculativeDispatchOutcome where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculativeDispatchOutcome::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::speculate::SpeculativeDispatchOutcome where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::speculate::SpeculativeDispatchOutcome where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculativeDispatchOutcome::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::speculate::SpeculativeDispatchOutcome::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::speculate::SpeculativeDispatchOutcome where U: core::convert::From<T>
pub fn vyre_driver::speculate::SpeculativeDispatchOutcome::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::speculate::SpeculativeDispatchOutcome where U: core::convert::Into<T>
pub type vyre_driver::speculate::SpeculativeDispatchOutcome::Error = core::convert::Infallible
pub fn vyre_driver::speculate::SpeculativeDispatchOutcome::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::speculate::SpeculativeDispatchOutcome where U: core::convert::TryFrom<T>
pub type vyre_driver::speculate::SpeculativeDispatchOutcome::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::speculate::SpeculativeDispatchOutcome::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::speculate::SpeculativeDispatchOutcome where T: core::clone::Clone
pub type vyre_driver::speculate::SpeculativeDispatchOutcome::Owned = T
pub fn vyre_driver::speculate::SpeculativeDispatchOutcome::clone_into(&self, target: &mut T)
pub fn vyre_driver::speculate::SpeculativeDispatchOutcome::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::speculate::SpeculativeDispatchOutcome where T: 'static + ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculativeDispatchOutcome::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::speculate::SpeculativeDispatchOutcome where T: ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculativeDispatchOutcome::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::speculate::SpeculativeDispatchOutcome where T: ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculativeDispatchOutcome::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::speculate::SpeculativeDispatchOutcome where T: core::clone::Clone
pub unsafe fn vyre_driver::speculate::SpeculativeDispatchOutcome::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::speculate::SpeculativeDispatchOutcome
pub fn vyre_driver::speculate::SpeculativeDispatchOutcome::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::speculate::SpeculativeDispatchOutcome
impl<T> tracing::instrument::WithSubscriber for vyre_driver::speculate::SpeculativeDispatchOutcome
impl<T> typenum::type_operators::Same for vyre_driver::speculate::SpeculativeDispatchOutcome
pub type vyre_driver::speculate::SpeculativeDispatchOutcome::Output = T
pub struct vyre_driver::speculate::SpeculativeDispatchPlan<'a>
pub vyre_driver::speculate::SpeculativeDispatchPlan::counter_output_index: usize
pub vyre_driver::speculate::SpeculativeDispatchPlan::fused_program: &'a vyre_foundation::ir_inner::model::program::core::Program
pub vyre_driver::speculate::SpeculativeDispatchPlan::prefilter_program: &'a vyre_foundation::ir_inner::model::program::core::Program
pub vyre_driver::speculate::SpeculativeDispatchPlan::strip_counter_tail: bool
impl<'a> core::clone::Clone for vyre_driver::speculate::SpeculativeDispatchPlan<'a>
pub fn vyre_driver::speculate::SpeculativeDispatchPlan<'a>::clone(&self) -> vyre_driver::speculate::SpeculativeDispatchPlan<'a>
impl<'a> core::fmt::Debug for vyre_driver::speculate::SpeculativeDispatchPlan<'a>
pub fn vyre_driver::speculate::SpeculativeDispatchPlan<'a>::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl<'a> core::marker::Copy for vyre_driver::speculate::SpeculativeDispatchPlan<'a>
impl<'a> core::marker::Freeze for vyre_driver::speculate::SpeculativeDispatchPlan<'a>
impl<'a> core::marker::Send for vyre_driver::speculate::SpeculativeDispatchPlan<'a>
impl<'a> core::marker::Sync for vyre_driver::speculate::SpeculativeDispatchPlan<'a>
impl<'a> core::marker::Unpin for vyre_driver::speculate::SpeculativeDispatchPlan<'a>
impl<'a> !core::panic::unwind_safe::RefUnwindSafe for vyre_driver::speculate::SpeculativeDispatchPlan<'a>
impl<'a> !core::panic::unwind_safe::UnwindSafe for vyre_driver::speculate::SpeculativeDispatchPlan<'a>
impl<T, U> core::convert::Into<U> for vyre_driver::speculate::SpeculativeDispatchPlan<'a> where U: core::convert::From<T>
pub fn vyre_driver::speculate::SpeculativeDispatchPlan<'a>::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::speculate::SpeculativeDispatchPlan<'a> where U: core::convert::Into<T>
pub type vyre_driver::speculate::SpeculativeDispatchPlan<'a>::Error = core::convert::Infallible
pub fn vyre_driver::speculate::SpeculativeDispatchPlan<'a>::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::speculate::SpeculativeDispatchPlan<'a> where U: core::convert::TryFrom<T>
pub type vyre_driver::speculate::SpeculativeDispatchPlan<'a>::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::speculate::SpeculativeDispatchPlan<'a>::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::speculate::SpeculativeDispatchPlan<'a> where T: core::clone::Clone
pub type vyre_driver::speculate::SpeculativeDispatchPlan<'a>::Owned = T
pub fn vyre_driver::speculate::SpeculativeDispatchPlan<'a>::clone_into(&self, target: &mut T)
pub fn vyre_driver::speculate::SpeculativeDispatchPlan<'a>::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::speculate::SpeculativeDispatchPlan<'a> where T: 'static + ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculativeDispatchPlan<'a>::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::speculate::SpeculativeDispatchPlan<'a> where T: ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculativeDispatchPlan<'a>::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::speculate::SpeculativeDispatchPlan<'a> where T: ?core::marker::Sized
pub fn vyre_driver::speculate::SpeculativeDispatchPlan<'a>::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::speculate::SpeculativeDispatchPlan<'a> where T: core::clone::Clone
pub unsafe fn vyre_driver::speculate::SpeculativeDispatchPlan<'a>::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::speculate::SpeculativeDispatchPlan<'a>
pub fn vyre_driver::speculate::SpeculativeDispatchPlan<'a>::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::speculate::SpeculativeDispatchPlan<'a>
impl<T> tracing::instrument::WithSubscriber for vyre_driver::speculate::SpeculativeDispatchPlan<'a>
impl<T> typenum::type_operators::Same for vyre_driver::speculate::SpeculativeDispatchPlan<'a>
pub type vyre_driver::speculate::SpeculativeDispatchPlan<'a>::Output = T
pub const vyre_driver::speculate::COUNTER_TAIL_BYTES: usize
pub const vyre_driver::speculate::DEFAULT_THRESHOLD_PCT: u32
pub fn vyre_driver::speculate::dispatch_prefilter_confirm<B, F>(backend: &B, speculator: &vyre_driver::speculate::AdaptiveSpeculator, plan: vyre_driver::speculate::SpeculativeDispatchPlan<'_>, inputs: &[&[u8]], config: &vyre_driver::DispatchConfig, confirm_serial: F) -> core::result::Result<vyre_driver::speculate::SpeculativeDispatchOutcome, vyre_driver::BackendError> where B: vyre_driver::VyreBackend + ?core::marker::Sized, F: core::ops::function::FnMut(vyre_driver::OutputBuffers) -> core::result::Result<vyre_driver::OutputBuffers, vyre_driver::BackendError>
pub fn vyre_driver::speculate::encode_counter_tail(report: vyre_driver::speculate::SpeculationReport) -> [u8; 8]
pub fn vyre_driver::speculate::parse_counter_tail(output_bytes: &[u8]) -> core::option::Option<vyre_driver::speculate::SpeculationReport>
pub mod vyre_driver::subgroup
#[non_exhaustive] pub enum vyre_driver::subgroup::SubgroupOp
pub vyre_driver::subgroup::SubgroupOp::Add
pub vyre_driver::subgroup::SubgroupOp::Broadcast
pub vyre_driver::subgroup::SubgroupOp::ExclusiveAdd
pub vyre_driver::subgroup::SubgroupOp::InclusiveAdd
pub vyre_driver::subgroup::SubgroupOp::Max
pub vyre_driver::subgroup::SubgroupOp::Min
pub vyre_driver::subgroup::SubgroupOp::ShuffleXor
impl vyre_driver::subgroup::SubgroupOp
pub const fn vyre_driver::subgroup::SubgroupOp::all() -> &'static [vyre_driver::subgroup::SubgroupOp]
impl core::clone::Clone for vyre_driver::subgroup::SubgroupOp
pub fn vyre_driver::subgroup::SubgroupOp::clone(&self) -> vyre_driver::subgroup::SubgroupOp
impl core::cmp::Eq for vyre_driver::subgroup::SubgroupOp
impl core::cmp::PartialEq for vyre_driver::subgroup::SubgroupOp
pub fn vyre_driver::subgroup::SubgroupOp::eq(&self, other: &vyre_driver::subgroup::SubgroupOp) -> bool
impl core::fmt::Debug for vyre_driver::subgroup::SubgroupOp
pub fn vyre_driver::subgroup::SubgroupOp::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::subgroup::SubgroupOp
pub fn vyre_driver::subgroup::SubgroupOp::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::subgroup::SubgroupOp
impl core::marker::StructuralPartialEq for vyre_driver::subgroup::SubgroupOp
impl core::marker::Freeze for vyre_driver::subgroup::SubgroupOp
impl core::marker::Send for vyre_driver::subgroup::SubgroupOp
impl core::marker::Sync for vyre_driver::subgroup::SubgroupOp
impl core::marker::Unpin for vyre_driver::subgroup::SubgroupOp
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::subgroup::SubgroupOp
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::subgroup::SubgroupOp
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::subgroup::SubgroupOp where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupOp::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::subgroup::SubgroupOp where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::subgroup::SubgroupOp where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupOp::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::subgroup::SubgroupOp::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::subgroup::SubgroupOp where U: core::convert::From<T>
pub fn vyre_driver::subgroup::SubgroupOp::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::subgroup::SubgroupOp where U: core::convert::Into<T>
pub type vyre_driver::subgroup::SubgroupOp::Error = core::convert::Infallible
pub fn vyre_driver::subgroup::SubgroupOp::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::subgroup::SubgroupOp where U: core::convert::TryFrom<T>
pub type vyre_driver::subgroup::SubgroupOp::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::subgroup::SubgroupOp::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::subgroup::SubgroupOp where T: core::clone::Clone
pub type vyre_driver::subgroup::SubgroupOp::Owned = T
pub fn vyre_driver::subgroup::SubgroupOp::clone_into(&self, target: &mut T)
pub fn vyre_driver::subgroup::SubgroupOp::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::subgroup::SubgroupOp where T: 'static + ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupOp::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::subgroup::SubgroupOp where T: ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupOp::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::subgroup::SubgroupOp where T: ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupOp::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::subgroup::SubgroupOp where T: core::clone::Clone
pub unsafe fn vyre_driver::subgroup::SubgroupOp::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::subgroup::SubgroupOp
pub fn vyre_driver::subgroup::SubgroupOp::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::subgroup::SubgroupOp
impl<T> tracing::instrument::WithSubscriber for vyre_driver::subgroup::SubgroupOp
impl<T> typenum::type_operators::Same for vyre_driver::subgroup::SubgroupOp
pub type vyre_driver::subgroup::SubgroupOp::Output = T
pub struct vyre_driver::subgroup::SubgroupCaps
pub vyre_driver::subgroup::SubgroupCaps::subgroup_size: u32
pub vyre_driver::subgroup::SubgroupCaps::supports_subgroup: bool
pub vyre_driver::subgroup::SubgroupCaps::supports_subgroup_vertex: bool
impl vyre_driver::subgroup::SubgroupCaps
pub const fn vyre_driver::subgroup::SubgroupCaps::native(subgroup_size: u32) -> Self
impl core::clone::Clone for vyre_driver::subgroup::SubgroupCaps
pub fn vyre_driver::subgroup::SubgroupCaps::clone(&self) -> vyre_driver::subgroup::SubgroupCaps
impl core::cmp::Eq for vyre_driver::subgroup::SubgroupCaps
impl core::cmp::PartialEq for vyre_driver::subgroup::SubgroupCaps
pub fn vyre_driver::subgroup::SubgroupCaps::eq(&self, other: &vyre_driver::subgroup::SubgroupCaps) -> bool
impl core::default::Default for vyre_driver::subgroup::SubgroupCaps
pub fn vyre_driver::subgroup::SubgroupCaps::default() -> vyre_driver::subgroup::SubgroupCaps
impl core::fmt::Debug for vyre_driver::subgroup::SubgroupCaps
pub fn vyre_driver::subgroup::SubgroupCaps::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::subgroup::SubgroupCaps
impl core::marker::StructuralPartialEq for vyre_driver::subgroup::SubgroupCaps
impl core::marker::Freeze for vyre_driver::subgroup::SubgroupCaps
impl core::marker::Send for vyre_driver::subgroup::SubgroupCaps
impl core::marker::Sync for vyre_driver::subgroup::SubgroupCaps
impl core::marker::Unpin for vyre_driver::subgroup::SubgroupCaps
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::subgroup::SubgroupCaps
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::subgroup::SubgroupCaps
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::subgroup::SubgroupCaps where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupCaps::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::subgroup::SubgroupCaps where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::subgroup::SubgroupCaps where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupCaps::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::subgroup::SubgroupCaps::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::subgroup::SubgroupCaps where U: core::convert::From<T>
pub fn vyre_driver::subgroup::SubgroupCaps::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::subgroup::SubgroupCaps where U: core::convert::Into<T>
pub type vyre_driver::subgroup::SubgroupCaps::Error = core::convert::Infallible
pub fn vyre_driver::subgroup::SubgroupCaps::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::subgroup::SubgroupCaps where U: core::convert::TryFrom<T>
pub type vyre_driver::subgroup::SubgroupCaps::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::subgroup::SubgroupCaps::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::subgroup::SubgroupCaps where T: core::clone::Clone
pub type vyre_driver::subgroup::SubgroupCaps::Owned = T
pub fn vyre_driver::subgroup::SubgroupCaps::clone_into(&self, target: &mut T)
pub fn vyre_driver::subgroup::SubgroupCaps::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::subgroup::SubgroupCaps where T: 'static + ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupCaps::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::subgroup::SubgroupCaps where T: ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupCaps::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::subgroup::SubgroupCaps where T: ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupCaps::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::subgroup::SubgroupCaps where T: core::clone::Clone
pub unsafe fn vyre_driver::subgroup::SubgroupCaps::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::subgroup::SubgroupCaps
pub fn vyre_driver::subgroup::SubgroupCaps::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::subgroup::SubgroupCaps
impl<T> tracing::instrument::WithSubscriber for vyre_driver::subgroup::SubgroupCaps
impl<T> typenum::type_operators::Same for vyre_driver::subgroup::SubgroupCaps
pub type vyre_driver::subgroup::SubgroupCaps::Output = T
pub mod vyre_driver::tuner
#[non_exhaustive] pub enum vyre_driver::tuner::Mode
pub vyre_driver::tuner::Mode::OffUseDefault
pub vyre_driver::tuner::Mode::On
impl vyre_driver::tuner::Mode
pub fn vyre_driver::tuner::Mode::from_env() -> Self
impl core::clone::Clone for vyre_driver::tuner::Mode
pub fn vyre_driver::tuner::Mode::clone(&self) -> vyre_driver::tuner::Mode
impl core::cmp::Eq for vyre_driver::tuner::Mode
impl core::cmp::PartialEq for vyre_driver::tuner::Mode
pub fn vyre_driver::tuner::Mode::eq(&self, other: &vyre_driver::tuner::Mode) -> bool
impl core::fmt::Debug for vyre_driver::tuner::Mode
pub fn vyre_driver::tuner::Mode::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::tuner::Mode
impl core::marker::StructuralPartialEq for vyre_driver::tuner::Mode
impl core::marker::Freeze for vyre_driver::tuner::Mode
impl core::marker::Send for vyre_driver::tuner::Mode
impl core::marker::Sync for vyre_driver::tuner::Mode
impl core::marker::Unpin for vyre_driver::tuner::Mode
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::tuner::Mode
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::tuner::Mode
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::tuner::Mode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::tuner::Mode::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::tuner::Mode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::tuner::Mode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::tuner::Mode::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::tuner::Mode::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::tuner::Mode where U: core::convert::From<T>
pub fn vyre_driver::tuner::Mode::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::tuner::Mode where U: core::convert::Into<T>
pub type vyre_driver::tuner::Mode::Error = core::convert::Infallible
pub fn vyre_driver::tuner::Mode::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::tuner::Mode where U: core::convert::TryFrom<T>
pub type vyre_driver::tuner::Mode::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::tuner::Mode::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::tuner::Mode where T: core::clone::Clone
pub type vyre_driver::tuner::Mode::Owned = T
pub fn vyre_driver::tuner::Mode::clone_into(&self, target: &mut T)
pub fn vyre_driver::tuner::Mode::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::tuner::Mode where T: 'static + ?core::marker::Sized
pub fn vyre_driver::tuner::Mode::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::tuner::Mode where T: ?core::marker::Sized
pub fn vyre_driver::tuner::Mode::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::tuner::Mode where T: ?core::marker::Sized
pub fn vyre_driver::tuner::Mode::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::tuner::Mode where T: core::clone::Clone
pub unsafe fn vyre_driver::tuner::Mode::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::tuner::Mode
pub fn vyre_driver::tuner::Mode::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::tuner::Mode
impl<T> tracing::instrument::WithSubscriber for vyre_driver::tuner::Mode
impl<T> typenum::type_operators::Same for vyre_driver::tuner::Mode
pub type vyre_driver::tuner::Mode::Output = T
pub struct vyre_driver::tuner::DefaultPolicy
pub vyre_driver::tuner::DefaultPolicy::adapter_max_workgroup_size_x: u32
pub vyre_driver::tuner::DefaultPolicy::idle_shrink_us: u64
pub vyre_driver::tuner::DefaultPolicy::minimum_workgroup_size_x: u32
pub vyre_driver::tuner::DefaultPolicy::saturation_threshold_per_us: f64
impl vyre_driver::tuner::DefaultPolicy
pub fn vyre_driver::tuner::DefaultPolicy::suggest_resize(&self, feedback: &vyre_driver::tuner::TunerFeedback) -> core::option::Option<u32>
impl core::clone::Clone for vyre_driver::tuner::DefaultPolicy
pub fn vyre_driver::tuner::DefaultPolicy::clone(&self) -> vyre_driver::tuner::DefaultPolicy
impl core::default::Default for vyre_driver::tuner::DefaultPolicy
pub fn vyre_driver::tuner::DefaultPolicy::default() -> Self
impl core::fmt::Debug for vyre_driver::tuner::DefaultPolicy
pub fn vyre_driver::tuner::DefaultPolicy::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::tuner::DefaultPolicy
impl core::marker::Send for vyre_driver::tuner::DefaultPolicy
impl core::marker::Sync for vyre_driver::tuner::DefaultPolicy
impl core::marker::Unpin for vyre_driver::tuner::DefaultPolicy
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::tuner::DefaultPolicy
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::tuner::DefaultPolicy
impl<T, U> core::convert::Into<U> for vyre_driver::tuner::DefaultPolicy where U: core::convert::From<T>
pub fn vyre_driver::tuner::DefaultPolicy::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::tuner::DefaultPolicy where U: core::convert::Into<T>
pub type vyre_driver::tuner::DefaultPolicy::Error = core::convert::Infallible
pub fn vyre_driver::tuner::DefaultPolicy::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::tuner::DefaultPolicy where U: core::convert::TryFrom<T>
pub type vyre_driver::tuner::DefaultPolicy::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::tuner::DefaultPolicy::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::tuner::DefaultPolicy where T: core::clone::Clone
pub type vyre_driver::tuner::DefaultPolicy::Owned = T
pub fn vyre_driver::tuner::DefaultPolicy::clone_into(&self, target: &mut T)
pub fn vyre_driver::tuner::DefaultPolicy::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::tuner::DefaultPolicy where T: 'static + ?core::marker::Sized
pub fn vyre_driver::tuner::DefaultPolicy::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::tuner::DefaultPolicy where T: ?core::marker::Sized
pub fn vyre_driver::tuner::DefaultPolicy::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::tuner::DefaultPolicy where T: ?core::marker::Sized
pub fn vyre_driver::tuner::DefaultPolicy::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::tuner::DefaultPolicy where T: core::clone::Clone
pub unsafe fn vyre_driver::tuner::DefaultPolicy::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::tuner::DefaultPolicy
pub fn vyre_driver::tuner::DefaultPolicy::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::tuner::DefaultPolicy
impl<T> tracing::instrument::WithSubscriber for vyre_driver::tuner::DefaultPolicy
impl<T> typenum::type_operators::Same for vyre_driver::tuner::DefaultPolicy
pub type vyre_driver::tuner::DefaultPolicy::Output = T
pub struct vyre_driver::tuner::StaticProgramShape
pub vyre_driver::tuner::StaticProgramShape::output_bytes: u64
pub vyre_driver::tuner::StaticProgramShape::workgroup_count: core::option::Option<[u32; 3]>
pub vyre_driver::tuner::StaticProgramShape::workgroup_size: [u32; 3]
impl vyre_driver::tuner::StaticProgramShape
pub fn vyre_driver::tuner::StaticProgramShape::new(program: &vyre_foundation::ir_inner::model::program::core::Program, workgroup_count: core::option::Option<[u32; 3]>, output_bytes: u64) -> Self
impl core::clone::Clone for vyre_driver::tuner::StaticProgramShape
pub fn vyre_driver::tuner::StaticProgramShape::clone(&self) -> vyre_driver::tuner::StaticProgramShape
impl core::cmp::Eq for vyre_driver::tuner::StaticProgramShape
impl core::cmp::PartialEq for vyre_driver::tuner::StaticProgramShape
pub fn vyre_driver::tuner::StaticProgramShape::eq(&self, other: &vyre_driver::tuner::StaticProgramShape) -> bool
impl core::fmt::Debug for vyre_driver::tuner::StaticProgramShape
pub fn vyre_driver::tuner::StaticProgramShape::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::tuner::StaticProgramShape
impl core::marker::StructuralPartialEq for vyre_driver::tuner::StaticProgramShape
impl core::marker::Freeze for vyre_driver::tuner::StaticProgramShape
impl core::marker::Send for vyre_driver::tuner::StaticProgramShape
impl core::marker::Sync for vyre_driver::tuner::StaticProgramShape
impl core::marker::Unpin for vyre_driver::tuner::StaticProgramShape
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::tuner::StaticProgramShape
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::tuner::StaticProgramShape
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::tuner::StaticProgramShape where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::tuner::StaticProgramShape::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::tuner::StaticProgramShape where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::tuner::StaticProgramShape where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::tuner::StaticProgramShape::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::tuner::StaticProgramShape::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::tuner::StaticProgramShape where U: core::convert::From<T>
pub fn vyre_driver::tuner::StaticProgramShape::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::tuner::StaticProgramShape where U: core::convert::Into<T>
pub type vyre_driver::tuner::StaticProgramShape::Error = core::convert::Infallible
pub fn vyre_driver::tuner::StaticProgramShape::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::tuner::StaticProgramShape where U: core::convert::TryFrom<T>
pub type vyre_driver::tuner::StaticProgramShape::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::tuner::StaticProgramShape::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::tuner::StaticProgramShape where T: core::clone::Clone
pub type vyre_driver::tuner::StaticProgramShape::Owned = T
pub fn vyre_driver::tuner::StaticProgramShape::clone_into(&self, target: &mut T)
pub fn vyre_driver::tuner::StaticProgramShape::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::tuner::StaticProgramShape where T: 'static + ?core::marker::Sized
pub fn vyre_driver::tuner::StaticProgramShape::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::tuner::StaticProgramShape where T: ?core::marker::Sized
pub fn vyre_driver::tuner::StaticProgramShape::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::tuner::StaticProgramShape where T: ?core::marker::Sized
pub fn vyre_driver::tuner::StaticProgramShape::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::tuner::StaticProgramShape where T: core::clone::Clone
pub unsafe fn vyre_driver::tuner::StaticProgramShape::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::tuner::StaticProgramShape
pub fn vyre_driver::tuner::StaticProgramShape::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::tuner::StaticProgramShape
impl<T> tracing::instrument::WithSubscriber for vyre_driver::tuner::StaticProgramShape
impl<T> typenum::type_operators::Same for vyre_driver::tuner::StaticProgramShape
pub type vyre_driver::tuner::StaticProgramShape::Output = T
pub struct vyre_driver::tuner::Tuner
impl vyre_driver::tuner::Tuner
pub fn vyre_driver::tuner::Tuner::best_of<T: vyre_driver::tuner::BackendTimer>(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, candidates: impl core::iter::traits::collect::IntoIterator<Item = [u32; 3]>, timer: &mut T) -> core::result::Result<core::option::Option<vyre_driver::tuner::TuningMeasurement>, <T as vyre_driver::tuner::BackendTimer>::Error>
pub fn vyre_driver::tuner::Tuner::cache_path_for_adapter(adapter_fp: &str) -> std::path::PathBuf
pub fn vyre_driver::tuner::Tuner::candidates_for(&self, max_invocations: u32) -> alloc::vec::Vec<u32>
pub const fn vyre_driver::tuner::Tuner::default_workgroup_size() -> [u32; 3]
pub const fn vyre_driver::tuner::Tuner::mode(&self) -> vyre_driver::tuner::Mode
pub fn vyre_driver::tuner::Tuner::new(adapter_fp: &str, mode: vyre_driver::tuner::Mode) -> Self
pub fn vyre_driver::tuner::Tuner::persist(&self) -> core::result::Result<(), alloc::string::String>
pub fn vyre_driver::tuner::Tuner::record_decision(&mut self, program_fp: impl core::convert::Into<alloc::string::String>, size: [u32; 3])
pub fn vyre_driver::tuner::Tuner::record_key_decision(&mut self, key: &vyre_driver::tuner::TunerProgramKey, size: [u32; 3])
pub fn vyre_driver::tuner::Tuner::resolve(&self, program_fp: &str) -> [u32; 3]
pub fn vyre_driver::tuner::Tuner::resolve_key(&self, key: &vyre_driver::tuner::TunerProgramKey) -> [u32; 3]
impl core::marker::Freeze for vyre_driver::tuner::Tuner
impl core::marker::Send for vyre_driver::tuner::Tuner
impl core::marker::Sync for vyre_driver::tuner::Tuner
impl core::marker::Unpin for vyre_driver::tuner::Tuner
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::tuner::Tuner
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::tuner::Tuner
impl<T, U> core::convert::Into<U> for vyre_driver::tuner::Tuner where U: core::convert::From<T>
pub fn vyre_driver::tuner::Tuner::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::tuner::Tuner where U: core::convert::Into<T>
pub type vyre_driver::tuner::Tuner::Error = core::convert::Infallible
pub fn vyre_driver::tuner::Tuner::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::tuner::Tuner where U: core::convert::TryFrom<T>
pub type vyre_driver::tuner::Tuner::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::tuner::Tuner::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::tuner::Tuner where T: 'static + ?core::marker::Sized
pub fn vyre_driver::tuner::Tuner::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::tuner::Tuner where T: ?core::marker::Sized
pub fn vyre_driver::tuner::Tuner::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::tuner::Tuner where T: ?core::marker::Sized
pub fn vyre_driver::tuner::Tuner::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::tuner::Tuner
pub fn vyre_driver::tuner::Tuner::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::tuner::Tuner
impl<T> tracing::instrument::WithSubscriber for vyre_driver::tuner::Tuner
impl<T> typenum::type_operators::Same for vyre_driver::tuner::Tuner
pub type vyre_driver::tuner::Tuner::Output = T
pub struct vyre_driver::tuner::TunerCache
pub vyre_driver::tuner::TunerCache::entries: alloc::collections::btree::map::BTreeMap<alloc::string::String, [u32; 3]>
impl vyre_driver::tuner::TunerCache
pub fn vyre_driver::tuner::TunerCache::get(&self, program_fp: &str) -> core::option::Option<[u32; 3]>
pub fn vyre_driver::tuner::TunerCache::get_key(&self, key: &vyre_driver::tuner::TunerProgramKey) -> core::option::Option<[u32; 3]>
pub fn vyre_driver::tuner::TunerCache::load(path: &std::path::Path) -> core::result::Result<Self, alloc::string::String>
pub fn vyre_driver::tuner::TunerCache::save(&self, path: &std::path::Path) -> core::result::Result<(), alloc::string::String>
pub fn vyre_driver::tuner::TunerCache::set(&mut self, program_fp: impl core::convert::Into<alloc::string::String>, size: [u32; 3])
pub fn vyre_driver::tuner::TunerCache::set_key(&mut self, key: &vyre_driver::tuner::TunerProgramKey, size: [u32; 3])
impl core::clone::Clone for vyre_driver::tuner::TunerCache
pub fn vyre_driver::tuner::TunerCache::clone(&self) -> vyre_driver::tuner::TunerCache
impl core::cmp::Eq for vyre_driver::tuner::TunerCache
impl core::cmp::PartialEq for vyre_driver::tuner::TunerCache
pub fn vyre_driver::tuner::TunerCache::eq(&self, other: &vyre_driver::tuner::TunerCache) -> bool
impl core::default::Default for vyre_driver::tuner::TunerCache
pub fn vyre_driver::tuner::TunerCache::default() -> vyre_driver::tuner::TunerCache
impl core::fmt::Debug for vyre_driver::tuner::TunerCache
pub fn vyre_driver::tuner::TunerCache::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::tuner::TunerCache
impl core::marker::Freeze for vyre_driver::tuner::TunerCache
impl core::marker::Send for vyre_driver::tuner::TunerCache
impl core::marker::Sync for vyre_driver::tuner::TunerCache
impl core::marker::Unpin for vyre_driver::tuner::TunerCache
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::tuner::TunerCache
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::tuner::TunerCache
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::tuner::TunerCache where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::tuner::TunerCache::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::tuner::TunerCache where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::tuner::TunerCache where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::tuner::TunerCache::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::tuner::TunerCache::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::tuner::TunerCache where U: core::convert::From<T>
pub fn vyre_driver::tuner::TunerCache::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::tuner::TunerCache where U: core::convert::Into<T>
pub type vyre_driver::tuner::TunerCache::Error = core::convert::Infallible
pub fn vyre_driver::tuner::TunerCache::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::tuner::TunerCache where U: core::convert::TryFrom<T>
pub type vyre_driver::tuner::TunerCache::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::tuner::TunerCache::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::tuner::TunerCache where T: core::clone::Clone
pub type vyre_driver::tuner::TunerCache::Owned = T
pub fn vyre_driver::tuner::TunerCache::clone_into(&self, target: &mut T)
pub fn vyre_driver::tuner::TunerCache::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::tuner::TunerCache where T: 'static + ?core::marker::Sized
pub fn vyre_driver::tuner::TunerCache::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::tuner::TunerCache where T: ?core::marker::Sized
pub fn vyre_driver::tuner::TunerCache::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::tuner::TunerCache where T: ?core::marker::Sized
pub fn vyre_driver::tuner::TunerCache::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::tuner::TunerCache where T: core::clone::Clone
pub unsafe fn vyre_driver::tuner::TunerCache::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::tuner::TunerCache
pub fn vyre_driver::tuner::TunerCache::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::tuner::TunerCache
impl<T> tracing::instrument::WithSubscriber for vyre_driver::tuner::TunerCache
impl<T> typenum::type_operators::Same for vyre_driver::tuner::TunerCache
pub type vyre_driver::tuner::TunerCache::Output = T
pub struct vyre_driver::tuner::TunerFeedback
pub vyre_driver::tuner::TunerFeedback::idle_us: u64
pub vyre_driver::tuner::TunerFeedback::observed_throughput_per_us: f64
pub vyre_driver::tuner::TunerFeedback::observed_workgroup_size_x: u32
pub vyre_driver::tuner::TunerFeedback::per_opcode_counts: alloc::vec::Vec<(u32, u32)>
pub vyre_driver::tuner::TunerFeedback::wall_time_us: u64
impl core::clone::Clone for vyre_driver::tuner::TunerFeedback
pub fn vyre_driver::tuner::TunerFeedback::clone(&self) -> vyre_driver::tuner::TunerFeedback
impl core::fmt::Debug for vyre_driver::tuner::TunerFeedback
pub fn vyre_driver::tuner::TunerFeedback::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::tuner::TunerFeedback
impl core::marker::Send for vyre_driver::tuner::TunerFeedback
impl core::marker::Sync for vyre_driver::tuner::TunerFeedback
impl core::marker::Unpin for vyre_driver::tuner::TunerFeedback
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::tuner::TunerFeedback
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::tuner::TunerFeedback
impl<T, U> core::convert::Into<U> for vyre_driver::tuner::TunerFeedback where U: core::convert::From<T>
pub fn vyre_driver::tuner::TunerFeedback::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::tuner::TunerFeedback where U: core::convert::Into<T>
pub type vyre_driver::tuner::TunerFeedback::Error = core::convert::Infallible
pub fn vyre_driver::tuner::TunerFeedback::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::tuner::TunerFeedback where U: core::convert::TryFrom<T>
pub type vyre_driver::tuner::TunerFeedback::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::tuner::TunerFeedback::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::tuner::TunerFeedback where T: core::clone::Clone
pub type vyre_driver::tuner::TunerFeedback::Owned = T
pub fn vyre_driver::tuner::TunerFeedback::clone_into(&self, target: &mut T)
pub fn vyre_driver::tuner::TunerFeedback::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::tuner::TunerFeedback where T: 'static + ?core::marker::Sized
pub fn vyre_driver::tuner::TunerFeedback::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::tuner::TunerFeedback where T: ?core::marker::Sized
pub fn vyre_driver::tuner::TunerFeedback::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::tuner::TunerFeedback where T: ?core::marker::Sized
pub fn vyre_driver::tuner::TunerFeedback::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::tuner::TunerFeedback where T: core::clone::Clone
pub unsafe fn vyre_driver::tuner::TunerFeedback::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::tuner::TunerFeedback
pub fn vyre_driver::tuner::TunerFeedback::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::tuner::TunerFeedback
impl<T> tracing::instrument::WithSubscriber for vyre_driver::tuner::TunerFeedback
impl<T> typenum::type_operators::Same for vyre_driver::tuner::TunerFeedback
pub type vyre_driver::tuner::TunerFeedback::Output = T
pub struct vyre_driver::tuner::TunerProgramKey(_)
impl vyre_driver::tuner::TunerProgramKey
pub fn vyre_driver::tuner::TunerProgramKey::as_str(&self) -> &str
pub fn vyre_driver::tuner::TunerProgramKey::from_program(program: &vyre_foundation::ir_inner::model::program::core::Program, shape: vyre_driver::tuner::StaticProgramShape) -> Self
impl core::clone::Clone for vyre_driver::tuner::TunerProgramKey
pub fn vyre_driver::tuner::TunerProgramKey::clone(&self) -> vyre_driver::tuner::TunerProgramKey
impl core::cmp::Eq for vyre_driver::tuner::TunerProgramKey
impl core::cmp::Ord for vyre_driver::tuner::TunerProgramKey
pub fn vyre_driver::tuner::TunerProgramKey::cmp(&self, other: &vyre_driver::tuner::TunerProgramKey) -> core::cmp::Ordering
impl core::cmp::PartialEq for vyre_driver::tuner::TunerProgramKey
pub fn vyre_driver::tuner::TunerProgramKey::eq(&self, other: &vyre_driver::tuner::TunerProgramKey) -> bool
impl core::cmp::PartialOrd for vyre_driver::tuner::TunerProgramKey
pub fn vyre_driver::tuner::TunerProgramKey::partial_cmp(&self, other: &vyre_driver::tuner::TunerProgramKey) -> core::option::Option<core::cmp::Ordering>
impl core::convert::AsRef<str> for vyre_driver::tuner::TunerProgramKey
pub fn vyre_driver::tuner::TunerProgramKey::as_ref(&self) -> &str
impl core::fmt::Debug for vyre_driver::tuner::TunerProgramKey
pub fn vyre_driver::tuner::TunerProgramKey::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::tuner::TunerProgramKey
pub fn vyre_driver::tuner::TunerProgramKey::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::StructuralPartialEq for vyre_driver::tuner::TunerProgramKey
impl core::marker::Freeze for vyre_driver::tuner::TunerProgramKey
impl core::marker::Send for vyre_driver::tuner::TunerProgramKey
impl core::marker::Sync for vyre_driver::tuner::TunerProgramKey
impl core::marker::Unpin for vyre_driver::tuner::TunerProgramKey
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::tuner::TunerProgramKey
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::tuner::TunerProgramKey
impl<Q, K> equivalent::Comparable<K> for vyre_driver::tuner::TunerProgramKey where Q: core::cmp::Ord + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::tuner::TunerProgramKey::compare(&self, key: &K) -> core::cmp::Ordering
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::tuner::TunerProgramKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::tuner::TunerProgramKey::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::tuner::TunerProgramKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::tuner::TunerProgramKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::tuner::TunerProgramKey::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::tuner::TunerProgramKey::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::tuner::TunerProgramKey where U: core::convert::From<T>
pub fn vyre_driver::tuner::TunerProgramKey::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::tuner::TunerProgramKey where U: core::convert::Into<T>
pub type vyre_driver::tuner::TunerProgramKey::Error = core::convert::Infallible
pub fn vyre_driver::tuner::TunerProgramKey::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::tuner::TunerProgramKey where U: core::convert::TryFrom<T>
pub type vyre_driver::tuner::TunerProgramKey::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::tuner::TunerProgramKey::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::tuner::TunerProgramKey where T: core::clone::Clone
pub type vyre_driver::tuner::TunerProgramKey::Owned = T
pub fn vyre_driver::tuner::TunerProgramKey::clone_into(&self, target: &mut T)
pub fn vyre_driver::tuner::TunerProgramKey::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::tuner::TunerProgramKey where T: 'static + ?core::marker::Sized
pub fn vyre_driver::tuner::TunerProgramKey::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::tuner::TunerProgramKey where T: ?core::marker::Sized
pub fn vyre_driver::tuner::TunerProgramKey::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::tuner::TunerProgramKey where T: ?core::marker::Sized
pub fn vyre_driver::tuner::TunerProgramKey::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::tuner::TunerProgramKey where T: core::clone::Clone
pub unsafe fn vyre_driver::tuner::TunerProgramKey::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::tuner::TunerProgramKey
pub fn vyre_driver::tuner::TunerProgramKey::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::tuner::TunerProgramKey
impl<T> tracing::instrument::WithSubscriber for vyre_driver::tuner::TunerProgramKey
impl<T> typenum::type_operators::Same for vyre_driver::tuner::TunerProgramKey
pub type vyre_driver::tuner::TunerProgramKey::Output = T
pub struct vyre_driver::tuner::TuningMeasurement
pub vyre_driver::tuner::TuningMeasurement::elapsed_ns: u64
pub vyre_driver::tuner::TuningMeasurement::workgroup_size: [u32; 3]
impl core::clone::Clone for vyre_driver::tuner::TuningMeasurement
pub fn vyre_driver::tuner::TuningMeasurement::clone(&self) -> vyre_driver::tuner::TuningMeasurement
impl core::cmp::Eq for vyre_driver::tuner::TuningMeasurement
impl core::cmp::PartialEq for vyre_driver::tuner::TuningMeasurement
pub fn vyre_driver::tuner::TuningMeasurement::eq(&self, other: &vyre_driver::tuner::TuningMeasurement) -> bool
impl core::fmt::Debug for vyre_driver::tuner::TuningMeasurement
pub fn vyre_driver::tuner::TuningMeasurement::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::tuner::TuningMeasurement
impl core::marker::StructuralPartialEq for vyre_driver::tuner::TuningMeasurement
impl core::marker::Freeze for vyre_driver::tuner::TuningMeasurement
impl core::marker::Send for vyre_driver::tuner::TuningMeasurement
impl core::marker::Sync for vyre_driver::tuner::TuningMeasurement
impl core::marker::Unpin for vyre_driver::tuner::TuningMeasurement
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::tuner::TuningMeasurement
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::tuner::TuningMeasurement
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::tuner::TuningMeasurement where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::tuner::TuningMeasurement::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::tuner::TuningMeasurement where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::tuner::TuningMeasurement where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::tuner::TuningMeasurement::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::tuner::TuningMeasurement::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::tuner::TuningMeasurement where U: core::convert::From<T>
pub fn vyre_driver::tuner::TuningMeasurement::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::tuner::TuningMeasurement where U: core::convert::Into<T>
pub type vyre_driver::tuner::TuningMeasurement::Error = core::convert::Infallible
pub fn vyre_driver::tuner::TuningMeasurement::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::tuner::TuningMeasurement where U: core::convert::TryFrom<T>
pub type vyre_driver::tuner::TuningMeasurement::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::tuner::TuningMeasurement::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::tuner::TuningMeasurement where T: core::clone::Clone
pub type vyre_driver::tuner::TuningMeasurement::Owned = T
pub fn vyre_driver::tuner::TuningMeasurement::clone_into(&self, target: &mut T)
pub fn vyre_driver::tuner::TuningMeasurement::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::tuner::TuningMeasurement where T: 'static + ?core::marker::Sized
pub fn vyre_driver::tuner::TuningMeasurement::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::tuner::TuningMeasurement where T: ?core::marker::Sized
pub fn vyre_driver::tuner::TuningMeasurement::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::tuner::TuningMeasurement where T: ?core::marker::Sized
pub fn vyre_driver::tuner::TuningMeasurement::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::tuner::TuningMeasurement where T: core::clone::Clone
pub unsafe fn vyre_driver::tuner::TuningMeasurement::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::tuner::TuningMeasurement
pub fn vyre_driver::tuner::TuningMeasurement::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::tuner::TuningMeasurement
impl<T> tracing::instrument::WithSubscriber for vyre_driver::tuner::TuningMeasurement
impl<T> typenum::type_operators::Same for vyre_driver::tuner::TuningMeasurement
pub type vyre_driver::tuner::TuningMeasurement::Output = T
pub trait vyre_driver::tuner::BackendTimer
pub type vyre_driver::tuner::BackendTimer::Error
pub fn vyre_driver::tuner::BackendTimer::measure_candidate_ns(&mut self, program: &vyre_foundation::ir_inner::model::program::core::Program, workgroup_size: [u32; 3]) -> core::result::Result<u64, Self::Error>
pub mod vyre_driver::validation
pub struct vyre_driver::validation::LaunchGeometryLimits
pub vyre_driver::validation::LaunchGeometryLimits::backend: &'static str
pub vyre_driver::validation::LaunchGeometryLimits::max_grid_dim: [u32; 3]
pub vyre_driver::validation::LaunchGeometryLimits::max_threads_per_block: u32
impl core::clone::Clone for vyre_driver::validation::LaunchGeometryLimits
pub fn vyre_driver::validation::LaunchGeometryLimits::clone(&self) -> vyre_driver::validation::LaunchGeometryLimits
impl core::cmp::Eq for vyre_driver::validation::LaunchGeometryLimits
impl core::cmp::PartialEq for vyre_driver::validation::LaunchGeometryLimits
pub fn vyre_driver::validation::LaunchGeometryLimits::eq(&self, other: &vyre_driver::validation::LaunchGeometryLimits) -> bool
impl core::fmt::Debug for vyre_driver::validation::LaunchGeometryLimits
pub fn vyre_driver::validation::LaunchGeometryLimits::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::validation::LaunchGeometryLimits
impl core::marker::StructuralPartialEq for vyre_driver::validation::LaunchGeometryLimits
impl core::marker::Freeze for vyre_driver::validation::LaunchGeometryLimits
impl core::marker::Send for vyre_driver::validation::LaunchGeometryLimits
impl core::marker::Sync for vyre_driver::validation::LaunchGeometryLimits
impl core::marker::Unpin for vyre_driver::validation::LaunchGeometryLimits
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::validation::LaunchGeometryLimits
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::validation::LaunchGeometryLimits
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::validation::LaunchGeometryLimits where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::validation::LaunchGeometryLimits::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::validation::LaunchGeometryLimits where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::validation::LaunchGeometryLimits where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::validation::LaunchGeometryLimits::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::validation::LaunchGeometryLimits::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::validation::LaunchGeometryLimits where U: core::convert::From<T>
pub fn vyre_driver::validation::LaunchGeometryLimits::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::validation::LaunchGeometryLimits where U: core::convert::Into<T>
pub type vyre_driver::validation::LaunchGeometryLimits::Error = core::convert::Infallible
pub fn vyre_driver::validation::LaunchGeometryLimits::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::validation::LaunchGeometryLimits where U: core::convert::TryFrom<T>
pub type vyre_driver::validation::LaunchGeometryLimits::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::validation::LaunchGeometryLimits::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::validation::LaunchGeometryLimits where T: core::clone::Clone
pub type vyre_driver::validation::LaunchGeometryLimits::Owned = T
pub fn vyre_driver::validation::LaunchGeometryLimits::clone_into(&self, target: &mut T)
pub fn vyre_driver::validation::LaunchGeometryLimits::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::validation::LaunchGeometryLimits where T: 'static + ?core::marker::Sized
pub fn vyre_driver::validation::LaunchGeometryLimits::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::validation::LaunchGeometryLimits where T: ?core::marker::Sized
pub fn vyre_driver::validation::LaunchGeometryLimits::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::validation::LaunchGeometryLimits where T: ?core::marker::Sized
pub fn vyre_driver::validation::LaunchGeometryLimits::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::validation::LaunchGeometryLimits where T: core::clone::Clone
pub unsafe fn vyre_driver::validation::LaunchGeometryLimits::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::validation::LaunchGeometryLimits
pub fn vyre_driver::validation::LaunchGeometryLimits::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::validation::LaunchGeometryLimits
impl<T> tracing::instrument::WithSubscriber for vyre_driver::validation::LaunchGeometryLimits
impl<T> typenum::type_operators::Same for vyre_driver::validation::LaunchGeometryLimits
pub type vyre_driver::validation::LaunchGeometryLimits::Output = T
pub struct vyre_driver::validation::ValidationCache
impl vyre_driver::validation::ValidationCache
pub fn vyre_driver::validation::ValidationCache::clear(&self) -> core::result::Result<(), vyre_driver::BackendError>
pub fn vyre_driver::validation::ValidationCache::contains_hash(&self, hash: &blake3::Hash) -> bool
pub fn vyre_driver::validation::ValidationCache::new(max_hash_entries: usize, max_vsa_entries: usize, vsa_shards: usize) -> Self
pub fn vyre_driver::validation::ValidationCache::program_hash(program: &vyre_foundation::ir_inner::model::program::core::Program) -> blake3::Hash
pub fn vyre_driver::validation::ValidationCache::remember_hash(&self, hash: blake3::Hash)
pub fn vyre_driver::validation::ValidationCache::remember_success(&self, hash: blake3::Hash, vsa: alloc::vec::Vec<u32>) -> core::result::Result<(), vyre_driver::BackendError>
impl core::default::Default for vyre_driver::validation::ValidationCache
pub fn vyre_driver::validation::ValidationCache::default() -> Self
impl core::fmt::Debug for vyre_driver::validation::ValidationCache
pub fn vyre_driver::validation::ValidationCache::fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::validation::ValidationCache
impl core::marker::Send for vyre_driver::validation::ValidationCache
impl core::marker::Sync for vyre_driver::validation::ValidationCache
impl core::marker::Unpin for vyre_driver::validation::ValidationCache
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver::validation::ValidationCache
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::validation::ValidationCache
impl<T, U> core::convert::Into<U> for vyre_driver::validation::ValidationCache where U: core::convert::From<T>
pub fn vyre_driver::validation::ValidationCache::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::validation::ValidationCache where U: core::convert::Into<T>
pub type vyre_driver::validation::ValidationCache::Error = core::convert::Infallible
pub fn vyre_driver::validation::ValidationCache::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::validation::ValidationCache where U: core::convert::TryFrom<T>
pub type vyre_driver::validation::ValidationCache::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::validation::ValidationCache::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::validation::ValidationCache where T: 'static + ?core::marker::Sized
pub fn vyre_driver::validation::ValidationCache::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::validation::ValidationCache where T: ?core::marker::Sized
pub fn vyre_driver::validation::ValidationCache::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::validation::ValidationCache where T: ?core::marker::Sized
pub fn vyre_driver::validation::ValidationCache::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::validation::ValidationCache
pub fn vyre_driver::validation::ValidationCache::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::validation::ValidationCache
impl<T> tracing::instrument::WithSubscriber for vyre_driver::validation::ValidationCache
impl<T> typenum::type_operators::Same for vyre_driver::validation::ValidationCache
pub type vyre_driver::validation::ValidationCache::Output = T
pub const vyre_driver::validation::DEFAULT_VALIDATION_HASH_ENTRIES: usize
pub const vyre_driver::validation::DEFAULT_VALIDATION_VSA_ENTRIES: usize
pub const vyre_driver::validation::DEFAULT_VALIDATION_VSA_SHARDS: usize
pub fn vyre_driver::validation::validate_launch_geometry(workgroup: [u32; 3], grid: [u32; 3], limits: vyre_driver::validation::LaunchGeometryLimits) -> core::result::Result<(), vyre_driver::BackendError>
#[non_exhaustive] pub enum vyre_driver::BackendError
pub vyre_driver::BackendError::DeviceOutOfMemory
pub vyre_driver::BackendError::DeviceOutOfMemory::available: u64
pub vyre_driver::BackendError::DeviceOutOfMemory::requested: u64
pub vyre_driver::BackendError::DispatchFailed
pub vyre_driver::BackendError::DispatchFailed::code: core::option::Option<i32>
pub vyre_driver::BackendError::DispatchFailed::message: alloc::string::String
pub vyre_driver::BackendError::InvalidProgram
pub vyre_driver::BackendError::InvalidProgram::fix: alloc::string::String
pub vyre_driver::BackendError::KernelCompileFailed
pub vyre_driver::BackendError::KernelCompileFailed::backend: alloc::string::String
pub vyre_driver::BackendError::KernelCompileFailed::compiler_message: alloc::string::String
pub vyre_driver::BackendError::PoisonedLock
pub vyre_driver::BackendError::PoisonedLock::lock_error: alloc::string::String
pub vyre_driver::BackendError::Raw(alloc::string::String)
pub vyre_driver::BackendError::UnsupportedFeature
pub vyre_driver::BackendError::UnsupportedFeature::backend: alloc::string::String
pub vyre_driver::BackendError::UnsupportedFeature::name: alloc::string::String
impl vyre_driver::BackendError
pub fn vyre_driver::BackendError::code(&self) -> vyre_driver::backend::ErrorCode
pub fn vyre_driver::BackendError::into_message(self) -> alloc::string::String
pub fn vyre_driver::BackendError::message(&self) -> alloc::string::String
pub fn vyre_driver::BackendError::new(message: impl core::convert::Into<alloc::string::String>) -> Self
pub fn vyre_driver::BackendError::poisoned_lock<T>(error: std::sync::poison::PoisonError<T>) -> Self
pub fn vyre_driver::BackendError::unsupported_extension(backend: impl core::convert::Into<alloc::string::String>, extension_kind: &str, debug_identity: &str) -> Self
impl core::clone::Clone for vyre_driver::BackendError
pub fn vyre_driver::BackendError::clone(&self) -> vyre_driver::BackendError
impl core::cmp::Eq for vyre_driver::BackendError
impl core::cmp::PartialEq for vyre_driver::BackendError
pub fn vyre_driver::BackendError::eq(&self, other: &vyre_driver::BackendError) -> bool
impl core::convert::From<vyre_foundation::error::Error> for vyre_driver::BackendError
pub fn vyre_driver::BackendError::from(error: vyre_foundation::error::Error) -> Self
impl core::error::Error for vyre_driver::BackendError
impl core::fmt::Debug for vyre_driver::BackendError
pub fn vyre_driver::BackendError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::BackendError
pub fn vyre_driver::BackendError::fmt(&self, __formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::BackendError
impl core::marker::Freeze for vyre_driver::BackendError
impl core::marker::Send for vyre_driver::BackendError
impl core::marker::Sync for vyre_driver::BackendError
impl core::marker::Unpin for vyre_driver::BackendError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::BackendError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::BackendError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::BackendError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::BackendError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::BackendError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::BackendError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::BackendError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::BackendError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::BackendError where U: core::convert::From<T>
pub fn vyre_driver::BackendError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::BackendError where U: core::convert::Into<T>
pub type vyre_driver::BackendError::Error = core::convert::Infallible
pub fn vyre_driver::BackendError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::BackendError where U: core::convert::TryFrom<T>
pub type vyre_driver::BackendError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::BackendError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::BackendError where T: core::clone::Clone
pub type vyre_driver::BackendError::Owned = T
pub fn vyre_driver::BackendError::clone_into(&self, target: &mut T)
pub fn vyre_driver::BackendError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::BackendError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::BackendError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::BackendError where T: 'static + ?core::marker::Sized
pub fn vyre_driver::BackendError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::BackendError where T: ?core::marker::Sized
pub fn vyre_driver::BackendError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::BackendError where T: ?core::marker::Sized
pub fn vyre_driver::BackendError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::BackendError where T: core::clone::Clone
pub unsafe fn vyre_driver::BackendError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::BackendError
pub fn vyre_driver::BackendError::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::BackendError
impl<T> tracing::instrument::WithSubscriber for vyre_driver::BackendError
impl<T> typenum::type_operators::Same for vyre_driver::BackendError
pub type vyre_driver::BackendError::Output = T
pub enum vyre_driver::BindingRole
pub vyre_driver::BindingRole::Input
pub vyre_driver::BindingRole::InputOutput
pub vyre_driver::BindingRole::Output
pub vyre_driver::BindingRole::Persistent
pub vyre_driver::BindingRole::Shared
pub vyre_driver::BindingRole::Uniform
impl core::clone::Clone for vyre_driver::binding::BindingRole
pub fn vyre_driver::binding::BindingRole::clone(&self) -> vyre_driver::binding::BindingRole
impl core::cmp::Eq for vyre_driver::binding::BindingRole
impl core::cmp::PartialEq for vyre_driver::binding::BindingRole
pub fn vyre_driver::binding::BindingRole::eq(&self, other: &vyre_driver::binding::BindingRole) -> bool
impl core::fmt::Debug for vyre_driver::binding::BindingRole
pub fn vyre_driver::binding::BindingRole::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::binding::BindingRole
impl core::marker::StructuralPartialEq for vyre_driver::binding::BindingRole
impl core::marker::Freeze for vyre_driver::binding::BindingRole
impl core::marker::Send for vyre_driver::binding::BindingRole
impl core::marker::Sync for vyre_driver::binding::BindingRole
impl core::marker::Unpin for vyre_driver::binding::BindingRole
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::binding::BindingRole
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::binding::BindingRole
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::binding::BindingRole where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::binding::BindingRole::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::binding::BindingRole where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::binding::BindingRole where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::binding::BindingRole::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::binding::BindingRole::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::binding::BindingRole where U: core::convert::From<T>
pub fn vyre_driver::binding::BindingRole::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::binding::BindingRole where U: core::convert::Into<T>
pub type vyre_driver::binding::BindingRole::Error = core::convert::Infallible
pub fn vyre_driver::binding::BindingRole::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::binding::BindingRole where U: core::convert::TryFrom<T>
pub type vyre_driver::binding::BindingRole::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::binding::BindingRole::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::binding::BindingRole where T: core::clone::Clone
pub type vyre_driver::binding::BindingRole::Owned = T
pub fn vyre_driver::binding::BindingRole::clone_into(&self, target: &mut T)
pub fn vyre_driver::binding::BindingRole::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::binding::BindingRole where T: 'static + ?core::marker::Sized
pub fn vyre_driver::binding::BindingRole::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::binding::BindingRole where T: ?core::marker::Sized
pub fn vyre_driver::binding::BindingRole::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::binding::BindingRole where T: ?core::marker::Sized
pub fn vyre_driver::binding::BindingRole::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::binding::BindingRole where T: core::clone::Clone
pub unsafe fn vyre_driver::binding::BindingRole::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::binding::BindingRole
pub fn vyre_driver::binding::BindingRole::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::binding::BindingRole
impl<T> tracing::instrument::WithSubscriber for vyre_driver::binding::BindingRole
impl<T> typenum::type_operators::Same for vyre_driver::binding::BindingRole
pub type vyre_driver::binding::BindingRole::Output = T
#[non_exhaustive] pub enum vyre_driver::EnforceVerdict
pub vyre_driver::EnforceVerdict::Allow
pub vyre_driver::EnforceVerdict::Deny
pub vyre_driver::EnforceVerdict::Deny::detail: alloc::string::String
pub vyre_driver::EnforceVerdict::Deny::policy: &'static str
impl core::clone::Clone for vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::EnforceVerdict::clone(&self) -> vyre_driver::registry::enforce::EnforceVerdict
impl core::cmp::Eq for vyre_driver::registry::enforce::EnforceVerdict
impl core::cmp::PartialEq for vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::EnforceVerdict::eq(&self, other: &vyre_driver::registry::enforce::EnforceVerdict) -> bool
impl core::fmt::Debug for vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::EnforceVerdict::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::enforce::EnforceVerdict
impl core::marker::Freeze for vyre_driver::registry::enforce::EnforceVerdict
impl core::marker::Send for vyre_driver::registry::enforce::EnforceVerdict
impl core::marker::Sync for vyre_driver::registry::enforce::EnforceVerdict
impl core::marker::Unpin for vyre_driver::registry::enforce::EnforceVerdict
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::enforce::EnforceVerdict
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::enforce::EnforceVerdict
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::enforce::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::enforce::EnforceVerdict::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::enforce::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::enforce::EnforceVerdict where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::enforce::EnforceVerdict::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::enforce::EnforceVerdict::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::enforce::EnforceVerdict where U: core::convert::From<T>
pub fn vyre_driver::registry::enforce::EnforceVerdict::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::enforce::EnforceVerdict where U: core::convert::Into<T>
pub type vyre_driver::registry::enforce::EnforceVerdict::Error = core::convert::Infallible
pub fn vyre_driver::registry::enforce::EnforceVerdict::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::enforce::EnforceVerdict where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::enforce::EnforceVerdict::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::enforce::EnforceVerdict::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::enforce::EnforceVerdict where T: core::clone::Clone
pub type vyre_driver::registry::enforce::EnforceVerdict::Owned = T
pub fn vyre_driver::registry::enforce::EnforceVerdict::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::enforce::EnforceVerdict::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::enforce::EnforceVerdict where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::enforce::EnforceVerdict::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::enforce::EnforceVerdict where T: ?core::marker::Sized
pub fn vyre_driver::registry::enforce::EnforceVerdict::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::enforce::EnforceVerdict where T: ?core::marker::Sized
pub fn vyre_driver::registry::enforce::EnforceVerdict::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::enforce::EnforceVerdict where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::enforce::EnforceVerdict::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::EnforceVerdict::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::enforce::EnforceVerdict
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::enforce::EnforceVerdict
impl<T> typenum::type_operators::Same for vyre_driver::registry::enforce::EnforceVerdict
pub type vyre_driver::registry::enforce::EnforceVerdict::Output = T
#[non_exhaustive] pub enum vyre_driver::MutationClass
pub vyre_driver::MutationClass::Cosmetic
pub vyre_driver::MutationClass::Lowering
pub vyre_driver::MutationClass::Semantic
pub vyre_driver::MutationClass::Structural
impl vyre_driver::registry::mutation::MutationClass
pub const fn vyre_driver::registry::mutation::MutationClass::requires_byte_parity(self) -> bool
pub const fn vyre_driver::registry::mutation::MutationClass::uses_law_proof(self) -> bool
impl core::clone::Clone for vyre_driver::registry::mutation::MutationClass
pub fn vyre_driver::registry::mutation::MutationClass::clone(&self) -> vyre_driver::registry::mutation::MutationClass
impl core::cmp::Eq for vyre_driver::registry::mutation::MutationClass
impl core::cmp::PartialEq for vyre_driver::registry::mutation::MutationClass
pub fn vyre_driver::registry::mutation::MutationClass::eq(&self, other: &vyre_driver::registry::mutation::MutationClass) -> bool
impl core::fmt::Debug for vyre_driver::registry::mutation::MutationClass
pub fn vyre_driver::registry::mutation::MutationClass::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::registry::mutation::MutationClass
pub fn vyre_driver::registry::mutation::MutationClass::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::registry::mutation::MutationClass
impl core::marker::StructuralPartialEq for vyre_driver::registry::mutation::MutationClass
impl core::marker::Freeze for vyre_driver::registry::mutation::MutationClass
impl core::marker::Send for vyre_driver::registry::mutation::MutationClass
impl core::marker::Sync for vyre_driver::registry::mutation::MutationClass
impl core::marker::Unpin for vyre_driver::registry::mutation::MutationClass
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::mutation::MutationClass
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::mutation::MutationClass
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::mutation::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::mutation::MutationClass::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::mutation::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::mutation::MutationClass where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::mutation::MutationClass::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::mutation::MutationClass::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::mutation::MutationClass where U: core::convert::From<T>
pub fn vyre_driver::registry::mutation::MutationClass::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::mutation::MutationClass where U: core::convert::Into<T>
pub type vyre_driver::registry::mutation::MutationClass::Error = core::convert::Infallible
pub fn vyre_driver::registry::mutation::MutationClass::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::mutation::MutationClass where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::mutation::MutationClass::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::mutation::MutationClass::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::mutation::MutationClass where T: core::clone::Clone
pub type vyre_driver::registry::mutation::MutationClass::Owned = T
pub fn vyre_driver::registry::mutation::MutationClass::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::mutation::MutationClass::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::mutation::MutationClass where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::mutation::MutationClass::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::mutation::MutationClass where T: ?core::marker::Sized
pub fn vyre_driver::registry::mutation::MutationClass::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::mutation::MutationClass where T: ?core::marker::Sized
pub fn vyre_driver::registry::mutation::MutationClass::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::mutation::MutationClass where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::mutation::MutationClass::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::mutation::MutationClass
pub fn vyre_driver::registry::mutation::MutationClass::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::mutation::MutationClass
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::mutation::MutationClass
impl<T> typenum::type_operators::Same for vyre_driver::registry::mutation::MutationClass
pub type vyre_driver::registry::mutation::MutationClass::Output = T
pub enum vyre_driver::Resource
pub vyre_driver::Resource::Borrowed(alloc::vec::Vec<u8>)
pub vyre_driver::Resource::Resident(u64)
impl core::clone::Clone for vyre_driver::Resource
pub fn vyre_driver::Resource::clone(&self) -> vyre_driver::Resource
impl core::cmp::Eq for vyre_driver::Resource
impl core::cmp::PartialEq for vyre_driver::Resource
pub fn vyre_driver::Resource::eq(&self, other: &vyre_driver::Resource) -> bool
impl core::convert::From<alloc::vec::Vec<u8>> for vyre_driver::Resource
pub fn vyre_driver::Resource::from(bytes: alloc::vec::Vec<u8>) -> Self
impl core::default::Default for vyre_driver::Resource
pub fn vyre_driver::Resource::default() -> Self
impl core::fmt::Debug for vyre_driver::Resource
pub fn vyre_driver::Resource::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::Resource
impl core::marker::Freeze for vyre_driver::Resource
impl core::marker::Send for vyre_driver::Resource
impl core::marker::Sync for vyre_driver::Resource
impl core::marker::Unpin for vyre_driver::Resource
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::Resource
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::Resource
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::Resource where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::Resource::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::Resource where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::Resource where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::Resource::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::Resource::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::Resource where U: core::convert::From<T>
pub fn vyre_driver::Resource::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::Resource where U: core::convert::Into<T>
pub type vyre_driver::Resource::Error = core::convert::Infallible
pub fn vyre_driver::Resource::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::Resource where U: core::convert::TryFrom<T>
pub type vyre_driver::Resource::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::Resource::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::Resource where T: core::clone::Clone
pub type vyre_driver::Resource::Owned = T
pub fn vyre_driver::Resource::clone_into(&self, target: &mut T)
pub fn vyre_driver::Resource::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::Resource where T: 'static + ?core::marker::Sized
pub fn vyre_driver::Resource::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::Resource where T: ?core::marker::Sized
pub fn vyre_driver::Resource::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::Resource where T: ?core::marker::Sized
pub fn vyre_driver::Resource::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::Resource where T: core::clone::Clone
pub unsafe fn vyre_driver::Resource::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::Resource
pub fn vyre_driver::Resource::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::Resource
impl<T> tracing::instrument::WithSubscriber for vyre_driver::Resource
impl<T> typenum::type_operators::Same for vyre_driver::Resource
pub type vyre_driver::Resource::Output = T
#[non_exhaustive] pub enum vyre_driver::Severity
pub vyre_driver::Severity::Error
pub vyre_driver::Severity::Note
pub vyre_driver::Severity::Warning
impl vyre_driver::diagnostics::Severity
pub const fn vyre_driver::diagnostics::Severity::label(self) -> &'static str
impl core::clone::Clone for vyre_driver::diagnostics::Severity
pub fn vyre_driver::diagnostics::Severity::clone(&self) -> vyre_driver::diagnostics::Severity
impl core::cmp::Eq for vyre_driver::diagnostics::Severity
impl core::cmp::PartialEq for vyre_driver::diagnostics::Severity
pub fn vyre_driver::diagnostics::Severity::eq(&self, other: &vyre_driver::diagnostics::Severity) -> bool
impl core::fmt::Debug for vyre_driver::diagnostics::Severity
pub fn vyre_driver::diagnostics::Severity::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::diagnostics::Severity
pub fn vyre_driver::diagnostics::Severity::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::diagnostics::Severity
impl core::marker::StructuralPartialEq for vyre_driver::diagnostics::Severity
impl serde_core::ser::Serialize for vyre_driver::diagnostics::Severity
pub fn vyre_driver::diagnostics::Severity::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::diagnostics::Severity
pub fn vyre_driver::diagnostics::Severity::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::diagnostics::Severity
impl core::marker::Send for vyre_driver::diagnostics::Severity
impl core::marker::Sync for vyre_driver::diagnostics::Severity
impl core::marker::Unpin for vyre_driver::diagnostics::Severity
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::diagnostics::Severity
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::diagnostics::Severity
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::diagnostics::Severity where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::diagnostics::Severity::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::diagnostics::Severity where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::diagnostics::Severity where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::diagnostics::Severity::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::diagnostics::Severity::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::diagnostics::Severity where U: core::convert::From<T>
pub fn vyre_driver::diagnostics::Severity::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::diagnostics::Severity where U: core::convert::Into<T>
pub type vyre_driver::diagnostics::Severity::Error = core::convert::Infallible
pub fn vyre_driver::diagnostics::Severity::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::diagnostics::Severity where U: core::convert::TryFrom<T>
pub type vyre_driver::diagnostics::Severity::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::diagnostics::Severity::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::diagnostics::Severity where T: core::clone::Clone
pub type vyre_driver::diagnostics::Severity::Owned = T
pub fn vyre_driver::diagnostics::Severity::clone_into(&self, target: &mut T)
pub fn vyre_driver::diagnostics::Severity::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::diagnostics::Severity where T: 'static + ?core::marker::Sized
pub fn vyre_driver::diagnostics::Severity::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::diagnostics::Severity where T: ?core::marker::Sized
pub fn vyre_driver::diagnostics::Severity::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::diagnostics::Severity where T: ?core::marker::Sized
pub fn vyre_driver::diagnostics::Severity::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::diagnostics::Severity where T: core::clone::Clone
pub unsafe fn vyre_driver::diagnostics::Severity::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::diagnostics::Severity
pub fn vyre_driver::diagnostics::Severity::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::diagnostics::Severity where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::diagnostics::Severity
impl<T> tracing::instrument::WithSubscriber for vyre_driver::diagnostics::Severity
impl<T> typenum::type_operators::Same for vyre_driver::diagnostics::Severity
pub type vyre_driver::diagnostics::Severity::Output = T
#[non_exhaustive] pub enum vyre_driver::SortBackend
pub vyre_driver::SortBackend::BitonicSort
pub vyre_driver::SortBackend::InsertionSort
pub vyre_driver::SortBackend::RadixSort
impl core::clone::Clone for vyre_driver::routing::SortBackend
pub fn vyre_driver::routing::SortBackend::clone(&self) -> vyre_driver::routing::SortBackend
impl core::cmp::Eq for vyre_driver::routing::SortBackend
impl core::cmp::PartialEq for vyre_driver::routing::SortBackend
pub fn vyre_driver::routing::SortBackend::eq(&self, other: &vyre_driver::routing::SortBackend) -> bool
impl core::fmt::Debug for vyre_driver::routing::SortBackend
pub fn vyre_driver::routing::SortBackend::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::routing::SortBackend
impl core::marker::StructuralPartialEq for vyre_driver::routing::SortBackend
impl core::marker::Freeze for vyre_driver::routing::SortBackend
impl core::marker::Send for vyre_driver::routing::SortBackend
impl core::marker::Sync for vyre_driver::routing::SortBackend
impl core::marker::Unpin for vyre_driver::routing::SortBackend
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::routing::SortBackend
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::routing::SortBackend
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::routing::SortBackend where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::routing::SortBackend::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::routing::SortBackend where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::routing::SortBackend where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::routing::SortBackend::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::routing::SortBackend::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::routing::SortBackend where U: core::convert::From<T>
pub fn vyre_driver::routing::SortBackend::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::routing::SortBackend where U: core::convert::Into<T>
pub type vyre_driver::routing::SortBackend::Error = core::convert::Infallible
pub fn vyre_driver::routing::SortBackend::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::routing::SortBackend where U: core::convert::TryFrom<T>
pub type vyre_driver::routing::SortBackend::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::routing::SortBackend::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::routing::SortBackend where T: core::clone::Clone
pub type vyre_driver::routing::SortBackend::Owned = T
pub fn vyre_driver::routing::SortBackend::clone_into(&self, target: &mut T)
pub fn vyre_driver::routing::SortBackend::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::routing::SortBackend where T: 'static + ?core::marker::Sized
pub fn vyre_driver::routing::SortBackend::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::routing::SortBackend where T: ?core::marker::Sized
pub fn vyre_driver::routing::SortBackend::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::routing::SortBackend where T: ?core::marker::Sized
pub fn vyre_driver::routing::SortBackend::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::routing::SortBackend where T: core::clone::Clone
pub unsafe fn vyre_driver::routing::SortBackend::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::routing::SortBackend
pub fn vyre_driver::routing::SortBackend::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::routing::SortBackend
impl<T> tracing::instrument::WithSubscriber for vyre_driver::routing::SortBackend
impl<T> typenum::type_operators::Same for vyre_driver::routing::SortBackend
pub type vyre_driver::routing::SortBackend::Output = T
#[non_exhaustive] pub enum vyre_driver::SpecValue
pub vyre_driver::SpecValue::Bool(bool)
pub vyre_driver::SpecValue::F32(f32)
pub vyre_driver::SpecValue::I32(i32)
pub vyre_driver::SpecValue::U32(u32)
impl vyre_driver::specialization::SpecValue
pub fn vyre_driver::specialization::SpecValue::as_pipeline_f64(self) -> f64
pub fn vyre_driver::specialization::SpecValue::cache_hash(self) -> u64
impl core::clone::Clone for vyre_driver::specialization::SpecValue
pub fn vyre_driver::specialization::SpecValue::clone(&self) -> vyre_driver::specialization::SpecValue
impl core::cmp::PartialEq for vyre_driver::specialization::SpecValue
pub fn vyre_driver::specialization::SpecValue::eq(&self, other: &vyre_driver::specialization::SpecValue) -> bool
impl core::fmt::Debug for vyre_driver::specialization::SpecValue
pub fn vyre_driver::specialization::SpecValue::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::specialization::SpecValue
impl core::marker::StructuralPartialEq for vyre_driver::specialization::SpecValue
impl core::marker::Freeze for vyre_driver::specialization::SpecValue
impl core::marker::Send for vyre_driver::specialization::SpecValue
impl core::marker::Sync for vyre_driver::specialization::SpecValue
impl core::marker::Unpin for vyre_driver::specialization::SpecValue
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::specialization::SpecValue
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::specialization::SpecValue
impl<T, U> core::convert::Into<U> for vyre_driver::specialization::SpecValue where U: core::convert::From<T>
pub fn vyre_driver::specialization::SpecValue::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::specialization::SpecValue where U: core::convert::Into<T>
pub type vyre_driver::specialization::SpecValue::Error = core::convert::Infallible
pub fn vyre_driver::specialization::SpecValue::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::specialization::SpecValue where U: core::convert::TryFrom<T>
pub type vyre_driver::specialization::SpecValue::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::specialization::SpecValue::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::specialization::SpecValue where T: core::clone::Clone
pub type vyre_driver::specialization::SpecValue::Owned = T
pub fn vyre_driver::specialization::SpecValue::clone_into(&self, target: &mut T)
pub fn vyre_driver::specialization::SpecValue::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::specialization::SpecValue where T: 'static + ?core::marker::Sized
pub fn vyre_driver::specialization::SpecValue::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::specialization::SpecValue where T: ?core::marker::Sized
pub fn vyre_driver::specialization::SpecValue::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::specialization::SpecValue where T: ?core::marker::Sized
pub fn vyre_driver::specialization::SpecValue::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::specialization::SpecValue where T: core::clone::Clone
pub unsafe fn vyre_driver::specialization::SpecValue::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::specialization::SpecValue
pub fn vyre_driver::specialization::SpecValue::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::specialization::SpecValue
impl<T> tracing::instrument::WithSubscriber for vyre_driver::specialization::SpecValue
impl<T> typenum::type_operators::Same for vyre_driver::specialization::SpecValue
pub type vyre_driver::specialization::SpecValue::Output = T
#[non_exhaustive] pub enum vyre_driver::SubgroupOp
pub vyre_driver::SubgroupOp::Add
pub vyre_driver::SubgroupOp::Broadcast
pub vyre_driver::SubgroupOp::ExclusiveAdd
pub vyre_driver::SubgroupOp::InclusiveAdd
pub vyre_driver::SubgroupOp::Max
pub vyre_driver::SubgroupOp::Min
pub vyre_driver::SubgroupOp::ShuffleXor
impl vyre_driver::subgroup::SubgroupOp
pub const fn vyre_driver::subgroup::SubgroupOp::all() -> &'static [vyre_driver::subgroup::SubgroupOp]
impl core::clone::Clone for vyre_driver::subgroup::SubgroupOp
pub fn vyre_driver::subgroup::SubgroupOp::clone(&self) -> vyre_driver::subgroup::SubgroupOp
impl core::cmp::Eq for vyre_driver::subgroup::SubgroupOp
impl core::cmp::PartialEq for vyre_driver::subgroup::SubgroupOp
pub fn vyre_driver::subgroup::SubgroupOp::eq(&self, other: &vyre_driver::subgroup::SubgroupOp) -> bool
impl core::fmt::Debug for vyre_driver::subgroup::SubgroupOp
pub fn vyre_driver::subgroup::SubgroupOp::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::subgroup::SubgroupOp
pub fn vyre_driver::subgroup::SubgroupOp::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::subgroup::SubgroupOp
impl core::marker::StructuralPartialEq for vyre_driver::subgroup::SubgroupOp
impl core::marker::Freeze for vyre_driver::subgroup::SubgroupOp
impl core::marker::Send for vyre_driver::subgroup::SubgroupOp
impl core::marker::Sync for vyre_driver::subgroup::SubgroupOp
impl core::marker::Unpin for vyre_driver::subgroup::SubgroupOp
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::subgroup::SubgroupOp
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::subgroup::SubgroupOp
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::subgroup::SubgroupOp where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupOp::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::subgroup::SubgroupOp where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::subgroup::SubgroupOp where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupOp::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::subgroup::SubgroupOp::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::subgroup::SubgroupOp where U: core::convert::From<T>
pub fn vyre_driver::subgroup::SubgroupOp::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::subgroup::SubgroupOp where U: core::convert::Into<T>
pub type vyre_driver::subgroup::SubgroupOp::Error = core::convert::Infallible
pub fn vyre_driver::subgroup::SubgroupOp::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::subgroup::SubgroupOp where U: core::convert::TryFrom<T>
pub type vyre_driver::subgroup::SubgroupOp::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::subgroup::SubgroupOp::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::subgroup::SubgroupOp where T: core::clone::Clone
pub type vyre_driver::subgroup::SubgroupOp::Owned = T
pub fn vyre_driver::subgroup::SubgroupOp::clone_into(&self, target: &mut T)
pub fn vyre_driver::subgroup::SubgroupOp::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::subgroup::SubgroupOp where T: 'static + ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupOp::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::subgroup::SubgroupOp where T: ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupOp::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::subgroup::SubgroupOp where T: ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupOp::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::subgroup::SubgroupOp where T: core::clone::Clone
pub unsafe fn vyre_driver::subgroup::SubgroupOp::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::subgroup::SubgroupOp
pub fn vyre_driver::subgroup::SubgroupOp::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::subgroup::SubgroupOp
impl<T> tracing::instrument::WithSubscriber for vyre_driver::subgroup::SubgroupOp
impl<T> typenum::type_operators::Same for vyre_driver::subgroup::SubgroupOp
pub type vyre_driver::subgroup::SubgroupOp::Output = T
#[non_exhaustive] pub enum vyre_driver::Target
pub vyre_driver::Target::Extension(&'static str)
pub vyre_driver::Target::MetalIr
pub vyre_driver::Target::Ptx
pub vyre_driver::Target::ReferenceBackend
pub vyre_driver::Target::Spirv
pub vyre_driver::Target::Wgsl
impl core::clone::Clone for vyre_driver::registry::registry::Target
pub fn vyre_driver::registry::registry::Target::clone(&self) -> vyre_driver::registry::registry::Target
impl core::cmp::Eq for vyre_driver::registry::registry::Target
impl core::cmp::PartialEq for vyre_driver::registry::registry::Target
pub fn vyre_driver::registry::registry::Target::eq(&self, other: &vyre_driver::registry::registry::Target) -> bool
impl core::fmt::Debug for vyre_driver::registry::registry::Target
pub fn vyre_driver::registry::registry::Target::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::registry::registry::Target
pub fn vyre_driver::registry::registry::Target::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::registry::registry::Target
impl core::marker::StructuralPartialEq for vyre_driver::registry::registry::Target
impl core::marker::Freeze for vyre_driver::registry::registry::Target
impl core::marker::Send for vyre_driver::registry::registry::Target
impl core::marker::Sync for vyre_driver::registry::registry::Target
impl core::marker::Unpin for vyre_driver::registry::registry::Target
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::registry::Target
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::registry::Target
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::registry::Target::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::registry::Target where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::registry::Target::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::registry::Target::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::registry::Target where U: core::convert::From<T>
pub fn vyre_driver::registry::registry::Target::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::registry::Target where U: core::convert::Into<T>
pub type vyre_driver::registry::registry::Target::Error = core::convert::Infallible
pub fn vyre_driver::registry::registry::Target::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::registry::Target where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::registry::Target::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::registry::Target::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::registry::Target where T: core::clone::Clone
pub type vyre_driver::registry::registry::Target::Owned = T
pub fn vyre_driver::registry::registry::Target::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::registry::Target::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::registry::registry::Target where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::registry::Target::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::registry::Target where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::Target::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::registry::Target where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::Target::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::registry::Target where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::registry::Target::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::registry::Target
pub fn vyre_driver::registry::registry::Target::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::registry::Target
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::registry::Target
impl<T> typenum::type_operators::Same for vyre_driver::registry::registry::Target
pub type vyre_driver::registry::registry::Target::Output = T
pub struct vyre_driver::AotEmitter
pub vyre_driver::AotEmitter::emit: fn(&vyre_foundation::ir_inner::model::program::core::Program, &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<u8>, alloc::string::String>
pub vyre_driver::AotEmitter::target: vyre_driver::aot::AotTargetId
impl inventory::Collect for vyre_driver::aot::AotEmitter
impl core::marker::Freeze for vyre_driver::aot::AotEmitter
impl core::marker::Send for vyre_driver::aot::AotEmitter
impl core::marker::Sync for vyre_driver::aot::AotEmitter
impl core::marker::Unpin for vyre_driver::aot::AotEmitter
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::aot::AotEmitter
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::aot::AotEmitter
impl<T, U> core::convert::Into<U> for vyre_driver::aot::AotEmitter where U: core::convert::From<T>
pub fn vyre_driver::aot::AotEmitter::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::aot::AotEmitter where U: core::convert::Into<T>
pub type vyre_driver::aot::AotEmitter::Error = core::convert::Infallible
pub fn vyre_driver::aot::AotEmitter::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::aot::AotEmitter where U: core::convert::TryFrom<T>
pub type vyre_driver::aot::AotEmitter::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::aot::AotEmitter::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::aot::AotEmitter where T: 'static + ?core::marker::Sized
pub fn vyre_driver::aot::AotEmitter::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::aot::AotEmitter where T: ?core::marker::Sized
pub fn vyre_driver::aot::AotEmitter::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::aot::AotEmitter where T: ?core::marker::Sized
pub fn vyre_driver::aot::AotEmitter::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::aot::AotEmitter
pub fn vyre_driver::aot::AotEmitter::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::aot::AotEmitter
impl<T> tracing::instrument::WithSubscriber for vyre_driver::aot::AotEmitter
impl<T> typenum::type_operators::Same for vyre_driver::aot::AotEmitter
pub type vyre_driver::aot::AotEmitter::Output = T
pub struct vyre_driver::BackendRegistration
pub vyre_driver::BackendRegistration::factory: fn() -> core::result::Result<alloc::boxed::Box<dyn vyre_driver::VyreBackend>, vyre_driver::BackendError>
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
impl<T> typenum::type_operators::Same for vyre_driver::BackendRegistration
pub type vyre_driver::BackendRegistration::Output = T
pub struct vyre_driver::Binding
pub vyre_driver::Binding::binding: u32
pub vyre_driver::Binding::buffer_index: usize
pub vyre_driver::Binding::element_count: u32
pub vyre_driver::Binding::element_size: usize
pub vyre_driver::Binding::input_index: core::option::Option<usize>
pub vyre_driver::Binding::name: alloc::string::String
pub vyre_driver::Binding::output_index: core::option::Option<usize>
pub vyre_driver::Binding::role: vyre_driver::binding::BindingRole
pub vyre_driver::Binding::static_byte_len: core::option::Option<usize>
impl core::clone::Clone for vyre_driver::binding::Binding
pub fn vyre_driver::binding::Binding::clone(&self) -> vyre_driver::binding::Binding
impl core::cmp::Eq for vyre_driver::binding::Binding
impl core::cmp::PartialEq for vyre_driver::binding::Binding
pub fn vyre_driver::binding::Binding::eq(&self, other: &vyre_driver::binding::Binding) -> bool
impl core::fmt::Debug for vyre_driver::binding::Binding
pub fn vyre_driver::binding::Binding::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::binding::Binding
impl core::marker::Freeze for vyre_driver::binding::Binding
impl core::marker::Send for vyre_driver::binding::Binding
impl core::marker::Sync for vyre_driver::binding::Binding
impl core::marker::Unpin for vyre_driver::binding::Binding
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::binding::Binding
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::binding::Binding
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::binding::Binding where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::binding::Binding::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::binding::Binding where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::binding::Binding where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::binding::Binding::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::binding::Binding::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::binding::Binding where U: core::convert::From<T>
pub fn vyre_driver::binding::Binding::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::binding::Binding where U: core::convert::Into<T>
pub type vyre_driver::binding::Binding::Error = core::convert::Infallible
pub fn vyre_driver::binding::Binding::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::binding::Binding where U: core::convert::TryFrom<T>
pub type vyre_driver::binding::Binding::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::binding::Binding::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::binding::Binding where T: core::clone::Clone
pub type vyre_driver::binding::Binding::Owned = T
pub fn vyre_driver::binding::Binding::clone_into(&self, target: &mut T)
pub fn vyre_driver::binding::Binding::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::binding::Binding where T: 'static + ?core::marker::Sized
pub fn vyre_driver::binding::Binding::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::binding::Binding where T: ?core::marker::Sized
pub fn vyre_driver::binding::Binding::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::binding::Binding where T: ?core::marker::Sized
pub fn vyre_driver::binding::Binding::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::binding::Binding where T: core::clone::Clone
pub unsafe fn vyre_driver::binding::Binding::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::binding::Binding
pub fn vyre_driver::binding::Binding::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::binding::Binding
impl<T> tracing::instrument::WithSubscriber for vyre_driver::binding::Binding
impl<T> typenum::type_operators::Same for vyre_driver::binding::Binding
pub type vyre_driver::binding::Binding::Output = T
pub struct vyre_driver::BindingPlan
pub vyre_driver::BindingPlan::bindings: alloc::vec::Vec<vyre_driver::binding::Binding>
pub vyre_driver::BindingPlan::input_indices: alloc::vec::Vec<usize>
pub vyre_driver::BindingPlan::output_indices: alloc::vec::Vec<usize>
pub vyre_driver::BindingPlan::shared_indices: alloc::vec::Vec<usize>
impl vyre_driver::binding::BindingPlan
pub fn vyre_driver::binding::BindingPlan::build(program: &vyre_foundation::ir_inner::model::program::core::Program) -> core::result::Result<Self, vyre_driver::BackendError>
pub fn vyre_driver::binding::BindingPlan::from_program(program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[alloc::vec::Vec<u8>]) -> core::result::Result<Self, vyre_driver::BackendError>
pub fn vyre_driver::binding::BindingPlan::validate_inputs(&self, inputs: &[alloc::vec::Vec<u8>]) -> core::result::Result<(), vyre_driver::BackendError>
impl core::clone::Clone for vyre_driver::binding::BindingPlan
pub fn vyre_driver::binding::BindingPlan::clone(&self) -> vyre_driver::binding::BindingPlan
impl core::cmp::Eq for vyre_driver::binding::BindingPlan
impl core::cmp::PartialEq for vyre_driver::binding::BindingPlan
pub fn vyre_driver::binding::BindingPlan::eq(&self, other: &vyre_driver::binding::BindingPlan) -> bool
impl core::fmt::Debug for vyre_driver::binding::BindingPlan
pub fn vyre_driver::binding::BindingPlan::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::binding::BindingPlan
impl core::marker::Freeze for vyre_driver::binding::BindingPlan
impl core::marker::Send for vyre_driver::binding::BindingPlan
impl core::marker::Sync for vyre_driver::binding::BindingPlan
impl core::marker::Unpin for vyre_driver::binding::BindingPlan
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::binding::BindingPlan
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::binding::BindingPlan
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::binding::BindingPlan where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::binding::BindingPlan::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::binding::BindingPlan where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::binding::BindingPlan where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::binding::BindingPlan::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::binding::BindingPlan::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::binding::BindingPlan where U: core::convert::From<T>
pub fn vyre_driver::binding::BindingPlan::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::binding::BindingPlan where U: core::convert::Into<T>
pub type vyre_driver::binding::BindingPlan::Error = core::convert::Infallible
pub fn vyre_driver::binding::BindingPlan::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::binding::BindingPlan where U: core::convert::TryFrom<T>
pub type vyre_driver::binding::BindingPlan::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::binding::BindingPlan::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::binding::BindingPlan where T: core::clone::Clone
pub type vyre_driver::binding::BindingPlan::Owned = T
pub fn vyre_driver::binding::BindingPlan::clone_into(&self, target: &mut T)
pub fn vyre_driver::binding::BindingPlan::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::binding::BindingPlan where T: 'static + ?core::marker::Sized
pub fn vyre_driver::binding::BindingPlan::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::binding::BindingPlan where T: ?core::marker::Sized
pub fn vyre_driver::binding::BindingPlan::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::binding::BindingPlan where T: ?core::marker::Sized
pub fn vyre_driver::binding::BindingPlan::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::binding::BindingPlan where T: core::clone::Clone
pub unsafe fn vyre_driver::binding::BindingPlan::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::binding::BindingPlan
pub fn vyre_driver::binding::BindingPlan::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::binding::BindingPlan
impl<T> tracing::instrument::WithSubscriber for vyre_driver::binding::BindingPlan
impl<T> typenum::type_operators::Same for vyre_driver::binding::BindingPlan
pub type vyre_driver::binding::BindingPlan::Output = T
pub struct vyre_driver::Chain<A, B>
impl<A: vyre_driver::registry::enforce::EnforceGate, B: vyre_driver::registry::enforce::EnforceGate> vyre_driver::registry::enforce::Chain<A, B>
pub fn vyre_driver::registry::enforce::Chain<A, B>::new(first: A, second: B) -> Self
impl<A: vyre_driver::registry::enforce::EnforceGate, B: vyre_driver::registry::enforce::EnforceGate> vyre_driver::registry::enforce::EnforceGate for vyre_driver::registry::enforce::Chain<A, B>
pub fn vyre_driver::registry::enforce::Chain<A, B>::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::core::Program) -> vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::Chain<A, B>::name(&self) -> &'static str
impl<A, B> core::marker::Freeze for vyre_driver::registry::enforce::Chain<A, B> where A: core::marker::Freeze, B: core::marker::Freeze
impl<A, B> core::marker::Send for vyre_driver::registry::enforce::Chain<A, B> where A: core::marker::Send, B: core::marker::Send
impl<A, B> core::marker::Sync for vyre_driver::registry::enforce::Chain<A, B> where A: core::marker::Sync, B: core::marker::Sync
impl<A, B> core::marker::Unpin for vyre_driver::registry::enforce::Chain<A, B> where A: core::marker::Unpin, B: core::marker::Unpin
impl<A, B> core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::enforce::Chain<A, B> where A: core::panic::unwind_safe::RefUnwindSafe, B: core::panic::unwind_safe::RefUnwindSafe
impl<A, B> core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::enforce::Chain<A, B> where A: core::panic::unwind_safe::UnwindSafe, B: core::panic::unwind_safe::UnwindSafe
impl<T, U> core::convert::Into<U> for vyre_driver::registry::enforce::Chain<A, B> where U: core::convert::From<T>
pub fn vyre_driver::registry::enforce::Chain<A, B>::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::enforce::Chain<A, B> where U: core::convert::Into<T>
pub type vyre_driver::registry::enforce::Chain<A, B>::Error = core::convert::Infallible
pub fn vyre_driver::registry::enforce::Chain<A, B>::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::enforce::Chain<A, B> where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::enforce::Chain<A, B>::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::enforce::Chain<A, B>::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::enforce::Chain<A, B> where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::enforce::Chain<A, B>::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::enforce::Chain<A, B> where T: ?core::marker::Sized
pub fn vyre_driver::registry::enforce::Chain<A, B>::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::enforce::Chain<A, B> where T: ?core::marker::Sized
pub fn vyre_driver::registry::enforce::Chain<A, B>::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::enforce::Chain<A, B>
pub fn vyre_driver::registry::enforce::Chain<A, B>::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::enforce::Chain<A, B>
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::enforce::Chain<A, B>
impl<T> typenum::type_operators::Same for vyre_driver::registry::enforce::Chain<A, B>
pub type vyre_driver::registry::enforce::Chain<A, B>::Output = T
pub struct vyre_driver::Diagnostic
pub vyre_driver::Diagnostic::code: vyre_driver::diagnostics::DiagnosticCode
pub vyre_driver::Diagnostic::doc_url: core::option::Option<alloc::borrow::Cow<'static, str>>
pub vyre_driver::Diagnostic::location: core::option::Option<vyre_driver::diagnostics::OpLocation>
pub vyre_driver::Diagnostic::message: alloc::borrow::Cow<'static, str>
pub vyre_driver::Diagnostic::severity: vyre_driver::diagnostics::Severity
pub vyre_driver::Diagnostic::suggested_fix: core::option::Option<alloc::borrow::Cow<'static, str>>
impl vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::error(code: &'static str, message: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::diagnostics::Diagnostic::note(code: &'static str, message: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::diagnostics::Diagnostic::render_human(&self) -> alloc::string::String
pub fn vyre_driver::diagnostics::Diagnostic::to_json(&self) -> alloc::string::String
pub fn vyre_driver::diagnostics::Diagnostic::warning(code: &'static str, message: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::diagnostics::Diagnostic::with_doc_url(self, url: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::diagnostics::Diagnostic::with_fix(self, fix: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::diagnostics::Diagnostic::with_location(self, loc: vyre_driver::diagnostics::OpLocation) -> Self
impl core::clone::Clone for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::clone(&self) -> vyre_driver::diagnostics::Diagnostic
impl core::cmp::Eq for vyre_driver::diagnostics::Diagnostic
impl core::cmp::PartialEq for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::eq(&self, other: &vyre_driver::diagnostics::Diagnostic) -> bool
impl core::convert::From<&vyre_foundation::error::Error> for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::from(err: &vyre_foundation::error::Error) -> Self
impl core::convert::From<vyre_foundation::error::Error> for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::from(err: vyre_foundation::error::Error) -> Self
impl core::fmt::Debug for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::diagnostics::Diagnostic
impl serde_core::ser::Serialize for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::diagnostics::Diagnostic
impl core::marker::Send for vyre_driver::diagnostics::Diagnostic
impl core::marker::Sync for vyre_driver::diagnostics::Diagnostic
impl core::marker::Unpin for vyre_driver::diagnostics::Diagnostic
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::diagnostics::Diagnostic
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::diagnostics::Diagnostic
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::diagnostics::Diagnostic where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::diagnostics::Diagnostic::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::diagnostics::Diagnostic where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::diagnostics::Diagnostic where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::diagnostics::Diagnostic::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::diagnostics::Diagnostic::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::diagnostics::Diagnostic where U: core::convert::From<T>
pub fn vyre_driver::diagnostics::Diagnostic::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::diagnostics::Diagnostic where U: core::convert::Into<T>
pub type vyre_driver::diagnostics::Diagnostic::Error = core::convert::Infallible
pub fn vyre_driver::diagnostics::Diagnostic::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::diagnostics::Diagnostic where U: core::convert::TryFrom<T>
pub type vyre_driver::diagnostics::Diagnostic::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::diagnostics::Diagnostic::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::diagnostics::Diagnostic where T: core::clone::Clone
pub type vyre_driver::diagnostics::Diagnostic::Owned = T
pub fn vyre_driver::diagnostics::Diagnostic::clone_into(&self, target: &mut T)
pub fn vyre_driver::diagnostics::Diagnostic::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::diagnostics::Diagnostic where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::diagnostics::Diagnostic::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::diagnostics::Diagnostic where T: 'static + ?core::marker::Sized
pub fn vyre_driver::diagnostics::Diagnostic::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::diagnostics::Diagnostic where T: ?core::marker::Sized
pub fn vyre_driver::diagnostics::Diagnostic::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::diagnostics::Diagnostic where T: ?core::marker::Sized
pub fn vyre_driver::diagnostics::Diagnostic::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::diagnostics::Diagnostic where T: core::clone::Clone
pub unsafe fn vyre_driver::diagnostics::Diagnostic::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::diagnostics::Diagnostic
pub fn vyre_driver::diagnostics::Diagnostic::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::diagnostics::Diagnostic where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::diagnostics::Diagnostic
impl<T> tracing::instrument::WithSubscriber for vyre_driver::diagnostics::Diagnostic
impl<T> typenum::type_operators::Same for vyre_driver::diagnostics::Diagnostic
pub type vyre_driver::diagnostics::Diagnostic::Output = T
pub struct vyre_driver::DiagnosticCode(pub alloc::borrow::Cow<'static, str>)
impl vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::as_str(&self) -> &str
pub const fn vyre_driver::diagnostics::DiagnosticCode::new(code: &'static str) -> Self
impl core::clone::Clone for vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::clone(&self) -> vyre_driver::diagnostics::DiagnosticCode
impl core::cmp::Eq for vyre_driver::diagnostics::DiagnosticCode
impl core::cmp::PartialEq for vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::eq(&self, other: &vyre_driver::diagnostics::DiagnosticCode) -> bool
impl core::fmt::Debug for vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::StructuralPartialEq for vyre_driver::diagnostics::DiagnosticCode
impl serde_core::ser::Serialize for vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::diagnostics::DiagnosticCode
impl core::marker::Send for vyre_driver::diagnostics::DiagnosticCode
impl core::marker::Sync for vyre_driver::diagnostics::DiagnosticCode
impl core::marker::Unpin for vyre_driver::diagnostics::DiagnosticCode
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::diagnostics::DiagnosticCode
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::diagnostics::DiagnosticCode
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::diagnostics::DiagnosticCode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::diagnostics::DiagnosticCode::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::diagnostics::DiagnosticCode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::diagnostics::DiagnosticCode where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::diagnostics::DiagnosticCode::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::diagnostics::DiagnosticCode::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::diagnostics::DiagnosticCode where U: core::convert::From<T>
pub fn vyre_driver::diagnostics::DiagnosticCode::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::diagnostics::DiagnosticCode where U: core::convert::Into<T>
pub type vyre_driver::diagnostics::DiagnosticCode::Error = core::convert::Infallible
pub fn vyre_driver::diagnostics::DiagnosticCode::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::diagnostics::DiagnosticCode where U: core::convert::TryFrom<T>
pub type vyre_driver::diagnostics::DiagnosticCode::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::diagnostics::DiagnosticCode::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::diagnostics::DiagnosticCode where T: core::clone::Clone
pub type vyre_driver::diagnostics::DiagnosticCode::Owned = T
pub fn vyre_driver::diagnostics::DiagnosticCode::clone_into(&self, target: &mut T)
pub fn vyre_driver::diagnostics::DiagnosticCode::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::diagnostics::DiagnosticCode where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::diagnostics::DiagnosticCode::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::diagnostics::DiagnosticCode where T: 'static + ?core::marker::Sized
pub fn vyre_driver::diagnostics::DiagnosticCode::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::diagnostics::DiagnosticCode where T: ?core::marker::Sized
pub fn vyre_driver::diagnostics::DiagnosticCode::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::diagnostics::DiagnosticCode where T: ?core::marker::Sized
pub fn vyre_driver::diagnostics::DiagnosticCode::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::diagnostics::DiagnosticCode where T: core::clone::Clone
pub unsafe fn vyre_driver::diagnostics::DiagnosticCode::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::diagnostics::DiagnosticCode
pub fn vyre_driver::diagnostics::DiagnosticCode::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::diagnostics::DiagnosticCode where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::diagnostics::DiagnosticCode
impl<T> tracing::instrument::WithSubscriber for vyre_driver::diagnostics::DiagnosticCode
impl<T> typenum::type_operators::Same for vyre_driver::diagnostics::DiagnosticCode
pub type vyre_driver::diagnostics::DiagnosticCode::Output = T
pub struct vyre_driver::Dialect
pub vyre_driver::Dialect::backends_required: &'static [vyre_spec::intrinsic_descriptor::Backend]
pub vyre_driver::Dialect::id: &'static str
pub vyre_driver::Dialect::ops: &'static [&'static str]
pub vyre_driver::Dialect::parent: core::option::Option<&'static str>
pub vyre_driver::Dialect::validator: fn() -> bool
pub vyre_driver::Dialect::version: u32
impl core::marker::Freeze for vyre_driver::registry::dialect::Dialect
impl core::marker::Send for vyre_driver::registry::dialect::Dialect
impl core::marker::Sync for vyre_driver::registry::dialect::Dialect
impl core::marker::Unpin for vyre_driver::registry::dialect::Dialect
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::dialect::Dialect
impl !core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::dialect::Dialect
impl<T, U> core::convert::Into<U> for vyre_driver::registry::dialect::Dialect where U: core::convert::From<T>
pub fn vyre_driver::registry::dialect::Dialect::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::dialect::Dialect where U: core::convert::Into<T>
pub type vyre_driver::registry::dialect::Dialect::Error = core::convert::Infallible
pub fn vyre_driver::registry::dialect::Dialect::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::dialect::Dialect where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::dialect::Dialect::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::dialect::Dialect::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::dialect::Dialect where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::dialect::Dialect::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::dialect::Dialect where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::Dialect::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::dialect::Dialect where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::Dialect::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::dialect::Dialect
pub fn vyre_driver::registry::dialect::Dialect::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::dialect::Dialect
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::dialect::Dialect
impl<T> typenum::type_operators::Same for vyre_driver::registry::dialect::Dialect
pub type vyre_driver::registry::dialect::Dialect::Output = T
pub struct vyre_driver::DialectRegistration
pub vyre_driver::DialectRegistration::dialect: fn() -> vyre_driver::registry::dialect::Dialect
impl inventory::Collect for vyre_driver::registry::dialect::DialectRegistration
impl core::marker::Freeze for vyre_driver::registry::dialect::DialectRegistration
impl core::marker::Send for vyre_driver::registry::dialect::DialectRegistration
impl core::marker::Sync for vyre_driver::registry::dialect::DialectRegistration
impl core::marker::Unpin for vyre_driver::registry::dialect::DialectRegistration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::dialect::DialectRegistration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::dialect::DialectRegistration
impl<T, U> core::convert::Into<U> for vyre_driver::registry::dialect::DialectRegistration where U: core::convert::From<T>
pub fn vyre_driver::registry::dialect::DialectRegistration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::dialect::DialectRegistration where U: core::convert::Into<T>
pub type vyre_driver::registry::dialect::DialectRegistration::Error = core::convert::Infallible
pub fn vyre_driver::registry::dialect::DialectRegistration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::dialect::DialectRegistration where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::dialect::DialectRegistration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::dialect::DialectRegistration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::dialect::DialectRegistration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::dialect::DialectRegistration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::dialect::DialectRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::DialectRegistration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::dialect::DialectRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::DialectRegistration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::dialect::DialectRegistration
pub fn vyre_driver::registry::dialect::DialectRegistration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::dialect::DialectRegistration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::dialect::DialectRegistration
impl<T> typenum::type_operators::Same for vyre_driver::registry::dialect::DialectRegistration
pub type vyre_driver::registry::dialect::DialectRegistration::Output = T
pub struct vyre_driver::DialectRegistry
impl vyre_driver::registry::registry::DialectRegistry
pub fn vyre_driver::registry::registry::DialectRegistry::get_lowering(&self, id: vyre_foundation::dialect_lookup::InternedOpId, target: vyre_driver::registry::registry::Target) -> core::option::Option<vyre_foundation::dialect_lookup::ReferenceKind>
pub fn vyre_driver::registry::registry::DialectRegistry::global() -> arc_swap::Guard<alloc::sync::Arc<Self>>
pub fn vyre_driver::registry::registry::DialectRegistry::install(new: Self)
pub fn vyre_driver::registry::registry::DialectRegistry::intern_op(&self, name: &str) -> vyre_foundation::dialect_lookup::InternedOpId
pub fn vyre_driver::registry::registry::DialectRegistry::iter(&self) -> impl core::iter::traits::iterator::Iterator<Item = &'static vyre_foundation::dialect_lookup::OpDef> + '_
pub fn vyre_driver::registry::registry::DialectRegistry::lookup(&self, id: vyre_foundation::dialect_lookup::InternedOpId) -> core::option::Option<&'static vyre_foundation::dialect_lookup::OpDef>
pub fn vyre_driver::registry::registry::DialectRegistry::validate_no_duplicates<'a>(defs: impl core::iter::traits::collect::IntoIterator<Item = &'a vyre_foundation::dialect_lookup::OpDef>) -> core::result::Result<(), vyre_driver::registry::registry::DuplicateOpIdError>
impl vyre_foundation::dialect_lookup::DialectLookup for vyre_driver::registry::registry::DialectRegistry
pub fn vyre_driver::registry::registry::DialectRegistry::intern_op(&self, name: &str) -> vyre_foundation::dialect_lookup::InternedOpId
pub fn vyre_driver::registry::registry::DialectRegistry::lookup(&self, id: vyre_foundation::dialect_lookup::InternedOpId) -> core::option::Option<&'static vyre_foundation::dialect_lookup::OpDef>
pub fn vyre_driver::registry::registry::DialectRegistry::provider_id(&self) -> &'static str
impl vyre_foundation::dialect_lookup::private::Sealed for vyre_driver::registry::registry::DialectRegistry
impl core::marker::Freeze for vyre_driver::registry::registry::DialectRegistry
impl core::marker::Send for vyre_driver::registry::registry::DialectRegistry
impl core::marker::Sync for vyre_driver::registry::registry::DialectRegistry
impl core::marker::Unpin for vyre_driver::registry::registry::DialectRegistry
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::registry::DialectRegistry
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::registry::DialectRegistry
impl<T, U> core::convert::Into<U> for vyre_driver::registry::registry::DialectRegistry where U: core::convert::From<T>
pub fn vyre_driver::registry::registry::DialectRegistry::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::registry::DialectRegistry where U: core::convert::Into<T>
pub type vyre_driver::registry::registry::DialectRegistry::Error = core::convert::Infallible
pub fn vyre_driver::registry::registry::DialectRegistry::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::registry::DialectRegistry where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::registry::DialectRegistry::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::registry::DialectRegistry::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::registry::DialectRegistry where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::registry::DialectRegistry::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::registry::DialectRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::DialectRegistry::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::registry::DialectRegistry where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::DialectRegistry::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::registry::DialectRegistry
pub fn vyre_driver::registry::registry::DialectRegistry::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::registry::DialectRegistry
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::registry::DialectRegistry
impl<T> typenum::type_operators::Same for vyre_driver::registry::registry::DialectRegistry
pub type vyre_driver::registry::registry::DialectRegistry::Output = T
#[non_exhaustive] pub struct vyre_driver::DispatchConfig
pub vyre_driver::DispatchConfig::fixpoint_iterations: core::option::Option<u32>
pub vyre_driver::DispatchConfig::grid_override: core::option::Option<[u32; 3]>
pub vyre_driver::DispatchConfig::label: core::option::Option<alloc::string::String>
pub vyre_driver::DispatchConfig::max_output_bytes: core::option::Option<usize>
pub vyre_driver::DispatchConfig::persistent_thread: core::option::Option<vyre_driver::persistent::PersistentThreadMode>
pub vyre_driver::DispatchConfig::profile: core::option::Option<alloc::string::String>
pub vyre_driver::DispatchConfig::speculation: core::option::Option<vyre_driver::speculate::SpeculationMode>
pub vyre_driver::DispatchConfig::timeout: core::option::Option<core::time::Duration>
pub vyre_driver::DispatchConfig::ulp_budget: core::option::Option<u8>
pub vyre_driver::DispatchConfig::workgroup_override: core::option::Option<[u32; 3]>
impl vyre_driver::DispatchConfig
pub fn vyre_driver::DispatchConfig::new(profile: core::option::Option<alloc::string::String>, ulp_budget: core::option::Option<u8>, timeout: core::option::Option<core::time::Duration>, label: core::option::Option<alloc::string::String>) -> Self
impl core::clone::Clone for vyre_driver::DispatchConfig
pub fn vyre_driver::DispatchConfig::clone(&self) -> vyre_driver::DispatchConfig
impl core::cmp::Eq for vyre_driver::DispatchConfig
impl core::cmp::PartialEq for vyre_driver::DispatchConfig
pub fn vyre_driver::DispatchConfig::eq(&self, other: &vyre_driver::DispatchConfig) -> bool
impl core::default::Default for vyre_driver::DispatchConfig
pub fn vyre_driver::DispatchConfig::default() -> vyre_driver::DispatchConfig
impl core::fmt::Debug for vyre_driver::DispatchConfig
pub fn vyre_driver::DispatchConfig::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::DispatchConfig
impl core::marker::Freeze for vyre_driver::DispatchConfig
impl core::marker::Send for vyre_driver::DispatchConfig
impl core::marker::Sync for vyre_driver::DispatchConfig
impl core::marker::Unpin for vyre_driver::DispatchConfig
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::DispatchConfig
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::DispatchConfig
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::DispatchConfig where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::DispatchConfig::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::DispatchConfig where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::DispatchConfig where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::DispatchConfig::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::DispatchConfig::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::DispatchConfig where U: core::convert::From<T>
pub fn vyre_driver::DispatchConfig::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::DispatchConfig where U: core::convert::Into<T>
pub type vyre_driver::DispatchConfig::Error = core::convert::Infallible
pub fn vyre_driver::DispatchConfig::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::DispatchConfig where U: core::convert::TryFrom<T>
pub type vyre_driver::DispatchConfig::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::DispatchConfig::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::DispatchConfig where T: core::clone::Clone
pub type vyre_driver::DispatchConfig::Owned = T
pub fn vyre_driver::DispatchConfig::clone_into(&self, target: &mut T)
pub fn vyre_driver::DispatchConfig::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::DispatchConfig where T: 'static + ?core::marker::Sized
pub fn vyre_driver::DispatchConfig::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::DispatchConfig where T: ?core::marker::Sized
pub fn vyre_driver::DispatchConfig::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::DispatchConfig where T: ?core::marker::Sized
pub fn vyre_driver::DispatchConfig::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::DispatchConfig where T: core::clone::Clone
pub unsafe fn vyre_driver::DispatchConfig::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::DispatchConfig
pub fn vyre_driver::DispatchConfig::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::DispatchConfig
impl<T> tracing::instrument::WithSubscriber for vyre_driver::DispatchConfig
impl<T> typenum::type_operators::Same for vyre_driver::DispatchConfig
pub type vyre_driver::DispatchConfig::Output = T
pub struct vyre_driver::Distribution
impl vyre_driver::routing::Distribution
pub fn vyre_driver::routing::Distribution::observe(values: &[u32]) -> Self
impl core::clone::Clone for vyre_driver::routing::Distribution
pub fn vyre_driver::routing::Distribution::clone(&self) -> vyre_driver::routing::Distribution
impl core::cmp::Eq for vyre_driver::routing::Distribution
impl core::cmp::PartialEq for vyre_driver::routing::Distribution
pub fn vyre_driver::routing::Distribution::eq(&self, other: &vyre_driver::routing::Distribution) -> bool
impl core::fmt::Debug for vyre_driver::routing::Distribution
pub fn vyre_driver::routing::Distribution::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::routing::Distribution
impl core::marker::StructuralPartialEq for vyre_driver::routing::Distribution
impl core::marker::Freeze for vyre_driver::routing::Distribution
impl core::marker::Send for vyre_driver::routing::Distribution
impl core::marker::Sync for vyre_driver::routing::Distribution
impl core::marker::Unpin for vyre_driver::routing::Distribution
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::routing::Distribution
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::routing::Distribution
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::routing::Distribution where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::routing::Distribution::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::routing::Distribution where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::routing::Distribution where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::routing::Distribution::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::routing::Distribution::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::routing::Distribution where U: core::convert::From<T>
pub fn vyre_driver::routing::Distribution::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::routing::Distribution where U: core::convert::Into<T>
pub type vyre_driver::routing::Distribution::Error = core::convert::Infallible
pub fn vyre_driver::routing::Distribution::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::routing::Distribution where U: core::convert::TryFrom<T>
pub type vyre_driver::routing::Distribution::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::routing::Distribution::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::routing::Distribution where T: core::clone::Clone
pub type vyre_driver::routing::Distribution::Owned = T
pub fn vyre_driver::routing::Distribution::clone_into(&self, target: &mut T)
pub fn vyre_driver::routing::Distribution::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::routing::Distribution where T: 'static + ?core::marker::Sized
pub fn vyre_driver::routing::Distribution::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::routing::Distribution where T: ?core::marker::Sized
pub fn vyre_driver::routing::Distribution::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::routing::Distribution where T: ?core::marker::Sized
pub fn vyre_driver::routing::Distribution::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::routing::Distribution where T: core::clone::Clone
pub unsafe fn vyre_driver::routing::Distribution::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::routing::Distribution
pub fn vyre_driver::routing::Distribution::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::routing::Distribution
impl<T> tracing::instrument::WithSubscriber for vyre_driver::routing::Distribution
impl<T> typenum::type_operators::Same for vyre_driver::routing::Distribution
pub type vyre_driver::routing::Distribution::Output = T
pub struct vyre_driver::DuplicateOpIdError
impl vyre_driver::registry::registry::DuplicateOpIdError
pub const fn vyre_driver::registry::registry::DuplicateOpIdError::first_registrant(&self) -> &'static str
pub const fn vyre_driver::registry::registry::DuplicateOpIdError::op_id(&self) -> &'static str
pub const fn vyre_driver::registry::registry::DuplicateOpIdError::second_registrant(&self) -> &'static str
impl core::clone::Clone for vyre_driver::registry::registry::DuplicateOpIdError
pub fn vyre_driver::registry::registry::DuplicateOpIdError::clone(&self) -> vyre_driver::registry::registry::DuplicateOpIdError
impl core::cmp::Eq for vyre_driver::registry::registry::DuplicateOpIdError
impl core::cmp::PartialEq for vyre_driver::registry::registry::DuplicateOpIdError
pub fn vyre_driver::registry::registry::DuplicateOpIdError::eq(&self, other: &vyre_driver::registry::registry::DuplicateOpIdError) -> bool
impl core::error::Error for vyre_driver::registry::registry::DuplicateOpIdError
impl core::fmt::Debug for vyre_driver::registry::registry::DuplicateOpIdError
pub fn vyre_driver::registry::registry::DuplicateOpIdError::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::fmt::Display for vyre_driver::registry::registry::DuplicateOpIdError
pub fn vyre_driver::registry::registry::DuplicateOpIdError::fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::registry::registry::DuplicateOpIdError
impl core::marker::Freeze for vyre_driver::registry::registry::DuplicateOpIdError
impl core::marker::Send for vyre_driver::registry::registry::DuplicateOpIdError
impl core::marker::Sync for vyre_driver::registry::registry::DuplicateOpIdError
impl core::marker::Unpin for vyre_driver::registry::registry::DuplicateOpIdError
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::registry::DuplicateOpIdError
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::registry::DuplicateOpIdError
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::registry::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::registry::registry::DuplicateOpIdError where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::registry::registry::DuplicateOpIdError::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::registry::registry::DuplicateOpIdError where U: core::convert::From<T>
pub fn vyre_driver::registry::registry::DuplicateOpIdError::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::registry::DuplicateOpIdError where U: core::convert::Into<T>
pub type vyre_driver::registry::registry::DuplicateOpIdError::Error = core::convert::Infallible
pub fn vyre_driver::registry::registry::DuplicateOpIdError::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::registry::DuplicateOpIdError where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::registry::DuplicateOpIdError::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::registry::DuplicateOpIdError::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::registry::registry::DuplicateOpIdError where T: core::clone::Clone
pub type vyre_driver::registry::registry::DuplicateOpIdError::Owned = T
pub fn vyre_driver::registry::registry::DuplicateOpIdError::clone_into(&self, target: &mut T)
pub fn vyre_driver::registry::registry::DuplicateOpIdError::to_owned(&self) -> T
impl<T> alloc::string::ToString for vyre_driver::registry::registry::DuplicateOpIdError where T: core::fmt::Display + ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::to_string(&self) -> alloc::string::String
impl<T> core::any::Any for vyre_driver::registry::registry::DuplicateOpIdError where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::registry::DuplicateOpIdError where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::registry::DuplicateOpIdError where T: ?core::marker::Sized
pub fn vyre_driver::registry::registry::DuplicateOpIdError::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::registry::registry::DuplicateOpIdError where T: core::clone::Clone
pub unsafe fn vyre_driver::registry::registry::DuplicateOpIdError::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::registry::registry::DuplicateOpIdError
pub fn vyre_driver::registry::registry::DuplicateOpIdError::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::registry::DuplicateOpIdError
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::registry::DuplicateOpIdError
impl<T> typenum::type_operators::Same for vyre_driver::registry::registry::DuplicateOpIdError
pub type vyre_driver::registry::registry::DuplicateOpIdError::Output = T
pub struct vyre_driver::IndirectDispatch
pub vyre_driver::IndirectDispatch::count_buffer: alloc::string::String
pub vyre_driver::IndirectDispatch::count_offset: u64
impl core::clone::Clone for vyre_driver::program_walks::IndirectDispatch
pub fn vyre_driver::program_walks::IndirectDispatch::clone(&self) -> vyre_driver::program_walks::IndirectDispatch
impl core::cmp::Eq for vyre_driver::program_walks::IndirectDispatch
impl core::cmp::PartialEq for vyre_driver::program_walks::IndirectDispatch
pub fn vyre_driver::program_walks::IndirectDispatch::eq(&self, other: &vyre_driver::program_walks::IndirectDispatch) -> bool
impl core::fmt::Debug for vyre_driver::program_walks::IndirectDispatch
pub fn vyre_driver::program_walks::IndirectDispatch::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::program_walks::IndirectDispatch
impl core::marker::Freeze for vyre_driver::program_walks::IndirectDispatch
impl core::marker::Send for vyre_driver::program_walks::IndirectDispatch
impl core::marker::Sync for vyre_driver::program_walks::IndirectDispatch
impl core::marker::Unpin for vyre_driver::program_walks::IndirectDispatch
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::program_walks::IndirectDispatch
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::program_walks::IndirectDispatch
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::program_walks::IndirectDispatch where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::program_walks::IndirectDispatch::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::program_walks::IndirectDispatch where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::program_walks::IndirectDispatch where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::program_walks::IndirectDispatch::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::program_walks::IndirectDispatch::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::program_walks::IndirectDispatch where U: core::convert::From<T>
pub fn vyre_driver::program_walks::IndirectDispatch::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::program_walks::IndirectDispatch where U: core::convert::Into<T>
pub type vyre_driver::program_walks::IndirectDispatch::Error = core::convert::Infallible
pub fn vyre_driver::program_walks::IndirectDispatch::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::program_walks::IndirectDispatch where U: core::convert::TryFrom<T>
pub type vyre_driver::program_walks::IndirectDispatch::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::program_walks::IndirectDispatch::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::program_walks::IndirectDispatch where T: core::clone::Clone
pub type vyre_driver::program_walks::IndirectDispatch::Owned = T
pub fn vyre_driver::program_walks::IndirectDispatch::clone_into(&self, target: &mut T)
pub fn vyre_driver::program_walks::IndirectDispatch::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::program_walks::IndirectDispatch where T: 'static + ?core::marker::Sized
pub fn vyre_driver::program_walks::IndirectDispatch::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::program_walks::IndirectDispatch where T: ?core::marker::Sized
pub fn vyre_driver::program_walks::IndirectDispatch::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::program_walks::IndirectDispatch where T: ?core::marker::Sized
pub fn vyre_driver::program_walks::IndirectDispatch::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::program_walks::IndirectDispatch where T: core::clone::Clone
pub unsafe fn vyre_driver::program_walks::IndirectDispatch::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::program_walks::IndirectDispatch
pub fn vyre_driver::program_walks::IndirectDispatch::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::program_walks::IndirectDispatch
impl<T> tracing::instrument::WithSubscriber for vyre_driver::program_walks::IndirectDispatch
impl<T> typenum::type_operators::Same for vyre_driver::program_walks::IndirectDispatch
pub type vyre_driver::program_walks::IndirectDispatch::Output = T
pub struct vyre_driver::OpBackendTarget
pub vyre_driver::OpBackendTarget::op: &'static str
pub vyre_driver::OpBackendTarget::target: &'static str
impl inventory::Collect for vyre_driver::registry::dialect::OpBackendTarget
impl core::marker::Freeze for vyre_driver::registry::dialect::OpBackendTarget
impl core::marker::Send for vyre_driver::registry::dialect::OpBackendTarget
impl core::marker::Sync for vyre_driver::registry::dialect::OpBackendTarget
impl core::marker::Unpin for vyre_driver::registry::dialect::OpBackendTarget
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::dialect::OpBackendTarget
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::dialect::OpBackendTarget
impl<T, U> core::convert::Into<U> for vyre_driver::registry::dialect::OpBackendTarget where U: core::convert::From<T>
pub fn vyre_driver::registry::dialect::OpBackendTarget::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::dialect::OpBackendTarget where U: core::convert::Into<T>
pub type vyre_driver::registry::dialect::OpBackendTarget::Error = core::convert::Infallible
pub fn vyre_driver::registry::dialect::OpBackendTarget::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::dialect::OpBackendTarget where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::dialect::OpBackendTarget::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::dialect::OpBackendTarget::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::dialect::OpBackendTarget where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpBackendTarget::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::dialect::OpBackendTarget where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpBackendTarget::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::dialect::OpBackendTarget where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpBackendTarget::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::dialect::OpBackendTarget
pub fn vyre_driver::registry::dialect::OpBackendTarget::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::dialect::OpBackendTarget
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::dialect::OpBackendTarget
impl<T> typenum::type_operators::Same for vyre_driver::registry::dialect::OpBackendTarget
pub type vyre_driver::registry::dialect::OpBackendTarget::Output = T
pub struct vyre_driver::OpDefRegistration
pub vyre_driver::OpDefRegistration::op: fn() -> vyre_foundation::dialect_lookup::OpDef
impl vyre_driver::registry::dialect::OpDefRegistration
pub const fn vyre_driver::registry::dialect::OpDefRegistration::new(op: fn() -> vyre_foundation::dialect_lookup::OpDef) -> Self
impl inventory::Collect for vyre_driver::registry::dialect::OpDefRegistration
impl core::marker::Freeze for vyre_driver::registry::dialect::OpDefRegistration
impl core::marker::Send for vyre_driver::registry::dialect::OpDefRegistration
impl core::marker::Sync for vyre_driver::registry::dialect::OpDefRegistration
impl core::marker::Unpin for vyre_driver::registry::dialect::OpDefRegistration
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::registry::dialect::OpDefRegistration
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::registry::dialect::OpDefRegistration
impl<T, U> core::convert::Into<U> for vyre_driver::registry::dialect::OpDefRegistration where U: core::convert::From<T>
pub fn vyre_driver::registry::dialect::OpDefRegistration::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::registry::dialect::OpDefRegistration where U: core::convert::Into<T>
pub type vyre_driver::registry::dialect::OpDefRegistration::Error = core::convert::Infallible
pub fn vyre_driver::registry::dialect::OpDefRegistration::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::registry::dialect::OpDefRegistration where U: core::convert::TryFrom<T>
pub type vyre_driver::registry::dialect::OpDefRegistration::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::registry::dialect::OpDefRegistration::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::registry::dialect::OpDefRegistration where T: 'static + ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpDefRegistration::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::registry::dialect::OpDefRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpDefRegistration::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::registry::dialect::OpDefRegistration where T: ?core::marker::Sized
pub fn vyre_driver::registry::dialect::OpDefRegistration::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::registry::dialect::OpDefRegistration
pub fn vyre_driver::registry::dialect::OpDefRegistration::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::registry::dialect::OpDefRegistration
impl<T> tracing::instrument::WithSubscriber for vyre_driver::registry::dialect::OpDefRegistration
impl<T> typenum::type_operators::Same for vyre_driver::registry::dialect::OpDefRegistration
pub type vyre_driver::registry::dialect::OpDefRegistration::Output = T
pub struct vyre_driver::OpLocation
pub vyre_driver::OpLocation::attr_name: core::option::Option<alloc::borrow::Cow<'static, str>>
pub vyre_driver::OpLocation::op_id: alloc::borrow::Cow<'static, str>
pub vyre_driver::OpLocation::operand_idx: core::option::Option<u32>
impl vyre_driver::diagnostics::OpLocation
pub fn vyre_driver::diagnostics::OpLocation::op(op_id: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::diagnostics::OpLocation::with_attr(self, name: impl core::convert::Into<alloc::borrow::Cow<'static, str>>) -> Self
pub fn vyre_driver::diagnostics::OpLocation::with_operand(self, idx: u32) -> Self
impl core::clone::Clone for vyre_driver::diagnostics::OpLocation
pub fn vyre_driver::diagnostics::OpLocation::clone(&self) -> vyre_driver::diagnostics::OpLocation
impl core::cmp::Eq for vyre_driver::diagnostics::OpLocation
impl core::cmp::PartialEq for vyre_driver::diagnostics::OpLocation
pub fn vyre_driver::diagnostics::OpLocation::eq(&self, other: &vyre_driver::diagnostics::OpLocation) -> bool
impl core::fmt::Debug for vyre_driver::diagnostics::OpLocation
pub fn vyre_driver::diagnostics::OpLocation::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::StructuralPartialEq for vyre_driver::diagnostics::OpLocation
impl serde_core::ser::Serialize for vyre_driver::diagnostics::OpLocation
pub fn vyre_driver::diagnostics::OpLocation::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::diagnostics::OpLocation
pub fn vyre_driver::diagnostics::OpLocation::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::diagnostics::OpLocation
impl core::marker::Send for vyre_driver::diagnostics::OpLocation
impl core::marker::Sync for vyre_driver::diagnostics::OpLocation
impl core::marker::Unpin for vyre_driver::diagnostics::OpLocation
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::diagnostics::OpLocation
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::diagnostics::OpLocation
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::diagnostics::OpLocation where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::diagnostics::OpLocation::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::diagnostics::OpLocation where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::diagnostics::OpLocation where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::diagnostics::OpLocation::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::diagnostics::OpLocation::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::diagnostics::OpLocation where U: core::convert::From<T>
pub fn vyre_driver::diagnostics::OpLocation::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::diagnostics::OpLocation where U: core::convert::Into<T>
pub type vyre_driver::diagnostics::OpLocation::Error = core::convert::Infallible
pub fn vyre_driver::diagnostics::OpLocation::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::diagnostics::OpLocation where U: core::convert::TryFrom<T>
pub type vyre_driver::diagnostics::OpLocation::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::diagnostics::OpLocation::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::diagnostics::OpLocation where T: core::clone::Clone
pub type vyre_driver::diagnostics::OpLocation::Owned = T
pub fn vyre_driver::diagnostics::OpLocation::clone_into(&self, target: &mut T)
pub fn vyre_driver::diagnostics::OpLocation::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::diagnostics::OpLocation where T: 'static + ?core::marker::Sized
pub fn vyre_driver::diagnostics::OpLocation::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::diagnostics::OpLocation where T: ?core::marker::Sized
pub fn vyre_driver::diagnostics::OpLocation::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::diagnostics::OpLocation where T: ?core::marker::Sized
pub fn vyre_driver::diagnostics::OpLocation::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::diagnostics::OpLocation where T: core::clone::Clone
pub unsafe fn vyre_driver::diagnostics::OpLocation::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::diagnostics::OpLocation
pub fn vyre_driver::diagnostics::OpLocation::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::diagnostics::OpLocation where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::diagnostics::OpLocation
impl<T> tracing::instrument::WithSubscriber for vyre_driver::diagnostics::OpLocation
impl<T> typenum::type_operators::Same for vyre_driver::diagnostics::OpLocation
pub type vyre_driver::diagnostics::OpLocation::Output = T
pub struct vyre_driver::OutputBindingLayout
pub vyre_driver::OutputBindingLayout::binding: u32
pub vyre_driver::OutputBindingLayout::layout: vyre_driver::program_walks::OutputLayout
pub vyre_driver::OutputBindingLayout::name: alloc::sync::Arc<str>
pub vyre_driver::OutputBindingLayout::word_count: usize
impl core::clone::Clone for vyre_driver::program_walks::OutputBindingLayout
pub fn vyre_driver::program_walks::OutputBindingLayout::clone(&self) -> vyre_driver::program_walks::OutputBindingLayout
impl core::fmt::Debug for vyre_driver::program_walks::OutputBindingLayout
pub fn vyre_driver::program_walks::OutputBindingLayout::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::program_walks::OutputBindingLayout
impl core::marker::Send for vyre_driver::program_walks::OutputBindingLayout
impl core::marker::Sync for vyre_driver::program_walks::OutputBindingLayout
impl core::marker::Unpin for vyre_driver::program_walks::OutputBindingLayout
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::program_walks::OutputBindingLayout
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::program_walks::OutputBindingLayout
impl<T, U> core::convert::Into<U> for vyre_driver::program_walks::OutputBindingLayout where U: core::convert::From<T>
pub fn vyre_driver::program_walks::OutputBindingLayout::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::program_walks::OutputBindingLayout where U: core::convert::Into<T>
pub type vyre_driver::program_walks::OutputBindingLayout::Error = core::convert::Infallible
pub fn vyre_driver::program_walks::OutputBindingLayout::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::program_walks::OutputBindingLayout where U: core::convert::TryFrom<T>
pub type vyre_driver::program_walks::OutputBindingLayout::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::program_walks::OutputBindingLayout::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::program_walks::OutputBindingLayout where T: core::clone::Clone
pub type vyre_driver::program_walks::OutputBindingLayout::Owned = T
pub fn vyre_driver::program_walks::OutputBindingLayout::clone_into(&self, target: &mut T)
pub fn vyre_driver::program_walks::OutputBindingLayout::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::program_walks::OutputBindingLayout where T: 'static + ?core::marker::Sized
pub fn vyre_driver::program_walks::OutputBindingLayout::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::program_walks::OutputBindingLayout where T: ?core::marker::Sized
pub fn vyre_driver::program_walks::OutputBindingLayout::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::program_walks::OutputBindingLayout where T: ?core::marker::Sized
pub fn vyre_driver::program_walks::OutputBindingLayout::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::program_walks::OutputBindingLayout where T: core::clone::Clone
pub unsafe fn vyre_driver::program_walks::OutputBindingLayout::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::program_walks::OutputBindingLayout
pub fn vyre_driver::program_walks::OutputBindingLayout::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::program_walks::OutputBindingLayout
impl<T> tracing::instrument::WithSubscriber for vyre_driver::program_walks::OutputBindingLayout
impl<T> typenum::type_operators::Same for vyre_driver::program_walks::OutputBindingLayout
pub type vyre_driver::program_walks::OutputBindingLayout::Output = T
pub struct vyre_driver::OutputLayout
pub vyre_driver::OutputLayout::copy_offset: usize
pub vyre_driver::OutputLayout::copy_size: usize
pub vyre_driver::OutputLayout::full_size: usize
pub vyre_driver::OutputLayout::read_size: usize
pub vyre_driver::OutputLayout::trim_start: usize
impl core::clone::Clone for vyre_driver::program_walks::OutputLayout
pub fn vyre_driver::program_walks::OutputLayout::clone(&self) -> vyre_driver::program_walks::OutputLayout
impl core::cmp::Eq for vyre_driver::program_walks::OutputLayout
impl core::cmp::PartialEq for vyre_driver::program_walks::OutputLayout
pub fn vyre_driver::program_walks::OutputLayout::eq(&self, other: &vyre_driver::program_walks::OutputLayout) -> bool
impl core::fmt::Debug for vyre_driver::program_walks::OutputLayout
pub fn vyre_driver::program_walks::OutputLayout::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::program_walks::OutputLayout
impl core::marker::StructuralPartialEq for vyre_driver::program_walks::OutputLayout
impl core::marker::Freeze for vyre_driver::program_walks::OutputLayout
impl core::marker::Send for vyre_driver::program_walks::OutputLayout
impl core::marker::Sync for vyre_driver::program_walks::OutputLayout
impl core::marker::Unpin for vyre_driver::program_walks::OutputLayout
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::program_walks::OutputLayout
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::program_walks::OutputLayout
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::program_walks::OutputLayout where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::program_walks::OutputLayout::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::program_walks::OutputLayout where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::program_walks::OutputLayout where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::program_walks::OutputLayout::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::program_walks::OutputLayout::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::program_walks::OutputLayout where U: core::convert::From<T>
pub fn vyre_driver::program_walks::OutputLayout::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::program_walks::OutputLayout where U: core::convert::Into<T>
pub type vyre_driver::program_walks::OutputLayout::Error = core::convert::Infallible
pub fn vyre_driver::program_walks::OutputLayout::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::program_walks::OutputLayout where U: core::convert::TryFrom<T>
pub type vyre_driver::program_walks::OutputLayout::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::program_walks::OutputLayout::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::program_walks::OutputLayout where T: core::clone::Clone
pub type vyre_driver::program_walks::OutputLayout::Owned = T
pub fn vyre_driver::program_walks::OutputLayout::clone_into(&self, target: &mut T)
pub fn vyre_driver::program_walks::OutputLayout::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::program_walks::OutputLayout where T: 'static + ?core::marker::Sized
pub fn vyre_driver::program_walks::OutputLayout::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::program_walks::OutputLayout where T: ?core::marker::Sized
pub fn vyre_driver::program_walks::OutputLayout::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::program_walks::OutputLayout where T: ?core::marker::Sized
pub fn vyre_driver::program_walks::OutputLayout::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::program_walks::OutputLayout where T: core::clone::Clone
pub unsafe fn vyre_driver::program_walks::OutputLayout::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::program_walks::OutputLayout
pub fn vyre_driver::program_walks::OutputLayout::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::program_walks::OutputLayout
impl<T> tracing::instrument::WithSubscriber for vyre_driver::program_walks::OutputLayout
impl<T> typenum::type_operators::Same for vyre_driver::program_walks::OutputLayout
pub type vyre_driver::program_walks::OutputLayout::Output = T
pub struct vyre_driver::PipelineCacheKey
pub vyre_driver::PipelineCacheKey::backend_id: vyre_spec::intrinsic_descriptor::BackendId
pub vyre_driver::PipelineCacheKey::bind_group_layout_hash: [u8; 32]
pub vyre_driver::PipelineCacheKey::feature_flags: vyre_driver::pipeline::PipelineFeatureFlags
pub vyre_driver::PipelineCacheKey::push_constant_size: u32
pub vyre_driver::PipelineCacheKey::shader_hash: [u8; 32]
pub vyre_driver::PipelineCacheKey::version: u32
pub vyre_driver::PipelineCacheKey::workgroup_size: [u32; 3]
impl vyre_driver::pipeline::PipelineCacheKey
pub fn vyre_driver::pipeline::PipelineCacheKey::new(shader_hash: [u8; 32], bind_group_layout_hash: [u8; 32], push_constant_size: u32, workgroup_size: [u32; 3], feature_flags: vyre_driver::pipeline::PipelineFeatureFlags, backend_id: vyre_spec::intrinsic_descriptor::BackendId) -> Self
impl core::clone::Clone for vyre_driver::pipeline::PipelineCacheKey
pub fn vyre_driver::pipeline::PipelineCacheKey::clone(&self) -> vyre_driver::pipeline::PipelineCacheKey
impl core::cmp::Eq for vyre_driver::pipeline::PipelineCacheKey
impl core::cmp::PartialEq for vyre_driver::pipeline::PipelineCacheKey
pub fn vyre_driver::pipeline::PipelineCacheKey::eq(&self, other: &vyre_driver::pipeline::PipelineCacheKey) -> bool
impl core::fmt::Debug for vyre_driver::pipeline::PipelineCacheKey
pub fn vyre_driver::pipeline::PipelineCacheKey::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::pipeline::PipelineCacheKey
pub fn vyre_driver::pipeline::PipelineCacheKey::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::StructuralPartialEq for vyre_driver::pipeline::PipelineCacheKey
impl core::marker::Freeze for vyre_driver::pipeline::PipelineCacheKey
impl core::marker::Send for vyre_driver::pipeline::PipelineCacheKey
impl core::marker::Sync for vyre_driver::pipeline::PipelineCacheKey
impl core::marker::Unpin for vyre_driver::pipeline::PipelineCacheKey
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::pipeline::PipelineCacheKey
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::pipeline::PipelineCacheKey
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::pipeline::PipelineCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineCacheKey::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pipeline::PipelineCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pipeline::PipelineCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineCacheKey::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::pipeline::PipelineCacheKey::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::pipeline::PipelineCacheKey where U: core::convert::From<T>
pub fn vyre_driver::pipeline::PipelineCacheKey::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::pipeline::PipelineCacheKey where U: core::convert::Into<T>
pub type vyre_driver::pipeline::PipelineCacheKey::Error = core::convert::Infallible
pub fn vyre_driver::pipeline::PipelineCacheKey::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::pipeline::PipelineCacheKey where U: core::convert::TryFrom<T>
pub type vyre_driver::pipeline::PipelineCacheKey::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::pipeline::PipelineCacheKey::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::pipeline::PipelineCacheKey where T: core::clone::Clone
pub type vyre_driver::pipeline::PipelineCacheKey::Owned = T
pub fn vyre_driver::pipeline::PipelineCacheKey::clone_into(&self, target: &mut T)
pub fn vyre_driver::pipeline::PipelineCacheKey::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::pipeline::PipelineCacheKey where T: 'static + ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineCacheKey::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::pipeline::PipelineCacheKey where T: ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineCacheKey::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::pipeline::PipelineCacheKey where T: ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineCacheKey::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::pipeline::PipelineCacheKey where T: core::clone::Clone
pub unsafe fn vyre_driver::pipeline::PipelineCacheKey::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::pipeline::PipelineCacheKey
pub fn vyre_driver::pipeline::PipelineCacheKey::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::pipeline::PipelineCacheKey
impl<T> tracing::instrument::WithSubscriber for vyre_driver::pipeline::PipelineCacheKey
impl<T> typenum::type_operators::Same for vyre_driver::pipeline::PipelineCacheKey
pub type vyre_driver::pipeline::PipelineCacheKey::Output = T
pub struct vyre_driver::PipelineFeatureFlags(pub u32)
impl vyre_driver::pipeline::PipelineFeatureFlags
pub const vyre_driver::pipeline::PipelineFeatureFlags::ASYNC_COMPUTE: Self
pub const vyre_driver::pipeline::PipelineFeatureFlags::BF16: Self
pub const vyre_driver::pipeline::PipelineFeatureFlags::F16: Self
pub const vyre_driver::pipeline::PipelineFeatureFlags::INDIRECT_DISPATCH: Self
pub const vyre_driver::pipeline::PipelineFeatureFlags::PERSISTENT_THREAD: Self
pub const vyre_driver::pipeline::PipelineFeatureFlags::PUSH_CONSTANTS: Self
pub const vyre_driver::pipeline::PipelineFeatureFlags::SPECULATIVE: Self
pub const vyre_driver::pipeline::PipelineFeatureFlags::SUBGROUP_OPS: Self
pub const vyre_driver::pipeline::PipelineFeatureFlags::TENSOR_CORES: Self
pub const fn vyre_driver::pipeline::PipelineFeatureFlags::bits(self) -> u32
pub const fn vyre_driver::pipeline::PipelineFeatureFlags::contains(self, other: Self) -> bool
pub const fn vyre_driver::pipeline::PipelineFeatureFlags::empty() -> Self
pub const fn vyre_driver::pipeline::PipelineFeatureFlags::union(self, other: Self) -> Self
impl core::clone::Clone for vyre_driver::pipeline::PipelineFeatureFlags
pub fn vyre_driver::pipeline::PipelineFeatureFlags::clone(&self) -> vyre_driver::pipeline::PipelineFeatureFlags
impl core::cmp::Eq for vyre_driver::pipeline::PipelineFeatureFlags
impl core::cmp::PartialEq for vyre_driver::pipeline::PipelineFeatureFlags
pub fn vyre_driver::pipeline::PipelineFeatureFlags::eq(&self, other: &vyre_driver::pipeline::PipelineFeatureFlags) -> bool
impl core::default::Default for vyre_driver::pipeline::PipelineFeatureFlags
pub fn vyre_driver::pipeline::PipelineFeatureFlags::default() -> vyre_driver::pipeline::PipelineFeatureFlags
impl core::fmt::Debug for vyre_driver::pipeline::PipelineFeatureFlags
pub fn vyre_driver::pipeline::PipelineFeatureFlags::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::pipeline::PipelineFeatureFlags
pub fn vyre_driver::pipeline::PipelineFeatureFlags::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::Copy for vyre_driver::pipeline::PipelineFeatureFlags
impl core::marker::StructuralPartialEq for vyre_driver::pipeline::PipelineFeatureFlags
impl serde_core::ser::Serialize for vyre_driver::pipeline::PipelineFeatureFlags
pub fn vyre_driver::pipeline::PipelineFeatureFlags::serialize<__S>(&self, __serializer: __S) -> core::result::Result<<__S as serde_core::ser::Serializer>::Ok, <__S as serde_core::ser::Serializer>::Error> where __S: serde_core::ser::Serializer
impl<'de> serde_core::de::Deserialize<'de> for vyre_driver::pipeline::PipelineFeatureFlags
pub fn vyre_driver::pipeline::PipelineFeatureFlags::deserialize<__D>(__deserializer: __D) -> core::result::Result<Self, <__D as serde_core::de::Deserializer>::Error> where __D: serde_core::de::Deserializer<'de>
impl core::marker::Freeze for vyre_driver::pipeline::PipelineFeatureFlags
impl core::marker::Send for vyre_driver::pipeline::PipelineFeatureFlags
impl core::marker::Sync for vyre_driver::pipeline::PipelineFeatureFlags
impl core::marker::Unpin for vyre_driver::pipeline::PipelineFeatureFlags
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::pipeline::PipelineFeatureFlags
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::pipeline::PipelineFeatureFlags
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::pipeline::PipelineFeatureFlags where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineFeatureFlags::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pipeline::PipelineFeatureFlags where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::pipeline::PipelineFeatureFlags where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineFeatureFlags::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::pipeline::PipelineFeatureFlags::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::pipeline::PipelineFeatureFlags where U: core::convert::From<T>
pub fn vyre_driver::pipeline::PipelineFeatureFlags::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::pipeline::PipelineFeatureFlags where U: core::convert::Into<T>
pub type vyre_driver::pipeline::PipelineFeatureFlags::Error = core::convert::Infallible
pub fn vyre_driver::pipeline::PipelineFeatureFlags::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::pipeline::PipelineFeatureFlags where U: core::convert::TryFrom<T>
pub type vyre_driver::pipeline::PipelineFeatureFlags::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::pipeline::PipelineFeatureFlags::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::pipeline::PipelineFeatureFlags where T: core::clone::Clone
pub type vyre_driver::pipeline::PipelineFeatureFlags::Owned = T
pub fn vyre_driver::pipeline::PipelineFeatureFlags::clone_into(&self, target: &mut T)
pub fn vyre_driver::pipeline::PipelineFeatureFlags::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::pipeline::PipelineFeatureFlags where T: 'static + ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineFeatureFlags::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::pipeline::PipelineFeatureFlags where T: ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineFeatureFlags::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::pipeline::PipelineFeatureFlags where T: ?core::marker::Sized
pub fn vyre_driver::pipeline::PipelineFeatureFlags::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::pipeline::PipelineFeatureFlags where T: core::clone::Clone
pub unsafe fn vyre_driver::pipeline::PipelineFeatureFlags::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::pipeline::PipelineFeatureFlags
pub fn vyre_driver::pipeline::PipelineFeatureFlags::from(t: T) -> T
impl<T> serde_core::de::DeserializeOwned for vyre_driver::pipeline::PipelineFeatureFlags where T: for<'de> serde_core::de::Deserialize<'de>
impl<T> tracing::instrument::Instrument for vyre_driver::pipeline::PipelineFeatureFlags
impl<T> tracing::instrument::WithSubscriber for vyre_driver::pipeline::PipelineFeatureFlags
impl<T> typenum::type_operators::Same for vyre_driver::pipeline::PipelineFeatureFlags
pub type vyre_driver::pipeline::PipelineFeatureFlags::Output = T
pub struct vyre_driver::RoutingTable
impl vyre_driver::routing::RoutingTable
pub fn vyre_driver::routing::RoutingTable::distribution(&self, call_site: &str) -> core::option::Option<vyre_driver::routing::Distribution>
pub fn vyre_driver::routing::RoutingTable::observe_sort_u32(&self, call_site: alloc::borrow::Cow<'_, str>, values: &[u32]) -> core::result::Result<vyre_driver::routing::SortBackend, alloc::string::String>
impl core::default::Default for vyre_driver::routing::RoutingTable
pub fn vyre_driver::routing::RoutingTable::default() -> vyre_driver::routing::RoutingTable
impl core::fmt::Debug for vyre_driver::routing::RoutingTable
pub fn vyre_driver::routing::RoutingTable::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::routing::RoutingTable
impl core::marker::Send for vyre_driver::routing::RoutingTable
impl core::marker::Sync for vyre_driver::routing::RoutingTable
impl core::marker::Unpin for vyre_driver::routing::RoutingTable
impl !core::panic::unwind_safe::RefUnwindSafe for vyre_driver::routing::RoutingTable
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::routing::RoutingTable
impl<T, U> core::convert::Into<U> for vyre_driver::routing::RoutingTable where U: core::convert::From<T>
pub fn vyre_driver::routing::RoutingTable::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::routing::RoutingTable where U: core::convert::Into<T>
pub type vyre_driver::routing::RoutingTable::Error = core::convert::Infallible
pub fn vyre_driver::routing::RoutingTable::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::routing::RoutingTable where U: core::convert::TryFrom<T>
pub type vyre_driver::routing::RoutingTable::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::routing::RoutingTable::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> core::any::Any for vyre_driver::routing::RoutingTable where T: 'static + ?core::marker::Sized
pub fn vyre_driver::routing::RoutingTable::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::routing::RoutingTable where T: ?core::marker::Sized
pub fn vyre_driver::routing::RoutingTable::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::routing::RoutingTable where T: ?core::marker::Sized
pub fn vyre_driver::routing::RoutingTable::borrow_mut(&mut self) -> &mut T
impl<T> core::convert::From<T> for vyre_driver::routing::RoutingTable
pub fn vyre_driver::routing::RoutingTable::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::routing::RoutingTable
impl<T> tracing::instrument::WithSubscriber for vyre_driver::routing::RoutingTable
impl<T> typenum::type_operators::Same for vyre_driver::routing::RoutingTable
pub type vyre_driver::routing::RoutingTable::Output = T
pub struct vyre_driver::SpecCacheKey
pub vyre_driver::SpecCacheKey::binding_sig: u64
pub vyre_driver::SpecCacheKey::shader_hash: u64
pub vyre_driver::SpecCacheKey::spec_hash: u64
pub vyre_driver::SpecCacheKey::workgroup_size: [u32; 3]
impl vyre_driver::specialization::SpecCacheKey
pub fn vyre_driver::specialization::SpecCacheKey::new(shader_hash: u64, binding_sig: u64, workgroup_size: [u32; 3], specs: &vyre_driver::specialization::SpecMap) -> Self
impl core::clone::Clone for vyre_driver::specialization::SpecCacheKey
pub fn vyre_driver::specialization::SpecCacheKey::clone(&self) -> vyre_driver::specialization::SpecCacheKey
impl core::cmp::Eq for vyre_driver::specialization::SpecCacheKey
impl core::cmp::PartialEq for vyre_driver::specialization::SpecCacheKey
pub fn vyre_driver::specialization::SpecCacheKey::eq(&self, other: &vyre_driver::specialization::SpecCacheKey) -> bool
impl core::fmt::Debug for vyre_driver::specialization::SpecCacheKey
pub fn vyre_driver::specialization::SpecCacheKey::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::hash::Hash for vyre_driver::specialization::SpecCacheKey
pub fn vyre_driver::specialization::SpecCacheKey::hash<__H: core::hash::Hasher>(&self, state: &mut __H)
impl core::marker::StructuralPartialEq for vyre_driver::specialization::SpecCacheKey
impl core::marker::Freeze for vyre_driver::specialization::SpecCacheKey
impl core::marker::Send for vyre_driver::specialization::SpecCacheKey
impl core::marker::Sync for vyre_driver::specialization::SpecCacheKey
impl core::marker::Unpin for vyre_driver::specialization::SpecCacheKey
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::specialization::SpecCacheKey
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::specialization::SpecCacheKey
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::specialization::SpecCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::specialization::SpecCacheKey::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::specialization::SpecCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::specialization::SpecCacheKey where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::specialization::SpecCacheKey::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::specialization::SpecCacheKey::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::specialization::SpecCacheKey where U: core::convert::From<T>
pub fn vyre_driver::specialization::SpecCacheKey::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::specialization::SpecCacheKey where U: core::convert::Into<T>
pub type vyre_driver::specialization::SpecCacheKey::Error = core::convert::Infallible
pub fn vyre_driver::specialization::SpecCacheKey::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::specialization::SpecCacheKey where U: core::convert::TryFrom<T>
pub type vyre_driver::specialization::SpecCacheKey::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::specialization::SpecCacheKey::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::specialization::SpecCacheKey where T: core::clone::Clone
pub type vyre_driver::specialization::SpecCacheKey::Owned = T
pub fn vyre_driver::specialization::SpecCacheKey::clone_into(&self, target: &mut T)
pub fn vyre_driver::specialization::SpecCacheKey::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::specialization::SpecCacheKey where T: 'static + ?core::marker::Sized
pub fn vyre_driver::specialization::SpecCacheKey::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::specialization::SpecCacheKey where T: ?core::marker::Sized
pub fn vyre_driver::specialization::SpecCacheKey::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::specialization::SpecCacheKey where T: ?core::marker::Sized
pub fn vyre_driver::specialization::SpecCacheKey::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::specialization::SpecCacheKey where T: core::clone::Clone
pub unsafe fn vyre_driver::specialization::SpecCacheKey::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::specialization::SpecCacheKey
pub fn vyre_driver::specialization::SpecCacheKey::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::specialization::SpecCacheKey
impl<T> tracing::instrument::WithSubscriber for vyre_driver::specialization::SpecCacheKey
impl<T> typenum::type_operators::Same for vyre_driver::specialization::SpecCacheKey
pub type vyre_driver::specialization::SpecCacheKey::Output = T
pub struct vyre_driver::SpecMap
impl vyre_driver::specialization::SpecMap
pub fn vyre_driver::specialization::SpecMap::cache_hash(&self) -> u64
pub fn vyre_driver::specialization::SpecMap::insert(&mut self, name: impl core::convert::Into<alloc::string::String>, value: vyre_driver::specialization::SpecValue)
pub fn vyre_driver::specialization::SpecMap::is_empty(&self) -> bool
pub fn vyre_driver::specialization::SpecMap::iter(&self) -> impl core::iter::traits::iterator::Iterator<Item = (&str, vyre_driver::specialization::SpecValue)>
pub fn vyre_driver::specialization::SpecMap::len(&self) -> usize
pub fn vyre_driver::specialization::SpecMap::new() -> Self
pub fn vyre_driver::specialization::SpecMap::to_numeric_constants(&self) -> std::collections::hash::map::HashMap<alloc::string::String, f64>
impl core::clone::Clone for vyre_driver::specialization::SpecMap
pub fn vyre_driver::specialization::SpecMap::clone(&self) -> vyre_driver::specialization::SpecMap
impl core::default::Default for vyre_driver::specialization::SpecMap
pub fn vyre_driver::specialization::SpecMap::default() -> vyre_driver::specialization::SpecMap
impl core::fmt::Debug for vyre_driver::specialization::SpecMap
pub fn vyre_driver::specialization::SpecMap::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Freeze for vyre_driver::specialization::SpecMap
impl core::marker::Send for vyre_driver::specialization::SpecMap
impl core::marker::Sync for vyre_driver::specialization::SpecMap
impl core::marker::Unpin for vyre_driver::specialization::SpecMap
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::specialization::SpecMap
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::specialization::SpecMap
impl<T, U> core::convert::Into<U> for vyre_driver::specialization::SpecMap where U: core::convert::From<T>
pub fn vyre_driver::specialization::SpecMap::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::specialization::SpecMap where U: core::convert::Into<T>
pub type vyre_driver::specialization::SpecMap::Error = core::convert::Infallible
pub fn vyre_driver::specialization::SpecMap::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::specialization::SpecMap where U: core::convert::TryFrom<T>
pub type vyre_driver::specialization::SpecMap::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::specialization::SpecMap::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::specialization::SpecMap where T: core::clone::Clone
pub type vyre_driver::specialization::SpecMap::Owned = T
pub fn vyre_driver::specialization::SpecMap::clone_into(&self, target: &mut T)
pub fn vyre_driver::specialization::SpecMap::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::specialization::SpecMap where T: 'static + ?core::marker::Sized
pub fn vyre_driver::specialization::SpecMap::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::specialization::SpecMap where T: ?core::marker::Sized
pub fn vyre_driver::specialization::SpecMap::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::specialization::SpecMap where T: ?core::marker::Sized
pub fn vyre_driver::specialization::SpecMap::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::specialization::SpecMap where T: core::clone::Clone
pub unsafe fn vyre_driver::specialization::SpecMap::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::specialization::SpecMap
pub fn vyre_driver::specialization::SpecMap::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::specialization::SpecMap
impl<T> tracing::instrument::WithSubscriber for vyre_driver::specialization::SpecMap
impl<T> typenum::type_operators::Same for vyre_driver::specialization::SpecMap
pub type vyre_driver::specialization::SpecMap::Output = T
pub struct vyre_driver::SubgroupCaps
pub vyre_driver::SubgroupCaps::subgroup_size: u32
pub vyre_driver::SubgroupCaps::supports_subgroup: bool
pub vyre_driver::SubgroupCaps::supports_subgroup_vertex: bool
impl vyre_driver::subgroup::SubgroupCaps
pub const fn vyre_driver::subgroup::SubgroupCaps::native(subgroup_size: u32) -> Self
impl core::clone::Clone for vyre_driver::subgroup::SubgroupCaps
pub fn vyre_driver::subgroup::SubgroupCaps::clone(&self) -> vyre_driver::subgroup::SubgroupCaps
impl core::cmp::Eq for vyre_driver::subgroup::SubgroupCaps
impl core::cmp::PartialEq for vyre_driver::subgroup::SubgroupCaps
pub fn vyre_driver::subgroup::SubgroupCaps::eq(&self, other: &vyre_driver::subgroup::SubgroupCaps) -> bool
impl core::default::Default for vyre_driver::subgroup::SubgroupCaps
pub fn vyre_driver::subgroup::SubgroupCaps::default() -> vyre_driver::subgroup::SubgroupCaps
impl core::fmt::Debug for vyre_driver::subgroup::SubgroupCaps
pub fn vyre_driver::subgroup::SubgroupCaps::fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
impl core::marker::Copy for vyre_driver::subgroup::SubgroupCaps
impl core::marker::StructuralPartialEq for vyre_driver::subgroup::SubgroupCaps
impl core::marker::Freeze for vyre_driver::subgroup::SubgroupCaps
impl core::marker::Send for vyre_driver::subgroup::SubgroupCaps
impl core::marker::Sync for vyre_driver::subgroup::SubgroupCaps
impl core::marker::Unpin for vyre_driver::subgroup::SubgroupCaps
impl core::panic::unwind_safe::RefUnwindSafe for vyre_driver::subgroup::SubgroupCaps
impl core::panic::unwind_safe::UnwindSafe for vyre_driver::subgroup::SubgroupCaps
impl<Q, K> equivalent::Equivalent<K> for vyre_driver::subgroup::SubgroupCaps where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupCaps::equivalent(&self, key: &K) -> bool
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::subgroup::SubgroupCaps where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
impl<Q, K> hashbrown::Equivalent<K> for vyre_driver::subgroup::SubgroupCaps where Q: core::cmp::Eq + ?core::marker::Sized, K: core::borrow::Borrow<Q> + ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupCaps::equivalent(&self, key: &K) -> bool
pub fn vyre_driver::subgroup::SubgroupCaps::equivalent(&self, key: &K) -> bool
impl<T, U> core::convert::Into<U> for vyre_driver::subgroup::SubgroupCaps where U: core::convert::From<T>
pub fn vyre_driver::subgroup::SubgroupCaps::into(self) -> U
impl<T, U> core::convert::TryFrom<U> for vyre_driver::subgroup::SubgroupCaps where U: core::convert::Into<T>
pub type vyre_driver::subgroup::SubgroupCaps::Error = core::convert::Infallible
pub fn vyre_driver::subgroup::SubgroupCaps::try_from(value: U) -> core::result::Result<T, <T as core::convert::TryFrom<U>>::Error>
impl<T, U> core::convert::TryInto<U> for vyre_driver::subgroup::SubgroupCaps where U: core::convert::TryFrom<T>
pub type vyre_driver::subgroup::SubgroupCaps::Error = <U as core::convert::TryFrom<T>>::Error
pub fn vyre_driver::subgroup::SubgroupCaps::try_into(self) -> core::result::Result<U, <U as core::convert::TryFrom<T>>::Error>
impl<T> alloc::borrow::ToOwned for vyre_driver::subgroup::SubgroupCaps where T: core::clone::Clone
pub type vyre_driver::subgroup::SubgroupCaps::Owned = T
pub fn vyre_driver::subgroup::SubgroupCaps::clone_into(&self, target: &mut T)
pub fn vyre_driver::subgroup::SubgroupCaps::to_owned(&self) -> T
impl<T> core::any::Any for vyre_driver::subgroup::SubgroupCaps where T: 'static + ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupCaps::type_id(&self) -> core::any::TypeId
impl<T> core::borrow::Borrow<T> for vyre_driver::subgroup::SubgroupCaps where T: ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupCaps::borrow(&self) -> &T
impl<T> core::borrow::BorrowMut<T> for vyre_driver::subgroup::SubgroupCaps where T: ?core::marker::Sized
pub fn vyre_driver::subgroup::SubgroupCaps::borrow_mut(&mut self) -> &mut T
impl<T> core::clone::CloneToUninit for vyre_driver::subgroup::SubgroupCaps where T: core::clone::Clone
pub unsafe fn vyre_driver::subgroup::SubgroupCaps::clone_to_uninit(&self, dest: *mut u8)
impl<T> core::convert::From<T> for vyre_driver::subgroup::SubgroupCaps
pub fn vyre_driver::subgroup::SubgroupCaps::from(t: T) -> T
impl<T> tracing::instrument::Instrument for vyre_driver::subgroup::SubgroupCaps
impl<T> tracing::instrument::WithSubscriber for vyre_driver::subgroup::SubgroupCaps
impl<T> typenum::type_operators::Same for vyre_driver::subgroup::SubgroupCaps
pub type vyre_driver::subgroup::SubgroupCaps::Output = T
pub const vyre_driver::CURRENT_PIPELINE_CACHE_KEY_VERSION: u32
pub trait vyre_driver::CompiledPipeline: private::Sealed + core::marker::Send + core::marker::Sync
pub fn vyre_driver::CompiledPipeline::dispatch(&self, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::BackendError>
pub fn vyre_driver::CompiledPipeline::dispatch_borrowed(&self, inputs: &[&[u8]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::BackendError>
pub fn vyre_driver::CompiledPipeline::dispatch_borrowed_into(&self, inputs: &[&[u8]], config: &vyre_driver::DispatchConfig, outputs: &mut vyre_driver::OutputBuffers) -> core::result::Result<(), vyre_driver::BackendError>
pub fn vyre_driver::CompiledPipeline::dispatch_persistent_handles(&self, _inputs: &[vyre_driver::Resource], _config: &vyre_driver::DispatchConfig) -> core::result::Result<vyre_driver::OutputBuffers, vyre_driver::BackendError>
pub fn vyre_driver::CompiledPipeline::id(&self) -> &str
pub trait vyre_driver::EnforceGate: vyre_driver::registry::enforce::private::Sealed + core::marker::Send + core::marker::Sync
pub fn vyre_driver::EnforceGate::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::core::Program) -> vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::EnforceGate::name(&self) -> &'static str
impl<A: vyre_driver::registry::enforce::EnforceGate, B: vyre_driver::registry::enforce::EnforceGate> vyre_driver::registry::enforce::EnforceGate for vyre_driver::registry::enforce::Chain<A, B>
pub fn vyre_driver::registry::enforce::Chain<A, B>::evaluate(&self, program: &vyre_foundation::ir_inner::model::program::core::Program) -> vyre_driver::registry::enforce::EnforceVerdict
pub fn vyre_driver::registry::enforce::Chain<A, B>::name(&self) -> &'static str
pub trait vyre_driver::Executable: vyre_driver::backend::Backend
pub fn vyre_driver::Executable::dispatch(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[vyre_driver::MemoryRef<'_>], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<vyre_driver::Memory>, vyre_driver::BackendError>
pub trait vyre_driver::PendingDispatch: private::Sealed + core::marker::Send + core::marker::Sync
pub fn vyre_driver::PendingDispatch::await_result(self: alloc::boxed::Box<Self>) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::BackendError>
pub fn vyre_driver::PendingDispatch::is_ready(&self) -> bool
pub trait vyre_driver::TypedDispatchExt: vyre_driver::VyreBackend
pub fn vyre_driver::TypedDispatchExt::dispatch_bytes(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[u8]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::BackendError>
pub fn vyre_driver::TypedDispatchExt::dispatch_f32(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[f32]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<f32>>, vyre_driver::BackendError>
pub fn vyre_driver::TypedDispatchExt::dispatch_pod<T: bytemuck::pod::Pod>(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[T]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<T>>, vyre_driver::BackendError>
pub fn vyre_driver::TypedDispatchExt::dispatch_u32(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[u32]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u32>>, vyre_driver::BackendError>
impl<T: vyre_driver::VyreBackend + ?core::marker::Sized> vyre_driver::TypedDispatchExt for T
pub fn T::dispatch_bytes(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[u8]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::BackendError>
pub fn T::dispatch_f32(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[f32]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<f32>>, vyre_driver::BackendError>
pub fn T::dispatch_pod<T: bytemuck::pod::Pod>(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[T]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<T>>, vyre_driver::BackendError>
pub fn T::dispatch_u32(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[u32]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u32>>, vyre_driver::BackendError>
pub trait vyre_driver::VyreBackend: private::Sealed + core::marker::Send + core::marker::Sync
pub fn vyre_driver::VyreBackend::compile_native(&self, _program: &vyre_foundation::ir_inner::model::program::core::Program, _config: &vyre_driver::DispatchConfig) -> core::result::Result<core::option::Option<alloc::sync::Arc<dyn vyre_driver::CompiledPipeline>>, vyre_driver::BackendError>
pub fn vyre_driver::VyreBackend::device_lost(&self) -> bool
pub fn vyre_driver::VyreBackend::dispatch(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::BackendError>
pub fn vyre_driver::VyreBackend::dispatch_async(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[alloc::vec::Vec<u8>], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::boxed::Box<dyn vyre_driver::PendingDispatch>, vyre_driver::BackendError>
pub fn vyre_driver::VyreBackend::dispatch_borrowed(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[u8]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, vyre_driver::BackendError>
pub fn vyre_driver::VyreBackend::dispatch_borrowed_async(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[u8]], config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::boxed::Box<dyn vyre_driver::PendingDispatch>, vyre_driver::BackendError>
pub fn vyre_driver::VyreBackend::dispatch_borrowed_into(&self, program: &vyre_foundation::ir_inner::model::program::core::Program, inputs: &[&[u8]], config: &vyre_driver::DispatchConfig, outputs: &mut vyre_driver::OutputBuffers) -> core::result::Result<(), vyre_driver::BackendError>
pub fn vyre_driver::VyreBackend::flush(&self) -> core::result::Result<(), vyre_driver::BackendError>
pub fn vyre_driver::VyreBackend::id(&self) -> &'static str
pub fn vyre_driver::VyreBackend::is_distributed(&self) -> bool
pub fn vyre_driver::VyreBackend::max_compute_invocations_per_workgroup(&self) -> u32
pub fn vyre_driver::VyreBackend::max_compute_workgroups_per_dimension(&self) -> u32
pub fn vyre_driver::VyreBackend::max_storage_buffer_bytes(&self) -> u64
pub fn vyre_driver::VyreBackend::max_workgroup_size(&self) -> [u32; 3]
pub fn vyre_driver::VyreBackend::prepare(&self) -> core::result::Result<(), vyre_driver::BackendError>
pub fn vyre_driver::VyreBackend::shutdown(&self) -> core::result::Result<(), vyre_driver::BackendError>
pub fn vyre_driver::VyreBackend::subgroup_size(&self) -> core::option::Option<u32>
pub fn vyre_driver::VyreBackend::supported_ops(&self) -> &std::collections::hash::set::HashSet<vyre_foundation::ir_inner::model::node_kind::OpId>
pub fn vyre_driver::VyreBackend::supports_async_compute(&self) -> bool
pub fn vyre_driver::VyreBackend::supports_bf16(&self) -> bool
pub fn vyre_driver::VyreBackend::supports_f16(&self) -> bool
pub fn vyre_driver::VyreBackend::supports_indirect_dispatch(&self) -> bool
pub fn vyre_driver::VyreBackend::supports_persistent_thread_dispatch(&self) -> bool
pub fn vyre_driver::VyreBackend::supports_speculation(&self) -> bool
pub fn vyre_driver::VyreBackend::supports_subgroup_ops(&self) -> bool
pub fn vyre_driver::VyreBackend::supports_tensor_cores(&self) -> bool
pub fn vyre_driver::VyreBackend::try_recover(&self) -> core::result::Result<(), vyre_driver::BackendError>
pub fn vyre_driver::VyreBackend::version(&self) -> &'static str
pub fn vyre_driver::compile(backend: alloc::sync::Arc<dyn vyre_driver::VyreBackend>, program: &vyre_foundation::ir_inner::model::program::core::Program, config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::sync::Arc<dyn vyre_driver::CompiledPipeline>, vyre_driver::BackendError>
pub fn vyre_driver::compile_shared(backend: alloc::sync::Arc<dyn vyre_driver::VyreBackend>, program: alloc::sync::Arc<vyre_foundation::ir_inner::model::program::core::Program>, config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::sync::Arc<dyn vyre_driver::CompiledPipeline>, vyre_driver::BackendError>
pub fn vyre_driver::default_validator() -> bool
pub fn vyre_driver::dispatch_element_count(bindings: &[vyre_driver::binding::Binding]) -> u32
pub fn vyre_driver::dispatch_param_words(bindings: &[vyre_driver::binding::Binding], element_count: u32) -> alloc::vec::Vec<u32>
pub fn vyre_driver::element_size_bytes(data_type: &vyre_spec::data_type::DataType) -> core::result::Result<usize, vyre_driver::BackendError>
pub fn vyre_driver::emit_aot_target(target: &str, program: &vyre_foundation::ir_inner::model::program::core::Program, config: &vyre_driver::DispatchConfig) -> core::result::Result<alloc::vec::Vec<u8>, vyre_driver::BackendError>
pub fn vyre_driver::enforce_actual_output_budget(config: &vyre_driver::DispatchConfig, outputs: &[alloc::vec::Vec<u8>]) -> core::result::Result<(), vyre_driver::BackendError>
pub fn vyre_driver::find_indirect_dispatch(program: &vyre_foundation::ir_inner::model::program::core::Program) -> core::result::Result<core::option::Option<vyre_driver::program_walks::IndirectDispatch>, vyre_driver::BackendError>
pub fn vyre_driver::output_binding_layout(output: &vyre_foundation::ir_inner::model::program::buffer_decl::BufferDecl) -> core::result::Result<vyre_driver::program_walks::OutputBindingLayout, vyre_driver::BackendError>
pub fn vyre_driver::output_binding_layouts(program: &vyre_foundation::ir_inner::model::program::core::Program) -> core::result::Result<alloc::vec::Vec<vyre_driver::program_walks::OutputBindingLayout>, vyre_driver::BackendError>
pub fn vyre_driver::output_layout_from_program(program: &vyre_foundation::ir_inner::model::program::core::Program) -> core::result::Result<vyre_driver::program_walks::OutputLayout, vyre_driver::BackendError>
pub fn vyre_driver::registered_aot_emitters() -> alloc::vec::Vec<&'static vyre_driver::aot::AotEmitter>
pub fn vyre_driver::select_sort_backend(distribution: vyre_driver::routing::Distribution) -> vyre_driver::routing::SortBackend
pub type vyre_driver::AotTargetId = &'static str
pub type vyre_driver::Memory = alloc::vec::Vec<u8>
pub type vyre_driver::MemoryRef<'a> = &'a [u8]
pub type vyre_driver::OutputBuffers = alloc::vec::Vec<alloc::vec::Vec<u8>>
