//! GPU device abstraction and initialization.

pub(crate) use device::pop_error_scope_now;
pub use device::EnabledFeatures;
pub use device::{acquire_gpu, cached_adapter_info, cached_device, init_device};
pub use selector::{
    acquire_gpu_for_adapter, adapter_index_from_env, enumerate_adapters, init_device_for_adapter,
    select_adapter, AdapterCriteria,
};
pub(crate) use selector::{init_device_for_adapter_identity, AdapterIdentity};

mod device;
mod selector;
