//! GPU device abstraction and initialization.

pub use device::EnabledFeatures;
pub use device::{acquire_gpu, cached_device, init_device};
pub use selector::{
    acquire_gpu_for_adapter, adapter_index_from_env, enumerate_adapters, init_device_for_adapter,
    select_adapter, AdapterCriteria,
};

mod device;
mod selector;

/// Backwards-compatible cached device path.
pub mod cached_device {
    pub use super::device::{cached_adapter_info, cached_device};
}

/// Backwards-compatible initialization path.
pub mod init_device {
    pub use super::device::init_device;
}
