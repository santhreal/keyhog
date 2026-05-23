//! GPU device abstraction and initialization.

pub(crate) use device::pop_error_scope_now;
pub use device::EnabledFeatures;
pub use device::{acquire_gpu, cached_adapter_info, cached_device, init_device};
pub use selector::{
    acquire_gpu_for_adapter, adapter_for_info, adapter_index_from_env, adapter_probe_report,
    enumerate_adapters, has_real_gpu_adapter, init_device_for_adapter, select_adapter,
    AdapterCriteria, AdapterProbeReport,
};
pub(crate) use selector::{init_device_for_adapter_identity, AdapterIdentity};

mod device;
mod selector;
