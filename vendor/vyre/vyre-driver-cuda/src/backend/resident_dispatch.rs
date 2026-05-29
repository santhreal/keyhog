//! CUDA dispatch path for long-lived resident buffers.

#[path = "resident_dispatch/helpers.rs"]
mod helpers;
#[path = "resident_dispatch/borrowed.rs"]
mod borrowed;
#[path = "resident_dispatch/async_dispatch.rs"]
mod async_dispatch;
#[path = "resident_dispatch/batch.rs"]
mod batch;
#[path = "resident_dispatch/sync.rs"]
mod sync;
#[path = "resident_dispatch/sequence_api.rs"]
mod sequence_api;
#[path = "resident_dispatch/sequence_fused.rs"]
mod sequence_fused;
#[path = "resident_dispatch/timed.rs"]
mod timed;

#[cfg(test)]
#[path = "resident_dispatch/tests.rs"]
mod tests;

pub(crate) use crate::backend::resident_dispatch_support::CudaResidentDispatch;
