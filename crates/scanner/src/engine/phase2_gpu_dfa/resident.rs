//! Catalog-owned resident Vyrë execution for phase-two regex-DFA admission.

use std::sync::Arc;
use vyre::backend::Resource;
use vyre::VyreBackend;

mod catalog;
mod shard;

#[cfg(test)]
pub(super) use catalog::resident_capacity_for_test;
pub(super) use catalog::Phase2GpuDfaCatalogResident;

pub(super) const U32_BYTES: usize = std::mem::size_of::<u32>();
pub(super) const SHARED_BINDINGS: usize = 4;
pub(super) const SHARD_BINDINGS: usize = 4;

pub(super) fn allocate(
    resources: &mut Vec<Resource>,
    backend: &Arc<dyn VyreBackend>,
    byte_len: usize,
    upload: Option<&[u8]>,
) -> Result<(), String> {
    let resource = backend
        .allocate_resident(byte_len)
        .map_err(|error| error.to_string())?;
    if let Some(bytes) = upload {
        if let Err(error) = backend.upload_resident(&resource, bytes) {
            let upload_error = error.to_string();
            return match backend.free_resident(resource) {
                Ok(()) => Err(upload_error),
                Err(cleanup) => Err(format!(
                    "{upload_error}; failed to free the rejected resident allocation: {cleanup}"
                )),
            };
        }
    }
    resources.push(resource);
    Ok(())
}

pub(super) fn free_resources(
    backend: &dyn VyreBackend,
    resources: Vec<Resource>,
) -> Result<(), String> {
    let mut first_error = None;
    for resource in resources {
        if let Err(error) = backend.free_resident(resource) {
            first_error.get_or_insert_with(|| error.to_string());
        }
    }
    first_error.map_or(Ok(()), Err)
}
