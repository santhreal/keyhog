//! Host mirrors for megakernel GPU-resident runtime buffers.

use super::execution::{Megakernel, MegakernelDispatchStats};
use super::io;
use super::protocol;
use super::protocol_api::{validate_control_bytes, validate_debug_log_bytes};
use super::readback::MegakernelReadback;
use super::scheduler::write_default_priority_offsets;
use crate::PipelineError;

/// Host-side mirror of the four buffers kept resident by the persistent
/// megakernel runtime: control, ring, debug log, and IO queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MegakernelResidentBuffers {
    control_bytes: Vec<u8>,
    ring_bytes: Vec<u8>,
    debug_log_bytes: Vec<u8>,
    io_queue_bytes: Vec<u8>,
    slot_count: u32,
}

impl MegakernelResidentBuffers {
    /// Allocate a fresh host mirror for a megakernel's resident buffers.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when any runtime buffer size overflows.
    pub fn new(
        slot_count: u32,
        tenant_count: u32,
        observable_slots: u32,
    ) -> Result<Self, PipelineError> {
        let control_capacity = protocol::control_byte_len(observable_slots).ok_or_else(|| {
            PipelineError::Backend(
                "megakernel resident control byte length overflowed usize. Fix: shard observable resident buffers before allocation."
                    .to_string(),
            )
        })?;
        let ring_capacity = protocol::ring_byte_len(slot_count).ok_or_else(|| {
            PipelineError::Backend(
                "megakernel resident ring byte length overflowed usize. Fix: shard resident rings before allocation."
                    .to_string(),
            )
        })?;
        let debug_log_capacity =
            protocol::debug_log_byte_len(protocol::debug::RECORD_CAPACITY).ok_or_else(|| {
                PipelineError::Backend(
                    "megakernel resident debug-log byte length overflowed usize. Fix: reduce debug record capacity before allocation."
                        .to_string(),
                )
            })?;
        let io_queue_capacity = io::empty_io_queue_byte_len(io::IO_SLOT_COUNT)?;
        let mut buffers = Self {
            control_bytes: Vec::with_capacity(control_capacity),
            ring_bytes: Vec::with_capacity(ring_capacity),
            debug_log_bytes: Vec::with_capacity(debug_log_capacity),
            io_queue_bytes: Vec::with_capacity(io_queue_capacity),
            slot_count,
        };
        buffers.reset(tenant_count, observable_slots)?;
        Ok(buffers)
    }

    /// Reinitialize this host mirror in place for the same resident geometry.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when any runtime buffer size overflows.
    pub fn reset(&mut self, tenant_count: u32, observable_slots: u32) -> Result<(), PipelineError> {
        Megakernel::try_encode_control_into(
            false,
            tenant_count,
            observable_slots,
            &mut self.control_bytes,
        )?;
        write_default_priority_offsets(&mut self.control_bytes, self.slot_count)?;
        Megakernel::try_encode_empty_ring_into(self.slot_count, &mut self.ring_bytes)?;
        Megakernel::try_encode_empty_debug_log_into(
            protocol::debug::RECORD_CAPACITY,
            &mut self.debug_log_bytes,
        )?;
        io::try_encode_empty_io_queue_into(io::IO_SLOT_COUNT, &mut self.io_queue_bytes)?;
        Ok(())
    }

    /// Build a resident-buffer mirror from caller-owned byte buffers.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when any buffer violates the megakernel ABI.
    pub fn from_parts(
        slot_count: u32,
        control_bytes: Vec<u8>,
        ring_bytes: Vec<u8>,
        debug_log_bytes: Vec<u8>,
        io_queue_bytes: Vec<u8>,
    ) -> Result<Self, PipelineError> {
        validate_control_bytes(&control_bytes)?;
        validate_debug_log_bytes(&debug_log_bytes)?;
        io::validate_io_queue_bytes(&io_queue_bytes)?;
        let expected_ring_bytes = protocol::ring_byte_len(slot_count).ok_or_else(|| {
            PipelineError::Backend(
                "megakernel resident ring byte length overflowed usize. Fix: shard resident rings before allocation."
                    .to_string(),
            )
        })?;
        if ring_bytes.len() != expected_ring_bytes {
            return Err(PipelineError::Backend(format!(
                "megakernel resident ring has {} bytes, expected {expected_ring_bytes}. Fix: build resident rings with the same slot_count as the Megakernel handle.",
                ring_bytes.len()
            )));
        }
        Ok(Self {
            control_bytes,
            ring_bytes,
            debug_log_bytes,
            io_queue_bytes,
            slot_count,
        })
    }

    /// Publish one work slot into the resident ring mirror.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::QueueFull`] when the slot is out of bounds or
    /// still in flight.
    pub fn publish_slot(
        &mut self,
        slot_idx: u32,
        tenant_id: u32,
        opcode: u32,
        args: &[u32],
    ) -> Result<(), PipelineError> {
        Megakernel::publish_slot(&mut self.ring_bytes, slot_idx, tenant_id, opcode, args)
    }

    /// Apply a strict dispatch readback to the resident host mirror.
    pub fn apply_readback(&mut self, readback: MegakernelReadback) {
        self.control_bytes = readback.control_bytes;
        self.ring_bytes = readback.ring_bytes;
        self.debug_log_bytes = readback.debug_log_bytes;
        self.io_queue_bytes = readback.io_queue_bytes;
    }

    /// Dispatch these buffers through `megakernel`, then update the mirror.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when dispatch or readback validation fails.
    pub fn dispatch(
        &mut self,
        megakernel: &Megakernel,
    ) -> Result<MegakernelReadback, PipelineError> {
        self.dispatch_update(megakernel)?;
        Ok(self.snapshot_readback())
    }

    /// Dispatch these buffers through `megakernel` and update this mirror in
    /// place without cloning the readback into a second owned copy.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when dispatch or readback validation fails.
    pub fn dispatch_update(&mut self, megakernel: &Megakernel) -> Result<(), PipelineError> {
        self.dispatch_update_observed(megakernel)?;
        Ok(())
    }

    /// Dispatch these buffers through `megakernel`, update this mirror in
    /// place, and return dispatch instrumentation without cloning a snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when dispatch or readback validation fails.
    pub fn dispatch_update_observed(
        &mut self,
        megakernel: &Megakernel,
    ) -> Result<MegakernelDispatchStats, PipelineError> {
        if megakernel.slot_count() != self.slot_count {
            return Err(PipelineError::Backend(format!(
                "resident buffer slot_count {} does not match megakernel slot_count {}. Fix: allocate resident buffers from the same Megakernel geometry.",
                self.slot_count,
                megakernel.slot_count()
            )));
        }
        let (readback, stats) = megakernel.dispatch_with_io_queue_readback_borrowed_observed(
            &self.control_bytes,
            &self.ring_bytes,
            &self.debug_log_bytes,
            &self.io_queue_bytes,
        )?;
        self.apply_readback(readback);
        Ok(stats)
    }

    /// Clone the current host mirror into a strict readback record.
    #[must_use]
    pub fn snapshot_readback(&self) -> MegakernelReadback {
        MegakernelReadback {
            control_bytes: self.control_bytes.clone(),
            ring_bytes: self.ring_bytes.clone(),
            debug_log_bytes: self.debug_log_bytes.clone(),
            io_queue_bytes: self.io_queue_bytes.clone(),
        }
    }

    /// Clone the current host mirror into caller-owned readback storage.
    pub fn snapshot_readback_into(&self, out: &mut MegakernelReadback) {
        out.control_bytes.clone_from(&self.control_bytes);
        out.ring_bytes.clone_from(&self.ring_bytes);
        out.debug_log_bytes.clone_from(&self.debug_log_bytes);
        out.io_queue_bytes.clone_from(&self.io_queue_bytes);
    }

    /// Control-buffer mirror bytes.
    #[must_use]
    pub fn control_bytes(&self) -> &[u8] {
        &self.control_bytes
    }

    /// Ring-buffer mirror bytes.
    #[must_use]
    pub fn ring_bytes(&self) -> &[u8] {
        &self.ring_bytes
    }

    /// Mutable ring-buffer mirror bytes.
    #[must_use]
    pub fn ring_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.ring_bytes
    }

    /// Debug-log mirror bytes.
    #[must_use]
    pub fn debug_log_bytes(&self) -> &[u8] {
        &self.debug_log_bytes
    }

    /// IO-queue mirror bytes.
    #[must_use]
    pub fn io_queue_bytes(&self) -> &[u8] {
        &self.io_queue_bytes
    }

    /// Resident ring slot count.
    #[must_use]
    pub const fn slot_count(&self) -> u32 {
        self.slot_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::megakernel::protocol::opcode;

    #[test]
    fn resident_buffers_keep_runtime_abi_separate_from_publish_logic() {
        let mut buffers = MegakernelResidentBuffers::new(4, 2, 8).unwrap();
        buffers
            .publish_slot(2, 1, opcode::STORE_U32, &[7, 9])
            .unwrap();
        assert_eq!(buffers.slot_count(), 4);
        assert_eq!(
            buffers.ring_bytes().len(),
            protocol::ring_byte_len(4).unwrap()
        );
    }

    #[test]
    fn resident_buffers_seed_priority_offsets_for_priority_scheduler() {
        let buffers = MegakernelResidentBuffers::new(10, 2, 0).unwrap();
        let read = |word: u32| {
            let start = word as usize * 4;
            u32::from_le_bytes(
                buffers.control_bytes()[start..start + 4]
                    .try_into()
                    .unwrap(),
            )
        };
        assert_eq!(read(protocol::control::PRIORITY_OFFSETS_BASE), 0);
        assert_eq!(
            read(
                protocol::control::PRIORITY_OFFSETS_BASE + super::super::scheduler::PRIORITY_LEVELS
            ),
            10
        );
    }

    #[test]
    fn resident_buffers_reset_reuses_encoded_storage() {
        let mut buffers = MegakernelResidentBuffers::new(8, 2, 4).unwrap();
        let control_ptr = buffers.control_bytes.as_ptr();
        let ring_ptr = buffers.ring_bytes.as_ptr();
        let debug_ptr = buffers.debug_log_bytes.as_ptr();
        let io_ptr = buffers.io_queue_bytes.as_ptr();

        buffers.reset(2, 4).unwrap();

        assert_eq!(buffers.control_bytes.as_ptr(), control_ptr);
        assert_eq!(buffers.ring_bytes.as_ptr(), ring_ptr);
        assert_eq!(buffers.debug_log_bytes.as_ptr(), debug_ptr);
        assert_eq!(buffers.io_queue_bytes.as_ptr(), io_ptr);
        assert!(buffers.ring_bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn resident_buffers_preallocate_exact_runtime_buffer_capacities() {
        let buffers = MegakernelResidentBuffers::new(8, 2, 4).unwrap();
        assert_eq!(
            buffers.control_bytes.capacity(),
            buffers.control_bytes.len()
        );
        assert_eq!(buffers.ring_bytes.capacity(), buffers.ring_bytes.len());
        assert_eq!(
            buffers.debug_log_bytes.capacity(),
            buffers.debug_log_bytes.len()
        );
        assert_eq!(
            buffers.io_queue_bytes.capacity(),
            buffers.io_queue_bytes.len()
        );
    }

    #[test]
    fn resident_buffers_reject_mismatched_ring_shape() {
        let control = Megakernel::try_encode_control(false, 1, 0).unwrap();
        let ring = Megakernel::try_encode_empty_ring(2).unwrap();
        let debug =
            Megakernel::try_encode_empty_debug_log(protocol::debug::RECORD_CAPACITY).unwrap();
        let io = io::try_encode_empty_io_queue(io::IO_SLOT_COUNT).unwrap();
        let error = MegakernelResidentBuffers::from_parts(4, control, ring, debug, io)
            .expect_err("resident ring shape must match declared slot count");
        assert!(error.to_string().contains("resident ring"));
    }

    #[test]
    fn snapshot_readback_into_reuses_buffers() {
        let buffers = MegakernelResidentBuffers::new(4, 2, 8).unwrap();
        let mut readback = buffers.snapshot_readback();
        let control_capacity = readback.control_bytes.capacity();
        let ring_capacity = readback.ring_bytes.capacity();
        let debug_capacity = readback.debug_log_bytes.capacity();
        let io_capacity = readback.io_queue_bytes.capacity();

        buffers.snapshot_readback_into(&mut readback);
        assert_eq!(readback.control_bytes.capacity(), control_capacity);
        assert_eq!(readback.ring_bytes.capacity(), ring_capacity);
        assert_eq!(readback.debug_log_bytes.capacity(), debug_capacity);
        assert_eq!(readback.io_queue_bytes.capacity(), io_capacity);
        assert_eq!(readback.ring_bytes, buffers.ring_bytes());
    }
}
