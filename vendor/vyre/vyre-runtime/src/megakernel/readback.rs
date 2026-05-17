//! Typed host readback view for persistent megakernel outputs.

use super::io;
use super::protocol;
use super::protocol_api::{validate_control_bytes, validate_debug_log_bytes};
use crate::PipelineError;

/// Decoded megakernel output buffers in ABI order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MegakernelReadback {
    /// Control buffer bytes after dispatch.
    pub control_bytes: Vec<u8>,
    /// Ring buffer bytes after dispatch.
    pub ring_bytes: Vec<u8>,
    /// Debug-log buffer bytes after dispatch.
    pub debug_log_bytes: Vec<u8>,
    /// IO queue bytes after dispatch.
    pub io_queue_bytes: Vec<u8>,
}

impl MegakernelReadback {
    /// Decode the backend output vector produced by [`super::Megakernel`].
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::Backend`] when output count or protocol buffer
    /// shapes do not match the persistent megakernel ABI.
    pub fn from_outputs(outputs: Vec<Vec<u8>>, slot_count: u32) -> Result<Self, PipelineError> {
        Self::validate_output_refs(&outputs, slot_count)?;
        let [control, ring, debug_log, io_queue] =
            <[Vec<u8>; 4]>::try_from(outputs).map_err(|outputs| {
                PipelineError::Backend(format!(
                    "megakernel readback returned {} buffers after validation, expected 4. Fix: keep output ownership immutable between validation and decode.",
                    outputs.len()
                ))
            })?;
        Ok(Self {
            control_bytes: control,
            ring_bytes: ring,
            debug_log_bytes: debug_log,
            io_queue_bytes: io_queue,
        })
    }

    /// Decode backend outputs into caller-owned readback storage.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::Backend`] when output count or protocol buffer
    /// shapes do not match the persistent megakernel ABI.
    pub fn from_outputs_into(
        outputs: Vec<Vec<u8>>,
        slot_count: u32,
        out: &mut Self,
    ) -> Result<(), PipelineError> {
        let readback = Self::from_outputs(outputs, slot_count)?;
        *out = readback;
        Ok(())
    }

    /// Decode backend outputs into caller-owned readback storage while
    /// preserving the outer output-vector allocation for the next dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::Backend`] when output count or protocol buffer
    /// shapes do not match the persistent megakernel ABI.
    pub fn drain_outputs_into(
        outputs: &mut Vec<Vec<u8>>,
        slot_count: u32,
        out: &mut Self,
    ) -> Result<(), PipelineError> {
        Self::validate_output_refs(outputs, slot_count)?;
        out.io_queue_bytes = pop_validated_output(outputs, "io queue")?;
        out.debug_log_bytes = pop_validated_output(outputs, "debug log")?;
        out.ring_bytes = pop_validated_output(outputs, "ring")?;
        out.control_bytes = pop_validated_output(outputs, "control")?;
        Ok(())
    }

    /// Number of slots described by this readback ring.
    ///
    /// # Errors
    ///
    /// Returns when the ring length is not a whole number of slot records.
    pub fn slot_count(&self) -> Result<u32, PipelineError> {
        let slot_words = usize::try_from(protocol::SLOT_WORDS).map_err(|_| {
            PipelineError::Backend(
                "megakernel SLOT_WORDS overflowed usize. Fix: reduce SLOT_WORDS.".to_string(),
            )
        })?;
        let slot_bytes = slot_words
            .checked_mul(std::mem::size_of::<u32>())
            .ok_or_else(|| {
                PipelineError::Backend(
                    "megakernel slot byte width overflowed usize. Fix: reduce SLOT_WORDS."
                        .to_string(),
                )
            })?;
        if self.ring_bytes.len() % slot_bytes != 0 {
            return Err(PipelineError::Backend(format!(
                "megakernel readback ring has {} bytes, not a multiple of {slot_bytes}. Fix: rebuild the ring with Megakernel::encode_empty_ring.",
                self.ring_bytes.len()
            )));
        }
        u32::try_from(self.ring_bytes.len() / slot_bytes).map_err(|_| {
            PipelineError::Backend(
                "megakernel readback slot count overflowed u32. Fix: split the ring into smaller shards."
                    .to_string(),
            )
        })
    }

    fn validate_output_refs(outputs: &[Vec<u8>], slot_count: u32) -> Result<(), PipelineError> {
        let [control, ring, debug_log, io_queue] = outputs else {
            return Err(PipelineError::Backend(format!(
                "megakernel readback returned {} buffers, expected 4. Fix: keep builder output declarations aligned with control/ring/debug/io ABI order.",
                outputs.len()
            )));
        };
        validate_control_bytes(control)?;
        validate_debug_log_bytes(debug_log)?;
        io::validate_io_queue_bytes(io_queue)?;
        let expected_ring_bytes = protocol::ring_byte_len(slot_count).ok_or_else(|| {
            PipelineError::Backend(
                "megakernel ring byte length overflowed usize during readback validation. Fix: split the ring into smaller shards."
                    .to_string(),
            )
        })?;
        if ring.len() != expected_ring_bytes {
            return Err(PipelineError::Backend(format!(
                "megakernel readback ring has {} bytes, expected {expected_ring_bytes}. Fix: read back the full ring buffer for the compiled slot count.",
                ring.len()
            )));
        }
        Ok(())
    }
}

fn pop_validated_output(outputs: &mut Vec<Vec<u8>>, name: &str) -> Result<Vec<u8>, PipelineError> {
    outputs.pop().ok_or_else(|| {
        PipelineError::Backend(format!(
            "megakernel readback lost the {name} buffer after validation. Fix: keep output ownership immutable during drain."
        ))
    })
}
