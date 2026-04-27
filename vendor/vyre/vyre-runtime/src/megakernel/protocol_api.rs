//! Host protocol API wrappers for megakernel control/ring buffers.

use crate::PipelineError;

use super::protocol::{
    self, slot, DebugRecord, ARG0_WORD, ARGS_PER_SLOT, OPCODE_WORD, PRIORITY_WORD, SLOT_WORDS,
    STATUS_WORD, TENANT_WORD,
};
use super::Megakernel;

impl Megakernel {
    /// Encode a control-buffer payload.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::QueueFull`] when the requested observable region
    /// cannot fit in process address space.
    pub fn encode_control(
        shutdown: bool,
        tenant_count: u32,
        observable_slots: u32,
    ) -> Result<Vec<u8>, PipelineError> {
        protocol::encode_control(shutdown, tenant_count, observable_slots).map_err(protocol_error)
    }

    /// Fallible control-buffer encoder for callers accepting untrusted sizing.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::QueueFull`] when the requested observable region
    /// cannot fit in process address space.
    pub fn try_encode_control(
        shutdown: bool,
        tenant_count: u32,
        observable_slots: u32,
    ) -> Result<Vec<u8>, PipelineError> {
        Self::encode_control(shutdown, tenant_count, observable_slots)
    }

    /// Encode an empty ring buffer with `slot_count` slots.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::QueueFull`] when `slot_count * SLOT_WORDS * 4`
    /// overflows.
    pub fn encode_empty_ring(slot_count: u32) -> Result<Vec<u8>, PipelineError> {
        protocol::encode_empty_ring(slot_count).map_err(protocol_error)
    }

    /// Fallible ring-buffer encoder for callers accepting untrusted slot counts.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::QueueFull`] when `slot_count * SLOT_WORDS * 4`
    /// overflows.
    pub fn try_encode_empty_ring(slot_count: u32) -> Result<Vec<u8>, PipelineError> {
        Self::encode_empty_ring(slot_count)
    }

    /// Encode an empty PRINTF channel buffer.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::QueueFull`] when the record capacity overflows.
    pub fn encode_empty_debug_log(record_capacity: u32) -> Result<Vec<u8>, PipelineError> {
        protocol::encode_empty_debug_log(record_capacity).map_err(protocol_error)
    }

    /// Fallible debug-log encoder for callers accepting untrusted capacities.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::QueueFull`] when the record capacity overflows.
    pub fn try_encode_empty_debug_log(record_capacity: u32) -> Result<Vec<u8>, PipelineError> {
        Self::encode_empty_debug_log(record_capacity)
    }

    /// Publish one opcode into `ring_bytes[slot_idx]`.
    ///
    /// # Errors
    ///
    /// [`PipelineError::QueueFull`] when out of bounds, too many args,
    /// or the slot is still in flight.
    pub fn publish_slot(
        ring_bytes: &mut [u8],
        slot_idx: u32,
        tenant_id: u32,
        opcode: u32,
        args: &[u32],
    ) -> Result<(), PipelineError> {
        let words_per_slot = SLOT_WORDS as usize;
        let slot_bytes = words_per_slot
            .checked_mul(4)
            .ok_or(PipelineError::QueueFull {
                queue: "submission",
                fix: "slot byte width overflowed usize; keep SLOT_WORDS within the u32 ABI",
            })?;
        if ring_bytes.len() % slot_bytes != 0 {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "ring buffer byte length is not an exact multiple of SLOT_WORDS * 4; rebuild it with Megakernel::encode_empty_ring",
            });
        }
        let slot_capacity = ring_bytes.len() / slot_bytes;
        if (slot_idx as usize) >= slot_capacity {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "slot_idx exceeds ring slot count; enlarge the ring via encode_empty_ring",
            });
        }
        if args.len() > ARGS_PER_SLOT as usize {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "too many args for one slot; 12 u32 args max per slot",
            });
        }
        if let Err(fix) = protocol::opcode::validate_publish_opcode(opcode) {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix,
            });
        }

        let base = (slot_idx as usize)
            .checked_mul(slot_bytes)
            .ok_or(PipelineError::QueueFull {
                queue: "submission",
                fix: "slot byte offset overflowed usize; shard the ring before publishing",
            })?;
        let read_word = |buf: &[u8], word_idx: usize| -> u32 {
            let off = base + word_idx * 4;
            let bytes: [u8; 4] = buf[off..off + 4]
                .try_into()
                .expect("publish_slot: slot bounds already validated");
            u32::from_le_bytes(bytes)
        };

        let current_status = read_word(ring_bytes, STATUS_WORD as usize);
        if current_status != slot::EMPTY && current_status != slot::DONE {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix:
                    "slot is not publishable; only EMPTY and DONE slots may be written by the host",
            });
        }

        let write_word = |buf: &mut [u8], word_idx: usize, value: u32| {
            let off = base + word_idx * 4;
            buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
        };

        write_word(ring_bytes, OPCODE_WORD as usize, opcode);
        write_word(ring_bytes, TENANT_WORD as usize, tenant_id);
        write_word(ring_bytes, PRIORITY_WORD as usize, slot::PRIORITY_NORMAL);
        for i in 0..ARGS_PER_SLOT as usize {
            write_word(ring_bytes, ARG0_WORD as usize + i, 0);
        }
        for (i, arg) in args.iter().enumerate() {
            write_word(ring_bytes, ARG0_WORD as usize + i, *arg);
        }
        // Status last — PUBLISH is the publish barrier.
        write_word(ring_bytes, STATUS_WORD as usize, slot::PUBLISHED);

        Ok(())
    }

    /// Publish one packed slot containing multiple inner ops.
    ///
    /// The inner opcode id is stored as `u8`; args are packed into the slot's
    /// 12-word payload tail and addressed by per-op `arg_offset` values.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError::QueueFull`] when the packed payload exceeds
    /// the slot capacity or when the target slot is not publishable.
    pub fn publish_packed_slot(
        ring_bytes: &mut [u8],
        slot_idx: u32,
        tenant_id: u32,
        ops: &[(u8, Vec<u32>)],
    ) -> Result<(), PipelineError> {
        let opcode_count = u8::try_from(ops.len()).map_err(|_| PipelineError::QueueFull {
            queue: "submission",
            fix: "packed slot supports at most 255 inner opcodes",
        })?;
        let metadata_bytes = ops
            .len()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(2))
            .ok_or(PipelineError::QueueFull {
                queue: "submission",
                fix: "packed slot metadata length overflowed usize; reduce packed opcode count",
            })?;
        let metadata_words = metadata_bytes.div_ceil(4);
        let mut packed_args = Vec::new();
        let mut pairs = Vec::with_capacity(ops.len());
        for (op_id, args) in ops {
            let arg_offset =
                u8::try_from(packed_args.len()).map_err(|_| PipelineError::QueueFull {
                    queue: "submission",
                    fix: "packed slot arg offsets must fit in one u8 word index",
                })?;
            packed_args.extend(args.iter().copied());
            pairs.push((*op_id, arg_offset));
        }
        let total_words =
            metadata_words
                .checked_add(packed_args.len())
                .ok_or(PipelineError::QueueFull {
                    queue: "submission",
                    fix: "packed slot total word count overflowed usize; reduce packed args",
                })?;
        if total_words > ARGS_PER_SLOT as usize {
            return Err(PipelineError::QueueFull {
                queue: "submission",
                fix: "packed slot payload exceeds the 12-word slot argument budget",
            });
        }

        let metadata_payload_bytes =
            metadata_words
                .checked_mul(4)
                .ok_or(PipelineError::QueueFull {
                queue: "submission",
                fix:
                    "packed slot metadata byte length overflowed usize; reduce packed opcode count",
            })?;
        let mut payload = vec![0u8; metadata_payload_bytes];
        payload[0] = opcode_count;
        // Byte 1: total packed_args word count, so the host-side
        // decoder can slice off the correct portion without relying
        // on trailing-zero heuristics (slot memory can legitimately
        // contain zero arg values, and rings aren't guaranteed zero
        // after wrap-around).
        payload[1] = u8::try_from(packed_args.len()).map_err(|_| PipelineError::QueueFull {
            queue: "submission",
            fix: "packed slot total arg words must fit in one u8",
        })?;
        for (index, (op_id, arg_offset)) in pairs.iter().enumerate() {
            let byte_index = 2 + index * 2;
            payload[byte_index] = *op_id;
            payload[byte_index + 1] = *arg_offset;
        }

        let mut args = payload
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect::<Vec<_>>();
        args.extend(packed_args);
        Self::publish_slot(
            ring_bytes,
            slot_idx,
            tenant_id,
            protocol::opcode::PACKED_SLOT,
            &args,
        )
    }

    /// Decode the kernel's `done_count` from a control buffer.
    #[must_use]
    pub fn read_done_count(control_bytes: &[u8]) -> u32 {
        protocol::read_done_count(control_bytes)
    }

    /// Decode PRINTF records out of the debug-log buffer.
    #[must_use]
    pub fn read_debug_log(debug_bytes: &[u8]) -> Vec<DebugRecord> {
        protocol::read_debug_log(debug_bytes)
    }

    /// Strictly decode PRINTF records out of the debug-log buffer.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when the debug-log buffer is malformed or the
    /// cursor points at a partial record.
    pub fn try_read_debug_log(debug_bytes: &[u8]) -> Result<Vec<DebugRecord>, PipelineError> {
        protocol::try_read_debug_log(debug_bytes).map_err(protocol_error)
    }

    /// Publish multiple slots atomically — the final slot is a
    /// `BATCH_FENCE` that signals completion to the host. This is
    /// the high-throughput entry point for scanner pipelines: publish
    /// N work items + 1 fence in one call.
    ///
    /// # Errors
    ///
    /// [`PipelineError::QueueFull`] if any slot rejects.
    pub fn batch_publish(
        ring_bytes: &mut [u8],
        start_slot: u32,
        tenant_id: u32,
        items: &[(u32, Vec<u32>)], // (opcode, args) pairs
        batch_tag: u32,
    ) -> Result<u32, PipelineError> {
        let item_count = u32::try_from(items.len()).map_err(|_| PipelineError::QueueFull {
            queue: "submission",
            fix: "batch item count exceeds u32::MAX; split the publish batch",
        })?;
        let mut slot_idx = start_slot;
        for (opcode, args) in items {
            Self::publish_slot(ring_bytes, slot_idx, tenant_id, *opcode, args)?;
            slot_idx = slot_idx.checked_add(1).ok_or(PipelineError::QueueFull {
                queue: "submission",
                fix: "batch publish slot index overflowed u32; split the publish batch",
            })?;
        }
        // Publish the fence as the final slot.
        Self::publish_slot(
            ring_bytes,
            slot_idx,
            tenant_id,
            protocol::opcode::BATCH_FENCE,
            &[item_count, batch_tag],
        )?;
        slot_idx
            .checked_add(1)
            .and_then(|end| end.checked_sub(start_slot))
            .ok_or(PipelineError::QueueFull {
                queue: "submission",
                fix: "batch publish consumed-slot count overflowed u32; split the publish batch",
            })
    }

    /// Read the epoch counter from a control buffer. The epoch
    /// increments on each `BATCH_FENCE` execution — the host polls
    /// this to detect batch completion without scanning the ring.
    #[must_use]
    pub fn read_epoch(control_bytes: &[u8]) -> u32 {
        protocol::read_epoch(control_bytes)
    }

    /// Read an observable result word from a control buffer.
    /// Opcodes like `LOAD_U32`, `COMPARE_SWAP`, and `BATCH_FENCE`
    /// write results here.
    #[must_use]
    pub fn read_observable(control_bytes: &[u8], index: u32) -> u32 {
        protocol::read_observable(control_bytes, index)
    }

    /// Strictly read an observable result word from a control buffer.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when the buffer is malformed or the
    /// observable index is outside the supplied readback.
    pub fn try_read_observable(control_bytes: &[u8], index: u32) -> Result<u32, PipelineError> {
        protocol::try_read_observable(control_bytes, index).map_err(protocol_error)
    }

    /// Read per-opcode metrics counters from a control buffer.
    /// Returns a map of `opcode_id → execution_count` for any
    /// non-zero counters.
    #[must_use]
    pub fn read_metrics(control_bytes: &[u8]) -> Vec<(u32, u32)> {
        protocol::read_metrics(control_bytes)
    }

    /// Strictly read per-opcode metrics counters from a control buffer.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when the buffer is malformed or too short for
    /// the fixed metrics window.
    pub fn try_read_metrics(control_bytes: &[u8]) -> Result<Vec<(u32, u32)>, PipelineError> {
        protocol::try_read_metrics(control_bytes).map_err(protocol_error)
    }
}

fn protocol_error(error: protocol::ProtocolError) -> PipelineError {
    match error {
        protocol::ProtocolError::ByteLengthOverflow { fix, .. } => PipelineError::QueueFull {
            queue: "submission",
            fix,
        },
        other => PipelineError::Backend(other.to_string()),
    }
}

pub(super) fn validate_control_bytes(control_bytes: &[u8]) -> Result<(), PipelineError> {
    let min = protocol::control_byte_len(0).ok_or_else(|| {
        PipelineError::Backend(
            "megakernel minimum control-buffer length overflowed usize. Fix: keep CONTROL_MIN_WORDS within host address limits."
                .to_string(),
        )
    })?;
    if control_bytes.len() < min || control_bytes.len() % 4 != 0 {
        return Err(PipelineError::Backend(format!(
            "megakernel control buffer has {} bytes, expected at least {min} bytes and 4-byte alignment. Fix: build it with Megakernel::encode_control.",
            control_bytes.len()
        )));
    }
    Ok(())
}

pub(super) fn validate_debug_log_bytes(debug_log_bytes: &[u8]) -> Result<(), PipelineError> {
    let expected = protocol::debug_log_byte_len(protocol::debug::RECORD_CAPACITY)
        .ok_or(PipelineError::QueueFull {
            queue: "submission",
            fix: "debug-log minimum length overflowed usize; keep debug ABI constants within host limits",
        })?;
    if debug_log_bytes.len() != expected {
        return Err(PipelineError::Backend(format!(
            "megakernel debug-log buffer has {} bytes, expected exactly {expected} bytes for {} PRINTF records. Fix: build it with Megakernel::encode_empty_debug_log(protocol::debug::RECORD_CAPACITY).",
            debug_log_bytes.len(),
            protocol::debug::RECORD_CAPACITY
        )));
    }
    Ok(())
}
