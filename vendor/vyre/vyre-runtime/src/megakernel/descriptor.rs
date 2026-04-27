//! Typed host-side descriptors for publishing work into the megakernel ring.
//!
//! Wrappers such as VyreOffload should not have to hand-assemble
//! `(opcode, tenant_id, args)` tuples or know when to switch to the
//! packed-slot path. These descriptors provide an additive typed API
//! over the existing wire protocol.

use crate::PipelineError;

use super::{protocol, Megakernel};

/// Built-in megakernel opcodes exposed as a typed host API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinOpcode {
    /// No-op heartbeat / probe.
    Nop,
    /// `control[arg1] = arg0`.
    StoreU32,
    /// `atomic_add(control[arg1], arg0)`.
    AtomicAdd,
    /// `control[OBSERVABLE_BASE + arg1] = control[arg0]`.
    LoadU32,
    /// Compare-and-swap on `control[arg0]`.
    CompareSwap,
    /// Copy `arg2` words from `control[arg0]` to `control[arg1]`.
    Memcpy,
    /// Single DFA transition step.
    DfaStep,
    /// Batch fence / epoch bump.
    BatchFence,
    /// Emit a debug log record.
    Printf,
    /// Set `SHUTDOWN=1`.
    Shutdown,
}

impl BuiltinOpcode {
    /// Underlying wire opcode.
    #[must_use]
    pub const fn into_wire(self) -> u32 {
        match self {
            Self::Nop => protocol::opcode::NOP,
            Self::StoreU32 => protocol::opcode::STORE_U32,
            Self::AtomicAdd => protocol::opcode::ATOMIC_ADD,
            Self::LoadU32 => protocol::opcode::LOAD_U32,
            Self::CompareSwap => protocol::opcode::COMPARE_SWAP,
            Self::Memcpy => protocol::opcode::MEMCPY,
            Self::DfaStep => protocol::opcode::DFA_STEP,
            Self::BatchFence => protocol::opcode::BATCH_FENCE,
            Self::Printf => protocol::opcode::PRINTF,
            Self::Shutdown => protocol::opcode::SHUTDOWN,
        }
    }
}

/// A slot opcode can target either a builtin wire opcode or a caller-defined
/// extension registered via an opcode handler (see `handlers` module).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotOpcode {
    /// One of the frozen builtins in [`protocol::opcode`].
    Builtin(BuiltinOpcode),
    /// A custom extension opcode.
    Custom(u32),
}

impl SlotOpcode {
    /// Underlying wire opcode.
    #[must_use]
    pub const fn into_wire(self) -> u32 {
        match self {
            Self::Builtin(op) => op.into_wire(),
            Self::Custom(op) => op,
        }
    }
}

/// One packed inner-op inside a `PACKED_SLOT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedOpDescriptor {
    /// Inner opcode id. Must fit in `u8` due to the current wire format.
    pub opcode: u8,
    /// Positional `u32` arguments for the inner opcode.
    pub args: Vec<u32>,
}

impl PackedOpDescriptor {
    /// Convenience constructor.
    #[must_use]
    pub fn new(opcode: u8, args: Vec<u32>) -> Self {
        Self { opcode, args }
    }
}

/// One top-level slot publication request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotDescriptor {
    /// Publish one normal slot.
    Single {
        /// Tenant id used for the runtime's authorization mask.
        tenant_id: u32,
        /// Slot opcode.
        opcode: SlotOpcode,
        /// Positional `u32` arguments.
        args: Vec<u32>,
    },
    /// Publish one packed slot containing several inner ops.
    Packed {
        /// Tenant id used for the runtime's authorization mask.
        tenant_id: u32,
        /// Inner packed ops.
        ops: Vec<PackedOpDescriptor>,
    },
}

impl SlotDescriptor {
    /// Build a simple slot descriptor.
    #[must_use]
    pub fn single(tenant_id: u32, opcode: SlotOpcode, args: Vec<u32>) -> Self {
        Self::Single {
            tenant_id,
            opcode,
            args,
        }
    }

    /// Build a packed-slot descriptor.
    #[must_use]
    pub fn packed(tenant_id: u32, ops: Vec<PackedOpDescriptor>) -> Self {
        Self::Packed { tenant_id, ops }
    }

    /// Publish this slot into the ring at `slot_idx`.
    ///
    /// # Errors
    ///
    /// Propagates any wire-level publication error from the underlying ring
    /// protocol helpers.
    pub fn publish_into(&self, ring_bytes: &mut [u8], slot_idx: u32) -> Result<(), PipelineError> {
        match self {
            Self::Single {
                tenant_id,
                opcode,
                args,
            } => {
                Megakernel::publish_slot(ring_bytes, slot_idx, *tenant_id, opcode.into_wire(), args)
            }
            Self::Packed { tenant_id, ops } => {
                let packed = ops
                    .iter()
                    .map(|op| (op.opcode, op.args.clone()))
                    .collect::<Vec<_>>();
                Megakernel::publish_packed_slot(ring_bytes, slot_idx, *tenant_id, &packed)
            }
        }
    }
}

/// A typed batch publication request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchDescriptor {
    /// Slot index where the first item should be written.
    pub start_slot: u32,
    /// Items to publish in order.
    pub items: Vec<SlotDescriptor>,
}

impl BatchDescriptor {
    /// Convenience constructor.
    #[must_use]
    pub fn new(start_slot: u32, items: Vec<SlotDescriptor>) -> Self {
        Self { start_slot, items }
    }

    /// Publish all items into the ring. Returns the number of slots consumed.
    ///
    /// # Errors
    ///
    /// Propagates any slot publication error.
    pub fn publish_into(&self, ring_bytes: &mut [u8]) -> Result<u32, PipelineError> {
        let item_count = u32::try_from(self.items.len()).map_err(|_| PipelineError::QueueFull {
            queue: "submission",
            fix: "batch size exceeds u32::MAX slots",
        })?;
        if item_count > 0 {
            self.start_slot
                .checked_add(item_count - 1)
                .ok_or(PipelineError::QueueFull {
                    queue: "submission",
                    fix: "batch start plus item count overflows u32; split the descriptor batch before publishing",
                })?;
        }
        for (index, item) in self.items.iter().enumerate() {
            let slot_idx =
                self.start_slot
                    .checked_add(u32::try_from(index).map_err(|_| PipelineError::QueueFull {
                        queue: "submission",
                        fix: "batch size exceeds u32::MAX slots",
                    })?)
                    .ok_or(PipelineError::QueueFull {
                        queue: "submission",
                        fix: "batch slot index overflowed u32; split the descriptor batch before publishing",
                    })?;
            item.publish_into(ring_bytes, slot_idx)?;
        }
        Ok(item_count)
    }
}

/// Classification for items published inside a window descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowClass {
    /// Required work that must converge for the window to be usable.
    Required,
    /// Lookahead work that improves the next step but is not on the immediate critical path.
    Lookahead,
}

impl WindowClass {
    /// Stable on-the-wire encoding — `Required` = 0, `Lookahead` = 1.
    #[must_use]
    pub const fn into_wire(self) -> u32 {
        match self {
            Self::Required => 0,
            Self::Lookahead => 1,
        }
    }
}

/// A ticketed window of related slot publications.
///
/// Each emitted slot receives a stable prefix of `[window_ticket, class_tag]`
/// followed by the caller-supplied payload, so wrappers can submit required and
/// lookahead work as one structured batch without hand-assembling the prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowDescriptor {
    /// Slot index where the first window item should be written.
    pub start_slot: u32,
    /// Tenant id used for all emitted slots.
    pub tenant_id: u32,
    /// Slot opcode shared by all emitted slots.
    pub opcode: SlotOpcode,
    /// Stable ticket id correlating every slot in this window.
    pub ticket: u32,
    /// Required entries for the window.
    pub required: Vec<Vec<u32>>,
    /// Lookahead entries for the window.
    pub lookahead: Vec<Vec<u32>>,
}

impl WindowDescriptor {
    /// Convenience constructor.
    #[must_use]
    pub fn new(
        start_slot: u32,
        tenant_id: u32,
        opcode: SlotOpcode,
        ticket: u32,
        required: Vec<Vec<u32>>,
        lookahead: Vec<Vec<u32>>,
    ) -> Self {
        Self {
            start_slot,
            tenant_id,
            opcode,
            ticket,
            required,
            lookahead,
        }
    }

    /// Convert the window into a typed batch publication.
    #[must_use]
    pub fn into_batch(&self) -> BatchDescriptor {
        let mut items = Vec::with_capacity(self.required.len() + self.lookahead.len());
        for payload in &self.required {
            let mut args = Vec::with_capacity(payload.len() + 2);
            args.push(self.ticket);
            args.push(WindowClass::Required.into_wire());
            args.extend(payload.iter().copied());
            items.push(SlotDescriptor::single(self.tenant_id, self.opcode, args));
        }
        for payload in &self.lookahead {
            let mut args = Vec::with_capacity(payload.len() + 2);
            args.push(self.ticket);
            args.push(WindowClass::Lookahead.into_wire());
            args.extend(payload.iter().copied());
            items.push(SlotDescriptor::single(self.tenant_id, self.opcode, args));
        }
        BatchDescriptor::new(self.start_slot, items)
    }

    /// Publish the full window into the ring and return the number of emitted slots.
    pub fn publish_into(&self, ring_bytes: &mut [u8]) -> Result<u32, PipelineError> {
        self.into_batch().publish_into(ring_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::megakernel::protocol::{slot, ARGS_PER_SLOT, SLOT_WORDS, STATUS_WORD};

    fn read_word(buf: &[u8], slot_idx: u32, word_idx: u32) -> u32 {
        let base = (slot_idx as usize) * (SLOT_WORDS as usize) * 4;
        let off = base + (word_idx as usize) * 4;
        u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
    }

    #[test]
    fn single_descriptor_publishes_normal_slot() {
        let mut ring = Megakernel::try_encode_empty_ring(4).unwrap();
        let slot = SlotDescriptor::single(
            7,
            SlotOpcode::Builtin(BuiltinOpcode::StoreU32),
            vec![11, 13],
        );
        slot.publish_into(&mut ring, 1).unwrap();
        assert_eq!(read_word(&ring, 1, STATUS_WORD), slot::PUBLISHED);
    }

    #[test]
    fn packed_descriptor_uses_packed_opcode() {
        let mut ring = Megakernel::try_encode_empty_ring(2).unwrap();
        let slot = SlotDescriptor::packed(
            3,
            vec![
                PackedOpDescriptor::new(9, vec![1, 2, 3]),
                PackedOpDescriptor::new(10, vec![4]),
            ],
        );
        slot.publish_into(&mut ring, 0).unwrap();
        assert_eq!(read_word(&ring, 0, STATUS_WORD), slot::PUBLISHED);
        assert_eq!(
            read_word(&ring, 0, protocol::OPCODE_WORD),
            protocol::opcode::PACKED_SLOT
        );
    }

    #[test]
    fn batch_descriptor_publishes_sequential_slots() {
        let mut ring = Megakernel::try_encode_empty_ring(4).unwrap();
        let batch = BatchDescriptor::new(
            1,
            vec![
                SlotDescriptor::single(0, SlotOpcode::Builtin(BuiltinOpcode::Nop), vec![]),
                SlotDescriptor::single(
                    0,
                    SlotOpcode::Builtin(BuiltinOpcode::AtomicAdd),
                    vec![1, 2],
                ),
            ],
        );
        let consumed = batch.publish_into(&mut ring).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(read_word(&ring, 1, STATUS_WORD), slot::PUBLISHED);
        assert_eq!(read_word(&ring, 2, STATUS_WORD), slot::PUBLISHED);
    }

    #[test]
    fn batch_descriptor_rejects_slot_index_overflow_before_publication() {
        let mut ring = Megakernel::try_encode_empty_ring(4).unwrap();
        let before = ring.clone();
        let batch = BatchDescriptor::new(
            u32::MAX,
            vec![
                SlotDescriptor::single(0, SlotOpcode::Builtin(BuiltinOpcode::Nop), vec![]),
                SlotDescriptor::single(0, SlotOpcode::Builtin(BuiltinOpcode::Nop), vec![]),
            ],
        );

        let err = batch.publish_into(&mut ring).unwrap_err();
        assert!(
            err.to_string().contains("overflows u32"),
            "overflowing descriptor batch must fail with an actionable message: {err}"
        );
        assert_eq!(
            ring, before,
            "overflow preflight must not partially publish slots before failing"
        );
    }

    #[test]
    fn normal_slot_respects_wire_arg_budget() {
        let mut ring = Megakernel::try_encode_empty_ring(1).unwrap();
        let slot = SlotDescriptor::single(
            0,
            SlotOpcode::Builtin(BuiltinOpcode::Memcpy),
            vec![0; ARGS_PER_SLOT as usize + 1],
        );
        let err = slot.publish_into(&mut ring, 0).unwrap_err();
        assert!(matches!(err, PipelineError::QueueFull { .. }));
    }

    #[test]
    fn window_descriptor_publishes_required_then_lookahead() {
        let mut ring = Megakernel::try_encode_empty_ring(4).unwrap();
        let window = WindowDescriptor::new(
            1,
            5,
            SlotOpcode::Custom(0xF101),
            77,
            vec![vec![17], vec![42]],
            vec![vec![99]],
        );
        let consumed = window.publish_into(&mut ring).unwrap();
        assert_eq!(consumed, 3);
        assert_eq!(read_word(&ring, 1, STATUS_WORD), slot::PUBLISHED);
        assert_eq!(read_word(&ring, 2, STATUS_WORD), slot::PUBLISHED);
        assert_eq!(read_word(&ring, 3, STATUS_WORD), slot::PUBLISHED);
        assert_eq!(read_word(&ring, 1, protocol::ARG0_WORD), 77);
        assert_eq!(
            read_word(&ring, 1, protocol::ARG0_WORD + 1),
            WindowClass::Required.into_wire()
        );
        assert_eq!(
            read_word(&ring, 3, protocol::ARG0_WORD + 1),
            WindowClass::Lookahead.into_wire()
        );
    }
}
