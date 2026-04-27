//! Ring-buffer protocol constants — slot layout, control words, opcodes, debug log.
//!
//! Pure data module. No logic, no imports beyond std. Every constant
//! has a doc-comment that says what the GPU kernel does with it.

/// A single PRINTF event decoded out of the debug-log buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugRecord {
    /// Format-string id — resolved by the host against its
    /// registered format table.
    pub fmt_id: u32,
    /// Three argument words in the order the kernel wrote them.
    pub args: [u32; 3],
}

/// Megakernel host-protocol encoding and decoding error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// A requested buffer length overflowed host address space.
    #[error("{buffer} byte length overflow. Fix: {fix}")]
    ByteLengthOverflow {
        /// Protocol buffer being sized.
        buffer: &'static str,
        /// Actionable remediation.
        fix: &'static str,
    },
    /// A byte slice is not aligned to full u32 protocol words.
    #[error("{buffer} has {byte_len} bytes, not a whole number of u32 words. Fix: {fix}")]
    MisalignedByteLength {
        /// Protocol buffer being decoded.
        buffer: &'static str,
        /// Byte length received by the decoder.
        byte_len: usize,
        /// Actionable remediation.
        fix: &'static str,
    },
    /// A requested protocol word is outside the supplied byte slice.
    #[error("{buffer} is missing word {word_idx} in {byte_len} bytes. Fix: {fix}")]
    MissingWord {
        /// Protocol buffer being decoded.
        buffer: &'static str,
        /// Word index requested.
        word_idx: usize,
        /// Byte length received by the decoder.
        byte_len: usize,
        /// Actionable remediation.
        fix: &'static str,
    },
}

/// Number of u32 words each ring-buffer slot occupies. 16 words = 64 B,
/// a cache line on x86_64 and the slot size NVMe Submission Queue
/// Entries will use when the `uring-cmd-nvme` extension lands.
pub const SLOT_WORDS: u32 = 16;

/// Word index of the slot status header (the CAS target).
pub const STATUS_WORD: u32 = 0;

/// Word index of the slot opcode (dispatched via If-tree).
pub const OPCODE_WORD: u32 = 1;

/// Word index of the slot tenant id.
pub const TENANT_WORD: u32 = 2;

/// Word index of the slot priority level.
pub const PRIORITY_WORD: u32 = 3;

/// First argument word. Opcodes read args at
/// `ring_buffer[slot_base + ARG0_WORD .. slot_base + SLOT_WORDS]`.
pub const ARG0_WORD: u32 = 4;

/// Number of u32 argument words available per slot (12).
pub const ARGS_PER_SLOT: u32 = SLOT_WORDS - ARG0_WORD;

/// Slot status discriminants. A slot transitions through these four
/// states exactly once per publish/execute cycle.
pub mod slot {
    /// The slot is free; the host may publish into it.
    pub const EMPTY: u32 = 0;
    /// The host finished writing; the GPU may claim it.
    pub const PUBLISHED: u32 = 1;
    /// A lane won the CAS; it now owns the slot.
    pub const CLAIMED: u32 = 2;
    /// The lane finished executing; the host may recycle the slot.
    pub const DONE: u32 = 3;
    /// The slot is waiting for an asynchronous IO continuation.
    pub const WAIT_IO: u32 = 4;
    /// The slot yielded execution back to the scheduler.
    pub const YIELD: u32 = 5;
    /// The slot is heavily contested and has been requeued.
    pub const REQUEUE: u32 = 6;
    /// The slot hit a hardware or software fault constraint.
    pub const FAULT: u32 = 7;
    /// Priority: normal scheduling (default).
    pub const PRIORITY_NORMAL: u32 = 0;
    /// Priority: high — kernel checks these slots first on each
    /// iteration, ensuring low-latency dispatch for interactive ops.
    pub const PRIORITY_HIGH: u32 = 1;
}

/// Control-buffer word indices.
pub mod control {
    /// Non-zero signals the kernel to exit on the next iteration.
    pub const SHUTDOWN: u32 = 0;
    /// Kernel atomic-adds 1 here every time it drains a slot. Host
    /// reads this to know how far the GPU has progressed.
    pub const DONE_COUNT: u32 = 1;
    /// Word index in `control` where the tenant-mask table begins.
    /// The host writes this value before the first dispatch; the
    /// kernel reads `control[tenant_base + tenant_id]` per slot to
    /// authorize execution.
    pub const TENANT_BASE: u32 = 2;
    /// Word index in `control` where the tenant quota table begins.
    /// Used by the IO continuation scheduler to throttle greedy tenants
    /// during heavy compilation.
    pub const TENANT_QUOTA_BASE: u32 = 32;
    /// Word index in `control` where the tenant fairness counters begin.
    /// Each word stores the cumulative execution count for that tenant.
    pub const TENANT_FAIRNESS_BASE: u32 = 64;
    /// Number of tenant fairness counters reserved in the control buffer.
    pub const TENANT_FAIRNESS_SLOTS: u32 = 32;
    /// Metrics region start. Per-opcode execution counters live here.
    /// Layout: `control[METRICS_BASE + opcode_id]` = count of times
    /// that opcode has been dispatched. Host reads for observability;
    /// kernel atomically increments before each opcode body executes.
    pub const METRICS_BASE: u32 = TENANT_FAIRNESS_BASE + TENANT_FAIRNESS_SLOTS;
    /// Total number of tracked opcode metric slots.
    pub const METRICS_SLOTS: u32 = 32;
    /// Epoch counter — host increments on each publish batch.
    /// The kernel reads this to detect new work without scanning
    /// the entire ring.
    pub const EPOCH: u32 = METRICS_BASE + METRICS_SLOTS;
    /// Word index in `control` where priority partition offsets begin.
    /// Layout: five priority starts plus one sentinel total-slot word.
    pub const PRIORITY_OFFSETS_BASE: u32 = EPOCH + 1;
    /// Number of priority partition offset words, including sentinel.
    pub const PRIORITY_OFFSETS_SLOTS: u32 = 6;
    /// Starvation counter word used by the priority scheduler.
    pub const PRIORITY_STARVATION_COUNTER: u32 = PRIORITY_OFFSETS_BASE + PRIORITY_OFFSETS_SLOTS;
    /// Word index in `control` where per-priority fairness counters begin.
    pub const PRIORITY_FAIRNESS_BASE: u32 = PRIORITY_STARVATION_COUNTER + 1;
    /// Number of priority fairness counters reserved in the control buffer.
    pub const PRIORITY_FAIRNESS_SLOTS: u32 = 5;
    /// First observable result word — opcodes write here. This region starts
    /// after metrics, epoch, and priority scheduler metadata so counters and
    /// user-visible results cannot alias.
    pub const OBSERVABLE_BASE: u32 = 160;

    const _: () = {
        if TENANT_BASE <= DONE_COUNT {
            panic!("tenant-mask table must start after fixed control header");
        }
        if TENANT_QUOTA_BASE <= TENANT_BASE {
            panic!("tenant quota table must not overlap tenant-mask header");
        }
        if TENANT_FAIRNESS_BASE <= TENANT_QUOTA_BASE {
            panic!("tenant fairness table must start after quota table");
        }
        if METRICS_BASE < TENANT_FAIRNESS_BASE + TENANT_FAIRNESS_SLOTS {
            panic!("metrics region must start after tenant fairness table");
        }
        if EPOCH < METRICS_BASE + METRICS_SLOTS {
            panic!("epoch word must not overlap opcode metrics");
        }
        if PRIORITY_OFFSETS_BASE <= EPOCH {
            panic!("priority offsets must start after epoch");
        }
        if PRIORITY_STARVATION_COUNTER < PRIORITY_OFFSETS_BASE + PRIORITY_OFFSETS_SLOTS {
            panic!("priority starvation counter must start after priority offsets");
        }
        if PRIORITY_FAIRNESS_BASE <= PRIORITY_STARVATION_COUNTER {
            panic!("priority fairness must start after priority offsets and starvation counter");
        }
        if OBSERVABLE_BASE <= PRIORITY_FAIRNESS_BASE + PRIORITY_FAIRNESS_SLOTS {
            panic!("observable region must start after scheduler/control metadata");
        }
    };
}

/// Built-in opcode discriminants.
pub mod opcode {
    /// Do nothing. Useful for heartbeat probes.
    pub const NOP: u32 = 0;

    /// `control[args[1]] = args[0]`.
    pub const STORE_U32: u32 = 1;

    /// `atomic_add(control[args[1]], args[0])`.
    pub const ATOMIC_ADD: u32 = 2;

    // --- New opcodes (V6.4) ---

    /// `result = control[args[0]]` — readback a control word into
    /// `control[OBSERVABLE_BASE + args[1]]`. Enables host to query
    /// GPU-side state without a full dispatch round-trip.
    pub const LOAD_U32: u32 = 3;

    /// `CAS(control[args[0]], expected=args[1], desired=args[2])`.
    /// Result written to `control[OBSERVABLE_BASE + args[0]]`.
    /// Enables lock-free coordination between host and kernel.
    pub const COMPARE_SWAP: u32 = 4;

    /// `memcpy control[args[0]..args[0]+args[2]] → control[args[1]..args[1]+args[2]]`.
    /// Bulk GPU→GPU copy within the control buffer. Used for
    /// shuffling observable results without host round-trips.
    pub const MEMCPY: u32 = 5;

    /// DFA single-step: `next_state = dfa_table[args[0] * 256 + args[1]]`.
    /// Result written to `control[OBSERVABLE_BASE + args[2]]`.
    /// The scanner opcode — one step of the lexer DFA per slot.
    /// At scale, publish N slots with N consecutive bytes; the
    /// megakernel processes them all in one pass.
    pub const DFA_STEP: u32 = 6;

    /// Batch fence — the host publishes N slots then one BATCH_FENCE.
    /// When the kernel reaches the fence, it atomically increments
    /// `control[EPOCH]`, signaling the host that the entire batch
    /// is complete. Args: `args[0]` = expected batch count (for
    /// validation), `args[1]` = user-tag written to observable.
    pub const BATCH_FENCE: u32 = 7;

    /// Packed slot — one outer ring slot carries several inner ops.
    ///
    /// Byte layout in `args[0..ARGS_PER_SLOT]`:
    /// - byte 0: opcode_count
    /// - byte 1: reserved
    /// - bytes 2..: `(op_id:u8, arg_offset:u8)` pairs
    /// - remaining bytes: packed args as little-endian `u32` words
    ///
    /// `arg_offset` is measured in packed-arg words from the start of the
    /// packed-args tail after the metadata header's 4-byte alignment.
    pub const PACKED_SLOT: u32 = 0x8000_0001;

    /// `debug_log[cursor..cursor+4] = (PRINTF, args[0], args[1], args[2])`;
    /// cursor atomically advanced by 4.
    pub const PRINTF: u32 = 0x0000_FFFE;

    /// Set `control[SHUTDOWN] = 1`. No args.
    ///
    /// Spelled `u32::MAX` so a zero-initialized slot can never be
    /// mis-decoded as SHUTDOWN.
    pub const SHUTDOWN: u32 = u32::MAX;

    /// High bit is reserved for system opcodes.
    pub const SYSTEM_MASK: u32 = 0x8000_0000;

    /// Lower bound for the high reserved range (like PRINTF and SHUTDOWN).
    pub const RESERVED_MAX_RANGE_MIN: u32 = 0x0000_FFF0;

    /// Return true if the opcode is reserved by the megakernel.
    #[must_use]
    pub const fn is_system(op: u32) -> bool {
        (op & SYSTEM_MASK) != 0
            || (op >= RESERVED_MAX_RANGE_MIN && op <= 0x0000_FFFF)
            || op <= BATCH_FENCE
    }

    /// Return true if the opcode is one of the frozen built-in opcodes that
    /// the host may publish directly.
    #[must_use]
    pub const fn is_builtin(op: u32) -> bool {
        op <= BATCH_FENCE || op == PACKED_SLOT || op == PRINTF || op == SHUTDOWN
    }

    /// Validate a user-defined opcode.
    ///
    /// # Errors
    /// Returns a static string describing the violation if it overlaps
    /// with a system reserved range.
    pub const fn validate_user_opcode(op: u32) -> Result<(), &'static str> {
        if is_system(op) {
            Err("User opcode overlaps with reserved system range or uses the high bit.")
        } else {
            Ok(())
        }
    }

    /// Validate an opcode that is about to be written to the ring.
    ///
    /// Built-ins are accepted. Caller-defined opcodes must stay out of every
    /// reserved system range.
    pub const fn validate_publish_opcode(op: u32) -> Result<(), &'static str> {
        if is_builtin(op) {
            Ok(())
        } else {
            validate_user_opcode(op)
        }
    }

    // Compile-time check for opcode uniqueness and validity.
    const _: () = {
        let opcodes = [
            NOP,
            STORE_U32,
            ATOMIC_ADD,
            LOAD_U32,
            COMPARE_SWAP,
            MEMCPY,
            DFA_STEP,
            BATCH_FENCE,
            PACKED_SLOT,
            PRINTF,
            SHUTDOWN,
        ];
        let mut i = 0;
        while i < opcodes.len() {
            let mut j = i + 1;
            while j < opcodes.len() {
                if opcodes[i] == opcodes[j] {
                    panic!("Megakernel built-in opcodes must be unique");
                }
                j += 1;
            }
            if !is_system(opcodes[i]) {
                panic!("Megakernel built-in opcodes must fall within system reserved ranges");
            }
            i += 1;
        }
    };
}

/// `debug_log` buffer layout. Word 0 is the atomic write cursor that
/// PRINTF opcodes advance with `atomic_add`; words 1.. are the raw
/// `(fmt_id, arg0, arg1, arg2)` records the host-side helper decodes.
pub mod debug {
    /// Atomic write cursor — the next word to be written by PRINTF.
    pub const CURSOR_WORD: u32 = 0;
    /// First record word.
    pub const RECORDS_BASE: u32 = 1;
    /// Number of u32 words per PRINTF record.
    pub const RECORD_WORDS: u32 = 4;
    /// Record capacity compiled into the default megakernel program.
    pub const RECORD_CAPACITY: u32 = 64;
    /// Total u32 words compiled into the default debug-log buffer.
    pub const BUFFER_WORDS: u32 = RECORDS_BASE + RECORD_CAPACITY * RECORD_WORDS;
}

/// Minimum control-buffer words required by the compiled megakernel ABI.
///
/// This covers shutdown, done count, tenant masks, metrics, epoch, priority
/// offsets, and the statically declared read/write buffer count in the IR.
pub const CONTROL_MIN_WORDS: u32 = 160;
/// Maximum host-observable words accepted by the protocol encoder.
pub const MAX_OBSERVABLE_SLOTS: u32 = 1_048_576;
/// Maximum ring slots accepted by the protocol encoder.
pub const MAX_RING_SLOTS: u32 = 1_048_576;
/// Maximum debug-log records accepted by the protocol encoder.
pub const MAX_DEBUG_RECORDS: u32 = 1_048_576;

/// Return the number of bytes required by a control buffer with `observable_slots`.
#[must_use]
pub fn control_byte_len(observable_slots: u32) -> Option<usize> {
    let words = control::OBSERVABLE_BASE.checked_add(observable_slots)?;
    words_to_bytes(words.max(CONTROL_MIN_WORDS))
}

/// Return the number of bytes required by a ring buffer with `slot_count` slots.
#[must_use]
pub fn ring_byte_len(slot_count: u32) -> Option<usize> {
    let words = slot_count.checked_mul(SLOT_WORDS)?;
    words_to_bytes(words)
}

/// Return the number of bytes required by a debug-log buffer.
#[must_use]
pub fn debug_log_byte_len(record_capacity: u32) -> Option<usize> {
    let record_words = record_capacity.checked_mul(debug::RECORD_WORDS)?;
    let words = debug::RECORDS_BASE.checked_add(record_words)?;
    words_to_bytes(words)
}

/// Encode a control-buffer payload.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the requested observable region overflows
/// host address space.
pub fn encode_control(
    shutdown: bool,
    tenant_count: u32,
    observable_slots: u32,
) -> Result<Vec<u8>, ProtocolError> {
    try_encode_control(shutdown, tenant_count, observable_slots)
}

/// Strictly encode a control-buffer payload.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the requested observable region overflows
/// host address space.
pub fn try_encode_control(
    shutdown: bool,
    tenant_count: u32,
    observable_slots: u32,
) -> Result<Vec<u8>, ProtocolError> {
    if observable_slots > MAX_OBSERVABLE_SLOTS {
        return Err(ProtocolError::ByteLengthOverflow {
            buffer: "control",
            fix: "shard observable results or reduce observable_slots to the megakernel protocol cap before encoding control",
        });
    }
    let total_bytes =
        control_byte_len(observable_slots).ok_or(ProtocolError::ByteLengthOverflow {
            buffer: "control",
            fix: "shard observable results or reduce observable_slots to the megakernel protocol cap before encoding control",
        })?;
    let mut bytes = vec![0u8; total_bytes];

    if shutdown {
        write_word(&mut bytes, control::SHUTDOWN as usize, 1);
    }
    write_word(
        &mut bytes,
        control::TENANT_BASE as usize,
        control::TENANT_BASE + 1,
    );

    let tenant_table_start = (control::TENANT_BASE as usize) + 1;
    let requested_tenant_words = usize::try_from(tenant_count).unwrap_or(usize::MAX);
    let tenant_table_end = core::cmp::min(
        tenant_table_start.saturating_add(requested_tenant_words),
        control::TENANT_QUOTA_BASE as usize,
    );
    for word_idx in tenant_table_start..tenant_table_end {
        write_word(&mut bytes, word_idx, !0u32);
    }

    let quota_table_start = control::TENANT_QUOTA_BASE as usize;
    let quota_table_end = core::cmp::min(
        quota_table_start.saturating_add(requested_tenant_words),
        control::TENANT_FAIRNESS_BASE as usize,
    );
    for word_idx in quota_table_start..quota_table_end {
        write_word(&mut bytes, word_idx, 1_000_000);
    }
    Ok(bytes)
}

/// Encode an empty ring buffer with `slot_count` slots.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the requested ring size overflows host
/// address space.
pub fn encode_empty_ring(slot_count: u32) -> Result<Vec<u8>, ProtocolError> {
    try_encode_empty_ring(slot_count)
}

/// Strictly encode an empty ring buffer with `slot_count` slots.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the requested ring size overflows host
/// address space.
pub fn try_encode_empty_ring(slot_count: u32) -> Result<Vec<u8>, ProtocolError> {
    if slot_count > MAX_RING_SLOTS {
        return Err(ProtocolError::ByteLengthOverflow {
            buffer: "ring",
            fix: "split the dispatch into smaller ring shards before encoding; slot_count exceeds the megakernel protocol cap or host address space",
        });
    }
    let total_bytes = ring_byte_len(slot_count).ok_or(ProtocolError::ByteLengthOverflow {
        buffer: "ring",
        fix: "split the dispatch into smaller ring shards before encoding; slot_count exceeds the megakernel protocol cap or host address space",
    })?;
    Ok(vec![0u8; total_bytes])
}

/// Encode an empty PRINTF channel buffer.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the requested debug-log size overflows host
/// address space.
pub fn encode_empty_debug_log(record_capacity: u32) -> Result<Vec<u8>, ProtocolError> {
    try_encode_empty_debug_log(record_capacity)
}

/// Strictly encode an empty PRINTF channel buffer.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the requested debug-log size overflows host
/// address space.
pub fn try_encode_empty_debug_log(record_capacity: u32) -> Result<Vec<u8>, ProtocolError> {
    if record_capacity > MAX_DEBUG_RECORDS {
        return Err(ProtocolError::ByteLengthOverflow {
            buffer: "debug_log",
            fix: "reduce debug-log record_capacity to the megakernel protocol cap before encoding",
        });
    }
    let total_bytes =
        debug_log_byte_len(record_capacity).ok_or(ProtocolError::ByteLengthOverflow {
            buffer: "debug_log",
            fix: "reduce debug-log record_capacity to the megakernel protocol cap before encoding",
        })?;
    Ok(vec![0u8; total_bytes])
}

/// Decode the kernel's `done_count` from a control buffer.
#[must_use]
pub fn read_done_count(control_bytes: &[u8]) -> u32 {
    read_word(control_bytes, control::DONE_COUNT as usize).unwrap_or(0)
}

/// Read the epoch counter from a control buffer.
#[must_use]
pub fn read_epoch(control_bytes: &[u8]) -> u32 {
    read_word(control_bytes, control::EPOCH as usize).unwrap_or(0)
}

/// Strictly decode the kernel's `done_count` from a control buffer.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the buffer is not word-aligned or is too
/// short to contain the fixed control header.
pub fn try_read_done_count(control_bytes: &[u8]) -> Result<u32, ProtocolError> {
    read_required_word("control", control_bytes, control::DONE_COUNT as usize)
}

/// Strictly decode the epoch counter from a control buffer.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the buffer is not word-aligned or is too
/// short to contain the epoch word.
pub fn try_read_epoch(control_bytes: &[u8]) -> Result<u32, ProtocolError> {
    read_required_word("control", control_bytes, control::EPOCH as usize)
}

/// Read an observable result word from a control buffer.
#[must_use]
pub fn read_observable(control_bytes: &[u8], index: u32) -> u32 {
    read_word(control_bytes, (control::OBSERVABLE_BASE + index) as usize).unwrap_or(0)
}

/// Strictly read an observable result word from a control buffer.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the buffer is not word-aligned, the index
/// overflows the observable word offset, or the word is outside the buffer.
pub fn try_read_observable(control_bytes: &[u8], index: u32) -> Result<u32, ProtocolError> {
    let word_idx =
        control::OBSERVABLE_BASE
            .checked_add(index)
            .ok_or(ProtocolError::ByteLengthOverflow {
                buffer: "control",
                fix: "observable index overflows the protocol word offset; shard observable reads",
            })? as usize;
    read_required_word("control", control_bytes, word_idx)
}

/// Read per-opcode metrics counters from a control buffer.
#[must_use]
pub fn read_metrics(control_bytes: &[u8]) -> Vec<(u32, u32)> {
    let mut result = Vec::new();
    for i in 0..control::METRICS_SLOTS {
        let Some(count) = read_word(control_bytes, (control::METRICS_BASE + i) as usize) else {
            break;
        };
        if count > 0 {
            result.push((i, count));
        }
    }
    result
}

/// Strictly read per-opcode metrics counters from a control buffer.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the buffer is not word-aligned or is too
/// short for the fixed metrics window.
pub fn try_read_metrics(control_bytes: &[u8]) -> Result<Vec<(u32, u32)>, ProtocolError> {
    validate_word_aligned("control", control_bytes)?;
    let mut result = Vec::new();
    for i in 0..control::METRICS_SLOTS {
        let word_idx = (control::METRICS_BASE + i) as usize;
        let count = read_required_word("control", control_bytes, word_idx)?;
        if count > 0 {
            result.push((i, count));
        }
    }
    Ok(result)
}

/// Decode PRINTF records out of the debug-log buffer.
#[must_use]
pub fn read_debug_log(debug_bytes: &[u8]) -> Vec<DebugRecord> {
    let Some(cursor) = read_word(debug_bytes, debug::CURSOR_WORD as usize) else {
        return Vec::new();
    };
    let record_words = debug::RECORD_WORDS as usize;
    let records_start = debug::RECORDS_BASE as usize;
    let total_word_capacity = debug_bytes.len() / 4;
    let available = core::cmp::min(
        cursor as usize,
        total_word_capacity.saturating_sub(records_start),
    );
    let record_count = available / record_words;

    (0..record_count)
        .map(|i| {
            let w = records_start + i * record_words;
            DebugRecord {
                fmt_id: read_word(debug_bytes, w).unwrap_or(0),
                args: [
                    read_word(debug_bytes, w + 1).unwrap_or(0),
                    read_word(debug_bytes, w + 2).unwrap_or(0),
                    read_word(debug_bytes, w + 3).unwrap_or(0),
                ],
            }
        })
        .collect()
}

/// Strictly decode PRINTF records out of the debug-log buffer.
///
/// # Errors
///
/// Returns [`ProtocolError`] when the buffer is not word-aligned, too short for
/// the cursor word, or the cursor points at a partial record.
pub fn try_read_debug_log(debug_bytes: &[u8]) -> Result<Vec<DebugRecord>, ProtocolError> {
    validate_word_aligned("debug_log", debug_bytes)?;
    let cursor = read_required_word("debug_log", debug_bytes, debug::CURSOR_WORD as usize)?;
    let record_words = debug::RECORD_WORDS as usize;
    let records_start = debug::RECORDS_BASE as usize;
    let total_word_capacity = debug_bytes.len() / 4;
    if total_word_capacity < records_start {
        return Err(ProtocolError::MissingWord {
            buffer: "debug_log",
            word_idx: records_start,
            byte_len: debug_bytes.len(),
            fix: "build debug-log bytes with encode_empty_debug_log",
        });
    }
    let capacity_words = total_word_capacity.saturating_sub(records_start);
    if cursor as usize > capacity_words {
        return Err(ProtocolError::MissingWord {
            buffer: "debug_log",
            word_idx: records_start + cursor as usize,
            byte_len: debug_bytes.len(),
            fix: "debug-log cursor must stay within the encoded record capacity",
        });
    }
    let available = cursor as usize;
    if available % record_words != 0 {
        return Err(ProtocolError::MissingWord {
            buffer: "debug_log",
            word_idx: records_start + available,
            byte_len: debug_bytes.len(),
            fix: "debug-log cursor must advance in whole PRINTF records",
        });
    }
    let record_count = available / record_words;
    let mut records = Vec::with_capacity(record_count);
    for i in 0..record_count {
        let w = records_start + i * record_words;
        records.push(DebugRecord {
            fmt_id: read_required_word("debug_log", debug_bytes, w)?,
            args: [
                read_required_word("debug_log", debug_bytes, w + 1)?,
                read_required_word("debug_log", debug_bytes, w + 2)?,
                read_required_word("debug_log", debug_bytes, w + 3)?,
            ],
        });
    }
    Ok(records)
}

fn read_word(bytes: &[u8], word_idx: usize) -> Option<u32> {
    let off = word_idx.checked_mul(4)?;
    let end = off.checked_add(4)?;
    let word = bytes.get(off..end)?;
    Some(u32::from_le_bytes(word.try_into().ok()?))
}

fn read_required_word(
    buffer: &'static str,
    bytes: &[u8],
    word_idx: usize,
) -> Result<u32, ProtocolError> {
    validate_word_aligned(buffer, bytes)?;
    read_word(bytes, word_idx).ok_or(ProtocolError::MissingWord {
        buffer,
        word_idx,
        byte_len: bytes.len(),
        fix: "decode only buffers produced by the matching megakernel protocol encoder",
    })
}

fn validate_word_aligned(buffer: &'static str, bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.len() % 4 == 0 {
        Ok(())
    } else {
        Err(ProtocolError::MisalignedByteLength {
            buffer,
            byte_len: bytes.len(),
            fix: "pass whole u32 protocol words; do not decode partial DMA/readback buffers",
        })
    }
}

fn write_word(bytes: &mut [u8], word_idx: usize, value: u32) {
    let off = word_idx * 4;
    bytes[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn words_to_bytes(words: u32) -> Option<usize> {
    usize::try_from(words).ok()?.checked_mul(4)
}

#[cfg(test)]
mod tests {
    use super::control;

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn control_regions_do_not_alias() {
        let metrics_end = control::METRICS_BASE + control::METRICS_SLOTS;
        assert!(metrics_end <= control::EPOCH);
        assert!(control::EPOCH < control::OBSERVABLE_BASE);
    }
}
