//! IR program builders — construct the megakernel `Program` from vyre IR.
//!
//! Two flavours:
//! - **Interpreted** (`build_program_sharded`) — If-tree opcode dispatch.
//! - **JIT** (`build_program_jit`) — payload processor fused directly.

use vyre_foundation::ir::{BufferDecl, DataType, Expr, Node, Program};

use super::c_frontend::{
    c_frontend_phase_dispatch_nodes, c_frontend_phase_machine_guard_nodes,
    c_frontend_workspace_bootstrap_nodes, CFrontendPhaseHandler, CFrontendWorkspaceManifest,
};
use super::handlers::{claimed_slot_body, OpcodeHandler};
use super::io::{
    io_word, IO_DESTINATION_CAPABILITY_TABLE, IO_QUEUE_DMA_TAG, IO_SLOT_COUNT, IO_SLOT_WORDS,
    IO_SOURCE_CAPABILITY_TABLE,
};
use super::protocol::*;

/// Emits a Relaxed atomic load.
/// WGSL atomics are implicitly Relaxed; explicit Acquire/Release requires memory barriers.
fn atomic_load_relaxed(buffer: &str, index: Expr) -> Expr {
    Expr::atomic_add(buffer, index, Expr::u32(0))
}

/// Build the default megakernel IR (256 lanes × 1 workgroup, no custom opcodes).
#[must_use]
pub fn build_program() -> Program {
    build_program_sharded(256, &[])
}

/// Build the megakernel IR with a custom workgroup size and optional
/// custom opcodes.
///
/// Buffers are declared with concrete `with_count(...)` sizes so the
/// wgpu readback layer allocates the right static staging size — a
/// `count=0` default reads back 4 bytes regardless of how much the
/// kernel wrote.
#[must_use]
pub fn build_program_sharded(workgroup_size_x: u32, opcodes: &[OpcodeHandler]) -> Program {
    build_program_sharded_slots(workgroup_size_x, workgroup_size_x.max(1), opcodes)
}

/// Build the megakernel IR for an explicit number of ring slots.
///
/// This is the production sharded ABI: `slot_count` sizes the ring buffer,
/// while `workgroup_size_x` controls lanes per workgroup. Dispatch must launch
/// `slot_count / workgroup_size_x` workgroups so every slot has an owning lane.
#[must_use]
pub fn build_program_sharded_slots(
    workgroup_size_x: u32,
    slot_count: u32,
    opcodes: &[OpcodeHandler],
) -> Program {
    build_program_sharded_slots_with_io(workgroup_size_x, slot_count, opcodes, false)
}

/// Build the sharded megakernel IR with a resident C frontend workspace ABI.
///
/// This declares the parser workspace buffer that a self-orchestrating C
/// frontend megakernel path consumes after launch. It does not add host parser
/// semantics; language work must be implemented as megakernel IR against the
/// resident workspace.
#[must_use]
pub fn build_program_sharded_with_c_frontend_workspace(
    workgroup_size_x: u32,
    slot_count: u32,
    opcodes: &[OpcodeHandler],
    manifest: &CFrontendWorkspaceManifest,
) -> Program {
    build_program_sharded_with_c_frontend_workspace_phases(
        workgroup_size_x,
        slot_count,
        opcodes,
        manifest,
        &[],
    )
}

/// Build the sharded megakernel IR with resident C frontend phase handlers.
///
/// This is the production composition point for the one-dispatch C frontend:
/// the CPU declares the resident workspace and launches the megakernel; parser
/// phases are explicit GPU IR handlers selected from manifest phase words.
#[must_use]
pub fn build_program_sharded_with_c_frontend_workspace_phases(
    workgroup_size_x: u32,
    slot_count: u32,
    opcodes: &[OpcodeHandler],
    manifest: &CFrontendWorkspaceManifest,
    c_frontend_handlers: &[CFrontendPhaseHandler],
) -> Program {
    wrap_persistent_megakernel_program_with_buffers(
        default_buffers_with_c_frontend_workspace(slot_count, manifest),
        workgroup_size_x,
        persistent_body_with_c_frontend(workgroup_size_x, opcodes, manifest, c_frontend_handlers),
    )
}

/// Build a finite one-pass sharded megakernel IR for host-submitted batches.
///
/// Unlike [`build_program_sharded_slots`], this program does not wrap the body
/// in `Node::forever`; each lane attempts to drain its owning slot once and the
/// dispatch returns. Use this for synchronous batch APIs that need a completion
/// report from the same queue submission.
#[must_use]
pub fn build_program_sharded_once_slots(
    workgroup_size_x: u32,
    slot_count: u32,
    opcodes: &[OpcodeHandler],
) -> Program {
    wrap_megakernel_program(
        workgroup_size_x,
        slot_count,
        persistent_body_with_io(workgroup_size_x, opcodes, false),
    )
}

/// Build the megakernel IR without the IO polling sidecar.
///
/// This is the dispatch path for host-provided [`vyre_driver_megakernel::WorkItem`]
/// queues. It keeps the executable kernel free of `AsyncLoad` nodes until the
/// runtime scheduler owns a concrete async-lowering pass.
#[must_use]
pub fn build_program_sharded_no_io(workgroup_size_x: u32, opcodes: &[OpcodeHandler]) -> Program {
    build_program_sharded_slots(workgroup_size_x, workgroup_size_x.max(1), opcodes)
}

/// Build the megakernel IR with the experimental IO polling sidecar.
///
/// The returned Program contains `AsyncLoad` nodes and must be lowered through
/// a runtime scheduler pass before reaching the wgpu code generator.
#[must_use]
pub fn build_program_sharded_with_io_polling(
    workgroup_size_x: u32,
    opcodes: &[OpcodeHandler],
) -> Program {
    build_program_sharded_slots_with_io(workgroup_size_x, workgroup_size_x.max(1), opcodes, true)
}

fn build_program_sharded_slots_with_io(
    workgroup_size_x: u32,
    slot_count: u32,
    opcodes: &[OpcodeHandler],
    include_io_polling: bool,
) -> Program {
    wrap_persistent_megakernel_program(
        workgroup_size_x,
        slot_count,
        persistent_body_with_io(workgroup_size_x, opcodes, include_io_polling),
    )
}

/// Build the JIT Megakernel IR where payload processor logic is fused into the body stream.
#[must_use]
pub fn build_program_jit(workgroup_size_x: u32, payload_processor: &[Node]) -> Program {
    build_program_jit_slots(workgroup_size_x, workgroup_size_x.max(1), payload_processor)
}

/// Build the JIT megakernel IR for an explicit number of ring slots.
#[must_use]
pub fn build_program_jit_slots(
    workgroup_size_x: u32,
    slot_count: u32,
    payload_processor: &[Node],
) -> Program {
    wrap_persistent_megakernel_program(
        workgroup_size_x,
        slot_count,
        persistent_body_jit(workgroup_size_x, payload_processor),
    )
}

fn wrap_persistent_megakernel_program(
    workgroup_size_x: u32,
    slot_count: u32,
    body: Vec<Node>,
) -> Program {
    wrap_megakernel_program(workgroup_size_x, slot_count, vec![Node::forever(body)])
}

fn wrap_persistent_megakernel_program_with_buffers(
    buffers: Vec<BufferDecl>,
    workgroup_size_x: u32,
    body: Vec<Node>,
) -> Program {
    Program::wrapped(buffers, [workgroup_size_x, 1, 1], vec![Node::forever(body)])
}

fn wrap_megakernel_program(workgroup_size_x: u32, slot_count: u32, body: Vec<Node>) -> Program {
    Program::wrapped(default_buffers(slot_count), [workgroup_size_x, 1, 1], body)
}

/// Reserve sizes for the megakernel's four host-visible buffers. All
/// four go through wgpu's static-readback path so every buffer needs
/// a concrete `count` (u32 elements). The numbers mirror the wire
/// layout in `protocol.rs`:
///
/// - **control**: 128 u32 words covers SHUTDOWN, DONE_COUNT, EPOCH,
///   METRICS_BASE..METRICS_BASE+METRICS_SLOTS, OBSERVABLE_BASE, and
///   the 32-entry tenant-mask table.
/// - **ring_buffer**: `slot_count` slots × `SLOT_WORDS`.
///   `slot_count` must match host-published ring bytes and dispatch geometry.
/// - **debug_log**: cursor word + `debug::RECORD_CAPACITY` × 4-word records.
/// - **io_queue**: 64 slots × 8 words (source, destination,
///   offset_low, offset_high, size, status, tag, pad).
fn default_buffers(slot_count: u32) -> Vec<BufferDecl> {
    let ring_slots = slot_count.max(1);
    let control = BufferDecl::read_write("control", 0, DataType::U32).with_count(CONTROL_MIN_WORDS);
    let ring_buffer = BufferDecl::read_write("ring_buffer", 1, DataType::U32)
        .with_count(ring_slots.saturating_mul(SLOT_WORDS));
    let debug_log =
        BufferDecl::read_write("debug_log", 2, DataType::U32).with_count(debug::BUFFER_WORDS);
    let io_queue = BufferDecl::read_write("io_queue", 3, DataType::U32).with_count(64 * 8);
    vec![control, ring_buffer, debug_log, io_queue]
}

fn default_buffers_with_c_frontend_workspace(
    slot_count: u32,
    manifest: &CFrontendWorkspaceManifest,
) -> Vec<BufferDecl> {
    let mut buffers = default_buffers(slot_count);
    buffers.push(manifest.buffer_decl());
    buffers
}

/// The body that runs once per iteration per lane. Exposed for tests
/// and downstream crates that splice additional opcodes.
#[must_use]
pub fn persistent_body(workgroup_size_x: u32, opcodes: &[OpcodeHandler]) -> Vec<Node> {
    persistent_body_with_io(workgroup_size_x, opcodes, false)
}

fn persistent_body_with_io(
    workgroup_size_x: u32,
    opcodes: &[OpcodeHandler],
    include_io_polling: bool,
) -> Vec<Node> {
    let mut body = vec![
        // -- Exit fast on shutdown. ------------------------------------
        Node::let_bind(
            "shutdown_flag",
            atomic_load_relaxed("control", Expr::u32(control::SHUTDOWN)),
        ),
        Node::if_then(
            Expr::ne(Expr::var("shutdown_flag"), Expr::u32(0)),
            vec![Node::Return],
        ),
        // -- Compute this lane's global slot index. --------------------
        Node::let_bind(
            "lane_id",
            Expr::add(
                Expr::mul(Expr::workgroup_x(), Expr::u32(workgroup_size_x)),
                Expr::local_x(),
            ),
        ),
        Node::let_bind(
            "slot_base",
            Expr::mul(Expr::var("lane_id"), Expr::u32(SLOT_WORDS)),
        ),
        // -- Tenant check. ------
        Node::let_bind(
            "tenant_id",
            Expr::load(
                "ring_buffer",
                Expr::add(Expr::var("slot_base"), Expr::u32(TENANT_WORD)),
            ),
        ),
        Node::let_bind(
            "tenant_base",
            atomic_load_relaxed("control", Expr::u32(control::TENANT_BASE)),
        ),
        Node::let_bind(
            "tenant_mask",
            atomic_load_relaxed(
                "control",
                Expr::add(Expr::var("tenant_base"), Expr::var("tenant_id")),
            ),
        ),
        Node::if_then(
            Expr::ne(Expr::var("tenant_mask"), Expr::u32(0)),
            tenant_body(opcodes, include_io_polling),
        ),
    ];

    body.reserve(0);
    body
}

fn persistent_body_with_c_frontend(
    workgroup_size_x: u32,
    opcodes: &[OpcodeHandler],
    manifest: &CFrontendWorkspaceManifest,
    c_frontend_handlers: &[CFrontendPhaseHandler],
) -> Vec<Node> {
    let mut body = c_frontend_workspace_bootstrap_nodes(manifest);
    body.extend(c_frontend_phase_machine_guard_nodes());
    body.extend(c_frontend_phase_dispatch_nodes(c_frontend_handlers));
    body.extend(persistent_body_with_io(workgroup_size_x, opcodes, false));
    body
}

fn tenant_body(opcodes: &[OpcodeHandler], include_io_polling: bool) -> Vec<Node> {
    let mut body = vec![Node::Block(execute_slot_body(opcodes))];
    if include_io_polling {
        body.push(Node::Block(process_io_requests()));
    }
    body
}

fn process_io_requests() -> Vec<Node> {
    let nodes = vec![Node::loop_for(
        "io_idx",
        Expr::u32(0),
        Expr::u32(IO_SLOT_COUNT),
        vec![
            Node::let_bind(
                "io_base",
                Expr::mul(Expr::var("io_idx"), Expr::u32(IO_SLOT_WORDS)),
            ),
            Node::let_bind(
                "io_status_idx",
                Expr::add(Expr::var("io_base"), Expr::u32(io_word::STATUS)),
            ),
            // CAS PUBLISHED -> CLAIMED
            Node::let_bind(
                "prev_io_status",
                Expr::atomic_compare_exchange(
                    "io_queue",
                    Expr::var("io_status_idx"),
                    Expr::u32(slot::PUBLISHED),
                    Expr::u32(slot::CLAIMED),
                ),
            ),
            Node::if_then(
                Expr::eq(Expr::var("prev_io_status"), Expr::u32(slot::PUBLISHED)),
                vec![
                    Node::let_bind(
                        "io_src_handle",
                        Expr::load(
                            "io_queue",
                            Expr::add(Expr::var("io_base"), Expr::u32(io_word::SRC_HANDLE)),
                        ),
                    ),
                    Node::let_bind(
                        "io_dst_handle",
                        Expr::load(
                            "io_queue",
                            Expr::add(Expr::var("io_base"), Expr::u32(io_word::DST_HANDLE)),
                        ),
                    ),
                    Node::AsyncLoad {
                        source: IO_SOURCE_CAPABILITY_TABLE.into(),
                        destination: IO_DESTINATION_CAPABILITY_TABLE.into(),
                        offset: Box::new(Expr::load(
                            "io_queue",
                            Expr::add(Expr::var("io_base"), Expr::u32(io_word::OFFSET_LO)),
                        )),
                        size: Box::new(Expr::load(
                            "io_queue",
                            Expr::add(Expr::var("io_base"), Expr::u32(io_word::BYTE_COUNT)),
                        )),
                        tag: IO_QUEUE_DMA_TAG.into(),
                    },
                    // Mark as DONE
                    Node::store(
                        "io_queue",
                        Expr::var("io_status_idx"),
                        Expr::u32(slot::DONE),
                    ),
                ],
            ),
        ],
    )];

    nodes
}

fn execute_slot_body(opcodes: &[OpcodeHandler]) -> Vec<Node> {
    vec![
        Node::let_bind(
            "status_index",
            Expr::add(Expr::var("slot_base"), Expr::u32(STATUS_WORD)),
        ),
        // CAS PUBLISHED -> CLAIMED.
        Node::let_bind(
            "prev_status",
            Expr::atomic_compare_exchange(
                "ring_buffer",
                Expr::var("status_index"),
                Expr::u32(slot::PUBLISHED),
                Expr::u32(slot::CLAIMED),
            ),
        ),
        Node::if_then(
            Expr::eq(Expr::var("prev_status"), Expr::u32(slot::PUBLISHED)),
            claimed_slot_body(opcodes),
        ),
    ]
}

// ---- JIT variant ----

/// The JIT body that runs once per iteration per lane.
#[must_use]
pub fn persistent_body_jit(workgroup_size_x: u32, payload_processor: &[Node]) -> Vec<Node> {
    let mut body = vec![
        Node::let_bind(
            "shutdown_flag",
            atomic_load_relaxed("control", Expr::u32(control::SHUTDOWN)),
        ),
        Node::if_then(
            Expr::ne(Expr::var("shutdown_flag"), Expr::u32(0)),
            vec![Node::Return],
        ),
        Node::let_bind(
            "lane_id",
            Expr::add(
                Expr::mul(Expr::workgroup_x(), Expr::u32(workgroup_size_x)),
                Expr::local_x(),
            ),
        ),
        Node::let_bind(
            "slot_base",
            Expr::mul(Expr::var("lane_id"), Expr::u32(SLOT_WORDS)),
        ),
        Node::let_bind(
            "tenant_id",
            Expr::load(
                "ring_buffer",
                Expr::add(Expr::var("slot_base"), Expr::u32(TENANT_WORD)),
            ),
        ),
        Node::let_bind(
            "tenant_base",
            atomic_load_relaxed("control", Expr::u32(control::TENANT_BASE)),
        ),
        Node::let_bind(
            "tenant_mask",
            atomic_load_relaxed(
                "control",
                Expr::add(Expr::var("tenant_base"), Expr::var("tenant_id")),
            ),
        ),
        Node::if_then(
            Expr::ne(Expr::var("tenant_mask"), Expr::u32(0)),
            vec![
                Node::Block(execute_slot_body_jit(payload_processor)),
                Node::Block(process_io_requests()),
            ],
        ),
    ];
    body.reserve(0);
    body
}

fn execute_slot_body_jit(payload_processor: &[Node]) -> Vec<Node> {
    vec![
        Node::let_bind(
            "status_index",
            Expr::add(Expr::var("slot_base"), Expr::u32(STATUS_WORD)),
        ),
        Node::let_bind(
            "prev_status",
            Expr::atomic_compare_exchange(
                "ring_buffer",
                Expr::var("status_index"),
                Expr::u32(slot::PUBLISHED),
                Expr::u32(slot::CLAIMED),
            ),
        ),
        Node::if_then(
            Expr::eq(Expr::var("prev_status"), Expr::u32(slot::PUBLISHED)),
            claimed_slot_body_jit(payload_processor),
        ),
    ]
}

fn claimed_slot_body_jit(payload_processor: &[Node]) -> Vec<Node> {
    let mut nodes = Vec::new();

    // Wire the statically JIT-compiled rule/payload evaluation graph.
    nodes.extend(payload_processor.iter().cloned());

    nodes.push(Node::let_bind(
        "done_prev",
        Expr::atomic_add("control", Expr::u32(control::DONE_COUNT), Expr::u32(1)),
    ));
    nodes.push(Node::store(
        "ring_buffer",
        Expr::var("status_index"),
        Expr::u32(slot::DONE),
    ));
    nodes
}

// ---- Priority-aware variant ----

/// Build a priority-aware megakernel IR.
///
/// Unlike `build_program_sharded` where each lane owns exactly one slot,
/// the priority variant has workers scan across priority-partitioned ring
/// regions, claiming the highest-priority PUBLISHED slot available. This
/// ensures latency-sensitive work (CRITICAL, HIGH) is processed before
/// background tasks (LOW, IDLE).
///
/// The control buffer is extended with `PRIORITY_OFFSETS_BASE..+6` words
/// that the host sets to define partition boundaries. The host can
/// dynamically resize partitions by updating these offsets between batches.
#[must_use]
pub fn build_program_priority(workgroup_size_x: u32, opcodes: &[OpcodeHandler]) -> Program {
    wrap_persistent_megakernel_program(
        workgroup_size_x,
        workgroup_size_x.max(1),
        persistent_body_priority(workgroup_size_x, opcodes),
    )
}

/// Priority-aware loop body. Replaces the per-lane 1:1 slot mapping
/// with the scheduler's priority scan.
#[must_use]
pub fn persistent_body_priority(workgroup_size_x: u32, opcodes: &[OpcodeHandler]) -> Vec<Node> {
    use super::scheduler;

    let lane_count = workgroup_size_x.max(1);
    let mut body = vec![
        // -- Exit fast on shutdown. ------------------------------------
        Node::let_bind(
            "shutdown_flag",
            atomic_load_relaxed("control", Expr::u32(control::SHUTDOWN)),
        ),
        Node::if_then(
            Expr::ne(Expr::var("shutdown_flag"), Expr::u32(0)),
            vec![Node::Return],
        ),
    ];

    // -- Priority scan: find and claim the best available slot. --------
    body.extend(scheduler::priority_scan_body(lane_count));

    // -- If claimed, execute the slot. ---------------------------------
    body.push(Node::if_then(
        Expr::ne(Expr::var("claimed_slot_base"), Expr::u32(u32::MAX)),
        {
            // Rebind `slot_base` to the claimed slot so downstream
            // handler code works unchanged.
            let mut exec = vec![Node::let_bind("slot_base", Expr::var("claimed_slot_base"))];

            // Tenant check on the claimed slot
            exec.extend(vec![
                Node::let_bind(
                    "status_index",
                    Expr::add(Expr::var("slot_base"), Expr::u32(STATUS_WORD)),
                ),
                Node::let_bind(
                    "tenant_id",
                    Expr::load(
                        "ring_buffer",
                        Expr::add(Expr::var("slot_base"), Expr::u32(TENANT_WORD)),
                    ),
                ),
                Node::let_bind(
                    "tenant_base",
                    atomic_load_relaxed("control", Expr::u32(control::TENANT_BASE)),
                ),
                Node::let_bind(
                    "tenant_mask",
                    atomic_load_relaxed(
                        "control",
                        Expr::add(Expr::var("tenant_base"), Expr::var("tenant_id")),
                    ),
                ),
                Node::if_then(
                    Expr::ne(Expr::var("tenant_mask"), Expr::u32(0)),
                    claimed_slot_body(opcodes),
                ),
            ]);

            exec
        },
    ));

    // -- IO poll (same as base variant). --------------------------------
    body.push(Node::Block(process_io_requests()));

    body
}

#[cfg(test)]
mod tests {
    use super::*;

    fn async_load_bindings(nodes: &[Node], out: &mut Vec<(String, String, String)>) {
        for node in nodes {
            match node {
                Node::AsyncLoad {
                    source,
                    destination,
                    tag,
                    ..
                } => out.push((
                    source.as_str().to_string(),
                    destination.as_str().to_string(),
                    tag.as_str().to_string(),
                )),
                Node::If {
                    then, otherwise, ..
                } => {
                    async_load_bindings(then, out);
                    async_load_bindings(otherwise, out);
                }
                Node::Loop { body, .. } | Node::Block(body) => async_load_bindings(body, out),
                Node::Region { body, .. } => async_load_bindings(body, out),
                _ => {}
            }
        }
    }

    #[test]
    fn io_polling_uses_capability_tables_not_fake_resource_names() {
        let program = build_program_sharded_with_io_polling(64, &[]);
        let mut bindings = Vec::new();
        async_load_bindings(&program.entry, &mut bindings);
        assert_eq!(bindings.len(), 1);
        let (source, destination, tag) = &bindings[0];
        assert_eq!(source, "io_source_capability_table");
        assert_eq!(destination, "io_destination_capability_table");
        assert_eq!(tag, "io_queue_dma");
        assert_ne!(source, "ssd_weights");
        assert_ne!(destination, "vram_cache");
    }
}
