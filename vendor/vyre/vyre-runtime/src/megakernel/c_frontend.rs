//! GPU-resident C frontend workspace ABI for the parser megakernel.
//!
//! This module describes the resident memory contract that a self-orchestrating
//! C frontend megakernel consumes after launch. It deliberately does not encode
//! host buffers or run a host parser: the CPU-facing surface is limited to
//! validating the compiled workspace shape and declaring the buffer ABI.

use vyre_foundation::ir::{BufferDecl, DataType, Expr, Node};

/// Binding used by the resident C frontend workspace.
///
/// Bindings `0..=3` are owned by the legacy megakernel control, ring,
/// debug-log, and IO queue buffers.
pub const C_FRONTEND_WORKSPACE_BINDING: u32 = 4;

/// Storage-buffer name used by C frontend megakernel IR nodes.
pub const C_FRONTEND_WORKSPACE_BUFFER: &str = "c_frontend_workspace";

/// Maximum resident workspace size accepted by the 0.6 protocol.
///
/// This caps manifest construction before a caller can create a huge static
/// buffer declaration that would be rejected later by a backend.
pub const MAX_C_FRONTEND_WORKSPACE_WORDS: u32 = 64 * 1024 * 1024;

/// Fixed manifest/header words at the start of the resident workspace.
pub const C_FRONTEND_MANIFEST_WORDS: u32 = 128;

/// Words per token arena record.
pub const C_FRONTEND_TOKEN_WORDS: u32 = 8;

/// Words per macro table record.
pub const C_FRONTEND_MACRO_WORDS: u32 = 12;

/// Words per conditional-stack record.
pub const C_FRONTEND_CONDITIONAL_WORDS: u32 = 4;

/// Words per VAST arena row.
pub const C_FRONTEND_VAST_ROW_WORDS: u32 = 8;

/// Words per semantic property-graph edge row.
pub const C_FRONTEND_PG_EDGE_WORDS: u32 = 8;

/// Words per resident diagnostic record.
pub const C_FRONTEND_DIAGNOSTIC_WORDS: u32 = 8;

/// Words per parser work-queue entry.
pub const C_FRONTEND_WORK_QUEUE_WORDS: u32 = 4;

/// Magic value written in the resident manifest header.
pub const C_FRONTEND_WORKSPACE_MAGIC: u32 = 0x5659_4346;

/// ABI version for the resident C frontend workspace.
pub const C_FRONTEND_WORKSPACE_ABI_VERSION: u32 = 1;

/// Manifest word indices reserved at the front of the workspace.
pub mod manifest_word {
    /// Magic word: [`super::C_FRONTEND_WORKSPACE_MAGIC`].
    pub const MAGIC: u32 = 0;
    /// ABI version word: [`super::C_FRONTEND_WORKSPACE_ABI_VERSION`].
    pub const ABI_VERSION: u32 = 1;
    /// Current phase id.
    pub const CURRENT_PHASE: u32 = 2;
    /// Requested next phase id.
    pub const REQUESTED_PHASE: u32 = 3;
    /// Non-zero when the megakernel has faulted the workspace.
    pub const STATUS: u32 = 4;
    /// Capacity diagnostic kind.
    pub const DIAGNOSTIC_KIND: u32 = 5;
    /// Region associated with the active capacity diagnostic.
    pub const DIAGNOSTIC_REGION: u32 = 6;
    /// Required words or records for the active capacity diagnostic.
    pub const DIAGNOSTIC_REQUIRED: u32 = 7;
    /// Available words or records for the active capacity diagnostic.
    pub const DIAGNOSTIC_CAPACITY: u32 = 8;
    /// Source byte count present in the resident source region.
    pub const SOURCE_BYTES: u32 = 9;
    /// Token count produced by the lexer.
    pub const TOKEN_COUNT: u32 = 10;
    /// Macro record count produced by directive handling.
    pub const MACRO_COUNT: u32 = 11;
    /// VAST row count produced by parsing.
    pub const VAST_ROW_COUNT: u32 = 12;
    /// PG edge count produced by semantic lowering.
    pub const PG_EDGE_COUNT: u32 = 13;
    /// Diagnostic record count produced by every phase.
    pub const DIAGNOSTIC_COUNT: u32 = 14;
    /// Work queue head cursor.
    pub const WORK_QUEUE_HEAD: u32 = 15;
    /// Work queue tail cursor.
    pub const WORK_QUEUE_TAIL: u32 = 16;
    /// Region table base. Each region occupies four words:
    /// `offset_words`, `words`, `record_words`, `capacity_records`.
    pub const REGION_TABLE_BASE: u32 = 32;
    /// Region-table words per region.
    pub const REGION_TABLE_ENTRY_WORDS: u32 = 4;
}

/// Resident C frontend phase identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CFrontendPhase {
    /// Workspace is resident and ready for the parser megakernel to claim.
    ResidentReady = 0,
    /// Source spans are normalized inside the resident workspace.
    Ingest = 1,
    /// Source bytes are lexed into token records.
    Lex = 2,
    /// Preprocessor directives are classified into resident metadata.
    DirectiveClassify = 3,
    /// Object-like and function-like macros are expanded.
    MacroExpand = 4,
    /// Conditional inclusion masks are resolved.
    ConditionalMask = 5,
    /// Identifiers are promoted to language/dialect keywords.
    KeywordPromote = 6,
    /// VAST rows are constructed.
    VastBuild = 7,
    /// Scope, label, type, and statement roles are classified.
    SemanticClassify = 8,
    /// Semantic property-graph edges are lowered.
    PgLower = 9,
    /// Resident artifacts and arena counts are validated.
    Validate = 10,
    /// The megakernel has completed the frontend path.
    Complete = 11,
    /// The megakernel detected a non-recoverable workspace fault.
    Fault = 12,
}

impl CFrontendPhase {
    /// Return the GPU-visible phase id.
    #[must_use]
    pub const fn id(self) -> u32 {
        self as u32
    }

    /// Decode a GPU-visible phase id.
    #[must_use]
    pub const fn from_id(id: u32) -> Option<Self> {
        match id {
            0 => Some(Self::ResidentReady),
            1 => Some(Self::Ingest),
            2 => Some(Self::Lex),
            3 => Some(Self::DirectiveClassify),
            4 => Some(Self::MacroExpand),
            5 => Some(Self::ConditionalMask),
            6 => Some(Self::KeywordPromote),
            7 => Some(Self::VastBuild),
            8 => Some(Self::SemanticClassify),
            9 => Some(Self::PgLower),
            10 => Some(Self::Validate),
            11 => Some(Self::Complete),
            12 => Some(Self::Fault),
            _ => None,
        }
    }

    /// Return the next successful phase in the parser megakernel state machine.
    #[must_use]
    pub const fn next_success(self) -> Option<Self> {
        match self {
            Self::ResidentReady => Some(Self::Ingest),
            Self::Ingest => Some(Self::Lex),
            Self::Lex => Some(Self::DirectiveClassify),
            Self::DirectiveClassify => Some(Self::MacroExpand),
            Self::MacroExpand => Some(Self::ConditionalMask),
            Self::ConditionalMask => Some(Self::KeywordPromote),
            Self::KeywordPromote => Some(Self::VastBuild),
            Self::VastBuild => Some(Self::SemanticClassify),
            Self::SemanticClassify => Some(Self::PgLower),
            Self::PgLower => Some(Self::Validate),
            Self::Validate => Some(Self::Complete),
            Self::Complete | Self::Fault => None,
        }
    }
}

/// Resident workspace arena identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CFrontendRegionId {
    /// Fixed manifest/header region.
    Manifest = 0,
    /// Resident source bytes packed into u32 words.
    SourceBytes = 1,
    /// Lexer token arena.
    Tokens = 2,
    /// Macro definition and expansion arena.
    Macros = 3,
    /// Conditional inclusion stack arena.
    Conditionals = 4,
    /// VAST row arena.
    VastRows = 5,
    /// Semantic property-graph edge arena.
    PgEdges = 6,
    /// Diagnostic record arena.
    Diagnostics = 7,
    /// Internal parser work queue.
    WorkQueue = 8,
}

impl CFrontendRegionId {
    /// Return the GPU-visible region id.
    #[must_use]
    pub const fn id(self) -> u32 {
        self as u32
    }
}

/// Capacity diagnostic kinds written by the resident frontend path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CFrontendCapacityDiagnosticKind {
    /// No capacity diagnostic is active.
    None = 0,
    /// Workspace word layout overflowed before a manifest could be built.
    WorkspaceWords = 1,
    /// Source byte region is too small.
    SourceBytes = 2,
    /// Token arena is too small.
    Tokens = 3,
    /// Macro arena is too small.
    Macros = 4,
    /// Conditional-stack arena is too small.
    Conditionals = 5,
    /// VAST row arena is too small.
    VastRows = 6,
    /// Semantic PG edge arena is too small.
    PgEdges = 7,
    /// Diagnostic arena is too small.
    Diagnostics = 8,
    /// Internal work queue is too small.
    WorkQueue = 9,
    /// Phase transition request is illegal.
    PhaseTransition = 10,
}

impl CFrontendCapacityDiagnosticKind {
    /// Return the GPU-visible diagnostic id.
    #[must_use]
    pub const fn id(self) -> u32 {
        self as u32
    }
}

/// Resident phase handler spliced into the parser megakernel.
///
/// A handler body is GPU IR only. It may read/write the C frontend workspace,
/// publish diagnostics, and then use [`c_frontend_advance_phase_nodes`] to
/// move to the next phase. Absence of a handler leaves the phase pending; the
/// builder never fabricates parser completion.
#[derive(Debug, Clone, PartialEq)]
pub struct CFrontendPhaseHandler {
    /// Phase this handler owns.
    pub phase: CFrontendPhase,
    /// GPU IR body for this phase.
    pub body: Vec<Node>,
}

impl CFrontendPhaseHandler {
    /// Build a resident phase handler.
    #[must_use]
    pub fn new(phase: CFrontendPhase, body: Vec<Node>) -> Self {
        Self { phase, body }
    }
}

/// Capacity request used to construct the resident workspace manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CFrontendWorkspaceLimits {
    /// Resident source bytes available to the megakernel.
    pub source_bytes: u32,
    /// Maximum token records.
    pub token_capacity: u32,
    /// Maximum macro records.
    pub macro_capacity: u32,
    /// Maximum nested conditional records.
    pub conditional_capacity: u32,
    /// Maximum VAST rows.
    pub vast_row_capacity: u32,
    /// Maximum semantic PG edges.
    pub pg_edge_capacity: u32,
    /// Maximum diagnostic records.
    pub diagnostic_capacity: u32,
    /// Maximum internal work-queue entries.
    pub work_queue_capacity: u32,
}

impl CFrontendWorkspaceLimits {
    /// Conservative default capacity profile for focused tests and small TUs.
    #[must_use]
    pub const fn small_translation_unit() -> Self {
        Self {
            source_bytes: 64 * 1024,
            token_capacity: 16 * 1024,
            macro_capacity: 2 * 1024,
            conditional_capacity: 512,
            vast_row_capacity: 16 * 1024,
            pg_edge_capacity: 32 * 1024,
            diagnostic_capacity: 2 * 1024,
            work_queue_capacity: 16 * 1024,
        }
    }

    /// Build a checked resident workspace manifest.
    ///
    /// # Errors
    ///
    /// Returns [`CFrontendWorkspaceError`] when a capacity is zero, arithmetic
    /// overflows, or the total resident workspace exceeds the protocol cap.
    pub fn manifest(self) -> Result<CFrontendWorkspaceManifest, CFrontendWorkspaceError> {
        CFrontendWorkspaceManifest::new(self)
    }
}

/// One contiguous region inside the resident C frontend workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CFrontendWorkspaceRegion {
    /// Region id encoded in the manifest region table.
    pub id: CFrontendRegionId,
    /// Offset from workspace word zero.
    pub offset_words: u32,
    /// Total words reserved for the region.
    pub words: u32,
    /// Words in a single logical record for this region.
    pub record_words: u32,
    /// Logical record capacity for this region.
    pub capacity_records: u32,
}

impl CFrontendWorkspaceRegion {
    /// Exclusive end offset for this region.
    #[must_use]
    pub const fn end_words(self) -> Option<u32> {
        self.offset_words.checked_add(self.words)
    }
}

/// Checked manifest for a GPU-resident C frontend workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CFrontendWorkspaceManifest {
    /// Requested capacities used to build this manifest.
    pub limits: CFrontendWorkspaceLimits,
    /// Fixed manifest/header region.
    pub manifest: CFrontendWorkspaceRegion,
    /// Resident source byte region.
    pub source_bytes: CFrontendWorkspaceRegion,
    /// Token arena region.
    pub tokens: CFrontendWorkspaceRegion,
    /// Macro arena region.
    pub macros: CFrontendWorkspaceRegion,
    /// Conditional-stack arena region.
    pub conditionals: CFrontendWorkspaceRegion,
    /// VAST row arena region.
    pub vast_rows: CFrontendWorkspaceRegion,
    /// Semantic PG edge arena region.
    pub pg_edges: CFrontendWorkspaceRegion,
    /// Diagnostic arena region.
    pub diagnostics: CFrontendWorkspaceRegion,
    /// Parser work-queue region.
    pub work_queue: CFrontendWorkspaceRegion,
    total_words: u32,
}

impl CFrontendWorkspaceManifest {
    /// Build a checked resident workspace manifest.
    ///
    /// # Errors
    ///
    /// Returns [`CFrontendWorkspaceError`] when capacities are zero, region
    /// sizing overflows, or the total workspace exceeds the ABI cap.
    pub fn new(limits: CFrontendWorkspaceLimits) -> Result<Self, CFrontendWorkspaceError> {
        validate_non_zero(limits.source_bytes, CFrontendRegionId::SourceBytes)?;
        validate_non_zero(limits.token_capacity, CFrontendRegionId::Tokens)?;
        validate_non_zero(limits.macro_capacity, CFrontendRegionId::Macros)?;
        validate_non_zero(limits.conditional_capacity, CFrontendRegionId::Conditionals)?;
        validate_non_zero(limits.vast_row_capacity, CFrontendRegionId::VastRows)?;
        validate_non_zero(limits.pg_edge_capacity, CFrontendRegionId::PgEdges)?;
        validate_non_zero(limits.diagnostic_capacity, CFrontendRegionId::Diagnostics)?;
        validate_non_zero(limits.work_queue_capacity, CFrontendRegionId::WorkQueue)?;

        let manifest = CFrontendWorkspaceRegion {
            id: CFrontendRegionId::Manifest,
            offset_words: 0,
            words: C_FRONTEND_MANIFEST_WORDS,
            record_words: 1,
            capacity_records: C_FRONTEND_MANIFEST_WORDS,
        };
        let source_words = limits.source_bytes.div_ceil(4);
        let source_bytes = next_region(
            manifest,
            CFrontendRegionId::SourceBytes,
            source_words,
            1,
            limits.source_bytes,
        )?;
        let tokens = next_record_region(
            source_bytes,
            CFrontendRegionId::Tokens,
            C_FRONTEND_TOKEN_WORDS,
            limits.token_capacity,
        )?;
        let macros = next_record_region(
            tokens,
            CFrontendRegionId::Macros,
            C_FRONTEND_MACRO_WORDS,
            limits.macro_capacity,
        )?;
        let conditionals = next_record_region(
            macros,
            CFrontendRegionId::Conditionals,
            C_FRONTEND_CONDITIONAL_WORDS,
            limits.conditional_capacity,
        )?;
        let vast_rows = next_record_region(
            conditionals,
            CFrontendRegionId::VastRows,
            C_FRONTEND_VAST_ROW_WORDS,
            limits.vast_row_capacity,
        )?;
        let pg_edges = next_record_region(
            vast_rows,
            CFrontendRegionId::PgEdges,
            C_FRONTEND_PG_EDGE_WORDS,
            limits.pg_edge_capacity,
        )?;
        let diagnostics = next_record_region(
            pg_edges,
            CFrontendRegionId::Diagnostics,
            C_FRONTEND_DIAGNOSTIC_WORDS,
            limits.diagnostic_capacity,
        )?;
        let work_queue = next_record_region(
            diagnostics,
            CFrontendRegionId::WorkQueue,
            C_FRONTEND_WORK_QUEUE_WORDS,
            limits.work_queue_capacity,
        )?;
        let total_words = work_queue
            .end_words()
            .ok_or(CFrontendWorkspaceError::WordOverflow {
                region: CFrontendRegionId::WorkQueue,
                fix: "reduce C frontend work-queue capacity or shard the resident parser workspace",
            })?;
        if total_words > MAX_C_FRONTEND_WORKSPACE_WORDS {
            return Err(CFrontendWorkspaceError::WorkspaceTooLarge {
                total_words,
                max_words: MAX_C_FRONTEND_WORKSPACE_WORDS,
                fix: "reduce C frontend capacities or split translation units across multiple resident workspaces",
            });
        }

        Ok(Self {
            limits,
            manifest,
            source_bytes,
            tokens,
            macros,
            conditionals,
            vast_rows,
            pg_edges,
            diagnostics,
            work_queue,
            total_words,
        })
    }

    /// Total u32 words in the resident workspace.
    #[must_use]
    pub const fn total_words(&self) -> u32 {
        self.total_words
    }

    /// Return all regions in on-wire order.
    #[must_use]
    pub const fn regions(&self) -> [CFrontendWorkspaceRegion; 9] {
        [
            self.manifest,
            self.source_bytes,
            self.tokens,
            self.macros,
            self.conditionals,
            self.vast_rows,
            self.pg_edges,
            self.diagnostics,
            self.work_queue,
        ]
    }

    /// Build the IR buffer declaration for this resident workspace.
    #[must_use]
    pub fn buffer_decl(&self) -> BufferDecl {
        BufferDecl::read_write(
            C_FRONTEND_WORKSPACE_BUFFER,
            C_FRONTEND_WORKSPACE_BINDING,
            DataType::U32,
        )
        .with_count(self.total_words)
        .with_pipeline_live_out(true)
    }
}

/// GPU IR that initializes the resident workspace manifest in-place.
///
/// This is launcher-safe: the CPU supplies only compile-time ABI constants in
/// the program body. The megakernel writes magic/version/region layout on
/// device when the workspace is uninitialized.
#[must_use]
pub fn c_frontend_workspace_bootstrap_nodes(manifest: &CFrontendWorkspaceManifest) -> Vec<Node> {
    let mut init = vec![
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::MAGIC),
            Expr::u32(C_FRONTEND_WORKSPACE_MAGIC),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::ABI_VERSION),
            Expr::u32(C_FRONTEND_WORKSPACE_ABI_VERSION),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::CURRENT_PHASE),
            Expr::u32(CFrontendPhase::ResidentReady.id()),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::REQUESTED_PHASE),
            Expr::u32(CFrontendPhase::ResidentReady.id()),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::STATUS),
            Expr::u32(0),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::DIAGNOSTIC_KIND),
            Expr::u32(CFrontendCapacityDiagnosticKind::None.id()),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::DIAGNOSTIC_REGION),
            Expr::u32(CFrontendRegionId::Manifest.id()),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::DIAGNOSTIC_REQUIRED),
            Expr::u32(0),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::DIAGNOSTIC_CAPACITY),
            Expr::u32(0),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::TOKEN_COUNT),
            Expr::u32(0),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::MACRO_COUNT),
            Expr::u32(0),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::VAST_ROW_COUNT),
            Expr::u32(0),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::PG_EDGE_COUNT),
            Expr::u32(0),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::DIAGNOSTIC_COUNT),
            Expr::u32(0),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::WORK_QUEUE_HEAD),
            Expr::u32(0),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::WORK_QUEUE_TAIL),
            Expr::u32(0),
        ),
    ];

    for region in manifest.regions() {
        init.extend(region_manifest_store_nodes(region));
    }

    vec![Node::if_then(
        Expr::eq(Expr::gid_x(), Expr::u32(0)),
        vec![
            Node::let_bind(
                "c_frontend_bootstrap_magic",
                Expr::load(C_FRONTEND_WORKSPACE_BUFFER, Expr::u32(manifest_word::MAGIC)),
            ),
            Node::if_then(
                Expr::ne(
                    Expr::var("c_frontend_bootstrap_magic"),
                    Expr::u32(C_FRONTEND_WORKSPACE_MAGIC),
                ),
                init,
            ),
        ],
    )]
}

/// GPU IR that dispatches resident C frontend phase handlers.
///
/// Only global invocation zero runs the control-plane phase machine. Data-plane
/// phase bodies may internally fan out across lanes/workgroups. If no handler
/// owns the current phase, this fragment leaves the phase unchanged.
#[must_use]
pub fn c_frontend_phase_dispatch_nodes(handlers: &[CFrontendPhaseHandler]) -> Vec<Node> {
    let mut dispatch = vec![
        Node::let_bind(
            "c_frontend_status",
            Expr::load(
                C_FRONTEND_WORKSPACE_BUFFER,
                Expr::u32(manifest_word::STATUS),
            ),
        ),
        Node::let_bind(
            "c_frontend_phase",
            Expr::load(
                C_FRONTEND_WORKSPACE_BUFFER,
                Expr::u32(manifest_word::CURRENT_PHASE),
            ),
        ),
    ];

    for handler in handlers {
        dispatch.push(Node::if_then(
            Expr::and(
                Expr::eq(Expr::var("c_frontend_status"), Expr::u32(0)),
                Expr::eq(Expr::var("c_frontend_phase"), Expr::u32(handler.phase.id())),
            ),
            handler.body.clone(),
        ));
    }

    vec![Node::if_then(
        Expr::eq(Expr::gid_x(), Expr::u32(0)),
        dispatch,
    )]
}

/// GPU IR that validates the resident requested/current phase pair.
///
/// The guard runs before phase dispatch. It does not fabricate progress: it
/// only faults malformed resident state so later handlers cannot silently run
/// against an impossible phase-machine edge.
#[must_use]
pub fn c_frontend_phase_machine_guard_nodes() -> Vec<Node> {
    vec![Node::if_then(
        Expr::eq(Expr::gid_x(), Expr::u32(0)),
        vec![
            Node::let_bind(
                "c_frontend_guard_status",
                Expr::load(
                    C_FRONTEND_WORKSPACE_BUFFER,
                    Expr::u32(manifest_word::STATUS),
                ),
            ),
            Node::let_bind(
                "c_frontend_guard_current_phase",
                Expr::load(
                    C_FRONTEND_WORKSPACE_BUFFER,
                    Expr::u32(manifest_word::CURRENT_PHASE),
                ),
            ),
            Node::let_bind(
                "c_frontend_guard_requested_phase",
                Expr::load(
                    C_FRONTEND_WORKSPACE_BUFFER,
                    Expr::u32(manifest_word::REQUESTED_PHASE),
                ),
            ),
            Node::if_then(
                Expr::and(
                    Expr::eq(Expr::var("c_frontend_guard_status"), Expr::u32(0)),
                    Expr::ne(
                        Expr::var("c_frontend_guard_requested_phase"),
                        Expr::var("c_frontend_guard_current_phase"),
                    ),
                ),
                vec![Node::if_then(
                    Expr::eq(c_frontend_requested_phase_valid_expr(), Expr::bool(false)),
                    c_frontend_fault_expr_nodes(
                        CFrontendCapacityDiagnosticKind::PhaseTransition,
                        CFrontendRegionId::Manifest,
                        Expr::var("c_frontend_guard_requested_phase"),
                        Expr::var("c_frontend_guard_current_phase"),
                    ),
                )],
            ),
        ],
    )]
}

/// GPU IR that advances a resident phase after a successful handler.
#[must_use]
pub fn c_frontend_advance_phase_nodes(
    from: CFrontendPhase,
    to: CFrontendPhase,
) -> Result<Vec<Node>, CFrontendWorkspaceError> {
    validate_c_frontend_phase_transition(from, to)?;
    Ok(vec![
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::REQUESTED_PHASE),
            Expr::u32(to.id()),
        ),
        Node::let_bind(
            "c_frontend_phase_prev",
            Expr::atomic_compare_exchange(
                C_FRONTEND_WORKSPACE_BUFFER,
                Expr::u32(manifest_word::CURRENT_PHASE),
                Expr::u32(from.id()),
                Expr::u32(to.id()),
            ),
        ),
        Node::if_then(
            Expr::ne(Expr::var("c_frontend_phase_prev"), Expr::u32(from.id())),
            c_frontend_fault_nodes(
                CFrontendCapacityDiagnosticKind::PhaseTransition,
                CFrontendRegionId::Manifest,
                to.id(),
                from.id(),
            ),
        ),
    ])
}

/// GPU IR that faults the resident C frontend workspace with a structured
/// diagnostic in manifest words.
#[must_use]
pub fn c_frontend_fault_nodes(
    kind: CFrontendCapacityDiagnosticKind,
    region: CFrontendRegionId,
    required: u32,
    capacity: u32,
) -> Vec<Node> {
    c_frontend_fault_expr_nodes(kind, region, Expr::u32(required), Expr::u32(capacity))
}

fn c_frontend_fault_expr_nodes(
    kind: CFrontendCapacityDiagnosticKind,
    region: CFrontendRegionId,
    required: Expr,
    capacity: Expr,
) -> Vec<Node> {
    vec![
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::DIAGNOSTIC_KIND),
            Expr::u32(kind.id()),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::DIAGNOSTIC_REGION),
            Expr::u32(region.id()),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::DIAGNOSTIC_REQUIRED),
            required,
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::DIAGNOSTIC_CAPACITY),
            capacity,
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::DIAGNOSTIC_COUNT),
            Expr::u32(1),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::STATUS),
            Expr::u32(kind.id()),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(manifest_word::CURRENT_PHASE),
            Expr::u32(CFrontendPhase::Fault.id()),
        ),
    ]
}

fn c_frontend_requested_phase_valid_expr() -> Expr {
    let current = Expr::var("c_frontend_guard_current_phase");
    let requested = Expr::var("c_frontend_guard_requested_phase");
    let in_range = Expr::and(
        Expr::le(current.clone(), Expr::u32(CFrontendPhase::Fault.id())),
        Expr::le(requested.clone(), Expr::u32(CFrontendPhase::Fault.id())),
    );
    let sequential = Expr::and(
        Expr::le(current.clone(), Expr::u32(CFrontendPhase::Validate.id())),
        Expr::eq(requested.clone(), Expr::add(current.clone(), Expr::u32(1))),
    );
    let reset_after_complete = Expr::and(
        Expr::eq(current.clone(), Expr::u32(CFrontendPhase::Complete.id())),
        Expr::eq(
            requested.clone(),
            Expr::u32(CFrontendPhase::ResidentReady.id()),
        ),
    );
    let requested_fault = Expr::eq(requested, Expr::u32(CFrontendPhase::Fault.id()));
    Expr::and(
        in_range,
        Expr::or(Expr::or(sequential, reset_after_complete), requested_fault),
    )
}

fn region_manifest_store_nodes(region: CFrontendWorkspaceRegion) -> Vec<Node> {
    let base =
        manifest_word::REGION_TABLE_BASE + region.id.id() * manifest_word::REGION_TABLE_ENTRY_WORDS;
    vec![
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(base),
            Expr::u32(region.offset_words),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(base + 1),
            Expr::u32(region.words),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(base + 2),
            Expr::u32(region.record_words),
        ),
        Node::store(
            C_FRONTEND_WORKSPACE_BUFFER,
            Expr::u32(base + 3),
            Expr::u32(region.capacity_records),
        ),
    ]
}

/// Error returned by resident C frontend workspace validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CFrontendWorkspaceError {
    /// A required region has zero capacity.
    #[error("{region:?} capacity is zero. Fix: reserve at least one resident record for every C frontend region so the megakernel never falls back to host state")]
    ZeroCapacity {
        /// Region with zero capacity.
        region: CFrontendRegionId,
    },
    /// Region word arithmetic overflowed.
    #[error("{region:?} word layout overflowed. Fix: {fix}")]
    WordOverflow {
        /// Region being sized when arithmetic overflowed.
        region: CFrontendRegionId,
        /// Actionable remediation.
        fix: &'static str,
    },
    /// Total workspace words exceed the ABI cap.
    #[error("C frontend workspace needs {total_words} words, cap is {max_words}. Fix: {fix}")]
    WorkspaceTooLarge {
        /// Requested total words.
        total_words: u32,
        /// Maximum accepted words.
        max_words: u32,
        /// Actionable remediation.
        fix: &'static str,
    },
    /// A requested phase transition is illegal.
    #[error("illegal C frontend phase transition {from:?} -> {to:?}. Fix: parser megakernel phases must advance linearly or transition to Fault with a diagnostic")]
    InvalidPhaseTransition {
        /// Current phase.
        from: CFrontendPhase,
        /// Requested phase.
        to: CFrontendPhase,
    },
}

/// Return true if `from -> to` is accepted by the resident phase machine.
#[must_use]
pub const fn is_valid_c_frontend_phase_transition(
    from: CFrontendPhase,
    to: CFrontendPhase,
) -> bool {
    matches!(to, CFrontendPhase::Fault)
        || matches!(from.next_success(), Some(next) if next.id() == to.id())
        || matches!(
            (from, to),
            (CFrontendPhase::Complete, CFrontendPhase::ResidentReady)
        )
}

/// Validate a resident C frontend phase transition.
///
/// # Errors
///
/// Returns [`CFrontendWorkspaceError::InvalidPhaseTransition`] if the
/// transition skips a successful phase or attempts to leave `Fault`.
pub fn validate_c_frontend_phase_transition(
    from: CFrontendPhase,
    to: CFrontendPhase,
) -> Result<(), CFrontendWorkspaceError> {
    if is_valid_c_frontend_phase_transition(from, to) {
        Ok(())
    } else {
        Err(CFrontendWorkspaceError::InvalidPhaseTransition { from, to })
    }
}

fn validate_non_zero(
    capacity: u32,
    region: CFrontendRegionId,
) -> Result<(), CFrontendWorkspaceError> {
    if capacity == 0 {
        Err(CFrontendWorkspaceError::ZeroCapacity { region })
    } else {
        Ok(())
    }
}

fn next_record_region(
    previous: CFrontendWorkspaceRegion,
    id: CFrontendRegionId,
    record_words: u32,
    capacity_records: u32,
) -> Result<CFrontendWorkspaceRegion, CFrontendWorkspaceError> {
    let words = record_words.checked_mul(capacity_records).ok_or(
        CFrontendWorkspaceError::WordOverflow {
            region: id,
            fix: "reduce C frontend arena capacity so record_words * capacity fits u32",
        },
    )?;
    next_region(previous, id, words, record_words, capacity_records)
}

fn next_region(
    previous: CFrontendWorkspaceRegion,
    id: CFrontendRegionId,
    words: u32,
    record_words: u32,
    capacity_records: u32,
) -> Result<CFrontendWorkspaceRegion, CFrontendWorkspaceError> {
    let offset_words = previous
        .end_words()
        .ok_or(CFrontendWorkspaceError::WordOverflow {
            region: previous.id,
            fix: "reduce C frontend arena capacity so region offsets fit u32",
        })?;
    Ok(CFrontendWorkspaceRegion {
        id,
        offset_words,
        words,
        record_words,
        capacity_records,
    })
}
