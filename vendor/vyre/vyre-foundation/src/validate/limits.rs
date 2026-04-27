// Shared safety limits for bounded IR operation builders.

/// Maximum graph nodes accepted by host-side graph builders.
pub const MAX_GRAPH_NODES: usize = 16_000_000;
/// Maximum graph edges accepted by host-side graph builders.
pub const MAX_GRAPH_EDGES: usize = 64_000_000;
/// Maximum DFA states accepted by DFA scan builders.
pub const MAX_DFA_STATES: u32 = 1_000_000;
/// Maximum per-invocation BFS queue slots.
pub const MAX_BFS_QUEUE: u32 = 65_536;
