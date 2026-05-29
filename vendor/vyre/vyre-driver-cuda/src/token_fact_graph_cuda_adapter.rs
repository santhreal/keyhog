//! CUDA adapter for the unified resident token/fact graph.

use crate::backend::accounting::{
    checked_add_u64_count as checked_add, checked_mul_u64_count as checked_mul,
    CudaArithmeticOverflow,
};
use crate::megakernel_scheduler::CudaMegakernelGraphShape;
use vyre_self_substrate::device_resident_token_fact_graph::DeviceResidentTokenFactGraph;

/// CUDA resident byte envelope for the unified compiler/dataflow graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaTokenFactGraphLayout {
    /// Scheduler-visible graph shape.
    pub graph_shape: CudaMegakernelGraphShape,
    /// Fixed bytes per resident node record.
    pub node_record_bytes: u64,
    /// Fixed bytes per resident edge record.
    pub edge_record_bytes: u64,
    /// Bytes for resident node records.
    pub node_bytes: u64,
    /// Bytes for resident edge records.
    pub edge_bytes: u64,
    /// Bytes for the shared token/fact payload slab.
    pub payload_bytes: u64,
    /// Total bytes that must remain device-resident for the layout.
    pub resident_bytes: u64,
}

/// CUDA token/fact adapter errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CudaTokenFactGraphLayoutError {
    /// Record widths must be explicit, non-zero ABI values.
    ZeroRecordWidth {
        /// Field that was zero.
        field: &'static str,
    },
    /// Byte arithmetic overflowed.
    ByteCountOverflow {
        /// Field being computed.
        field: &'static str,
    },
}

impl std::fmt::Display for CudaTokenFactGraphLayoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroRecordWidth { field } => write!(
                f,
                "CUDA token/fact graph adapter received zero {field}. Fix: pass the concrete resident ABI record width."
            ),
            Self::ByteCountOverflow { field } => write!(
                f,
                "CUDA token/fact graph adapter overflowed while computing {field}. Fix: shard the token/fact graph before resident upload."
            ),
        }
    }
}

impl std::error::Error for CudaTokenFactGraphLayoutError {}

impl CudaArithmeticOverflow for CudaTokenFactGraphLayoutError {
    fn arithmetic_overflow(field: &'static str) -> Self {
        Self::ByteCountOverflow { field }
    }
}

/// Convert the unified token/fact graph into CUDA scheduler shape and bytes.
pub fn adapt_token_fact_graph_to_cuda_layout(
    graph: &DeviceResidentTokenFactGraph,
    node_record_bytes: u64,
    edge_record_bytes: u64,
) -> Result<CudaTokenFactGraphLayout, CudaTokenFactGraphLayoutError> {
    if node_record_bytes == 0 {
        return Err(CudaTokenFactGraphLayoutError::ZeroRecordWidth {
            field: "node_record_bytes",
        });
    }
    if edge_record_bytes == 0 {
        return Err(CudaTokenFactGraphLayoutError::ZeroRecordWidth {
            field: "edge_record_bytes",
        });
    }
    let node_count = u64::try_from(graph.node_ids.len()).map_err(|_| {
        CudaTokenFactGraphLayoutError::ByteCountOverflow {
            field: "node count",
        }
    })?;
    let edge_count = u64::try_from(graph.column_indices.len()).map_err(|_| {
        CudaTokenFactGraphLayoutError::ByteCountOverflow {
            field: "edge count",
        }
    })?;
    let node_bytes = checked_mul(node_count, node_record_bytes, "node bytes")?;
    let edge_bytes = checked_mul(edge_count, edge_record_bytes, "edge bytes")?;
    let resident_without_payload = checked_add(node_bytes, edge_bytes, "node plus edge bytes")?;
    let resident_bytes = checked_add(
        resident_without_payload,
        graph.payload_bytes,
        "resident bytes",
    )?;

    Ok(CudaTokenFactGraphLayout {
        graph_shape: CudaMegakernelGraphShape {
            node_count,
            edge_count,
        },
        node_record_bytes,
        edge_record_bytes,
        node_bytes,
        edge_bytes,
        payload_bytes: graph.payload_bytes,
        resident_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::megakernel_scheduler::{plan_cuda_megakernel_memory_budget, CudaMegakernelTopology};
    use vyre_self_substrate::device_resident_token_fact_graph::{
        plan_device_resident_token_fact_graph, TokenFactEdge, TokenFactEdgeKind, TokenFactNode,
        TokenFactNodeKind,
    };

    #[test]
    fn token_fact_adapter_uses_shared_typed_cuda_arithmetic() {
        let source = include_str!("token_fact_graph_cuda_adapter.rs");

        assert!(source.contains("checked_add_u64_count as checked_add"));
        assert!(source.contains("checked_mul_u64_count as checked_mul"));
        assert!(source.contains("impl CudaArithmeticOverflow for CudaTokenFactGraphLayoutError"));
        assert!(!source.contains(concat!("fn checked_", "mul(")));
        assert!(!source.contains(concat!("fn checked_", "add(")));
    }

    #[test]
    fn adapter_accounts_for_cuda_resident_token_fact_layout() {
        let graph = plan_device_resident_token_fact_graph(
            &[
                node(1, TokenFactNodeKind::Token, 0, 8),
                node(2, TokenFactNodeKind::Semantic, 8, 8),
                node(3, TokenFactNodeKind::Fact, 16, 8),
            ],
            &[
                edge(1, 2, TokenFactEdgeKind::SemanticFact),
                edge(2, 3, TokenFactEdgeKind::FactDependency),
            ],
            24,
        )
        .expect("Fix: token/fact graph should pack");

        let cuda = adapt_token_fact_graph_to_cuda_layout(&graph, 32, 16)
            .expect("Fix: token/fact graph should adapt to CUDA layout");

        assert_eq!(cuda.graph_shape.node_count, 3);
        assert_eq!(cuda.graph_shape.edge_count, 2);
        assert_eq!(cuda.node_bytes, 96);
        assert_eq!(cuda.edge_bytes, 32);
        assert_eq!(cuda.resident_bytes, 152);
        let memory = plan_cuda_megakernel_memory_budget(
            CudaMegakernelTopology::SparseFrontier,
            cuda.graph_shape,
            cuda.node_record_bytes,
            cuda.edge_record_bytes,
            64,
            cuda.payload_bytes,
            16,
            512,
        )
        .expect("Fix: adapted token/fact graph should feed CUDA memory planning");
        assert_eq!(memory.graph_bytes, 128);
    }

    #[test]
    fn adapter_rejects_missing_abi_widths() {
        let graph = plan_device_resident_token_fact_graph(&[], &[], 0)
            .expect("Fix: empty graph still has a valid resident layout");

        assert_eq!(
            adapt_token_fact_graph_to_cuda_layout(&graph, 0, 8)
                .expect_err("zero node record width should fail"),
            CudaTokenFactGraphLayoutError::ZeroRecordWidth {
                field: "node_record_bytes",
            }
        );
        assert_eq!(
            adapt_token_fact_graph_to_cuda_layout(&graph, 8, 0)
                .expect_err("zero edge record width should fail"),
            CudaTokenFactGraphLayoutError::ZeroRecordWidth {
                field: "edge_record_bytes",
            }
        );
    }

    fn node(
        id: u32,
        kind: TokenFactNodeKind,
        payload_offset: u64,
        payload_bytes: u64,
    ) -> TokenFactNode {
        TokenFactNode {
            id,
            kind,
            payload_offset,
            payload_bytes,
        }
    }

    fn edge(from: u32, to: u32, kind: TokenFactEdgeKind) -> TokenFactEdge {
        TokenFactEdge { from, to, kind }
    }
}
