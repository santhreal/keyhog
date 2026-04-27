//! Cross-dispatch kernel fusion pass (C-B8).
//!
//! The generic optimizer already fuses adjacent ops *within* one
//! dispatch (see `vyre-core/src/optimizer/passes/fusion.rs`). C-B8
//! extends fusion *across* dispatches: when dispatch N's output is
//! consumed only by dispatch N+1 and their workgroup layouts
//! match, the two kernels collapse into one ComputePipeline. The
//! fused kernel eliminates a queue-submit, a copy, and a readback
//! round-trip.
//!
//! This module ships the fusion-decision logic — the pure analysis
//! that answers "can these two dispatches be fused given these
//! adapter caps?". The naga::Module stitching happens in the
//! actual wgpu lowering pipeline when this pass reports a green
//! light; the pure decision module below is what the PassManager
//! (A-C7b) consumes.

use crate::lowering::specialization::SpecMap;
use rustc_hash::FxHashSet;

/// One dispatch's pre-fusion description.
#[derive(Debug, Clone)]
pub struct DispatchShape {
    /// Stable id for this dispatch inside the containing Program.
    pub id: &'static str,
    /// Workgroup size `[x, y, z]`.
    pub workgroup_size: [u32; 3],
    /// Per-dispatch shared memory bytes.
    pub shared_memory_bytes: u32,
    /// Buffers this dispatch reads.
    pub inputs: Vec<&'static str>,
    /// Buffers this dispatch writes.
    pub outputs: Vec<&'static str>,
    /// Specialization constants baked into this dispatch.
    pub specs: SpecMap,
}

/// Adapter caps the fusion pass honors.
#[derive(Debug, Clone, Copy)]
pub struct FusionCaps {
    /// Maximum workgroup-shared memory the adapter can serve.
    pub max_shared_memory_bytes: u32,
    /// Maximum workgroup invocation count.
    pub max_invocations_per_workgroup: u32,
}

impl Default for FusionCaps {
    fn default() -> Self {
        Self {
            max_shared_memory_bytes: 16 * 1024,
            max_invocations_per_workgroup: 256,
        }
    }
}

impl FusionCaps {
    /// The RTX 5090 profile — used in tests that want to measure
    /// the fast-path budget.
    #[must_use]
    pub const fn rtx_5090() -> Self {
        Self {
            max_shared_memory_bytes: 128 * 1024,
            max_invocations_per_workgroup: 1024,
        }
    }
}

/// Why the fusion pass accepted or rejected a pair.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FusionDecision {
    /// Fusion is legal and will run. The caller stitches two
    /// naga::Modules into one and compiles.
    Accept,
    /// Workgroup size mismatch — caller must keep the dispatches
    /// separate.
    WorkgroupSizeMismatch {
        /// Upstream size.
        upstream: [u32; 3],
        /// Downstream size.
        downstream: [u32; 3],
    },
    /// Shared-memory budget would exceed adapter caps.
    SharedMemoryBudget {
        /// Combined bytes the fused kernel would request.
        needed: u32,
        /// The adapter's cap.
        cap: u32,
    },
    /// A downstream input is still consumed by a third dispatch —
    /// can't eliminate the round-trip without cascading breakage.
    OutputConsumedElsewhere,
    /// No buffer flows directly from upstream's output to
    /// downstream's input. Fusion would have no benefit.
    NoPipelineDependency,
}

/// The fusion pass — pure analysis, no naga plumbing.
pub struct FusionPass;

impl FusionPass {
    /// Decide whether `upstream` → `downstream` is legal to fuse
    /// given `caps`. `other_consumers` enumerates any third
    /// dispatches that also read `upstream`'s outputs; if
    /// non-empty, fusion would change semantics.
    #[must_use]
    pub fn decide(
        upstream: &DispatchShape,
        downstream: &DispatchShape,
        caps: FusionCaps,
        other_consumers: &[&str],
    ) -> FusionDecision {
        if upstream.workgroup_size != downstream.workgroup_size {
            return FusionDecision::WorkgroupSizeMismatch {
                upstream: upstream.workgroup_size,
                downstream: downstream.workgroup_size,
            };
        }
        let invocations = upstream.workgroup_size[0]
            .saturating_mul(upstream.workgroup_size[1])
            .saturating_mul(upstream.workgroup_size[2]);
        if invocations > caps.max_invocations_per_workgroup {
            return FusionDecision::WorkgroupSizeMismatch {
                upstream: upstream.workgroup_size,
                downstream: downstream.workgroup_size,
            };
        }
        let needed = upstream
            .shared_memory_bytes
            .saturating_add(downstream.shared_memory_bytes);
        if needed > caps.max_shared_memory_bytes {
            return FusionDecision::SharedMemoryBudget {
                needed,
                cap: caps.max_shared_memory_bytes,
            };
        }

        // Pre-compute O(1) lookup sets so the intersection tests below
        // are linear in the sizes of the two sets rather than O(M·N).
        let downstream_inputs: FxHashSet<&str> = downstream.inputs.iter().copied().collect();
        let other_consumers_set: FxHashSet<&str> = other_consumers.iter().copied().collect();

        // Find the buffer(s) that flow from upstream's outputs into
        // downstream's inputs.
        let flows_through: Vec<&&str> = upstream
            .outputs
            .iter()
            .filter(|b| downstream_inputs.contains(*b))
            .collect();
        if flows_through.is_empty() {
            return FusionDecision::NoPipelineDependency;
        }
        // If any "flows-through" buffer has another consumer, we
        // can't eliminate it — that would break semantic equivalence.
        if flows_through
            .iter()
            .any(|b| other_consumers_set.contains(*b))
        {
            return FusionDecision::OutputConsumedElsewhere;
        }
        FusionDecision::Accept
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dispatch(
        id: &'static str,
        inputs: &[&'static str],
        outputs: &[&'static str],
    ) -> DispatchShape {
        DispatchShape {
            id,
            workgroup_size: [64, 1, 1],
            shared_memory_bytes: 1024,
            inputs: inputs.to_vec(),
            outputs: outputs.to_vec(),
            specs: SpecMap::new(),
        }
    }

    #[test]
    fn straight_producer_consumer_fuses() {
        let up = dispatch("load", &["in"], &["stage"]);
        let down = dispatch("xor", &["stage"], &["out"]);
        let d = FusionPass::decide(&up, &down, FusionCaps::rtx_5090(), &[]);
        assert_eq!(d, FusionDecision::Accept);
    }

    #[test]
    fn workgroup_size_mismatch_rejects() {
        let up = dispatch("a", &[], &["x"]);
        let mut down = dispatch("b", &["x"], &[]);
        down.workgroup_size = [32, 1, 1];
        let d = FusionPass::decide(&up, &down, FusionCaps::rtx_5090(), &[]);
        assert!(matches!(d, FusionDecision::WorkgroupSizeMismatch { .. }));
    }

    #[test]
    fn shared_memory_budget_rejects() {
        let mut up = dispatch("a", &[], &["x"]);
        let mut down = dispatch("b", &["x"], &[]);
        up.shared_memory_bytes = 10_000;
        down.shared_memory_bytes = 10_000;
        let caps = FusionCaps {
            max_shared_memory_bytes: 16_384,
            max_invocations_per_workgroup: 1024,
        };
        let d = FusionPass::decide(&up, &down, caps, &[]);
        assert!(matches!(
            d,
            FusionDecision::SharedMemoryBudget { needed: 20_000, .. }
        ));
    }

    #[test]
    fn output_consumed_elsewhere_rejects() {
        let up = dispatch("a", &[], &["x"]);
        let down = dispatch("b", &["x"], &[]);
        let d = FusionPass::decide(&up, &down, FusionCaps::rtx_5090(), &["x"]);
        assert_eq!(d, FusionDecision::OutputConsumedElsewhere);
    }

    #[test]
    fn no_pipeline_dependency_rejects() {
        let up = dispatch("a", &[], &["x"]);
        let down = dispatch("b", &["y"], &[]);
        let d = FusionPass::decide(&up, &down, FusionCaps::rtx_5090(), &[]);
        assert_eq!(d, FusionDecision::NoPipelineDependency);
    }

    #[test]
    fn default_caps_are_conservative() {
        let caps = FusionCaps::default();
        assert_eq!(caps.max_shared_memory_bytes, 16 * 1024);
    }

    /// CPX-10 regression guard: 64×64 bitmap precompute must yield the
    /// same decision bit as the old O(M·N) path.
    #[test]
    fn decide_64x64_bitmap_precompute_matches() {
        let outputs: Vec<&'static str> = (0..64)
            .map(|i| Box::leak(format!("out_{i}").into_boxed_str()) as &'static str)
            .collect();
        let inputs: Vec<&'static str> = (0..64)
            .map(|i| Box::leak(format!("in_{i}").into_boxed_str()) as &'static str)
            .collect();

        // Overlap on out_31 only.
        let up_outputs = outputs.clone();
        let mut down_inputs = inputs.clone();
        down_inputs[31] = up_outputs[31];

        let up = dispatch("producer", &[], &up_outputs);
        let down = dispatch("consumer", &down_inputs, &[]);

        // Without a third consumer → Accept.
        assert_eq!(
            FusionPass::decide(&up, &down, FusionCaps::rtx_5090(), &[]),
            FusionDecision::Accept
        );

        // With a third consumer touching the overlapping buffer → OutputConsumedElsewhere.
        assert_eq!(
            FusionPass::decide(&up, &down, FusionCaps::rtx_5090(), &[up_outputs[31]]),
            FusionDecision::OutputConsumedElsewhere
        );

        // No overlap → NoPipelineDependency.
        let down_no_overlap = dispatch("consumer", &inputs, &[]);
        assert_eq!(
            FusionPass::decide(&up, &down_no_overlap, FusionCaps::rtx_5090(), &[]),
            FusionDecision::NoPipelineDependency
        );
    }
}
