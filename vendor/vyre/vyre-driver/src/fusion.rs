//! Cross-dispatch fusion decisions shared by concrete backends.

use crate::specialization::SpecMap;

/// One dispatch's pre-fusion description.
#[derive(Debug, Clone)]
pub struct DispatchShape {
    /// Stable id for this dispatch inside the containing program.
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

/// Adapter caps honored by the generic fusion pass.
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
    /// High-end profile for tests and capability probes.
    #[must_use]
    pub const fn high_end() -> Self {
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
    /// Fusion is legal; the concrete backend may stitch its target modules.
    Accept,
    /// Workgroup size mismatch or invocation budget violation.
    WorkgroupSizeMismatch {
        /// Upstream size.
        upstream: [u32; 3],
        /// Downstream size.
        downstream: [u32; 3],
    },
    /// Shared-memory budget would exceed adapter caps.
    SharedMemoryBudget {
        /// Combined bytes the fused kernel would request.
        needed: u64,
        /// Adapter cap.
        cap: u32,
    },
    /// A flow-through output is still consumed by a third dispatch.
    OutputConsumedElsewhere,
    /// No buffer flows from upstream outputs to downstream inputs.
    NoPipelineDependency,
}

/// Pure cross-dispatch fusion analysis.
pub struct FusionPass;

impl FusionPass {
    /// Decide whether `upstream` -> `downstream` is legal to fuse.
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
        let invocations = u128::from(upstream.workgroup_size[0])
            * u128::from(upstream.workgroup_size[1])
            * u128::from(upstream.workgroup_size[2]);
        if invocations > u128::from(caps.max_invocations_per_workgroup) {
            return FusionDecision::WorkgroupSizeMismatch {
                upstream: upstream.workgroup_size,
                downstream: downstream.workgroup_size,
            };
        }
        let needed =
            u64::from(upstream.shared_memory_bytes) + u64::from(downstream.shared_memory_bytes);
        if needed > u64::from(caps.max_shared_memory_bytes) {
            return FusionDecision::SharedMemoryBudget {
                needed,
                cap: caps.max_shared_memory_bytes,
            };
        }

        let mut has_pipeline_dependency = false;
        for output in &upstream.outputs {
            if !downstream.inputs.iter().any(|input| input == output) {
                continue;
            }
            has_pipeline_dependency = true;
            if other_consumers.iter().any(|consumer| consumer == output) {
                return FusionDecision::OutputConsumedElsewhere;
            }
        }
        if !has_pipeline_dependency {
            return FusionDecision::NoPipelineDependency;
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
        assert_eq!(
            FusionPass::decide(&up, &down, FusionCaps::high_end(), &[]),
            FusionDecision::Accept
        );
    }

    #[test]
    fn third_consumer_rejects() {
        let up = dispatch("a", &[], &["x"]);
        let down = dispatch("b", &["x"], &[]);
        assert_eq!(
            FusionPass::decide(&up, &down, FusionCaps::high_end(), &["x"]),
            FusionDecision::OutputConsumedElsewhere
        );
    }

    #[test]
    fn workgroup_invocation_overflow_rejects_instead_of_wrapping_or_clamping() {
        let mut up = dispatch("wide-a", &["in"], &["stage"]);
        up.workgroup_size = [u32::MAX, u32::MAX, 2];
        let mut down = dispatch("wide-b", &["stage"], &["out"]);
        down.workgroup_size = up.workgroup_size;
        assert_eq!(
            FusionPass::decide(&up, &down, FusionCaps::high_end(), &[]),
            FusionDecision::WorkgroupSizeMismatch {
                upstream: up.workgroup_size,
                downstream: down.workgroup_size,
            }
        );
    }

    #[test]
    fn shared_memory_overflow_rejects_instead_of_appearing_under_cap() {
        let mut up = dispatch("smem-a", &["in"], &["stage"]);
        up.shared_memory_bytes = u32::MAX;
        let mut down = dispatch("smem-b", &["stage"], &["out"]);
        down.shared_memory_bytes = 1;
        assert_eq!(
            FusionPass::decide(&up, &down, FusionCaps::high_end(), &[]),
            FusionDecision::SharedMemoryBudget {
                needed: u64::from(u32::MAX) + 1,
                cap: FusionCaps::high_end().max_shared_memory_bytes,
            }
        );
    }

    #[test]
    fn source_has_no_clamped_fusion_admission_math() {
        let source = include_str!("fusion.rs");
        assert!(
            !source.contains(concat!(".", "saturating_")),
            "fusion admission must use widened exact arithmetic, not silent clamps"
        );
    }
}
