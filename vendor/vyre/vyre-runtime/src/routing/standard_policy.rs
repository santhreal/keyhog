//! Standard routing policies for common compute workloads.

use super::{RoutingDecision, RoutingPolicy};
use vyre_foundation::execution_plan::{ExecutionPlan, PolicyRoute, SchedulingPolicy};

/// Default performance-balanced policy.
pub struct StandardPolicy;

impl RoutingPolicy for StandardPolicy {
    fn name(&self) -> &'static str {
        "standard-balanced"
    }

    fn route(&self, plan: &ExecutionPlan) -> RoutingDecision {
        match SchedulingPolicy::standard().route(plan.fusion.node_count, plan.memory.static_bytes) {
            PolicyRoute::CpuSimd => RoutingDecision::CpuSimd,
            PolicyRoute::GpuPipeline => RoutingDecision::GpuPipeline,
            PolicyRoute::PersistentMegakernel => RoutingDecision::PersistentMegakernel,
        }
    }
}
