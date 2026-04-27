//! High-level execution routing engine.
//!
//! Substrate-neutral policies that consume [`vyre_foundation::execution_plan::ExecutionPlan`]
//! facts and map them to concrete backend strategies.

use vyre_foundation::execution_plan::ExecutionPlan;

/// Target backend category chosen by the router.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RoutingDecision {
    /// Use CPU SIMD reference interpreter (latency optimized).
    CpuSimd,
    /// Use the default GPU pipeline.
    GpuPipeline,
    /// Use the persistent megakernel.
    PersistentMegakernel,
}

/// Pluggable routing policy.
pub trait RoutingPolicy: Send + Sync {
    /// Name of the policy for diagnostics.
    fn name(&self) -> &'static str;

    /// Decide which backend route to take for a given plan.
    fn route(&self, plan: &ExecutionPlan) -> RoutingDecision;
}

/// The standard routing engine.
pub struct RoutingEngine {
    policy: Box<dyn RoutingPolicy>,
}

impl RoutingEngine {
    /// Create a new engine with the given policy.
    pub fn new(policy: impl RoutingPolicy + 'static) -> Self {
        Self {
            policy: Box::new(policy),
        }
    }

    /// Route a program to a backend.
    pub fn route(&self, plan: &ExecutionPlan) -> RoutingDecision {
        self.policy.route(plan)
    }
}
pub mod standard_policy;
