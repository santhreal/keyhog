//! Output type for the AoS→SoA layout-transform analysis.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LayoutCandidate {
    pub binding_slot: u32,
    /// Number of LoadGlobal sites against this binding.
    pub load_count: u32,
    /// Number of components in the AoS element (e.g. 4 for Vec4).
    pub component_count: u32,
    /// Estimated speedup if split: `1.0 + (component_count - 1) * 0.3`.
    /// Conservative — actual gain depends on access pattern coalescing.
    pub estimated_speedup_factor: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LayoutTransformPlan {
    pub kernel_id: String,
    pub candidates: Vec<LayoutCandidate>,
}

impl LayoutTransformPlan {
    #[must_use]
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_plan_has_zero_candidates() {
        let p = LayoutTransformPlan {
            kernel_id: "k".into(),
            candidates: vec![],
        };
        assert_eq!(p.candidate_count(), 0);
    }

    #[test]
    fn vec4_speedup_grows_with_component_count() {
        // 1.0 + (4 - 1) * 0.3 = 1.9
        let cand = LayoutCandidate {
            binding_slot: 0,
            load_count: 4,
            component_count: 4,
            estimated_speedup_factor: 1.9,
        };
        assert!((cand.estimated_speedup_factor - 1.9).abs() < 1e-5);
    }
}
