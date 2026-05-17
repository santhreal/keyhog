//! Output type for the texture-memory promotion analysis.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TextureCandidate {
    pub binding_slot: u32,
    /// Number of distinct LoadGlobal sites against this binding.
    pub load_count: u32,
    /// Estimated speedup multiplier from texture promotion. Conservative
    /// `1.5 + log2(load_count)` to avoid overpromise.
    pub estimated_speedup_factor: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TexturePromotionPlan {
    pub kernel_id: String,
    pub candidates: Vec<TextureCandidate>,
}

impl TexturePromotionPlan {
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
        let p = TexturePromotionPlan {
            kernel_id: "empty".into(),
            candidates: vec![],
        };
        assert_eq!(p.candidate_count(), 0);
    }

    #[test]
    fn candidate_speedup_grows_with_log_load_count() {
        let cand = TextureCandidate {
            binding_slot: 0,
            load_count: 8,
            estimated_speedup_factor: 1.5 + 3.0, // log2(8) = 3
        };
        assert!((cand.estimated_speedup_factor - 4.5).abs() < 1e-5);
    }
}
