//! Statistical timing evidence persisted by autoroute calibration.

use keyhog_core::timing::{midpoint_u128, two_sided_95_student_t_critical};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackendTimingEvidence {
    pub(crate) trials_ns: Vec<u128>,
}

impl BackendTimingEvidence {
    pub(crate) fn add_to_first_trial(mut self, overhead_ns: u128) -> Self {
        if let Some(first) = self.trials_ns.first_mut() {
            *first = first.saturating_add(overhead_ns);
        }
        self
    }

    pub(crate) fn from_durations(durations: Vec<Duration>) -> Option<Self> {
        let trials_ns = durations.into_iter().map(|dur| dur.as_nanos()).collect();
        Self::from_trial_ns(trials_ns)
    }

    #[cfg(test)]
    pub(crate) fn constant_ms(ms: u128, trials: usize) -> Self {
        let trials_ns = vec![ms.saturating_mul(1_000_000); trials.max(1)];
        match Self::from_trial_ns(trials_ns) {
            Some(evidence) => evidence,
            None => unreachable!("a non-empty trial set always yields timing evidence"),
        }
    }

    pub(crate) fn from_trial_ns(trials_ns: Vec<u128>) -> Option<Self> {
        if trials_ns.is_empty() {
            return None;
        }
        Some(Self { trials_ns })
    }

    pub(crate) fn median_ns(&self) -> u128 {
        let mut trials = self.trials_ns.clone();
        trials.sort_unstable();
        let middle = trials.len() / 2;
        if trials.len() % 2 == 1 {
            trials[middle]
        } else {
            midpoint_u128(trials[middle - 1], trials[middle])
        }
    }

    pub(crate) fn median_ms(&self) -> u128 {
        self.median_ns() / 1_000_000
    }

    pub(crate) fn confidence_interval_95_ns(&self) -> TimingConfidenceInterval {
        TimingConfidenceInterval::from_trials(&self.trials_ns)
    }

    pub(crate) fn is_valid_for_trials(&self, expected_trials: usize) -> bool {
        self.trials_ns.len() == expected_trials && self.trials_ns.iter().all(|&trial| trial > 0)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ColdWarmStatisticalModel {
    pub(crate) cold_one_shot_ns: u128,
    pub(crate) warm_trials_ns: Vec<u128>,
    pub(crate) warm_median_ns: u128,
}

impl ColdWarmStatisticalModel {
    pub(crate) fn from_timing(timing: &BackendTimingEvidence) -> Option<Self> {
        let expected_trials = crate::orchestrator::dispatch::backend::AUTOROUTE_CALIBRATION_TRIALS;
        if !timing.is_valid_for_trials(expected_trials) {
            return None;
        }
        let cold_one_shot_ns = timing.trials_ns[0];
        let warm_trials_ns = timing.trials_ns[1..].to_vec();
        let warm_median_ns =
            BackendTimingEvidence::from_trial_ns(warm_trials_ns.clone())?.median_ns();
        Some(Self {
            cold_one_shot_ns,
            warm_trials_ns,
            warm_median_ns,
        })
    }
}

impl BackendTimingEvidence {
    pub(crate) fn cold_warm_model(&self) -> Option<ColdWarmStatisticalModel> {
        ColdWarmStatisticalModel::from_timing(self)
    }
}

pub(crate) fn paired_candidate_is_faster_95(
    candidate_trials_ns: &[u128],
    competitor_trials_ns: &[u128],
) -> bool {
    if candidate_trials_ns.len() != competitor_trials_ns.len() {
        return false;
    }
    let count = candidate_trials_ns.len();
    if count < 2 {
        return false;
    }
    let paired_differences = || {
        candidate_trials_ns
            .iter()
            .zip(competitor_trials_ns)
            .map(|(&candidate, &competitor)| {
                if competitor >= candidate {
                    (competitor - candidate) as f64
                } else {
                    -((candidate - competitor) as f64)
                }
            })
    };
    let count_f64 = count as f64;
    let mean = paired_differences().sum::<f64>() / count_f64;
    let variance = paired_differences()
        .map(|difference| {
            let delta = difference - mean;
            delta * delta
        })
        .sum::<f64>()
        / (count_f64 - 1.0);
    let half_width =
        two_sided_95_student_t_critical(count) * variance.max(0.0).sqrt() / count_f64.sqrt();
    mean - half_width > 0.0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TimingConfidenceInterval {
    pub(crate) low_ns: u128,
    pub(crate) high_ns: u128,
}

impl TimingConfidenceInterval {
    fn from_trials(trials_ns: &[u128]) -> Self {
        if trials_ns.is_empty() {
            return Self {
                low_ns: 0,
                high_ns: 0,
            };
        }
        let count = trials_ns.len() as f64;
        let mean = trials_ns.iter().map(|&ns| ns as f64).sum::<f64>() / count;
        let variance = if trials_ns.len() > 1 {
            trials_ns
                .iter()
                .map(|&ns| {
                    let delta = ns as f64 - mean;
                    delta * delta
                })
                .sum::<f64>()
                / (count - 1.0)
        } else {
            0.0
        };
        let half_width = two_sided_95_student_t_critical(trials_ns.len())
            * variance.max(0.0).sqrt()
            / count.sqrt();
        Self {
            low_ns: (mean - half_width).max(0.0).floor() as u128,
            high_ns: (mean + half_width).ceil() as u128,
        }
    }
}

#[cfg(test)]
#[path = "../../../../../tests/unit/backend_timing.rs"]
mod tests;
