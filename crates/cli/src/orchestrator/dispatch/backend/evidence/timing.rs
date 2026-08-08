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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ColdWarmStatisticalModel {
    pub(crate) cold_one_shot_ns: u128,
    pub(crate) warm_trials_ns: Vec<u128>,
    pub(crate) warm_median_ns: u128,
    pub(crate) warm_ci: TimingConfidenceInterval,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairedDifferenceDistribution {
    pub(crate) count: usize,
    pub(crate) mean_diff_ns: f64,
    pub(crate) variance: f64,
    pub(crate) ci_half_width_ns: f64,
    pub(crate) is_statistically_faster_95: bool,
}

impl ColdWarmStatisticalModel {
    pub(crate) fn from_timing(timing: &BackendTimingEvidence) -> Option<Self> {
        let (&cold_one_shot_ns, warm_trials) = timing.trials_ns.split_first()?;
        if warm_trials.is_empty() {
            return None;
        }
        let warm_timing = BackendTimingEvidence::from_trial_ns(warm_trials.to_vec())?;
        let warm_median_ns = warm_timing.median_ns();
        let warm_ci = warm_timing.confidence_interval_95_ns();
        Some(Self {
            cold_one_shot_ns,
            warm_trials_ns: warm_trials.to_vec(),
            warm_median_ns,
            warm_ci,
        })
    }

    pub(crate) fn paired_difference(
        &self,
        competitor: &ColdWarmStatisticalModel,
    ) -> PairedDifferenceDistribution {
        let count = self.warm_trials_ns.len().min(competitor.warm_trials_ns.len());
        if count < 2 {
            return PairedDifferenceDistribution {
                count,
                mean_diff_ns: 0.0,
                variance: 0.0,
                ci_half_width_ns: 0.0,
                is_statistically_faster_95: false,
            };
        }
        let paired_diffs: Vec<f64> = self.warm_trials_ns[..count]
            .iter()
            .zip(&competitor.warm_trials_ns[..count])
            .map(|(&cand, &comp)| comp as f64 - cand as f64)
            .collect();
        let count_f64 = count as f64;
        let mean = paired_diffs.iter().sum::<f64>() / count_f64;
        let variance = paired_diffs
            .iter()
            .map(|&diff| {
                let d = diff - mean;
                d * d
            })
            .sum::<f64>()
            / (count_f64 - 1.0);
        let half_width = two_sided_95_student_t_critical(count) * variance.max(0.0).sqrt() / count_f64.sqrt();
        PairedDifferenceDistribution {
            count,
            mean_diff_ns: mean,
            variance,
            ci_half_width_ns: half_width,
            is_statistically_faster_95: mean - half_width > 0.0,
        }
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
    let count = candidate_trials_ns.len().min(competitor_trials_ns.len());
    if count < 2 {
        return false;
    }
    let paired_differences = || {
        candidate_trials_ns
            .iter()
            .zip(competitor_trials_ns)
            .take(count)
            .map(|(&candidate, &competitor)| competitor as f64 - candidate as f64)
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
    let half_width = two_sided_95_student_t_critical(count) * variance.max(0.0).sqrt() / count_f64.sqrt();
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
        let half_width =
            two_sided_95_student_t_critical(trials_ns.len()) * variance.max(0.0).sqrt() / count.sqrt();
        Self {
            low_ns: (mean - half_width).max(0.0).floor() as u128,
            high_ns: (mean + half_width).ceil() as u128,
        }
    }
}

#[cfg(test)]
#[path = "../../../../../tests/unit/backend_timing.rs"]
mod tests;
