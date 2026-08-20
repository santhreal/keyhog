use crate::{RunProfile, Stage};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

pub const PROFILE_COMPARISON_VERSION: u16 = 1;
pub const COMPARISON_DIFFERENCE_VERSION: u16 = 1;
pub const STAGE_COMPARISON_VERSION: u16 = 1;

/// One identity or workload field that prevents a valid performance comparison.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComparisonDifference {
    pub version: u16,
    pub field: String,
    pub baseline: String,
    pub candidate: String,
}

/// Exact aggregate difference for one stage.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StageComparison {
    pub version: u16,
    pub stage: Stage,
    pub baseline_elapsed_ns: u64,
    pub candidate_elapsed_ns: u64,
    pub elapsed_delta_ns: i128,
    pub elapsed_change_percent: Option<f64>,
    pub baseline_calls: u64,
    pub candidate_calls: u64,
    pub calls_delta: i128,
}

/// Deterministic comparison of two profile records.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProfileComparison {
    pub version: u16,
    pub baseline_run_id: String,
    pub candidate_run_id: String,
    pub comparable: bool,
    pub incompatibilities: Vec<ComparisonDifference>,
    pub baseline_wall_time_ns: u64,
    pub candidate_wall_time_ns: u64,
    pub wall_time_delta_ns: i128,
    pub wall_time_change_percent: Option<f64>,
    pub stages: Vec<StageComparison>,
}

fn signed_delta(candidate: u64, baseline: u64) -> i128 {
    i128::from(candidate) - i128::from(baseline)
}

fn percent_change(candidate: u64, baseline: u64) -> Option<f64> {
    if baseline == 0 {
        return (candidate == 0).then_some(0.0);
    }
    Some((candidate as f64 - baseline as f64) * 100.0 / baseline as f64)
}

fn compare_field<T: Debug + PartialEq>(
    differences: &mut Vec<ComparisonDifference>,
    field: &str,
    baseline: &T,
    candidate: &T,
) {
    if baseline != candidate {
        differences.push(ComparisonDifference {
            version: COMPARISON_DIFFERENCE_VERSION,
            field: field.to_owned(),
            baseline: format!("{baseline:?}"),
            candidate: format!("{candidate:?}"),
        });
    }
}

/// Compare two runs only after checking every identity field that changes timing.
pub fn compare_profiles(baseline: &RunProfile, candidate: &RunProfile) -> ProfileComparison {
    let mut incompatibilities = Vec::new();
    compare_field(
        &mut incompatibilities,
        "profile.schema",
        &baseline.schema,
        &candidate.schema,
    );
    compare_field(
        &mut incompatibilities,
        "profile.version",
        &baseline.version,
        &candidate.version,
    );
    compare_field(
        &mut incompatibilities,
        "identity.version",
        &baseline.identity.version,
        &candidate.identity.version,
    );
    compare_field(
        &mut incompatibilities,
        "identity.binary_version",
        &baseline.identity.binary_version,
        &candidate.identity.binary_version,
    );
    compare_field(
        &mut incompatibilities,
        "identity.detector_digest",
        &baseline.identity.detector_digest,
        &candidate.identity.detector_digest,
    );
    compare_field(
        &mut incompatibilities,
        "identity.config_digest",
        &baseline.identity.config_digest,
        &candidate.identity.config_digest,
    );
    compare_field(
        &mut incompatibilities,
        "identity.source_kind",
        &baseline.identity.source_kind,
        &candidate.identity.source_kind,
    );
    compare_field(
        &mut incompatibilities,
        "identity.workload_class",
        &baseline.identity.workload_class,
        &candidate.identity.workload_class,
    );
    compare_field(
        &mut incompatibilities,
        "identity.backend_requested",
        &baseline.identity.backend_requested,
        &candidate.identity.backend_requested,
    );
    compare_field(
        &mut incompatibilities,
        "identity.backend_selected",
        &baseline.identity.backend_selected,
        &candidate.identity.backend_selected,
    );
    compare_field(
        &mut incompatibilities,
        "identity.cache_state",
        &baseline.identity.cache_state,
        &candidate.identity.cache_state,
    );
    compare_field(
        &mut incompatibilities,
        "identity.daemon_state",
        &baseline.identity.daemon_state,
        &candidate.identity.daemon_state,
    );
    compare_field(
        &mut incompatibilities,
        "identity.scanner_threads",
        &baseline.identity.scanner_threads,
        &candidate.identity.scanner_threads,
    );
    compare_field(
        &mut incompatibilities,
        "identity.reader_threads",
        &baseline.identity.reader_threads,
        &candidate.identity.reader_threads,
    );
    compare_field(
        &mut incompatibilities,
        "identity.logical_cpus",
        &baseline.identity.logical_cpus,
        &candidate.identity.logical_cpus,
    );
    compare_field(
        &mut incompatibilities,
        "input_bytes",
        &baseline.input_bytes,
        &candidate.input_bytes,
    );
    compare_field(
        &mut incompatibilities,
        "input_units",
        &baseline.input_units,
        &candidate.input_units,
    );
    compare_field(
        &mut incompatibilities,
        "collectors",
        &baseline.collectors,
        &candidate.collectors,
    );

    let stages = Stage::ALL
        .into_iter()
        .filter_map(|stage| {
            let baseline_stage = baseline.stages.iter().find(|item| item.stage == stage);
            let candidate_stage = candidate.stages.iter().find(|item| item.stage == stage);
            if baseline_stage.is_none() && candidate_stage.is_none() {
                return None;
            }
            let baseline_elapsed_ns = baseline_stage.map_or(0, |item| item.elapsed_ns);
            let candidate_elapsed_ns = candidate_stage.map_or(0, |item| item.elapsed_ns);
            let baseline_calls = baseline_stage.map_or(0, |item| item.calls);
            let candidate_calls = candidate_stage.map_or(0, |item| item.calls);
            Some(StageComparison {
                version: STAGE_COMPARISON_VERSION,
                stage,
                baseline_elapsed_ns,
                candidate_elapsed_ns,
                elapsed_delta_ns: signed_delta(candidate_elapsed_ns, baseline_elapsed_ns),
                elapsed_change_percent: percent_change(candidate_elapsed_ns, baseline_elapsed_ns),
                baseline_calls,
                candidate_calls,
                calls_delta: signed_delta(candidate_calls, baseline_calls),
            })
        })
        .collect();

    ProfileComparison {
        version: PROFILE_COMPARISON_VERSION,
        baseline_run_id: baseline.identity.run_id.clone(),
        candidate_run_id: candidate.identity.run_id.clone(),
        comparable: incompatibilities.is_empty(),
        incompatibilities,
        baseline_wall_time_ns: baseline.wall_time_ns,
        candidate_wall_time_ns: candidate.wall_time_ns,
        wall_time_delta_ns: signed_delta(candidate.wall_time_ns, baseline.wall_time_ns),
        wall_time_change_percent: percent_change(candidate.wall_time_ns, baseline.wall_time_ns),
        stages,
    }
}

impl ProfileComparison {
    /// Render a stable text comparison. Incompatible inputs remain visible and are never called a speedup.
    pub fn render_text(&self) -> String {
        let mut output = format!(
            "KeyHog profile comparison comparable={} baseline_run={:?} candidate_run={:?}\n",
            self.comparable, self.baseline_run_id, self.candidate_run_id,
        );
        for difference in &self.incompatibilities {
            output.push_str(&format!(
                "incompatible field={} baseline={} candidate={}\n",
                difference.field, difference.baseline, difference.candidate,
            ));
        }
        output.push_str(&format!(
            "wall baseline_ns={} candidate_ns={} delta_ns={}",
            self.baseline_wall_time_ns, self.candidate_wall_time_ns, self.wall_time_delta_ns,
        ));
        if let Some(percent) = self.wall_time_change_percent {
            output.push_str(&format!(" change_percent={percent:.3}"));
        } else {
            output.push_str(" change_percent=undefined");
        }
        output.push('\n');
        for stage in &self.stages {
            output.push_str(&format!(
                "stage {} baseline_ns={} candidate_ns={} delta_ns={} calls={}->{}",
                stage.stage.as_str(),
                stage.baseline_elapsed_ns,
                stage.candidate_elapsed_ns,
                stage.elapsed_delta_ns,
                stage.baseline_calls,
                stage.candidate_calls,
            ));
            if let Some(percent) = stage.elapsed_change_percent {
                output.push_str(&format!(" change_percent={percent:.3}"));
            } else {
                output.push_str(" change_percent=undefined");
            }
            output.push('\n');
        }
        output
    }

    /// Render a clean tabular Markdown comparison report for terminal and browser inspection (Row 108).
    pub fn render_markdown(&self) -> String {
        let mut out = String::with_capacity(2048);
        out.push_str(&format!(
            "# KeyHog Profile Comparison\n\n\
             - **Comparable**: `{}`\n\
             - **Baseline Run**: `{:?}`\n\
             - **Candidate Run**: `{:?}`\n\n",
            self.comparable, self.baseline_run_id, self.candidate_run_id
        ));

        if !self.incompatibilities.is_empty() {
            out.push_str("## Incompatibilities\n\n");
            out.push_str("| Field | Baseline | Candidate |\n");
            out.push_str("| :--- | :--- | :--- |\n");
            for diff in &self.incompatibilities {
                out.push_str(&format!(
                    "| {} | {} | {} |\n",
                    diff.field, diff.baseline, diff.candidate
                ));
            }
            out.push('\n');
        }

        let wall_change = match self.wall_time_change_percent {
            Some(pct) => format!("{pct:+.2}%"),
            None => "undefined".to_string(),
        };
        out.push_str("## Wall Time\n\n");
        out.push_str(&format!(
            "- **Baseline**: {:.3} ms\n\
             - **Candidate**: {:.3} ms\n\
             - **Delta**: {:+.3} ms ({})\n\n",
            self.baseline_wall_time_ns as f64 / 1_000_000.0,
            self.candidate_wall_time_ns as f64 / 1_000_000.0,
            self.wall_time_delta_ns as f64 / 1_000_000.0,
            wall_change,
        ));

        out.push_str("## Stages\n\n");
        out.push_str("| Stage | Baseline (ms) | Candidate (ms) | Delta (ms) | Change (%) | Calls (Base -> Cand) |\n");
        out.push_str("| :--- | ---: | ---: | ---: | ---: | :--- |\n");
        for stage in &self.stages {
            let change_str = match stage.elapsed_change_percent {
                Some(pct) => format!("{pct:+.2}%"),
                None => "undefined".to_string(),
            };
            out.push_str(&format!(
                "| {} | {:.3} | {:.3} | {:+.3} | {} | {} -> {} |\n",
                stage.stage.as_str(),
                stage.baseline_elapsed_ns as f64 / 1_000_000.0,
                stage.candidate_elapsed_ns as f64 / 1_000_000.0,
                stage.elapsed_delta_ns as f64 / 1_000_000.0,
                change_str,
                stage.baseline_calls,
                stage.candidate_calls,
            ));
        }
        out.push('\n');
        out
    }
}
