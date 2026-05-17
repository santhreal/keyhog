use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::api::case::{Correctness, PerformanceContract, PerformanceEvaluation};
use crate::api::metric::MetricStats;
use crate::probes::environment::EnvironmentData;

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSchema {
    pub schema: String,
    pub run_id: String,
    pub suite: String,
    #[serde(default)]
    pub selected_backend: Option<String>,
    pub git: BTreeMap<String, String>,
    #[serde(default)]
    pub source_fingerprint: String,
    pub environment: EnvironmentData,
    pub features: Vec<String>,
    pub cases: Vec<CaseReport>,
    pub summary: ReportSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CaseReport {
    pub id: String,
    #[serde(default)]
    pub workload_fingerprint: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub owner_crate: String,
    #[serde(default)]
    pub workload_class: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub backend_id: Option<String>,
    #[serde(default)]
    pub needs_gpu: bool,
    #[serde(default)]
    pub min_vram_bytes: Option<u64>,
    #[serde(default)]
    pub min_input_bytes: Option<u64>,
    #[serde(default)]
    pub required_features: Vec<String>,
    pub status: String,
    pub wall_ns: Option<f64>,
    pub correctness: Correctness,
    pub contract: Option<PerformanceContract>,
    pub performance: Option<PerformanceEvaluation>,
    pub metrics: BTreeMap<String, MetricStats>,
    #[serde(default)]
    pub optimization_passes_applied: Vec<String>,
    pub artifacts: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_cases: usize,
    pub passed: usize,
    pub failed: usize,
    pub total_time_ns: u64,
    pub cache_hit_rate: Option<f64>,
}

pub fn generate_json_report(report: &ReportSchema) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}
