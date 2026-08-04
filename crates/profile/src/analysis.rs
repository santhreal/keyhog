use crate::runtime::{runtime_for_drain, RawStageCounters, Runtime};
use crate::schema::{Stage, StageMeasurement, STAGE_MEASUREMENT_VERSION};

fn materialize_stage_measurements(raw: RawStageCounters) -> Vec<StageMeasurement> {
    Stage::ALL
        .into_iter()
        .filter_map(|stage| {
            let index = stage.index();
            let elapsed_ns = raw.elapsed_ns[index];
            let calls = raw.calls[index];
            let attributed_ns = raw.attributed_ns[index];
            (elapsed_ns != 0 || calls != 0 || attributed_ns != 0).then_some(StageMeasurement {
                version: STAGE_MEASUREMENT_VERSION,
                stage,
                elapsed_ns,
                calls,
                attributed_ns,
            })
        })
        .collect()
}

impl Runtime {
    pub(crate) fn take_session_stage_measurements(&self) -> Vec<StageMeasurement> {
        materialize_stage_measurements(self.drain_stage_counters(true))
    }
}

/// Atomically drain fixed counters and materialize stable stage records.
pub fn take_stage_measurements() -> Vec<StageMeasurement> {
    materialize_stage_measurements(runtime_for_drain().drain_stage_counters(false))
}
