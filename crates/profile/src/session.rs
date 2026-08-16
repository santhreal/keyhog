use crate::collector::SnapshotCollector;
use crate::config::ProfileConfig;
use crate::hardware::HardwareSession;
use crate::resources::{resource_usage, state_measurements, ProcessResourceCollector};
use crate::runtime::{ContextGuard, Runtime};
use crate::schema::{
    ResourceSample, ResourceSnapshot, RunIdentity, RunProfile, RunState, StateTransition,
    PROFILE_SCHEMA,
};
use crate::system::SystemSession;
use std::fmt;
use std::time::Instant;

/// Reserved error type for profile-session initialization failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionActive;

impl fmt::Display for SessionActive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a KeyHog profile session could not be initialized")
    }
}

impl std::error::Error for SessionActive {}

/// One causal profiling session with isolated owned metric storage.
pub struct Session {
    identity: Option<RunIdentity>,
    runtime: Runtime,
    context: Option<ContextGuard>,
    started: Instant,
    resources_at_start: ResourceSnapshot,
    resource_collector: ProcessResourceCollector,
    transitions: Vec<StateTransition>,
    resource_samples: Vec<ResourceSample>,
    hardware: Option<HardwareSession>,
    system: Option<SystemSession>,
    finished: bool,
}

impl Session {
    /// Start a fresh isolated session.
    pub fn start(identity: RunIdentity) -> Result<Self, SessionActive> {
        let started = Instant::now();
        let runtime = Runtime::new_at(started);
        let context = runtime.enter();
        let mut resource_collector = ProcessResourceCollector::new();
        let resources_at_start = resource_collector.sample();
        Ok(Self {
            identity: Some(identity),
            runtime,
            context: Some(context),
            started,
            resources_at_start,
            resource_collector,
            transitions: vec![StateTransition {
                version: crate::schema::STATE_TRANSITION_VERSION,
                state: RunState::Created,
                elapsed_ns: 0,
            }],
            resource_samples: vec![ResourceSample {
                version: crate::schema::RESOURCE_SAMPLE_VERSION,
                state: RunState::Created,
                elapsed_ns: 0,
                snapshot: resources_at_start,
            }],
            hardware: Some(HardwareSession::new()),
            system: Some(SystemSession::new()),
            finished: false,
        })
    }

    /// Start a fresh isolated session configured by [`ProfileConfig`].
    pub fn start_with_config(
        config: &ProfileConfig,
        identity: RunIdentity,
    ) -> Result<Self, SessionActive> {
        if config.enabled {
            crate::set_detail(config.detail);
        } else {
            crate::set_detail(crate::Detail::Off);
        }
        Self::start(identity)
    }

    /// Clone the runtime handle for propagation to a worker or async task.
    pub fn runtime(&self) -> Runtime {
        self.runtime.clone()
    }

    /// Mutate run identity before the session is finalized.
    pub fn identity_mut(&mut self) -> &mut RunIdentity {
        self.identity
            .as_mut()
            .expect("unfinished profile owns identity")
    }

    /// Record an explicit macro state transition.
    pub fn transition(&mut self, state: RunState) {
        let elapsed_ns = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.transitions.push(StateTransition {
            version: crate::schema::STATE_TRANSITION_VERSION,
            state,
            elapsed_ns,
        });
        self.resource_samples.push(ResourceSample {
            version: crate::schema::RESOURCE_SAMPLE_VERSION,
            state,
            elapsed_ns,
            snapshot: self.resource_collector.sample(),
        });
        if let Some(hardware) = self.hardware.as_mut() {
            hardware.transition_sample();
        }
    }

    /// Finish the session and return its complete structured record.
    pub fn finish(mut self, status: RunState) -> RunProfile {
        self.transition(status);
        let wall = self.started.elapsed();
        let finish_resources = self
            .resource_samples
            .last()
            .map_or(self.resources_at_start, |sample| sample.snapshot);
        if let Some(resident_bytes) = finish_resources.resident_bytes {
            self.runtime
                .set_gauge(crate::GaugeId::ResidentMemory, resident_bytes);
        }
        if let Some(virtual_bytes) = finish_resources.virtual_bytes {
            self.runtime
                .set_gauge(crate::GaugeId::VirtualMemory, virtual_bytes);
        }
        if let Some(thread_count) = finish_resources.thread_count {
            self.runtime
                .set_gauge(crate::GaugeId::ProcessThreads, thread_count);
        }
        if let (Some(start_ms), Some(finish_ms)) = (
            self.resources_at_start.cpu_time_ms,
            finish_resources.cpu_time_ms,
        ) {
            self.runtime.add_counter(
                crate::CounterId::ProcessCpuTime,
                finish_ms.saturating_sub(start_ms),
            );
        }
        self.context.take();
        let (input_bytes, input_units) = self.runtime.take_session_input_totals();
        let (derived_decoder_bytes, backend_dispatched_bytes) =
            self.runtime.take_session_workload_totals();
        let stages = self.runtime.take_session_stage_measurements();
        let resource_samples = std::mem::take(&mut self.resource_samples);
        let states = state_measurements(&self.transitions, &resource_samples);
        let resources = resource_usage(
            self.resources_at_start,
            finish_resources,
            wall,
            &resource_samples,
        );
        let wall_ns = u64::try_from(wall.as_nanos()).unwrap_or(u64::MAX);
        let hardware_session = self
            .hardware
            .take()
            .expect("unfinished profile owns hardware");
        let mut collectors = vec![self.resource_collector.capability()];
        collectors.extend(hardware_session.capabilities());
        let hardware = hardware_session.finish_evidence(wall_ns, &self.runtime);
        let system_session = self.system.take().expect("unfinished profile owns system");
        collectors.extend(system_session.capabilities());
        let system = system_session.finish_evidence(
            &self.runtime,
            &finish_resources,
            input_bytes,
            derived_decoder_bytes,
        );
        let profile = RunProfile {
            version: crate::schema::RUN_PROFILE_VERSION,
            schema: PROFILE_SCHEMA.to_string(),
            identity: self
                .identity
                .take()
                .expect("unfinished profile owns identity"),
            status,
            wall_time_ns: wall_ns,
            input_bytes,
            input_units,
            workload: crate::schema::WorkloadMeasurements::measured(
                derived_decoder_bytes,
                backend_dispatched_bytes,
            ),
            stages,
            transitions: std::mem::take(&mut self.transitions),
            states,
            collectors,
            resource_samples,
            resources,
            hardware,
            system,
        };
        self.finished = true;
        profile
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.finished {
            self.context.take();
        }
    }
}
