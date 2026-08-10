//! Authenticated GPU device-set identity and deterministic shard scheduling.

use crate::hw_probe::ScanBackend;
use serde::{Deserialize, Serialize};

/// Persisted schema for calibrated ordered GPU device routes.
pub const GPU_DEVICE_ROUTE_SCHEMA_VERSION: u32 = 1;
/// Hard ceiling for adapters admitted into one process route.
pub const MAX_GPU_ROUTE_DEVICES: usize = 64;
/// Hard ceiling for exact chunk/shard rows accepted by one scheduling call.
pub const MAX_GPU_ROUTE_SHARDS: usize = 1 << 20;
const MAX_GPU_DEVICE_WEIGHT: u64 = 1_000_000_000;
const MAX_GPU_DEVICE_TIMING_TRIALS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum GpuApi {
    Cuda,
    Metal,
    Wgpu,
}

impl GpuApi {
    #[must_use]
    pub const fn scan_backend(self) -> ScanBackend {
        match self {
            Self::Cuda => ScanBackend::GpuCuda,
            Self::Metal => ScanBackend::GpuMetal,
            Self::Wgpu => ScanBackend::GpuWgpu,
        }
    }

    const fn preference(self) -> u8 {
        match self {
            Self::Cuda | Self::Metal => 2,
            Self::Wgpu => 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuDeviceExposure {
    pub api: GpuApi,
    pub api_ordinal: usize,
    /// Stable physical identity. PCI BDF, registry LUID, or Metal registry id.
    pub physical_identity: String,
    /// Stable topology identity, including NUMA/root-complex placement when known.
    pub topology_identity: String,
    pub name: String,
    pub vendor_id: u32,
    pub device_id: u32,
    pub driver_identity: String,
    pub runtime_identity: String,
    pub capacity_bytes: u64,
    pub is_software: bool,
    pub is_display_only: bool,
    /// `None` means independently eligible before cross-API deduplication.
    pub ineligible_reason: Option<String>,
}

impl GpuDeviceExposure {
    fn validate_identity(&self) -> Result<(), String> {
        if self.physical_identity.trim().is_empty() {
            return Err("physical adapter identity is unavailable".to_string());
        }
        if self.topology_identity.trim().is_empty() {
            return Err("physical adapter topology identity is unavailable".to_string());
        }
        if self.driver_identity.trim().is_empty() {
            return Err("GPU driver identity is unavailable".to_string());
        }
        if self.runtime_identity.trim().is_empty() {
            return Err("GPU runtime identity is unavailable".to_string());
        }
        if self.capacity_bytes == 0 {
            return Err("GPU capacity is zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuApiCensusFailure {
    pub api: GpuApi,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuAdapterCensus {
    /// One row for every API exposure, including excluded duplicate rows.
    pub exposures: Vec<GpuDeviceExposure>,
    /// Indices into `exposures`, stable physical/topology order, one per device.
    pub eligible: Vec<usize>,
    /// API-level discovery failures retained for operator-visible diagnosis.
    pub failures: Vec<GpuApiCensusFailure>,
}

/// Validate and deduplicate API exposures into stable physical topology order.
///
/// Every rejected exposure retains an explicit reason. Native APIs win over WGPU
/// for the same physical adapter; ties are resolved by API then ordinal.
pub fn deduplicate_gpu_exposures(
    mut exposures: Vec<GpuDeviceExposure>,
) -> Result<GpuAdapterCensus, String> {
    if exposures.len() > MAX_GPU_ROUTE_DEVICES.saturating_mul(8) {
        return Err(format!(
            "GPU census contains {} API exposures, above the bounded limit of {}",
            exposures.len(),
            MAX_GPU_ROUTE_DEVICES * 8
        ));
    }
    for exposure in &mut exposures {
        if exposure.ineligible_reason.is_none() {
            exposure.ineligible_reason = if exposure.is_software {
                Some("software adapter is not eligible for calibrated GPU execution".to_string())
            } else if exposure.is_display_only {
                Some("display-only adapter is not eligible for compute execution".to_string())
            } else {
                exposure.validate_identity().err()
            };
        }
    }
    exposures.sort_by(|left, right| {
        left.physical_identity
            .cmp(&right.physical_identity)
            .then_with(|| left.topology_identity.cmp(&right.topology_identity))
            .then_with(|| right.api.preference().cmp(&left.api.preference()))
            .then_with(|| left.api.cmp(&right.api))
            .then_with(|| left.api_ordinal.cmp(&right.api_ordinal))
    });

    let mut eligible = Vec::new();
    eligible
        .try_reserve(exposures.len().min(MAX_GPU_ROUTE_DEVICES))
        .map_err(|error| format!("GPU eligible-device census reserve failed: {error}"))?;
    let mut last_selected: Option<(String, String, usize)> = None;
    for index in 0..exposures.len() {
        if exposures[index].ineligible_reason.is_some() {
            continue;
        }
        let key = (
            exposures[index].physical_identity.clone(),
            exposures[index].topology_identity.clone(),
        );
        if let Some((physical, topology, selected)) = &last_selected {
            if physical == &key.0 && topology == &key.1 {
                let winner = &exposures[*selected];
                exposures[index].ineligible_reason = Some(format!(
                    "duplicate API exposure of {} through {:?} ordinal {}",
                    winner.physical_identity, winner.api, winner.api_ordinal
                ));
                continue;
            }
        }
        if eligible.len() == MAX_GPU_ROUTE_DEVICES {
            exposures[index].ineligible_reason = Some(format!(
                "adapter exceeds the bounded route limit of {MAX_GPU_ROUTE_DEVICES} devices"
            ));
            continue;
        }
        eligible.push(index);
        last_selected = Some((key.0, key.1, index));
    }
    Ok(GpuAdapterCensus {
        exposures,
        eligible,
        failures: Vec::new(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceTimingEvidence {
    pub sample_bytes: u64,
    pub trials_ns: Vec<u64>,
}

/// Derive deterministic per-device resident ceilings from physical capacity and
/// one process-wide ceiling. The returned sum never exceeds either bound.
pub fn derive_resident_budgets(
    capacities: &[u64],
    process_resident_limit_bytes: u64,
) -> Result<Vec<u64>, String> {
    if capacities.is_empty() || capacities.len() > MAX_GPU_ROUTE_DEVICES {
        return Err(format!(
            "GPU resident budget derivation requires 1..={MAX_GPU_ROUTE_DEVICES} devices"
        ));
    }
    if process_resident_limit_bytes < capacities.len() as u64
        || capacities.iter().any(|capacity| *capacity == 0)
    {
        return Err(
            "GPU resident budget derivation requires nonzero capacity and at least one process byte per device"
                .to_string(),
        );
    }
    let total_capacity = capacities
        .iter()
        .try_fold(0u128, |total, capacity| total.checked_add(u128::from(*capacity)))
        .ok_or_else(|| "GPU capacity sum overflows u128".to_string())?;
    let usable_process = u128::from(process_resident_limit_bytes).min(total_capacity);
    let base_bytes = capacities.len() as u128;
    let distributable = usable_process - base_bytes;
    let residual_capacity = total_capacity - base_bytes;
    let mut budgets = Vec::new();
    budgets
        .try_reserve_exact(capacities.len())
        .map_err(|error| format!("GPU resident budget reserve failed: {error}"))?;
    let mut assigned_extra = 0u128;
    for capacity in capacities {
        let residual = u128::from(*capacity - 1);
        let extra = if residual_capacity == 0 {
            0
        } else {
            distributable
                .checked_mul(residual)
                .ok_or_else(|| "GPU proportional resident budget overflows u128".to_string())?
                / residual_capacity
        };
        assigned_extra = assigned_extra
            .checked_add(extra)
            .ok_or_else(|| "GPU resident budget assignment overflows u128".to_string())?;
        budgets.push((extra + 1) as u64);
    }
    let mut remainder = distributable - assigned_extra;
    for (budget, capacity) in budgets.iter_mut().zip(capacities) {
        if remainder == 0 {
            break;
        }
        if *budget < *capacity {
            *budget += 1;
            remainder -= 1;
        }
    }
    if remainder != 0 {
        return Err("GPU resident budget remainder could not fit device capacities".to_string());
    }
    Ok(budgets)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalibratedGpuDevice {
    pub api: GpuApi,
    pub api_ordinal: usize,
    pub physical_identity: String,
    pub topology_identity: String,
    pub software_eligible: bool,
    pub display_eligible: bool,
    pub driver_identity: String,
    pub runtime_identity: String,
    pub capacity_bytes: u64,
    /// Integer throughput weight measured for this exact workload class.
    pub workload_weight: u64,
    pub timing: DeviceTimingEvidence,
    /// Maximum resident bytes this device may own for this process route.
    pub resident_budget_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderedGpuDeviceRoute {
    pub schema_version: u32,
    pub workload_identity: String,
    pub detector_digest: String,
    pub config_digest: String,
    pub process_resident_limit_bytes: u64,
    pub devices: Vec<CalibratedGpuDevice>,
    /// BLAKE3 of the canonical route fields above, preserving device order.
    pub authenticated_digest: String,
}

impl OrderedGpuDeviceRoute {
    pub fn new(
        workload_identity: String,
        detector_digest: String,
        config_digest: String,
        process_resident_limit_bytes: u64,
        devices: Vec<CalibratedGpuDevice>,
    ) -> Result<Self, String> {
        let mut route = Self {
            schema_version: GPU_DEVICE_ROUTE_SCHEMA_VERSION,
            workload_identity,
            detector_digest,
            config_digest,
            process_resident_limit_bytes,
            devices,
            authenticated_digest: String::new(),
        };
        route.validate_fields()?;
        route.authenticated_digest = route.compute_digest();
        Ok(route)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validate_fields()?;
        let expected = self.compute_digest();
        if self.authenticated_digest != expected {
            return Err("ordered GPU device route authentication digest mismatch".to_string());
        }
        Ok(())
    }

    pub fn validate_live_set(&self, live: &GpuAdapterCensus) -> Result<(), String> {
        self.validate()?;
        if live.eligible.len() != self.devices.len() {
            return Err(format!(
                "calibrated GPU route requires {} device(s), but live census has {}",
                self.devices.len(),
                live.eligible.len()
            ));
        }
        for (position, (&live_index, expected)) in
            live.eligible.iter().zip(&self.devices).enumerate()
        {
            let actual = live.exposures.get(live_index).ok_or_else(|| {
                format!("live GPU census eligible index {live_index} is out of bounds")
            })?;
            if actual.ineligible_reason.is_some()
                || actual.is_software
                || actual.is_display_only
                || actual.api != expected.api
                || actual.api_ordinal != expected.api_ordinal
                || actual.physical_identity != expected.physical_identity
                || actual.topology_identity != expected.topology_identity
                || actual.driver_identity != expected.driver_identity
                || actual.runtime_identity != expected.runtime_identity
                || actual.capacity_bytes != expected.capacity_bytes
            {
                return Err(format!(
                    "live GPU device at ordered position {position} does not match calibrated identity"
                ));
            }
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), String> {
        if self.schema_version != GPU_DEVICE_ROUTE_SCHEMA_VERSION {
            return Err(format!(
                "unsupported GPU device route schema {}; expected {}",
                self.schema_version, GPU_DEVICE_ROUTE_SCHEMA_VERSION
            ));
        }
        if self.workload_identity.trim().is_empty()
            || self.detector_digest.trim().is_empty()
            || self.config_digest.trim().is_empty()
        {
            return Err("GPU device route workload/detector/config identity is incomplete".to_string());
        }
        if self.devices.is_empty() || self.devices.len() > MAX_GPU_ROUTE_DEVICES {
            return Err(format!(
                "GPU device route contains {} devices; expected 1..={MAX_GPU_ROUTE_DEVICES}",
                self.devices.len()
            ));
        }
        if self.process_resident_limit_bytes == 0 {
            return Err("GPU process-wide resident limit is zero".to_string());
        }
        let mut resident_total = 0u64;
        for (device_index, device) in self.devices.iter().enumerate() {
            if !device.software_eligible || !device.display_eligible {
                return Err("GPU route contains an ineligible software or display-only adapter".to_string());
            }
            if device.physical_identity.trim().is_empty()
                || device.topology_identity.trim().is_empty()
                || device.driver_identity.trim().is_empty()
                || device.runtime_identity.trim().is_empty()
            {
                return Err("GPU route contains incomplete device identity".to_string());
            }
            if self.devices[..device_index].iter().any(|prior| {
                prior.physical_identity == device.physical_identity
                    && prior.topology_identity == device.topology_identity
            }) {
                return Err("GPU route contains a duplicate physical adapter".to_string());
            }
            if device.capacity_bytes == 0
                || device.resident_budget_bytes == 0
                || device.resident_budget_bytes > device.capacity_bytes
            {
                return Err("GPU route contains an invalid per-device resident budget".to_string());
            }
            resident_total = resident_total
                .checked_add(device.resident_budget_bytes)
                .ok_or_else(|| "GPU route resident budget sum overflows u64".to_string())?;
            if device.workload_weight == 0
                || device.workload_weight > MAX_GPU_DEVICE_WEIGHT
                || device.timing.sample_bytes == 0
                || device.timing.trials_ns.is_empty()
                || device.timing.trials_ns.len() > MAX_GPU_DEVICE_TIMING_TRIALS
                || device.timing.trials_ns.iter().any(|trial| *trial == 0)
            {
                return Err("GPU route contains missing per-workload weight or timing evidence".to_string());
            }
        }
        if resident_total > self.process_resident_limit_bytes {
            return Err(format!(
                "GPU route resident budgets total {resident_total} bytes, above process ceiling {}",
                self.process_resident_limit_bytes
            ));
        }
        Ok(())
    }

    fn compute_digest(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"keyhog-ordered-gpu-device-route-v1\0");
        hasher.update(&self.schema_version.to_le_bytes());
        hash_str(&mut hasher, &self.workload_identity);
        hash_str(&mut hasher, &self.detector_digest);
        hash_str(&mut hasher, &self.config_digest);
        hasher.update(&self.process_resident_limit_bytes.to_le_bytes());
        hasher.update(&(self.devices.len() as u64).to_le_bytes());
        for device in &self.devices {
            hasher.update(&[device.api as u8]);
            hasher.update(&(device.api_ordinal as u64).to_le_bytes());
            hash_str(&mut hasher, &device.physical_identity);
            hash_str(&mut hasher, &device.topology_identity);
            hasher.update(&[device.software_eligible as u8, device.display_eligible as u8]);
            hash_str(&mut hasher, &device.driver_identity);
            hash_str(&mut hasher, &device.runtime_identity);
            hasher.update(&device.capacity_bytes.to_le_bytes());
            hasher.update(&device.workload_weight.to_le_bytes());
            hasher.update(&device.timing.sample_bytes.to_le_bytes());
            hasher.update(&(device.timing.trials_ns.len() as u64).to_le_bytes());
            for trial in &device.timing.trials_ns {
                hasher.update(&trial.to_le_bytes());
            }
            hasher.update(&device.resident_budget_bytes.to_le_bytes());
        }
        hasher.finalize().to_hex().to_string()
    }
}

fn hash_str(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactShard {
    pub index: usize,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShardAssignment {
    pub shard_index: usize,
    pub device_index: usize,
}

/// A borrowed single-device plan avoids every scheduling allocation.
#[derive(Debug, Eq, PartialEq)]
pub enum WeightedShardPlan<'a> {
    SingleDevice(&'a [ExactShard]),
    MultiDevice(Vec<ShardAssignment>),
}

pub fn partition_exact_shards<'a>(
    route: &OrderedGpuDeviceRoute,
    shards: &'a [ExactShard],
) -> Result<WeightedShardPlan<'a>, String> {
    route.validate()?;
    if shards.len() > MAX_GPU_ROUTE_SHARDS {
        return Err(format!(
            "GPU shard count {} exceeds bounded limit {MAX_GPU_ROUTE_SHARDS}",
            shards.len()
        ));
    }
    if route.devices.len() == 1 {
        return Ok(WeightedShardPlan::SingleDevice(shards));
    }
    let mut assigned_cost = vec![0u128; route.devices.len()];
    let mut assignments = Vec::new();
    assignments
        .try_reserve_exact(shards.len())
        .map_err(|error| format!("GPU shard assignment reserve failed: {error}"))?;
    for shard in shards {
        let cost = u128::from(shard.bytes.max(1));
        let mut selected = 0usize;
        for candidate in 1..route.devices.len() {
            let left = assigned_cost[candidate]
                .checked_mul(u128::from(route.devices[selected].workload_weight))
                .ok_or_else(|| "GPU weighted shard comparison overflows u128".to_string())?;
            let right = assigned_cost[selected]
                .checked_mul(u128::from(route.devices[candidate].workload_weight))
                .ok_or_else(|| "GPU weighted shard comparison overflows u128".to_string())?;
            if left < right {
                selected = candidate;
            }
        }
        assigned_cost[selected] = assigned_cost[selected]
            .checked_add(cost)
            .ok_or_else(|| "GPU assigned shard cost overflows u128".to_string())?;
        assignments.push(ShardAssignment {
            shard_index: shard.index,
            device_index: selected,
        });
    }
    Ok(WeightedShardPlan::MultiDevice(assignments))
}

/// Checked resident-byte accounting performed before backend allocation.
#[derive(Debug)]
pub struct ResidentBudgetTracker<'a> {
    route: &'a OrderedGpuDeviceRoute,
    per_device: Vec<u64>,
    process: u64,
}

impl<'a> ResidentBudgetTracker<'a> {
    pub fn new(route: &'a OrderedGpuDeviceRoute) -> Result<Self, String> {
        route.validate()?;
        Ok(Self {
            route,
            per_device: vec![0; route.devices.len()],
            process: 0,
        })
    }

    pub fn reserve(&mut self, device_index: usize, bytes: u64) -> Result<(), String> {
        let device = self.route.devices.get(device_index).ok_or_else(|| {
            format!("GPU resident reservation names missing device {device_index}")
        })?;
        let current = self.per_device[device_index];
        let next_device = current
            .checked_add(bytes)
            .ok_or_else(|| "GPU per-device resident accounting overflows u64".to_string())?;
        let next_process = self
            .process
            .checked_add(bytes)
            .ok_or_else(|| "GPU process resident accounting overflows u64".to_string())?;
        if next_device > device.resident_budget_bytes {
            return Err(format!(
                "GPU device {device_index} resident request exceeds calibrated budget {}",
                device.resident_budget_bytes
            ));
        }
        if next_process > self.route.process_resident_limit_bytes {
            return Err(format!(
                "GPU process resident request exceeds ceiling {}",
                self.route.process_resident_limit_bytes
            ));
        }
        self.per_device[device_index] = next_device;
        self.process = next_process;
        Ok(())
    }

    pub fn release(&mut self, device_index: usize, bytes: u64) -> Result<(), String> {
        let current = self.per_device.get_mut(device_index).ok_or_else(|| {
            format!("GPU resident release names missing device {device_index}")
        })?;
        *current = current
            .checked_sub(bytes)
            .ok_or_else(|| "GPU per-device resident release underflows".to_string())?;
        self.process = self
            .process
            .checked_sub(bytes)
            .ok_or_else(|| "GPU process resident release underflows".to_string())?;
        Ok(())
    }
}

/// Bounded deterministic retirement owner. Any required-device failure poisons
/// the complete route; successful siblings can never produce partial coverage.
pub struct DeterministicRetirement<T> {
    slots: Vec<Option<T>>,
    failure: Option<String>,
    cancelled: bool,
}

impl<T> DeterministicRetirement<T> {
    pub fn new(shard_count: usize) -> Result<Self, String> {
        if shard_count > MAX_GPU_ROUTE_SHARDS {
            return Err(format!(
                "GPU retirement slot count {shard_count} exceeds bounded limit {MAX_GPU_ROUTE_SHARDS}"
            ));
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(shard_count)
            .map_err(|error| format!("GPU retirement slot reserve failed: {error}"))?;
        slots.resize_with(shard_count, || None);
        Ok(Self {
            slots,
            failure: None,
            cancelled: false,
        })
    }

    pub fn record_success(&mut self, shard_index: usize, value: T) -> Result<(), String> {
        if self.cancelled || self.failure.is_some() {
            return Err("GPU route is already invalidated".to_string());
        }
        let slot = self
            .slots
            .get_mut(shard_index)
            .ok_or_else(|| format!("GPU retirement shard {shard_index} is out of bounds"))?;
        if slot.is_some() {
            return Err(format!("GPU retirement shard {shard_index} completed twice"));
        }
        *slot = Some(value);
        Ok(())
    }

    pub fn record_failure(&mut self, device_index: usize, phase: &str, error: &str) {
        if self.failure.is_none() {
            self.failure = Some(format!(
                "required GPU device {device_index} {phase} failed: {error}; the ordered device-set route is invalid"
            ));
        }
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    pub fn finish(self) -> Result<Vec<T>, String> {
        if self.cancelled {
            return Err("ordered GPU device-set route was cancelled before complete retirement".to_string());
        }
        if let Some(error) = self.failure {
            return Err(error);
        }
        self.slots
            .into_iter()
            .enumerate()
            .map(|(index, slot)| {
                slot.ok_or_else(|| {
                    format!("ordered GPU device-set route is missing retired shard {index}")
                })
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/gpu_device_set.rs"]
mod tests;
