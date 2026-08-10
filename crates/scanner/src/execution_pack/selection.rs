use super::{
    ExecutionPack, ExecutionPackBackend, ExecutionPackError, ExecutionPackIdentity,
    ExecutionPackPolicy, ExecutionPackSigningKey,
};
use std::path::PathBuf;

pub const ROUTE_DECISION_VERSION: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteSelectionContext {
    pub policy: ExecutionPackPolicy,
    pub workload_digest: [u8; 32],
    pub host_digest: [u8; 32],
    pub calibration_digest: [u8; 32],
    pub feature_schema_digest: [u8; 32],
    pub quantized_model_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistedRouteDecision {
    pub version: u16,
    pub policy: ExecutionPackPolicy,
    pub backend: ExecutionPackBackend,
    pub workload_digest: [u8; 32],
    pub host_digest: [u8; 32],
    pub calibration_digest: [u8; 32],
    pub pack_identity_digest: [u8; 32],
    pub pack_content_digest: [u8; 32],
    pub feature_schema_digest: [u8; 32],
    pub quantized_model_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionPackCandidate {
    pub backend: ExecutionPackBackend,
    pub path: PathBuf,
    pub signature_path: PathBuf,
    pub identity: ExecutionPackIdentity,
}

impl ExecutionPackCandidate {
    pub fn new(
        backend: ExecutionPackBackend,
        path: impl Into<PathBuf>,
        signature_path: impl Into<PathBuf>,
        identity: ExecutionPackIdentity,
    ) -> Self {
        Self {
            backend,
            path: path.into(),
            signature_path: signature_path.into(),
            identity,
        }
    }
}

pub struct SelectedExecutionPack {
    decision: PersistedRouteDecision,
    pack: ExecutionPack,
}

impl SelectedExecutionPack {
    pub const fn decision(&self) -> PersistedRouteDecision {
        self.decision
    }

    pub fn pack(&self) -> &ExecutionPack {
        &self.pack
    }
}

/// Select one calibrated route from metadata, then map only that backend pack.
pub fn select_execution_pack(
    context: RouteSelectionContext,
    decision: PersistedRouteDecision,
    signing_key: &ExecutionPackSigningKey,
    candidates: &[ExecutionPackCandidate],
) -> Result<SelectedExecutionPack, ExecutionPackError> {
    validate_decision(context, decision)?;
    let mut selected: Option<&ExecutionPackCandidate> = None;
    for candidate in candidates {
        if candidate.backend != candidate.identity.backend {
            return Err(ExecutionPackError::InvalidPack(format!(
                "execution-pack candidate {} labels backend {:?} but its identity names {:?}",
                candidate.path.display(),
                candidate.backend,
                candidate.identity.backend
            )));
        }
        if candidate.backend == decision.backend {
            if selected.replace(candidate).is_some() {
                return Err(ExecutionPackError::InvalidPack(format!(
                    "route decision {:?} has multiple execution-pack candidates; publish one immutable generation",
                    decision.backend
                )));
            }
        }
    }
    let selected = selected.ok_or_else(|| {
        ExecutionPackError::Incompatible(format!(
            "route decision {:?} has no execution pack; reinstall and recalibrate",
            decision.backend
        ))
    })?;
    if selected.identity.policy != decision.policy {
        return Err(ExecutionPackError::Incompatible(format!(
            "selected execution pack policy {:?} does not match route decision {:?}; reinstall and recalibrate",
            selected.identity.policy, decision.policy
        )));
    }
    if selected.identity.digest() != decision.pack_identity_digest {
        return Err(ExecutionPackError::Incompatible(format!(
            "selected execution pack {} identity does not match the calibrated route; reinstall and recalibrate",
            selected.path.display()
        )));
    }

    let pack = ExecutionPack::open_authenticated(
        &selected.path,
        &selected.signature_path,
        selected.identity,
        signing_key,
    )?;
    if pack.content_digest() != decision.pack_content_digest {
        return Err(ExecutionPackError::Incompatible(format!(
            "selected execution pack {} content does not match the calibrated route; reinstall and recalibrate",
            selected.path.display()
        )));
    }
    Ok(SelectedExecutionPack { decision, pack })
}

fn validate_decision(
    context: RouteSelectionContext,
    decision: PersistedRouteDecision,
) -> Result<(), ExecutionPackError> {
    if decision.version != ROUTE_DECISION_VERSION {
        return Err(ExecutionPackError::Incompatible(format!(
            "autoroute decision version {} is unsupported; recalibrate with this binary",
            decision.version
        )));
    }
    for (name, actual, expected) in [
        (
            "workload",
            decision.workload_digest,
            context.workload_digest,
        ),
        ("host", decision.host_digest, context.host_digest),
        (
            "calibration",
            decision.calibration_digest,
            context.calibration_digest,
        ),
    ] {
        if actual != expected {
            return Err(ExecutionPackError::Incompatible(format!(
                "autoroute {name} identity is stale; recalibrate before scanning"
            )));
        }
    }
    for (name, actual, expected) in [
        (
            "feature schema",
            decision.feature_schema_digest,
            context.feature_schema_digest,
        ),
        (
            "quantized model",
            decision.quantized_model_digest,
            context.quantized_model_digest,
        ),
    ] {
        if actual != expected {
            return Err(ExecutionPackError::Incompatible(format!(
                "autoroute {name} identity is stale; reinstall and recalibrate"
            )));
        }
    }
    if decision.policy != context.policy {
        return Err(ExecutionPackError::Incompatible(
            "autoroute policy identity is stale; recalibrate before scanning".to_owned(),
        ));
    }
    Ok(())
}
