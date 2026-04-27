//! Program → required-capability analysis.
//!
//! Scan a `Program` and report the hardware capabilities its lowering will
//! need. Callers (backends, conformance harnesses, certificate emitters)
//! compare the required set against what a backend advertises and surface
//! `MissingCapability` *before* handing the kernel to the device, avoiding
//! panics inside `create_shader_module` / `createComputePipeline`.
//!
//! The scanner is strictly syntactic: it walks every `Expr` and `Node` in
//! the program and checks the IR surface. It intentionally does **not**
//! know anything about backend-specific lowering rules — that would make it
//! a circular dependency of the very thing it is supposed to gate.

use std::fmt;

use crate::ir::Program;

/// Capabilities a `Program` needs from whichever backend executes it.
///
/// This is a structured replacement for hardcoded "exempt op" lists. A
/// universal diff harness asks `scan(program)` which bits the program
/// needs, asks the backend which bits it advertises, and skips the pair
/// when they disagree. The result reasons are attached for telemetry.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct RequiredCapabilities {
    /// The program invokes `Expr::SubgroupAdd`, `SubgroupBallot`, or
    /// `SubgroupShuffle`. Lowering paths need the SUBGROUP / wave-op
    /// feature on the target device.
    pub subgroup_ops: bool,
    /// The program uses any IEEE 754 binary16 operand.
    pub f16: bool,
    /// The program uses any bfloat16 operand.
    pub bf16: bool,
    /// The program uses 64-bit floats.
    pub f64: bool,
    /// The program dispatches async DMA (`Node::AsyncLoad` / `AsyncStore`).
    pub async_dispatch: bool,
    /// The program emits `Node::IndirectDispatch`.
    pub indirect_dispatch: bool,
    /// The program reaches into tensor / tensor-core operand types.
    pub tensor_ops: bool,
    /// The program uses a `Node::Trap` — backend needs trap propagation.
    pub trap: bool,
    /// Maximum workgroup size declared by the program across all axes.
    pub max_workgroup_size: [u32; 3],
    /// Sum of `BufferDecl::count * sizeof(DataType)` across every buffer
    /// whose size can be computed statically. `0` means every buffer has
    /// dynamic size.
    pub static_storage_bytes: u64,
}

impl RequiredCapabilities {
    /// Empty set — the Program needs nothing beyond the minimum substrate.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Build the union of two capability sets (field-wise `OR` and `max`).
    #[must_use]
    pub fn union(mut self, other: RequiredCapabilities) -> Self {
        self.subgroup_ops |= other.subgroup_ops;
        self.f16 |= other.f16;
        self.bf16 |= other.bf16;
        self.f64 |= other.f64;
        self.async_dispatch |= other.async_dispatch;
        self.indirect_dispatch |= other.indirect_dispatch;
        self.tensor_ops |= other.tensor_ops;
        self.trap |= other.trap;
        for axis in 0..3 {
            self.max_workgroup_size[axis] =
                self.max_workgroup_size[axis].max(other.max_workgroup_size[axis]);
        }
        self.static_storage_bytes = self
            .static_storage_bytes
            .saturating_add(other.static_storage_bytes);
        self
    }
}

/// The reason a backend cannot execute a program.
///
/// Returned by [`check_backend_capabilities`] when the scan finds a
/// capability the backend did not advertise. Carries every missing bit
/// so callers can emit one actionable error instead of bisecting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissingCapability {
    /// Backend identifier that was asked to run the program.
    pub backend: String,
    /// Flat list of human-readable capability names the backend lacks.
    pub missing: Vec<&'static str>,
}

impl fmt::Display for MissingCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "backend `{}` is missing required capabilities: {}. \
             Fix: pick a backend that advertises these capabilities, \
             or run the program on the CPU reference.",
            self.backend,
            self.missing.join(", ")
        )
    }
}

impl std::error::Error for MissingCapability {}

/// Walk the program and collect the union of capabilities it requires.
#[must_use]
pub fn scan(program: &Program) -> RequiredCapabilities {
    let stats = program.stats();
    RequiredCapabilities {
        subgroup_ops: stats.subgroup_ops(),
        f16: stats.f16(),
        bf16: stats.bf16(),
        f64: stats.f64(),
        async_dispatch: stats.async_dispatch(),
        indirect_dispatch: stats.indirect_dispatch(),
        tensor_ops: stats.tensor_ops(),
        trap: stats.trap(),
        max_workgroup_size: program.workgroup_size,
        static_storage_bytes: stats.static_storage_bytes,
    }
}

/// Return `Ok(())` when a backend with the given advertised capabilities
/// can run a program whose required set is `required`, otherwise return
/// the missing-capability explanation.
///
/// The caller passes in the boolean capability queries from
/// [`crate::ir::Program`]'s backend trait (`supports_subgroup_ops`,
/// `supports_f16`, etc.) so this function stays free of the
/// `VyreBackend` trait import and can live in vyre-foundation.
pub fn check_backend_capabilities(
    backend_id: &str,
    supports_subgroup_ops: bool,
    supports_f16: bool,
    supports_bf16: bool,
    supports_indirect_dispatch: bool,
    supports_trap_propagation: bool,
    max_workgroup_size: [u32; 3],
    required: &RequiredCapabilities,
) -> Result<(), MissingCapability> {
    let mut missing = Vec::new();
    if required.subgroup_ops && !supports_subgroup_ops {
        missing.push("subgroup_ops");
    }
    if required.f16 && !supports_f16 {
        missing.push("f16");
    }
    if required.bf16 && !supports_bf16 {
        missing.push("bf16");
    }
    if required.indirect_dispatch && !supports_indirect_dispatch {
        missing.push("indirect_dispatch");
    }
    if required.trap && !supports_trap_propagation {
        missing.push("trap_propagation");
    }
    for (req_size, max_size) in required
        .max_workgroup_size
        .iter()
        .zip(max_workgroup_size.iter())
    {
        if *req_size > *max_size && *max_size != 0 {
            missing.push("workgroup_size");
            break;
        }
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(MissingCapability {
            backend: backend_id.to_string(),
            missing,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferAccess, BufferDecl, DataType, Expr as IrExpr, Node as IrNode, Program};

    fn empty_program() -> Program {
        Program::wrapped(
            vec![BufferDecl::storage(
                "out",
                0,
                BufferAccess::ReadWrite,
                DataType::U32,
            )],
            [1, 1, 1],
            vec![IrNode::let_bind("x", IrExpr::u32(0))],
        )
    }

    #[test]
    fn scan_scalar_program_declares_no_capabilities() {
        let caps = scan(&empty_program());
        assert!(!caps.subgroup_ops);
        assert!(!caps.f16);
        assert!(!caps.async_dispatch);
    }

    #[test]
    fn scan_subgroup_add_requires_subgroup_ops() {
        let program = Program::wrapped(
            vec![BufferDecl::storage(
                "out",
                0,
                BufferAccess::ReadWrite,
                DataType::U32,
            )],
            [1, 1, 1],
            vec![IrNode::let_bind(
                "s",
                IrExpr::SubgroupAdd {
                    value: Box::new(IrExpr::u32(1)),
                },
            )],
        );
        let caps = scan(&program);
        assert!(caps.subgroup_ops);
    }

    #[test]
    fn scan_call_to_subgroup_intrinsic_requires_subgroup_ops() {
        let program = Program::wrapped(
            vec![BufferDecl::storage(
                "out",
                0,
                BufferAccess::ReadWrite,
                DataType::U32,
            )],
            [1, 1, 1],
            vec![IrNode::let_bind(
                "s",
                IrExpr::call(
                    "vyre-intrinsics::math::subgroup_inclusive_add",
                    vec![IrExpr::u32(1)],
                ),
            )],
        );
        let caps = scan(&program);
        assert!(caps.subgroup_ops);
    }

    #[test]
    fn check_backend_reports_every_missing_bit() {
        let required = RequiredCapabilities {
            subgroup_ops: true,
            f16: true,
            trap: true,
            ..RequiredCapabilities::default()
        };
        let error = check_backend_capabilities(
            "test_backend",
            false,
            false,
            false,
            false,
            false,
            [64, 1, 1],
            &required,
        )
        .unwrap_err();
        assert_eq!(error.backend, "test_backend");
        assert!(error.missing.contains(&"subgroup_ops"));
        assert!(error.missing.contains(&"f16"));
        assert!(error.missing.contains(&"trap_propagation"));
    }
}
