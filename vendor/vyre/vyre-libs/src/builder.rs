//! Shared helpers used by the per-op Cat-A builders.
//!
//! Each op in `vyre-libs` ships a chainable builder that:
//!
//! 1. Accepts [`TensorRef`]s instead of bare `&str` buffer names, so
//!    dtype + shape mismatches fail at `build()` time.
//! 2. Checks every pair of buffer names is unique.
//! 3. Verifies every [`TensorRef`]'s dtype against the op's expected dtype.
//! 4. Verifies element-count overflow.
//! 5. Allows chained overrides (workgroup size, region generator,
//!    tenant id) without churning the function signature — extension
//!    fields live inside a `#[non_exhaustive]` options struct so new
//!    knobs never break existing call sites.
//!
//! `BuildOptions` is intentionally small at launch; fields are added
//! rather than removed (the `#[non_exhaustive]` attribute enforces
//! this). Every Cat-A op exposes its builder as `<Op>Builder::new(...)`
//! and delegates defaults through `BuildOptions::default()`.

use vyre::ir::DataType;

use crate::tensor_ref::{TensorRef, TensorRefError};

/// Shared options every Cat-A builder threads through. Lives here so
/// every op agrees on the same surface.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct BuildOptions {
    /// Workgroup size override. `None` = op's canonical default.
    pub workgroup_size: Option<[u32; 3]>,
    /// Region generator override. `None` = op's canonical `"vyre-libs::…"`
    /// identifier. Used when a downstream crate wraps a Cat-A op and
    /// wants its own generator id in conformance certificates.
    pub region_generator: Option<&'static str>,
    /// Tenant id baked into the region metadata for multi-tenant
    /// deployments. Routed through the megakernel's tenant-mask table
    /// when the Program runs inside `vyre-runtime`.
    pub tenant_id: Option<u32>,
}

impl BuildOptions {
    /// Fluent constructor — start with defaults and chain overrides.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the workgroup size.
    #[must_use]
    pub fn with_workgroup_size(mut self, size: [u32; 3]) -> Self {
        self.workgroup_size = Some(size);
        self
    }

    /// Override the region generator name (must be `&'static str`).
    #[must_use]
    pub fn with_region_generator(mut self, name: &'static str) -> Self {
        self.region_generator = Some(name);
        self
    }

    /// Stamp a tenant id into the Cat-A op's region metadata.
    #[must_use]
    pub fn with_tenant_id(mut self, tenant_id: u32) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }
}

/// Validate a slice of `TensorRef`s against an expected `DataType`
/// for each position, plus name-uniqueness across the whole slice.
/// Used by every op's `build()` to consolidate the fanout of checks.
pub fn check_tensors(
    op: &'static str,
    tensors: &[(&TensorRef, DataType)],
) -> Result<(), TensorRefError> {
    // Dtype check per tensor.
    for (r, expected) in tensors {
        crate::tensor_ref::check_dtype(r, expected.clone(), op)?;
        if r.element_count().is_none() {
            return Err(TensorRefError::ElementCountOverflow {
                name: r.name.as_str().to_string(),
                shape: r.shape.to_vec(),
            });
        }
    }
    // Name-uniqueness check across the whole slice.
    let refs: Vec<&TensorRef> = tensors.iter().map(|(r, _)| *r).collect();
    crate::tensor_ref::check_unique_names(&refs, op)?;
    Ok(())
}

/// Tensor-ref elementwise builders; reserved for upcoming domain ops.
#[allow(dead_code)]
pub(crate) fn build_elementwise_binary<F>(
    op_id: &'static str,
    a: crate::tensor_ref::TensorRef,
    b: crate::tensor_ref::TensorRef,
    out: crate::tensor_ref::TensorRef,
    options: BuildOptions,
    f: F,
) -> Result<vyre::ir::Program, crate::tensor_ref::TensorRefError>
where
    F: Fn(vyre::ir::Expr, vyre::ir::Expr) -> vyre::ir::Expr,
{
    check_tensors(
        op_id,
        &[
            (&a, vyre::ir::DataType::U32),
            (&b, vyre::ir::DataType::U32),
            (&out, vyre::ir::DataType::U32),
        ],
    )?;

    if a.shape != b.shape || a.shape != out.shape {
        return Err(crate::tensor_ref::TensorRefError::ShapeMismatch {
            name: "elementwise_binary".into(),
            found: vec![],
            expected: vec![],
            op: op_id,
        });
    }

    let a_count = a.element_count().unwrap();
    let out_count = out.element_count().unwrap();
    if out_count < a_count {
        return Err(crate::tensor_ref::TensorRefError::ShapeMismatch {
            name: out.name_str().to_string(),
            found: out.shape.to_vec(),
            expected: a.shape.to_vec(),
            op: op_id,
        });
    }

    let n = a.element_count().unwrap();
    let body = vec![
        vyre::ir::Node::let_bind("idx", vyre::ir::Expr::InvocationId { axis: 0 }),
        vyre::ir::Node::if_then(
            vyre::ir::Expr::lt(vyre::ir::Expr::var("idx"), vyre::ir::Expr::u32(n)),
            vec![vyre::ir::Node::store(
                out.name_str(),
                vyre::ir::Expr::var("idx"),
                f(
                    vyre::ir::Expr::load(a.name_str(), vyre::ir::Expr::var("idx")),
                    vyre::ir::Expr::load(b.name_str(), vyre::ir::Expr::var("idx")),
                ),
            )],
        ),
    ];

    let group = options.workgroup_size.unwrap_or([64, 1, 1]);

    Ok(vyre::ir::Program::wrapped(
        vec![
            vyre::ir::BufferDecl::storage(
                a.name_str(),
                0,
                vyre::ir::BufferAccess::ReadOnly,
                vyre::ir::DataType::U32,
            )
            .with_count(n),
            vyre::ir::BufferDecl::storage(
                b.name_str(),
                1,
                vyre::ir::BufferAccess::ReadOnly,
                vyre::ir::DataType::U32,
            )
            .with_count(n),
            vyre::ir::BufferDecl::output(out.name_str(), 2, vyre::ir::DataType::U32).with_count(n),
        ],
        group,
        vec![crate::region::wrap_anonymous(op_id, body)],
    ))
}

#[allow(dead_code)]
pub(crate) fn build_elementwise_unary<F>(
    op_id: &'static str,
    a: crate::tensor_ref::TensorRef,
    out: crate::tensor_ref::TensorRef,
    options: BuildOptions,
    f: F,
) -> Result<vyre::ir::Program, crate::tensor_ref::TensorRefError>
where
    F: Fn(vyre::ir::Expr) -> vyre::ir::Expr,
{
    check_tensors(
        op_id,
        &[
            (&a, vyre::ir::DataType::U32),
            (&out, vyre::ir::DataType::U32),
        ],
    )?;

    if a.shape != out.shape {
        return Err(crate::tensor_ref::TensorRefError::ShapeMismatch {
            name: "elementwise_unary".into(),
            found: vec![],
            expected: vec![],
            op: op_id,
        });
    }

    let n = a.element_count().unwrap();
    let body = vec![
        vyre::ir::Node::let_bind("idx", vyre::ir::Expr::InvocationId { axis: 0 }),
        vyre::ir::Node::if_then(
            vyre::ir::Expr::lt(vyre::ir::Expr::var("idx"), vyre::ir::Expr::u32(n)),
            vec![vyre::ir::Node::store(
                out.name_str(),
                vyre::ir::Expr::var("idx"),
                f(vyre::ir::Expr::load(
                    a.name_str(),
                    vyre::ir::Expr::var("idx"),
                )),
            )],
        ),
    ];

    let group = options.workgroup_size.unwrap_or([64, 1, 1]);

    Ok(vyre::ir::Program::wrapped(
        vec![
            vyre::ir::BufferDecl::storage(
                a.name_str(),
                0,
                vyre::ir::BufferAccess::ReadOnly,
                vyre::ir::DataType::U32,
            )
            .with_count(n),
            vyre::ir::BufferDecl::output(out.name_str(), 1, vyre::ir::DataType::U32).with_count(n),
        ],
        group,
        vec![crate::region::wrap_anonymous(op_id, body)],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_options_defaults_are_all_none() {
        let o = BuildOptions::default();
        assert!(o.workgroup_size.is_none());
        assert!(o.region_generator.is_none());
        assert!(o.tenant_id.is_none());
    }

    #[test]
    fn build_options_chain_preserves_earlier_setters() {
        let o = BuildOptions::new()
            .with_workgroup_size([128, 1, 1])
            .with_region_generator("test::op")
            .with_tenant_id(7);
        assert_eq!(o.workgroup_size, Some([128, 1, 1]));
        assert_eq!(o.region_generator, Some("test::op"));
        assert_eq!(o.tenant_id, Some(7));
    }

    #[test]
    fn check_tensors_passes_on_clean_inputs() {
        let a = TensorRef::u32_1d("a", 4);
        let b = TensorRef::u32_1d("b", 4);
        assert!(check_tensors("op", &[(&a, DataType::U32), (&b, DataType::U32)]).is_ok());
    }

    #[test]
    fn check_tensors_catches_dtype_mismatch() {
        let a = TensorRef::u32_1d("a", 4);
        let err = check_tensors("op", &[(&a, DataType::F32)]).unwrap_err();
        assert!(matches!(err, TensorRefError::DtypeMismatch { .. }));
    }

    #[test]
    fn check_tensors_catches_overflow() {
        let a = TensorRef::new("big", DataType::U32, vec![1u32 << 20, 1u32 << 20]);
        let err = check_tensors("op", &[(&a, DataType::U32)]).unwrap_err();
        assert!(matches!(err, TensorRefError::ElementCountOverflow { .. }));
    }

    #[test]
    fn check_tensors_catches_name_collision() {
        let a = TensorRef::u32_1d("x", 4);
        let b = TensorRef::u32_1d("x", 4);
        let err = check_tensors("op", &[(&a, DataType::U32), (&b, DataType::U32)]).unwrap_err();
        assert!(matches!(err, TensorRefError::NameCollision { .. }));
    }
}
