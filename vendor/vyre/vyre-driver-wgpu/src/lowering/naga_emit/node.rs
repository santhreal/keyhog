use super::{utils::*, LoweringError, WgpuEmitNode, TRAP_SIDECAR_NAME};
use naga::{
    AtomicFunction, BinaryOperator, Block, Expression, Literal, ScalarKind, Span, Statement,
};
use naga::{GlobalVariable, LocalVariable};
use vyre_foundation::ir::{DataType, Expr, Node};
impl super::FunctionBuilder<'_> {
    pub(crate) fn emit_nodes(&mut self, nodes: &[Node]) -> Result<(), LoweringError> {
        for node in nodes {
            self.emit_node(node)?;
        }
        Ok(())
    }

    pub(crate) fn emit_node(&mut self, node: &Node) -> Result<(), LoweringError> {
        match node {
            Node::Let { name, value } => {
                let value_handle = self.emit_expr(value)?;
                let ty = self.module.scalar_type(expr_type(value, self)?)?;
                let local = self.function.local_variables.append(
                    LocalVariable {
                        name: Some(name.to_string()),
                        ty,
                        init: None,
                    },
                    Span::UNDEFINED,
                );
                let pointer = self.append_expr(Expression::LocalVariable(local));
                self.function.body.push(
                    Statement::Store {
                        pointer,
                        value: value_handle,
                    },
                    Span::UNDEFINED,
                );
                self.locals.insert(name.to_string(), local);
                self.local_types
                    .insert(name.to_string(), expr_type(value, self)?);
            }
            Node::Assign { name, value } => {
                let local = self.locals.get(name.as_str()).copied().ok_or_else(|| {
                    LoweringError::invalid(format!(
                        "assignment targets unknown local `{name}`. Fix: bind it before assignment."
                    ))
                })?;
                let pointer = self.append_expr(Expression::LocalVariable(local));
                let value = self.emit_expr(value)?;
                self.function
                    .body
                    .push(Statement::Store { pointer, value }, Span::UNDEFINED);
            }
            Node::Store {
                buffer,
                index,
                value,
            } => {
                let pointer = self.emit_buffer_pointer(buffer.as_str(), index)?;
                let mut value_handle = self.emit_expr(value)?;
                // If the target buffer is declared with DataType::Bool, the
                // storage element is u32 (bool is not HOST_SHAREABLE). Cast
                // the value from bool to u32 before storing.
                let buffer_decl_is_bool = self
                    .module
                    .buffers
                    .get(buffer.as_str())
                    .map(|b| b.decl.element == DataType::Bool)
                    .unwrap_or(false);
                if buffer_decl_is_bool {
                    value_handle = self.append_expr(Expression::As {
                        expr: value_handle,
                        kind: ScalarKind::Uint,
                        convert: Some(4),
                    });
                }
                self.function.body.push(
                    Statement::Store {
                        pointer,
                        value: value_handle,
                    },
                    Span::UNDEFINED,
                );
            }
            Node::If {
                cond,
                then,
                otherwise,
            } => {
                let condition = self.emit_bool_expr(cond)?;
                let accept = self.emit_child_block(then)?;
                let reject = self.emit_child_block(otherwise)?;
                self.function.body.push(
                    Statement::If {
                        condition,
                        accept,
                        reject,
                    },
                    Span::UNDEFINED,
                );
            }
            Node::Block(nodes) => self.emit_nodes(nodes)?,
            Node::Region {
                generator, body, ..
            } => {
                // Region is a debug-wrapper produced by vyre-libs Cat-A
                // compositions. `generator` + `source_region` are
                // informational only — they carry zero runtime
                // semantics. The body lowers identically to a sibling
                // Block. Handling Region here (instead of forcing
                // region_inline to fire upstream) keeps large-region
                // Cat-A ops like blake3_compress dispatchable without
                // callers tuning inline thresholds or running optimize()
                // manually.
                self.region_generators.push(generator.to_string());
                let region = self.emit_child_block(body.as_slice());
                self.region_generators.pop();
                self.function
                    .body
                    .push(Statement::Block(region?), Span::UNDEFINED);
            }
            Node::Barrier => self.function.body.push(
                // `Barrier::all()` in naga 24 implies the subgroup flag,
                // which requires the SUBGROUP / SUBGROUP_BARRIER device
                // capabilities. That capability isn't in the default
                // feature set the conform runner opens. Storage +
                // WorkGroup together cover every fence semantics the
                // Cat-C `workgroup_barrier` / `storage_barrier` ops
                // promise (identity store followed by a memory fence)
                // without tripping the subgroup-capability wall.
                Statement::Barrier(naga::Barrier::STORAGE | naga::Barrier::WORK_GROUP),
                Span::UNDEFINED,
            ),
            Node::Return => self
                .function
                .body
                .push(Statement::Return { value: None }, Span::UNDEFINED),
            Node::Loop {
                var,
                from,
                to,
                body,
            } => {
                let from_ty = expr_type(from, self)?;
                let to_ty = expr_type(to, self)?;
                if from_ty != to_ty {
                    return Err(LoweringError::invalid(format!(
                        "loop `{var}` has mismatched bounds: from is {from_ty:?}, to is {to_ty:?}. Fix: cast both bounds to the same integer type before lowering."
                    )));
                }
                if !matches!(from_ty, DataType::U32 | DataType::I32) {
                    return Err(LoweringError::invalid(format!(
                        "loop `{var}` uses non-integer bound type {from_ty:?}. Fix: use u32 or i32 loop bounds."
                    )));
                }

                let bound_name = self.next_temp_name("loop_to");
                let bound_value = self.emit_expr(to)?;
                let bound_local = self.function.local_variables.append(
                    LocalVariable {
                        name: Some(bound_name),
                        ty: self.module.scalar_type(to_ty.clone())?,
                        init: None,
                    },
                    Span::UNDEFINED,
                );
                let bound_pointer = self.append_expr(Expression::LocalVariable(bound_local));
                self.function.body.push(
                    Statement::Store {
                        pointer: bound_pointer,
                        value: bound_value,
                    },
                    Span::UNDEFINED,
                );

                let initial_value = self.emit_expr(from)?;
                let local = self.function.local_variables.append(
                    LocalVariable {
                        name: Some(var.to_string()),
                        ty: self.module.scalar_type(from_ty.clone())?,
                        init: None,
                    },
                    Span::UNDEFINED,
                );
                let pointer = self.append_expr(Expression::LocalVariable(local));
                self.function.body.push(
                    Statement::Store {
                        pointer,
                        value: initial_value,
                    },
                    Span::UNDEFINED,
                );

                let previous_local = self.locals.insert(var.to_string(), local);
                let previous_type = self.local_types.insert(var.to_string(), from_ty.clone());
                let result = self.emit_bounded_loop(local, bound_local, body, &from_ty);
                match previous_local {
                    Some(previous) => {
                        self.locals.insert(var.to_string(), previous);
                    }
                    None => {
                        self.locals.remove(var.as_str());
                    }
                }
                match previous_type {
                    Some(previous) => {
                        self.local_types.insert(var.to_string(), previous);
                    }
                    None => {
                        self.local_types.remove(var.as_str());
                    }
                }
                result?;
            }
            Node::IndirectDispatch { .. } => {
                return Err(LoweringError::invalid(
                    "Node::IndirectDispatch reached wgpu lowering directly. Fix: build with indirect_dispatch() so the pipeline extracts the descriptor before codegen.",
                ));
            }
            Node::AsyncLoad { .. } | Node::AsyncStore { .. } | Node::AsyncWait { .. } => {
                return Err(LoweringError::invalid(
                    "Node::AsyncLoad/AsyncStore/AsyncWait reached wgpu lowering directly. Fix: strip async nodes before GPU codegen or lower them through a runtime scheduler node.",
                ));
            }
            Node::Trap { address, tag } => self.emit_trap(address, tag.as_str())?,
            Node::Resume { .. } => {
                return Err(LoweringError::invalid(
                    "Node::Resume reached wgpu lowering directly. Fix: route resume through a runtime-owned replay path; wgpu trap propagation only records trap state.",
                ));
            }
            Node::Opaque(ext) => {
                if let Some(wgpu_ext) = ext.as_any().downcast_ref::<&dyn WgpuEmitNode>() {
                    return wgpu_ext.wgpu_emit_node(self);
                }
                return Err(LoweringError::invalid(format!(
                    "unsupported opaque node `{}` in wgpu lowering. Fix: implement WgpuEmitNode for this extension.",
                    ext.extension_kind()
                )));
            }
            _ => {
                return Err(LoweringError::invalid(
                    "unknown future Node variant reached wgpu Naga lowering. Fix: update vyre-wgpu before dispatching this Program.",
                ));
            }
        }
        Ok(())
    }

    fn emit_bounded_loop(
        &mut self,
        local: naga::Handle<LocalVariable>,
        bound_local: naga::Handle<LocalVariable>,
        body: &[Node],
        index_ty: &DataType,
    ) -> Result<(), LoweringError> {
        let mut loop_body = self.emit_loop_guard_block(local, bound_local)?;
        loop_body.extend_block(self.emit_child_block(body)?);
        let (continuing, break_if) =
            self.emit_loop_continuing_block(local, bound_local, index_ty)?;
        self.function.body.push(
            Statement::Loop {
                body: loop_body,
                continuing,
                break_if: Some(break_if),
            },
            Span::UNDEFINED,
        );
        Ok(())
    }

    fn emit_loop_guard_block(
        &mut self,
        local: naga::Handle<LocalVariable>,
        bound_local: naga::Handle<LocalVariable>,
    ) -> Result<Block, LoweringError> {
        let (guard, ()) = self.with_isolated_body(|this| {
            let condition = this.emit_loop_bound_condition(local, bound_local)?;
            let mut accept = Block::new();
            accept.push(Statement::Break, Span::UNDEFINED);
            this.function.body.push(
                Statement::If {
                    condition,
                    accept,
                    reject: Block::new(),
                },
                Span::UNDEFINED,
            );
            Ok(())
        })?;
        Ok(guard)
    }

    fn emit_trap(&mut self, address: &Expr, tag: &str) -> Result<(), LoweringError> {
        if expr_type(address, self)? != DataType::U32 {
            return Err(LoweringError::invalid(format!(
                "Node::Trap address for tag `{tag}` is not u32. Fix: cast the trap address to u32 before wgpu lowering."
            )));
        }
        let tag_code = self.trap_tag_codes.get(tag).copied().ok_or_else(|| {
            LoweringError::invalid(format!(
                "Node::Trap tag `{tag}` has no wgpu sidecar code. Fix: collect trap tags from the prepared Program before Naga emission."
            ))
        })?;

        let flag_pointer = self.emit_trap_sidecar_pointer(0)?;
        let expected_zero = self.append_expr(Expression::Literal(Literal::U32(0)));
        let flag_one = self.append_expr(Expression::Literal(Literal::U32(1)));
        let result = self.function.expressions.append(
            Expression::AtomicResult {
                ty: self.module.types.atomic_compare_exchange_u32_ty,
                comparison: true,
            },
            Span::UNDEFINED,
        );
        self.function.body.push(
            Statement::Atomic {
                pointer: flag_pointer,
                fun: AtomicFunction::Exchange {
                    compare: Some(expected_zero),
                },
                value: flag_one,
                result: Some(result),
            },
            Span::UNDEFINED,
        );

        let previous_flag = self.append_expr(Expression::AccessIndex {
            base: result,
            index: 0,
        });
        let zero = self.append_expr(Expression::Literal(Literal::U32(0)));
        let first_trap = self.append_expr(Expression::Binary {
            op: BinaryOperator::Equal,
            left: previous_flag,
            right: zero,
        });
        let (accept, ()) = self.with_isolated_body(|this| {
            let address_value = this.emit_expr(address)?;
            this.emit_trap_sidecar_atomic_exchange(1, address_value)?;
            let tag_value = this.append_expr(Expression::Literal(Literal::U32(tag_code)));
            this.emit_trap_sidecar_atomic_exchange(2, tag_value)?;
            let lane = this.emit_builtin_axis(this.gid_arg, 0)?;
            this.emit_trap_sidecar_atomic_exchange(3, lane)?;
            Ok(())
        })?;
        self.function.body.push(
            Statement::If {
                condition: first_trap,
                accept,
                reject: Block::new(),
            },
            Span::UNDEFINED,
        );
        let mut trap_return = Block::new();
        trap_return.push(Statement::Return { value: None }, Span::UNDEFINED);
        let always = self.append_expr(Expression::Literal(Literal::Bool(true)));
        self.function.body.push(
            Statement::If {
                condition: always,
                accept: trap_return,
                reject: Block::new(),
            },
            Span::UNDEFINED,
        );
        Ok(())
    }

    fn emit_trap_sidecar_pointer(
        &mut self,
        word: u32,
    ) -> Result<naga::Handle<Expression>, LoweringError> {
        let global = self.buffer_global(TRAP_SIDECAR_NAME)?;
        let base = self.append_expr(Expression::GlobalVariable(global));
        let index = self.append_expr(Expression::Literal(Literal::U32(word)));
        Ok(self.append_expr(Expression::Access { base, index }))
    }

    fn emit_trap_sidecar_atomic_exchange(
        &mut self,
        word: u32,
        value: naga::Handle<Expression>,
    ) -> Result<(), LoweringError> {
        let pointer = self.emit_trap_sidecar_pointer(word)?;
        let result = self.function.expressions.append(
            Expression::AtomicResult {
                ty: self.module.types.u32_ty,
                comparison: false,
            },
            Span::UNDEFINED,
        );
        self.function.body.push(
            Statement::Atomic {
                pointer,
                fun: AtomicFunction::Exchange { compare: None },
                value,
                result: Some(result),
            },
            Span::UNDEFINED,
        );
        Ok(())
    }

    fn emit_loop_continuing_block(
        &mut self,
        local: naga::Handle<LocalVariable>,
        bound_local: naga::Handle<LocalVariable>,
        index_ty: &DataType,
    ) -> Result<(Block, naga::Handle<Expression>), LoweringError> {
        let (continuing, break_if) = self.with_isolated_body(|this| {
            let pointer = this.append_expr(Expression::LocalVariable(local));
            let current = this.append_expr(Expression::Load { pointer });
            let one = match index_ty {
                DataType::U32 => this.append_expr(Expression::Literal(Literal::U32(1))),
                DataType::I32 => this.append_expr(Expression::Literal(Literal::I32(1))),
                other => return Err(LoweringError::unsupported_type(other)),
            };
            let next = this.append_expr(Expression::Binary {
                op: BinaryOperator::Add,
                left: current,
                right: one,
            });
            this.function.body.push(
                Statement::Store {
                    pointer,
                    value: next,
                },
                Span::UNDEFINED,
            );

            this.emit_loop_bound_condition(local, bound_local)
        })?;
        Ok((continuing, break_if))
    }

    fn emit_loop_bound_condition(
        &mut self,
        local: naga::Handle<LocalVariable>,
        bound_local: naga::Handle<LocalVariable>,
    ) -> Result<naga::Handle<Expression>, LoweringError> {
        let pointer = self.append_expr(Expression::LocalVariable(local));
        let current = self.append_expr(Expression::Load { pointer });
        let end_pointer = self.append_expr(Expression::LocalVariable(bound_local));
        let end = self.append_expr(Expression::Load {
            pointer: end_pointer,
        });
        Ok(self.append_expr(Expression::Binary {
            op: BinaryOperator::GreaterEqual,
            left: current,
            right: end,
        }))
    }

    fn emit_child_block(&mut self, nodes: &[Node]) -> Result<Block, LoweringError> {
        let saved_locals = self.locals.clone();
        let saved_local_types = self.local_types.clone();
        let (child, ()) = self.with_isolated_body(|this| this.emit_nodes(nodes))?;
        self.locals = saved_locals;
        self.local_types = saved_local_types;
        Ok(child)
    }

    fn with_isolated_body<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, LoweringError>,
    ) -> Result<(Block, T), LoweringError> {
        let saved = std::mem::replace(&mut self.function.body, Block::new());
        let result = f(self);
        let isolated = std::mem::replace(&mut self.function.body, saved);
        result.map(|value| (isolated, value))
    }

    pub(crate) fn emit_builtin_axis(
        &mut self,
        arg_index: u32,
        axis: u8,
    ) -> Result<naga::Handle<Expression>, LoweringError> {
        if axis > 2 {
            return Err(LoweringError::invalid(format!(
                "builtin axis {axis} is outside 0..=2. Fix: use x/y/z axis only."
            )));
        }
        // FunctionArgument returns a value (not a pointer). AccessIndex on a
        // vec3<u32> produces a u32 value directly — no Load required. Emitting
        // a Load here fails naga validation with `InvalidPointer`.
        let arg = self.append_expr(Expression::FunctionArgument(arg_index));
        Ok(self.append_expr(Expression::AccessIndex {
            base: arg,
            index: axis.into(),
        }))
    }

    pub(crate) fn emit_buffer_pointer(
        &mut self,
        name: &str,
        index: &Expr,
    ) -> Result<naga::Handle<Expression>, LoweringError> {
        let global = self.buffer_global(name)?;
        let base = self.append_expr(Expression::GlobalVariable(global));
        let index = self.emit_expr(index)?;
        Ok(self.append_expr(Expression::Access { base, index }))
    }

    pub(crate) fn buffer_global(
        &self,
        name: &str,
    ) -> Result<naga::Handle<GlobalVariable>, LoweringError> {
        self.module
            .buffers
            .get(name)
            .map(|binding| binding.global)
            .ok_or_else(|| {
                LoweringError::invalid(format!(
                    "unknown buffer `{name}`. Fix: declare the buffer in Program::buffers before use."
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use naga::{BuiltIn, Function};

    fn test_builder() -> super::super::FunctionBuilder<'static> {
        let module = Box::leak(Box::new(super::super::ModuleBuilder::new()));
        let mut function = Function::default();
        let gid_arg = push_builtin_arg(
            &mut function,
            "_vyre_gid",
            module.types.vec3_u32_ty,
            BuiltIn::GlobalInvocationId,
        );
        let wgid_arg = push_builtin_arg(
            &mut function,
            "_vyre_wgid",
            module.types.vec3_u32_ty,
            BuiltIn::WorkGroupId,
        );
        let lid_arg = push_builtin_arg(
            &mut function,
            "_vyre_lid",
            module.types.vec3_u32_ty,
            BuiltIn::LocalInvocationId,
        );
        super::super::FunctionBuilder {
            module,
            function,
            locals: rustc_hash::FxHashMap::default(),
            local_types: rustc_hash::FxHashMap::default(),
            gid_arg,
            wgid_arg,
            lid_arg,
            sgid_arg: None,
            sgsize_arg: None,
            temp_counter: 0,
            region_generators: Vec::new(),
            trap_tag_codes: rustc_hash::FxHashMap::default(),
        }
    }

    #[test]
    fn emit_child_block_restores_body_after_error() {
        let mut builder = test_builder();
        builder
            .function
            .body
            .push(Statement::Return { value: None }, Span::UNDEFINED);

        let err = builder.emit_child_block(&[Node::assign("missing", Expr::u32(1))]);
        assert!(err.is_err(), "missing assignment target must error");

        builder
            .function
            .body
            .push(Statement::Break, Span::UNDEFINED);
        assert_eq!(
            builder.function.body.len(),
            2,
            "Fix: failed isolated block emission must not discard previously emitted statements.",
        );
    }

    #[test]
    fn region_locals_are_scoped_to_the_region_body() {
        let mut builder = test_builder();
        builder
            .emit_node(&Node::Region {
                generator: "region_test".into(),
                source_region: None,
                body: std::sync::Arc::new(vec![Node::let_bind("scoped_value", Expr::u32(9))]),
            })
            .expect("Fix: region lowering itself must succeed.");

        let err = builder.emit_expr(&Expr::var("scoped_value"));
        assert!(
            err.is_err(),
            "Fix: locals introduced inside Node::Region must not leak into the parent scope.",
        );
    }
}
