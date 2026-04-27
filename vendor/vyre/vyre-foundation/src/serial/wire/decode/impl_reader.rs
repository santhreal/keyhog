use crate::ir::DataType;
use crate::serial::wire::decode::reject_reserved_extension_id;
use crate::serial::wire::tags::{
    atomic_op_from_tag, bin_op_from_tag, data_type_from_tag, un_op_from_tag,
};
use crate::serial::wire::{Expr, Node, Reader, MAX_ARGS, MAX_DECODE_DEPTH, MAX_NODES};

impl Reader<'_> {
    /// Decode a statement-node vector from the wire format.
    ///
    /// # Wire-format layout
    ///
    /// A little-endian `u32` count (checked against `MAX_NODES`), followed by
    /// that many `Node` records decoded via `Reader::node`.
    ///
    /// # Bounds checks
    ///
    /// * Count > `MAX_NODES` → rejected with a `Fix:` error (I10).
    /// * Underlying bytes truncated before the last node → rejected by the
    ///   sub-decode calls.
    ///
    /// # Return semantics
    ///
    /// * `Ok(Vec<Node>)` – owned vector of decoded statements.
    /// * `Err(String)` – actionable `Fix:`-prefixed error (truncation, unknown
    ///   tag, depth limit, etc.).
    #[inline]
    pub(crate) fn nodes(&mut self) -> Result<Vec<Node>, String> {
        let count = self.bounded_len(MAX_NODES, "node count")?;
        let mut nodes = Vec::with_capacity(count);
        for _ in 0..count {
            nodes.push(self.node()?);
        }
        Ok(nodes)
    }

    /// Decode a single `Node` from the wire format.
    ///
    /// # Decode-time invariants
    ///
    /// Reads a one-byte tag and dispatches:
    /// * `0` – `Let` (name string, value expression)
    /// * `1` – `Assign` (name string, value expression)
    /// * `2` – `Store` (buffer name string, index expression, value expression)
    /// * `3` – `If` (condition expression, then-body node list, else-body node list)
    /// * `4` – `Loop` (variable name string, from expression, to expression,
    ///   body node list)
    /// * `5` – `Return`
    /// * `6` – `Block` (nested node list)
    /// * `7` – `Barrier`
    /// * `8` – `IndirectDispatch` (count buffer name string, count offset `u64`)
    /// * `9` – `AsyncLoad` (tag string)
    /// * `10` – `AsyncWait` (tag string)
    /// * `13` – `Trap` (address expression, tag string)
    /// * `14` – `Resume` (tag string)
    /// * any other tag – rejected as unknown.
    ///
    /// # Recursion guard (L.1.35)
    ///
    /// Increments `Reader::depth` on entry and decrements on exit.
    /// If the depth already equals `MAX_DECODE_DEPTH`, the blob is rejected
    /// **before** any further decode to prevent stack-overflow DoS from
    /// deeply nested `Block`, `If`, or `Loop` bodies.
    ///
    /// # Return semantics
    ///
    /// * `Ok(Node)` – successfully decoded statement.
    /// * `Err(String)` – actionable `Fix:`-prefixed error describing the
    ///   failure (unknown tag, depth exceeded, truncation, etc.).
    #[inline]
    pub(crate) fn node(&mut self) -> Result<Node, String> {
        // Recursion guard: every `node()` enter increments depth, every
        // exit decrements. Nested decode stops at `MAX_DECODE_DEPTH`.
        if self.depth >= MAX_DECODE_DEPTH {
            return Err(format!(
                "Fix: IR wire format exceeds maximum decode depth {MAX_DECODE_DEPTH}; flatten deeply nested Block/If/Loop structures or reject this untrusted blob."
            ));
        }
        self.depth += 1;
        let result = self.node_inner();
        self.depth -= 1;
        result
    }

    fn node_inner(&mut self) -> Result<Node, String> {
        match self.u8()? {
            0 => Ok(Node::Let {
                name: self.string()?.into(),
                value: self.expr()?,
            }),
            1 => Ok(Node::Assign {
                name: self.string()?.into(),
                value: self.expr()?,
            }),
            2 => Ok(Node::Store {
                buffer: self.string()?.into(),
                index: self.expr()?,
                value: self.expr()?,
            }),
            3 => Ok(Node::If {
                cond: self.expr()?,
                then: self.nodes()?,
                otherwise: self.nodes()?,
            }),
            4 => Ok(Node::Loop {
                var: self.string()?.into(),
                from: self.expr()?,
                to: self.expr()?,
                body: self.nodes()?,
            }),
            5 => Ok(Node::Return),
            6 => Ok(Node::Block(self.nodes()?)),
            7 => Ok(Node::Barrier),
            8 => Ok(Node::IndirectDispatch {
                count_buffer: self.string()?.into(),
                count_offset: self.u64()?,
            }),
            9 => {
                let source: crate::ir::Ident = self.string()?.into();
                let destination: crate::ir::Ident = self.string()?.into();
                let offset = self.expr()?;
                let size = self.expr()?;
                let tag: crate::ir::Ident = self.string()?.into();
                Ok(Node::async_load_ext(source, destination, offset, size, tag))
            }
            10 => Ok(Node::AsyncWait {
                tag: self.string()?.into(),
            }),
            12 => {
                let source: crate::ir::Ident = self.string()?.into();
                let destination: crate::ir::Ident = self.string()?.into();
                let offset = self.expr()?;
                let size = self.expr()?;
                let tag: crate::ir::Ident = self.string()?.into();
                Ok(Node::async_store(source, destination, offset, size, tag))
            }
            13 => Ok(Node::trap(self.expr()?, self.string()?)),
            14 => Ok(Node::resume(self.string()?)),
            11 => {
                let generator: crate::ir::Ident = self.string()?.into();
                let presence = self.u8()?;
                let source_region = match presence {
                    0 => None,
                    1 => Some(crate::ir::model::expr::GeneratorRef {
                        name: self.string()?,
                    }),
                    other => {
                        return Err(format!(
                            "Fix: Region source_region presence byte must be 0 or 1, got {other}"
                        ));
                    }
                };
                let body = self.nodes()?;
                Ok(Node::Region {
                    generator,
                    source_region,
                    body: std::sync::Arc::new(body),
                })
            }
            0x80 => {
                let kind = self.string()?;
                let payload_len = self.bounded_len(MAX_ARGS * 1024, "opaque node payload")?;
                let payload = self.bytes(payload_len)?;
                crate::extension::decode_opaque_node(&kind, &payload)
            }
            tag => Err(format!(
                "Fix: unknown IR node tag {tag}; use a Program serializer compatible with this vyre version."
            )),
        }
    }

    /// Decode a single `Expr` from the wire format.
    ///
    /// # Decode-time invariants
    ///
    /// Reads a one-byte tag and dispatches:
    /// * `0` – `LitU32` (little-endian `u32`)
    /// * `1` – `LitI32` (little-endian `i32` reinterpreted from `u32` bits)
    /// * `2` – `LitBool` (`0` = false, non-zero = true)
    /// * `3` – `Var` (string name)
    /// * `4` – `Load` (buffer name string, index expression)
    /// * `5` – `BufLen` (buffer name string)
    /// * `6` – `InvocationId` (axis `u8`)
    /// * `7` – `WorkgroupId` (axis `u8`)
    /// * `8` – `LocalId` (axis `u8`)
    /// * `9` – `BinOp` (operator tag, left expr, right expr)
    /// * `10` – `UnOp` (operator tag, operand expr)
    /// * `11` – `Call` (op id string, argument count ≤ `MAX_ARGS`, arguments)
    /// * `12` – `Select` (cond expr, true expr, false expr)
    /// * `13` – `Cast` (target `DataType`, value expr)
    /// * `14` – `Atomic` (operator tag, buffer name string, index expr,
    ///   expected-expr flag, value expr)
    /// * `15` – `LitF32` (`f32` reinterpreted from `u32` bits)
    /// * `16` – `Fma` (a expr, b expr, c expr)
    /// * any other tag – rejected as unknown.
    ///
    /// # Recursion guard (L.1.35)
    ///
    /// Increments the shared `Reader::depth` counter on entry and decrements
    /// on exit. If the depth already equals `MAX_DECODE_DEPTH`, the blob is
    /// rejected **before** any nested expression is decoded. This prevents
    /// stack-overflow DoS from arbitrarily nested `BinOp`, `UnOp`, `Select`,
    /// `Cast`, or `Call` argument trees.
    ///
    /// # Return semantics
    ///
    /// * `Ok(Expr)` – successfully decoded expression.
    /// * `Err(String)` – actionable `Fix:`-prefixed error (unknown tag, depth
    ///   exceeded, truncation, invalid UTF-8, etc.).
    #[inline]
    pub(crate) fn expr(&mut self) -> Result<Expr, String> {
        // Recursion guard for arbitrarily nested Expr trees (BinOp, UnOp,
        // Select, Cast, Call arg lists, etc). Shares the same depth
        // counter and budget as `node()` so a hostile blob can't evade
        // the limit by alternating statement and expression levels.
        if self.depth >= MAX_DECODE_DEPTH {
            return Err(format!(
                "Fix: IR wire format exceeds maximum decode depth {MAX_DECODE_DEPTH}; flatten deeply nested Expr trees or reject this untrusted blob."
            ));
        }
        self.depth += 1;
        let result = self.expr_inner();
        self.depth -= 1;
        result
    }

    /// Decode a `DataType` from the wire format.
    ///
    /// # Wire-format tag semantics
    ///
    /// * `12` – dynamic-length `Array` type: a little-endian `u32` element size
    ///   follows, which must fit in `usize` on the target platform.
    /// * any other value – forwarded to `data_type_from_tag`, which maps
    ///   fixed scalar tags (`u8`/`i8`/`u32`/etc.) to their `DataType`
    ///   variants. Unknown scalar tags are rejected there.
    ///
    /// # Bounds checks
    ///
    /// * `element_size` > `usize::MAX` on the current target → rejected with a
    ///   `Fix:` error advising decode on a supported target or rejection of the
    ///   blob.
    ///
    /// # Return semantics
    ///
    /// * `Ok(DataType)` – valid scalar or array type.
    /// * `Err(String)` – actionable `Fix:`-prefixed error (overflow or unknown
    ///   scalar tag).
    #[inline]
    pub(crate) fn data_type(&mut self) -> Result<DataType, String> {
        let tag = self.u8()?;
        if tag == 0x08 {
            let element_size = usize::try_from(self.u32()?).map_err(|err| {
                format!(
                    "Fix: array element_size cannot fit usize on this target ({err}); decode this VIR0 blob on a supported target or reject it."
                )
            })?;
            return Ok(DataType::Array { element_size });
        }
        if tag == 0x13 {
            return Ok(DataType::Handle(vyre_spec::data_type::TypeId(self.u32()?)));
        }
        if tag == 0x14 {
            let element = Box::new(self.data_type()?);
            let count = self.u8()?;
            return Ok(DataType::Vec { element, count });
        }
        if tag == 0x15 {
            let element = Box::new(self.data_type()?);
            let len = usize::try_from(self.u32()?).map_err(|err| {
                format!("Fix: tensor rank cannot fit usize on this target ({err}); reject this VIR0 blob.")
            })?;
            let mut shape = smallvec::SmallVec::<[u32; 4]>::new();
            for _ in 0..len {
                shape.push(self.u32()?);
            }
            return Ok(DataType::TensorShaped { element, shape });
        }
        if tag == 0x80 {
            // Opaque: u32 extension id follows.
            let id = reject_reserved_extension_id(self.u32()?, "DataType")?;
            return Ok(DataType::Opaque(vyre_spec::extension::ExtensionDataTypeId(
                id,
            )));
        }
        data_type_from_tag(tag)
    }

    fn expr_inner(&mut self) -> Result<Expr, String> {
        match self.u8()? {
            0 => Ok(Expr::LitU32(self.u32()?)),
            1 => Ok(Expr::LitI32(self.i32()?)),
            2 => Ok(Expr::LitBool(self.u8()? != 0)),
            15 => Ok(Expr::LitF32(f32::from_bits(self.u32()?))),
            3 => Ok(Expr::Var(self.string()?.into())),
            4 => Ok(Expr::Load {
                buffer: self.string()?.into(),
                index: Box::new(self.expr()?),
            }),
            5 => Ok(Expr::BufLen {
                buffer: self.string()?.into(),
            }),
            6 => Ok(Expr::InvocationId { axis: self.u8()? }),
            7 => Ok(Expr::WorkgroupId { axis: self.u8()? }),
            8 => Ok(Expr::LocalId { axis: self.u8()? }),
            9 => {
                let tag = self.u8()?;
                let op = if tag == 0x80 {
                    // Opaque BinOp: u32 extension id follows.
                    let id = reject_reserved_extension_id(self.u32()?, "BinOp")?;
                    crate::ir::BinOp::Opaque(vyre_spec::extension::ExtensionBinOpId(id))
                } else {
                    bin_op_from_tag(tag)?
                };
                Ok(Expr::BinOp {
                    op,
                    left: Box::new(self.expr()?),
                    right: Box::new(self.expr()?),
                })
            }
            10 => {
                let tag = self.u8()?;
                let op = if tag == 0x80 {
                    let id = reject_reserved_extension_id(self.u32()?, "UnOp")?;
                    crate::ir::UnOp::Opaque(vyre_spec::extension::ExtensionUnOpId(id))
                } else {
                    un_op_from_tag(tag)?
                };
                Ok(Expr::UnOp {
                    op,
                    operand: Box::new(self.expr()?),
                })
            }
            11 => {
                let op_id = self.string()?.into();
                let count = self.bounded_len(MAX_ARGS, "call argument count")?;
                let mut args = Vec::with_capacity(count);
                for _ in 0..count {
                    args.push(self.expr()?);
                }
                Ok(Expr::Call { op_id, args })
            }
            12 => Ok(Expr::Select {
                cond: Box::new(self.expr()?),
                true_val: Box::new(self.expr()?),
                false_val: Box::new(self.expr()?),
            }),
            13 => Ok(Expr::Cast {
                target: self.data_type()?,
                value: Box::new(self.expr()?),
            }),
            14 => {
                let tag = self.u8()?;
                let op = if tag == 0x80 {
                    let id = reject_reserved_extension_id(self.u32()?, "AtomicOp")?;
                    crate::ir::AtomicOp::Opaque(vyre_spec::extension::ExtensionAtomicOpId(id))
                } else {
                    atomic_op_from_tag(tag)?
                };
                Ok(Expr::Atomic {
                    op,
                    buffer: self.string()?.into(),
                    index: Box::new(self.expr()?),
                    expected: if self.u8()? == 0 {
                        None
                    } else {
                        Some(Box::new(self.expr()?))
                    },
                    value: Box::new(self.expr()?),
                })
            }
            16 => Ok(Expr::Fma {
                a: Box::new(self.expr()?),
                b: Box::new(self.expr()?),
                c: Box::new(self.expr()?),
            }),
            17 => Ok(Expr::SubgroupAdd {
                value: Box::new(self.expr()?),
            }),
            18 => Ok(Expr::SubgroupShuffle {
                value: Box::new(self.expr()?),
                lane: Box::new(self.expr()?),
            }),
            19 => Ok(Expr::SubgroupBallot {
                cond: Box::new(self.expr()?),
            }),
            20 => Ok(Expr::SubgroupLocalId),
            21 => Ok(Expr::SubgroupSize),
            0x80 => {
                let kind = self.string()?;
                let payload_len = self.bounded_len(MAX_ARGS * 1024, "opaque expression payload")?;
                let payload = self.bytes(payload_len)?;
                crate::extension::decode_opaque_expr(&kind, &payload)
            }
            tag => Err(format!(
                "Fix: unknown IR expression tag {tag}; use a Program serializer compatible with this vyre version."
            )),
        }
    }
}
