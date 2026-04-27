use crate::parsing::c::lex::tokens::*;
use crate::parsing::c::sema::{
    intern::emit_identifier_intern,
    lookup::{
        emit_declaration_lookup, DECL_KIND_ENUM_CONSTANT, DECL_KIND_FUNCTION,
        DECL_KIND_FUNCTION_DECL, DECL_KIND_LABEL, DECL_KIND_NONE, DECL_KIND_TYPEDEF,
        DECL_KIND_VARIABLE,
    },
    walk::emit_scope_resolution,
};
use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Map token index `i` to:
///
/// 1. `scope_id`
/// 2. `scope_parent_id`
/// 3. `decl_kind`
/// 4. `identifier_intern_id`
///
/// The output is one 4-word record per token.
#[must_use]
pub fn c_sema_scope(
    tok_types: &str,
    tok_starts: &str,
    tok_lens: &str,
    haystack: &str,
    haystack_len: Expr,
    num_tokens: Expr,
    out_scope_tree: &str,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let tok_count = match &num_tokens {
        Expr::LitU32(n) => *n,
        _ => 1,
    };
    let haystack_words = match &haystack_len {
        Expr::LitU32(n) => *n,
        _ => 1,
    };

    let mut loop_body = vec![Node::let_bind("tok_type", Expr::load(tok_types, t.clone()))];
    loop_body.extend(emit_scope_resolution(tok_types, t.clone(), &num_tokens));
    loop_body.extend(emit_declaration_lookup(t.clone(), &num_tokens));
    loop_body.extend(emit_identifier_intern(
        tok_starts,
        tok_lens,
        haystack,
        t.clone(),
    ));

    let out_words = tok_count.saturating_mul(4).max(1);
    let mut guarded_body = loop_body;
    guarded_body.extend([
        Node::store(
            out_scope_tree,
            Expr::mul(t.clone(), Expr::u32(4)),
            Expr::var("scope_id"),
        ),
        Node::store(
            out_scope_tree,
            Expr::add(Expr::mul(t.clone(), Expr::u32(4)), Expr::u32(1)),
            Expr::var("scope_parent_id"),
        ),
        Node::store(
            out_scope_tree,
            Expr::add(Expr::mul(t.clone(), Expr::u32(4)), Expr::u32(2)),
            Expr::var("decl_kind"),
        ),
        Node::store(
            out_scope_tree,
            Expr::add(Expr::mul(t.clone(), Expr::u32(4)), Expr::u32(3)),
            Expr::var("identifier_intern_id"),
        ),
    ]);

    Program::wrapped(
        vec![
            BufferDecl::storage(tok_types, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_count.max(1)),
            BufferDecl::storage(tok_starts, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_count.max(1)),
            BufferDecl::storage(tok_lens, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_count.max(1)),
            BufferDecl::storage(haystack, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(haystack_words.max(1)),
            BufferDecl::storage(out_scope_tree, 4, BufferAccess::ReadWrite, DataType::U32)
                .with_count(out_words),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::c_sema_scope",
            vec![Node::if_then(
                Expr::lt(t.clone(), num_tokens.clone()),
                guarded_body,
            )],
        )],
    )
    .with_entry_op_id("vyre-libs::parsing::c_sema_scope")
    .with_non_composable_with_self(true)
}

/// Compute the same mapping on CPU for conformance and witness generation.
#[must_use]
pub fn reference_scope_tree(
    tok_types: &[u32],
    tok_starts: &[u32],
    tok_lens: &[u32],
    haystack: &[u32],
) -> Vec<u32> {
    let mut out = Vec::with_capacity(tok_types.len() * 4);
    for node_idx in 0..tok_types.len() {
        let scope_id = scope_id_for_node(tok_types, node_idx);
        let scope_parent_id = scope_parent_id_for_node(tok_types, node_idx, scope_id);
        let decl_kind = decl_kind_for_node(tok_types, tok_starts, tok_lens, haystack, node_idx);
        let identifier_intern_id =
            identifier_intern_id_for_node(tok_types, tok_starts, tok_lens, haystack, node_idx);

        out.push(scope_id);
        out.push(scope_parent_id);
        out.push(decl_kind);
        out.push(identifier_intern_id);
    }

    out
}

fn scope_id_for_node(tok_types: &[u32], node_idx: usize) -> u32 {
    if let Some((scope_id, _)) = function_parameter_scope(tok_types, node_idx) {
        return scope_id;
    }

    brace_scope_id_for_node(tok_types, node_idx)
}

fn brace_scope_id_for_node(tok_types: &[u32], node_idx: usize) -> u32 {
    if node_idx == 0 {
        return 0;
    }

    let mut depth = 0u32;
    for scan_idx in (0..node_idx).rev() {
        match tok_types[scan_idx] {
            TOK_RBRACE => depth = depth.saturating_add(1),
            TOK_LBRACE => {
                if depth == 0 {
                    return u32::try_from(scan_idx + 1).unwrap_or(0);
                }
                if depth > 0 {
                    depth = depth.saturating_sub(1);
                }
            }
            _ => {}
        }
    }

    0
}

fn scope_parent_id_for_node(tok_types: &[u32], node_idx: usize, scope_id: u32) -> u32 {
    if let Some((_, parent_id)) = function_parameter_scope(tok_types, node_idx) {
        return parent_id;
    }

    brace_scope_parent_id_for_node(tok_types, node_idx, scope_id)
}

fn brace_scope_parent_id_for_node(tok_types: &[u32], node_idx: usize, scope_id: u32) -> u32 {
    if scope_id == 0 {
        return 0;
    }

    let scope_open = scope_id.saturating_sub(1) as usize;
    if scope_open == 0 {
        return 0;
    }

    let mut depth = 0u32;
    for scan_idx in (0..scope_open).rev() {
        match tok_types[scan_idx] {
            TOK_RBRACE => depth = depth.saturating_add(1),
            TOK_LBRACE => {
                if depth == 0 {
                    return if scan_idx < node_idx {
                        u32::try_from(scan_idx + 1).unwrap_or(0)
                    } else {
                        0
                    };
                }
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }

    0
}

fn decl_kind_for_node(
    tok_types: &[u32],
    _tok_starts: &[u32],
    _tok_lens: &[u32],
    _haystack: &[u32],
    node_idx: usize,
) -> u32 {
    let current = tok_types[node_idx];
    if current != TOK_IDENTIFIER {
        return DECL_KIND_NONE;
    }

    let prev_tok = if node_idx > 0 {
        tok_types[node_idx - 1]
    } else {
        0
    };
    let next_tok = if node_idx + 1 < tok_types.len() {
        tok_types[node_idx + 1]
    } else {
        0
    };

    if next_tok == TOK_COLON {
        if prev_tok == TOK_CASE || prev_tok == TOK_GOTO {
            return DECL_KIND_NONE;
        }
        return DECL_KIND_LABEL;
    }

    if is_tag_name(tok_types, node_idx) {
        return DECL_KIND_NONE;
    }

    if let Some(aggregate) = aggregate_body_kind(tok_types, node_idx) {
        return if aggregate == TOK_ENUM && is_enum_constant(tok_types, node_idx) {
            DECL_KIND_ENUM_CONSTANT
        } else {
            DECL_KIND_NONE
        };
    }

    if next_tok == TOK_LPAREN {
        let mut paren_depth = 0u32;
        let mut matching_rparen: Option<usize> = None;
        for scan_idx in (node_idx + 1)..tok_types.len() {
            match tok_types[scan_idx] {
                TOK_LPAREN => paren_depth = paren_depth.saturating_add(1),
                TOK_RPAREN => {
                    if paren_depth <= 1 {
                        matching_rparen = Some(scan_idx);
                        break;
                    }
                    paren_depth = paren_depth.saturating_sub(1);
                }
                _ => {}
            }
        }
        if let Some(rparen_idx) = matching_rparen {
            if declaration_boundary_after_paren(tok_types, rparen_idx) == Some(TOK_LBRACE) {
                return DECL_KIND_FUNCTION;
            }
            if is_declaration_context_token(prev_tok) {
                return if prev_tok == TOK_TYPEDEF {
                    DECL_KIND_TYPEDEF
                } else {
                    DECL_KIND_FUNCTION_DECL
                };
            }
            if prev_tok == TOK_TYPEDEF {
                return DECL_KIND_TYPEDEF;
            }
        }
    }

    if prev_tok == TOK_TYPEDEF {
        return DECL_KIND_TYPEDEF;
    }

    if seen_typedef_in_declaration(tok_types, node_idx) {
        return DECL_KIND_TYPEDEF;
    }

    if is_declaration_context_token(prev_tok) {
        return DECL_KIND_VARIABLE;
    }

    DECL_KIND_NONE
}

fn is_declaration_context_token(token: u32) -> bool {
    matches!(
        token,
        TOK_INT
            | TOK_CHAR_KW
            | TOK_VOID
            | TOK_STRUCT
            | TOK_TYPEDEF
            | TOK_COMMA
            | TOK_SEMICOLON
            | TOK_LPAREN
            | TOK_RPAREN
            | TOK_STAR
            | TOK_AUTO
            | TOK_CONST
            | TOK_DOUBLE
            | TOK_ENUM
            | TOK_EXTERN
            | TOK_FLOAT_KW
            | TOK_INLINE
            | TOK_LONG
            | TOK_REGISTER
            | TOK_RESTRICT
            | TOK_SHORT
            | TOK_SIGNED
            | TOK_STATIC
            | TOK_THREAD_LOCAL
            | TOK_UNION
            | TOK_UNSIGNED
            | TOK_VOLATILE
    )
}

fn is_tag_keyword(token: u32) -> bool {
    matches!(token, TOK_STRUCT | TOK_UNION | TOK_ENUM)
}

fn is_tag_name(tok_types: &[u32], node_idx: usize) -> bool {
    node_idx > 0 && is_tag_keyword(tok_types[node_idx - 1])
}

fn aggregate_body_kind(tok_types: &[u32], node_idx: usize) -> Option<u32> {
    let mut depth = 0u32;
    for scan_idx in (0..node_idx).rev() {
        match tok_types[scan_idx] {
            TOK_RBRACE => depth = depth.saturating_add(1),
            TOK_LBRACE => {
                if depth == 0 {
                    let prev = scan_idx.checked_sub(1).map(|idx| tok_types[idx]);
                    let prev_prev = scan_idx.checked_sub(2).map(|idx| tok_types[idx]);
                    return prev
                        .filter(|token| is_tag_keyword(*token))
                        .or_else(|| prev_prev.filter(|token| is_tag_keyword(*token)));
                }
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    None
}

fn is_enum_constant(tok_types: &[u32], node_idx: usize) -> bool {
    let prev = node_idx
        .checked_sub(1)
        .map(|idx| tok_types[idx])
        .unwrap_or(0);
    let next = tok_types.get(node_idx + 1).copied().unwrap_or(0);
    matches!(prev, TOK_LBRACE | TOK_COMMA) || matches!(next, TOK_ASSIGN | TOK_COMMA | TOK_RBRACE)
}

fn seen_typedef_in_declaration(tok_types: &[u32], node_idx: usize) -> bool {
    for scan_idx in (0..node_idx).rev() {
        match tok_types[scan_idx] {
            TOK_TYPEDEF => return true,
            TOK_SEMICOLON | TOK_LBRACE => return false,
            _ => {}
        }
    }
    false
}

fn declaration_boundary_after_paren(tok_types: &[u32], rparen_idx: usize) -> Option<u32> {
    match tok_types.get(rparen_idx + 1).copied() {
        Some(TOK_LBRACE | TOK_SEMICOLON) => tok_types.get(rparen_idx + 1).copied(),
        Some(_) => tok_types
            .iter()
            .skip(rparen_idx + 1)
            .copied()
            .find(|token| *token == TOK_LBRACE),
        None => None,
    }
}

fn function_parameter_scope(tok_types: &[u32], node_idx: usize) -> Option<(u32, u32)> {
    let lparen_idx = enclosing_lparen(tok_types, node_idx)?;
    if lparen_idx == 0 || tok_types.get(lparen_idx - 1).copied() != Some(TOK_IDENTIFIER) {
        return None;
    }
    let prefix = lparen_idx
        .checked_sub(2)
        .and_then(|idx| tok_types.get(idx))
        .copied()
        .unwrap_or(0);
    if !is_function_name_prefix(prefix) {
        return None;
    }
    let rparen_idx = matching_rparen(tok_types, lparen_idx)?;
    if node_idx >= rparen_idx {
        return None;
    }
    let scope_open = match declaration_boundary_after_paren(tok_types, rparen_idx)? {
        TOK_LBRACE => tok_types
            .iter()
            .enumerate()
            .skip(rparen_idx + 1)
            .find_map(|(idx, token)| (*token == TOK_LBRACE).then_some(idx + 1))
            .and_then(|idx| u32::try_from(idx).ok())?,
        TOK_SEMICOLON => u32::try_from(lparen_idx + 1).ok()?,
        _ => return None,
    };

    let brace_scope = brace_scope_id_for_node(tok_types, node_idx);
    let brace_parent = brace_scope_parent_id_for_node(tok_types, node_idx, brace_scope);
    let scope_open_idx = usize::try_from(scope_open.saturating_sub(1)).ok()?;
    let mut parent = brace_scope;
    let has_pending_delimiter = tok_types.get(node_idx).copied() == Some(TOK_LBRACE)
        || tok_types
            .iter()
            .copied()
            .take(scope_open_idx)
            .skip(node_idx.saturating_add(1))
            .any(|token| matches!(token, TOK_LBRACE | TOK_RBRACE));
    if has_pending_delimiter {
        parent = brace_parent;
    }

    Some((scope_open, parent))
}

fn enclosing_lparen(tok_types: &[u32], node_idx: usize) -> Option<usize> {
    let mut depth = 0u32;
    for scan_idx in (0..node_idx).rev() {
        match tok_types[scan_idx] {
            TOK_RPAREN => depth = depth.saturating_add(1),
            TOK_LPAREN => {
                if depth == 0 {
                    return Some(scan_idx);
                }
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    None
}

fn matching_rparen(tok_types: &[u32], lparen_idx: usize) -> Option<usize> {
    let mut depth = 1u32;
    for (scan_idx, token) in tok_types.iter().copied().enumerate().skip(lparen_idx + 1) {
        match token {
            TOK_LPAREN => depth = depth.saturating_add(1),
            TOK_RPAREN => {
                if depth == 1 {
                    return Some(scan_idx);
                }
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    None
}

fn is_function_name_prefix(token: u32) -> bool {
    matches!(
        token,
        TOK_AUTO
            | TOK_CHAR_KW
            | TOK_CONST
            | TOK_DOUBLE
            | TOK_ENUM
            | TOK_EXTERN
            | TOK_FLOAT_KW
            | TOK_IDENTIFIER
            | TOK_INLINE
            | TOK_INT
            | TOK_LONG
            | TOK_REGISTER
            | TOK_RESTRICT
            | TOK_SHORT
            | TOK_SIGNED
            | TOK_STATIC
            | TOK_STRUCT
            | TOK_THREAD_LOCAL
            | TOK_TYPEDEF
            | TOK_UNION
            | TOK_UNSIGNED
            | TOK_VOID
            | TOK_VOLATILE
    )
}

fn identifier_intern_id_for_node(
    tok_types: &[u32],
    tok_starts: &[u32],
    tok_lens: &[u32],
    haystack: &[u32],
    node_idx: usize,
) -> u32 {
    if node_idx >= tok_types.len() || tok_types[node_idx] != TOK_IDENTIFIER {
        return 0;
    }
    let start = tok_starts[node_idx];
    let len = tok_lens[node_idx];
    let max = match start.checked_add(len) {
        Some(v) => usize::try_from(v).unwrap_or(haystack.len()),
        None => haystack.len(),
    };
    let start_usize = usize::try_from(start).unwrap_or(haystack.len());
    let end = max.min(haystack.len());
    if start_usize >= haystack.len() || start_usize >= end {
        return 0;
    }

    let mut hash = 0x811c_9dc5u32;
    for &byte in &haystack[start_usize..end] {
        hash = (hash ^ byte).wrapping_mul(0x0100_0193);
    }
    hash
}

fn pack_u32(v: &[u32]) -> Vec<u8> {
    v.iter().flat_map(|value| value.to_le_bytes()).collect()
}

#[derive(Clone, Copy)]
struct FixtureAtom {
    token: u32,
    start: u32,
    len: u32,
}

fn witness_fixture() -> (Vec<u32>, Vec<u32>, Vec<u32>, Vec<u32>) {
    let atoms = [
        FixtureAtom {
            token: TOK_INT,
            start: 0,
            len: 0,
        },
        FixtureAtom {
            token: TOK_IDENTIFIER,
            start: 0,
            len: 4,
        },
        FixtureAtom {
            token: TOK_LPAREN,
            start: 0,
            len: 0,
        },
        FixtureAtom {
            token: TOK_RPAREN,
            start: 0,
            len: 0,
        },
        FixtureAtom {
            token: TOK_LBRACE,
            start: 0,
            len: 0,
        },
        FixtureAtom {
            token: TOK_INT,
            start: 4,
            len: 0,
        },
        FixtureAtom {
            token: TOK_IDENTIFIER,
            start: 4,
            len: 1,
        },
        FixtureAtom {
            token: TOK_SEMICOLON,
            start: 0,
            len: 0,
        },
        FixtureAtom {
            token: TOK_RBRACE,
            start: 0,
            len: 0,
        },
        FixtureAtom {
            token: TOK_IDENTIFIER,
            start: 5,
            len: 5,
        },
        FixtureAtom {
            token: TOK_COLON,
            start: 0,
            len: 0,
        },
        FixtureAtom {
            token: TOK_GOTO,
            start: 0,
            len: 0,
        },
        FixtureAtom {
            token: TOK_IDENTIFIER,
            start: 10,
            len: 5,
        },
        FixtureAtom {
            token: TOK_SEMICOLON,
            start: 0,
            len: 0,
        },
    ];

    let mut tokens = Vec::with_capacity(atoms.len());
    let mut starts = Vec::with_capacity(atoms.len());
    let mut lens = Vec::with_capacity(atoms.len());
    let mut max_end = 0usize;
    for atom in atoms {
        let end = usize::try_from(atom.start.saturating_add(atom.len)).unwrap_or(0);
        max_end = max_end.max(end);
        tokens.push(atom.token);
        starts.push(atom.start);
        lens.push(atom.len);
    }
    let mut haystack = vec![0u32; max_end.max(16)];
    haystack[0..4].copy_from_slice(&[b'm', b'a', b'i', b'n'].map(u32::from));
    haystack[4] = u32::from(b'x');
    haystack[5..10].copy_from_slice(&[b'l', b'a', b'b', b'e', b'l'].map(u32::from));
    haystack[10..15].copy_from_slice(&[b'l', b'a', b'b', b'e', b'l'].map(u32::from));
    (tokens, starts, lens, haystack)
}

fn witness_inputs() -> Vec<Vec<Vec<u8>>> {
    let (tokens, starts, lens, haystack) = witness_fixture();
    vec![vec![
        pack_u32(&tokens),
        pack_u32(&starts),
        pack_u32(&lens),
        pack_u32(&haystack),
        vec![0; tokens.len() * 4 * 4],
    ]]
}

fn witness_expected() -> Vec<Vec<Vec<u8>>> {
    let (tokens, starts, lens, haystack) = witness_fixture();
    let outputs = reference_scope_tree(&tokens, &starts, &lens, &haystack);
    vec![vec![pack_u32(&outputs)]]
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::parsing::c_sema_scope",
        build: || {
            let (tokens, _, _, _) = witness_fixture();
            c_sema_scope(
                "tok_types",
                "tok_starts",
                "tok_lens",
                "haystack",
                Expr::u32(16),
                Expr::u32(u32::try_from(tokens.len()).unwrap_or(0)),
                "out_scope_tree",
            )
        },
        test_inputs: Some(witness_inputs),
        expected_output: Some(witness_expected),
    }
}
