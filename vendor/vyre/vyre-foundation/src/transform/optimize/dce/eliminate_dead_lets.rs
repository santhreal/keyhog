use super::{collect_expr_refs, expr_has_effect, reachable_prefix, LiveResult};
use crate::ir::Node;
use im::HashSet;

#[inline]
pub(crate) fn eliminate_dead_lets(nodes: Vec<Node>, live_after: HashSet<String>) -> LiveResult {
    let reachable_len = reachable_prefix(&nodes).len();
    let mut live = live_after;
    let mut kept = Vec::with_capacity(reachable_len);

    for node in nodes.into_iter().take(reachable_len).rev() {
        match node {
            Node::Let { name, value }
                if !live.contains(name.as_str()) && !expr_has_effect(&value) => {}
            Node::Let { name, value } => {
                live.remove(name.as_str());
                collect_expr_refs(&value, &mut live);
                kept.push(Node::let_bind(&name, value));
            }
            Node::Assign { name, value } => {
                live.insert(name.to_string());
                collect_expr_refs(&value, &mut live);
                kept.push(Node::assign(&name, value));
            }
            Node::Store {
                buffer,
                index,
                value,
            } => {
                collect_expr_refs(&index, &mut live);
                collect_expr_refs(&value, &mut live);
                kept.push(Node::store(&buffer, index, value));
            }
            Node::If {
                cond,
                then,
                otherwise,
            } => {
                let then_result = eliminate_dead_lets(then, live.clone());
                let otherwise_result = eliminate_dead_lets(otherwise, live.clone());
                let mut branch_live = then_result.live_in;
                branch_live.extend(otherwise_result.live_in);
                collect_expr_refs(&cond, &mut branch_live);
                live = branch_live;
                kept.push(Node::if_then_else(
                    cond,
                    then_result.nodes,
                    otherwise_result.nodes,
                ));
            }
            Node::Loop {
                var,
                from,
                to,
                body,
            } => {
                let mut body_live_after = live.clone();
                body_live_after.insert(var.to_string());
                let body_result = eliminate_dead_lets(body, body_live_after);
                live.extend(body_result.live_in);
                live.remove(var.as_str());
                collect_expr_refs(&from, &mut live);
                collect_expr_refs(&to, &mut live);
                kept.push(Node::loop_for(&var, from, to, body_result.nodes));
            }
            Node::Block(block_nodes) => {
                let block_result = eliminate_dead_lets(block_nodes, live.clone());
                live.extend(block_result.live_in);
                kept.push(Node::block(block_result.nodes));
            }
            Node::Return => kept.push(Node::Return),
            Node::Barrier => kept.push(Node::Barrier),
            Node::IndirectDispatch {
                count_buffer,
                count_offset,
            } => kept.push(Node::IndirectDispatch {
                count_buffer,
                count_offset,
            }),
            Node::AsyncLoad {
                source,
                destination,
                offset,
                size,
                tag,
            } => kept.push(Node::async_load_ext(
                source,
                destination,
                *offset,
                *size,
                tag,
            )),
            Node::AsyncStore {
                source,
                destination,
                offset,
                size,
                tag,
            } => kept.push(Node::async_store(source, destination, *offset, *size, tag)),
            Node::AsyncWait { tag } => kept.push(Node::async_wait(&tag)),
            Node::Region {
                generator,
                source_region,
                body,
            } => kept.push(Node::Region {
                generator: generator.clone(),
                source_region: source_region.clone(),
                body: body.clone(),
            }),
            Node::Trap { .. } | Node::Resume { .. } => kept.push(node.clone()),
            Node::Opaque(extension) => kept.push(Node::Opaque(extension.clone())),
        }
    }

    kept.reverse();
    LiveResult {
        nodes: kept,
        live_in: live,
    }
}
