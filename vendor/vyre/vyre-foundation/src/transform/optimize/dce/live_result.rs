use crate::ir::Node;
use im::HashSet;

pub(crate) struct LiveResult {
    pub(super) nodes: Vec<Node>,
    pub(super) live_in: HashSet<String>,
}
