//! **VAST** — packed AST wire layout (host validator + tree walks).
//!
//! Matches the buffer contract in `docs/parsing-and-frontends.md` in the
//! vyre workspace (magic `VAST`, fixed `Node` rows). GPU `ast_walk_*`
//! compositions target the same logical layout.

mod error;
mod header;
mod layout;
mod node;
mod pack;
mod validate;
mod walk;

pub use error::VastError;
pub use header::{VastHeader, HEADER_LEN, VAST_MAGIC, VAST_VERSION};
pub use node::{VastFile, VastNode, NODE_STRIDE_U32, SENTINEL};
pub use pack::pack_spine_vast;
pub use validate::validate_vast;
pub use walk::{walk_postorder_indices, walk_preorder_indices};
