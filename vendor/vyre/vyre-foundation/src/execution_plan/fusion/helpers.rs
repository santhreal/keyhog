//! Misc fusion helpers: composition keys + buffer-access lattice upgrade.

use crate::ir::{BufferAccess, BufferDecl, Program};

pub(super) fn fallback_composition_key(prog: &Program) -> String {
    let mut hasher = blake3::Hasher::new();
    for buf in prog.buffers() {
        hasher.update(buf.name().as_bytes());
        hasher.update(&[0]);
    }
    for dim in prog.workgroup_size() {
        hasher.update(&dim.to_le_bytes());
    }
    hasher.update(&(prog.entry().len() as u64).to_le_bytes());
    format!("{}", hasher.finalize().to_hex())
}

/// Upgrade `buffer.access` to the more permissive of the two modes.
pub(super) fn upgrade_buffer_access(buffer: &mut BufferDecl, other: BufferAccess) {
    use BufferAccess::*;
    let current = buffer.access();
    buffer.access = match (&current, &other) {
        (ReadWrite, _) | (_, ReadWrite) => ReadWrite,
        (Uniform, _) | (_, Uniform) => Uniform,
        (Workgroup, _) | (_, Workgroup) => Workgroup,
        _ => ReadOnly,
    };
    // Keep kind in sync with the upgraded access.
    buffer.kind = match buffer.access {
        ReadOnly => crate::ir::MemoryKind::Readonly,
        ReadWrite => crate::ir::MemoryKind::Global,
        Uniform => crate::ir::MemoryKind::Uniform,
        Workgroup => crate::ir::MemoryKind::Shared,
        _ => crate::ir::MemoryKind::Global,
    };
}
