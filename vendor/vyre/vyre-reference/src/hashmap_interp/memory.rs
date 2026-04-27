//! Buffer storage for the HashMap interpreter.
//!
//! Storage buffers persist across workgroups; workgroup buffers are rebuilt for
//! each workgroup dispatch. The helpers here centralize that distinction so the
//! executor does not duplicate storage/workgroup lookup plumbing.

use crate::{oob::Buffer, value::Value, workgroup::MAX_WORKGROUP_BYTES};
use std::collections::HashMap;
use vyre::ir::{BufferAccess, BufferDecl, Program};
use vyre::Error;

pub(crate) struct HashmapMemory {
    pub(crate) storage: HashMap<String, Buffer>,
    pub(crate) workgroup: HashMap<String, Buffer>,
}

impl HashmapMemory {
    pub(crate) fn new(storage: HashMap<String, Buffer>) -> Self {
        Self {
            storage,
            workgroup: HashMap::new(),
        }
    }

    pub(crate) fn reset_workgroup(&mut self, program: &Program) -> Result<(), Error> {
        self.workgroup = workgroup_memory(program)?;
        Ok(())
    }
}

pub(crate) fn output_value(buffer: Buffer, decl: &BufferDecl) -> Value {
    let mut bytes = buffer.to_value().to_bytes();
    if let Some(range) = decl.output_byte_range() {
        if range.start <= range.end && range.end <= bytes.len() {
            bytes = bytes[range].to_vec();
        }
    }
    Value::from(bytes)
}

pub(crate) fn workgroup_memory(program: &Program) -> Result<HashMap<String, Buffer>, Error> {
    let mut workgroup = HashMap::new();
    let mut allocated = 0usize;
    for decl in program
        .buffers()
        .iter()
        .filter(|decl| decl.access() == BufferAccess::Workgroup)
    {
        let element_size = decl.element().min_bytes();
        let len = (decl . count () as usize) . checked_mul (element_size) . ok_or_else (| | { Error :: interp (format ! ("workgroup buffer `{}` byte size overflows usize. Fix: reduce count or element size." , decl . name ())) }) ? ;
        allocated = allocated . checked_add (len) . ok_or_else (| | { Error :: interp ("total workgroup memory byte size overflows usize. Fix: reduce workgroup buffer declarations." ,) }) ? ;
        if allocated > MAX_WORKGROUP_BYTES {
            return Err(Error::interp(format!(
                "workgroup memory requires {allocated} bytes, exceeding the {MAX_WORKGROUP_BYTES}-byte reference budget. Fix: reduce workgroup buffer counts."
            )));
        }
        workgroup.insert(
            decl.name().to_string(),
            Buffer::new(vec![0; len], decl.element().clone()),
        );
    }
    Ok(workgroup)
}

pub(crate) fn resolve_buffer<'a>(
    memory: &'a HashmapMemory,
    name: &str,
) -> Result<&'a Buffer, Error> {
    memory
        .storage
        .get(name)
        .or_else(|| memory.workgroup.get(name))
        .ok_or_else(|| {
            Error::interp(format!(
                "missing buffer `{name}`. Fix: initialize all declared buffers."
            ))
        })
}

pub(crate) fn buffer_mut<'a>(
    memory: &'a mut HashmapMemory,
    name: &str,
) -> Result<&'a mut Buffer, Error> {
    memory
        .storage
        .get_mut(name)
        .or_else(|| memory.workgroup.get_mut(name))
        .ok_or_else(|| {
            Error::interp(format!(
                "missing buffer `{name}`. Fix: initialize all declared buffers."
            ))
        })
}

pub(crate) fn atomic_buffer_mut<'a>(
    memory: &'a mut HashmapMemory,
    name: &str,
) -> Result<&'a mut Buffer, Error> {
    memory . storage . get_mut (name) . ok_or_else (| | { Error :: interp (format ! ("atomic target `{name}` is workgroup memory or missing. Fix: atomics only support ReadWrite storage buffers.")) })
}
