//! Out-of-bounds rules enforced by the parity engine.
//!
//! GPU drivers differ on what happens when a shader indexes past the end of a
//! buffer: some clamp, some return zero, some crash. The reference interpreter
//! eliminates that ambiguity by defining one deterministic behavior — defined-type
//! zero-fill for scalar loads, empty slice for `Bytes`, and silent no-op for stores.
//! Any backend that diverges from these rules fails the conform gate.

use vyre::ir::DataType as IrDataType;

use crate::value::Value;
use vyre::ir::DataType;

use std::sync::{Arc, RwLock};

/// Typed bytes backing one declared IR buffer.
///
/// This struct exists to give the reference interpreter a single place to enforce
/// stride-correct indexing and OOB semantics, independent of how any GPU driver
/// handles buffer bounds.
#[derive(Debug, Clone)]
pub struct Buffer {
    pub(crate) bytes: Arc<RwLock<Vec<u8>>>,
    pub(crate) element: IrDataType,
}

impl Buffer {
    /// Create a buffer from typed bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>, element: DataType) -> Self {
        Self {
            bytes: Arc::new(RwLock::new(bytes)),
            element,
        }
    }

    pub(crate) fn len(&self) -> u32 {
        let bytes_guard = self.bytes.read().unwrap();
        let stride = self.element.min_bytes();
        let count = if stride == 0 {
            bytes_guard.len()
        } else {
            bytes_guard.len() / stride
        };
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    /// Consume this buffer and return its contents as a Value.
    #[must_use]
    pub fn to_value(self) -> crate::value::Value {
        let vec = std::sync::Arc::try_unwrap(self.bytes)
            .map(|rw| rw.into_inner().unwrap())
            .unwrap_or_else(|a| a.read().unwrap().clone());
        crate::value::Value::from(vec)
    }
}

pub(crate) fn load(buffer: &Buffer, index: u32) -> Value {
    let bytes_guard = buffer.bytes.read().unwrap();
    let stride = buffer.element.min_bytes();
    let ty = ir_to_conform_type(buffer.element.clone());
    if matches!(buffer.element, IrDataType::Bytes) {
        let offset = index as usize;
        if offset > bytes_guard.len() {
            return Value::from(Vec::new());
        }
        return Value::from(&bytes_guard[offset..]);
    }
    let Some(offset) = byte_offset(index, stride) else {
        return Value::try_zero_for(ty).unwrap_or_else(|| Value::from(Vec::new()));
    };
    if stride == 0 || offset + stride > bytes_guard.len() {
        return Value::try_zero_for(ty).unwrap_or_else(|| Value::from(Vec::new()));
    }
    Value::from_element_bytes(ty.clone(), &bytes_guard[offset..offset + stride])
        .unwrap_or_else(|_| Value::try_zero_for(ty).unwrap_or_else(|| Value::from(Vec::new())))
}

pub(crate) fn store(buffer: &mut Buffer, index: u32, value: &Value) {
    let mut bytes_guard = buffer.bytes.write().unwrap();
    let stride = buffer.element.min_bytes();
    if matches!(buffer.element, IrDataType::Bytes) {
        let offset = index as usize;
        if offset >= bytes_guard.len() {
            return;
        }
        let bytes = value.to_bytes();
        let available = bytes_guard.len() - offset;
        let write_len = bytes.len().min(available);
        bytes_guard[offset..offset + write_len].copy_from_slice(&bytes[..write_len]);
        return;
    }
    let Some(offset) = byte_offset(index, stride) else {
        return;
    };
    if stride == 0 || offset + stride > bytes_guard.len() {
        return;
    }
    write_element(
        buffer.element.clone(),
        &mut bytes_guard[offset..offset + stride],
        value,
    );
}

pub(crate) fn atomic_load(buffer: &Buffer, index: u32) -> Option<u32> {
    let bytes_guard = buffer.bytes.read().unwrap();
    let stride = buffer.element.min_bytes().max(4);
    let offset = byte_offset(index, stride)?;
    if offset + 4 > bytes_guard.len() {
        None
    } else {
        Some(read_u32(&bytes_guard[offset..offset + 4]))
    }
}

pub(crate) fn atomic_store(buffer: &mut Buffer, index: u32, value: u32) {
    let mut bytes_guard = buffer.bytes.write().unwrap();
    let stride = buffer.element.min_bytes().max(4);
    let Some(offset) = byte_offset(index, stride) else {
        return;
    };
    if offset + 4 <= bytes_guard.len() {
        write_u32(&mut bytes_guard[offset..offset + 4], value);
    }
}

fn byte_offset(index: u32, stride: usize) -> Option<usize> {
    (index as usize).checked_mul(stride)
}

fn write_element(element: IrDataType, target: &mut [u8], value: &Value) {
    match element {
        IrDataType::U32 => {
            target.copy_from_slice(&value.to_bytes_width(4)[..4]);
        }
        IrDataType::I32 => {
            target.copy_from_slice(&value.to_bytes_width(4)[..4]);
        }
        IrDataType::Bool => {
            target.copy_from_slice(&value.to_bytes_width(4)[..4]);
        }
        IrDataType::U64 => {
            let bytes = value.to_bytes_width(8);
            target.copy_from_slice(&bytes[..8]);
        }
        IrDataType::F32 => {
            // Value::Float carries an f64; the GPU buffer is four bytes
            // of f32, so narrow via `as f32` before writing. Dropping the
            // upper four bytes of `v.to_le_bytes()` (what the default
            // to_bytes_width path does) would mangle the f32 bit pattern.
            let v = match value {
                Value::Float(v) => *v as f32,
                Value::U32(v) => f32::from_bits(*v),
                _ => 0.0,
            };
            target.copy_from_slice(&v.to_le_bytes());
        }
        IrDataType::Bytes | IrDataType::Vec2U32 | IrDataType::Vec4U32 => {
            let bytes = value.to_bytes_width(target.len());
            let len = target.len().min(bytes.len());
            target[..len].copy_from_slice(&bytes[..len]);
            target[len..].fill(0);
        }
        _ => {
            let bytes = value.to_bytes_width(target.len());
            let len = target.len().min(bytes.len());
            target[..len].copy_from_slice(&bytes[..len]);
            target[len..].fill(0);
        }
    }
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn write_u32(bytes: &mut [u8], value: u32) {
    bytes.copy_from_slice(&value.to_le_bytes());
}

fn ir_to_conform_type(ty: IrDataType) -> DataType {
    match ty {
        IrDataType::U32 => DataType::U32,
        IrDataType::I32 => DataType::I32,
        IrDataType::U64 => DataType::U64,
        IrDataType::F32 => DataType::F32,
        IrDataType::Vec2U32 => DataType::Vec2U32,
        IrDataType::Vec4U32 => DataType::Vec4U32,
        IrDataType::Bool => DataType::U32,
        IrDataType::Bytes => DataType::Bytes,
        _ => DataType::Bytes,
    }
}
