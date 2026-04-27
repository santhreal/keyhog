//! Cast helpers for the expression evaluator.

use crate::ops::{read_u32_prefix, read_u64_prefix};
use crate::value::Value;
use vyre::ir::DataType;
use vyre::Error;

pub(crate) fn spec_output_value(ty: DataType, bytes: &[u8]) -> Value {
    match ty {
        DataType::U32 => Value::U32(read_u32_prefix(bytes)),
        DataType::I32 => Value::I32(read_u32_prefix(bytes) as i32),
        DataType::Bool => Value::Bool(read_u32_prefix(bytes) != 0),
        DataType::U64 => Value::U64(read_u64_prefix(bytes)),
        DataType::F32 => Value::Float(f32::from_bits(read_u32_prefix(bytes)) as f64),
        DataType::Vec2U32 => Value::from(read_fixed_prefix(bytes, 8)),
        DataType::Vec4U32 => Value::from(read_fixed_prefix(bytes, 16)),
        DataType::Bytes => Value::from(bytes),
        _ => Value::from(bytes),
    }
}

pub(crate) fn cast_value(target: DataType, value: &Value) -> Result<Value, vyre::Error> {
    match target {
        DataType::U32 => match value {
            Value::I32(v) => Ok(Value::U32(*v as u32)),
            Value::Float(v) => Ok(Value::U32((*v) as u32)),
            _ => value
                .try_as_u32()
                .map(Value::U32)
                .ok_or_else(|| invalid_cast(target, value)),
        },
        DataType::I32 => match value {
            Value::I32(value) => Ok(Value::I32(*value)),
            Value::Float(v) => Ok(Value::I32(*v as i32)),
            _ => value
                .try_as_u32()
                .map(|value| Value::I32(value as i32))
                .ok_or_else(|| invalid_cast(target, value)),
        },
        DataType::U64 => value
            .try_as_u64()
            .map(Value::U64)
            .ok_or_else(|| invalid_cast(target, value)),
        DataType::F32 => match value {
            // Integer → float is a value conversion, not a bit-cast,
            // matching WGSL `f32(u32_value)` semantics. Without this
            // arm the evaluator dropped through to the bytes-copy
            // fallback and produced f32 bits equal to the raw u32,
            // which aliases u32(5) to 7e-45 instead of 5.0.
            Value::U32(v) => Ok(Value::Float(f64::from(*v as f32))),
            Value::I32(v) => Ok(Value::Float(f64::from(*v as f32))),
            Value::U64(v) => Ok(Value::Float(f64::from(*v as f32))),
            Value::Float(v) => Ok(Value::Float(*v)),
            Value::Bool(b) => Ok(Value::Float(if *b { 1.0 } else { 0.0 })),
            _ => value
                .try_as_u32()
                .map(|v| Value::Float(f64::from(v as f32)))
                .ok_or_else(|| invalid_cast(target, value)),
        },
        DataType::Bool => Ok(Value::Bool(value.truthy())),
        DataType::Bytes => Ok(Value::from(value.to_bytes())),
        DataType::Vec2U32 => Ok(Value::from(widen_to_words(value, 2))),
        DataType::Vec4U32 => Ok(Value::from(widen_to_words(value, 4))),
        _ => Ok(Value::from(value.to_bytes())),
    }
}

fn read_fixed_prefix(bytes: &[u8], width: usize) -> Vec<u8> {
    let mut fixed = vec![0u8; width];
    let len = bytes.len().min(width);
    fixed[..len].copy_from_slice(&bytes[..len]);
    fixed
}

fn invalid_cast(target: DataType, value: &Value) -> Error {
    Error::interp(format!(
        "cast to {target:?} cannot represent {value:?} losslessly. Fix: cast from an in-range scalar value."
    ))
}

fn widen_to_words(value: &Value, words: usize) -> Vec<u8> {
    let target_bytes = words * 4;
    let mut bytes = value.to_bytes();
    if bytes.len() > target_bytes {
        bytes.truncate(target_bytes);
    } else if bytes.len() < target_bytes {
        bytes.resize(target_bytes, 0);
    }
    bytes
}
