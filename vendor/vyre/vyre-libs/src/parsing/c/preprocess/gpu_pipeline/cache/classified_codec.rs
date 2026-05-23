use super::super::ClassifiedTokens;
use super::classified_memory::ClassifiedCacheKey;
use super::disk_common::CLASSIFIED_DISK_MAGIC;

pub(crate) fn encode_classified(
    key: &ClassifiedCacheKey,
    classified: &ClassifiedTokens,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        CLASSIFIED_DISK_MAGIC.len()
            + 32
            + classified.tok_types.len() * 4
            + classified.tok_starts.len() * 4
            + classified.tok_lens.len() * 4
            + classified.directive_kinds.len() * 4
            + classified.source.len(),
    );
    out.extend_from_slice(CLASSIFIED_DISK_MAGIC);
    let path_bytes = key
        .path
        .as_os_str()
        .to_string_lossy()
        .into_owned()
        .into_bytes();
    out.extend_from_slice(&(path_bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(&path_bytes);
    out.extend_from_slice(&(key.source_len as u64).to_le_bytes());
    out.extend_from_slice(&key.source_hash);
    write_u32_vec(&mut out, &classified.tok_types);
    write_u32_vec(&mut out, &classified.tok_starts);
    write_u32_vec(&mut out, &classified.tok_lens);
    write_u32_vec(&mut out, &classified.directive_kinds);
    out.extend_from_slice(&(classified.source.len() as u64).to_le_bytes());
    out.extend_from_slice(&classified.source);
    out
}

pub(crate) fn write_u32_vec(out: &mut Vec<u8>, vec: &[u32]) {
    out.extend_from_slice(&(vec.len() as u64).to_le_bytes());
    for value in vec {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

#[derive(Debug)]
pub(crate) enum DecodeError {
    Truncated,
    BadMagic,
    KeyMismatch,
}

pub(crate) fn decode_classified(
    bytes: &[u8],
    expected_key: &ClassifiedCacheKey,
) -> Result<ClassifiedTokens, DecodeError> {
    let mut cursor = 0usize;
    if bytes.len() < CLASSIFIED_DISK_MAGIC.len()
        || &bytes[..CLASSIFIED_DISK_MAGIC.len()] != CLASSIFIED_DISK_MAGIC
    {
        return Err(DecodeError::BadMagic);
    }
    cursor += CLASSIFIED_DISK_MAGIC.len();
    let path_len = read_u64(bytes, &mut cursor)? as usize;
    let path_end = cursor.checked_add(path_len).ok_or(DecodeError::Truncated)?;
    if path_end > bytes.len() {
        return Err(DecodeError::Truncated);
    }
    let path_str =
        std::str::from_utf8(&bytes[cursor..path_end]).map_err(|_| DecodeError::KeyMismatch)?;
    cursor = path_end;
    if std::path::Path::new(path_str) != expected_key.path.as_path() {
        return Err(DecodeError::KeyMismatch);
    }
    let source_len = read_u64(bytes, &mut cursor)? as usize;
    let source_hash = read_hash128(bytes, &mut cursor)?;
    if source_len != expected_key.source_len || source_hash != expected_key.source_hash {
        return Err(DecodeError::KeyMismatch);
    }
    let tok_types = read_u32_vec(bytes, &mut cursor)?;
    let tok_starts = read_u32_vec(bytes, &mut cursor)?;
    let tok_lens = read_u32_vec(bytes, &mut cursor)?;
    let directive_kinds = read_u32_vec(bytes, &mut cursor)?;
    let src_len = read_u64(bytes, &mut cursor)? as usize;
    let src_end = cursor.checked_add(src_len).ok_or(DecodeError::Truncated)?;
    if src_end > bytes.len() {
        return Err(DecodeError::Truncated);
    }
    let source = std::sync::Arc::from(&bytes[cursor..src_end]);
    Ok(ClassifiedTokens::from_parts(
        tok_types,
        tok_starts,
        tok_lens,
        directive_kinds,
        source,
    ))
}

pub(crate) fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, DecodeError> {
    let end = cursor.checked_add(8).ok_or(DecodeError::Truncated)?;
    if end > bytes.len() {
        return Err(DecodeError::Truncated);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[*cursor..end]);
    *cursor = end;
    Ok(u64::from_le_bytes(buf))
}

pub(crate) fn read_hash128(bytes: &[u8], cursor: &mut usize) -> Result<[u8; 16], DecodeError> {
    let end = cursor.checked_add(16).ok_or(DecodeError::Truncated)?;
    if end > bytes.len() {
        return Err(DecodeError::Truncated);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[*cursor..end]);
    *cursor = end;
    Ok(out)
}

pub(crate) fn read_u32_vec(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u32>, DecodeError> {
    let count = read_u64(bytes, cursor)? as usize;
    let span = count
        .checked_mul(4)
        .and_then(|n| cursor.checked_add(n))
        .ok_or(DecodeError::Truncated)?;
    if span > bytes.len() {
        return Err(DecodeError::Truncated);
    }
    let mut vec = Vec::with_capacity(count);
    for _ in 0..count {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[*cursor..*cursor + 4]);
        vec.push(u32::from_le_bytes(buf));
        *cursor += 4;
    }
    Ok(vec)
}
