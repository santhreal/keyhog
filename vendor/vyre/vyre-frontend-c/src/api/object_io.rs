use std::path::Path;

use crate::object_format::{parse_embedded_vyrecob2, Vyrecob2};

pub(crate) fn decode_embedded_object<T, F>(object_bytes: &[u8], decode: F) -> Result<T, String>
where
    F: for<'container> FnOnce(&Vyrecob2<'container>) -> Result<T, String>,
{
    let container = parse_embedded_vyrecob2(object_bytes)?;
    decode(&container)
}

pub(crate) fn read_object_file<T, F>(path: &Path, decode: F) -> Result<T, String>
where
    F: FnOnce(&[u8]) -> Result<T, String>,
{
    let bytes = std::fs::read(path)
        .map_err(|error| format!("vyre-frontend-c: read object {}: {error}", path.display()))?;
    decode(&bytes)
}
