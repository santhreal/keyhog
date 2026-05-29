use super::super::DirectivePayload;
use super::disk_common::{
    disk_cache_tmp_path, parsed_ast_cache_dir, publish_disk_cache_file, remove_disk_cache_file,
};
use super::payload_codec::{decode_payloads, encode_payloads};
use super::payload_keys::{payloads_disk_path, PayloadsCacheKey};

pub(crate) fn load_payloads_from_disk(key: &PayloadsCacheKey) -> Option<Vec<DirectivePayload>> {
    let dir = parsed_ast_cache_dir();
    let path = payloads_disk_path(&dir, key);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => {
            panic!(
                "vyre C GPU preprocessor disk cache could not read payload entry {}: {error}. Fix: repair cache directory permissions or delete the cache root.",
                path.display()
            )
        }
    };
    match decode_payloads(&bytes, key) {
        Ok(payloads) => Some(payloads),
        Err(_) => {
            remove_disk_cache_file(&path, "payload");
            None
        }
    }
}

pub(crate) fn store_payloads_to_disk(
    key: &PayloadsCacheKey,
    payloads: &[DirectivePayload],
) -> Result<(), String> {
    let dir = parsed_ast_cache_dir();
    let path = payloads_disk_path(&dir, key);
    let encoded = encode_payloads(key, payloads)?;
    let tmp = disk_cache_tmp_path(&path, "vpl");
    std::fs::write(&tmp, &encoded).map_err(|error| {
        format!(
            "vyre C GPU preprocessor disk cache could not write payload temp entry {}: {error}. Fix: repair cache directory permissions.",
            tmp.display()
        )
    })?;
    publish_disk_cache_file(&tmp, &path, "payload");
    Ok(())
}
