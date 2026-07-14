use std::path::Path;

pub(crate) struct StableHasher {
    inner: blake3::Hasher,
}

impl StableHasher {
    pub(crate) fn new(domain: &str) -> Self {
        let mut out = Self {
            inner: blake3::Hasher::new(),
        };
        out.tagged_bytes(b"keyhog-stable-hash", b"v1");
        out.field_str("domain", domain);
        out
    }

    pub(crate) fn field_bool(&mut self, name: &str, value: bool) -> &mut Self {
        self.field_name(name);
        self.tagged_bytes(b"bool", &[u8::from(value)]);
        self
    }

    pub(crate) fn field_bytes(&mut self, name: &str, value: &[u8]) -> &mut Self {
        self.field_name(name);
        self.tagged_bytes(b"bytes", value);
        self
    }

    pub(crate) fn field_f64_bits(&mut self, name: &str, value: f64) -> &mut Self {
        self.field_u64(name, value.to_bits())
    }

    pub(crate) fn field_option_path(&mut self, name: &str, value: Option<&Path>) -> &mut Self {
        self.field_name(name);
        match value {
            Some(path) => {
                self.tagged_bytes(b"option", b"some");
                self.tagged_path(path);
            }
            None => self.tagged_bytes(b"option", b"none"),
        }
        self
    }

    pub(crate) fn field_option_str(&mut self, name: &str, value: Option<&str>) -> &mut Self {
        self.field_name(name);
        match value {
            Some(value) => {
                self.tagged_bytes(b"option", b"some");
                self.tagged_bytes(b"str", value.as_bytes());
            }
            None => self.tagged_bytes(b"option", b"none"),
        }
        self
    }

    pub(crate) fn field_option_u64(&mut self, name: &str, value: Option<u64>) -> &mut Self {
        self.field_name(name);
        match value {
            Some(value) => {
                self.tagged_bytes(b"option", b"some");
                self.tagged_bytes(b"u64", &value.to_le_bytes());
            }
            None => self.tagged_bytes(b"option", b"none"),
        }
        self
    }

    pub(crate) fn field_option_usize(&mut self, name: &str, value: Option<usize>) -> &mut Self {
        self.field_option_u64(name, value.map(|value| value as u64))
    }

    pub(crate) fn field_path(&mut self, name: &str, value: &Path) -> &mut Self {
        self.field_name(name);
        self.tagged_path(value);
        self
    }

    pub(crate) fn field_str(&mut self, name: &str, value: &str) -> &mut Self {
        self.field_name(name);
        self.tagged_bytes(b"str", value.as_bytes());
        self
    }

    pub(crate) fn field_u64(&mut self, name: &str, value: u64) -> &mut Self {
        self.field_name(name);
        self.tagged_bytes(b"u64", &value.to_le_bytes());
        self
    }

    pub(crate) fn field_usize(&mut self, name: &str, value: usize) -> &mut Self {
        self.field_u64(name, value as u64)
    }

    pub(crate) fn finish_u64(&self) -> u64 {
        let digest = self.finish_256();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        u64::from_le_bytes(bytes)
    }

    pub(crate) fn finish_256(&self) -> [u8; 32] {
        *self.inner.finalize().as_bytes()
    }

    fn field_name(&mut self, name: &str) {
        self.tagged_bytes(b"field", name.as_bytes());
    }

    fn tagged_bytes(&mut self, tag: &[u8], value: &[u8]) {
        self.inner.update(&(tag.len() as u64).to_le_bytes());
        self.inner.update(tag);
        self.inner.update(&(value.len() as u64).to_le_bytes());
        self.inner.update(value);
    }

    fn tagged_path(&mut self, value: &Path) {
        self.tagged_bytes(b"path", value.to_string_lossy().as_bytes());
    }
}
