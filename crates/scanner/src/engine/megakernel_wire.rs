//! On-disk wire (de)serialization for the megakernel catalog cache.
//!
//! Split out of `megakernel.rs` (Law 5): the catalog's BUILD + GPU DISPATCH
//! responsibility lives there; this module owns the orthogonal, stable
//! responsibility of turning a [`MegakernelCatalog`] into the byte blob the
//! generic `vyre_libs::scan::cached_load_or_compile` persists at
//! `~/.cache/keyhog/programs/`, and back. The wire format is independent of how
//! the catalog is built or dispatched, so this boundary survives the megakernel
//! live-backend wiring work untouched.
//!
//! Every decode failure means "stale or corrupt blob — drop and recompile" (the
//! `cached_load_or_compile` contract), never "refuse to start" (Law 10: a cache
//! miss degrades loudly to a rebuild, never a silent wrong-catalog load).

use vyre_runtime::megakernel::BatchRuleProgram;

use super::megakernel::{MegakernelCatalog, CATALOG_WIRE_MAGIC};

/// Wire-decode failures for the cached catalog. Every variant means "stale or
/// corrupt blob — drop and recompile" (the `cached_load_or_compile` contract),
/// never "refuse to start".
#[derive(Debug)]
pub(crate) enum CatalogWireError {
    /// Buffer ended mid-field.
    Truncated,
    /// Leading magic did not match `WIRE_MAGIC`.
    BadMagic,
    /// Wire version did not match `WIRE_VERSION`.
    VersionMismatch,
    /// A decoded rule failed `BatchRuleProgram::new` shape validation.
    BadRuleShape,
}

impl std::fmt::Display for CatalogWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "cached megakernel catalog truncated",
            Self::BadMagic => "cached megakernel catalog has wrong magic",
            Self::VersionMismatch => "cached megakernel catalog wire-version mismatch",
            Self::BadRuleShape => "cached megakernel catalog rule failed shape validation",
        })
    }
}

/// Little-endian cursor over a cache blob with bounds checks. No panics and no
/// `bytemuck` alignment assumptions on read — every multi-byte field is decoded
/// via `from_le_bytes`. The cache is host-local, so LE encoding is fine.
struct WireReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CatalogWireError> {
        let end = self.pos.checked_add(n).ok_or(CatalogWireError::Truncated)?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or(CatalogWireError::Truncated)?;
        self.pos = end;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, CatalogWireError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, CatalogWireError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
    fn u32_vec(&mut self, len: usize) -> Result<Vec<u32>, CatalogWireError> {
        let bytes = self.take(len.checked_mul(4).ok_or(CatalogWireError::Truncated)?)?;
        Ok(bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect())
    }
    fn usize_vec(&mut self, len: usize) -> Result<Vec<usize>, CatalogWireError> {
        let mut v = Vec::with_capacity(len.min(1 << 20));
        for _ in 0..len {
            v.push(self.u64()? as usize);
        }
        Ok(v)
    }
    /// A `u32`-length-prefixed raw byte run (a grouped rule's literal bytes).
    fn bytes_vec(&mut self) -> Result<Vec<u8>, CatalogWireError> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }
}

impl vyre_libs::scan::MatchEngineCache for MegakernelCatalog {
    type WireError = CatalogWireError;
    const WIRE_MAGIC: [u8; 4] = CATALOG_WIRE_MAGIC;
    // v2: `rule_to_detector` (Vec<usize>) became `rule_to_detectors`
    // (Vec<Vec<usize>>) for dedup fan-out.
    // v3: added `group_literals` (Vec<Vec<(Vec<u8>, Vec<usize>)>>) — the per-rule
    // byte-check disambiguation table for GROUPED literal rules. The wire layout
    // changed again, so reject v1/v2 blobs and rebuild rather than misparse.
    const WIRE_VERSION: u32 = 3;
    // The catalog is ~GB of dense DFA transition tables; the default 64 MiB
    // bound would reject it as oversized and force a full rebuild every run.
    const MAX_CACHE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

    fn to_bytes(&self) -> Result<Vec<u8>, CatalogWireError> {
        let words: usize = self
            .rules
            .iter()
            .map(|r| r.transitions.len() + r.accept.len() + 4)
            .sum();
        let mut out = Vec::with_capacity(words * 4 + 64);
        out.extend_from_slice(&Self::WIRE_MAGIC);
        out.extend_from_slice(&Self::WIRE_VERSION.to_le_bytes());
        out.extend_from_slice(&(self.rules.len() as u32).to_le_bytes());
        for r in &self.rules {
            out.extend_from_slice(&r.rule_idx.to_le_bytes());
            out.extend_from_slice(&r.state_count.to_le_bytes());
            out.extend_from_slice(&(r.transitions.len() as u32).to_le_bytes());
            out.extend_from_slice(bytemuck::cast_slice(&r.transitions));
            out.extend_from_slice(&(r.accept.len() as u32).to_le_bytes());
            out.extend_from_slice(bytemuck::cast_slice(&r.accept));
        }
        out.extend_from_slice(&(self.rule_to_detectors.len() as u32).to_le_bytes());
        for dets in &self.rule_to_detectors {
            out.extend_from_slice(&(dets.len() as u32).to_le_bytes());
            for &d in dets {
                out.extend_from_slice(&(d as u64).to_le_bytes());
            }
        }
        // group_literals: per rule, a list of (literal bytes, anchors). EMPTY list
        // for a single/regex rule. `rule_to_detectors.len() == group_literals.len()`
        // (one entry per rule) by construction; both are length-prefixed independently
        // so a decode never has to assume that.
        out.extend_from_slice(&(self.group_literals.len() as u32).to_le_bytes());
        for lits in &self.group_literals {
            out.extend_from_slice(&(lits.len() as u32).to_le_bytes());
            for (lit, anchors) in lits {
                out.extend_from_slice(&(lit.len() as u32).to_le_bytes());
                out.extend_from_slice(lit);
                out.extend_from_slice(&(anchors.len() as u32).to_le_bytes());
                for &a in anchors {
                    out.extend_from_slice(&(a as u64).to_le_bytes());
                }
            }
        }
        out.extend_from_slice(&(self.host_detectors.len() as u32).to_le_bytes());
        for &d in &self.host_detectors {
            out.extend_from_slice(&(d as u64).to_le_bytes());
        }
        Ok(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CatalogWireError> {
        let mut r = WireReader::new(bytes);
        if r.take(4)? != Self::WIRE_MAGIC {
            return Err(CatalogWireError::BadMagic);
        }
        if r.u32()? != Self::WIRE_VERSION {
            return Err(CatalogWireError::VersionMismatch);
        }
        let rule_count = r.u32()? as usize;
        let mut rules = Vec::with_capacity(rule_count.min(1 << 20));
        for _ in 0..rule_count {
            let rule_idx = r.u32()?;
            let state_count = r.u32()?;
            let tlen = r.u32()? as usize;
            let transitions = r.u32_vec(tlen)?;
            let alen = r.u32()? as usize;
            let accept = r.u32_vec(alen)?;
            let rule = BatchRuleProgram::new(rule_idx, transitions, accept, state_count)
                .map_err(|_| CatalogWireError::BadRuleShape)?;
            rules.push(rule);
        }
        let rtd_len = r.u32()? as usize;
        let mut rule_to_detectors = Vec::with_capacity(rtd_len.min(1 << 20));
        for _ in 0..rtd_len {
            let inner = r.u32()? as usize;
            rule_to_detectors.push(r.usize_vec(inner)?);
        }
        let gl_len = r.u32()? as usize;
        let mut group_literals = Vec::with_capacity(gl_len.min(1 << 20));
        for _ in 0..gl_len {
            let n = r.u32()? as usize;
            let mut lits = Vec::with_capacity(n.min(1 << 20));
            for _ in 0..n {
                let lit = r.bytes_vec()?;
                let alen = r.u32()? as usize;
                let anchors = r.usize_vec(alen)?;
                lits.push((lit, anchors));
            }
            group_literals.push(lits);
        }
        let host_len = r.u32()? as usize;
        let host_detectors = r.usize_vec(host_len)?;
        Ok(Self {
            rules,
            rule_to_detectors,
            group_literals,
            host_detectors,
            dispatcher: std::sync::Mutex::new(None),
            resident_batch: std::sync::Mutex::new(None),
            lowercase_staging: std::sync::Mutex::new(Vec::new()),
            segment_overlap: std::sync::OnceLock::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_libs::scan::MatchEngineCache;

    /// A round-trip through the on-disk wire format reproduces the catalog
    /// (rules, rule→detector map, host detectors) so a cached load matches a
    /// fresh build.
    #[test]
    fn catalog_wire_roundtrip() {
        let patterns = vec![
            ("ghp_[A-Za-z0-9]{36}".to_string(), 7),
            ("AKIA[A-Z0-9]{16}".to_string(), 3),
            ("AIza[A-Za-z0-9_-]{35}".to_string(), 5), // host path
        ];
        let built = MegakernelCatalog::build(&patterns);
        let bytes = built.to_bytes().expect("encode");
        let loaded = MegakernelCatalog::from_bytes(&bytes).expect("decode");
        assert_eq!(loaded.rule_count(), built.rule_count());
        assert_eq!(loaded.rule_to_detectors, built.rule_to_detectors);
        assert_eq!(loaded.group_literals, built.group_literals);
        assert_eq!(loaded.host_detectors(), built.host_detectors());
        assert_eq!(loaded.rules, built.rules);
    }
}
