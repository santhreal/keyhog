//! Exact first-bigram prescreen for literal-set Aho-Corasick scans.
//!
//! Each set bit means at least one literal can start with that adjacent byte
//! pair. If a text contains none of the indexed first bigrams, the corresponding
//! AC cannot match and the caller can skip the state-machine scan entirely. A
//! hit is only a maybe: callers still run their exact AC to preserve the same
//! match set.

pub(crate) struct FirstBigramSet {
    bits: Box<[u64; 1024]>,
    fail_open: bool,
}

impl FirstBigramSet {
    /// Build from deduplicated anchor literals. When `ascii_case_insensitive`
    /// is true, insert all ASCII case variants for the first pair to mirror an
    /// `ascii_case_insensitive` AC. Called once at scanner-build time.
    pub(crate) fn from_literals<'a>(
        lits: impl IntoIterator<Item = &'a [u8]>,
        ascii_case_insensitive: bool,
    ) -> Self {
        let mut bits = Box::new([0u64; 1024]);
        for lit in lits {
            if lit.len() < 2 {
                // Law 10: a <2-byte literal has no first-bigram to gate on, so
                // absence can never be proven. Saturate the set: every text falls
                // through to the exact AC, never a silent skip.
                return Self {
                    bits: Box::new([u64::MAX; 1024]),
                    fail_open: true,
                };
            }
            let a = lit[0];
            let b = lit[1];
            let mut a_variants = [a; 2];
            let a_len = if ascii_case_insensitive && a.is_ascii_alphabetic() {
                a_variants = [a.to_ascii_lowercase(), a.to_ascii_uppercase()];
                2
            } else {
                1
            };
            let mut b_variants = [b; 2];
            let b_len = if ascii_case_insensitive && b.is_ascii_alphabetic() {
                b_variants = [b.to_ascii_lowercase(), b.to_ascii_uppercase()];
                2
            } else {
                1
            };
            for &ca in &a_variants[..a_len] {
                for &cb in &b_variants[..b_len] {
                    let idx = (ca as usize) << 8 | cb as usize;
                    bits[idx >> 6] |= 1u64 << (idx & 63);
                }
            }
        }
        Self {
            bits,
            fail_open: false,
        }
    }

    #[inline]
    pub(crate) fn may_have_match(&self, match_text: &str) -> bool {
        if self.fail_open {
            return true;
        }
        let bytes = match_text.as_bytes();
        let bits = self.bits.as_ref();
        let len = bytes.len();
        if len < 2 {
            return false;
        }
        let last_start = len - 2;
        #[inline(always)]
        fn probe(bits: &[u64; 1024], bytes: &[u8], i: usize) -> bool {
            let idx = (bytes[i] as usize) << 8 | bytes[i + 1] as usize;
            bits[idx >> 6] & (1u64 << (idx & 63)) != 0
        }
        let mut i = 0usize;
        while i + 4 <= last_start + 1 {
            if probe(bits, bytes, i)
                | probe(bits, bytes, i + 1)
                | probe(bits, bytes, i + 2)
                | probe(bits, bytes, i + 3)
            {
                return true;
            }
            i += 4;
        }
        while i <= last_start {
            if probe(bits, bytes, i) {
                return true;
            }
            i += 1;
        }
        false
    }
}
