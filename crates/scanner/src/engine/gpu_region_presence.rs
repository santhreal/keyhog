//! Dense-output GPU phase-1: per-chunk pattern triggers via vyre's
//! region-attributed presence kernel, replacing the `(id,start,end)` triple
//! emission whose global atomic counter collapses on match-dense input.
//!
//! The downstream phase-2 (`scan_prepared_with_pattern_hits`) consumes only the
//! per-chunk pattern set — it explicitly discards GPU positions ("GPU AC match
//! POSITIONS are unreliable… confirm each hit pid against the WHOLE chunk") and
//! unions the canonical CPU AC trigger roots as a fail-closed backstop. So this
//! path emits `(pid, 0, 0)` placeholder triples carrying only the pid, exactly the
//! shape that consumer already handles, and recall is CPU-backstopped regardless.
//!
//! Sharding: a coalesced batch (256 MiB–1 GiB) exceeds one wgpu dispatch's reach
//! (65535 workgroups), so the buffer is sliced like the triple path and each shard
//! is dispatched with its global base offset (`region_base`) against the whole
//! batch's `region_starts`. Per-shard presence bitmaps are OR-ed (idempotent) into
//! the batch bitmap, then folded to per-chunk triggers.

use super::*;

/// Tri-state cached result of the per-backend region-presence self-test.
/// `None` until the first scan runs the self-test; then `Some(true)` (the GPU
/// region-presence kernel matches the CPU oracle on this backend → use it) or
/// `Some(false)` (lowering/dispatch mismatch → stay on the triple path).
static REGION_PRESENCE_BACKEND_OK: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

impl CompiledScanner {
    /// Dense-output GPU AC phase-1. Returns `Some(Hits(per_chunk_hits))` when the
    /// region-presence path produced the per-chunk trigger sets, or `None` when it
    /// could not run (no matcher/backend, dispatch/readback error, region table
    /// not zero-based) — the caller then falls back to the triple AC path. The
    /// `None` cases are recall-neutral: the triple path produces the same trigger
    /// sets through a different mechanism.
    pub(crate) fn scan_coalesced_gpu_ac_phase1_region_presence(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> Option<GpuPhase1Output> {
        let matcher = self.gpu_matcher()?;
        let backend = self.gpu_backend.as_ref()?;

        let (entries, mut buffer) = super::gpu_coalesce::coalesce_chunks(chunks);
        // Same case-fold + 4-alignment + DONTDUMP contract as the triple AC path
        // (gpu_ac_phase1.rs): the literal automaton is caseless, phase-2 re-confirms
        // on original bytes, and the fold/padding are position-preserving.
        buffer.make_ascii_lowercase();
        while !buffer.len().is_multiple_of(4) {
            buffer.push(0);
        }
        #[cfg(target_os = "linux")]
        // SAFETY: identical contract to scan_coalesced_gpu_ac_phase1 — `buffer` is a
        // live owned Vec describing a valid range; madvise is advisory.
        unsafe {
            libc::madvise(
                buffer.as_ptr() as *mut libc::c_void,
                buffer.len(),
                libc::MADV_DONTDUMP,
            );
        }

        // Region table: the start offset of each coalesced chunk. `coalesce_chunks`
        // emits entries in buffer order with `entries[r].0 == r` and the first chunk
        // at offset 0, so region index == chunk index and region_starts[0] == 0.
        let region_starts: Vec<u32> = entries.iter().map(|&(_, start, _)| start as u32).collect();
        if region_starts.first() != Some(&0) {
            tracing::warn!(
                target: "keyhog::routing",
                "region-presence: coalesced region_starts[0] != 0; using triple AC path"
            );
            return None;
        }
        let region_count = region_starts.len();
        let pattern_count = matcher.pattern_lengths.len();
        let words = pattern_count.div_ceil(32).max(1);

        // Shard like the triple AC path so the per-workgroup blind spot at shard
        // boundaries is identical (recall-parity), and never exceed wgpu's 65535
        // workgroups/dim. workgroup_size_x is the region-presence program's (128).
        let workgroup_x = 128usize;
        let gpu_dispatch_max_bytes = 65_535 * workgroup_x;
        let started = std::time::Instant::now();

        let mut presence = vec![0u32; region_count * words];
        let mut scratch = vyre_libs::scan::dispatch_io::ScanDispatchScratch::default();
        let mut shard_start = 0usize;
        while shard_start < buffer.len() {
            let shard_end = (shard_start + gpu_dispatch_max_bytes).min(buffer.len());
            let shard_bitmap = match matcher.scan_presence_by_region_with_scratch(
                &**backend,
                &buffer[shard_start..shard_end],
                &region_starts,
                shard_start as u32,
                &mut scratch,
            ) {
                Ok(b) => b,
                Err(error) => {
                    // Loud, recall-neutral: fall back to the triple AC path, which
                    // produces the same trigger sets. NOT a silent degrade.
                    tracing::warn!(
                        target: "keyhog::routing",
                        %error,
                        shard_start,
                        "region-presence shard dispatch failed; using triple AC path"
                    );
                    return None;
                }
            };
            if shard_bitmap.len() != presence.len() {
                tracing::warn!(
                    target: "keyhog::routing",
                    got = shard_bitmap.len(),
                    want = presence.len(),
                    "region-presence shard bitmap size mismatch; using triple AC path"
                );
                return None;
            }
            // Idempotent OR: a chunk that straddles a shard boundary has its bits
            // set by whichever shard(s) cover its bytes — union is correct.
            for (acc, w) in presence.iter_mut().zip(shard_bitmap.iter()) {
                *acc |= *w;
            }
            shard_start = shard_end;
        }

        // Fold the per-region bitmap into the `(pid, 0, 0)` per-chunk hit lists the
        // existing phase-2 consumes (it uses only the pid; the CPU AC union backstops
        // recall). Placeholder spans are (0, 0): never used downstream.
        let total_patterns = self.ac_map.len() + self.fallback.len();
        let mut per_chunk_hits: Vec<Vec<(u32, u32, u32)>> =
            (0..chunks.len()).map(|_| Vec::new()).collect();
        for (r, &(chunk_index, _, _)) in entries.iter().enumerate() {
            if chunk_index >= per_chunk_hits.len() {
                continue;
            }
            let row = &presence[r * words..(r + 1) * words];
            for (word_idx, &word) in row.iter().enumerate() {
                let mut bits = word;
                while bits != 0 {
                    let bit = bits.trailing_zeros() as usize;
                    let pid = (word_idx * 32 + bit) as u32;
                    if (pid as usize) < total_patterns {
                        per_chunk_hits[chunk_index].push((pid, 0, 0));
                    }
                    bits &= bits - 1;
                }
            }
        }

        let total_hits: usize = per_chunk_hits.iter().map(Vec::len).sum();
        tracing::debug!(
            target: "keyhog::routing",
            chunks = chunks.len(),
            buffer_bytes = buffer.len(),
            regions = region_count,
            trigger_hits = total_hits,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "region-presence GPU phase-1 produced per-chunk triggers"
        );
        Some(GpuPhase1Output::Hits(per_chunk_hits))
    }

    /// Public introspection: is the dense-output region-presence GPU phase-1 active
    /// on the acquired backend? Runs the one-time self-test on first call. Mirrors
    /// [`Self::gpu_backend_label`] as an observability accessor (tests, `doctor`).
    #[must_use]
    pub fn gpu_region_presence_active(&self) -> bool {
        self.gpu_backend.is_some() && self.gpu_matcher().is_some() && self.region_presence_backend_ok()
    }

    /// Whether the region-presence kernel is correct on the acquired GPU backend.
    ///
    /// The kernel logic is proven recall-identical (test `gpu_region_presence_parity`),
    /// but lowering differs per backend (the triple path is itself CUDA-broken,
    /// PERF-07c). This runs a ONE-TIME self-test on the actual backend: dispatch the
    /// region-presence kernel on a tiny coalesced buffer and compare its per-region
    /// trigger sets against the CPU `reference_scan` oracle. Result cached
    /// process-wide (the GPU backend is process-global). On mismatch or error the
    /// region-presence path is disabled LOUDLY and scanning stays on the triple
    /// path — no silent degrade, no recall risk.
    pub(crate) fn region_presence_backend_ok(&self) -> bool {
        *REGION_PRESENCE_BACKEND_OK.get_or_init(|| self.run_region_presence_selftest())
    }

    fn run_region_presence_selftest(&self) -> bool {
        let Some(matcher) = self.gpu_matcher() else {
            return false;
        };
        let Some(backend) = self.gpu_backend.as_ref() else {
            return false;
        };
        let pattern_count = matcher.pattern_lengths.len();
        if pattern_count == 0 {
            return false;
        }
        let words = pattern_count.div_ceil(32).max(1);

        // Tiny coalesced buffer: a few files with well-known secret-literal prefixes,
        // NUL-separated, lowercased to the literal fold, region_starts[0] == 0.
        let files: [&str; 4] = [
            "key = akiaqylpmn5hfiqr7bbb end",
            "pat: ghp_xyz1234abcd5678efgh9ijkl0123mnop",
            "plain prose, nothing to find here",
            "stripe sk_live_4ec39hqlyjwdarjtt1zdp7dc x",
        ];
        let mut haystack: Vec<u8> = Vec::new();
        let mut region_starts: Vec<u32> = Vec::new();
        for f in &files {
            region_starts.push(haystack.len() as u32);
            haystack.extend_from_slice(f.as_bytes());
            haystack.extend_from_slice(&[0u8; 8]);
        }
        let region_count = region_starts.len();

        // CPU oracle: reference_scan triples reduced to a per-region pid set.
        let mut expected = vec![0u32; region_count * words];
        for m in matcher.reference_scan(&haystack) {
            let pos = m.start;
            let r = region_starts
                .iter()
                .rposition(|&s| s <= pos)
                .unwrap_or(0);
            let pid = m.pattern_id as usize;
            if pid < pattern_count {
                expected[r * words + (pid >> 5)] |= 1u32 << (pid & 31);
            }
        }

        // GPU region-presence (single dispatch, base 0).
        let actual = match matcher.scan_presence_by_region(&**backend, &haystack, &region_starts) {
            Ok(a) => a,
            Err(error) => {
                tracing::warn!(
                    target: "keyhog::routing",
                    %error,
                    "region-presence self-test dispatch failed; region-presence DISABLED, using triple AC path"
                );
                return false;
            }
        };

        if actual == expected {
            tracing::debug!(
                target: "keyhog::routing",
                backend = self.gpu_backend_label().unwrap_or("?"),
                regions = region_count,
                "region-presence self-test PASSED; dense-output GPU phase-1 enabled"
            );
            true
        } else {
            tracing::warn!(
                target: "keyhog::routing",
                backend = self.gpu_backend_label().unwrap_or("?"),
                "region-presence self-test MISMATCH vs CPU oracle; region-presence DISABLED, using triple AC path (no recall impact)"
            );
            false
        }
    }
}
