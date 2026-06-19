//! Live wiring of the megakernel detection path (`engine/megakernel.rs`) into a
//! coalesced GPU scan.
//!
//! Trigger production is the ONLY thing this path changes. It builds the rule
//! catalog from `ac_map` once, dispatches the whole chunk batch in ONE GPU
//! launch, and turns the resulting `(file, detector)` firings into the SAME
//! per-chunk `Option<Vec<u64>>` trigger bitmap the Hyperscan prefilter produces
//! — then hands it to the SHARED `scan_coalesced_phase2`. So windowing,
//! confirmed extraction, fallback, generic, entropy, ML, suppression, dedup,
//! cross-file reassembly and cross-chunk boundary scan are byte-for-byte the
//! coalesced CPU path: the GPU only replaces phase 1.
//!
//! Recall + precision: raw GPU firings are validated against the real detector
//! regex before phase 2. The full CPU Hyperscan trigger floor is not part of the
//! default fast path when every detector lowered to GPU; it is enabled only for
//! explicit parity/debug runs or when host-only detectors need CPU coverage.

#[cfg(all(feature = "gpu", test))]
use super::megakernel_triggers::validation_window_range;
#[cfg(feature = "gpu")]
use super::megakernel_triggers::{merge_validated_triggers, validate_detector_match};
use super::*;
use crate::hw_probe::ScanBackend;

impl CompiledScanner {
    /// The megakernel rule catalog, built once from `ac_map` (or loaded from the
    /// on-disk cache) and held resident. Returns `None` when the catalog has no
    /// GPU rules (nothing lowered / pack failed — both LOUDLY logged at build),
    /// so the caller degrades loudly rather than dispatching an empty catalog.
    #[cfg(feature = "gpu")]
    fn megakernel_catalog(&self) -> Option<&super::megakernel::MegakernelCatalog> {
        let catalog = self.megakernel_catalog.get_or_init(|| {
            // GPU catalog rules are the bounded LITERAL ANCHORS (`gpu_literals`,
            // already ASCII-lowercased + built index-parallel to `ac_map`), NOT the
            // full detector regexes. Rationale (measured): a literal's DFA is always
            // bounded-sync ⇒ intra-file segmentable, whereas the full-regex DFA is
            // `UnboundedCycle` for ~85% of detectors (the in-value `[..]+` self-loop
            // never re-synchronizes) and falls to the host — so a full-regex catalog
            // put only 130/3124 rules on the GPU and they found 0 hits. The literal
            // catalog makes the GPU a device-SATURATED prefilter: every firing is a
            // CANDIDATE the validate gate (`ac_map[i].regex.is_match`) confirms
            // before phase 2 — identical semantics to the CPU AC prefilter, so recall
            // is the AC prefilter's. The megakernel haystack is ASCII-lowercased to
            // match (see `scan_coalesced_megakernel`), the same caseless contract
            // `build_gpu_literals` documents.
            let Some(literals) = self.gpu_literals.as_ref() else {
                // No GPU literal set (GPU disabled, or a degenerate empty literal
                // disabled it): build NO catalog so the megakernel degrades LOUDLY to
                // the CPU scan rather than silently running a weaker/empty GPU pass
                // (Law 10). `rule_count() == 0` ⇒ this returns `None` ⇒ degrade.
                return super::megakernel::MegakernelCatalog::build(&[]);
            };
            if literals.len() != self.ac_map.len() {
                // Invariant: `gpu_literals` is pushed in lockstep with `ac_map`
                // (compiler_build.rs). A length mismatch would silently drop the
                // tail detectors from the catalog — fail CLOSED to the CPU scan and
                // surface it, never build a partial GPU catalog (Law 10).
                eprintln!(
                    "keyhog: gpu_literals/ac_map length mismatch ({} vs {}) — building NO GPU \
                     catalog, scanning on the CPU path (recall-preserving). This is a build-time \
                     invariant break; fix the lockstep construction.",
                    literals.len(),
                    self.ac_map.len()
                );
                return super::megakernel::MegakernelCatalog::build(&[]);
            }
            let patterns: Vec<(String, usize)> = literals
                .iter()
                .enumerate()
                .map(|(i, lit)| {
                    // Literals are byte strings; `regex::escape` so a metacharacter
                    // inside a literal (`.`, `+`, …) matches literally. A non-UTF8
                    // literal can't feed the regex DFA builder, so fall back to the
                    // detector's FULL regex for that rule — it lowers to an
                    // (unbounded) host rule, keeping the detector covered on the CPU
                    // path rather than dropped (Law 10). Token-prefix literals are
                    // ASCII in practice, so this is the rare tail.
                    match std::str::from_utf8(lit) {
                        Ok(s) => (regex::escape(s), i),
                        Err(_) => (self.ac_map[i].regex.as_str().to_string(), i), // LAW10: non-UTF8 literal ⇒ full detector regex (superset, recall preserved, never dropped); catalog-build cost only, rounding error per scan (see block comment above).
                    }
                })
                .collect();
            super::megakernel::MegakernelCatalog::build_cached(&patterns)
        });
        (catalog.rule_count() > 0).then_some(catalog)
    }

    /// Coalesced megakernel scan: one GPU dispatch over the whole `chunks` batch
    /// produces the per-chunk trigger bitmap, then the SHARED coalesced phase-2
    /// tail runs the identical per-chunk extraction every other backend uses.
    /// Degrades LOUDLY to the per-chunk SIMD path when the catalog or backend is
    /// unavailable, or the dispatch errors — never a silent empty result.
    pub(crate) fn scan_coalesced_megakernel(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        if chunks.is_empty() {
            return Vec::new();
        }

        let degrade = |reason: String| -> Vec<Vec<keyhog_core::RawMatch>> {
            super::gpu_forced::deny_silent_gpu_degrade(self, ScanBackend::Gpu);
            // Degrade to the backend that is ACTUALLY live, not a hardcoded
            // `SimdCpu`: with the `simd` feature compiled but no Hyperscan
            // prefilter built (`simd_prefilter == None`), routing through
            // `SimdCpu` would itself silently re-degrade to the pure-CPU AC
            // path inside `scan_with_backend`. `degraded_backend_after_gpu_failure`
            // returns `SimdCpu` only when the prefilter is live and
            // `CpuFallback` otherwise, so the operator-visible backend matches
            // what runs (Law 10).
            let degraded = self.degraded_backend_after_gpu_failure();
            // Record the reason so operators (and the GPU self-test) can see WHY
            // the GPU path fell back, not just that it did.
            if let Ok(mut slot) = self.gpu_last_degrade_reason.lock() {
                *slot = Some(reason.clone());
            }
            self.gpu_degrade_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                target: "keyhog::gpu",
                %reason,
                ?degraded,
                "megakernel scan degraded off GPU (loud, recall-preserving)",
            );
            use rayon::prelude::*;
            let mut results: Vec<Vec<keyhog_core::RawMatch>> = chunks
                .par_iter()
                .map(|chunk| self.scan_with_backend(chunk, degraded))
                .collect();
            super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
            results
        };

        // The shared coalesced phase-2 tail is `#[cfg(feature = "simd")]` (it is
        // the Hyperscan path's extraction). `gpu` implies `simd` at the feature
        // level (see keyhog-scanner Cargo.toml: `gpu = ["simd", ...]`), so this
        // body is ALWAYS compiled under `gpu` and the megakernel always has its
        // tail. The `#[cfg(feature = "simd")]` is retained as a fail-closed
        // assertion of that invariant: were the dependency ever dropped, this
        // function would fail to compile rather than silently lose its tail.
        #[cfg(feature = "simd")]
        {
            let kh = super::profile::perf_trace_enabled();
            let t_cat = std::time::Instant::now();
            let Some(catalog) = self.megakernel_catalog() else {
                return degrade("catalog: no ac_map pattern lowered to a GPU DFA".to_string());
            };
            let cat_s = t_cat.elapsed();
            let Some(backend) = self.wgpu_backend.as_ref() else {
                return degrade("no wgpu backend acquired at compile time".to_string());
            };

            let words = self.ac_map.len().div_ceil(64).max(1);

            // Step 1: GPU dispatch — the raw firing set (over-fires + possibly
            // a dropped firing). The catalog owns the reusable lowercase
            // staging buffers so this dispatch path does not allocate one
            // fresh haystack `Vec` per chunk per batch.
            let t_co = std::time::Instant::now();
            let co_s = t_co.elapsed();

            let t_dis = std::time::Instant::now();
            let firings = match catalog.scan(backend, chunks) {
                Ok(f) => f,
                Err(error) => return degrade(format!("dispatch error: {error}")),
            };
            let dis_s = t_dis.elapsed();

            let t_val = std::time::Instant::now();
            let full_recall_floor = self.tuning.gpu_recall_floor_enabled();
            let host_floor = !catalog.host_detectors().is_empty();
            let cpu_triggers = if full_recall_floor || host_floor {
                match self.simd_prefilter.as_ref() {
                    Some(scanner) => Some(self.compute_coalesced_triggers(chunks, scanner)),
                    None if host_floor => {
                        return degrade(format!(
                            "catalog has {} host-only detector(s) but no SIMD prefilter is live",
                            catalog.host_detectors().len()
                        ));
                    }
                    None => None,
                }
            } else {
                None
            };

            // The validation oracle MUST scan the SAME text phase-2 extracts from
            // — the PREPROCESSED chunk (homoglyph-normalized + interior-control
            // stripped), NOT raw bytes. A secret obfuscated with a zero-width
            // space (`ghp_<ZWSP>aBcD…`) does not match the detector regex on raw
            // bytes but DOES after `prepare_chunk`'s control strip, and the SIMD
            // path's literal prefilter fires on the raw `ghp_` and lets phase-2
            // find it on the stripped text. Validating on raw bytes would drop
            // that bit — a silent recall loss vs SIMD (Law 10). So we prepare each
            // candidate chunk ONCE (cached; most chunks have no candidate and pay
            // nothing) and run the oracle on `preprocessed.text`.
            let prepared_text: Vec<std::cell::OnceCell<String>> = (0..chunks.len())
                .map(|_| std::cell::OnceCell::new())
                .collect();
            let validate = |ci: usize, det: usize, match_offset: Option<usize>| -> bool {
                let text = prepared_text[ci].get_or_init(|| {
                    self.prepare_chunk(&chunks[ci])
                        .preprocessed
                        .text
                        .as_ref()
                        .to_string()
                });
                let rx = self.ac_map[det].regex.get();
                validate_detector_match(
                    text.as_str(),
                    rx,
                    match_offset,
                    self.ac_match_upper_bounds.get(det).copied().flatten(),
                )
            };
            let merged = merge_validated_triggers(
                chunks.len(),
                words,
                self.ac_map.len(),
                &firings,
                cpu_triggers.as_deref(),
                catalog.host_detectors(),
                validate,
            );
            let triggers = merged.triggers;
            let raw_pairs = merged.raw_pairs;
            let gpu_overfire_dropped = merged.gpu_overfire_dropped;
            let gpu_underfire_recovered = merged.gpu_underfire_recovered;
            let val_s = t_val.elapsed();

            // Surface a GPU under-fire LOUDLY: the GPU DFA missed a real
            // detector match the CPU floor recovered. This is a vyre megakernel
            // recall bug (ring overflow / byte-class edge / divergence) the
            // floor papered over — record it so it is fixed at the source, never
            // hidden (Law 10). One-shot per process to avoid log spam.
            if gpu_underfire_recovered > 0 {
                static UNDERFIRE_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
                if UNDERFIRE_WARNED.set(()).is_ok() {
                    eprintln!(
                        "keyhog: GPU megakernel under-fired on {gpu_underfire_recovered} \
                         (chunk, detector) pair(s) recovered by gpu_recall_floor/host \
                         coverage — fix the vyre DFA path before treating GPU-only as parity-safe."
                    );
                }
                tracing::warn!(
                    target: "keyhog::gpu",
                    recovered = gpu_underfire_recovered,
                    "GPU megakernel under-fire recovered by CPU recall floor (vyre recall bug)",
                );
            }

            // Count the validated trigger bits actually fed to phase-2: the
            // over-firing metric. This is the candidate count the lane caps at
            // ≤ the SIMD path's bit count.
            let validated_trigger_bits: usize = triggers
                .iter()
                .filter_map(|t| t.as_ref())
                .map(|w| w.iter().map(|x| x.count_ones() as usize).sum::<usize>())
                .sum();

            let t_p2 = std::time::Instant::now();
            let results = self.scan_coalesced_phase2(chunks, triggers);
            if kh {
                eprintln!(
                    "perf-trace megakernel: chunks={} catalog={:.3}s coalesce={:.3}s dispatch={:.3}s validate={:.3}s phase2={:.3}s firings={} raw_pairs={} overfire_dropped={} underfire_recovered={} trigger_bits={} gpu_rules={} host_only={} full_recall_floor={} host_floor={}",
                    chunks.len(),
                    cat_s.as_secs_f64(),
                    co_s.as_secs_f64(),
                    dis_s.as_secs_f64(),
                    val_s.as_secs_f64(),
                    t_p2.elapsed().as_secs_f64(),
                    firings.len(),
                    // Distinct (chunk, detector) firing pairs the GPU produced,
                    // before validation — the raw over-firing surface.
                    raw_pairs,
                    // Pairs the anchored regex rejected (pure GPU over-fire,
                    // dropped from phase-2 — the over-firing reduction).
                    gpu_overfire_dropped,
                    // Pairs the CPU floor recovered (GPU under-fire — a vyre
                    // recall bug, surfaced loudly above).
                    gpu_underfire_recovered,
                    // Validated trigger bits fed to phase-2 (the candidate count).
                    validated_trigger_bits,
                    catalog.rule_count(),
                    catalog.host_detectors().len(),
                    full_recall_floor,
                    host_floor,
                );
            }
            // Diagnostic: dump the phase-2 leaf breakdown (Confirmed / FbPrefilter /
            // Generic / Entropy / Ml …) so the localizable-vs-whole-chunk cost split
            // is visible — the data Part B (localized phase 2) is designed against.
            // Gated through the single profiler owner, so dispatch does not grow
            // a second environment-control path.
            if super::profile::enabled() {
                super::profile::dump("megakernel-phase2");
            }
            results
        }
    }
}

#[cfg(all(test, feature = "gpu"))]
mod tests {
    use super::*;

    #[test]
    fn merge_passes_gpu_match_offset_to_validator_once_per_pair() {
        let firings = [
            super::super::megakernel::Firing {
                file_index: 0,
                detector: 2,
                match_offset: 17,
            },
            super::super::megakernel::Firing {
                file_index: 0,
                detector: 2,
                match_offset: 99,
            },
        ];
        let mut seen = Vec::new();
        let merged = merge_validated_triggers(1, 1, 8, &firings, None, &[], |ci, det, hit| {
            seen.push((ci, det, hit));
            hit == Some(17)
        });

        assert_eq!(merged.raw_pairs, 1);
        assert_eq!(merged.gpu_overfire_dropped, 0);
        assert_eq!(merged.gpu_underfire_recovered, 0);
        assert_eq!(seen, vec![(0, 2, Some(17))]);
        assert_eq!(merged.triggers[0].as_ref().unwrap()[0], 1u64 << 2);
    }

    #[test]
    fn merge_passes_no_match_offset_for_cpu_recall_floor() {
        let cpu_triggers = vec![Some(vec![1u64 << 3])];
        let mut seen = Vec::new();
        let merged =
            merge_validated_triggers(1, 1, 8, &[], Some(&cpu_triggers), &[], |ci, det, hit| {
                seen.push((ci, det, hit));
                hit.is_none()
            });

        assert_eq!(merged.raw_pairs, 0);
        assert_eq!(merged.gpu_overfire_dropped, 0);
        assert_eq!(merged.gpu_underfire_recovered, 1);
        assert_eq!(seen, vec![(0, 3, None)]);
        assert_eq!(merged.triggers[0].as_ref().unwrap()[0], 1u64 << 3);
    }

    #[test]
    fn validation_window_range_preserves_utf8_boundaries() {
        let text = "αβghp_secretδ";
        let (start, end) = validation_window_range(text, 6, 5).expect("window");

        assert!(text.is_char_boundary(start));
        assert!(text.is_char_boundary(end));
        assert!(text[start..end].contains("ghp"));
    }

    #[test]
    fn bounded_gpu_firing_rejects_window_miss_without_full_chunk_scan() {
        let rx = regex::Regex::new(r"SECRET-[0-9]{4}").expect("regex");
        let text = "prefix bait hit here\n\nlots of filler\n\nSECRET-1234";
        let distant_match_offset = text.find("SECRET-1234").expect("match");

        assert!(
            validate_detector_match(
                text,
                &rx,
                Some(distant_match_offset),
                Some("SECRET-1234".len())
            ),
            "bounded validator must accept a real local match"
        );
        assert!(
            !validate_detector_match(text, &rx, Some(0), Some("SECRET-1234".len())),
            "bounded GPU over-fire validation must not fall back to a full-chunk \
             regex scan after the local window misses"
        );
    }

    #[test]
    fn unbounded_and_cpu_floor_validation_keep_full_chunk_oracle() {
        let rx = regex::Regex::new(r"SECRET=.*END").expect("regex");
        let text = "prefix bait hit here\nSECRET=abc123END";

        assert!(
            validate_detector_match(text, &rx, Some(0), None),
            "unbounded detector validation keeps the full prepared-chunk oracle"
        );
        assert!(
            validate_detector_match(text, &rx, None, Some(8)),
            "CPU recall-floor validation has no GPU offset, so it keeps the full \
             prepared-chunk oracle"
        );
    }

    #[test]
    fn bounded_validation_source_has_no_old_full_chunk_fallback() {
        let src = include_str!("megakernel_dispatch.rs");
        let old_full_chunk_regex_scan = ["rx.is_match", "(text.as_str())"].concat();
        assert!(
            !src.contains(&old_full_chunk_regex_scan),
            "bounded GPU firing validation must not fall back to a full prepared-chunk \
             regex scan after its local proof window misses"
        );
    }
}
