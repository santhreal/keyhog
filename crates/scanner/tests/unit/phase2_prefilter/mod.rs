use super::dispatch_plan::{BatchMatcher, DispatchConfig, DispatchPlan, PrefilterScope};
use super::gating::{combined_gate_decision, CombinedGateDecision, PortableGateEvidence};
use super::trigger_evidence::{ChunkTriggerEvidence, TriggerEvidence};
use super::{CombinedNoCandidateGate, FirstBigramSet, PortablePrefilter, PrefilterBatch};

/// A batch whose matcher cells are already populated. Every test below passes
/// an EMPTY pattern slice alongside it, so any attempt to (re)compile would
/// panic on an out-of-range phase-2 index. That is the assertion: a resolved
/// matcher is served from its cell, never rebuilt per chunk.
fn seeded_batch(
    sources: &[&str],
    phase2_indices: Vec<usize>,
    gateable: bool,
    homoglyph_skippable: bool,
) -> PrefilterBatch {
    let build = || regex::RegexSet::new(sources).expect("fixture RegexSet");
    let batch = PrefilterBatch {
        phase2_indices,
        case_insensitive: false,
        gateable,
        homoglyph_skippable,
        set: std::sync::OnceLock::new(),
        ascii_set: std::sync::OnceLock::new(),
        set_trunc: std::sync::OnceLock::new(),
        ascii_set_trunc: std::sync::OnceLock::new(),
    };
    batch.set.set(Some(build())).expect("fresh cell");
    batch.ascii_set.set(Some(build())).expect("fresh cell");
    batch.set_trunc.set(Some(build())).expect("fresh cell");
    batch
        .ascii_set_trunc
        .set(Some(build()))
        .expect("fresh cell");
    batch
}

/// The compile input for a seeded batch: empty, so a compile attempt panics.
const NO_PATTERNS: &[(crate::types::CompiledPattern, Vec<String>)] = &[];

fn run_matcher(matcher: BatchMatcher<'_>, text: &str) -> Vec<usize> {
    match matcher {
        BatchMatcher::Run(set) => set.matches(text).iter().collect(),
        BatchMatcher::Unavailable => panic!("seeded batch must resolve a matcher"),
    }
}

fn config() -> DispatchConfig {
    DispatchConfig {
        #[cfg(feature = "simd")]
        fallback_hs: true,
        #[cfg(feature = "simd")]
        hs_prefilter_max_len: 16,
        homoglyph_gate: true,
        homoglyph_ascii_skip: true,
        fallback_prefix_gate: true,
        prefilter_truncate: true,
    }
}

/// Regression for KH-043: trigger observation distinguishes exact presence,
/// exact absence, and unavailable evidence while borrowing the original bytes.
#[test]
fn exact_trigger_evidence_preserves_bytes_and_unknown_state() {
    let ac = aho_corasick::AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(["client_secret", "api-token"])
        .expect("fixture automaton");
    let text = "prefix CLIENT_SECRET suffix";
    let evidence = ChunkTriggerEvidence::inspect(text);

    assert_eq!(evidence.text().as_ptr(), text.as_ptr());
    assert_eq!(evidence.text().len(), text.len());
    assert!(evidence.is_ascii());
    assert_eq!(evidence.observe_ac(Some(&ac)), TriggerEvidence::Present);
    assert_eq!(
        ChunkTriggerEvidence::inspect("dense but irrelevant bytes").observe_ac(Some(&ac)),
        TriggerEvidence::Absent
    );
    assert_eq!(evidence.observe_ac(None), TriggerEvidence::Unavailable);
}

/// Regression for KH-043: adversarial dense trigger-like input is classified
/// by the exact automaton rather than byte density or a substring heuristic.
#[test]
fn dense_adversarial_input_requires_an_exact_trigger() {
    let ac = aho_corasick::AhoCorasick::new(["token="]).expect("fixture automaton");
    let mut dense = "tokentokentokentokentokentokentoken".repeat(4096);
    assert_eq!(
        ChunkTriggerEvidence::inspect(&dense).observe_ac(Some(&ac)),
        TriggerEvidence::Absent
    );

    dense.push_str("token=");
    assert_eq!(
        ChunkTriggerEvidence::inspect(&dense).observe_ac(Some(&ac)),
        TriggerEvidence::Present
    );
}

/// Regression for KH-043: combined gating dispatches on positive, disabled,
/// non-ASCII, and unavailable evidence, bypassing only an exact ASCII negative.
#[test]
fn combined_gate_positive_negative_and_degraded_truth_table() {
    let literal = &b"client_secret"[..];
    let gate = CombinedNoCandidateGate {
        anchor_ac: aho_corasick::AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build([literal])
            .expect("fixture automaton"),
        non_anchorable: Vec::new(),
        anchor_first_bigram: FirstBigramSet::from_literals([literal], true),
    };
    assert_eq!(
        combined_gate_decision(
            ChunkTriggerEvidence::inspect("CLIENT_SECRET=value"),
            true,
            Some(&gate)
        ),
        CombinedGateDecision::Dispatch
    );
    assert_eq!(
        combined_gate_decision(
            ChunkTriggerEvidence::inspect("client-secret-like dense noise"),
            true,
            Some(&gate)
        ),
        CombinedGateDecision::NonAnchorableOnly
    );
    assert_eq!(
        combined_gate_decision(
            ChunkTriggerEvidence::inspect("é irrelevant"),
            true,
            Some(&gate)
        ),
        CombinedGateDecision::Dispatch
    );
    assert_eq!(
        combined_gate_decision(
            ChunkTriggerEvidence::inspect("irrelevant"),
            false,
            Some(&gate)
        ),
        CombinedGateDecision::Dispatch
    );
    assert_eq!(
        combined_gate_decision(ChunkTriggerEvidence::inspect("irrelevant"), true, None),
        CombinedGateDecision::Dispatch
    );
}

/// Regression for KH-043: CI and plain gates act only on their own partition,
/// and unavailable evidence makes both partitions run rather than silently skip.
#[test]
fn portable_partition_gates_are_independent_and_fail_closed() {
    let portable = PortablePrefilter {
        batches: Vec::new(),
        ci_gate: Some(
            aho_corasick::AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(["client_secret"])
                .expect("CI fixture automaton"),
        ),
        plain_gate: Some(
            aho_corasick::AhoCorasick::new(["token="]).expect("plain fixture automaton"),
        ),
    };

    let ci_only = PortableGateEvidence::new(
        ChunkTriggerEvidence::inspect("CLIENT_SECRET=value"),
        true,
        true,
        &portable,
    );
    assert!(ci_only.run_gateable_batch(false));
    assert!(!ci_only.run_gateable_batch(true));

    let absent = PortableGateEvidence::new(
        ChunkTriggerEvidence::inspect("irrelevant"),
        true,
        true,
        &portable,
    );
    assert!(!absent.run_gateable_batch(false));
    assert!(!absent.run_gateable_batch(true));

    let unavailable = PortableGateEvidence::new(
        ChunkTriggerEvidence::inspect("é irrelevant"),
        true,
        false,
        &portable,
    );
    assert!(unavailable.run_gateable_batch(false));
    assert!(unavailable.run_gateable_batch(true));
}

/// Regression for KH-043: ownership modes map to exact full, anchor-residual,
/// and localized-residual plans without changing pattern order.
#[test]
fn dispatch_plan_selects_the_exact_ownership_scope() {
    assert_eq!(
        DispatchPlan::for_mark("ascii", false, false, true, config()).scope(),
        PrefilterScope::Full
    );
    assert_eq!(
        DispatchPlan::for_mark("ascii", true, false, true, config()).scope(),
        PrefilterScope::AnchorResidual
    );
    assert_eq!(
        DispatchPlan::for_mark("ascii", true, true, true, config()).scope(),
        PrefilterScope::LocalizedResidual
    );
    assert_eq!(
        DispatchPlan::for_mark("é", true, true, true, config()).scope(),
        PrefilterScope::AnchorResidual
    );
}

#[cfg(feature = "simd")]
/// Regression for KH-043: marking and admission share one HS predicate—large
/// ASCII remains eligible, large non-ASCII does not, and disabled HS never is.
#[test]
fn dispatch_plan_has_one_hyperscan_truth_table() {
    let large_ascii = "a".repeat(32);
    let large_unicode = "é".repeat(32);
    assert!(DispatchPlan::for_mark(&large_ascii, false, false, true, config()).try_hyperscan());
    assert!(DispatchPlan::for_admission(&large_ascii, true, config()).try_hyperscan());
    assert!(!DispatchPlan::for_mark(&large_unicode, false, false, true, config()).try_hyperscan());
    assert!(!DispatchPlan::for_admission(&large_unicode, true, config()).try_hyperscan());
    assert!(!DispatchPlan::for_admission(&large_ascii, false, config()).try_hyperscan());
}

/// Regression for KH-043: planning stays fixed-size and borrows arbitrarily
/// large dense input, preventing per-byte allocation or scale-dependent storage.
#[test]
fn dispatch_plan_storage_is_constant_scale_and_borrows_input() {
    fn assert_copy<T: Copy>() {}
    assert_copy::<DispatchPlan<'static>>();

    let small = "token=token=";
    let dense = "token=".repeat(128 * 1024);
    let small_plan = DispatchPlan::for_admission(small, true, config());
    let dense_plan = DispatchPlan::for_admission(&dense, true, config());

    assert_eq!(
        std::mem::size_of_val(&small_plan),
        std::mem::size_of_val(&dense_plan)
    );
    assert_eq!(dense_plan.chunk().text().as_ptr(), dense.as_ptr());
    assert_eq!(dense_plan.chunk().text().len(), dense.len());
}

/// Regression for KH-043: every portable matcher plan reports identical set
/// entry ids and preserves their phase-2 marking order on dense mixed triggers.
#[test]
fn portable_dispatch_plans_preserve_exact_match_id_order() {
    let batch = seeded_batch(
        &[r"token=[A-Z0-9]+", r"secret=[a-z0-9]+", r"key_[0-9]+="],
        vec![11, 3, 29],
        false,
        false,
    );
    let text = format!(
        "{} secret=abc token=XYZ9 key_42= {}",
        "tokenish=".repeat(4096),
        "secretish=".repeat(4096)
    );

    let truncated = DispatchPlan::for_admission(&text, false, config());
    let mut full_config = config();
    full_config.prefilter_truncate = false;
    let full = DispatchPlan::for_admission(&text, false, full_config);
    let expected = vec![0, 1, 2];
    assert_eq!(
        run_matcher(truncated.matcher_for(&batch, NO_PATTERNS), &text),
        expected
    );
    assert_eq!(
        run_matcher(full.matcher_for(&batch, NO_PATTERNS), &text),
        expected
    );
    assert_eq!(
        expected
            .iter()
            .map(|&set_index| batch.phase2_indices[set_index])
            .collect::<Vec<_>>(),
        vec![11, 3, 29]
    );
}

/// A batch the plan skips must never compile a matcher. Eager compilation
/// charged 1.4 s of RegexSet construction to the first decoded sub-chunk of a
/// scan and then skipped every batch it had just built, which made decode
/// through the dominant cost of an otherwise sub-second scan.
///
/// The batch here has EMPTY matcher cells and an out-of-range phase-2 index, so
/// resolving a matcher would panic. Reaching the end of the test proves the
/// skip happened before any compile was attempted.
#[test]
fn a_skipped_homoglyph_batch_never_compiles_its_matcher() {
    let batch = PrefilterBatch {
        phase2_indices: vec![usize::MAX],
        case_insensitive: false,
        gateable: false,
        homoglyph_skippable: true,
        set: std::sync::OnceLock::new(),
        ascii_set: std::sync::OnceLock::new(),
        set_trunc: std::sync::OnceLock::new(),
        ascii_set_trunc: std::sync::OnceLock::new(),
    };
    // A pure-ASCII chunk with homoglyph ASCII-skip enabled is exactly the case
    // the skip exists for.
    let plan = DispatchPlan::for_admission("plain ascii chunk", false, config());
    assert!(
        plan.skip_homoglyph_batch(&batch),
        "an ASCII chunk must skip a homoglyph-variant batch"
    );
    assert!(
        batch.set.get().is_none()
            && batch.set_trunc.get().is_none()
            && batch.ascii_set.get().is_none()
            && batch.ascii_set_trunc.get().is_none(),
        "deciding to skip a batch must not populate any matcher cell"
    );
}

/// Each matcher variant is compiled independently, so selecting the truncated
/// form must leave the untruncated cell empty. A batch that eagerly built all
/// four variants paid four compiles to run one.
#[test]
fn resolving_one_variant_leaves_the_others_uncompiled() {
    let batch = PrefilterBatch {
        phase2_indices: vec![usize::MAX],
        case_insensitive: false,
        gateable: false,
        homoglyph_skippable: false,
        set: std::sync::OnceLock::new(),
        ascii_set: std::sync::OnceLock::new(),
        set_trunc: std::sync::OnceLock::new(),
        ascii_set_trunc: std::sync::OnceLock::new(),
    };
    let sources = [r"token=[A-Z0-9]+"];
    batch
        .ascii_set_trunc
        .set(Some(
            regex::RegexSet::new(sources).expect("fixture RegexSet"),
        ))
        .expect("fresh cell");

    // ASCII text with the homoglyph gate on selects the folded truncated form.
    let plan = DispatchPlan::for_admission("token=ABC1", false, config());
    assert_eq!(
        run_matcher(plan.matcher_for(&batch, NO_PATTERNS), "token=ABC1"),
        vec![0]
    );
    assert!(
        batch.set.get().is_none()
            && batch.set_trunc.get().is_none()
            && batch.ascii_set.get().is_none(),
        "resolving the folded truncated matcher must not compile the other three"
    );
}
