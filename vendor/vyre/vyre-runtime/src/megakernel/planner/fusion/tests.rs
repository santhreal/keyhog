use super::*;

fn item(op_handle: u32, input_handle: u32, output_handle: u32) -> MegakernelWorkItem {
    MegakernelWorkItem {
        op_handle,
        input_handle,
        output_handle,
        param: 0,
    }
}

#[test]
fn compact_plan_reuses_scratch_and_records_exchange_graph() {
    let work = [item(7, 1, 2), item(7, 3, 4), item(9, 4, 5)];
    let mut scratch = CompactFusionPlanningScratch::default();

    let selected = plan_compact_fusion_into(&work, &mut scratch).to_vec();

    assert_eq!(selected.len(), work.len());
    assert_eq!(scratch.exchange_adj().len(), work.len() * work.len());
    assert_eq!(
        scratch.exchange_adj()[1],
        1,
        "same-op work items must be connected in the runtime exchange graph"
    );
    assert_eq!(
        scratch.exchange_adj()[5],
        0,
        "linear output->input discount changes cost, not exchange incompatibility"
    );
}

#[test]
fn compact_plan_empty_batch_clears_previous_scratch() {
    let work = [item(1, 1, 2)];
    let mut scratch = CompactFusionPlanningScratch::default();
    let selected_before_clear = plan_compact_fusion_into(&work, &mut scratch);
    assert_eq!(selected_before_clear.len(), work.len());
    assert!(!scratch.exchange_adj().is_empty());

    let selected = plan_compact_fusion_into(&[], &mut scratch);

    assert!(selected.is_empty());
    assert!(scratch.exchange_adj().is_empty());
}

// ── C5: gated no-op middle-arm elimination tests ────────────────

#[test]
fn prune_dead_arms_zeroes_only_selected_dead_arms() {
    let mut sel = vec![1, 1, 1, 1, 1];
    let dead = vec![false, true, false, true, false];
    let n = prune_dead_arms_inplace(&mut sel, &dead);
    assert_eq!(sel, vec![1, 0, 1, 0, 1]);
    assert_eq!(n, 2);
}

#[test]
fn select_fused_subset_pruned_eliminates_dead_selected_arm() {
    let costs = [1.0, 2.0, 3.0];
    let exchange_adj = vec![0_u32; 9];
    let dead = [false, true, false];

    let selected = select_fused_subset_pruned(&costs, 3, &exchange_adj, &dead);

    assert_eq!(selected, vec![1, 0, 1]);
}

#[test]
fn select_fused_subset_pruned_into_reuses_selection_scratch() {
    let costs = [1.0, 2.0, 3.0, 4.0];
    let exchange_adj = vec![0_u32; 16];
    let dead = [true, false, true, false];
    let mut scratch = FusionSelectionScratch::default();

    select_fused_subset_pruned_into(&costs, 4, &exchange_adj, &dead, &mut scratch);

    assert_eq!(scratch.result, vec![0, 1, 0, 1]);
    assert_eq!(scratch.order.len(), 4);
}

#[test]
fn prune_dead_arms_does_not_count_unselected_dead_arms() {
    // Arm 1 is dead but ALREADY unselected (selection=0). It should
    // not increment the eliminated count — there's nothing to remove.
    let mut sel = vec![1, 0, 1];
    let dead = vec![false, true, false];
    let n = prune_dead_arms_inplace(&mut sel, &dead);
    assert_eq!(sel, vec![1, 0, 1]);
    assert_eq!(n, 0);
}

#[test]
fn prune_dead_arms_returns_zero_on_length_mismatch() {
    let mut sel = vec![1, 1, 1];
    let dead = vec![true, false]; // wrong length
    let n = prune_dead_arms_inplace(&mut sel, &dead);
    assert_eq!(n, 0);
    // Selection must be untouched.
    assert_eq!(sel, vec![1, 1, 1]);
}

#[test]
fn prune_dead_arms_handles_empty_selection() {
    let mut sel: Vec<u32> = vec![];
    let dead: Vec<bool> = vec![];
    let n = prune_dead_arms_inplace(&mut sel, &dead);
    assert_eq!(n, 0);
}

#[test]
fn prune_dead_arms_idempotent_on_repeated_call() {
    let mut sel = vec![1, 1, 0, 1];
    let dead = vec![true, false, true, true];
    let first = prune_dead_arms_inplace(&mut sel, &dead);
    let after_first = sel.clone();
    let second = prune_dead_arms_inplace(&mut sel, &dead);
    assert_eq!(first, 2);
    assert_eq!(second, 0, "second pass must find nothing left to prune");
    assert_eq!(sel, after_first);
}

#[test]
fn prune_dead_arms_preserves_non_zero_unselected_entries() {
    // Defensive: planner cost vectors sometimes carry sentinel
    // values like u32::MAX. The substrate must only zero entries
    // that are dead AND currently selected; it must not stomp on
    // sentinel values it doesn't understand.
    let mut sel = vec![u32::MAX, 1, 1];
    let dead = vec![false, true, false];
    let n = prune_dead_arms_inplace(&mut sel, &dead);
    assert_eq!(sel, vec![u32::MAX, 0, 1]);
    assert_eq!(n, 1);
}

// ── C3: shared prologue extraction tests ─────────────────────────

#[test]
fn shared_prologue_zero_when_arm_list_empty() {
    let arms: [&[MegakernelWorkItem]; 0] = [];
    assert_eq!(shared_prologue_length(&arms), 0);
}

#[test]
fn shared_prologue_zero_when_any_arm_empty() {
    let a = vec![item(1, 0, 0), item(2, 0, 0)];
    let b: Vec<MegakernelWorkItem> = vec![];
    let arms: [&[MegakernelWorkItem]; 2] = [&a, &b];
    assert_eq!(shared_prologue_length(&arms), 0);
}

#[test]
fn shared_prologue_zero_when_first_op_differs() {
    let a = vec![item(1, 0, 0), item(2, 0, 0)];
    let b = vec![item(7, 0, 0), item(2, 0, 0)];
    let arms: [&[MegakernelWorkItem]; 2] = [&a, &b];
    assert_eq!(shared_prologue_length(&arms), 0);
}

#[test]
fn shared_prologue_returns_full_length_when_all_arms_identical() {
    let a = vec![item(1, 0, 0), item(2, 0, 0), item(3, 0, 0)];
    let arms: [&[MegakernelWorkItem]; 3] = [&a, &a, &a];
    assert_eq!(shared_prologue_length(&arms), 3);
}

#[test]
fn shared_prologue_returns_partial_prefix_when_arms_diverge_midway() {
    // First two ops match, third differs.
    let a = vec![item(1, 0, 0), item(2, 0, 0), item(3, 0, 0)];
    let b = vec![item(1, 0, 0), item(2, 0, 0), item(99, 0, 0)];
    let c = vec![item(1, 0, 0), item(2, 0, 0)];
    let arms: [&[MegakernelWorkItem]; 3] = [&a, &b, &c];
    // c is the shortest at length 2; shared prefix capped at 2.
    assert_eq!(shared_prologue_length(&arms), 2);
}

#[test]
fn shared_prologue_distinguishes_input_handle_difference() {
    // Same op_handle, different input_handle → not equal.
    let a = vec![item(1, 7, 0)];
    let b = vec![item(1, 9, 0)];
    let arms: [&[MegakernelWorkItem]; 2] = [&a, &b];
    assert_eq!(shared_prologue_length(&arms), 0);
}

#[test]
fn shared_prologue_capped_by_shortest_arm() {
    let a = vec![item(1, 0, 0), item(2, 0, 0), item(3, 0, 0), item(4, 0, 0)];
    let b = vec![item(1, 0, 0), item(2, 0, 0)];
    let arms: [&[MegakernelWorkItem]; 2] = [&a, &b];
    assert_eq!(shared_prologue_length(&arms), 2);
}

#[test]
fn checked_selector_reports_shape_errors() {
    let mut scratch = FusionSelectionScratch::default();
    let err = select_fused_subset_checked_into(&[1.0], 2, &[0, 0, 0, 0], &mut scratch).unwrap_err();
    assert_eq!(
        err,
        FusionSelectionError::CostLen {
            expected: 2,
            actual: 1,
        }
    );

    let err = select_fused_subset_compact_checked_into(&[1, 2], 2, &[0], &mut scratch).unwrap_err();
    assert_eq!(
        err,
        FusionSelectionError::ExchangeAdjLen {
            expected: 4,
            actual: 1,
        }
    );
}

#[test]
fn selector_large_n_with_forced_conflict_skips_one_selected_arm() {
    let n = 257_usize;
    let mut costs = vec![10.0_f64; n];
    costs[n - 2] = 1.0;
    costs[n - 1] = 2.0;

    let mut exchange_adj = vec![0_u32; n * n];
    exchange_adj[(n - 2) * n + (n - 1)] = 1;
    exchange_adj[(n - 1) * n + (n - 2)] = 1;

    let selected = select_fused_subset(&costs, n as u32, &exchange_adj);

    assert_eq!(selected[n - 2], 1);
    assert_eq!(selected[n - 1], 0);
    assert_eq!(selected.iter().filter(|&&x| x == 1).count(), n - 1);
}

#[test]
fn selector_large_n_without_conflict_returns_all_selected() {
    let n = 300_usize;
    let costs: Vec<f64> = (0..n).map(|idx| idx as f64).collect();
    let exchange_adj = vec![0_u32; n * n];

    let selected = select_fused_subset(&costs, n as u32, &exchange_adj);

    assert_eq!(selected.len(), n);
    assert!(selected.iter().all(|&value| value == 1));
}

#[test]
fn selector_large_n_with_asymmetric_conflict_treats_as_conflict() {
    let n = 300_usize;
    let mut costs = vec![10.0_f64; n];
    costs[255] = 1.0;
    costs[1] = 1000.0;

    let mut exchange_adj = vec![0_u32; n * n];
    exchange_adj[255 * n + 1] = 1;

    let selected = select_fused_subset(&costs, n as u32, &exchange_adj);

    assert_eq!(selected[255], 1);
    assert_eq!(selected[1], 0);
}
