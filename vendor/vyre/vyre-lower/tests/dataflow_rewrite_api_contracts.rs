use vyre_lower::analyses::alias_facts::AliasFactSet;
use vyre_lower::analyses::reaching_def_facts::ReachingDefFactSet;
use vyre_lower::rewrites::{
    dead_store_with_alias_facts, dead_store_with_dataflow_facts, licm_with_alias_facts,
    licm_with_dataflow_facts, load_forwarding_with_alias_facts,
    load_forwarding_with_dataflow_facts, loop_fission_with_alias_facts,
    loop_fission_with_dataflow_facts, loop_fusion_with_alias_facts,
    loop_fusion_with_dataflow_facts,
};
use vyre_lower::KernelDescriptor;

type AliasRewriteFn = fn(&KernelDescriptor, &AliasFactSet) -> KernelDescriptor;
type DataflowRewriteFn =
    fn(&KernelDescriptor, &AliasFactSet, &ReachingDefFactSet) -> KernelDescriptor;

#[test]
fn public_dataflow_rewrite_api_signatures_are_stable() {
    let alias_aware_rewrites: [AliasRewriteFn; 5] = [
        dead_store_with_alias_facts,
        licm_with_alias_facts,
        load_forwarding_with_alias_facts,
        loop_fission_with_alias_facts,
        loop_fusion_with_alias_facts,
    ];
    let dataflow_aware_rewrites: [DataflowRewriteFn; 5] = [
        dead_store_with_dataflow_facts,
        licm_with_dataflow_facts,
        load_forwarding_with_dataflow_facts,
        loop_fission_with_dataflow_facts,
        loop_fusion_with_dataflow_facts,
    ];

    assert_eq!(alias_aware_rewrites.len(), 5);
    assert_eq!(dataflow_aware_rewrites.len(), 5);
}
