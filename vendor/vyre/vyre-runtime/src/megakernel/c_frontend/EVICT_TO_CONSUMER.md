# c_frontend Eviction Plan

**Target Crate**: `vyre-libs-c` (or consumer equivalent)

**Public Symbols to Migrate**:
- C_FRONTEND_WORKSPACE_BINDING
- C_FRONTEND_WORKSPACE_BUFFER
- MAX_C_FRONTEND_WORKSPACE_WORDS
- C_FRONTEND_MANIFEST_WORDS
- C_FRONTEND_TOKEN_WORDS
- C_FRONTEND_MACRO_WORDS
- C_FRONTEND_CONDITIONAL_WORDS
- C_FRONTEND_VAST_ROW_WORDS
- C_FRONTEND_PG_EDGE_WORDS
- C_FRONTEND_DIAGNOSTIC_WORDS
- C_FRONTEND_WORK_QUEUE_WORDS
- C_FRONTEND_WORKSPACE_MAGIC
- C_FRONTEND_WORKSPACE_ABI_VERSION
- manifest_word (mod)
- CFrontendPhase
- CFrontendRegionId
- CFrontendCapacityDiagnosticKind
- CFrontendPhaseHandler
- CFrontendWorkspaceLimits
- CFrontendWorkspaceRegion
- CFrontendWorkspaceManifest
- CFrontendWorkspaceError
- c_frontend_workspace_bootstrap_nodes
- c_frontend_phase_dispatch_nodes
- c_frontend_phase_machine_guard_nodes
- c_frontend_advance_phase_nodes
- c_frontend_fault_nodes
- is_valid_c_frontend_phase_transition
- validate_c_frontend_phase_transition

**Downstream Consumers to Update**:
- The main substrate pipeline should no longer depend directly on `c_frontend`. C-language parsing and handling will be instantiated by `vyre-libs-c` (or surgec) which will use the core substrate as a library rather than polluting `vyre-runtime` with domain-specific C logic.
- Remove `c_frontend` module dependency from `megakernel/builder.rs` and execution path, moving initialization strictly to the consumer's setup.
