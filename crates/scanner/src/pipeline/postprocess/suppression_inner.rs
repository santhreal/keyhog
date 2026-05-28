use crate::context;
use super::suppression_helpers::*;
use super::suppression_markers::check_marker_and_prefix_gates;
use super::suppression_tail::check_shape_context_and_b64_gates;

pub(super) fn should_suppress_inner(
    credential: &str,
    path: Option<&str>,
    context: context::CodeContext,
    source_type: Option<&str>,
    skip_b64_decode_recheck: bool,
    bypass_shape_gates: bool,
) -> bool {
    let credential = suppression_credential_slice(credential);
    let upper = credential.to_uppercase();

    if check_marker_and_prefix_gates(credential, path, &upper, bypass_shape_gates) {
        return true;
    }
    check_shape_context_and_b64_gates(
        credential,
        path,
        context,
        source_type,
        &upper,
        skip_b64_decode_recheck,
        bypass_shape_gates,
    )
}
