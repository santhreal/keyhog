pub enum MutationClass {
/// Renames and alias collapse only. Byte-exact output required.
Cosmetic,
/// Reshape without semantic change (CSE, DCE, flatten, inline). Byte-exact.
Structural,
/// Semantic change under a declared precondition. Requires witness proof.
Semantic,
/// Backend lowering. Output checked against declared algebraic laws, not
/// against byte-for-byte reference output.
Lowering,
}
