pub trait Lowerable<Ctx: ?Sized> {
/// Visit this IR structure and emit into the backend-specific context.
fn lower(&self, ctx: &mut Ctx) -> Result<(), crate::error::Error>;
}
