pub(crate) struct PreprocessorExprParser<'src, 'defs, 'name> {
    pub(crate) bytes: &'src [u8],
    pub(crate) index: usize,
    pub(crate) base_offset: usize,
    pub(crate) defined_macros: &'defs [&'name [u8]],
}
